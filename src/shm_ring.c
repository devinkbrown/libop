/*
 * libop/src/shm_ring.c — SPSC shared-memory lock-free ring buffer.
 *
 * See libop/include/op_shm_ring.h for design notes.
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_shm_ring.h>

#include <string.h>
#include <op_atomic.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#ifndef _WIN32
# include <sys/stat.h>
#endif

/* ── memfd / shm_open backend ─────────────────────────────────────────── */

#if defined(__linux__) && defined(__NR_memfd_create)
# include <sys/syscall.h>
# ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 1U
# endif
static int
_shm_fd_create(size_t sz)
{
	int fd = (int)syscall(__NR_memfd_create, "op_shm_ring", (unsigned int)MFD_CLOEXEC);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, (off_t)sz) < 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}
#elif !defined(_WIN32)
/* POSIX shm_open fallback (macOS, BSDs, older Linux). */
# include <sys/mman.h>
static int
_shm_fd_create(size_t sz)
{
	char name[64];
	snprintf(name, sizeof(name), "/op_shm_%d", (int)getpid());
	int fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
	if (fd < 0)
		return -1;
	/* Unlink immediately: the fd keeps the segment alive. */
	shm_unlink(name);
	if (ftruncate(fd, (off_t)sz) < 0)
	{
		close(fd);
		return -1;
	}
	/* POSIX shm_open does NOT set CLOEXEC; set it now so the parent
	 * controls inheritance explicitly. */
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return fd;
}
#else  /* Windows — not yet implemented */
static int
_shm_fd_create(size_t sz)
{
	(void)sz;
	errno = ENOSYS;
	return -1;
}
#endif

/* ── public API ─────────────────────────────────────────────────────────── */

size_t
op_shm_ring_map_size(uint32_t slot_count)
{
	return sizeof(op_shm_ring_t)
	       + (size_t)slot_count * sizeof(struct op_shm_slot);
}

int
op_shm_ring_create(uint32_t slot_count)
{
	return _shm_fd_create(op_shm_ring_map_size(slot_count));
}

op_shm_ring_t *
op_shm_ring_map(int fd, uint32_t slot_count, bool init)
{
	size_t sz = op_shm_ring_map_size(slot_count);
#ifdef _WIN32
	(void)fd; (void)init;
	return NULL;
#else
	void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		return NULL;

	op_shm_ring_t *ring = (op_shm_ring_t *)p;
	if (init)
	{
		memset(ring, 0, sz);
		ring->hdr.magic      = OP_SHM_RING_MAGIC;
		ring->hdr.slot_count = slot_count;
		atomic_store_explicit(&ring->hdr.prod_pos, 0, memory_order_relaxed);
		atomic_store_explicit(&ring->hdr.cons_pos, 0, memory_order_relaxed);
	}
	return ring;
#endif
}

void
op_shm_ring_unmap(op_shm_ring_t *ring, uint32_t slot_count)
{
#ifndef _WIN32
	if (ring != NULL)
		munmap(ring, op_shm_ring_map_size(slot_count));
#else
	(void)ring; (void)slot_count;
#endif
}

bool
op_shm_ring_readable(const op_shm_ring_t *ring)
{
	uint64_t prod = atomic_load_explicit(&ring->hdr.prod_pos, memory_order_acquire);
	uint64_t cons = atomic_load_explicit(&ring->hdr.cons_pos, memory_order_relaxed);
	if (prod == cons)
		return false;
	/* Verify the next slot is actually published (handles wrap-around). */
	const struct op_shm_slot *slot =
		&ring->slots[cons & (ring->hdr.slot_count - 1)];
	return atomic_load_explicit(&slot->len, memory_order_acquire) != 0;
}

int
op_shm_ring_push(op_shm_ring_t *ring, uint64_t conn_id,
                 const void *buf, uint32_t len)
{
	if (len == 0)
		return 0;

	const uint8_t *src       = (const uint8_t *)buf;
	uint32_t       remaining = len;
	uint32_t       capacity  = ring->hdr.slot_count;
	uint64_t       prod      = atomic_load_explicit(&ring->hdr.prod_pos,
	                                                memory_order_relaxed);
	bool           first     = true;

	while (remaining > 0)
	{
		/* Check ring has space. */
		uint64_t cons = atomic_load_explicit(&ring->hdr.cons_pos,
		                                     memory_order_acquire);
		if (prod - cons >= capacity)
			return -1;  /* ring full */

		struct op_shm_slot *slot = &ring->slots[prod & (capacity - 1)];

		/* Ensure the consumer has cleared this slot. */
		if (atomic_load_explicit(&slot->len, memory_order_acquire) != 0)
			return -1;  /* slot not yet freed — treat as full */

		uint32_t chunk = (remaining < OP_SHM_SLOT_PAYLOAD)
		                 ? remaining : (uint32_t)OP_SHM_SLOT_PAYLOAD;

		uint16_t flags = 0;
		if (first)            flags |= OP_SHM_FLAG_FIRST;
		if (chunk < remaining) flags |= OP_SHM_FLAG_MORE;

		slot->conn_id = conn_id;
		slot->flags   = flags;
		memcpy(slot->data, src, chunk);

		/* Publish: store length LAST with release so the consumer sees
		 * a fully written slot once it observes len != 0. */
		atomic_store_explicit(&slot->len, chunk, memory_order_release);

		/* Advance producer sequence. */
		atomic_store_explicit(&ring->hdr.prod_pos, prod + 1,
		                      memory_order_release);

		src       += chunk;
		remaining -= chunk;
		prod++;
		first = false;
	}
	return 0;
}

int
op_shm_ring_pop(op_shm_ring_t *ring, uint64_t *conn_id_out,
                void *out_buf, uint16_t *flags_out)
{
	uint64_t cons     = atomic_load_explicit(&ring->hdr.cons_pos,
	                                         memory_order_relaxed);
	uint64_t prod     = atomic_load_explicit(&ring->hdr.prod_pos,
	                                         memory_order_acquire);
	uint32_t capacity = ring->hdr.slot_count;

	if (cons == prod)
		return 0;  /* empty */

	struct op_shm_slot *slot = &ring->slots[cons & (capacity - 1)];
	uint32_t plen = atomic_load_explicit(&slot->len, memory_order_acquire);
	if (plen == 0)
		return 0;  /* slot not yet published (race between prod_pos and len) */

	*conn_id_out = slot->conn_id;
	*flags_out   = slot->flags;
	memcpy(out_buf, slot->data, plen);

	/* Release slot back to producer: clear len LAST with release. */
	atomic_store_explicit(&slot->len, 0, memory_order_release);
	atomic_store_explicit(&ring->hdr.cons_pos, cons + 1, memory_order_release);

	return (int)plen;
}
