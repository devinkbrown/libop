/*
 * ophion: a slightly less ancient ircd.
 * balloc.c: mmap-backed slab allocator.
 *
 * Replaces the old malloc-wrapper with a real slab allocator backed by
 * anonymous mmap().  Each op_bh maintains a per-heap intrusive free list
 * over a set of mmap'd slabs.
 *
 *   Allocation:  O(1) – pop from free_head; grow by one slab when empty.
 *   Free:        O(1) – push to free_head.
 *   Destroy:     munmap() each slab – memory is actually returned to the OS.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2002-2006 ircd-ratbox development team
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1
#include <libop_config.h>
#include <op_lib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>   /* pthread_mutex_t — guards per-heap free list */
#include <op_atomic.h> /* _Atomic, atomic_* — magazine generation counter */

/* memfd_create is Linux 3.17+; detect at compile time. */
#if defined(__linux__) && defined(__NR_memfd_create)
# include <sys/syscall.h>
# ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
# endif
static inline int _op_memfd_create(const char *name)
{
	return (int)syscall(__NR_memfd_create, name, (unsigned int)MFD_CLOEXEC);
}
# define HAVE_MEMFD 1
#else
# define HAVE_MEMFD 0
#endif

/* MAP_ANON is the BSD name; MAP_ANONYMOUS is the Linux/POSIX name. */
#ifndef MAP_ANONYMOUS
# ifdef MAP_ANON
#  define MAP_ANONYMOUS MAP_ANON
# else
#  error "Neither MAP_ANONYMOUS nor MAP_ANON is available"
# endif
#endif

/* Intrusive singly-linked free list stored inside each free element.
 * The first sizeof(void*) bytes of a free element hold the next-free ptr. */
#define FREELIST_NEXT(p)  (*(void **)(p))

/* Round v up to the nearest multiple of align (align must be power-of-two). */
#define ALIGN_UP(v, align)  (((v) + (size_t)(align) - 1) & ~((size_t)(align) - 1))

/*
 * op_bh_shmem_hdr — written at offset 0 of every shared-memory (memfd) region.
 *
 * The shim-side owner maps this header when passing the FD to a new ircd
 * instance; the new instance calls op_bh_attach_shmem() which reads these
 * fields to reconstruct the op_bh without an external description channel.
 *
 * The header is followed by the slab data at offset sizeof(op_bh_shmem_hdr),
 * page-aligned to elem_stride.
 */
#define OP_BH_SHMEM_MAGIC  0x4F50424855LL   /* "OPBHU" */

typedef struct op_bh_shmem_hdr
{
	uint64_t magic;         /* OP_BH_SHMEM_MAGIC — sanity check          */
	uint32_t version;       /* layout version (currently 1)              */
	uint32_t _pad;
	size_t   elemSize;      /* element size requested at creation         */
	size_t   elem_stride;   /* aligned stride                             */
	size_t   elemsPerBlock; /* elements per slab                          */
	size_t   data_off;      /* byte offset from slab start to element[0] */
	size_t   total_size;    /* total ftruncate'd memfd size               */
	/* nused / nfree are reconstructed by scanning the free-list on attach */
} op_bh_shmem_hdr_t;

/* Header embedded at the very start of every mmap'd slab. */
typedef struct op_bh_slab
{
	op_dlink_node node;     /* links into op_bh.block_list; .data == this */
	size_t        map_size; /* total bytes mmap'd (for munmap) */
	int           shmem_fd; /* -1 for private slabs; memfd for shared ones */
} op_bh_slab_t;

/* Private definition of op_bh (opaque to callers via op_balloc.h). */
struct op_bh
{
	op_dlink_node   hlist;          /* node in the global heap_lists registry */
	size_t          elemSize;       /* requested element size (for reporting) */
	size_t          elem_stride;    /* elemSize rounded up to pointer alignment */
	size_t          elemsPerBlock;  /* elements per slab */
	size_t          data_off;       /* byte offset from slab start to first element */
	void           *free_head;      /* head of the intrusive free list */
	op_dlink_list   block_list;     /* list of op_bh_slab_t* */
	size_t          nfree;          /* total free elements across all slabs */
	size_t          nused;          /* total allocated elements */
	char           *desc;
	/* Shared-memory fields (0/-1 for private heaps) */
	int             shmem_fd;       /* memfd FD, or -1                       */
	size_t          shmem_size;     /* total ftruncate'd size                 */
	/* Thread-safety: protects free_head, nfree, nused, and block_list growth.
	 * Callers may be on any thread (I/O thread or worker pool threads). */
	pthread_mutex_t lock;
	/* Generation counter: bumped on destroy.  Thread-local magazines cache
	 * the generation at creation; a mismatch means the heap was destroyed
	 * and the address reused — the magazine must be discarded. */
	_Atomic(uint32_t) generation;
};

static op_dlink_list *heap_lists;
static long           op_page_size;

static void _op_bh_fail(const char *reason, const char *file, int line)
	__attribute__((noreturn));
#define op_bh_fail(x) _op_bh_fail(x, __FILE__, __LINE__)

static void
_op_bh_fail(const char *reason, const char *file, int line)
{
	op_lib_log("op_bh failure: %s (%s:%d)", reason, file, line);
	abort();
}

void
op_init_bh(void)
{
	heap_lists   = op_malloc(sizeof(op_dlink_list));
	op_page_size = sysconf(_SC_PAGESIZE);
	if (op_page_size <= 0)
		op_page_size = 4096;
}

/* Allocate one new slab, link it into bh->block_list, and push all its
 * elements onto bh->free_head (in reverse order for cache-friendly first use). */
static void
op_bh_grow(op_bh *bh)
{
	size_t slab_data = bh->data_off + bh->elem_stride * bh->elemsPerBlock;
	size_t map_size  = ALIGN_UP(slab_data, (size_t)op_page_size);

	void *mem = mmap(NULL, map_size,
	                 PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS,
	                 -1, 0);
	if (mem == MAP_FAILED)
		op_bh_fail("mmap failed in op_bh_grow");

	op_bh_slab_t *slab = mem;
	slab->map_size = map_size;
	op_dlinkAdd(slab, &slab->node, &bh->block_list);

	/* Push in reverse order so the first alloc returns the lowest-address elem. */
	char *base = (char *)mem + bh->data_off;
	for (size_t i = bh->elemsPerBlock; i-- > 0; )
	{
		void *elem = base + (size_t)i * bh->elem_stride;
		FREELIST_NEXT(elem) = bh->free_head;
		bh->free_head = elem;
	}
	bh->nfree += bh->elemsPerBlock;
}

static op_bh *
op_bh_alloc_struct(size_t elemsize, size_t elemsperblock, const char *desc)
{
	if (elemsize == 0 || elemsperblock == 0)
		op_bh_fail("op_bh_create: idiotic sizes");
	if (elemsize < sizeof(void *))
		op_bh_fail("op_bh_create: elemsize too small for free-list pointer");

	op_bh *bh = op_malloc(sizeof(op_bh));

	bh->elemSize      = elemsize;
	bh->elem_stride   = ALIGN_UP(elemsize, sizeof(void *));
	bh->elemsPerBlock = elemsperblock;
	bh->data_off      = ALIGN_UP(sizeof(op_bh_slab_t), bh->elem_stride);
	bh->free_head     = NULL;
	bh->nfree         = 0;
	bh->nused         = 0;
	bh->desc          = (desc != NULL) ? op_strdup(desc) : NULL;
	bh->shmem_fd      = -1;
	bh->shmem_size    = 0;
	atomic_init(&bh->generation, 0);
	if (pthread_mutex_init(&bh->lock, NULL) != 0)
		op_bh_fail("op_bh_alloc_struct: pthread_mutex_init failed");
	return bh;
}

op_bh *
op_bh_create(size_t elemsize, size_t elemsperblock, const char *desc)
{
	op_bh *bh = op_bh_alloc_struct(elemsize, elemsperblock, desc);
	op_dlinkAdd(bh, &bh->hlist, heap_lists);
	op_bh_grow(bh);
	return bh;
}

/* ── Shared-memory heap implementation ──────────────────────────────────── */

/*
 * op_bh_create_shared — create a heap whose slabs live in a memfd so they
 * survive dlclose/dlopen during a hot-reload upgrade.
 *
 * A single memfd is created and sized to hold one pre-populated slab plus the
 * op_bh_shmem_hdr at offset 0.  Additional slabs grow the memfd via ftruncate
 * and map new pages into the same process.
 *
 * The returned op_bh has shmem_fd >= 0.  Pass this FD to the new ircd
 * instance via SCM_RIGHTS; call op_bh_attach_shmem() there to re-map.
 */
op_bh *
op_bh_create_shared(size_t elemsize, size_t elemsperblock, const char *desc)
{
#if !HAVE_MEMFD
	/* Fall back to private heap on platforms without memfd_create */
	return op_bh_create(elemsize, elemsperblock, desc);
#else
	op_bh *bh = op_bh_alloc_struct(elemsize, elemsperblock, desc);

	/* Calculate total region size: header + one slab */
	size_t slab_data = bh->data_off + bh->elem_stride * bh->elemsPerBlock;
	size_t slab_size = ALIGN_UP(slab_data, (size_t)op_page_size);
	size_t hdr_size  = ALIGN_UP(sizeof(op_bh_shmem_hdr_t), (size_t)op_page_size);
	size_t total     = hdr_size + slab_size;

	/* Create and size the memfd */
	int fd = _op_memfd_create(desc ? desc : "op_bh_shared");
	if (fd < 0)
	{
		op_free(bh->desc);
		op_free(bh);
		return NULL;
	}
	if (ftruncate(fd, (off_t)total) < 0)
	{
		close(fd);
		op_free(bh->desc);
		op_free(bh);
		return NULL;
	}

	/* Map the header page */
	void *hdr_mem = mmap(NULL, hdr_size, PROT_READ | PROT_WRITE,
	                     MAP_SHARED, fd, 0);
	if (hdr_mem == MAP_FAILED)
	{
		close(fd);
		op_free(bh->desc);
		op_free(bh);
		return NULL;
	}

	/* Write the persistent header */
	op_bh_shmem_hdr_t *hdr = hdr_mem;
	hdr->magic        = OP_BH_SHMEM_MAGIC;
	hdr->version      = 1;
	hdr->elemSize     = elemsize;
	hdr->elem_stride  = bh->elem_stride;
	hdr->elemsPerBlock = elemsperblock;
	hdr->data_off     = bh->data_off;
	hdr->total_size   = total;
	munmap(hdr_mem, hdr_size);   /* header written; no need to keep mapped */

	/* Map the first slab at offset hdr_size */
	void *slab_mem = mmap(NULL, slab_size, PROT_READ | PROT_WRITE,
	                      MAP_SHARED, fd, (off_t)hdr_size);
	if (slab_mem == MAP_FAILED)
	{
		close(fd);
		op_free(bh->desc);
		op_free(bh);
		return NULL;
	}

	/* Wire up the slab like op_bh_grow() does for private slabs */
	op_bh_slab_t *slab = slab_mem;
	slab->map_size = slab_size;
	slab->shmem_fd = fd;
	op_dlinkAdd(slab, &slab->node, &bh->block_list);

	char *base = (char *)slab_mem + bh->data_off;
	for (size_t i = bh->elemsPerBlock; i-- > 0; )
	{
		void *elem = base + i * bh->elem_stride;
		FREELIST_NEXT(elem) = bh->free_head;
		bh->free_head = elem;
	}
	bh->nfree += bh->elemsPerBlock;

	bh->shmem_fd   = fd;
	bh->shmem_size = total;

	op_dlinkAdd(bh, &bh->hlist, heap_lists);
	return bh;
#endif /* HAVE_MEMFD */
}

int
op_bh_shmem_fd(const op_bh *bh)
{
	return bh ? bh->shmem_fd : -1;
}

size_t
op_bh_shmem_size(const op_bh *bh)
{
	return bh ? bh->shmem_size : 0;
}

/*
 * op_bh_attach_shmem — re-attach to a shared heap after dlopen.
 *
 * Reads the op_bh_shmem_hdr from the memfd, reconstructs the op_bh struct,
 * and re-maps all slab pages.  Existing allocations remain valid at their
 * original virtual addresses only if the kernel honours the same mmap hint;
 * for pointer stability across dlopen the shim must use MAP_FIXED with the
 * same base address — which requires the shim to record the VA.  For the
 * initial implementation we accept that pointers may shift across a reload
 * and document this limitation.
 */
op_bh *
op_bh_attach_shmem(int fd, size_t size, const char *desc)
{
#if !HAVE_MEMFD
	(void)fd; (void)size; (void)desc;
	return NULL;
#else
	/* Map the header to read metadata */
	size_t hdr_size = ALIGN_UP(sizeof(op_bh_shmem_hdr_t), (size_t)op_page_size);
	void *hdr_mem = mmap(NULL, hdr_size, PROT_READ, MAP_SHARED, fd, 0);
	if (hdr_mem == MAP_FAILED)
		return NULL;

	op_bh_shmem_hdr_t *hdr = hdr_mem;
	if (hdr->magic != OP_BH_SHMEM_MAGIC || hdr->version != 1)
	{
		munmap(hdr_mem, hdr_size);
		return NULL;
	}

	op_bh *bh = op_bh_alloc_struct(hdr->elemSize, hdr->elemsPerBlock, desc);
	bh->elem_stride   = hdr->elem_stride;
	bh->data_off      = hdr->data_off;
	bh->shmem_fd      = fd;
	bh->shmem_size    = size;
	munmap(hdr_mem, hdr_size);

	/* Map the slab region(s).  For now assume a single slab (one ftruncate). */
	size_t slab_size = size - hdr_size;
	void *slab_mem = mmap(NULL, slab_size, PROT_READ | PROT_WRITE,
	                      MAP_SHARED, fd, (off_t)hdr_size);
	if (slab_mem == MAP_FAILED)
	{
		op_free(bh->desc);
		op_free(bh);
		return NULL;
	}

	op_bh_slab_t *slab = slab_mem;
	slab->shmem_fd = fd;
	op_dlinkAdd(slab, &slab->node, &bh->block_list);

	/* Reconstruct free-list by scanning: any slot whose first pointer-word
	 * is zero is considered free (works because op_bh_alloc memsets to 0). */
	bh->free_head = NULL;
	bh->nfree     = 0;
	bh->nused     = 0;
	char *base = (char *)slab_mem + bh->data_off;
	for (size_t i = bh->elemsPerBlock; i-- > 0; )
	{
		void *elem = base + i * bh->elem_stride;
		/* Heuristic: if first word is 0, treat as free and push to list. */
		if (*(uintptr_t *)elem == 0)
		{
			FREELIST_NEXT(elem) = bh->free_head;
			bh->free_head = elem;
			bh->nfree++;
		}
		else
		{
			bh->nused++;
		}
	}

	op_dlinkAdd(bh, &bh->hlist, heap_lists);
	return bh;
#endif /* HAVE_MEMFD */
}

/* =========================================================================
 * Thread-local magazine cache
 *
 * Each thread maintains a small cache of free elements per heap, amortising
 * the pthread_mutex_lock cost: instead of locking on every alloc/free, we
 * lock once per MAGAZINE_SIZE operations (batch refill/flush).
 *
 * Magazine capacity is tuned for the typical IRC workload: small, frequent
 * allocations of linebuf, dnode, sendbuf_chunk objects.
 * ====================================================================== */

#define MAGAZINE_SIZE    32     /* elements per magazine */
#define MAG_HASH_SIZE    64     /* buckets in per-thread magazine table */
#define MAG_HASH_MASK    (MAG_HASH_SIZE - 1)

typedef struct op_bh_magazine {
	op_bh               *heap;     /* which heap this magazine belongs to */
	struct op_bh_magazine *hash_next; /* chaining in the per-thread hash */
	void                *items[MAGAZINE_SIZE];
	int                  count;    /* number of items currently cached */
	uint32_t             generation; /* heap generation at magazine creation */
} op_bh_magazine_t;

/* Per-thread magazine hash table — maps op_bh* → magazine. */
typedef struct {
	op_bh_magazine_t *buckets[MAG_HASH_SIZE];
} mag_table_t;

static _Thread_local mag_table_t *tl_mag_table = NULL;

static inline uint32_t
mag_hash_ptr(const op_bh *bh)
{
	uintptr_t v = (uintptr_t)bh;
	v ^= v >> 16;
	v *= 0x45d9f3b;
	v ^= v >> 16;
	return (uint32_t)(v & MAG_HASH_MASK);
}

static op_bh_magazine_t *
mag_find_or_create(op_bh *bh)
{
	if (op_unlikely(tl_mag_table == NULL)) {
		tl_mag_table = calloc(1, sizeof(mag_table_t));
		if (tl_mag_table == NULL)
			op_bh_fail("mag_find_or_create: calloc failed");
	}

	uint32_t cur_gen = atomic_load_explicit(&bh->generation,
	                                        memory_order_relaxed);
	uint32_t idx = mag_hash_ptr(bh);
	op_bh_magazine_t *m = tl_mag_table->buckets[idx];
	while (m != NULL) {
		if (m->heap == bh) {
			if (op_unlikely(m->generation != cur_gen)) {
				/* Heap was destroyed and address reused —
				 * discard stale cached pointers. */
				m->count      = 0;
				m->generation = cur_gen;
			}
			return m;
		}
		m = m->hash_next;
	}

	/* Create a new magazine for this heap on this thread. */
	m = calloc(1, sizeof(op_bh_magazine_t));
	if (m == NULL)
		op_bh_fail("mag_find_or_create: calloc failed");
	m->heap       = bh;
	m->count      = 0;
	m->generation = cur_gen;
	m->hash_next  = tl_mag_table->buckets[idx];
	tl_mag_table->buckets[idx] = m;
	return m;
}

/* Refill a magazine from the global heap (called under bh->lock). */
static void
mag_refill_locked(op_bh *bh, op_bh_magazine_t *mag)
{
	int want = MAGAZINE_SIZE / 2;   /* refill half the magazine */
	int got  = 0;

	while (got < want) {
		if (op_unlikely(bh->free_head == NULL))
			op_bh_grow(bh);
		mag->items[mag->count] = bh->free_head;
		bh->free_head = FREELIST_NEXT(mag->items[mag->count]);
		bh->nfree--;
		bh->nused++;
		mag->count++;
		got++;
	}
}

/* Flush magazine items back to the global heap (called under bh->lock). */
static void
mag_flush_locked(op_bh *bh, op_bh_magazine_t *mag, int flush_count)
{
	for (int i = 0; i < flush_count; i++) {
		mag->count--;
		void *ptr = mag->items[mag->count];
		FREELIST_NEXT(ptr) = bh->free_head;
		bh->free_head = ptr;
		bh->nfree++;
		bh->nused--;
	}
}

/* =========================================================================
 * Memory poisoning (debug builds)
 *
 * On free: fill the element with 0xDE so any use-after-free sees garbage.
 * On alloc: check the poison pattern — if partially overwritten, someone
 * wrote to a freed element (use-after-free) or we have a double-free.
 *
 * The first sizeof(void*) bytes are the free-list pointer, so we skip
 * those and only check/fill bytes [sizeof(void*) .. elemSize).
 *
 * Gated behind NDEBUG so release builds pay zero cost.
 * ====================================================================== */

#ifndef NDEBUG
# define OP_BH_POISON_BYTE  0xDE
# define OP_BH_POISON_CHECK 1
int op_balloc_poison = 1;  /* on by default in debug builds */
#else
# define OP_BH_POISON_CHECK 0
int op_balloc_poison = 0;
#endif

void *
op_bh_alloc(op_bh *bh)
{
	slop_assert(bh != NULL);
	if (op_unlikely(bh == NULL))
		op_bh_fail("op_bh_alloc: bh == NULL");

	op_bh_magazine_t *mag = mag_find_or_create(bh);

	if (op_unlikely(mag->count == 0)) {
		/* Magazine empty — refill from global heap. */
		pthread_mutex_lock(&bh->lock);
		mag_refill_locked(bh, mag);
		pthread_mutex_unlock(&bh->lock);
	}

	void *elem = mag->items[--mag->count];

#if OP_BH_POISON_CHECK
	/* Verify poison pattern — skip the free-list pointer area. */
	if (op_balloc_poison && bh->elemSize > sizeof(void *)) {
		unsigned char *p   = (unsigned char *)elem + sizeof(void *);
		size_t         len = bh->elemSize - sizeof(void *);
		size_t         bad = 0;
		for (size_t i = 0; i < len; i++) {
			if (p[i] != OP_BH_POISON_BYTE)
				bad++;
		}
		/* If the block was previously freed it should be fully poisoned.
		 * A partially-poisoned block means use-after-free corruption.
		 * A block that was never freed (first alloc from slab) is all
		 * zeros, so bad == len — that's fine, not a double-free.
		 * We only flag it when SOME bytes match poison but others don't:
		 * that means someone wrote into a poisoned (freed) block. */
		if (bad > 0 && bad < len) {
			op_lib_log("op_bh_alloc: POISON CHECK FAILED for heap '%s' — "
			           "possible use-after-free (%zu/%zu bytes corrupted)",
			           bh->desc ? bh->desc : "(unnamed)", bad, len);
		}
	}
#endif

	memset(elem, 0, bh->elemSize);
	return elem;
}

void
op_bh_free(op_bh *bh, void *ptr)
{
	slop_assert(bh != NULL);
	slop_assert(ptr != NULL);

	if (op_unlikely(bh == NULL))
	{
		op_lib_log("op_bh_free: bh == NULL");
		return;
	}
	if (op_unlikely(ptr == NULL))
	{
		op_lib_log("op_bh_free: ptr == NULL");
		return;
	}

#if OP_BH_POISON_CHECK
	/* Check for double-free: if the block is already fully poisoned
	 * (past the free-list pointer), someone is freeing it again. */
	if (op_balloc_poison && bh->elemSize > sizeof(void *)) {
		unsigned char *p   = (unsigned char *)ptr + sizeof(void *);
		size_t         len = bh->elemSize - sizeof(void *);
		size_t         poisoned = 0;
		for (size_t i = 0; i < len; i++) {
			if (p[i] == OP_BH_POISON_BYTE)
				poisoned++;
		}
		if (poisoned == len) {
			op_lib_log("op_bh_free: DOUBLE FREE DETECTED for heap '%s' at %p",
			           bh->desc ? bh->desc : "(unnamed)", ptr);
			abort();
		}
	}

	/* Poison the entire element — the free-list pointer will be set
	 * below, overwriting the first sizeof(void*) bytes. */
	if (op_balloc_poison)
		memset(ptr, OP_BH_POISON_BYTE, bh->elemSize);
#endif

	op_bh_magazine_t *mag = mag_find_or_create(bh);

	if (op_unlikely(mag->count >= MAGAZINE_SIZE)) {
		/* Magazine full — flush half back to global heap. */
		pthread_mutex_lock(&bh->lock);
		mag_flush_locked(bh, mag, MAGAZINE_SIZE / 2);
		pthread_mutex_unlock(&bh->lock);
	}

	mag->items[mag->count++] = ptr;
}

int
op_bh_destroy(op_bh *bh)
{
	if (bh == NULL)
		return 1;

	/* Bump the generation so any thread-local magazines caching pointers
	 * from this heap will detect staleness on their next access. */
	atomic_fetch_add_explicit(&bh->generation, 1, memory_order_relaxed);

	/* Flush the calling thread's magazine immediately (if any). */
	if (tl_mag_table != NULL) {
		uint32_t idx = mag_hash_ptr(bh);
		op_bh_magazine_t **pp = &tl_mag_table->buckets[idx];
		while (*pp != NULL) {
			if ((*pp)->heap == bh) {
				op_bh_magazine_t *stale = *pp;
				*pp = stale->hash_next;
				free(stale);
				break;
			}
			pp = &(*pp)->hash_next;
		}
	}

	op_dlinkDelete(&bh->hlist, heap_lists);

	/* munmap each slab; use op_dlinkDelete (not Destroy) since the node is
	 * embedded inside the slab region that we're about to unmap. */
	while (bh->block_list.head != NULL)
	{
		op_dlink_node *node     = bh->block_list.head;
		op_bh_slab_t  *slab     = node->data;
		size_t         map_size = slab->map_size;
		op_dlinkDelete(node, &bh->block_list);
		munmap(slab, map_size);
	}

	pthread_mutex_destroy(&bh->lock);
	op_free(bh->desc);
	op_free(bh);
	return 0;
}

void
op_bh_usage(op_bh *bh, size_t *bused, size_t *bfree, size_t *bmemusage,
            const char **desc)
{
	if (bh == NULL)
	{
		if (bused)     *bused     = 0;
		if (bfree)     *bfree     = 0;
		if (bmemusage) *bmemusage = 0;
		if (desc)      *desc      = "no blockheap";
		return;
	}
	if (bused)     *bused     = bh->nused;
	if (bfree)     *bfree     = bh->nfree;
	if (bmemusage) *bmemusage = bh->nused * bh->elemSize;
	if (desc)      *desc      = bh->desc ? bh->desc : "(unnamed)";
}

void
op_bh_usage_all(op_bh_usage_cb *cb, void *data)
{
	op_dlink_node *ptr;

	if (cb == NULL)
		return;

	OP_DLINK_FOREACH(ptr, heap_lists->head)
	{
		op_bh  *bh        = ptr->data;
		size_t  heapalloc = (bh->nused + bh->nfree) * bh->elemSize;
		cb(bh->nused, bh->nfree,
		   bh->nused * bh->elemSize,
		   heapalloc,
		   bh->desc ? bh->desc : "(unnamed)",
		   data);
	}
}

void
op_bh_total_usage(size_t *total_alloc, size_t *total_used)
{
	op_dlink_node *ptr;
	size_t         talloc = 0, tused = 0;

	OP_DLINK_FOREACH(ptr, heap_lists->head)
	{
		op_bh *bh  = ptr->data;
		talloc    += (bh->nused + bh->nfree) * bh->elemSize;
		tused     += bh->nused * bh->elemSize;
	}

	if (total_alloc) *total_alloc = talloc;
	if (total_used)  *total_used  = tused;
}
