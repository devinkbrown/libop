/*
 * libop/include/op_shm_ring.h — SPSC shared-memory lock-free ring buffer.
 *
 * Zero-copy inter-process IPC: producer (ssld) writes directly into shared
 * memory; consumer (ircd) reads from the same mapping.  No kernel copy.
 *
 * Design (SPSC — Single Producer, Single Consumer):
 *
 *   • Each slot carries a fixed-size payload plus a conn_id tag so a single
 *     ring serves all connections of one ssld instance.
 *   • Synchronisation is via a single _Atomic(uint32_t) len field per slot:
 *       Producer: writes data, then atomic_store(..., len, release)
 *       Consumer: atomic_load(..., acquire) != 0 → data ready
 *                 reads data, then atomic_store(..., 0, release)
 *   • prod_pos / cons_pos in the header are also atomic so each side can
 *     detect full / empty without spinning on every slot.
 *   • Cache-line padding (64 B) on prod_pos and cons_pos prevents false
 *     sharing between the two processes.
 *
 * Bootstrap (Linux):
 *   Parent (ircd): fd = op_shm_ring_create(256);  ring = op_shm_ring_map(fd,256,true);
 *   Before exec:   clear FD_CLOEXEC on fd; set env SHM_DATA_FD=<fd>
 *   Child (ssld):  fd = atoi(getenv("SHM_DATA_FD")); ring = op_shm_ring_map(fd,256,false);
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */
#ifndef LIBOP_LIB_H
# error "Do not include op_shm_ring.h directly; include op_lib.h"
#endif

#ifndef OP_SHM_RING_H
#define OP_SHM_RING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <op_atomic.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define OP_SHM_RING_MAGIC    UINT32_C(0x4F505352)  /* "OPSR" */

/*
 * Payload bytes per slot.  4080 + 16 bytes of header = 4096 (one page).
 * Large enough for any IRC message including IRCv3 message tags (≤ 8191 B)
 * split across consecutive slots via OP_SHM_FLAG_MORE chaining.
 */
#define OP_SHM_SLOT_PAYLOAD  4080

/* Default ring depth — power-of-2, fits in one huge-page boundary (2 MB). */
#define OP_SHM_DEFAULT_SLOTS 512

/* Flags embedded in op_shm_slot.flags */
#define OP_SHM_FLAG_FIRST  UINT16_C(0x0001)  /* first (or only) chunk     */
#define OP_SHM_FLAG_MORE   UINT16_C(0x0002)  /* more chunks follow        */

/* ── Data structures ────────────────────────────────────────────────────── */

/*
 * op_shm_slot — one ring entry (exactly 4096 bytes = one memory page).
 *
 * Synchronisation contract:
 *   Producer writes conn_id / flags / data BEFORE publishing via len.
 *   Consumer sees a consistent slot once it observes len != 0.
 *   Consumer clears len to 0 to return the slot to the producer.
 */
struct op_shm_slot
{
    _Atomic(uint32_t)  len;                    /* 0=empty; >0=payload bytes  */
    uint16_t           flags;                  /* OP_SHM_FLAG_* bitmask      */
    uint16_t           _pad;
    uint64_t           conn_id;               /* originating connection id   */
    uint8_t            data[OP_SHM_SLOT_PAYLOAD];
    /* Total: 4+2+2+8+4080 = 4096 bytes */
};

/*
 * op_shm_ring_hdr — ring control header (192 bytes, 3 cache lines).
 *
 * prod_pos / cons_pos are sequence numbers (not masked indices).
 * Slot index = pos & (slot_count - 1).
 * Each is written ONLY by its respective owner; both are read by either side.
 * Separate cache lines prevent false sharing.
 */
struct op_shm_ring_hdr
{
    uint32_t           magic;       /* OP_SHM_RING_MAGIC                     */
    uint32_t           slot_count;  /* capacity (power-of-2)                 */
    uint8_t            _pad0[56];   /* ── pad header to 64 B ─────────────── */

    _Alignas(64) _Atomic(uint64_t) prod_pos; /* next slot to write (producer) */
    uint8_t            _pad1[56];

    _Alignas(64) _Atomic(uint64_t) cons_pos; /* next slot to read (consumer)  */
    uint8_t            _pad2[56];
};

/* Full ring: header immediately followed by the slot array. */
typedef struct {
    struct op_shm_ring_hdr hdr;
    struct op_shm_slot     slots[];  /* slot_count entries                   */
} op_shm_ring_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * op_shm_ring_map_size — total mmap size for `slot_count` slots.
 */
size_t op_shm_ring_map_size(uint32_t slot_count);

/*
 * op_shm_ring_create — allocate anonymous shared memory (memfd_create on
 * Linux, shm_open on POSIX) sized for `slot_count` slots.
 * Returns an open file descriptor, or -1 on error.
 * The returned fd has FD_CLOEXEC set; clear it before exec if the child
 * needs to inherit it.
 */
int op_shm_ring_create(uint32_t slot_count);

/*
 * op_shm_ring_map — mmap an existing shm fd.
 * Pass init=true once (in the creating process) to zero and initialise the
 * header.  The child passes init=false.
 * Returns the mapped ring pointer, or NULL on error.
 */
op_shm_ring_t *op_shm_ring_map(int fd, uint32_t slot_count, bool init);

/* op_shm_ring_unmap — munmap the ring.  Does not close the fd. */
void op_shm_ring_unmap(op_shm_ring_t *ring, uint32_t slot_count);

/*
 * op_shm_ring_push — producer: write up to `len` bytes from `buf` into the
 * ring, tagged with `conn_id`.  Payloads > OP_SHM_SLOT_PAYLOAD are split
 * across consecutive slots using the OP_SHM_FLAG_MORE chain.
 * Returns 0 on success, -1 if the ring is full (caller should fall back to
 * the socket path and retry later).
 */
int op_shm_ring_push(op_shm_ring_t *ring, uint64_t conn_id,
                     const void *buf, uint32_t len);

/*
 * op_shm_ring_pop — consumer: read the next ready slot.
 * `out_buf` must hold at least OP_SHM_SLOT_PAYLOAD bytes.
 * Sets *conn_id_out and *flags_out, returns payload length.
 * Returns 0 if the ring is empty, -1 on internal error.
 */
int op_shm_ring_pop(op_shm_ring_t *ring, uint64_t *conn_id_out,
                    void *out_buf, uint16_t *flags_out);

/* Returns true if the ring has at least one ready slot. */
bool op_shm_ring_readable(const op_shm_ring_t *ring);

#endif /* OP_SHM_RING_H */
