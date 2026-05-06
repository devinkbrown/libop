/*
 * ophion: a slightly less ancient ircd.
 * op_sendbuf.h: Zero-copy chunk-based outgoing send queue.
 *
 * Two chunk types share a single ordered queue:
 *
 *   SENDBUF_CHUNK_LINE  — a reference-counted pointer into a shared
 *     buf_line_t (formatted IRC message).  No byte copy: the buf_line_t
 *     is kept alive by incrementing its refcount; the chunk owns that
 *     reference and releases it via op_linebuf_unref() when the bytes
 *     are fully sent.
 *
 *   SENDBUF_CHUNK_BLOCK — an owned 4 KiB byte block for raw writes
 *     (e.g. SSL handshake data, PASS/SERVER lines, or future raw-byte
 *     paths).  Multiple consecutive op_sendbuf_write() calls are packed
 *     into the same tail block before a new one is allocated.
 *
 * For the dominant fan-out workload (channel message → N clients):
 *   Old path: N × memcpy(~512 B) into block queue   ≈ 256 KB copied
 *   New path: N × refcount++ + chunk alloc           ≈ 0 B copied
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_sendbuf.h directly; include op_lib.h"
#endif

#ifndef OP_SENDBUF_H
#define OP_SENDBUF_H

/* ---- types --------------------------------------------------------------- */

/* Byte block for raw data and SSL paths. */
#define OP_SENDBUF_BLOCK_SIZE  4096

typedef struct op_sendbuf_block
{
	char     buf[OP_SENDBUF_BLOCK_SIZE];
	uint16_t wpos;   /* next write offset; buf[0..wpos) contains data */
} op_sendbuf_block_t;

/* Chunk type discriminator. */
#define SENDBUF_CHUNK_LINE  0   /* shared buf_line_t reference (zero-copy) */
#define SENDBUF_CHUNK_BLOCK 1   /* owned op_sendbuf_block_t                */

/*
 * Unified queue entry.  rpos tracks how many bytes of this chunk have
 * already been sent (for partial-write recovery).
 *
 * LINE:  data lives at line->buf + rpos, total = line->len bytes.
 * BLOCK: data lives at block->buf + rpos, total = block->wpos bytes.
 */
/*
 * The queue is an intrusive singly-linked list (next pointer embedded here)
 * to avoid a separate op_dlink_node allocation per chunk.  Only FIFO access
 * is needed, so a singly-linked list is sufficient and saves one heap
 * alloc+free per queued message under channel fanout.
 */
typedef struct op_sendbuf_chunk
{
	struct op_sendbuf_chunk *next;  /* intrusive link; NULL = end of queue */
	uint8_t  type;
	uint16_t rpos;   /* bytes consumed from this chunk so far */
	union
	{
		buf_line_t         *line;    /* SENDBUF_CHUNK_LINE  */
		op_sendbuf_block_t *block;   /* SENDBUF_CHUNK_BLOCK */
	};
} op_sendbuf_chunk_t;

/* The send queue itself.  A zero-initialised op_sendbuf_t is valid (empty).
 * op_malloc() already zeros, so no explicit init call is needed when the
 * struct is embedded in a zero-initialised LocalUser.
 *
 * Threading model (lock-free MPSC):
 *   Multiple worker threads push chunks to the atomic `inbox` stack
 *   (Treiber stack, CAS-based, lock-free).  The I/O thread is the
 *   single consumer: it atomically swaps inbox to NULL, reverses the
 *   stack into FIFO order, and appends the result to the active
 *   head/tail list for flushing.  No spinlock is needed.
 *
 *   head/tail: consumer-only (I/O thread).
 *   inbox:     multi-producer (workers), single-consumer (I/O thread).
 *   len:       atomically updated by both producers and consumer.
 */
typedef struct op_sendbuf
{
	/* Active queue — only the I/O thread touches these. */
	op_sendbuf_chunk_t *head;  /* oldest chunk (flushed first) */
	op_sendbuf_chunk_t *tail;  /* newest chunk (appended last) */

	/* MPSC inbox — workers push here lock-free. */
	_Atomic(op_sendbuf_chunk_t *) inbox;

	/* Total queued bytes (active + inbox). */
	_Atomic(size_t)     len;
} op_sendbuf_t;

#define op_sendbuf_len(sb)  atomic_load_explicit(&(sb)->len, memory_order_relaxed)

/* ---- API ----------------------------------------------------------------- */

void    op_sendbuf_init(size_t heap_size);
void    op_sendbuf_donebuf(op_sendbuf_t *sb);

/* Append raw bytes (copied into block storage). */
int     op_sendbuf_write(op_sendbuf_t *sb, const void *data, size_t len);

/* Zero-copy: enqueue all terminated lines from a temporary buf_head_t by
 * taking a reference on each buf_line_t.  The caller may free the
 * buf_head_t immediately after; the bytes remain accessible via the refs. */
int     op_sendbuf_write_linebuf(op_sendbuf_t *sb, buf_head_t *linebuf);

/* Flush as much as possible to socket F.
 * Returns bytes written (> 0), 0 on EOF, or -1 with errno set on error. */
ssize_t op_sendbuf_flush(op_sendbuf_t *sb, op_fde_t *F);

/* Drain at most `limit` bytes from the front of the queue into `buf`,
 * advancing rpos and freeing fully-consumed chunks.  Used by compression
 * paths that read raw bytes themselves instead of calling flush.
 * Returns actual bytes copied (0 if queue is empty). */
size_t  op_sendbuf_drain_to_buf(op_sendbuf_t *sb, void *buf, size_t limit);

#endif /* OP_SENDBUF_H */
