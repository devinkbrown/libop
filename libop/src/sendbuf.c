/*
 * Ophion IRC Daemon
 * sendbuf.c: Zero-copy chunk-based outgoing send queue.
 *
 * See op_sendbuf.h for the design overview.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_atomic.h>
#include <commio-int.h>

static op_bh *op_sendbuf_block_heap;
static op_bh *op_sendbuf_chunk_heap;

void
op_sendbuf_init(size_t heap_size)
{
	op_sendbuf_block_heap = op_bh_create(sizeof(op_sendbuf_block_t),
	                                     heap_size,
	                                     "libop_sendbuf_block_heap");
	op_sendbuf_chunk_heap = op_bh_create(sizeof(op_sendbuf_chunk_t),
	                                     heap_size * 4,
	                                     "libop_sendbuf_chunk_heap");
}

/* ---- intrusive queue helpers --------------------------------------------- */

/* Append a chunk to the active (consumer-only) list.
 * Caller must be the I/O thread — no synchronisation. */
static inline void
sendbuf_enqueue(op_sendbuf_t *sb, op_sendbuf_chunk_t *chunk)
{
	chunk->next = NULL;
	if (sb->tail)
		sb->tail->next = chunk;
	else
		sb->head = chunk;
	sb->tail = chunk;
}

/* Dequeue and free the head chunk, releasing its payload reference.
 * Caller must be the I/O thread. */
static inline void
sendbuf_free_head(op_sendbuf_t *sb)
{
	op_sendbuf_chunk_t *chunk = sb->head;

	sb->head = chunk->next;
	if (sb->head == NULL)
		sb->tail = NULL;

	if (chunk->type == SENDBUF_CHUNK_LINE)
		op_linebuf_unref(chunk->line);
	else
		op_bh_free(op_sendbuf_block_heap, chunk->block);

	op_bh_free(op_sendbuf_chunk_heap, chunk);
}

/* ---- MPSC inbox (lock-free Treiber stack) -------------------------------- */

/* Push a single chunk to the inbox.  Safe to call from any thread. */
static inline void
sendbuf_inbox_push(op_sendbuf_t *sb, op_sendbuf_chunk_t *chunk)
{
	op_sendbuf_chunk_t *old_top =
	    atomic_load_explicit(&sb->inbox, memory_order_relaxed);
	do {
		chunk->next = old_top;
	} while (!atomic_compare_exchange_weak_explicit(
	    &sb->inbox, &old_top, chunk,
	    memory_order_release, memory_order_relaxed));
}

/* Drain the inbox into the active queue (I/O thread only).
 *
 * Atomically swaps inbox to NULL, reverses the LIFO stack into FIFO
 * order, and appends the result to the active head/tail list. */
static void
sendbuf_drain_inbox(op_sendbuf_t *sb)
{
	op_sendbuf_chunk_t *stack = atomic_exchange_explicit(
	    &sb->inbox, NULL, memory_order_acquire);

	if (stack == NULL)
		return;

	/* Reverse the stack (LIFO → FIFO). */
	op_sendbuf_chunk_t *prev = NULL;
	while (stack != NULL)
	{
		op_sendbuf_chunk_t *next = stack->next;
		stack->next = prev;
		prev = stack;
		stack = next;
	}
	/* prev is now the head of the FIFO chain; find its tail. */
	op_sendbuf_chunk_t *fifo_head = prev;
	op_sendbuf_chunk_t *fifo_tail = prev;
	while (fifo_tail->next != NULL)
		fifo_tail = fifo_tail->next;

	/* Append to the active queue. */
	if (sb->tail)
		sb->tail->next = fifo_head;
	else
		sb->head = fifo_head;
	sb->tail = fifo_tail;
}

/* ---- public API ---------------------------------------------------------- */

/* Free all chunks.  LINE chunks release their buf_line_t ref; BLOCK chunks
 * free their block back to the pool.  Must only be called when no producers
 * can be racing (client teardown). */
void
op_sendbuf_donebuf(op_sendbuf_t *sb)
{
	sendbuf_drain_inbox(sb);
	while (sb->head != NULL)
		sendbuf_free_head(sb);
	atomic_store_explicit(&sb->len, 0, memory_order_relaxed);
}

/* Append len bytes from data into block storage (copy path, used for raw
 * writes and SSL).  Multiple calls are packed into the same tail block
 * before a new block is allocated. */
int
op_sendbuf_write(op_sendbuf_t *sb, const void *data, size_t len)
{
	const char *ptr = data;
	size_t remaining = len;

	while (remaining > 0)
	{
		op_sendbuf_chunk_t *chunk = NULL;
		op_sendbuf_block_t *blk = NULL;

		/* Pack into the tail block if it has space and is a BLOCK chunk. */
		if (sb->tail != NULL && sb->tail->type == SENDBUF_CHUNK_BLOCK &&
		   sb->tail->block->wpos < OP_SENDBUF_BLOCK_SIZE)
		{
			chunk = sb->tail;
			blk   = chunk->block;
		}

		if (blk == NULL)
		{
			blk = op_bh_alloc(op_sendbuf_block_heap);
			if (op_unlikely(blk == NULL))
				return -1;
			blk->wpos = 0;

			chunk = op_bh_alloc(op_sendbuf_chunk_heap);
			if (op_unlikely(chunk == NULL))
			{
				op_bh_free(op_sendbuf_block_heap, blk);
				return -1;
			}
			chunk->type  = SENDBUF_CHUNK_BLOCK;
			chunk->rpos  = 0;
			chunk->block = blk;
			sendbuf_enqueue(sb, chunk);
		}

		size_t space = OP_SENDBUF_BLOCK_SIZE - blk->wpos;
		size_t copy  = remaining < space ? remaining : space;
		memcpy(blk->buf + blk->wpos, ptr, copy);
		blk->wpos  += (uint16_t)copy;
		ptr        += copy;
		remaining  -= copy;
		atomic_fetch_add_explicit(&sb->len, copy, memory_order_relaxed);
	}

	return 0;
}

/* Zero-copy enqueue: for each terminated buf_line_t in linebuf, take a
 * reference and add a CHUNK_LINE.  The caller may destroy the buf_head_t
 * immediately; the bytes stay alive via the refs until fully flushed.
 *
 * Thread-safe: pushes to the MPSC inbox (lock-free).  May be called from
 * any thread. */
int
op_sendbuf_write_linebuf(op_sendbuf_t *sb, buf_head_t *linebuf)
{
	op_dlink_node *ptr;
	size_t total_bytes = 0;

	OP_DLINK_FOREACH(ptr, linebuf->list.head)
	{
		buf_line_t *line = ptr->data;

		if (line->len == 0 || !line->terminated)
			continue;

		op_sendbuf_chunk_t *chunk = op_bh_alloc(op_sendbuf_chunk_heap);
		if (op_unlikely(chunk == NULL))
			return -1;

		op_linebuf_ref(line);      /* keep alive past buf_head_t destruction */
		chunk->type = SENDBUF_CHUNK_LINE;
		chunk->rpos = 0;
		chunk->line = line;
		sendbuf_inbox_push(sb, chunk);
		total_bytes += line->len;
	}

	if (total_bytes > 0)
		atomic_fetch_add_explicit(&sb->len, total_bytes, memory_order_release);

	return 0;
}

/* ---- internal helpers ---------------------------------------------------- */

/* Advance chunks by `consumed` bytes, freeing fully-sent ones. */
static void
sendbuf_advance(op_sendbuf_t *sb, ssize_t consumed)
{
	atomic_fetch_sub_explicit(&sb->len, (size_t)consumed, memory_order_relaxed);

	while (consumed > 0 && sb->head != NULL)
	{
		op_sendbuf_chunk_t *chunk = sb->head;
		size_t avail;

		if (chunk->type == SENDBUF_CHUNK_LINE)
			avail = chunk->line->len - chunk->rpos;
		else
			avail = (size_t)chunk->block->wpos - chunk->rpos;

		if ((size_t)consumed < avail)
		{
			chunk->rpos += (uint16_t)consumed;
			break;
		}

		consumed -= (ssize_t)avail;
		sendbuf_free_head(sb);
	}
}

/* ---- drain --------------------------------------------------------------- */

/* Copy at most `limit` bytes from the front of the queue into `buf`,
 * consuming the bytes (advancing rpos, freeing fully-consumed chunks).
 * Used by transport layers that need raw bytes before writing.
 * Must only be called from the I/O thread (single consumer). */
size_t
op_sendbuf_drain_to_buf(op_sendbuf_t *sb, void *buf, size_t limit)
{
	sendbuf_drain_inbox(sb);

	char  *out  = buf;
	size_t done = 0;

	while (done < limit && sb->head != NULL)
	{
		op_sendbuf_chunk_t *chunk = sb->head;
		const char *base;
		size_t avail;

		if (chunk->type == SENDBUF_CHUNK_LINE)
		{
			base  = chunk->line->buf + chunk->rpos;
			avail = chunk->line->len - chunk->rpos;
		}
		else
		{
			base  = chunk->block->buf + chunk->rpos;
			avail = (size_t)chunk->block->wpos - chunk->rpos;
		}

		size_t copy = (limit - done < avail) ? (limit - done) : avail;
		memcpy(out + done, base, copy);
		done += copy;

		if (copy < avail)
		{
			chunk->rpos += (uint16_t)copy;
			continue;
		}

		sendbuf_free_head(sb);
	}

	atomic_fetch_sub_explicit(&sb->len, done, memory_order_relaxed);
	return done;
}

/* ---- flush --------------------------------------------------------------- */

ssize_t
op_sendbuf_flush(op_sendbuf_t *sb, op_fde_t *F)
{
	sendbuf_drain_inbox(sb);

	if (op_sendbuf_len(sb) == 0)
	{
		errno = EWOULDBLOCK;
		return -1;
	}

#ifdef HAVE_WRITEV
	if (!op_fd_ssl(F) && !op_fd_ws(F))
	{
		struct op_iovec vec[OP_UIO_MAXIOV];
		int nvec = 0;
		ssize_t total;

		for (op_sendbuf_chunk_t *chunk = sb->head; chunk != NULL; chunk = chunk->next)
		{
			size_t avail;
			const char *base;

			if (chunk->type == SENDBUF_CHUNK_LINE)
			{
				avail = chunk->line->len - chunk->rpos;
				base  = chunk->line->buf + chunk->rpos;
			}
			else
			{
				avail = (size_t)chunk->block->wpos - chunk->rpos;
				base  = chunk->block->buf + chunk->rpos;
			}

			if (avail == 0)
				continue;

			vec[nvec].iov_base = (void *)base;
			vec[nvec].iov_len  = avail;
			if (++nvec == OP_UIO_MAXIOV)
				break;
		}

		if (nvec == 0)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		total = op_writev(F, vec, nvec);
		if (total <= 0)
			return total;

		sendbuf_advance(sb, total);
		return total;
	}
#endif /* HAVE_WRITEV */

	/* SSL or no-writev fallback: write the first contiguous segment only. */
	{
		op_sendbuf_chunk_t *chunk = sb->head;
		const char *base;
		size_t avail;
		ssize_t written;

		if (chunk == NULL)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		if (chunk->type == SENDBUF_CHUNK_LINE)
		{
			base  = chunk->line->buf + chunk->rpos;
			avail = chunk->line->len - chunk->rpos;
		}
		else
		{
			base  = chunk->block->buf + chunk->rpos;
			avail = (size_t)chunk->block->wpos - chunk->rpos;
		}

		written = op_write(F, base, avail);
		if (written <= 0)
			return written;

		sendbuf_advance(sb, written);
		return written;
	}
}
