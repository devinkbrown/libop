/*
 * libop: ophion support library.
 * op_ringbuf.h: Lock-free single-producer / single-consumer ring buffer.
 *
 * A classic SPSC ring buffer built on C11 atomics with acquire/release
 * memory ordering.  No mutexes, no spin-waiting — push returns false when
 * full, pop returns false when empty.
 *
 * Usage model:
 *   - Exactly ONE thread (or context) may call op_ringbuf_push() at a time.
 *   - Exactly ONE thread (or context) may call op_ringbuf_pop() at a time.
 *   - The producer and consumer may run concurrently without locking.
 *   - Capacity is rounded up to the next power of two.
 *
 * Typical uses in ophion:
 *   - Helper process stdout → main thread (structured log or auth responses).
 *   - Producer accumulating sendbuf blocks, consumer draining to socket.
 *   - Future thread-pool work-item queues.
 *
 * This is a header-only implementation — no corresponding .c file needed.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_ringbuf.h directly; include op_lib.h"
#endif

#ifndef LIBOP_RINGBUF_H
#define LIBOP_RINGBUF_H

#include <op_atomic.h>

/* ---- type ---------------------------------------------------------------- */

/*
 * Head and tail live on separate cache lines to avoid false sharing between
 * the producer (writes head) and consumer (writes tail).
 */
typedef struct op_ringbuf
{
	size_t              mask;       /* capacity - 1                   */
	char                _pad0[64 - sizeof(size_t)];

	_Atomic(size_t)     head;       /* producer's write cursor         */
	char                _pad1[64 - sizeof(_Atomic(size_t))];

	_Atomic(size_t)     tail;       /* consumer's read cursor          */
	char                _pad2[64 - sizeof(_Atomic(size_t))];

	void               *slots[];    /* flexible array of (capacity) pointers */
} op_ringbuf_t;

/* ---- construction / destruction ------------------------------------------ */

/*
 * op_ringbuf_create — allocate a ring buffer.
 *
 * capacity is rounded up to the next power of two (minimum 2).
 * Returns a pointer to the ring buffer; aborts on OOM (same as op_malloc).
 */
static inline op_ringbuf_t *
op_ringbuf_create(size_t capacity)
{
	/* Round up to power of two, minimum 2. */
	if (capacity < 2)
		capacity = 2;
	capacity--;
	capacity |= capacity >> 1;
	capacity |= capacity >> 2;
	capacity |= capacity >> 4;
	capacity |= capacity >> 8;
	capacity |= capacity >> 16;
	capacity |= capacity >> 32;
	capacity++;

	op_ringbuf_t *rb = op_malloc(sizeof(op_ringbuf_t) + capacity * sizeof(void *));
	rb->mask = capacity - 1;
	atomic_init(&rb->head, 0);
	atomic_init(&rb->tail, 0);
	memset(rb->slots, 0, capacity * sizeof(void *));
	return rb;
}

static inline void
op_ringbuf_destroy(op_ringbuf_t *rb)
{
	op_free(rb);
}

/* ---- producer-side (single producer only) -------------------------------- */

/*
 * op_ringbuf_push — enqueue one pointer.
 *
 * Returns true on success, false if the buffer is full.
 * May only be called from the producer context.
 */
static inline bool
op_ringbuf_push(op_ringbuf_t *rb, void *item)
{
	size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
	size_t next = (head + 1) & rb->mask;

	/* Full if the next write position == tail (consumer's cursor). */
	if (next == atomic_load_explicit(&rb->tail, memory_order_acquire))
		return false;

	rb->slots[head & rb->mask] = item;
	atomic_store_explicit(&rb->head, next, memory_order_release);
	return true;
}

/* ---- consumer-side (single consumer only) -------------------------------- */

/*
 * op_ringbuf_pop — dequeue one pointer into *item.
 *
 * Returns true on success, false if the buffer is empty.
 * May only be called from the consumer context.
 */
static inline bool
op_ringbuf_pop(op_ringbuf_t *rb, void **item)
{
	size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

	/* Empty if tail == head (producer's cursor). */
	if (tail == atomic_load_explicit(&rb->head, memory_order_acquire))
		return false;

	*item = rb->slots[tail & rb->mask];
	atomic_store_explicit(&rb->tail, (tail + 1) & rb->mask, memory_order_release);
	return true;
}

/* ---- introspection (approximate — not sequentially consistent) ----------- */

static inline size_t
op_ringbuf_cap(const op_ringbuf_t *rb)
{
	return rb->mask + 1;
}

static inline bool
op_ringbuf_empty(const op_ringbuf_t *rb)
{
	return atomic_load_explicit(&rb->tail, memory_order_acquire)
	    == atomic_load_explicit(&rb->head, memory_order_acquire);
}

static inline bool
op_ringbuf_full(const op_ringbuf_t *rb)
{
	size_t next = (atomic_load_explicit(&rb->head, memory_order_acquire) + 1)
	              & rb->mask;
	return next == atomic_load_explicit(&rb->tail, memory_order_acquire);
}

/*
 * op_ringbuf_count — approximate number of items currently in the buffer.
 * May be transiently inaccurate under concurrent access.
 */
static inline size_t
op_ringbuf_count(const op_ringbuf_t *rb)
{
	size_t h = atomic_load_explicit(&rb->head, memory_order_acquire);
	size_t t = atomic_load_explicit(&rb->tail, memory_order_acquire);
	return (h - t) & rb->mask;
}

#endif /* LIBOP_RINGBUF_H */
