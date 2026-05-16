/*
 * libop/include/op_spsc.h — Lock-free SPSC ring buffer.
 *
 * Single-producer, single-consumer bounded queue. Cache-line-aligned
 * head/tail counters prevent false sharing. Power-of-two capacity.
 *
 * On x86 TSO: acquire/release map to plain MOV (compiler fence only).
 * On ARM64: LDAR/STLR.
 *
 * Copyright (c) 2026 Ophion Development Team.  GPL v2.
 */

#ifndef OP_SPSC_H
#define OP_SPSC_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define OP_CACHELINE 64

typedef struct {
	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) head;
	char _pad0[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) tail;
	char _pad1[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	uint64_t  mask;
	void    **slots;
} op_spsc_t;

static inline int
op_spsc_init(op_spsc_t *q, uint64_t capacity)
{
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return -1;
	memset(q, 0, sizeof(*q));
	q->mask = capacity - 1;
	q->slots = (void **)calloc((size_t)capacity, sizeof(void *));
	return q->slots ? 0 : -1;
}

static inline void
op_spsc_destroy(op_spsc_t *q)
{
	free(q->slots);
	q->slots = NULL;
}

static inline int
op_spsc_push(op_spsc_t *q, void *item)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
	if ((h - t) > q->mask)
		return 0;
	q->slots[h & q->mask] = item;
	atomic_store_explicit(&q->head, h + 1, memory_order_release);
	return 1;
}

static inline void *
op_spsc_pop(op_spsc_t *q)
{
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
	uint64_t h = atomic_load_explicit(&q->head, memory_order_acquire);
	if (h == t)
		return NULL;
	void *item = q->slots[t & q->mask];
	atomic_store_explicit(&q->tail, t + 1, memory_order_release);
	return item;
}

static inline uint64_t
op_spsc_size(const op_spsc_t *q)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_acquire);
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
	return h - t;
}

static inline int
op_spsc_empty(const op_spsc_t *q)
{
	return op_spsc_size(q) == 0;
}

#endif /* OP_SPSC_H */
