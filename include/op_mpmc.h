/*
 * libop/include/op_mpmc.h — Vyukov bounded MPMC queue.
 *
 * Multi-producer, multi-consumer bounded queue. One CAS per enqueue,
 * one CAS per dequeue. Per-slot sequence counters eliminate ABA.
 * Power-of-two capacity required.
 *
 * Based on Dmitry Vyukov's design (1024cores.net).
 *
 * Copyright (c) 2026 Ophion Development Team.  GPL v2.
 */

#ifndef OP_MPMC_H
#define OP_MPMC_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef OP_CACHELINE
#define OP_CACHELINE 64
#endif

typedef struct {
	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) seq;
	void             *data;
	char              _pad[OP_CACHELINE - sizeof(_Atomic(uint64_t)) - sizeof(void *)];
} op_mpmc_slot_t;

typedef struct {
	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) head;
	char _pad0[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	_Alignas(OP_CACHELINE)
	_Atomic(uint64_t) tail;
	char _pad1[OP_CACHELINE - sizeof(_Atomic(uint64_t))];

	uint64_t         mask;
	op_mpmc_slot_t  *slots;
} op_mpmc_t;

static inline int
op_mpmc_init(op_mpmc_t *q, uint64_t capacity)
{
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return -1;

	memset(q, 0, sizeof(*q));
	q->mask = capacity - 1;
	q->slots = (op_mpmc_slot_t *)calloc((size_t)capacity, sizeof(op_mpmc_slot_t));
	if (!q->slots)
		return -1;

	for (uint64_t i = 0; i < capacity; i++)
		atomic_store_explicit(&q->slots[i].seq, i, memory_order_relaxed);

	return 0;
}

static inline void
op_mpmc_destroy(op_mpmc_t *q)
{
	free(q->slots);
	q->slots = NULL;
}

static inline int
op_mpmc_push(op_mpmc_t *q, void *item)
{
	uint64_t pos = atomic_load_explicit(&q->head, memory_order_relaxed);

	for (;;) {
		op_mpmc_slot_t *slot = &q->slots[pos & q->mask];
		uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		int64_t diff = (int64_t)seq - (int64_t)pos;

		if (diff == 0) {
			if (atomic_compare_exchange_weak_explicit(
				    &q->head, &pos, pos + 1,
				    memory_order_relaxed,
				    memory_order_relaxed)) {
				slot->data = item;
				atomic_store_explicit(&slot->seq, pos + 1,
				                      memory_order_release);
				return 1;
			}
		} else if (diff < 0) {
			return 0;  /* full */
		} else {
			pos = atomic_load_explicit(&q->head, memory_order_relaxed);
		}
	}
}

static inline void *
op_mpmc_pop(op_mpmc_t *q)
{
	uint64_t pos = atomic_load_explicit(&q->tail, memory_order_relaxed);

	for (;;) {
		op_mpmc_slot_t *slot = &q->slots[pos & q->mask];
		uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
		int64_t diff = (int64_t)seq - (int64_t)(pos + 1);

		if (diff == 0) {
			if (atomic_compare_exchange_weak_explicit(
				    &q->tail, &pos, pos + 1,
				    memory_order_relaxed,
				    memory_order_relaxed)) {
				void *item = slot->data;
				atomic_store_explicit(&slot->seq, pos + q->mask + 1,
				                      memory_order_release);
				return item;
			}
		} else if (diff < 0) {
			return NULL;  /* empty */
		} else {
			pos = atomic_load_explicit(&q->tail, memory_order_relaxed);
		}
	}
}

static inline uint64_t
op_mpmc_size(const op_mpmc_t *q)
{
	uint64_t h = atomic_load_explicit(&q->head, memory_order_acquire);
	uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
	return h - t;
}

#endif /* OP_MPMC_H */
