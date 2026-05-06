/*
 * libop: ophion support library.
 * op_pqueue.h: Pointer-based min-heap priority queue.
 *
 * A dynamically-resizing binary min-heap.  Elements are void pointers;
 * ordering is determined by a caller-supplied comparison function.
 *
 * Interface:
 *   op_pqueue_t *pq = op_pqueue_create(cmp, NULL);
 *   op_pqueue_push(pq, element);
 *   void *top = op_pqueue_peek(pq);   // smallest, O(1)
 *   void *top = op_pqueue_pop(pq);    // remove and return smallest, O(log n)
 *   size_t n  = op_pqueue_size(pq);
 *   bool empty = op_pqueue_empty(pq);
 *   op_pqueue_destroy(pq, free_cb, userdata);
 *
 * The comparison function follows qsort() convention:
 *   int cmp(const void *a, const void *b)
 *   Returns < 0 if a < b (a should be at the top), > 0 if a > b, 0 if equal.
 *
 * Typical uses in ophion:
 *   - Event scheduling: elements are (timestamp, callback) pairs; pop fires
 *     the next due event.
 *   - Per-connection priority: serve clients with lowest debt first.
 *   - Bandwidth shaping: tokens bucket + priority queue of queued writes.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_PQUEUE_H
#define LIBOP_PQUEUE_H

#include <stddef.h>
#include <stdbool.h>

/* ---- opaque type --------------------------------------------------------- */

typedef struct op_pqueue op_pqueue_t;

/* Comparison function: return <0 if a should be above b (lower priority
 * number = higher precedence in a min-heap). */
typedef int (*op_pqueue_cmp_t)(const void *a, const void *b);

/* Callback for op_pqueue_destroy — called for each remaining element. */
typedef void (*op_pqueue_free_t)(void *elem, void *userdata);

/* ---- construction / destruction ------------------------------------------ */

/*
 * op_pqueue_create — allocate an empty priority queue.
 *
 * cmp      — comparison function (must not be NULL)
 * initial  — initial capacity hint (0 → library-chosen default)
 *
 * Returns a pointer to the queue; aborts on OOM (consistent with op_malloc).
 */
op_pqueue_t *op_pqueue_create(op_pqueue_cmp_t cmp, size_t initial);

/*
 * op_pqueue_destroy — free the queue and, optionally, its elements.
 *
 * If free_cb is non-NULL it is called for each element still in the queue
 * before the queue is freed.  Pass NULL to skip element cleanup.
 */
void op_pqueue_destroy(op_pqueue_t *pq, op_pqueue_free_t free_cb, void *userdata);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_pqueue_push — insert an element.  O(log n).
 */
void op_pqueue_push(op_pqueue_t *pq, void *elem);

/*
 * op_pqueue_pop — remove and return the minimum element.  O(log n).
 * Returns NULL if the queue is empty.
 */
void *op_pqueue_pop(op_pqueue_t *pq);

/*
 * op_pqueue_remove — remove a specific element by pointer equality.  O(n).
 *
 * Returns true if the element was found and removed.  Useful for cancelling
 * an already-queued timer or event.
 */
bool op_pqueue_remove(op_pqueue_t *pq, const void *elem);

/* ---- introspection ------------------------------------------------------- */

/*
 * op_pqueue_peek — return (without removing) the minimum element.  O(1).
 * Returns NULL if the queue is empty.
 */
void *op_pqueue_peek(const op_pqueue_t *pq);

/* Number of elements currently in the queue. */
size_t op_pqueue_size(const op_pqueue_t *pq);

/* True if the queue has no elements. */
bool op_pqueue_empty(const op_pqueue_t *pq);

/*
 * op_pqueue_foreach — iterate over all elements in heap order (not sorted).
 *
 * Calls cb(elem, userdata) for each element.  Return non-zero from cb to
 * stop early.  Do NOT push or pop during iteration.
 */
void op_pqueue_foreach(const op_pqueue_t *pq,
                       int (*cb)(void *elem, void *userdata),
                       void *userdata);

#endif /* LIBOP_PQUEUE_H */
