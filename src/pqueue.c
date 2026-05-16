/*
 * libop: ophion support library.
 * pqueue.c: Pointer-based min-heap priority queue implementation.
 *
 * Binary min-heap using a flat array.  Classic heap invariant:
 *   heap[parent] <= heap[child]  (per the cmp function).
 *
 * Array indexing (1-based):
 *   parent(i)       = i / 2
 *   left_child(i)   = 2 * i
 *   right_child(i)  = 2 * i + 1
 *
 * We use 1-based indexing internally (slot 0 is unused) to make the
 * parent/child arithmetic branchless.
 *
 * Growth strategy: double capacity when full; shrink by half when size
 * drops to 1/4 of capacity (hysteresis avoids thrashing).
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
#include <op_pqueue.h>

#define PQ_DEFAULT_CAP  16

struct op_pqueue
{
    op_pqueue_cmp_t  cmp;       /* comparison function             */
    void           **heap;      /* 1-based array: heap[1..size]    */
    size_t           size;      /* number of elements              */
    size_t           cap;       /* allocated slots (heap[0..cap])  */
};

/* ---- internal helpers ---------------------------------------------------- */

/* Swap two heap slots. */
static inline void
pq_swap(void **heap, size_t a, size_t b)
{
    void *tmp = heap[a];
    heap[a]   = heap[b];
    heap[b]   = tmp;
}

/*
 * Grow or shrink the backing array.
 * new_cap must be >= size + 1 (to keep the 1-based sentinel at [0]).
 */
static void
pq_resize(op_pqueue_t *pq, size_t new_cap)
{
    pq->heap = op_realloc(pq->heap, (new_cap + 1) * sizeof(void *));
    pq->cap  = new_cap;
}

/*
 * Sift element at position i upward until the heap property is restored.
 * Used after inserting at the end.
 */
static void
pq_sift_up(op_pqueue_t *pq, size_t i)
{
    while (i > 1)
    {
        size_t parent = i / 2;
        if (pq->cmp(pq->heap[i], pq->heap[parent]) < 0)
        {
            pq_swap(pq->heap, i, parent);
            i = parent;
        }
        else
            break;
    }
}

/*
 * Sift element at position i downward until the heap property is restored.
 * Used after removing the root (replacing it with the last element).
 */
static void
pq_sift_down(op_pqueue_t *pq, size_t i)
{
    size_t n = pq->size;

    for (;;)
    {
        size_t smallest = i;
        size_t left     = 2 * i;
        size_t right    = 2 * i + 1;

        if (left <= n && pq->cmp(pq->heap[left], pq->heap[smallest]) < 0)
            smallest = left;
        if (right <= n && pq->cmp(pq->heap[right], pq->heap[smallest]) < 0)
            smallest = right;

        if (smallest == i)
            break;

        pq_swap(pq->heap, i, smallest);
        i = smallest;
    }
}

/* ---- construction / destruction ------------------------------------------ */

op_pqueue_t *
op_pqueue_create(op_pqueue_cmp_t cmp, size_t initial)
{
    size_t cap = (initial > 0) ? initial : PQ_DEFAULT_CAP;

    op_pqueue_t *pq = op_malloc(sizeof(*pq));
    pq->cmp  = cmp;
    pq->size = 0;
    pq->cap  = cap;
    /* Allocate cap+1 slots; slot 0 is a sentinel (unused). */
    pq->heap = op_malloc((cap + 1) * sizeof(void *));
    pq->heap[0] = NULL;
    return pq;
}

void
op_pqueue_destroy(op_pqueue_t *pq, op_pqueue_free_t free_cb, void *userdata)
{
    if (free_cb != NULL)
    {
        for (size_t i = 1; i <= pq->size; i++)
            free_cb(pq->heap[i], userdata);
    }
    op_free(pq->heap);
    op_free(pq);
}

/* ---- mutation ------------------------------------------------------------ */

void
op_pqueue_push(op_pqueue_t *pq, void *elem)
{
    /* Grow if full. */
    if (pq->size >= pq->cap)
    {
        size_t new_cap = pq->cap * 2;
        if (op_unlikely(new_cap < pq->cap || new_cap > SIZE_MAX / sizeof(void *)))
            abort();
        if (new_cap < PQ_DEFAULT_CAP)
            new_cap = PQ_DEFAULT_CAP;
        pq_resize(pq, new_cap);
    }

    pq->size++;
    pq->heap[pq->size] = elem;
    pq_sift_up(pq, pq->size);
}

void *
op_pqueue_pop(op_pqueue_t *pq)
{
    if (pq->size == 0)
        return NULL;

    void *top = pq->heap[1];

    /* Replace root with last element, shrink, sift down. */
    pq->heap[1] = pq->heap[pq->size];
    pq->size--;

    if (pq->size > 0)
        pq_sift_down(pq, 1);

    /* Shrink if we're using less than 1/4 of capacity. */
    if (pq->size > 0 && pq->size <= pq->cap / 4 && pq->cap > PQ_DEFAULT_CAP)
        pq_resize(pq, pq->cap / 2);

    return top;
}

bool
op_pqueue_remove(op_pqueue_t *pq, const void *elem)
{
    /* Linear scan for pointer equality. */
    for (size_t i = 1; i <= pq->size; i++)
    {
        if (pq->heap[i] != elem)
            continue;

        /* Replace with last element and restore heap. */
        pq->heap[i] = pq->heap[pq->size];
        pq->size--;

        if (i <= pq->size)
        {
            pq_sift_up(pq, i);
            pq_sift_down(pq, i);
        }
        return true;
    }
    return false;
}

/* ---- introspection ------------------------------------------------------- */

void *
op_pqueue_peek(const op_pqueue_t *pq)
{
    return pq->size > 0 ? pq->heap[1] : NULL;
}

size_t
op_pqueue_size(const op_pqueue_t *pq)
{
    return pq->size;
}

bool
op_pqueue_empty(const op_pqueue_t *pq)
{
    return pq->size == 0;
}

void
op_pqueue_foreach(const op_pqueue_t *pq,
                  int (*cb)(void *elem, void *userdata),
                  void *userdata)
{
    for (size_t i = 1; i <= pq->size; i++)
    {
        if (cb(pq->heap[i], userdata) != 0)
            break;
    }
}
