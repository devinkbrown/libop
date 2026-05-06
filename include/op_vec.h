/*
 * libop: ophion support library.
 * op_vec.h: Generic dynamic array (vector) of void pointers.
 *
 * A dynamically-resizing array.  All elements are stored as void pointers
 * so the vector can hold any pointer-sized value.  Indexing is 0-based.
 *
 * Two usage patterns are supported:
 *
 *   1. Embedded (stack / struct-member):
 *        op_vec_t v;
 *        op_vec_init(&v, 0);
 *        op_vec_push(&v, ptr);
 *        ...
 *        op_vec_fini(&v, free_cb, ud);
 *
 *   2. Heap-allocated (opaque handle):
 *        op_vec_t *v = op_vec_create(0);
 *        op_vec_push(v, ptr);
 *        ...
 *        op_vec_destroy(v, free_cb, ud);
 *
 * Typical uses in ophion:
 *   - Building ordered lists during SCAN / STATS pass, then sorting once.
 *   - Collecting pending callbacks before dispatching.
 *   - Any place that currently uses a fixed-size stack buffer or a linked
 *     list just for its dynamic-size property.
 *
 * Growth strategy: double capacity when full; shrink by half when occupancy
 * falls to ≤ 1/4 of capacity (hysteresis avoids push/pop thrashing).
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_VEC_H
#define LIBOP_VEC_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ---- type ---------------------------------------------------------------- */

typedef struct op_vec
{
    void  **data;   /* element array                           */
    size_t  size;   /* number of live elements                 */
    size_t  cap;    /* allocated slot count                    */
} op_vec_t;

/* Callback types */
typedef void (*op_vec_free_t)(void *elem, void *userdata);
typedef int  (*op_vec_cmp_t)(const void *a, const void *b);
typedef int  (*op_vec_each_t)(void *elem, void *userdata);

/* ---- embedded-use init / fini -------------------------------------------- */

/*
 * op_vec_init — initialise an op_vec_t in place.
 *
 * initial_cap: hint for initial allocation (0 → library default).
 * After init, size == 0 and cap >= initial_cap.
 */
void op_vec_init(op_vec_t *v, size_t initial_cap);

/*
 * op_vec_fini — release internal storage.
 *
 * If free_cb is non-NULL it is called for each remaining element first.
 * The op_vec_t itself is NOT freed (caller owns it).
 */
void op_vec_fini(op_vec_t *v, op_vec_free_t free_cb, void *userdata);

/* ---- heap-allocated handle ----------------------------------------------- */

/*
 * op_vec_create — allocate and initialise a heap-owned vector.
 * Returns NULL on OOM (consistent with op_malloc behaviour: aborts).
 */
op_vec_t *op_vec_create(size_t initial_cap);

/*
 * op_vec_destroy — free elements (if free_cb given) then free the vector.
 */
void op_vec_destroy(op_vec_t *v, op_vec_free_t free_cb, void *userdata);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_vec_push — append elem to the end.  Amortised O(1).
 */
void op_vec_push(op_vec_t *v, void *elem);

/*
 * op_vec_pop — remove and return the last element.  O(1).
 * Returns NULL if the vector is empty.
 */
void *op_vec_pop(op_vec_t *v);

/*
 * op_vec_insert — insert elem at position idx, shifting later elements right.
 * O(n).  idx == size is equivalent to op_vec_push.
 */
void op_vec_insert(op_vec_t *v, size_t idx, void *elem);

/*
 * op_vec_remove — remove element at idx, shifting later elements left.  O(n).
 * Returns the removed element.
 */
void *op_vec_remove(op_vec_t *v, size_t idx);

/*
 * op_vec_remove_fast — remove element at idx by swapping with the last
 * element.  O(1) but does NOT preserve order.
 * Returns the removed element.
 */
void *op_vec_remove_fast(op_vec_t *v, size_t idx);

/*
 * op_vec_clear — remove all elements.  O(n) if free_cb given, else O(1).
 * Does NOT release the backing buffer (use op_vec_shrink afterwards).
 */
void op_vec_clear(op_vec_t *v, op_vec_free_t free_cb, void *userdata);

/* ---- indexed access ------------------------------------------------------ */

/*
 * op_vec_get — return element at idx.  Behaviour undefined if idx >= size.
 */
static inline void *
op_vec_get(const op_vec_t *v, size_t idx)
{
    return v->data[idx];
}

/*
 * op_vec_set — replace element at idx.  Behaviour undefined if idx >= size.
 */
static inline void
op_vec_set(op_vec_t *v, size_t idx, void *elem)
{
    v->data[idx] = elem;
}

/* ---- introspection ------------------------------------------------------- */

static inline size_t op_vec_size(const op_vec_t *v)  { return v->size; }
static inline bool   op_vec_empty(const op_vec_t *v) { return v->size == 0; }

/*
 * op_vec_reserve — ensure capacity for at least new_cap elements without
 * growing further than necessary.  Does not shrink.
 */
void op_vec_reserve(op_vec_t *v, size_t new_cap);

/*
 * op_vec_shrink — release excess backing storage so cap == size.
 */
void op_vec_shrink(op_vec_t *v);

/* ---- searching / sorting ------------------------------------------------- */

/*
 * op_vec_find — linear search.  Returns the first index where cmp(elem, key)
 * == 0, or (size_t)-1 if not found.
 */
size_t op_vec_find(const op_vec_t *v, const void *key, op_vec_cmp_t cmp);

/*
 * op_vec_bsearch — binary search on a sorted vector.  Returns the first index
 * where cmp(elem, key) == 0, or (size_t)-1 if not found.
 * The vector MUST be sorted by the same cmp before calling this.
 */
size_t op_vec_bsearch(const op_vec_t *v, const void *key, op_vec_cmp_t cmp);

/*
 * op_vec_sort — sort the vector in place using cmp.
 * cmp follows qsort convention; both arguments are pointers to void*.
 */
void op_vec_sort(op_vec_t *v, int (*cmp)(const void *, const void *));

/* ---- iteration ----------------------------------------------------------- */

/*
 * op_vec_foreach — call cb(elem, userdata) for each element in order.
 * Return non-zero from cb to stop early.
 */
void op_vec_foreach(const op_vec_t *v, op_vec_each_t cb, void *userdata);

/*
 * OP_VEC_FOREACH — lightweight iteration macro (no break support needed):
 *   op_vec_t v = ...;
 *   size_t i;
 *   void *elem;
 *   OP_VEC_FOREACH(&v, i, elem) { use(elem); }
 */
#define OP_VEC_FOREACH(v, idx, elem)                              \
    for ((idx) = 0;                                               \
         (idx) < (v)->size && ((elem) = (v)->data[(idx)], 1);    \
         (idx)++)

#endif /* LIBOP_VEC_H */
