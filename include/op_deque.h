/*
 * libop: ophion support library.
 * op_deque.h: Double-ended queue (circular-buffer deque of void *).
 *
 * Provides O(1) amortized push/pop at both ends and O(1) random access
 * by index.  Grows automatically when capacity is reached (2× realloc).
 *
 * Not thread-safe — protect with op_mutex_t if shared across threads.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_deque.h directly; include op_lib.h"
#endif

#ifndef LIBOP_DEQUE_H
#define LIBOP_DEQUE_H

/* ---- types --------------------------------------------------------------- */

typedef struct op_deque
{
    void   **slots;   /* circular buffer of (cap) pointers */
    size_t   head;    /* index of the first valid element  */
    size_t   size;    /* number of live elements           */
    size_t   cap;     /* allocated capacity (power of two) */
} op_deque_t;

typedef bool (*op_deque_each_t)(void *item, void *ud);

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_deque_create — allocate a deque with at least `hint` initial capacity.
 * hint=0 → default capacity (8).  Capacity is always a power of two.
 */
op_deque_t *op_deque_create(size_t hint);
void        op_deque_destroy(op_deque_t *d);

/* op_deque_init / op_deque_fini — for stack-allocated deques. */
void op_deque_init(op_deque_t *d, size_t hint);
void op_deque_fini(op_deque_t *d);

/* ---- push / pop ---------------------------------------------------------- */

void  op_deque_push_back (op_deque_t *d, void *item);
void  op_deque_push_front(op_deque_t *d, void *item);

void *op_deque_pop_back (op_deque_t *d);   /* NULL if empty */
void *op_deque_pop_front(op_deque_t *d);   /* NULL if empty */

/* ---- peek ---------------------------------------------------------------- */

void *op_deque_front(const op_deque_t *d);  /* NULL if empty */
void *op_deque_back (const op_deque_t *d);  /* NULL if empty */

/* ---- random access ------------------------------------------------------- */

/*
 * op_deque_at — O(1) access by logical index (0 = front).
 * Returns NULL and does nothing if i >= size.
 */
void *op_deque_at(const op_deque_t *d, size_t i);
void  op_deque_set(op_deque_t *d, size_t i, void *item);

/* ---- bulk ---------------------------------------------------------------- */

void op_deque_clear(op_deque_t *d);

/*
 * op_deque_reserve — ensure capacity for at least `n` total elements
 * without triggering a resize during subsequent pushes.
 */
void op_deque_reserve(op_deque_t *d, size_t n);

/* ---- iteration ----------------------------------------------------------- */

/*
 * op_deque_foreach — call fn(item, ud) for each element front-to-back.
 * Stops early if fn returns false.
 */
void op_deque_foreach(const op_deque_t *d, op_deque_each_t fn, void *ud);

/* ---- introspection ------------------------------------------------------- */

static inline size_t op_deque_size (const op_deque_t *d) { return d->size;       }
static inline size_t op_deque_cap  (const op_deque_t *d) { return d->cap;        }
static inline bool   op_deque_empty(const op_deque_t *d) { return d->size == 0;  }

#endif /* LIBOP_DEQUE_H */
