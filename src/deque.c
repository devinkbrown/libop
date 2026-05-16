/*
 * libop: ophion support library.
 * deque.c: Double-ended queue (circular-buffer).
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

#define DEFAULT_CAP 8

/* ---- capacity helpers ---------------------------------------------------- */

/* Round n up to the next power of two (minimum 8). */
static size_t
next_pow2(size_t n)
{
    if (n < DEFAULT_CAP)
        return DEFAULT_CAP;
    if (op_unlikely(n > SIZE_MAX / 2))
        abort();
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return n + 1;
}

/* Physical slot index for logical index i within a deque of cap `cap`. */
static inline size_t
slot(const op_deque_t *d, size_t i)
{
    return (d->head + i) & (d->cap - 1);
}

/* ---- growth -------------------------------------------------------------- */

static void
deque_grow(op_deque_t *d)
{
    size_t  new_cap  = d->cap * 2;
    if (op_unlikely(new_cap < d->cap || new_cap > SIZE_MAX / sizeof(void *)))
        abort();
    void  **new_slots = op_malloc(new_cap * sizeof(void *));

    /* Linearise the existing elements into the new buffer front-to-back. */
    for (size_t i = 0; i < d->size; i++)
        new_slots[i] = d->slots[slot(d, i)];

    op_free(d->slots);
    d->slots = new_slots;
    d->head  = 0;
    d->cap   = new_cap;
}

/* ---- lifecycle ----------------------------------------------------------- */

void
op_deque_init(op_deque_t *d, size_t hint)
{
    d->cap   = next_pow2(hint);
    d->slots = op_malloc(d->cap * sizeof(void *));
    d->head  = 0;
    d->size  = 0;
}

void
op_deque_fini(op_deque_t *d)
{
    op_free(d->slots);
    d->slots = NULL;
    d->head  = 0;
    d->size  = 0;
    d->cap   = 0;
}

op_deque_t *
op_deque_create(size_t hint)
{
    op_deque_t *d = op_malloc(sizeof(*d));
    op_deque_init(d, hint);
    return d;
}

void
op_deque_destroy(op_deque_t *d)
{
    if (d == NULL)
        return;
    op_free(d->slots);
    op_free(d);
}

/* ---- push / pop ---------------------------------------------------------- */

void
op_deque_push_back(op_deque_t *d, void *item)
{
    if (d->size == d->cap)
        deque_grow(d);
    d->slots[slot(d, d->size)] = item;
    d->size++;
}

void
op_deque_push_front(op_deque_t *d, void *item)
{
    if (d->size == d->cap)
        deque_grow(d);
    d->head = (d->head - 1) & (d->cap - 1);
    d->slots[d->head] = item;
    d->size++;
}

void *
op_deque_pop_back(op_deque_t *d)
{
    if (d->size == 0)
        return NULL;
    d->size--;
    return d->slots[slot(d, d->size)];
}

void *
op_deque_pop_front(op_deque_t *d)
{
    if (d->size == 0)
        return NULL;
    void *item = d->slots[d->head];
    d->head    = (d->head + 1) & (d->cap - 1);
    d->size--;
    return item;
}

/* ---- peek ---------------------------------------------------------------- */

void *
op_deque_front(const op_deque_t *d)
{
    return d->size ? d->slots[d->head] : NULL;
}

void *
op_deque_back(const op_deque_t *d)
{
    return d->size ? d->slots[slot(d, d->size - 1)] : NULL;
}

/* ---- random access ------------------------------------------------------- */

void *
op_deque_at(const op_deque_t *d, size_t i)
{
    if (i >= d->size)
        return NULL;
    return d->slots[slot(d, i)];
}

void
op_deque_set(op_deque_t *d, size_t i, void *item)
{
    if (i >= d->size)
        return;
    d->slots[slot(d, i)] = item;
}

/* ---- bulk ---------------------------------------------------------------- */

void
op_deque_clear(op_deque_t *d)
{
    d->head = 0;
    d->size = 0;
}

void
op_deque_reserve(op_deque_t *d, size_t n)
{
    if (n <= d->cap)
        return;
    size_t  new_cap   = next_pow2(n);
    void  **new_slots = op_malloc(new_cap * sizeof(void *));
    for (size_t i = 0; i < d->size; i++)
        new_slots[i] = d->slots[slot(d, i)];
    op_free(d->slots);
    d->slots = new_slots;
    d->head  = 0;
    d->cap   = new_cap;
}

/* ---- iteration ----------------------------------------------------------- */

void
op_deque_foreach(const op_deque_t *d, op_deque_each_t fn, void *ud)
{
    for (size_t i = 0; i < d->size; i++)
    {
        if (!fn(d->slots[slot(d, i)], ud))
            return;
    }
}
