/*
 * libop: ophion support library.
 * vec.c: Generic dynamic array implementation.
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
#include <op_vec.h>

#define VEC_DEFAULT_CAP  8

/* ---- internal helpers ---------------------------------------------------- */

static void
vec_resize(op_vec_t *v, size_t new_cap)
{
    v->data = op_realloc(v->data, new_cap * sizeof(void *));
    v->cap  = new_cap;
}

static void
vec_maybe_grow(op_vec_t *v)
{
    if (v->size < v->cap)
        return;
    size_t new_cap = v->cap ? v->cap * 2 : VEC_DEFAULT_CAP;
    if (op_unlikely(new_cap < v->cap || new_cap > SIZE_MAX / sizeof(void *)))
        abort();
    vec_resize(v, new_cap);
}

static void
vec_maybe_shrink(op_vec_t *v)
{
    if (v->cap <= VEC_DEFAULT_CAP)
        return;
    if (v->size > v->cap / 4)
        return;
    size_t new_cap = v->cap / 2;
    if (new_cap < VEC_DEFAULT_CAP)
        new_cap = VEC_DEFAULT_CAP;
    vec_resize(v, new_cap);
}

/* ---- init / fini --------------------------------------------------------- */

void
op_vec_init(op_vec_t *v, size_t initial_cap)
{
    size_t cap = initial_cap > 0 ? initial_cap : VEC_DEFAULT_CAP;
    v->data = op_malloc(cap * sizeof(void *));
    v->size = 0;
    v->cap  = cap;
}

void
op_vec_fini(op_vec_t *v, op_vec_free_t free_cb, void *userdata)
{
    if (free_cb != NULL)
    {
        for (size_t i = 0; i < v->size; i++)
            free_cb(v->data[i], userdata);
    }
    op_free(v->data);
    v->data = NULL;
    v->size = 0;
    v->cap  = 0;
}

/* ---- heap-allocated handle ----------------------------------------------- */

op_vec_t *
op_vec_create(size_t initial_cap)
{
    op_vec_t *v = op_malloc(sizeof(*v));
    op_vec_init(v, initial_cap);
    return v;
}

void
op_vec_destroy(op_vec_t *v, op_vec_free_t free_cb, void *userdata)
{
    op_vec_fini(v, free_cb, userdata);
    op_free(v);
}

/* ---- mutation ------------------------------------------------------------ */

void
op_vec_push(op_vec_t *v, void *elem)
{
    vec_maybe_grow(v);
    v->data[v->size++] = elem;
}

void *
op_vec_pop(op_vec_t *v)
{
    if (v->size == 0)
        return NULL;
    void *elem = v->data[--v->size];
    vec_maybe_shrink(v);
    return elem;
}

void
op_vec_insert(op_vec_t *v, size_t idx, void *elem)
{
    /* idx == size is a push; idx > size is out of bounds — treat as push. */
    if (idx > v->size)
        idx = v->size;
    vec_maybe_grow(v);
    /* Shift elements [idx, size) one position to the right. */
    if (idx < v->size)
        memmove(&v->data[idx + 1], &v->data[idx],
                (v->size - idx) * sizeof(void *));
    v->data[idx] = elem;
    v->size++;
}

void *
op_vec_remove(op_vec_t *v, size_t idx)
{
    if (idx >= v->size)
        return NULL;
    void *elem = v->data[idx];
    if (idx < v->size - 1)
        memmove(&v->data[idx], &v->data[idx + 1],
                (v->size - idx - 1) * sizeof(void *));
    v->size--;
    vec_maybe_shrink(v);
    return elem;
}

void *
op_vec_remove_fast(op_vec_t *v, size_t idx)
{
    if (idx >= v->size)
        return NULL;
    void *elem = v->data[idx];
    v->data[idx] = v->data[--v->size];
    vec_maybe_shrink(v);
    return elem;
}

void
op_vec_clear(op_vec_t *v, op_vec_free_t free_cb, void *userdata)
{
    if (free_cb != NULL)
    {
        for (size_t i = 0; i < v->size; i++)
            free_cb(v->data[i], userdata);
    }
    v->size = 0;
}

/* ---- capacity ------------------------------------------------------------ */

void
op_vec_reserve(op_vec_t *v, size_t new_cap)
{
    if (new_cap > v->cap)
        vec_resize(v, new_cap);
}

void
op_vec_shrink(op_vec_t *v)
{
    if (v->size == 0)
    {
        op_free(v->data);
        v->data = op_malloc(VEC_DEFAULT_CAP * sizeof(void *));
        v->cap  = VEC_DEFAULT_CAP;
        return;
    }
    if (v->size < v->cap)
        vec_resize(v, v->size);
}

/* ---- search / sort ------------------------------------------------------- */

size_t
op_vec_find(const op_vec_t *v, const void *key, op_vec_cmp_t cmp)
{
    for (size_t i = 0; i < v->size; i++)
    {
        if (cmp(v->data[i], key) == 0)
            return i;
    }
    return (size_t)-1;
}

size_t
op_vec_bsearch(const op_vec_t *v, const void *key, op_vec_cmp_t cmp)
{
    size_t lo = 0, hi = v->size;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int c = cmp(v->data[mid], key);
        if (c == 0)
            return mid;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return (size_t)-1;
}

void
op_vec_sort(op_vec_t *v, int (*cmp)(const void *, const void *))
{
    if (v->size > 1)
        qsort(v->data, v->size, sizeof(void *), cmp);
}

/* ---- iteration ----------------------------------------------------------- */

void
op_vec_foreach(const op_vec_t *v, op_vec_each_t cb, void *userdata)
{
    for (size_t i = 0; i < v->size; i++)
    {
        if (cb(v->data[i], userdata) != 0)
            break;
    }
}
