/*
 * libop: ophion support library.
 * lru.c: LRU cache implementation.
 *
 * Internal layout
 * ---------------
 * Each entry is an `op_lru_entry_t` allocated from the block heap.  Entries
 * are linked in a doubly-linked recency list (head = most recently used,
 * tail = least recently used) AND indexed by an `op_htab` for O(1) lookup.
 *
 * Operations:
 *   get:    htab lookup → promote entry to list head → O(1)
 *   set:    htab lookup → (update or insert) → promote/insert at head →
 *           evict tail if over capacity → O(1)
 *   delete: htab lookup → unlink from list → O(1)
 *   evict:  unlink tail → htab delete → evict_cb → O(1)
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
#include <op_lru.h>

/* ---- internal types ------------------------------------------------------ */

typedef struct op_lru_entry
{
    void               *key;
    void               *val;
    struct op_lru_entry *prev;   /* more-recently-used neighbour (or NULL) */
    struct op_lru_entry *next;   /* less-recently-used neighbour (or NULL) */
} op_lru_entry_t;

struct op_lru
{
    op_htab         *ht;        /* key → op_lru_entry* */
    op_lru_entry_t  *head;      /* most recently used  */
    op_lru_entry_t  *tail;      /* least recently used */
    size_t           size;      /* current entry count */
    size_t           capacity;  /* maximum entry count */
    op_lru_evict_cb  evict_cb;
    void            *userdata;
    const char      *name;

    /* statistics */
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t insertions;
    uint64_t updates;
};

/* ---- entry allocation ---------------------------------------------------- */

static inline op_lru_entry_t *
entry_alloc(void)
{
    /* op_malloc zero-initialises, so prev/next start as NULL. */
    return op_malloc(sizeof(op_lru_entry_t));
}

static inline void
entry_free(op_lru_entry_t *e)
{
    op_free(e);
}

/* ---- list helpers -------------------------------------------------------- */

static inline void
list_push_head(op_lru_t *lru, op_lru_entry_t *e)
{
    e->prev = NULL;
    e->next = lru->head;
    if (lru->head)
        lru->head->prev = e;
    else
        lru->tail = e;
    lru->head = e;
}

static inline void
list_unlink(op_lru_t *lru, op_lru_entry_t *e)
{
    if (e->prev)
        e->prev->next = e->next;
    else
        lru->head = e->next;

    if (e->next)
        e->next->prev = e->prev;
    else
        lru->tail = e->prev;

    e->prev = e->next = NULL;
}

static inline void
list_promote(op_lru_t *lru, op_lru_entry_t *e)
{
    if (lru->head == e)
        return;
    list_unlink(lru, e);
    list_push_head(lru, e);
}

/* ---- eviction ------------------------------------------------------------ */

static void
lru_evict_tail(op_lru_t *lru)
{
    op_lru_entry_t *e = lru->tail;
    if (!e)
        return;

    list_unlink(lru, e);
    op_htab_del(lru->ht, e->key);
    lru->size--;
    lru->evictions++;

    if (lru->evict_cb)
        lru->evict_cb(e->key, e->val, lru->userdata);

    entry_free(e);
}

/* ---- construction -------------------------------------------------------- */

static op_lru_t *
lru_create_common(const char *name, size_t capacity,
                  op_lru_evict_cb evict_cb, void *userdata,
                  op_htab *ht)
{
    
    op_lru_t *lru = op_malloc(sizeof(*lru));
    lru->ht        = ht;
    lru->head      = lru->tail = NULL;
    lru->size      = 0;
    lru->capacity  = (capacity > 0) ? capacity : 1;
    lru->evict_cb  = evict_cb;
    lru->userdata  = userdata;
    lru->name      = name;
    lru->hits = lru->misses = lru->evictions = lru->insertions = lru->updates = 0;
    return lru;
}

op_lru_t *
op_lru_create(const char *name, size_t capacity,
               op_lru_evict_cb evict_cb, void *userdata)
{
    size_t initial = capacity < 16 ? 16 : capacity;
    return lru_create_common(name, capacity, evict_cb, userdata,
                             op_htab_create_str(name, initial));
}

op_lru_t *
op_lru_create_istr(const char *name, size_t capacity,
                    op_lru_evict_cb evict_cb, void *userdata)
{
    size_t initial = capacity < 16 ? 16 : capacity;
    return lru_create_common(name, capacity, evict_cb, userdata,
                             op_htab_create_istr(name, initial));
}

/* ---- destruction --------------------------------------------------------- */

void
op_lru_destroy(op_lru_t *lru, bool call_evict)
{
    op_lru_entry_t *e = lru->head;
    while (e)
    {
        op_lru_entry_t *next = e->next;
        if (call_evict && lru->evict_cb)
            lru->evict_cb(e->key, e->val, lru->userdata);
        entry_free(e);
        e = next;
    }
    op_htab_destroy(lru->ht, NULL, NULL);
    op_free(lru);
}

/* ---- lookup -------------------------------------------------------------- */

void *
op_lru_get(op_lru_t *lru, const void *key)
{
    op_lru_entry_t *e = op_htab_get(lru->ht, key);
    if (!e)
    {
        lru->misses++;
        return NULL;
    }
    lru->hits++;
    list_promote(lru, e);
    return e->val;
}

/* ---- insertion ----------------------------------------------------------- */

void
op_lru_set(op_lru_t *lru, void *key, void *val)
{
    op_lru_entry_t *e = op_htab_get(lru->ht, key);
    if (e)
    {
        /* Update existing entry. */
        if (lru->evict_cb && e->val != val)
            lru->evict_cb(e->key, e->val, lru->userdata);
        e->key = key;
        e->val = val;
        list_promote(lru, e);
        lru->updates++;
        return;
    }

    /* Evict LRU entry if at capacity. */
    if (lru->size >= lru->capacity)
        lru_evict_tail(lru);

    e = entry_alloc();
    e->key = key;
    e->val = val;
    e->prev = e->next = NULL;

    op_htab_set(lru->ht, key, e, NULL);
    list_push_head(lru, e);
    lru->size++;
    lru->insertions++;
}

/* ---- deletion ------------------------------------------------------------ */

bool
op_lru_delete(op_lru_t *lru, const void *key)
{
    op_lru_entry_t *e = op_htab_del(lru->ht, key);
    if (!e)
        return false;

    list_unlink(lru, e);
    lru->size--;

    if (lru->evict_cb)
        lru->evict_cb(e->key, e->val, lru->userdata);

    entry_free(e);
    return true;
}

void
op_lru_flush(op_lru_t *lru)
{
    while (lru->tail)
        lru_evict_tail(lru);
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_lru_size(const op_lru_t *lru)
{
    return lru->size;
}

size_t
op_lru_capacity(const op_lru_t *lru)
{
    return lru->capacity;
}

const char *
op_lru_name(const op_lru_t *lru)
{
    return lru->name;
}

/* ---- statistics ---------------------------------------------------------- */

void
op_lru_stats(const op_lru_t *lru, op_lru_stats_t *out)
{
    out->hits       = lru->hits;
    out->misses     = lru->misses;
    out->evictions  = lru->evictions;
    out->insertions = lru->insertions;
    out->updates    = lru->updates;
}

void
op_lru_stats_reset(op_lru_t *lru)
{
    lru->hits = lru->misses = lru->evictions = lru->insertions = lru->updates = 0;
}

/* ---- iteration ----------------------------------------------------------- */

void
op_lru_foreach(const op_lru_t *lru,
                int (*cb)(const void *key, void *val, void *userdata),
                void *userdata)
{
    for (op_lru_entry_t *e = lru->head; e != NULL; e = e->next)
    {
        if (cb(e->key, e->val, userdata) != 0)
            break;
    }
}
