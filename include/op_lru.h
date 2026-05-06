/*
 * libop: ophion support library.
 * op_lru.h: LRU cache with configurable capacity.
 *
 * A fixed-capacity least-recently-used cache built on top of op_htab (O(1)
 * lookup) with a doubly-linked eviction list (O(1) promote/evict).  The
 * combination gives true O(1) amortised get, set, and evict.
 *
 * When the cache is full and a new key is inserted, the least-recently-used
 * entry is evicted and the optional `evict_cb` is called so the caller can
 * release associated resources.
 *
 * Key/value ownership
 * -------------------
 * The cache stores raw void* pointers; it does NOT copy keys or values.
 * The caller is responsible for ensuring that key/value pointers remain valid
 * while the entry is live, and for freeing them in the evict_cb.
 *
 * Thread safety
 * -------------
 * NOT thread-safe.  Callers must provide external locking if needed.
 *
 * Usage
 * -----
 *   static void on_evict(void *key, void *val, void *ud) {
 *       op_free(key); op_free(val);
 *   }
 *
 *   op_lru_t *cache = op_lru_create("dns-cache", 4096, on_evict, NULL);
 *
 *   op_lru_set(cache, hostname_copy, rr_copy);
 *
 *   void *rr = op_lru_get(cache, hostname);  // NULL if not cached
 *   if (rr) { ... }
 *
 *   op_lru_destroy(cache, true);  // true = call evict_cb on remaining entries
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_lru.h directly; include op_lib.h"
#endif

#ifndef LIBOP_LRU_H
#define LIBOP_LRU_H

/* ---- types --------------------------------------------------------------- */

typedef void (*op_lru_evict_cb)(void *key, void *val, void *userdata);

/* Opaque handle. */
struct op_lru;
typedef struct op_lru op_lru_t;

/* ---- construction / destruction ------------------------------------------ */

/*
 * op_lru_create — allocate a new LRU cache.
 *
 *   name      — label for stats and debug output.
 *   capacity  — maximum number of entries (must be >= 1).
 *   evict_cb  — called when an entry is evicted (may be NULL).
 *   userdata  — passed verbatim to evict_cb.
 *
 * Keys are compared case-sensitively as NUL-terminated strings by default.
 * Use op_lru_create_istr() for IRC case-insensitive keys.
 */
op_lru_t *op_lru_create(const char *name, size_t capacity,
                          op_lru_evict_cb evict_cb, void *userdata);

/* IRC case-insensitive string keys (A-Z = a-z, plus []{}\|~^). */
op_lru_t *op_lru_create_istr(const char *name, size_t capacity,
                               op_lru_evict_cb evict_cb, void *userdata);

/*
 * op_lru_destroy — free the cache.
 *
 * If `call_evict` is true, the evict_cb is invoked for every remaining entry
 * so that the caller can free key/value memory.
 */
void op_lru_destroy(op_lru_t *lru, bool call_evict);

/* ---- lookup -------------------------------------------------------------- */

/*
 * op_lru_get — look up a key; returns the value or NULL if not cached.
 *
 * On hit, promotes the entry to the head of the recency list (most recently
 * used).  On miss, returns NULL without modifying the cache.
 */
void *op_lru_get(op_lru_t *lru, const void *key);

/* ---- insertion ----------------------------------------------------------- */

/*
 * op_lru_set — insert or update a key→value mapping.
 *
 * If the key already exists, its value is replaced (the old value is passed
 * to evict_cb if non-NULL, so the caller can free it).  The entry is
 * promoted to most-recently-used.
 *
 * If the cache is full and the key is new, the least-recently-used entry is
 * evicted (evict_cb called) before the new entry is inserted.
 */
void op_lru_set(op_lru_t *lru, void *key, void *val);

/* ---- deletion ------------------------------------------------------------ */

/*
 * op_lru_delete — remove the entry with the given key.
 *
 * If found, evict_cb is called with the entry's key and value, then the
 * entry is removed.  Returns true if found, false if not present.
 */
bool op_lru_delete(op_lru_t *lru, const void *key);

/*
 * op_lru_flush — evict all entries.
 *
 * Calls evict_cb for each entry.  The cache is empty and reusable afterwards.
 */
void op_lru_flush(op_lru_t *lru);

/* ---- introspection ------------------------------------------------------- */

size_t      op_lru_size    (const op_lru_t *lru);
size_t      op_lru_capacity(const op_lru_t *lru);
const char *op_lru_name    (const op_lru_t *lru);

/* ---- statistics ---------------------------------------------------------- */

typedef struct op_lru_stats
{
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t insertions;
    uint64_t updates;
} op_lru_stats_t;

void op_lru_stats(const op_lru_t *lru, op_lru_stats_t *out);

/* Reset all hit/miss/eviction counters to zero. */
void op_lru_stats_reset(op_lru_t *lru);

/* ---- iteration (for stats / debug; does not modify recency order) -------- */

/*
 * op_lru_foreach — iterate all entries from most- to least-recently-used.
 *
 * Calls cb(key, val, userdata) for each entry.  Returning non-zero from cb
 * aborts the iteration.  Do NOT insert or delete entries from cb.
 */
void op_lru_foreach(const op_lru_t *lru,
                     int (*cb)(const void *key, void *val, void *userdata),
                     void *userdata);

#endif /* LIBOP_LRU_H */
