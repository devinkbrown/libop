/*
 * libop: ophion support library.
 * op_trie.h: Ternary search trie (TST) for string keys.
 *
 * A ternary search trie stores string→void* mappings with O(k) insert,
 * lookup, and delete (k = key length), and supports efficient prefix
 * enumeration.  Keys are NUL-terminated C strings.
 *
 * Unlike a hash map, the TST preserves lexicographic order of keys and
 * allows:
 *   op_trie_prefix(t, prefix, fn, ud) — all keys with a given prefix
 *   op_trie_wildcard(t, pat, fn, ud)  — glob-style * and ? matching
 *
 * Case sensitivity is configurable at creation time.  When icase=true
 * all keys are folded to lower-case on insert/lookup.
 *
 * Not thread-safe — protect externally when shared across threads.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_trie.h directly; include op_lib.h"
#endif

#ifndef LIBOP_TRIE_H
#define LIBOP_TRIE_H

/* ---- callback types ------------------------------------------------------ */

/*
 * op_trie_each_t — called for each matching key.
 * key — the NUL-terminated key string.
 * val — stored value (may be NULL).
 * ud  — caller's context pointer.
 * Return true to continue, false to stop early.
 */
typedef bool (*op_trie_each_t)(const char *key, void *val, void *ud);

typedef void (*op_trie_free_t)(void *val, void *ud);

/* ---- opaque handle ------------------------------------------------------- */

struct op_trie;
typedef struct op_trie op_trie_t;

/* ---- lifecycle ----------------------------------------------------------- */

op_trie_t *op_trie_create(const char *name, bool icase);
void       op_trie_destroy(op_trie_t *t, op_trie_free_t free_fn, void *ud);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_trie_set — insert or update key→val.
 *
 * If old_val is non-NULL, *old_val receives the previous value (or NULL if
 * this is a new key).
 *
 * Returns 1 if a new key was inserted, 0 if an existing key was updated.
 */
int op_trie_set(op_trie_t *t, const char *key, void *val, void **old_val);

/*
 * op_trie_del — remove key.
 *
 * Returns the old value if found, NULL if the key was not present.
 * Note: NULL cannot be distinguished from "not found" — use op_trie_has()
 * if you need to store NULL values.
 */
void *op_trie_del(op_trie_t *t, const char *key);

/* ---- lookup -------------------------------------------------------------- */

void *op_trie_get(const op_trie_t *t, const char *key);
bool  op_trie_has(const op_trie_t *t, const char *key);

/* ---- enumeration --------------------------------------------------------- */

/*
 * op_trie_foreach — call fn for every key in the trie (lexicographic order).
 * Stops early if fn returns false.
 */
void op_trie_foreach(const op_trie_t *t, op_trie_each_t fn, void *ud);

/*
 * op_trie_prefix — call fn for every key that starts with prefix.
 * prefix="" matches all keys (same as op_trie_foreach).
 * Stops early if fn returns false.
 */
void op_trie_prefix(const op_trie_t *t, const char *prefix,
                    op_trie_each_t fn, void *ud);

/*
 * op_trie_wildcard — call fn for every key matching the glob pattern.
 * Supports '*' (zero or more chars) and '?' (exactly one char).
 * This is O(n) in the worst case; use prefix() when possible.
 */
void op_trie_wildcard(const op_trie_t *t, const char *pattern,
                      op_trie_each_t fn, void *ud);

/* ---- introspection ------------------------------------------------------- */

size_t      op_trie_count(const op_trie_t *t);
const char *op_trie_name (const op_trie_t *t);

#endif /* LIBOP_TRIE_H */
