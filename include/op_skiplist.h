/*
 * libop: ophion support library.
 * op_skiplist.h: Probabilistic skip list (ordered map).
 *
 * Overview
 * ========
 * op_skiplist is a randomised ordered associative structure providing
 * O(log n) expected-time insertion, deletion, and lookup.  Like op_rbt it
 * maintains keys in sorted order and supports:
 *
 *   - Exact lookup, lower-bound, upper-bound (range queries)
 *   - Min/max in O(log n) expected
 *   - In-order and reverse-order iteration without copying
 *   - Stack-allocatable forward iterator (no heap)
 *
 * Implementation: standard skip list (Pugh 1990) with a sentinel head node
 * spanning SKIPLIST_MAX_LEVEL (32) levels, p = 0.25 level-promotion
 * probability, and a backward pointer at level 0 for O(n) reverse walk.
 *
 * Comparator
 * ==========
 * op_skiplist_cmp_t works like strcmp / qsort: negative if a < b, 0 if
 * a == b, positive if a > b.  The list stores user-supplied key and value
 * pointers without interpreting them.
 *
 * Convenience comparators for common key types:
 *   op_skiplist_cmp_str()   — strcmp (case-sensitive string keys)
 *   op_skiplist_cmp_istr()  — IRC case-insensitive string keys
 *   op_skiplist_cmp_u64()   — uint64_t keys (passed as cast pointers)
 *   op_skiplist_cmp_ptr()   — pointer identity (address order)
 *
 * Typical usage
 * =============
 *   // Sorted channel member list:
 *   op_skiplist_t *members = op_skiplist_create("members", op_skiplist_cmp_str);
 *   op_skiplist_set(members, client->name, client, NULL);
 *
 *   // Iterate a prefix range:
 *   op_skiplist_iter_t it;
 *   op_skiplist_iter_lower(&it, members, "A");
 *   void *k; void *v;
 *   while (op_skiplist_iter_next(&it, &k, &v)) {
 *       const char *nick = k;
 *       if (nick[0] != 'A' && nick[0] != 'a') break;
 *       ...
 *   }
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_skiplist.h directly; include op_lib.h"
#endif

#ifndef LIBOP_SKIPLIST_H
#define LIBOP_SKIPLIST_H

/* ---- types --------------------------------------------------------------- */

typedef int  (*op_skiplist_cmp_t) (const void *a, const void *b);
typedef void (*op_skiplist_free_t)(void *key, void *val, void *ud);
typedef bool (*op_skiplist_each_t)(void *key, void *val, void *ud);

/* Opaque list handle. */
typedef struct op_skiplist op_skiplist_t;

/*
 * Forward iterator — zero allocation, fits on the stack.
 * Valid only while the list is not modified.
 */
typedef struct op_skiplist_iter
{
    const void *cur;   /* current slnode_t pointer (opaque); NULL = exhausted */
} op_skiplist_iter_t;

/* ---- convenience comparators --------------------------------------------- */

int op_skiplist_cmp_str (const void *a, const void *b);   /* strcmp             */
int op_skiplist_cmp_istr(const void *a, const void *b);   /* IRC case-insensitive */
int op_skiplist_cmp_u64 (const void *a, const void *b);   /* uint64_t by value  */
int op_skiplist_cmp_ptr (const void *a, const void *b);   /* pointer address    */

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_skiplist_create — allocate a new empty skip list.
 *
 * name: diagnostic label (stored; must remain valid for the lifetime of the
 *       list — use string literals).
 * cmp:  key comparator; must produce a strict total order.
 *
 * Never returns NULL; aborts on OOM.
 */
op_skiplist_t *op_skiplist_create(const char *name, op_skiplist_cmp_t cmp);

/*
 * op_skiplist_destroy — free the list and all nodes.
 *
 * If free_fn is non-NULL it is called for every live entry before the
 * node memory is released.
 */
void op_skiplist_destroy(op_skiplist_t *sl, op_skiplist_free_t free_fn, void *ud);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_skiplist_set — insert or update.
 *
 * Returns 1 if key is new; returns 0 if key existed (value replaced).
 * When returning 0 and old_val is non-NULL, *old_val receives the old value.
 * On insert, *old_val is set to NULL.
 */
int op_skiplist_set(op_skiplist_t *sl, void *key, void *val, void **old_val);

/*
 * op_skiplist_del — remove the entry with the given key.
 *
 * Returns the associated value, or NULL if not found.
 */
void *op_skiplist_del(op_skiplist_t *sl, const void *key);

/* ---- lookup -------------------------------------------------------------- */

/* Returns the value for key, or NULL if not found. */
void *op_skiplist_get(const op_skiplist_t *sl, const void *key);

/* Returns true if key is present. */
bool  op_skiplist_has(const op_skiplist_t *sl, const void *key);

/*
 * op_skiplist_min_key / op_skiplist_max_key — smallest / largest key.
 * Returns NULL if the list is empty.
 */
void *op_skiplist_min_key(const op_skiplist_t *sl);
void *op_skiplist_max_key(const op_skiplist_t *sl);

/*
 * op_skiplist_lower_bound — smallest key ≥ key ("ceiling").
 * Returns NULL if no such key exists.
 */
void *op_skiplist_lower_bound(const op_skiplist_t *sl, const void *key);

/*
 * op_skiplist_upper_bound — smallest key > key ("strict ceiling").
 * Returns NULL if no such key exists.
 */
void *op_skiplist_upper_bound(const op_skiplist_t *sl, const void *key);

/* ---- introspection ------------------------------------------------------- */

size_t      op_skiplist_size(const op_skiplist_t *sl);
const char *op_skiplist_name(const op_skiplist_t *sl);

/* ---- in-order traversal -------------------------------------------------- */

/*
 * op_skiplist_foreach — call fn(key, val, ud) for every entry in ascending
 * key order.  Stops early if fn returns false.
 * Must not modify the list during iteration.
 */
void op_skiplist_foreach(const op_skiplist_t *sl, op_skiplist_each_t fn, void *ud);

/*
 * op_skiplist_foreach_rev — same but in descending order.
 */
void op_skiplist_foreach_rev(const op_skiplist_t *sl, op_skiplist_each_t fn, void *ud);

/* ---- forward iterator ---------------------------------------------------- */

/*
 * op_skiplist_iter_init — position iterator at the smallest key (begin).
 */
void op_skiplist_iter_init(op_skiplist_iter_t *it, const op_skiplist_t *sl);

/*
 * op_skiplist_iter_lower — position iterator at the first key ≥ lower
 * (lower-bound seek).
 */
void op_skiplist_iter_lower(op_skiplist_iter_t *it, const op_skiplist_t *sl,
                            const void *lower);

/*
 * op_skiplist_iter_next — advance and read.
 *
 * Writes the current key/value to *key / *val (pass NULL to ignore) and
 * advances to the next node.  Returns false when exhausted.
 */
bool op_skiplist_iter_next(op_skiplist_iter_t *it, void **key, void **val);

#endif /* LIBOP_SKIPLIST_H */
