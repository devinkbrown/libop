/*
 * libop: ophion support library.
 * op_rbt.h: Left-leaning red-black tree (ordered map).
 *
 * Overview
 * ========
 * op_rbt is a balanced binary search tree providing O(log n) insertion,
 * deletion, lookup, and in-order traversal.  Unlike op_htab (unordered,
 * O(1) average), op_rbt maintains keys in sorted order and supports:
 *
 *   - Exact lookup, lower-bound, upper-bound (range queries)
 *   - Min/max in O(log n)
 *   - In-order iteration without copying the tree
 *   - Predecessor/successor walk (O(log n) per step)
 *
 * Implementation: Left-Leaning Red-Black (LLRB) tree by Sedgewick 2008.
 * LLRB has the same asymptotic guarantees as classic red-black trees but
 * substantially simpler insert/delete code: there are only 3 structural
 * transformations (rotate_left, rotate_right, flip_colours) used uniformly
 * in both insert and delete.
 *
 * Invariants maintained:
 *   1. No node has two consecutive red links.
 *   2. Every root-to-leaf path has the same number of black links (perfect
 *      black balance).
 *   3. Red links lean left: a right child is never red when the left is not.
 *
 * Height is at most 2 lg n, so all operations are O(log n) worst-case.
 *
 * Comparator
 * ==========
 * op_rbt_cmp_t works like strcmp / qsort: negative if a < b, 0 if a == b,
 * positive if a > b.  The tree stores user-supplied key and value pointers
 * without interpreting them.
 *
 * Convenience comparators for common key types:
 *   op_rbt_cmp_str()   — strcmp (case-sensitive string keys)
 *   op_rbt_cmp_istr()  — IRC case-insensitive string keys
 *   op_rbt_cmp_u64()   — uint64_t keys (passed as cast pointers)
 *   op_rbt_cmp_ptr()   — pointer identity (address order)
 *
 * Typical usage
 * =============
 *   // Build a sorted nick → Client map:
 *   op_rbt_t *nicks = op_rbt_create("nicks", op_rbt_cmp_str);
 *   op_rbt_set(nicks, client->name, client, NULL);
 *
 *   // Range: iterate all nicks starting with 'A':
 *   op_rbt_iter_t it;
 *   op_rbt_iter_lower(nicks, "A", &it);
 *   void *k; void *v;
 *   while (op_rbt_iter_next(&it, &k, &v)) {
 *       struct Client *c = v;
 *       if (c->name[0] != 'A' && c->name[0] != 'a') break;
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
# error "Do not include op_rbt.h directly; include op_lib.h"
#endif

#ifndef LIBOP_RBT_H
#define LIBOP_RBT_H

/* ---- types --------------------------------------------------------------- */

typedef int  (*op_rbt_cmp_t) (const void *a, const void *b);
typedef void (*op_rbt_free_t)(void *key, void *val, void *ud);
typedef bool (*op_rbt_each_t)(void *key, void *val, void *ud);

/* Opaque tree handle. */
typedef struct op_rbt op_rbt_t;

/*
 * Stack-based iterator — no allocation.
 * The stack depth bounds the tree height; 64 levels covers 2^32 nodes.
 */
#define OP_RBT_ITER_DEPTH 64

typedef struct op_rbt_iter
{
    void  *stack[OP_RBT_ITER_DEPTH]; /* rbt_node_t pointers (opaque)      */
    int    sp;                        /* stack pointer (−1 = exhausted)    */
} op_rbt_iter_t;

/* ---- convenience comparators --------------------------------------------- */

int op_rbt_cmp_str (const void *a, const void *b);   /* strcmp             */
int op_rbt_cmp_istr(const void *a, const void *b);   /* IRC case-insensitive */
int op_rbt_cmp_u64 (const void *a, const void *b);   /* uint64_t by value  */
int op_rbt_cmp_ptr (const void *a, const void *b);   /* pointer address    */

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_rbt_create — allocate and initialise a new empty tree.
 *
 * name: diagnostic label (stored; not copied — must be a string literal or
 *       remain valid for the lifetime of the tree).
 * cmp:  comparator; must be consistent and produce a total order.
 *
 * Never returns NULL; aborts on OOM.
 */
op_rbt_t *op_rbt_create(const char *name, op_rbt_cmp_t cmp);

/*
 * op_rbt_destroy — free the tree and all nodes.
 *
 * If free_fn is non-NULL it is called for every live entry before the
 * node memory is released.  Key and value pointers are NOT freed unless
 * free_fn does so explicitly.
 */
void op_rbt_destroy(op_rbt_t *t, op_rbt_free_t free_fn, void *ud);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_rbt_set — insert or update.
 *
 * If key is already in the tree, the value is replaced and the old value
 * is returned via *old_val (if non-NULL); returns 0.
 * If key is new, inserts the node and returns 1.
 *
 * The key pointer is stored as-is.  On update, the old key pointer is
 * replaced with the new one (allows key objects to be refreshed).
 */
int op_rbt_set(op_rbt_t *t, void *key, void *val, void **old_val);

/*
 * op_rbt_del — remove the entry with the given key.
 *
 * Returns the value that was associated with the key, or NULL if not found.
 * The key is not freed.
 */
void *op_rbt_del(op_rbt_t *t, const void *key);

/* ---- lookup -------------------------------------------------------------- */

/* Returns the value for key, or NULL if not found. */
void *op_rbt_get(const op_rbt_t *t, const void *key);

/* Returns true if key is present. */
bool  op_rbt_has(const op_rbt_t *t, const void *key);

/*
 * op_rbt_min_key / op_rbt_max_key — smallest / largest key in O(log n).
 * Returns NULL if the tree is empty.
 */
void *op_rbt_min_key(const op_rbt_t *t);
void *op_rbt_max_key(const op_rbt_t *t);

/*
 * op_rbt_lower_bound — smallest key ≥ key ("ceiling").
 * Returns NULL if no such key exists.
 */
void *op_rbt_lower_bound(const op_rbt_t *t, const void *key);

/*
 * op_rbt_upper_bound — smallest key > key ("strict ceiling").
 * Returns NULL if no such key exists.
 */
void *op_rbt_upper_bound(const op_rbt_t *t, const void *key);

/* ---- introspection ------------------------------------------------------- */

size_t      op_rbt_size(const op_rbt_t *t);
const char *op_rbt_name(const op_rbt_t *t);

/* ---- in-order traversal -------------------------------------------------- */

/*
 * op_rbt_foreach — call fn(key, val, ud) for every entry in ascending key
 * order.  Stops early if fn returns false.  Must not modify the tree during
 * iteration (no insert/delete).
 */
void op_rbt_foreach(const op_rbt_t *t, op_rbt_each_t fn, void *ud);

/*
 * op_rbt_foreach_rev — same but in descending order.
 */
void op_rbt_foreach_rev(const op_rbt_t *t, op_rbt_each_t fn, void *ud);

/* ---- stack-based iterators ----------------------------------------------- */

/*
 * op_rbt_iter_init — initialise an iterator to the smallest key (begin).
 *
 * The iterator walks the tree in ascending order.  It uses a small on-stack
 * path stack; no heap allocation.
 *
 * The tree must not be modified while an iterator is active.
 */
void op_rbt_iter_init(op_rbt_iter_t *it, const op_rbt_t *t);

/*
 * op_rbt_iter_lower — initialise an iterator starting at the first key ≥
 * lower (lower-bound seek).
 *
 * Useful for range scans without iterating from the beginning.
 */
void op_rbt_iter_lower(op_rbt_iter_t *it, const op_rbt_t *t,
                       const void *lower);

/*
 * op_rbt_iter_next — advance the iterator.
 *
 * Sets *key and *val to the current entry and returns true.
 * Returns false when all entries have been visited.
 * Passing NULL for key or val is safe (the pointer is not written).
 */
bool op_rbt_iter_next(op_rbt_iter_t *it, void **key, void **val);

#endif /* LIBOP_RBT_H */
