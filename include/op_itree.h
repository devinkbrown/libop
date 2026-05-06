/*
 * libop: ophion support library.
 * op_itree.h: Augmented interval tree (centered interval tree over int64_t).
 *
 * Stores intervals [lo, hi] keyed by lo.  Multiple intervals may share the
 * same lo value — they are chained in insertion order at each key node.
 *
 * Supported queries:
 *   op_itree_stab(t, x, fn, ud)  — all intervals where lo <= x <= hi
 *   op_itree_overlap(t, a, b, fn, ud) — all intervals overlapping [a, b]
 *
 * Both run in O(log n + k) where k is the number of results, assuming a
 * reasonably balanced tree.  The augmented max_end field is maintained
 * during every insert and delete.
 *
 * Interval endpoints are int64_t so the tree handles both Unix timestamps
 * and IPv4/IPv6 address ranges (cast to uint64_t/int64_t as needed).
 *
 * Not thread-safe — protect with op_mutex_t when accessed from multiple
 * threads.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_itree.h directly; include op_lib.h"
#endif

#ifndef LIBOP_ITREE_H
#define LIBOP_ITREE_H

/* ---- callback types ------------------------------------------------------ */

/*
 * op_itree_each_t — called for each matching interval during a query.
 *
 * lo, hi — the interval endpoints.
 * val    — the user value stored with this interval.
 * ud     — caller-supplied context pointer.
 *
 * Return true to continue, false to stop early.
 */
typedef bool (*op_itree_each_t)(int64_t lo, int64_t hi, void *val, void *ud);

/*
 * op_itree_free_t — optional destructor called on every stored value when
 * the tree is destroyed.
 */
typedef void (*op_itree_free_t)(void *val, void *ud);

/* ---- opaque handle ------------------------------------------------------- */

struct op_itree;
typedef struct op_itree op_itree_t;

/* ---- lifecycle ----------------------------------------------------------- */

op_itree_t *op_itree_create(const char *name);
void        op_itree_destroy(op_itree_t *t, op_itree_free_t free_fn, void *ud);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_itree_insert — add interval [lo, hi] with associated value val.
 *
 * Multiple intervals with the same lo are allowed and all are stored
 * independently.  hi must be >= lo.
 *
 * Returns 1 on success, -1 if hi < lo.
 */
int op_itree_insert(op_itree_t *t, int64_t lo, int64_t hi, void *val);

/*
 * op_itree_delete — remove the first interval [lo, hi] whose stored val
 * pointer equals val.
 *
 * Returns 1 if found and removed, 0 if not found.
 */
int op_itree_delete(op_itree_t *t, int64_t lo, int64_t hi, void *val);

/* ---- queries ------------------------------------------------------------- */

/*
 * op_itree_stab — call fn for every interval containing point x
 * (i.e. lo <= x && x <= hi).
 * Stops early if fn returns false.
 */
void op_itree_stab(const op_itree_t *t, int64_t x,
                   op_itree_each_t fn, void *ud);

/*
 * op_itree_overlap — call fn for every interval that overlaps [a, b]
 * (i.e. lo <= b && hi >= a).
 * Stops early if fn returns false.
 */
void op_itree_overlap(const op_itree_t *t, int64_t a, int64_t b,
                      op_itree_each_t fn, void *ud);

/*
 * op_itree_first_stab — return the val of the first interval containing x,
 * or NULL if none.  Useful for single-result lookups.
 */
void *op_itree_first_stab(const op_itree_t *t, int64_t x);

/* ---- introspection ------------------------------------------------------- */

size_t      op_itree_count(const op_itree_t *t);
const char *op_itree_name (const op_itree_t *t);

#endif /* LIBOP_ITREE_H */
