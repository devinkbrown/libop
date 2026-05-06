/*
 * libop: ophion support library.
 * op_htab.h: Robin Hood open-addressing hash table.
 *
 * A fast, general-purpose hash table suitable for all lookup-heavy paths in
 * the IRC server (nick tables, channel tables, IP reject caches, etc.).
 *
 * Design properties:
 *   - Open addressing with Robin Hood probing: rich entries (short probe chains)
 *     yield their slot to poor entries (long probe chains), keeping variance of
 *     probe length at O(log n) expected rather than O(n) worst case.
 *   - Tombstone-free deletion via backward-shift, so tables remain compact
 *     even under high churn.
 *   - Power-of-2 bucket count, 75% load factor cap, automatic doubling.
 *   - Cached per-slot hash value (avoids re-hashing on probe chain traversal).
 *   - Pluggable hash + equality functions; convenience constructors for string
 *     keys (case-sensitive and IRC case-insensitive) and pointer-identity keys.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_htab.h directly; include op_lib.h"
#endif

#ifndef LIBOP_HTAB_H
#define LIBOP_HTAB_H

/* ---- types --------------------------------------------------------------- */

typedef uint64_t (*op_htab_hash_fn)(const void *key);
typedef bool     (*op_htab_eq_fn)  (const void *a, const void *b);

/* One bucket.  hash == 0 means the slot is empty. */
typedef struct op_htab_slot
{
	void    *key;
	void    *val;
	uint64_t hash;   /* cached hash; 0 ≡ empty */
} op_htab_slot_t;

/* Opaque table handle (pointer returned by op_htab_create*). */
struct op_htab;
typedef struct op_htab op_htab;

/*
 * Iterator — initialise with op_htab_iter_init(), advance with
 * op_htab_iter_next().
 *
 * To delete the current element during iteration, call op_htab_iter_del()
 * instead of op_htab_del().  Do NOT call op_htab_del() during iteration:
 * backward-shift deletion shifts entries from i+1 down to i, but the iterator
 * has already advanced past i and will miss the shifted entries.
 * op_htab_iter_del() rewinds the iterator to re-examine the slot.
 */
typedef struct op_htab_iter
{
	size_t idx;   /* next slot index to examine                         */
	size_t cur;   /* index of element returned by last iter_next call;
	               * SIZE_MAX when no current element                   */
} op_htab_iter_t;

/* ---- construction / destruction ------------------------------------------ */

/*
 * op_htab_create — generic constructor.
 *
 *   name        descriptive label (for stats / debugging).
 *   hash_fn     maps a key to a uint64_t; must never return 0 (remapped).
 *   eq_fn       returns true iff two keys compare equal.
 *   initial_cap desired initial bucket count (rounded up to the next
 *               power of two, minimum 16).
 */
op_htab *op_htab_create(const char *name,
                         op_htab_hash_fn hash_fn,
                         op_htab_eq_fn   eq_fn,
                         size_t          initial_cap);

/* Convenience: case-sensitive string keys. */
op_htab *op_htab_create_str (const char *name, size_t initial_cap);

/* Convenience: IRC case-insensitive string keys (A-Z treated as a-z,
 * plus [ \ ] { | } ~ ^). */
op_htab *op_htab_create_istr(const char *name, size_t initial_cap);

/* Convenience: pointer identity (hash = address, eq = pointer equality). */
op_htab *op_htab_create_ptr (const char *name, size_t initial_cap);

/*
 * op_htab_destroy — free the table and all bucket storage.
 *
 * If destroy_cb is non-NULL it is called for every live entry before the
 * table memory is released.  The caller is responsible for freeing key/val
 * data if necessary.
 */
void op_htab_destroy(op_htab *ht,
                      void (*destroy_cb)(void *key, void *val, void *ud),
                      void *ud);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_htab_set — insert or update.
 *
 * If the key is already present its value is replaced and the old value is
 * returned via *old_val (if old_val is non-NULL).  Returns 1 on insert,
 * 0 on update, -1 on internal allocation failure (OOM — normally fatal in
 * libop, but exposed here for testing).
 */
int op_htab_set(op_htab *ht, void *key, void *val, void **old_val);

/*
 * op_htab_del — remove the entry with the given key.
 *
 * Returns the value that was associated with the key, or NULL if not found.
 *
 * WARNING: do not call during op_htab_iter_next / OP_HTAB_FOREACH iteration.
 * Use op_htab_iter_del() instead.
 */
void *op_htab_del(op_htab *ht, const void *key);

/*
 * op_htab_get_or_set — return the existing value for key if present;
 * otherwise insert (key, val) and return val.
 *
 * *created is set to true on insert, false on hit.  Pass NULL to ignore.
 * Avoids a double-probe for the common "insert if absent" pattern:
 *
 *   bool created;
 *   void *v = op_htab_get_or_set(ht, key, default_val, &created);
 *   if (created) ...  // initialise the new entry
 */
void *op_htab_get_or_set(op_htab *ht, void *key, void *val, bool *created);

/* ---- lookup -------------------------------------------------------------- */

/* Returns the value associated with key, or NULL if not found. */
void *op_htab_get(const op_htab *ht, const void *key);

/* Returns true if the key exists in the table. */
bool  op_htab_has(const op_htab *ht, const void *key);

/* ---- introspection ------------------------------------------------------- */

size_t      op_htab_size(const op_htab *ht);
size_t      op_htab_cap (const op_htab *ht);
const char *op_htab_name(const op_htab *ht);

/*
 * op_htab_compact — shrink the backing array to the minimum power-of-2
 * capacity that keeps the load factor at or below 50%.
 *
 * The table never shrinks automatically (to avoid latency spikes under churn).
 * Call this manually after bulk deletions (netsplit cleanup, mass-ban flush)
 * to reclaim memory.  No-op if the table is already at minimum size.
 */
void op_htab_compact(op_htab *ht);

/* ---- iteration ----------------------------------------------------------- */

void op_htab_iter_init(const op_htab *ht, op_htab_iter_t *it);

/*
 * op_htab_iter_next — advance iterator and populate key/val outputs.
 *
 * Returns true while elements remain, false when exhausted.
 * Records the returned slot index in it->cur for op_htab_iter_del.
 */
bool op_htab_iter_next(const op_htab *ht, op_htab_iter_t *it,
                        void **key, void **val);

/*
 * op_htab_iter_del — safely remove the element most recently returned by
 * op_htab_iter_next and return its value.
 *
 * Because backward-shift deletion can shift the entry at slot i+1 down into
 * slot i, this function rewinds the iterator to re-examine slot i on the next
 * op_htab_iter_next call, so no entries are skipped.
 *
 * Safe to call at most once per op_htab_iter_next call.  Returns NULL when
 * there is no current element (e.g., called twice in a row).
 */
void *op_htab_iter_del(op_htab *ht, op_htab_iter_t *it);

/*
 * op_htab_foreach — callback-based iteration.
 *
 * Calls cb(key, val, ud) for every live entry.  Returning non-zero from cb
 * aborts the iteration early.  Do not insert or delete entries from cb;
 * for delete-during-iteration use op_htab_iter_next / op_htab_iter_del.
 */
void op_htab_foreach(const op_htab *ht,
                      int (*cb)(void *key, void *val, void *ud),
                      void *ud);

/* ---- built-in hash functions (also useful to callers) ------------------- */

/* FNV-1a 64-bit hash of a NUL-terminated string. */
uint64_t op_htab_hash_str (const void *key);

/* IRC case-insensitive FNV-1a 64-bit hash of a NUL-terminated string. */
uint64_t op_htab_hash_istr(const void *key);

/* Identity hash (mixes address bits). */
uint64_t op_htab_hash_ptr (const void *key);

/* ---- merge --------------------------------------------------------------- */

/*
 * op_htab_merge — insert all entries from src into dst.
 *
 * If a key exists in both tables, dst wins and conflict_cb is called with
 * the destination key/value and the source key/value so the caller can
 * handle the collision (e.g. free a duplicate).  Pass NULL to silently keep
 * the destination value.
 *
 * src is not modified.
 */
void op_htab_merge(op_htab *dst, const op_htab *src,
                   void (*conflict_cb)(void *dst_key, void *dst_val,
                                       void *src_key, void *src_val,
                                       void *ud),
                   void *ud);

/* ---- global statistics walk ---------------------------------------------- */

/*
 * op_htab_stats_walk — invoke cb(line, privdata) once per registered htab.
 *
 * The output format is a human-readable stats line used by m_stats.c /stats z.
 */
void op_htab_stats_walk(void (*cb)(const char *line, void *privdata),
                         void *privdata);

/* ---- convenience macro for foreach --------------------------------------- */

#define OP_HTAB_FOREACH(key_, val_, ht_) \
	do { \
		op_htab_iter_t _hit; \
		op_htab_iter_init((ht_), &_hit); \
		void *key_ = NULL, *val_ = NULL; \
		while (op_htab_iter_next((ht_), &_hit, &(key_), &(val_)))

#define OP_HTAB_FOREACH_END \
	} while (0)

#endif /* LIBOP_HTAB_H */
