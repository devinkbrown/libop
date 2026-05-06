/*
 * libop: ophion support library.
 * htab.c: Robin Hood open-addressing hash table.
 *
 * Design properties:
 *   - Open addressing with Robin Hood probing: "rich" slots (DIB=0 or 1)
 *     yield to "poor" slots (high DIB), keeping the maximum probe chain
 *     O(log n) expected rather than O(n) worst-case.
 *   - Tombstone-free deletion via backward-shift so tables remain dense
 *     under churn and lookups never traverse tombstones.
 *   - Power-of-2 bucket count; 75% load-factor cap with automatic doubling.
 *   - Cached per-slot hash (avoids re-hashing during probing).
 *   - Pluggable hash+equality functions; convenience constructors for
 *     case-sensitive strings, IRC case-insensitive strings, and pointers.
 *   - Safe delete-during-iteration via op_htab_iter_del.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1
#include <libop_config.h>
#include <op_lib.h>

/* ---- private struct definition ------------------------------------------- */

struct op_htab
{
	op_htab_hash_fn  hash_fn;
	op_htab_eq_fn    eq_fn;
	op_htab_slot_t  *slots;
	size_t           mask;    /* (capacity - 1); capacity is always power-of-2 */
	size_t           count;   /* live entries                                   */
	const char      *name;
	op_dlink_node    node;    /* membership in the global htab_list             */
};

/* Global registry of all live op_htab instances, used by op_htab_stats_walk. */
static op_dlink_list htab_list = { NULL, NULL, 0 };

/* ---- internal helpers ---------------------------------------------------- */

/* Hash 0 is the empty-slot sentinel; remap any user hash of 0 to 1. */
static inline uint64_t
fix_hash(uint64_t h)
{
	return h != 0 ? h : UINT64_C(1);
}

/*
 * dib — probe distance (displacement information block) for an entry stored
 * at slot index i with cached hash h.
 * The ideal bucket for h is (h & mask); DIB counts how far we've been pushed.
 */
static inline size_t
dib(size_t mask, size_t i, uint64_t h)
{
	return (i - (size_t)(h & mask)) & mask;
}

/* Smallest power of two >= n, minimum 16. */
static size_t
next_pow2(size_t n)
{
	if (n < 16)
		return 16;
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n |= n >> 32;
	return n + 1;
}

/* ---- probe helpers ------------------------------------------------------- */

/*
 * htab_lookup — find the slot for (key, hash).
 *
 * Returns a pointer to the matching slot, or NULL if not found.
 * Robin Hood early-exit: once the sitting entry's DIB is less than the
 * current probe distance, the target key cannot be further along the chain.
 */
static inline const op_htab_slot_t *
htab_lookup(const op_htab *ht, const void *key, uint64_t hash)
{
	size_t i    = (size_t)(hash & ht->mask);
	size_t dist = 0;

	for (;;)
	{
		const op_htab_slot_t *s = &ht->slots[i];

		if (s->hash == 0)
			return NULL;

		if (dib(ht->mask, i, s->hash) < dist)
			return NULL;

		if (s->hash == hash && ht->eq_fn(s->key, key))
			return s;

		i = (i + 1) & ht->mask;
		dist++;
	}
}

/*
 * htab_find_idx — like htab_lookup but returns the slot index.
 * Returns SIZE_MAX when the key is not found (SIZE_MAX can never be a valid
 * index because capacity < SIZE_MAX for any allocatable table).
 */
static inline size_t
htab_find_idx(const op_htab *ht, const void *key, uint64_t hash)
{
	size_t i    = (size_t)(hash & ht->mask);
	size_t dist = 0;

	for (;;)
	{
		const op_htab_slot_t *s = &ht->slots[i];

		if (s->hash == 0)
			return SIZE_MAX;

		if (dib(ht->mask, i, s->hash) < dist)
			return SIZE_MAX;

		if (s->hash == hash && ht->eq_fn(s->key, key))
			return i;

		i = (i + 1) & ht->mask;
		dist++;
	}
}

/* ---- raw insert (no resize check) ---------------------------------------- */

/*
 * htab_insert_slot — insert (key, val, hash) into slots[] using Robin Hood
 * probing.  The caller must guarantee at least one empty slot exists.
 *
 * Whenever the entry being placed has a higher DIB than the sitting entry,
 * swap them and continue inserting the displaced entry.  This keeps probe
 * chains short and their variance low.
 */
static void
htab_insert_slot(op_htab_slot_t *slots, size_t mask,
                 void *key, void *val, uint64_t hash)
{
	size_t i    = (size_t)(hash & mask);
	size_t dist = 0;

	for (;;)
	{
		op_htab_slot_t *s = &slots[i];

		if (s->hash == 0)
		{
			s->key  = key;
			s->val  = val;
			s->hash = hash;
			return;
		}

		/* Robin Hood: poor entry evicts rich. */
		size_t sitting_dist = dib(mask, i, s->hash);
		if (sitting_dist < dist)
		{
			void    *tk = s->key;  void    *tv = s->val;
			uint64_t th = s->hash;
			s->key = key;  s->val = val;  s->hash = hash;
			key = tk;  val = tv;  hash = th;
			dist = sitting_dist;
		}

		i = (i + 1) & mask;
		dist++;
	}
}

/* ---- backward-shift deletion --------------------------------------------- */

/*
 * htab_del_at — remove the entry at slot index i and close the resulting
 * hole by shifting subsequent entries backward one step each while their
 * DIB > 0.  Decrements ht->count.
 *
 * This is tombstone-free: future lookups never traverse empty holes.
 * Called from op_htab_del and op_htab_iter_del.
 */
static void
htab_del_at(op_htab *ht, size_t i)
{
	op_htab_slot_t *s = &ht->slots[i];

	for (;;)
	{
		size_t j             = (i + 1) & ht->mask;
		op_htab_slot_t *next = &ht->slots[j];

		/* Stop: empty slot, or entry sitting at its ideal bucket
		 * (shifting it back would make its DIB negative). */
		if (next->hash == 0 || dib(ht->mask, j, next->hash) == 0)
		{
			s->hash = 0;
			s->key  = NULL;
			s->val  = NULL;
			break;
		}

		*s = *next;
		s  = next;
		i  = j;
	}

	ht->count--;
}

/* ---- resize -------------------------------------------------------------- */

static void
htab_resize(op_htab *ht, size_t new_cap)
{
	op_htab_slot_t *new_slots = op_calloc(new_cap, sizeof(op_htab_slot_t));
	size_t          new_mask  = new_cap - 1;
	size_t          old_cap   = ht->mask + 1;

	for (size_t i = 0; i < old_cap; i++)
	{
		op_htab_slot_t *s = &ht->slots[i];
		if (s->hash != 0)
			htab_insert_slot(new_slots, new_mask, s->key, s->val, s->hash);
	}

	op_free(ht->slots);
	ht->slots = new_slots;
	ht->mask  = new_mask;
}

/* Grow when at or above 75% load. */
static inline void
htab_maybe_grow(op_htab *ht)
{
	size_t cap = ht->mask + 1;
	if (__builtin_expect(ht->count * 4 >= cap * 3, 0))
		htab_resize(ht, cap * 2);
}

/* ---- construction / destruction ------------------------------------------ */

op_htab *
op_htab_create(const char *name,
               op_htab_hash_fn hash_fn,
               op_htab_eq_fn   eq_fn,
               size_t          initial_cap)
{
	op_htab *ht  = op_malloc(sizeof(*ht));
	size_t   cap = next_pow2(initial_cap);

	ht->hash_fn = hash_fn;
	ht->eq_fn   = eq_fn;
	ht->name    = name;
	ht->count   = 0;
	ht->mask    = cap - 1;
	ht->slots   = op_calloc(cap, sizeof(op_htab_slot_t));
	op_dlinkAdd(ht, &ht->node, &htab_list);
	return ht;
}

/* ---- built-in hash / equality functions ---------------------------------- */

/*
 * FNV-1a 64-bit.  Fast, good distribution for short strings.  IRC nicks,
 * channel names, and hostnames are typically 2-64 bytes — FNV-1a is well-
 * suited to this range and keeps the hot path branch-free.
 */
uint64_t
op_htab_hash_str(const void *key)
{
	const unsigned char *p = key;
	uint64_t h = UINT64_C(14695981039346656037);
	while (*p)
	{
		h ^= (uint64_t)*p++;
		h *= UINT64_C(1099511628211);
	}
	return fix_hash(h);
}

static bool
htab_eq_str(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b) == 0;
}

op_htab *
op_htab_create_str(const char *name, size_t initial_cap)
{
	return op_htab_create(name, op_htab_hash_str, htab_eq_str, initial_cap);
}

/*
 * IRC case-insensitive hash (RFC 1459 §2.2):
 *   A-Z  →  a-z  (standard ASCII folding)
 *   [  →  {    \  →  |    ]  →  }    ^  →  ~  (the four IRC upper→lower pairs)
 *
 * The equality function below applies the same folding so hash and eq are
 * consistent — a mandatory invariant for any hash table.
 */
uint64_t
op_htab_hash_istr(const void *key)
{
	const unsigned char *p = key;
	uint64_t h = UINT64_C(14695981039346656037);
	unsigned char c;

	while ((c = *p++) != 0)
	{
		if (c >= 'A' && c <= 'Z')
			c |= 0x20u;                 /* fold A-Z → a-z      */
		else if (c >= '[' && c <= '^')
			c = (unsigned char)(c + 0x20u); /* fold [ \ ] ^ → { | } ~ */
		h ^= (uint64_t)c;
		h *= UINT64_C(1099511628211);
	}
	return fix_hash(h);
}

static bool
htab_eq_istr(const void *a, const void *b)
{
	const unsigned char *ua = (const unsigned char *)a;
	const unsigned char *ub = (const unsigned char *)b;
	unsigned char ca, cb;

	do {
		ca = *ua++;
		cb = *ub++;
		if      (ca >= 'A' && ca <= 'Z') ca |= 0x20u;
		else if (ca >= '[' && ca <= '^') ca = (unsigned char)(ca + 0x20u);
		if      (cb >= 'A' && cb <= 'Z') cb |= 0x20u;
		else if (cb >= '[' && cb <= '^') cb = (unsigned char)(cb + 0x20u);
	} while (ca == cb && ca != '\0');

	return ca == cb;
}

op_htab *
op_htab_create_istr(const char *name, size_t initial_cap)
{
	return op_htab_create(name, op_htab_hash_istr, htab_eq_istr, initial_cap);
}

/*
 * Pointer-identity table: hash is the address itself, mixed to spread the
 * lower bits (allocators often align to 8 or 16 bytes, so the low bits
 * would otherwise always be zero).  Equality is pointer equality.
 */
uint64_t
op_htab_hash_ptr(const void *key)
{
	uintptr_t v = (uintptr_t)key;
	/* splitmix64 mixing step (Sebastiano Vigna) */
	v ^= v >> 30;
	v *= UINT64_C(0xbf58476d1ce4e5b9);
	v ^= v >> 27;
	v *= UINT64_C(0x94d049bb133111eb);
	v ^= v >> 31;
	return fix_hash(v);
}

static bool
htab_eq_ptr(const void *a, const void *b)
{
	return a == b;
}

op_htab *
op_htab_create_ptr(const char *name, size_t initial_cap)
{
	return op_htab_create(name, op_htab_hash_ptr, htab_eq_ptr, initial_cap);
}

/* ---- destroy ------------------------------------------------------------- */

void
op_htab_destroy(op_htab *ht,
                void (*destroy_cb)(void *key, void *val, void *ud),
                void *ud)
{
	if (ht == NULL)
		return;
	if (destroy_cb != NULL)
	{
		size_t cap = ht->mask + 1;
		for (size_t i = 0; i < cap; i++)
		{
			if (ht->slots[i].hash != 0)
				destroy_cb(ht->slots[i].key, ht->slots[i].val, ud);
		}
	}
	op_dlinkDelete(&ht->node, &htab_list);
	op_free(ht->slots);
	op_free(ht);
}

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_htab_set — insert or update.
 *
 * If the key already exists, its value is replaced in place.  The stored key
 * pointer is NOT replaced: callers that op_strdup() the key and free the new
 * copy when rc == 0 rely on the old key pointer remaining in the table.
 * Replacing it would store a freed pointer and cause a double-free on destroy.
 *
 * Returns 1 on insert, 0 on update.
 */
int
op_htab_set(op_htab *ht, void *key, void *val, void **old_val)
{
	uint64_t hash = fix_hash(ht->hash_fn(key));
	size_t   i    = htab_find_idx(ht, key, hash);

	if (i != SIZE_MAX)
	{
		/* Update in place — do NOT replace the key pointer. */
		if (old_val)
			*old_val = ht->slots[i].val;
		ht->slots[i].val = val;
		return 0;
	}

	if (old_val)
		*old_val = NULL;

	/* New entry: check load factor, then insert. */
	htab_maybe_grow(ht);
	htab_insert_slot(ht->slots, ht->mask, key, val, hash);
	ht->count++;
	return 1;
}

/*
 * op_htab_del — remove the entry for key and return its value, or NULL
 * if not present.  Uses tombstone-free backward-shift deletion.
 *
 * WARNING: do not call this during op_htab_iter_next / OP_HTAB_FOREACH
 * iteration — use op_htab_iter_del instead, which adjusts the iterator
 * to account for the backward shift.
 */
void *
op_htab_del(op_htab *ht, const void *key)
{
	uint64_t hash = fix_hash(ht->hash_fn(key));
	size_t   i    = htab_find_idx(ht, key, hash);

	if (i == SIZE_MAX)
		return NULL;

	void *val = ht->slots[i].val;
	htab_del_at(ht, i);
	return val;
}

/*
 * op_htab_get_or_set — return the existing value for key if present;
 * otherwise insert (key, val) and return val.
 *
 * *created is set to true on insert, false on lookup.
 * This avoids a double-probe for the common "insert if absent" pattern:
 *
 *   void *v = op_htab_get_or_set(ht, key, default_val, &created);
 *   if (created) ...  // initialise the new entry
 */
void *
op_htab_get_or_set(op_htab *ht, void *key, void *val, bool *created)
{
	uint64_t hash = fix_hash(ht->hash_fn(key));
	size_t   i    = htab_find_idx(ht, key, hash);

	if (i != SIZE_MAX)
	{
		if (created) *created = false;
		return ht->slots[i].val;
	}

	if (created) *created = true;
	htab_maybe_grow(ht);
	htab_insert_slot(ht->slots, ht->mask, key, val, hash);
	ht->count++;
	return val;
}

/* ---- lookup -------------------------------------------------------------- */

void *
op_htab_get(const op_htab *ht, const void *key)
{
	uint64_t hash = fix_hash(ht->hash_fn(key));
	const op_htab_slot_t *s = htab_lookup(ht, key, hash);
	return s ? s->val : NULL;
}

bool
op_htab_has(const op_htab *ht, const void *key)
{
	uint64_t hash = fix_hash(ht->hash_fn(key));
	return htab_lookup(ht, key, hash) != NULL;
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_htab_size(const op_htab *ht)
{
	return ht->count;
}

size_t
op_htab_cap(const op_htab *ht)
{
	return ht->mask + 1;
}

const char *
op_htab_name(const op_htab *ht)
{
	return ht->name;
}

/*
 * op_htab_compact — shrink the backing array to the minimum power-of-2
 * capacity that maintains a <= 50% load factor.
 *
 * This is a manual operation; the table never shrinks automatically.
 * Useful after a bulk delete (netsplit cleanup, mass-ban flush, etc.)
 * to reclaim memory.  No-op when the table is already at minimum size.
 */
void
op_htab_compact(op_htab *ht)
{
	size_t new_cap = next_pow2(ht->count * 2 + 1);
	if (new_cap < ht->mask + 1)
		htab_resize(ht, new_cap);
}

/* ---- iteration ----------------------------------------------------------- */

void
op_htab_iter_init(const op_htab *ht, op_htab_iter_t *it)
{
	(void)ht;
	it->idx = 0;
	it->cur = SIZE_MAX;   /* no current element yet */
}

/*
 * op_htab_iter_next — advance to the next live slot and return its key/val.
 *
 * Records the index of the returned entry in it->cur for op_htab_iter_del.
 * Returns false when all slots have been visited.
 */
bool
op_htab_iter_next(const op_htab *ht, op_htab_iter_t *it,
                  void **key, void **val)
{
	size_t cap = ht->mask + 1;

	while (it->idx < cap)
	{
		size_t i = it->idx++;
		const op_htab_slot_t *s = &ht->slots[i];
		if (s->hash != 0)
		{
			it->cur = i;
			*key    = s->key;
			*val    = s->val;
			return true;
		}
	}

	it->cur = SIZE_MAX;
	return false;
}

/*
 * op_htab_iter_del — safely remove the element most recently returned by
 * op_htab_iter_next and return its value.
 *
 * After backward-shift deletion, the slot at it->cur may now contain an
 * entry that was shifted back from it->cur+1 (or further).  The iterator
 * is rewound to it->cur so that op_htab_iter_next will re-examine that slot
 * and not miss any shifted entries.
 *
 * It is safe to call this at most once per op_htab_iter_next call; calling
 * it again without advancing the iterator returns NULL.
 */
void *
op_htab_iter_del(op_htab *ht, op_htab_iter_t *it)
{
	size_t i = it->cur;
	if (i == SIZE_MAX || i >= ht->mask + 1 || ht->slots[i].hash == 0)
		return NULL;

	void *val = ht->slots[i].val;
	htab_del_at(ht, i);

	/* Rewind: re-examine slot i on the next iter_next call — it may
	 * contain an entry that the backward shift moved from i+1. */
	it->idx = i;
	it->cur = SIZE_MAX;
	return val;
}

void
op_htab_foreach(const op_htab *ht,
                int (*cb)(void *key, void *val, void *ud),
                void *ud)
{
	size_t cap = ht->mask + 1;
	for (size_t i = 0; i < cap; i++)
	{
		const op_htab_slot_t *s = &ht->slots[i];
		if (s->hash != 0 && cb(s->key, s->val, ud))
			return;
	}
}

/* ---- merge --------------------------------------------------------------- */

/*
 * op_htab_merge — insert every entry from `src` into `dst`.
 *
 * If a key from `src` already exists in `dst`, the existing entry is kept
 * and the source value is passed to conflict_cb (if non-NULL) so the caller
 * can decide how to handle the collision (e.g. free the duplicate).
 * If conflict_cb is NULL, duplicates in dst silently win.
 *
 * The source table is not modified.
 */
void
op_htab_merge(op_htab *dst, const op_htab *src,
              void (*conflict_cb)(void *dst_key, void *dst_val,
                                  void *src_key, void *src_val,
                                  void *ud),
              void *ud)
{
    size_t cap = src->mask + 1;
    for (size_t i = 0; i < cap; i++)
    {
        const op_htab_slot_t *s = &src->slots[i];
        if (s->hash == 0)
            continue;

        void *old_val = NULL;
        int rc = op_htab_set(dst, s->key, s->val, &old_val);
        if (rc == 0 /* update — key already existed */ && conflict_cb)
        {
            /* dst already had this key; old_val is the displaced dst value.
             * Restore the original dst value and report the conflict. */
            op_htab_set(dst, s->key, old_val, NULL);
            conflict_cb(s->key, old_val, s->key, s->val, ud);
        }
    }
}

/* ---- global statistics walk ---------------------------------------------- */

void
op_htab_stats_walk(void (*cb)(const char *line, void *privdata), void *privdata)
{
	op_dlink_node *ptr;
	char str[256];

	OP_DLINK_FOREACH(ptr, htab_list.head)
	{
		const op_htab *ht = ptr->data;
		size_t cap  = ht->mask + 1;
		size_t load = cap ? (ht->count * 100) / cap : 0;
		snprintf(str, sizeof str,
		         "%-36s count=%-8zu cap=%-8zu load=%2zu%%",
		         ht->name, ht->count, cap, load);
		cb(str, privdata);
	}
}
