/*
 * libop — crdt.c
 * Delta-state OR-Set implementation.
 *
 * Copyright (c) 2026 Ophion Development Team.  MIT License.
 */

#include <op_lib.h>
#include <op_crdt.h>

/* Per-replica dot counter (monotonically increasing, local to this process). */
static _Atomic(uint64_t) s_dot_counter;

/* Find an entry by key, or return -1. */
static int
orset_find(const op_crdt_orset_t *set, const void *key, uint16_t key_len)
{
	for (uint32_t i = 0; i < set->count; i++) {
		if (set->entries[i].key_len == key_len &&
		    memcmp(set->entries[i].key, key, key_len) == 0)
			return (int)i;
	}
	return -1;
}

/* Ensure capacity for at least one more entry. */
static int
orset_grow(op_crdt_orset_t *set)
{
	if (set->count < set->capacity)
		return 0;
	uint32_t newcap = set->capacity ? set->capacity * 2 : 16;
	op_crdt_orset_entry_t *ne = op_realloc(set->entries,
	                                        newcap * sizeof(*ne));
	if (!ne) return -1;
	set->entries  = ne;
	set->capacity = newcap;
	return 0;
}

void
op_crdt_orset_init(op_crdt_orset_t *set, uint32_t initial_cap)
{
	memset(set, 0, sizeof(*set));
	if (initial_cap > 0) {
		set->entries = op_calloc(initial_cap, sizeof(*set->entries));
		set->capacity = set->entries ? initial_cap : 0;
	}
}

void
op_crdt_orset_free(op_crdt_orset_t *set)
{
	op_free(set->entries);
	memset(set, 0, sizeof(*set));
}

op_crdt_orset_delta_t
op_crdt_orset_add(op_crdt_orset_t *set,
                  const void *key, uint16_t key_len,
                  const uint8_t replica[8])
{
	op_crdt_orset_delta_t delta;
	memset(&delta, 0, sizeof(delta));

	if (key_len > OP_CRDT_ORSET_KEY_MAX)
		return delta;

	/* Generate a new globally unique dot. */
	op_crdt_dot_t dot;
	memcpy(dot.replica, replica, 8);
	dot.counter = atomic_fetch_add_explicit(&s_dot_counter, 1,
	                                        memory_order_relaxed) + 1;

	/* Build the delta: entry = {key: {dot}}, cc = {dot} */
	memcpy(delta.entry.key, key, key_len);
	delta.entry.key_len = key_len;
	delta.entry.dots[0] = dot;
	delta.entry.dot_count = 1;
	delta.has_entry = true;
	op_crdt_cc_add(&delta.cc, &dot);

	/* Apply the delta locally. */
	int idx = orset_find(set, key, key_len);
	if (idx >= 0) {
		/* Add the new dot to the existing entry. */
		op_crdt_orset_entry_t *e = &set->entries[idx];
		if (e->dot_count < OP_CRDT_ORSET_MAX_DOTS) {
			e->dots[e->dot_count++] = dot;
		} else {
			/* Evict oldest dot (dots[0]) and shift. */
			memmove(&e->dots[0], &e->dots[1],
			        (OP_CRDT_ORSET_MAX_DOTS - 1) * sizeof(e->dots[0]));
			e->dots[OP_CRDT_ORSET_MAX_DOTS - 1] = dot;
		}
	} else {
		if (orset_grow(set) == 0) {
			op_crdt_orset_entry_t *e = &set->entries[set->count++];
			memset(e, 0, sizeof(*e));
			memcpy(e->key, key, key_len);
			e->key_len = key_len;
			e->dots[0] = dot;
			e->dot_count = 1;
		}
	}

	op_crdt_cc_add(&set->cc, &dot);
	return delta;
}

op_crdt_orset_delta_t
op_crdt_orset_remove(op_crdt_orset_t *set,
                     const void *key, uint16_t key_len)
{
	op_crdt_orset_delta_t delta;
	memset(&delta, 0, sizeof(delta));
	delta.has_entry = false;

	int idx = orset_find(set, key, key_len);
	if (idx < 0)
		return delta;

	/* The remove delta's CC contains all observed dots for this element. */
	op_crdt_orset_entry_t *e = &set->entries[idx];
	for (int i = 0; i < e->dot_count; i++)
		op_crdt_cc_add(&delta.cc, &e->dots[i]);

	/* Remove the entry locally. */
	set->entries[idx] = set->entries[--set->count];

	return delta;
}

void
op_crdt_orset_apply_delta(op_crdt_orset_t *set,
                          const op_crdt_orset_delta_t *delta)
{
	/*
	 * OR-Set merge rule:
	 *   For each element e:
	 *     live_dots = (local_dots - delta_cc) ∪ (delta_dots - local_cc) ∪
	 *                 (local_dots ∩ delta_dots)
	 *     if live_dots ≠ ∅: keep element with live_dots
	 *     else: remove element
	 */
	if (delta->has_entry) {
		const op_crdt_orset_entry_t *de = &delta->entry;
		int idx = orset_find(set, de->key, de->key_len);

		if (idx >= 0) {
			/* Merge dots: keep dots not dominated by the delta's CC,
			 * plus the delta's dots not dominated by our CC. */
			op_crdt_orset_entry_t *e = &set->entries[idx];
			op_crdt_dot_t merged[OP_CRDT_ORSET_MAX_DOTS * 2];
			int mc = 0;

			for (int i = 0; i < e->dot_count && mc < OP_CRDT_ORSET_MAX_DOTS; i++) {
				if (!op_crdt_cc_contains(&delta->cc, &e->dots[i]))
					merged[mc++] = e->dots[i];
			}
			for (int i = 0; i < de->dot_count && mc < OP_CRDT_ORSET_MAX_DOTS; i++) {
				if (!op_crdt_cc_contains(&set->cc, &de->dots[i])) {
					bool dup = false;
					for (int j = 0; j < mc; j++) {
						if (op_crdt_dot_eq(&merged[j], &de->dots[i])) {
							dup = true;
							break;
						}
					}
					if (!dup) merged[mc++] = de->dots[i];
				}
			}

			if (mc > 0) {
				e->dot_count = (uint8_t)(mc > OP_CRDT_ORSET_MAX_DOTS ?
				                         OP_CRDT_ORSET_MAX_DOTS : mc);
				memcpy(e->dots, merged, (size_t)e->dot_count * sizeof(e->dots[0]));
			} else {
				set->entries[idx] = set->entries[--set->count];
			}
		} else {
			/* New element: add dots not dominated by our CC. */
			op_crdt_dot_t live[OP_CRDT_ORSET_MAX_DOTS];
			int lc = 0;
			for (int i = 0; i < de->dot_count && lc < OP_CRDT_ORSET_MAX_DOTS; i++) {
				if (!op_crdt_cc_contains(&set->cc, &de->dots[i]))
					live[lc++] = de->dots[i];
			}
			if (lc > 0 && orset_grow(set) == 0) {
				op_crdt_orset_entry_t *e = &set->entries[set->count++];
				memset(e, 0, sizeof(*e));
				memcpy(e->key, de->key, de->key_len);
				e->key_len = de->key_len;
				e->dot_count = (uint8_t)lc;
				memcpy(e->dots, live, (size_t)lc * sizeof(live[0]));
			}
		}
	} else {
		/* Remove-only delta: remove any entry whose dots are all in delta_cc. */
		for (uint32_t i = 0; i < set->count; ) {
			op_crdt_orset_entry_t *e = &set->entries[i];
			int surviving = 0;
			for (int j = 0; j < e->dot_count; j++) {
				if (!op_crdt_cc_contains(&delta->cc, &e->dots[j]))
					e->dots[surviving++] = e->dots[j];
			}
			if (surviving == 0) {
				set->entries[i] = set->entries[--set->count];
			} else {
				e->dot_count = (uint8_t)surviving;
				i++;
			}
		}
	}

	/* Merge the delta's causal context into ours. */
	op_crdt_cc_merge(&set->cc, &delta->cc);
}

bool
op_crdt_orset_contains(const op_crdt_orset_t *set,
                       const void *key, uint16_t key_len)
{
	return orset_find(set, key, key_len) >= 0;
}
