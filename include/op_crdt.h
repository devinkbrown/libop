/*
 * libop — op_crdt.h
 * Conflict-Free Replicated Data Types for LADON S2S mesh protocol.
 *
 * Implements:
 *   - Delta-state OR-Set with dot-store (channel membership, ban lists)
 *   - LWW-Register with deterministic tiebreak (topics, nicks, modes)
 *   - G-Counter (monotonic counters)
 *
 * All types satisfy the join-semilattice property:
 *   commutative, associative, idempotent merge.
 *
 * Dot-store OR-Set uses (replica_id, counter) dots instead of UUIDs,
 * keeping each delta at ~48 bytes for a single add/remove.
 *
 * Copyright (c) 2026 Ophion Development Team.  MIT License.
 */

#ifndef OP_CRDT_H
#define OP_CRDT_H

#ifndef LIBOP_LIB_H
# error "Do not include op_crdt.h directly; include op_lib.h"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <op_hlc.h>

/* =====================================================================
 * Dot: a globally unique event identifier (replica_id, counter)
 * ===================================================================== */

typedef struct op_crdt_dot {
	uint8_t  replica[8];   /* first 8 bytes of server Ed25519 pubkey */
	uint64_t counter;      /* monotonically increasing per-replica */
} op_crdt_dot_t;

static inline bool
op_crdt_dot_eq(const op_crdt_dot_t *a, const op_crdt_dot_t *b)
{
	return memcmp(a->replica, b->replica, 8) == 0 && a->counter == b->counter;
}

/* =====================================================================
 * Causal Context: compact representation of all observed dots.
 *
 * For each replica, stores the max contiguous counter.  Dots above
 * the contiguous frontier are stored in a small overflow set.
 * This keeps the CC at O(replicas) instead of O(total_operations).
 * ===================================================================== */

#define OP_CRDT_CC_MAX_REPLICAS   32
#define OP_CRDT_CC_MAX_OVERFLOW   64

typedef struct op_crdt_cc_entry {
	uint8_t  replica[8];
	uint64_t max_contiguous;  /* all dots (replica, 1..max_contiguous) are observed */
} op_crdt_cc_entry_t;

typedef struct op_crdt_cc {
	op_crdt_cc_entry_t entries[OP_CRDT_CC_MAX_REPLICAS];
	uint8_t            count;
	op_crdt_dot_t      overflow[OP_CRDT_CC_MAX_OVERFLOW];
	uint8_t            overflow_count;
} op_crdt_cc_t;

/* Check if a dot is in the causal context. */
static inline bool
op_crdt_cc_contains(const op_crdt_cc_t *cc, const op_crdt_dot_t *dot)
{
	for (int i = 0; i < cc->count; i++) {
		if (memcmp(cc->entries[i].replica, dot->replica, 8) == 0) {
			if (dot->counter <= cc->entries[i].max_contiguous)
				return true;
			break;
		}
	}
	for (int i = 0; i < cc->overflow_count; i++) {
		if (op_crdt_dot_eq(&cc->overflow[i], dot))
			return true;
	}
	return false;
}

/* Add a dot to the causal context. */
static inline void
op_crdt_cc_add(op_crdt_cc_t *cc, const op_crdt_dot_t *dot)
{
	int ridx = -1;
	for (int i = 0; i < cc->count; i++) {
		if (memcmp(cc->entries[i].replica, dot->replica, 8) == 0) {
			ridx = i;
			break;
		}
	}

	if (ridx < 0) {
		if (cc->count >= OP_CRDT_CC_MAX_REPLICAS)
			return;
		ridx = cc->count++;
		memcpy(cc->entries[ridx].replica, dot->replica, 8);
		cc->entries[ridx].max_contiguous = 0;
	}

	if (dot->counter == cc->entries[ridx].max_contiguous + 1) {
		cc->entries[ridx].max_contiguous = dot->counter;
		/* Compact: pull in any overflow dots that are now contiguous. */
		bool changed = true;
		while (changed) {
			changed = false;
			for (int i = 0; i < cc->overflow_count; i++) {
				if (memcmp(cc->overflow[i].replica, dot->replica, 8) == 0 &&
				    cc->overflow[i].counter == cc->entries[ridx].max_contiguous + 1) {
					cc->entries[ridx].max_contiguous++;
					cc->overflow[i] = cc->overflow[--cc->overflow_count];
					changed = true;
					break;
				}
			}
		}
	} else if (dot->counter > cc->entries[ridx].max_contiguous + 1) {
		if (cc->overflow_count < OP_CRDT_CC_MAX_OVERFLOW)
			cc->overflow[cc->overflow_count++] = *dot;
	}
}

/* Merge another causal context into this one. */
static inline void
op_crdt_cc_merge(op_crdt_cc_t *dst, const op_crdt_cc_t *src)
{
	for (int i = 0; i < src->count; i++) {
		op_crdt_dot_t dot = {
			.counter = src->entries[i].max_contiguous
		};
		memcpy(dot.replica, src->entries[i].replica, 8);

		int didx = -1;
		for (int j = 0; j < dst->count; j++) {
			if (memcmp(dst->entries[j].replica, dot.replica, 8) == 0) {
				didx = j;
				break;
			}
		}
		if (didx >= 0) {
			if (src->entries[i].max_contiguous > dst->entries[didx].max_contiguous)
				dst->entries[didx].max_contiguous = src->entries[i].max_contiguous;
		} else if (dst->count < OP_CRDT_CC_MAX_REPLICAS) {
			dst->entries[dst->count++] = src->entries[i];
		}
	}
	for (int i = 0; i < src->overflow_count; i++) {
		if (!op_crdt_cc_contains(dst, &src->overflow[i]))
			op_crdt_cc_add(dst, &src->overflow[i]);
	}
}

/* =====================================================================
 * Delta-state OR-Set
 *
 * State: a dot-store (element → set of dots) plus a causal context.
 * The dot-store is implemented as a flat array of (element_key, dot)
 * pairs.  element_key is an opaque blob of up to OP_CRDT_ORSET_KEY_MAX
 * bytes (sufficient for nick!ident@host masks, channel names, etc.).
 *
 * A delta for add(e): dot-store = {e: {new_dot}}, cc = {new_dot}
 * A delta for remove(e): dot-store = {}, cc = {observed dots of e}
 * ===================================================================== */

#define OP_CRDT_ORSET_KEY_MAX    256
#define OP_CRDT_ORSET_MAX_DOTS   4  /* max dots per element (concurrent adds) */

typedef struct op_crdt_orset_entry {
	uint8_t       key[OP_CRDT_ORSET_KEY_MAX];
	uint16_t      key_len;
	op_crdt_dot_t dots[OP_CRDT_ORSET_MAX_DOTS];
	uint8_t       dot_count;
} op_crdt_orset_entry_t;

/* Full OR-Set state is dynamically allocated; this header tracks metadata. */
typedef struct op_crdt_orset {
	op_crdt_orset_entry_t *entries;
	uint32_t               count;
	uint32_t               capacity;
	op_crdt_cc_t           cc;
} op_crdt_orset_t;

/* A delta produced by an add or remove operation. */
typedef struct op_crdt_orset_delta {
	op_crdt_orset_entry_t entry;   /* single entry (or empty for remove) */
	bool                  has_entry;
	op_crdt_cc_t          cc;
} op_crdt_orset_delta_t;

/* Initialise an empty OR-Set. */
void op_crdt_orset_init(op_crdt_orset_t *set, uint32_t initial_cap);

/* Free an OR-Set. */
void op_crdt_orset_free(op_crdt_orset_t *set);

/* Generate and apply an add-delta.  Returns the delta for propagation. */
op_crdt_orset_delta_t op_crdt_orset_add(op_crdt_orset_t *set,
                                         const void *key, uint16_t key_len,
                                         const uint8_t replica[8]);

/* Generate and apply a remove-delta.  Returns the delta for propagation. */
op_crdt_orset_delta_t op_crdt_orset_remove(op_crdt_orset_t *set,
                                            const void *key, uint16_t key_len);

/* Apply a received delta to the local state (merge). */
void op_crdt_orset_apply_delta(op_crdt_orset_t *set,
                                const op_crdt_orset_delta_t *delta);

/* Check if an element is in the set. */
bool op_crdt_orset_contains(const op_crdt_orset_t *set,
                             const void *key, uint16_t key_len);

/* Return the number of live elements. */
static inline uint32_t
op_crdt_orset_size(const op_crdt_orset_t *set)
{
	return set->count;
}

/* =====================================================================
 * LWW-Register: Last-Writer-Wins register with deterministic tiebreak.
 *
 * Value is an opaque blob.  On concurrent writes with the same HLC
 * timestamp, the server with the lexicographically greater replica key
 * wins (deterministic total order).
 * ===================================================================== */

#define OP_CRDT_LWW_VALUE_MAX   512

typedef struct op_crdt_lww {
	uint8_t       value[OP_CRDT_LWW_VALUE_MAX];
	uint16_t      value_len;
	op_hlc_t      hlc;
	uint8_t       writer[8];   /* replica key of last writer */
} op_crdt_lww_t;

#define OP_CRDT_LWW_ZERO  ((op_crdt_lww_t){ .value_len = 0, .hlc = OP_HLC_ZERO })

/* Set a new value.  Returns true if the value was updated. */
static inline bool
op_crdt_lww_set(op_crdt_lww_t *reg, const void *value, uint16_t len,
                op_hlc_t hlc, const uint8_t writer[8])
{
	if (len > OP_CRDT_LWW_VALUE_MAX)
		return false;

	int cmp = op_hlc_cmp(hlc, reg->hlc);
	if (cmp < 0)
		return false;
	if (cmp == 0 && memcmp(writer, reg->writer, 8) <= 0)
		return false;

	memcpy(reg->value, value, len);
	reg->value_len = len;
	reg->hlc = hlc;
	memcpy(reg->writer, writer, 8);
	return true;
}

/* Merge a remote LWW register into the local one. */
static inline bool
op_crdt_lww_merge(op_crdt_lww_t *lww_local, const op_crdt_lww_t *lww_remote)
{
	return op_crdt_lww_set(lww_local, lww_remote->value, lww_remote->value_len,
	                       lww_remote->hlc, lww_remote->writer);
}

/* =====================================================================
 * G-Counter: grow-only distributed counter.
 *
 * Each replica maintains its own count.  The global value is the sum
 * of all replica counts.  Merge is component-wise max.
 * ===================================================================== */

#define OP_CRDT_GCTR_MAX_REPLICAS  32

typedef struct op_crdt_gctr_entry {
	uint8_t  replica[8];
	uint64_t count;
} op_crdt_gctr_entry_t;

typedef struct op_crdt_gctr {
	op_crdt_gctr_entry_t entries[OP_CRDT_GCTR_MAX_REPLICAS];
	uint8_t              count;
} op_crdt_gctr_t;

#define OP_CRDT_GCTR_ZERO  ((op_crdt_gctr_t){ .count = 0 })

/* Increment the counter for a replica. */
static inline uint64_t
op_crdt_gctr_inc(op_crdt_gctr_t *ctr, const uint8_t replica[8])
{
	for (int i = 0; i < ctr->count; i++) {
		if (memcmp(ctr->entries[i].replica, replica, 8) == 0)
			return ++ctr->entries[i].count;
	}
	if (ctr->count >= OP_CRDT_GCTR_MAX_REPLICAS)
		return 0;
	int idx = ctr->count++;
	memcpy(ctr->entries[idx].replica, replica, 8);
	ctr->entries[idx].count = 1;
	return 1;
}

/* Get the global counter value (sum of all replicas). */
static inline uint64_t
op_crdt_gctr_value(const op_crdt_gctr_t *ctr)
{
	uint64_t total = 0;
	for (int i = 0; i < ctr->count; i++)
		total += ctr->entries[i].count;
	return total;
}

/* Merge another G-Counter (component-wise max). */
static inline void
op_crdt_gctr_merge(op_crdt_gctr_t *dst, const op_crdt_gctr_t *src)
{
	for (int i = 0; i < src->count; i++) {
		int didx = -1;
		for (int j = 0; j < dst->count; j++) {
			if (memcmp(dst->entries[j].replica, src->entries[i].replica, 8) == 0) {
				didx = j;
				break;
			}
		}
		if (didx >= 0) {
			if (src->entries[i].count > dst->entries[didx].count)
				dst->entries[didx].count = src->entries[i].count;
		} else if (dst->count < OP_CRDT_GCTR_MAX_REPLICAS) {
			dst->entries[dst->count++] = src->entries[i];
		}
	}
}

#endif /* OP_CRDT_H */
