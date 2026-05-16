/*
 * libop — op_vclock.h
 * Fixed-size vector clock for small server meshes.
 *
 * LADON uses a compact vector clock with at most OP_VCLOCK_MAX_ENTRIES
 * replicas.  Each entry is a (server_key_prefix, counter) pair where
 * server_key_prefix is the first 8 bytes of the server's Ed25519 public
 * key (a stable, globally unique identifier).
 *
 * The vector clock supports:
 *   - tick(server_id): increment own counter
 *   - merge(other):    component-wise max
 *   - cmp(a, b):       causal ordering (happens-before, concurrent, etc.)
 *   - encode/decode:   to/from flat byte arrays for wire transmission
 *
 * Copyright (c) 2026 Ophion Development Team.  MIT License.
 */

#ifndef OP_VCLOCK_H
#define OP_VCLOCK_H

#ifndef LIBOP_LIB_H
# error "Do not include op_vclock.h directly; include op_lib.h"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define OP_VCLOCK_MAX_ENTRIES  32

typedef struct op_vclock_entry {
	uint8_t  server_key[8];
	uint64_t counter;
} op_vclock_entry_t;

typedef struct op_vclock {
	op_vclock_entry_t entries[OP_VCLOCK_MAX_ENTRIES];
	uint8_t           count;
} op_vclock_t;

#define OP_VCLOCK_ZERO  ((op_vclock_t){ .count = 0 })

/* Find the index of a server key, or -1 if not present. */
static inline int
op_vclock_find(const op_vclock_t *vc, const uint8_t server_key[8])
{
	for (int i = 0; i < vc->count; i++) {
		if (memcmp(vc->entries[i].server_key, server_key, 8) == 0)
			return i;
	}
	return -1;
}

/* Get the counter value for a server, or 0 if not present. */
static inline uint64_t
op_vclock_get(const op_vclock_t *vc, const uint8_t server_key[8])
{
	int idx = op_vclock_find(vc, server_key);
	return idx >= 0 ? vc->entries[idx].counter : 0;
}

/* Increment the counter for a server (creates entry if needed).
 * Returns the new counter value, or 0 on overflow. */
static inline uint64_t
op_vclock_tick(op_vclock_t *vc, const uint8_t server_key[8])
{
	int idx = op_vclock_find(vc, server_key);
	if (idx >= 0) {
		return ++vc->entries[idx].counter;
	}
	if (vc->count >= OP_VCLOCK_MAX_ENTRIES)
		return 0;
	idx = vc->count++;
	memcpy(vc->entries[idx].server_key, server_key, 8);
	vc->entries[idx].counter = 1;
	return 1;
}

/* Merge another vector clock into this one (component-wise max). */
static inline void
op_vclock_merge(op_vclock_t *dst, const op_vclock_t *src)
{
	for (int i = 0; i < src->count; i++) {
		int idx = op_vclock_find(dst, src->entries[i].server_key);
		if (idx >= 0) {
			if (src->entries[i].counter > dst->entries[idx].counter)
				dst->entries[idx].counter = src->entries[i].counter;
		} else if (dst->count < OP_VCLOCK_MAX_ENTRIES) {
			dst->entries[dst->count] = src->entries[i];
			dst->count++;
		}
	}
}

/*
 * Causal ordering comparison.
 * Returns:
 *   -1  if a happens-before b  (a < b)
 *    0  if a == b
 *    1  if b happens-before a  (a > b)
 *    2  if a and b are concurrent  (a || b)
 */
static inline int
op_vclock_cmp(const op_vclock_t *a, const op_vclock_t *b)
{
	bool a_le_b = true, b_le_a = true;

	/* Check all entries in a against b. */
	for (int i = 0; i < a->count; i++) {
		uint64_t bval = op_vclock_get(b, a->entries[i].server_key);
		if (a->entries[i].counter > bval) a_le_b = false;
		if (a->entries[i].counter < bval) b_le_a = false;
	}

	/* Check entries in b not in a. */
	for (int i = 0; i < b->count; i++) {
		uint64_t aval = op_vclock_get(a, b->entries[i].server_key);
		if (b->entries[i].counter > aval) b_le_a = false;
		if (b->entries[i].counter < aval) a_le_b = false;
	}

	if (a_le_b && b_le_a) return 0;   /* equal */
	if (a_le_b)            return -1;  /* a < b */
	if (b_le_a)            return 1;   /* a > b */
	return 2;                          /* concurrent */
}

/* Serialized size: 1 byte count + count * (8 + 8) bytes. */
static inline size_t
op_vclock_wire_size(const op_vclock_t *vc)
{
	return 1 + (size_t)vc->count * 16;
}

/* Encode to a byte buffer.  Returns bytes written. */
static inline size_t
op_vclock_encode(const op_vclock_t *vc, uint8_t *out, size_t cap)
{
	size_t need = op_vclock_wire_size(vc);
	if (cap < need) return 0;

	out[0] = vc->count;
	size_t pos = 1;
	for (int i = 0; i < vc->count; i++) {
		memcpy(out + pos, vc->entries[i].server_key, 8);
		pos += 8;
		uint64_t c = vc->entries[i].counter;
		out[pos++] = (uint8_t)(c >> 56);
		out[pos++] = (uint8_t)(c >> 48);
		out[pos++] = (uint8_t)(c >> 40);
		out[pos++] = (uint8_t)(c >> 32);
		out[pos++] = (uint8_t)(c >> 24);
		out[pos++] = (uint8_t)(c >> 16);
		out[pos++] = (uint8_t)(c >> 8);
		out[pos++] = (uint8_t)(c);
	}
	return pos;
}

/* Decode from a byte buffer.  Returns bytes consumed, or 0 on error. */
static inline size_t
op_vclock_decode(op_vclock_t *vc, const uint8_t *buf, size_t len)
{
	if (len < 1) return 0;
	uint8_t cnt = buf[0];
	if (cnt > OP_VCLOCK_MAX_ENTRIES) return 0;
	if (len < 1 + (size_t)cnt * 16) return 0;

	vc->count = cnt;
	size_t pos = 1;
	for (int i = 0; i < cnt; i++) {
		memcpy(vc->entries[i].server_key, buf + pos, 8);
		pos += 8;
		vc->entries[i].counter =
			((uint64_t)buf[pos]   << 56) | ((uint64_t)buf[pos+1] << 48) |
			((uint64_t)buf[pos+2] << 40) | ((uint64_t)buf[pos+3] << 32) |
			((uint64_t)buf[pos+4] << 24) | ((uint64_t)buf[pos+5] << 16) |
			((uint64_t)buf[pos+6] << 8)  |  (uint64_t)buf[pos+7];
		pos += 8;
	}
	return pos;
}

#endif /* OP_VCLOCK_H */
