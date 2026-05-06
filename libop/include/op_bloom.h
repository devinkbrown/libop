/*
 * libop: ophion support library.
 * op_bloom.h: Counting Bloom filter with deletion support.
 *
 * A counting Bloom filter uses k-bit counters (here: 4-bit, packed 2-per-byte)
 * instead of single bits.  This allows element deletion as long as no counter
 * overflows (each counter saturates at 15 rather than wrapping).
 *
 * Two independent hash functions are used:
 *   h1 — SipHash-1-3 with a compile-time fixed key
 *   h2 — FNV-1a 64-bit
 * Filter positions: (h1 + i*h2) % m  for i = 0..k-1  (double hashing)
 *
 * Optimal parameters are computed from (capacity, false_positive_rate):
 *   m (bits)  = -(n * ln(p)) / (ln 2)^2
 *   k (hashes)= (m/n) * ln 2
 *
 * Usage:
 *   op_bloom_t *b = op_bloom_new(10000, 0.01);  // 10k items, 1% FP rate
 *   op_bloom_add(b, "nick!user@host", 14);
 *   if (op_bloom_test(b, "nick!user@host", 14)) { ... }
 *   op_bloom_remove(b, "nick!user@host", 14);
 *   op_bloom_free(b);
 *
 * Copyright (C) 2026 ophion development team.  BSD 3-Clause.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_bloom.h directly; include op_lib.h"
#endif

#ifndef LIBOP_BLOOM_H
#define LIBOP_BLOOM_H

typedef struct op_bloom op_bloom_t;

/*
 * op_bloom_new — create a new counting Bloom filter.
 * @capacity:   expected number of elements
 * @fp_rate:    desired false-positive probability (0.0 < fp_rate < 1.0)
 * Returns NULL on allocation failure.
 */
op_bloom_t *op_bloom_new(size_t capacity, double fp_rate);

/* op_bloom_free — destroy a filter and free all memory. */
void op_bloom_free(op_bloom_t *b);

/*
 * op_bloom_add — insert key[0..len-1] into the filter.
 * Returns true if the key was already present (possible false positive).
 */
bool op_bloom_add(op_bloom_t *b, const void *key, size_t len);

/*
 * op_bloom_test — query whether key[0..len-1] is in the filter.
 * Returns true if possibly present (may be a false positive).
 * Returns false if definitely absent.
 */
bool op_bloom_test(const op_bloom_t *b, const void *key, size_t len);

/*
 * op_bloom_remove — remove one occurrence of key[0..len-1].
 * Only safe if you know the key was previously added exactly once.
 * Decrements counters; no-ops on zero counters (no underflow).
 */
void op_bloom_remove(op_bloom_t *b, const void *key, size_t len);

/* op_bloom_reset — clear all counters (empty the filter). */
void op_bloom_reset(op_bloom_t *b);

/* op_bloom_params — query the actual bit-count and hash-function count. */
void op_bloom_params(const op_bloom_t *b, size_t *out_bits, unsigned *out_k);

#endif /* LIBOP_BLOOM_H */
