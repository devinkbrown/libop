/*
 * libop: ophion support library.
 * op_hll.h: HyperLogLog approximate cardinality estimator.
 *
 * Overview
 * ========
 * HyperLogLog (Flajolet et al. 2007) estimates the number of distinct
 * elements in a multiset using O(m) memory where m = 2^b registers.
 *
 * Precision / memory trade-off
 * =============================
 *   b   m       memory   typical error
 *   4   16       16 B     ~26 %
 *   8   256     256 B     ~6.5 %
 *  10   1024      1 KB    ~3.25 %
 *  12   4096      4 KB    ~1.6 %
 *  14   16384    16 KB    ~0.8 %
 *  16   65536    64 KB    ~0.4 %
 *
 * Recommended default: b = 12 (1.6 % error, 4 KB).
 * Range: 4 ≤ b ≤ 16.
 *
 * Hash function: 64-bit MurmurHash3 finalizer applied to a
 * caller-supplied byte string.
 *
 * Typical use
 * ===========
 *   // Count distinct connecting IPs over time:
 *   op_hll_t *hll = op_hll_create(12);
 *
 *   op_hll_add(hll, ip_string, strlen(ip_string));
 *   ...
 *   uint64_t unique_ips = op_hll_count(hll);
 *
 *   // Union two HLLs (e.g., per-server stats → global):
 *   op_hll_merge(global_hll, server_hll);
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_hll.h directly; include op_lib.h"
#endif

#ifndef LIBOP_HLL_H
#define LIBOP_HLL_H

/* ---- opaque type --------------------------------------------------------- */

typedef struct op_hll op_hll_t;

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_hll_create — allocate a HyperLogLog estimator with 2^b registers.
 * b must be in [4, 16]; values outside this range are clamped.
 * Never returns NULL; aborts on OOM.
 */
op_hll_t *op_hll_create(int b);

void op_hll_destroy(op_hll_t *hll);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_hll_add — record one observation of the element described by
 * (data, len).  The element is hashed internally; the caller need not
 * pre-hash.
 */
void op_hll_add(op_hll_t *hll, const void *data, size_t len);

/*
 * op_hll_add_hash — add an already-computed 64-bit hash value.
 * Use when the caller hashes elements independently for other purposes.
 */
void op_hll_add_hash(op_hll_t *hll, uint64_t h);

/*
 * op_hll_merge — union dst with src in place (per-register max).
 * Both HLLs must have the same precision b; no-op if they differ.
 */
void op_hll_merge(op_hll_t *dst, const op_hll_t *src);

/* Reset all registers to 0 (forget all observations). */
void op_hll_reset(op_hll_t *hll);

/* ---- query --------------------------------------------------------------- */

/*
 * op_hll_count — estimate the number of distinct elements seen so far.
 * Returns an unsigned 64-bit integer.  Error is ≈ 1.04 / sqrt(m).
 */
uint64_t op_hll_count(const op_hll_t *hll);

/* ---- introspection ------------------------------------------------------- */

/* Precision parameter b as passed to op_hll_create. */
int    op_hll_precision(const op_hll_t *hll);

/* Number of registers (2^b). */
size_t op_hll_register_count(const op_hll_t *hll);

/* Memory used by register array in bytes. */
size_t op_hll_memory(const op_hll_t *hll);

#endif /* LIBOP_HLL_H */
