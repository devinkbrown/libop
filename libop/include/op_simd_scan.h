/*
 * libop/include/op_simd_scan.h — SIMD-accelerated byte-scan primitives.
 *
 * These functions replace inner hot loops in the IRC message parser that
 * search for delimiter characters (space 0x20, NUL 0x00, semicolon 0x3B).
 *
 * Runtime dispatch selects the best available ISA extension:
 *   x86-64: AVX2 (32 bytes/iter) → SSE2 (16 bytes/iter) → scalar
 *   AArch64: NEON (16 bytes/iter) → scalar
 *   Other:   scalar
 *
 * All functions are safe to call with any pointer; they never read past `end`
 * (for bounded variants) or past the NUL terminator (for unbounded variants).
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */
#ifndef LIBOP_LIB_H
# error "Do not include op_simd_scan.h directly; include op_lib.h"
#endif

#ifndef OP_SIMD_SCAN_H
#define OP_SIMD_SCAN_H

#include <stddef.h>

/*
 * op_simd_find_delim — scan [p, end) for the first byte equal to `d1` or
 * `d2` (either may be 0 to match NUL as a terminator).
 *
 * Returns a pointer to the first matching byte, or `end` if none found.
 * `end` must be >= `p`; no read occurs past `end`.
 */
const char *op_simd_find_delim(const char *p, const char *end,
                               unsigned char d1, unsigned char d2);

/*
 * op_simd_count_leading — count contiguous bytes equal to `c` starting at `p`
 * (up to but not including `end`).  Used to skip leading spaces efficiently.
 */
size_t op_simd_count_leading(const char *p, const char *end, unsigned char c);

#endif /* OP_SIMD_SCAN_H */
