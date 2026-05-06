/*
 * libop: ophion support library.
 * op_bitset.h: Fixed-size bit array with O(1) set/clear/test and
 *              O(n/64) population-count / iteration operations.
 *
 * Design
 * ------
 * A bitset of N bits is stored as ⌈N/64⌉ uint64_t words.  The size N is
 * a compile-time constant embedded in the type name via the macro
 * OP_BITSET_DEFINE.  All operations are header-only static inline functions
 * so the compiler can constant-fold index calculations and emit optimal code.
 *
 * Usage
 * -----
 * // Define a bitset type named "chmode_set" that can hold 256 bits:
 * OP_BITSET_DEFINE(chmode_set, 256)
 *
 * chmode_set s;
 * op_bs_zero(&s);                    // clear all bits
 * op_bs_set(&s, 42);                 // set bit 42
 * bool on = op_bs_test(&s, 42);      // true
 * op_bs_clear(&s, 42);               // clear bit 42
 * int n = op_bs_count(&s);           // popcount
 * op_bs_or(&s, &other);              // bitwise OR into s
 * op_bs_and(&s, &mask);              // bitwise AND into s
 * op_bs_xor(&s, &other);             // bitwise XOR into s
 * op_bs_andnot(&s, &other);          // s &= ~other
 * bool any = op_bs_any(&s);          // true if any bit set
 * bool none = op_bs_none(&s);        // true if all bits clear
 * op_bs_not(&s);                     // invert all bits (flip)
 *
 * Iteration over set bits:
 *   // op_bs_next returns the next set bit >= `from`, or -1 if none.
 *   for (int b = op_bs_next(bs->w, NWORDS, 0); b >= 0;
 *            b = op_bs_next(bs->w, NWORDS, b + 1)) {
 *       // b is the current set-bit index
 *   }
 *
 *   // Convenience macro using the type's NWORDS constant:
 *   OP_BS_FOREACH(&modes, bit) {
 *       apply_channel_mode(chptr, bit);
 *   }
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_BITSET_H
#define LIBOP_BITSET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>   /* memset */

/* ---- bitset type definition --------------------------------------------- */

/*
 * OP_BITSET_DEFINE(name, nbits) — define a bitset type.
 *
 * nbits should be a multiple of 64, but any value ≥ 1 is accepted —
 * trailing bits in the last word are always zero after op_bs_zero().
 *
 * Usage: OP_BITSET_DEFINE(chmode_set, 256);
 * (must be followed by a semicolon at the call site to form a complete
 * statement; the trailing enum declaration absorbs it)
 *
 * The word count is always derived from sizeof at the call sites via
 * _OP_BS_NW(bs), so no separate NWORDS constant is needed.
 */
#define OP_BITSET_WORDS(nbits)  (((nbits) + 63) / 64)

#define OP_BITSET_DEFINE(name, nbits)                                    \
    typedef struct name { uint64_t w[OP_BITSET_WORDS(nbits)]; } name

/* ---- low-level word/bit helpers ----------------------------------------- */

/* Index of the 64-bit word containing bit i */
#define OP_BS_WORD(i)  ((size_t)(i) / 64u)
/* Mask for bit i within its word */
#define OP_BS_MASK(i)  (UINT64_C(1) << ((size_t)(i) % 64u))

/* ---- core per-bit operations -------------------------------------------- */

/* op_bs_zero — clear all bits */
#define op_bs_zero(bs)  memset((bs)->w, 0,    sizeof((bs)->w))
/* op_bs_fill — set all bits */
#define op_bs_fill(bs)  memset((bs)->w, 0xFF, sizeof((bs)->w))

/* op_bs_set — set bit i */
#define op_bs_set(bs, i)    ((bs)->w[OP_BS_WORD(i)] |=  OP_BS_MASK(i))
/* op_bs_clear — clear bit i */
#define op_bs_clear(bs, i)  ((bs)->w[OP_BS_WORD(i)] &= ~OP_BS_MASK(i))
/* op_bs_test — non-zero if bit i is set */
#define op_bs_test(bs, i)   ((bs)->w[OP_BS_WORD(i)] &   OP_BS_MASK(i))
/* op_bs_flip — toggle bit i */
#define op_bs_flip(bs, i)   ((bs)->w[OP_BS_WORD(i)] ^=  OP_BS_MASK(i))

/* ---- aggregate operations ----------------------------------------------- */

/*
 * Word-count for the aggregate ops below is derived from sizeof(bs->w).
 * GCC/Clang const-folds fixed-size loops entirely.
 */
#define _OP_BS_NW(bs)   (sizeof((bs)->w) / sizeof(uint64_t))

/* op_bs_or    — bs |= other  */
#define op_bs_or(bs, other)  \
    do { for (size_t _i = 0; _i < _OP_BS_NW(bs); _i++) (bs)->w[_i] |=  (other)->w[_i]; } while (0)
/* op_bs_and   — bs &= other  */
#define op_bs_and(bs, other) \
    do { for (size_t _i = 0; _i < _OP_BS_NW(bs); _i++) (bs)->w[_i] &=  (other)->w[_i]; } while (0)
/* op_bs_xor   — bs ^= other  */
#define op_bs_xor(bs, other) \
    do { for (size_t _i = 0; _i < _OP_BS_NW(bs); _i++) (bs)->w[_i] ^=  (other)->w[_i]; } while (0)
/* op_bs_andnot — bs &= ~other */
#define op_bs_andnot(bs, other) \
    do { for (size_t _i = 0; _i < _OP_BS_NW(bs); _i++) (bs)->w[_i] &= ~(other)->w[_i]; } while (0)
/* op_bs_not   — invert all bits */
#define op_bs_not(bs) \
    do { for (size_t _i = 0; _i < _OP_BS_NW(bs); _i++) (bs)->w[_i]  = ~(bs)->w[_i];   } while (0)

/* op_bs_any — true if any bit is set */
static inline bool
op_bs_any_impl(const uint64_t *w, size_t nw)
{
    for (size_t i = 0; i < nw; i++)
        if (w[i])
            return true;
    return false;
}
#define op_bs_any(bs)   op_bs_any_impl((bs)->w, _OP_BS_NW(bs))
#define op_bs_none(bs)  (!op_bs_any(bs))

/* op_bs_count — number of set bits (population count) */
static inline int
op_bs_count_impl(const uint64_t *w, size_t nw)
{
    int n = 0;
    for (size_t i = 0; i < nw; i++)
        n += __builtin_popcountll(w[i]);
    return n;
}
#define op_bs_count(bs) op_bs_count_impl((bs)->w, _OP_BS_NW(bs))

/* op_bs_eq — true if two bitsets are identical */
static inline bool
op_bs_eq_impl(const uint64_t *a, const uint64_t *b, size_t nw)
{
    for (size_t i = 0; i < nw; i++)
        if (a[i] != b[i])
            return false;
    return true;
}
#define op_bs_eq(a, b)  op_bs_eq_impl((a)->w, (b)->w, _OP_BS_NW(a))

/* op_bs_subset — true if every bit of `a` is also set in `b` (a ⊆ b) */
static inline bool
op_bs_subset_impl(const uint64_t *a, const uint64_t *b, size_t nw)
{
    for (size_t i = 0; i < nw; i++)
        if ((a[i] & b[i]) != a[i])
            return false;
    return true;
}
#define op_bs_subset(a, b)  op_bs_subset_impl((a)->w, (b)->w, _OP_BS_NW(a))

/* op_bs_intersects — true if any bit is set in both a and b */
static inline bool
op_bs_intersects_impl(const uint64_t *a, const uint64_t *b, size_t nw)
{
    for (size_t i = 0; i < nw; i++)
        if (a[i] & b[i])
            return true;
    return false;
}
#define op_bs_intersects(a, b) \
    op_bs_intersects_impl((a)->w, (b)->w, _OP_BS_NW(a))

/* ---- iteration ---------------------------------------------------------- */

/*
 * op_bs_next — find the next set bit at position >= `from`.
 *
 * Returns the bit index of the next set bit, or -1 if no bit is set at
 * or after `from`.  Uses __builtin_ctzll for O(1) per-word scan.
 *
 * `from` = 0 scans from the lowest bit.  The typical iteration idiom is:
 *
 *   for (int bit = op_bs_next(bs->w, NWORDS, 0); bit >= 0;
 *            bit = op_bs_next(bs->w, NWORDS, bit + 1)) {
 *       // process bit
 *   }
 *
 * The `nw` argument must equal the number of uint64_t words in the array.
 * Use the name##_NWORDS constant generated by OP_BITSET_DEFINE for safety.
 */
static inline int
op_bs_next(const uint64_t *w, size_t nw, int from)
{
    if (from < 0)
        return -1;

    size_t start_word = (size_t)from / 64u;
    size_t start_bit  = (size_t)from % 64u;

    if (start_word >= nw)
        return -1;

    /* Mask off bits before `start_bit` in the first word. */
    uint64_t word = w[start_word] >> start_bit;
    if (word)
        return (int)(start_word * 64u + start_bit + (size_t)__builtin_ctzll(word));

    /* Scan subsequent words. */
    for (size_t wi = start_word + 1; wi < nw; wi++)
    {
        if (w[wi])
            return (int)(wi * 64u + (size_t)__builtin_ctzll(w[wi]));
    }

    return -1;
}

/*
 * OP_BS_FOREACH(bs, bit) — iterate over set bits using the loop variable
 * declared by the caller.
 *
 * Example (requires C99 or later):
 *   int bit;
 *   OP_BS_FOREACH(&modes, bit) {
 *       apply_channel_mode(chptr, bit);
 *   }
 *
 * The macro expands to a standard for-loop; `break` and `continue` work
 * as expected.  The bitset must not be modified during iteration.
 */
#define OP_BS_FOREACH(bs, bit)                                     \
    for ((bit) = op_bs_next((bs)->w, _OP_BS_NW(bs), 0);           \
         (bit) >= 0;                                               \
         (bit) = op_bs_next((bs)->w, _OP_BS_NW(bs), (bit) + 1))

#endif /* LIBOP_BITSET_H */
