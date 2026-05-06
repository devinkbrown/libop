/*
 * libop: ophion support library.
 * hll.c: HyperLogLog approximate cardinality estimator.
 *
 * Algorithm: Flajolet, Fusy, Gandouet, Meunier (2007).
 * Hash:      64-bit MurmurHash3 finalizer (Thomas Wang's mix).
 * Corrections:
 *   - Small range: linear counting when estimate < 2.5 * m
 *     and there are empty registers.
 *   - Large range: correction for hash space saturation when
 *     estimate > 2^32 / 30 (rare in practice).
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <math.h>

/* ---- internal type ------------------------------------------------------- */

struct op_hll
{
    int      b;     /* precision: number of index bits */
    uint32_t m;     /* number of registers = 2^b */
    uint8_t *regs;  /* register array (each stores max leading-zeros+1, ≤64) */
};

/* ---- hash ---------------------------------------------------------------- */

/*
 * hll_hash — 64-bit hash of arbitrary bytes via Thomas Wang's finaliser
 * seeded with a Fibonacci constant.  Fast, good avalanche, no external deps.
 */
static uint64_t
hll_hash(const void *data, size_t len)
{
    const uint8_t *p   = data;
    uint64_t       h   = UINT64_C(0x9e3779b97f4a7c15);

    for (size_t i = 0; i < len; i++)
    {
        h ^= (uint64_t)p[i];
        h *= UINT64_C(0xbf58476d1ce4e5b9);
        h ^= h >> 31;
        h *= UINT64_C(0x94d049bb133111eb);
        h ^= h >> 32;
    }

    /* Final Wang64 mix. */
    h = (~h) + (h << 21);
    h ^= h >> 24;
    h = (h + (h << 3)) + (h << 8);
    h ^= h >> 14;
    h = (h + (h << 2)) + (h << 4);
    h ^= h >> 28;
    h += h << 31;
    return h;
}

/* Number of leading zero bits in v (treating 0 as 64 zeros). */
static inline int
clz64(uint64_t v)
{
    if (v == 0) return 64;
#ifdef __GNUC__
    return __builtin_clzll((unsigned long long)v);
#else
    int n = 0;
    if (!(v >> 32)) { n += 32; v <<= 32; }
    if (!(v >> 48)) { n += 16; v <<= 16; }
    if (!(v >> 56)) { n +=  8; v <<=  8; }
    if (!(v >> 60)) { n +=  4; v <<=  4; }
    if (!(v >> 62)) { n +=  2; v <<=  2; }
    if (!(v >> 63)) { n +=  1; }
    return n;
#endif
}

/* ---- alpha constant ------------------------------------------------------ */

/*
 * hll_alpha — bias-correction constant for the raw HyperLogLog estimate.
 * Derived from Flajolet et al. Table 1.
 */
static double
hll_alpha(uint32_t m)
{
    switch (m)
    {
        case 16:  return 0.673;
        case 32:  return 0.697;
        case 64:  return 0.709;
        default:  return 0.7213 / (1.0 + 1.079 / m);
    }
}

/* ---- lifecycle ----------------------------------------------------------- */

op_hll_t *
op_hll_create(int b)
{
    if (b < 4)  b = 4;
    if (b > 16) b = 16;

    op_hll_t *hll = op_malloc(sizeof(*hll));
    hll->b    = b;
    hll->m    = 1u << b;
    hll->regs = op_calloc(hll->m, 1);
    return hll;
}

void
op_hll_destroy(op_hll_t *hll)
{
    op_free(hll->regs);
    op_free(hll);
}

/* ---- mutation ------------------------------------------------------------ */

void
op_hll_add_hash(op_hll_t *hll, uint64_t h)
{
    /* Use the top b bits as the register index. */
    uint32_t idx = (uint32_t)(h >> (64 - hll->b));

    /* Remaining bits: count leading zeros of the rest + 1 (rho).
     * Cap at (64 - b + 1): when rest == 0 clz64 returns 64, but only
     * (64 - b) bits are meaningful so the maximum valid rho is (64 - b + 1). */
    uint64_t rest  = h << hll->b;
    int      lz    = clz64(rest);
    int      max_rho = 64 - hll->b + 1;
    uint8_t  rho   = (uint8_t)(lz < max_rho ? lz + 1 : max_rho);

    if (rho > hll->regs[idx])
        hll->regs[idx] = rho;
}

void
op_hll_add(op_hll_t *hll, const void *data, size_t len)
{
    op_hll_add_hash(hll, hll_hash(data, len));
}

void
op_hll_merge(op_hll_t *dst, const op_hll_t *src)
{
    if (dst->b != src->b)
        return;
    for (uint32_t i = 0; i < dst->m; i++)
        if (src->regs[i] > dst->regs[i])
            dst->regs[i] = src->regs[i];
}

void
op_hll_reset(op_hll_t *hll)
{
    memset(hll->regs, 0, hll->m);
}

/* ---- query --------------------------------------------------------------- */

uint64_t
op_hll_count(const op_hll_t *hll)
{
    double sum  = 0.0;
    int    zero = 0;

    for (uint32_t i = 0; i < hll->m; i++)
    {
        sum += 1.0 / (1u << hll->regs[i]);
        if (hll->regs[i] == 0)
            zero++;
    }

    double m      = (double)hll->m;
    double raw    = hll_alpha(hll->m) * m * m / sum;

    /* Small-range correction: linear counting when there are empty registers. */
    if (raw <= 2.5 * m && zero > 0)
        raw = m * log(m / zero);

    /* Large-range correction (hash space saturation). */
    else if (raw > (1.0 / 30.0) * 4294967296.0)
        raw = -4294967296.0 * log(1.0 - raw / 4294967296.0);

    return (uint64_t)raw;
}

/* ---- introspection ------------------------------------------------------- */

int    op_hll_precision      (const op_hll_t *hll) { return hll->b;    }
size_t op_hll_register_count (const op_hll_t *hll) { return hll->m;    }
size_t op_hll_memory         (const op_hll_t *hll) { return hll->m;    }
