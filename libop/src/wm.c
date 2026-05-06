/*
 * libop: ophion support library.
 * wm.c: Sliding-window rate meter (circular bucket array).
 *
 * Implementation
 * --------------
 * The window is divided into n_buckets equal-width slots.  Each slot tracks:
 *   - ts_ms  : the start timestamp (ms) of that bucket's epoch
 *   - count  : accumulated events in that epoch
 *
 * On each add/tick, expired buckets are zeroed (i.e., those whose epoch
 * started more than window_ms ago).  The current bucket index is:
 *   idx = (now_ms / bucket_ms) % n_buckets
 *
 * Because each bucket is only cleared once per window, the total cost
 * across any window of time is O(n_buckets).
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

/* ---- time helper --------------------------------------------------------- */

static uint64_t
now_ms(void)
{
    struct timeval tv;
    op_gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/* ---- internal advance ---------------------------------------------------- */

/*
 * Advance any expired buckets to zero.  A bucket is expired when its
 * epoch is more than window_ms in the past.
 */
static void
advance(op_wm_t *wm, uint64_t now)
{
    for (uint32_t i = 0; i < wm->n; i++)
    {
        if (now >= wm->buckets[i].ts_ms + wm->window_ms)
        {
            wm->buckets[i].ts_ms = 0;
            wm->buckets[i].count = 0;
        }
    }
}

/* ---- lifecycle ----------------------------------------------------------- */

static void
wm_setup(op_wm_t *wm, uint64_t window_ms, uint32_t n_buckets)
{
    if (n_buckets == 0) n_buckets = 1;
    if (window_ms == 0) window_ms = 1;
    wm->n         = n_buckets;
    wm->window_ms = window_ms;
    wm->bucket_ms = window_ms / n_buckets;
    if (wm->bucket_ms == 0) wm->bucket_ms = 1;
    wm->buckets   = op_calloc(n_buckets, sizeof(wm_bucket_t));
}

op_wm_t *
op_wm_create(uint64_t window_ms, uint32_t n_buckets)
{
    op_wm_t *wm = op_malloc(sizeof(*wm));
    wm_setup(wm, window_ms, n_buckets);
    return wm;
}

void
op_wm_destroy(op_wm_t *wm)
{
    op_free(wm->buckets);
    op_free(wm);
}

void
op_wm_init(op_wm_t *wm, uint64_t window_ms, uint32_t n_buckets)
{
    wm_setup(wm, window_ms, n_buckets);
}

void
op_wm_fini(op_wm_t *wm)
{
    op_free(wm->buckets);
    wm->buckets = NULL;
}

/* ---- mutation ------------------------------------------------------------ */

void
op_wm_add(op_wm_t *wm, uint64_t n)
{
    uint64_t t   = now_ms();
    uint32_t idx = (uint32_t)((t / wm->bucket_ms) % wm->n);

    advance(wm, t);

    uint64_t epoch = (t / wm->bucket_ms) * wm->bucket_ms;
    if (wm->buckets[idx].ts_ms != epoch)
    {
        wm->buckets[idx].ts_ms = epoch;
        wm->buckets[idx].count = 0;
    }

    wm->buckets[idx].count += n;
}

void
op_wm_tick(op_wm_t *wm)
{
    advance(wm, now_ms());
}

void
op_wm_reset(op_wm_t *wm)
{
    memset(wm->buckets, 0, wm->n * sizeof(wm_bucket_t));
}

/* ---- query --------------------------------------------------------------- */

uint64_t
op_wm_count(op_wm_t *wm)
{
    uint64_t t = now_ms();
    advance(wm, t);

    uint64_t total = 0;
    for (uint32_t i = 0; i < wm->n; i++)
        total += wm->buckets[i].count;
    return total;
}

double
op_wm_rate(op_wm_t *wm)
{
    return (double)op_wm_count(wm) * 1000.0 / (double)wm->window_ms;
}

/* ---- introspection ------------------------------------------------------- */

uint64_t op_wm_window_ms(const op_wm_t *wm) { return wm->window_ms; }
uint32_t op_wm_n_buckets(const op_wm_t *wm) { return wm->n;         }
uint64_t op_wm_bucket_ms(const op_wm_t *wm) { return wm->bucket_ms; }
