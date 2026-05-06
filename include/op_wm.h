/*
 * libop: ophion support library.
 * op_wm.h: Sliding-window rate meter.
 *
 * Overview
 * ========
 * op_wm tracks event counts within a sliding time window using a circular
 * array of fixed-width time buckets.  Accuracy is proportional to the
 * number of buckets: more buckets → finer granularity.
 *
 * Operations are O(n_buckets) worst-case but O(1) amortised when time
 * advances slowly (each bucket is only cleared once per window).
 *
 * Parameters
 * ==========
 *   window_ms   — total observation window in milliseconds
 *   n_buckets   — number of equal-width time buckets
 *
 * The effective resolution is window_ms / n_buckets milliseconds.
 *
 * Typical use
 * ===========
 *   // 5-second window split into 50 buckets (100 ms resolution):
 *   op_wm_t *flood = op_wm_create(5000, 50);
 *
 *   // On each incoming message:
 *   op_wm_add(flood, 1);
 *
 *   // Flood check:
 *   if (op_wm_count(flood) > FLOOD_LIMIT) kick_client();
 *
 *   // Cleanup:
 *   op_wm_destroy(flood);
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_wm.h directly; include op_lib.h"
#endif

#ifndef LIBOP_WM_H
#define LIBOP_WM_H

/* ---- types --------------------------------------------------------------- */

typedef struct wm_bucket
{
    uint64_t ts_ms;   /* epoch start this bucket represents */
    uint64_t count;
} wm_bucket_t;

typedef struct op_wm
{
    wm_bucket_t *buckets;
    uint32_t     n;          /* number of buckets */
    uint64_t     window_ms;
    uint64_t     bucket_ms;
} op_wm_t;

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_wm_create — allocate a sliding-window meter.
 *
 * window_ms  — observation window length in milliseconds (must be > 0)
 * n_buckets  — number of time buckets (must be ≥ 1; recommended 10–100)
 *
 * Uses the current wall clock on first call to op_wm_add.
 * Never returns NULL; aborts on OOM.
 */
op_wm_t *op_wm_create(uint64_t window_ms, uint32_t n_buckets);

void op_wm_destroy(op_wm_t *wm);

/* Stack-allocated init/fini (caller provides storage via op_wm_t *). */
void op_wm_init(op_wm_t *wm, uint64_t window_ms, uint32_t n_buckets);
void op_wm_fini(op_wm_t *wm);

/* ---- mutation ------------------------------------------------------------ */

/*
 * op_wm_add — record n events at the current wall-clock time.
 * Advances expired buckets to zero before adding.
 * n=0 is a no-op (use op_wm_tick() to just advance the clock).
 */
void op_wm_add(op_wm_t *wm, uint64_t n);

/* Advance the clock without adding events (prune expired buckets). */
void op_wm_tick(op_wm_t *wm);

/* Reset all buckets to zero. */
void op_wm_reset(op_wm_t *wm);

/* ---- query --------------------------------------------------------------- */

/*
 * op_wm_count — total events recorded in the last window_ms milliseconds.
 * Advances expired buckets before counting (side effect: updates state).
 */
uint64_t op_wm_count(op_wm_t *wm);

/*
 * op_wm_rate — events per second as a floating-point rate.
 * Equivalent to op_wm_count(wm) * 1000.0 / window_ms.
 */
double op_wm_rate(op_wm_t *wm);

/* ---- introspection ------------------------------------------------------- */

uint64_t op_wm_window_ms (const op_wm_t *wm);
uint32_t op_wm_n_buckets (const op_wm_t *wm);
uint64_t op_wm_bucket_ms (const op_wm_t *wm);

#endif /* LIBOP_WM_H */
