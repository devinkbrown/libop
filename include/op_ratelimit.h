/*
 * libop: ophion support library.
 * op_ratelimit.h: Generic token-bucket rate limiter (header-only).
 *
 * A token-bucket limiter: the bucket refills at a constant rate (tokens/second)
 * and each event consumes one token.  If the bucket is empty the event is
 * rejected.  Bursting up to `capacity` tokens is allowed, allowing short
 * traffic spikes without false positives.
 *
 * Design choices
 * --------------
 * - Header-only: all functions are static inline.  No .c file, no link dep.
 * - Time is expressed in microseconds (uint64_t) so callers can pass
 *   op_current_time_usec() or any monotonic clock without conversion.
 * - No dynamic allocation: the limiter struct is embedded wherever needed
 *   (per-client, per-channel, per-IP) and initialised with op_ratelimit_init().
 * - Thread-safe: NOT — callers must hold their own locks if needed.
 *
 * Usage
 * -----
 *   op_ratelimit_t flood;
 *   // Allow 5 messages/sec burst up to 10:
 *   op_ratelimit_init(&flood, 10, 5, op_current_time_usec());
 *
 *   // In the message handler:
 *   if (!op_ratelimit_check(&flood, op_current_time_usec())) {
 *       // drop or throttle the message
 *   }
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_ratelimit.h directly; include op_lib.h"
#endif

#ifndef LIBOP_RATELIMIT_H
#define LIBOP_RATELIMIT_H

#include <stdint.h>

/* ---- type ---------------------------------------------------------------- */

/*
 * op_ratelimit_t — token-bucket limiter state.
 *
 * Keep all fields in one struct so it can be embedded directly in per-client
 * or per-channel structs without extra pointer indirection.
 *
 *   capacity    — maximum tokens the bucket can hold (burst size)
 *   rate_usec   — microseconds per token (1 / rate_per_second * 1e6)
 *   tokens      — current token count (scaled by OP_RATELIMIT_SCALE)
 *   last_refill — time of last refill (microseconds)
 */

/* Internal fixed-point scale factor.  Tokens are stored as integers
 * multiplied by this factor to avoid floating-point arithmetic. */
#define OP_RATELIMIT_SCALE  1000u

typedef struct op_ratelimit
{
    uint64_t last_refill;   /* µs timestamp of last op_ratelimit_check() */
    uint64_t rate_usec;     /* µs per 1 token (1_000_000 / rate_per_sec)  */
    uint32_t tokens;        /* current tokens * OP_RATELIMIT_SCALE         */
    uint32_t capacity;      /* maximum tokens * OP_RATELIMIT_SCALE         */
} op_ratelimit_t;

/* ---- construction -------------------------------------------------------- */

/*
 * op_ratelimit_init — initialise a rate limiter.
 *
 *   rl            — pointer to uninitialised op_ratelimit_t
 *   capacity      — maximum burst size (tokens)
 *   rate_per_sec  — sustained rate (tokens per second)
 *   now_usec      — current monotonic time in microseconds
 *
 * The bucket starts full (tokens == capacity).
 */
static inline void
op_ratelimit_init(op_ratelimit_t *rl, unsigned capacity, unsigned rate_per_sec,
                  uint64_t now_usec)
{
    rl->rate_usec   = (rate_per_sec > 0) ? 1000000u / rate_per_sec : UINT64_MAX;
    rl->capacity    = capacity    * OP_RATELIMIT_SCALE;
    rl->tokens      = rl->capacity;   /* start full */
    rl->last_refill = now_usec;
}

/* ---- checking ------------------------------------------------------------ */

/*
 * op_ratelimit_check — consume one token.
 *
 * Refills the bucket based on elapsed time, then attempts to consume one
 * token.
 *
 * Returns true  — token consumed; event is allowed.
 * Returns false — bucket empty; event should be dropped or throttled.
 *
 * `now_usec` must be >= the last value passed to this function or to
 * op_ratelimit_init().  Passing a stale clock is safe (no negative refill).
 */
static inline bool
op_ratelimit_check(op_ratelimit_t *rl, uint64_t now_usec)
{
    /* Compute elapsed microseconds since last refill, clamped to positive. */
    uint64_t elapsed = (now_usec > rl->last_refill) ? now_usec - rl->last_refill : 0;
    rl->last_refill  = now_usec;

    /* Add new tokens: elapsed / rate_usec tokens, scaled. */
    if (rl->rate_usec < UINT64_MAX && elapsed > 0)
    {
        uint64_t new_tokens = (elapsed / rl->rate_usec) * OP_RATELIMIT_SCALE;
        uint64_t total      = (uint64_t)rl->tokens + new_tokens;
        rl->tokens = (total > rl->capacity) ? rl->capacity : (uint32_t)total;
    }

    /* Consume one token (OP_RATELIMIT_SCALE units). */
    if (rl->tokens < OP_RATELIMIT_SCALE)
        return false;

    rl->tokens -= OP_RATELIMIT_SCALE;
    return true;
}

/*
 * op_ratelimit_check_n — consume n tokens at once.
 *
 * Useful for weighted events (e.g. long messages consume more tokens).
 * Returns false if fewer than n tokens are available.
 */
static inline bool
op_ratelimit_check_n(op_ratelimit_t *rl, uint64_t now_usec, unsigned n)
{
    /* Refill first (reuse the single-token path without the consume). */
    uint64_t elapsed = (now_usec > rl->last_refill) ? now_usec - rl->last_refill : 0;
    rl->last_refill  = now_usec;

    if (rl->rate_usec < UINT64_MAX && elapsed > 0)
    {
        uint64_t new_tokens = (elapsed / rl->rate_usec) * OP_RATELIMIT_SCALE;
        uint64_t total      = (uint64_t)rl->tokens + new_tokens;
        rl->tokens = (total > rl->capacity) ? rl->capacity : (uint32_t)total;
    }

    uint32_t cost = n * OP_RATELIMIT_SCALE;
    if (rl->tokens < cost)
        return false;

    rl->tokens -= cost;
    return true;
}

/* ---- introspection ------------------------------------------------------- */

/*
 * op_ratelimit_tokens — return the current number of whole tokens available.
 *
 * Does NOT advance the clock or consume anything.  Useful for stats/debug.
 */
static inline unsigned
op_ratelimit_tokens(const op_ratelimit_t *rl)
{
    return rl->tokens / OP_RATELIMIT_SCALE;
}

/*
 * op_ratelimit_reset — refill the bucket to capacity without consuming time.
 *
 * Useful when a client authenticates (exempt from flood rules) or after a
 * connection is promoted to oper.
 */
static inline void
op_ratelimit_reset(op_ratelimit_t *rl, uint64_t now_usec)
{
    rl->tokens      = rl->capacity;
    rl->last_refill = now_usec;
}

/*
 * op_ratelimit_drain — empty the bucket instantly.
 *
 * Force a client into rate-limited state (e.g. after a flood warning).
 */
static inline void
op_ratelimit_drain(op_ratelimit_t *rl)
{
    rl->tokens = 0;
}

/* ---- convenience: current monotonic time --------------------------------- */

/*
 * op_current_time_usec — return the current CLOCK_MONOTONIC time in µs.
 *
 * Use this to feed op_ratelimit_init / op_ratelimit_check in ircd code.
 * Falls back to gettimeofday if CLOCK_MONOTONIC is unavailable.
 */
static inline uint64_t
op_current_time_usec(void)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
    /* Fallback: gettimeofday. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000u + (uint64_t)tv.tv_usec;
}

#endif /* LIBOP_RATELIMIT_H */
