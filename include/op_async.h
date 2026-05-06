/*
 * libop: ophion support library.
 * op_async.h: Generic async task executor with main-thread completion callbacks.
 *
 * Overview
 * ========
 * op_async provides a "fire and forget" pattern for CPU- or I/O-bound work
 * that should not block the event loop:
 *
 *   1. Caller submits a task (work function + context) to op_async_submit().
 *   2. A worker thread (from the internal thread pool) executes the work fn.
 *   3. On completion, the result is posted to an MPSC completion queue.
 *   4. The event loop drains the completion queue via op_async_drain()
 *      (called once per event loop tick) and invokes done_fn on the result.
 *
 *                        op_async_submit()
 *                              │
 *                              ▼
 *                    ┌─────────────────┐
 *                    │ op_thread_pool  │  worker threads
 *                    └────────┬────────┘
 *                             │ work_fn(ctx) finishes
 *                             ▼
 *                    ┌─────────────────┐
 *                    │ completion ring │  MPSC lock-free ring
 *                    └────────┬────────┘
 *                             │ eventfd signal
 *                             ▼
 *           op_async_drain() on main thread → done_fn(ctx)
 *
 * Thread safety
 * =============
 * op_async_submit() is safe from any thread.
 * op_async_drain()  must be called from the main thread only.
 * work_fn()         runs on a worker thread; must not touch event-loop state.
 * done_fn()         runs on the main thread; full ircd state is accessible.
 *
 * Usage example (async config file read)
 * ======================================
 *   typedef struct { char *path; char *content; } read_ctx_t;
 *
 *   static void do_read(void *arg) {
 *       read_ctx_t *c = arg;
 *       c->content = slurp_file(c->path);  // blocking — OK in worker
 *   }
 *   static void on_done(void *arg) {
 *       read_ctx_t *c = arg;
 *       process_config(c->content);        // main thread — safe
 *       free(c->content); free(c);
 *   }
 *   read_ctx_t *c = calloc(1, sizeof(*c));
 *   c->path = strdup("/etc/ophion/ircd.conf");
 *   op_async_submit(do_read, on_done, c);
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_ASYNC_H
#define LIBOP_ASYNC_H

#include <stdbool.h>
#include <stddef.h>

/* ---- types --------------------------------------------------------------- */

/*
 * op_async_work_t — function executed in a worker thread.
 * May block.  Must not call event-loop APIs.
 */
typedef void (*op_async_work_t)(void *ctx);

/*
 * op_async_done_t — completion callback invoked on the main thread.
 * Receives the same ctx that was passed to op_async_submit().
 * May freely access all ircd state.
 */
typedef void (*op_async_done_t)(void *ctx);

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_async_init — initialise the async task system.
 *
 * nthreads: worker thread count (0 = auto-detect, same as op_tpool_create(0)).
 *
 * Must be called after op_lib_init() and before the first op_async_submit().
 * The completion eventfd is registered with the active I/O backend so that
 * op_async_drain() is called automatically from the event loop.
 *
 * Returns true on success.
 */
bool op_async_init(int nthreads);

/*
 * op_async_shutdown — drain all pending completions and destroy the pool.
 *
 * Blocks until all in-flight work_fn calls have finished and all done_fn
 * completions have been delivered.
 */
void op_async_shutdown(void);

/* ---- submission ---------------------------------------------------------- */

/*
 * op_async_submit — enqueue a task.
 *
 * work_fn(ctx) is called on a worker thread (may block).
 * done_fn(ctx) is called on the main thread after work_fn returns.
 *
 * If done_fn is NULL the task is fire-and-forget; ctx cleanup is the
 * caller's responsibility inside work_fn.
 *
 * Safe to call from any thread (including worker threads).
 */
void op_async_submit(op_async_work_t work_fn, op_async_done_t done_fn, void *ctx);

/* ---- completion drain ---------------------------------------------------- */

/*
 * op_async_drain — deliver all pending completions to their done_fn.
 *
 * Must be called from the main thread.  Typically called once per event
 * loop tick, either explicitly or via the registered I/O event handler.
 *
 * Returns the number of completions delivered.
 */
int op_async_drain(void);

/* ---- introspection ------------------------------------------------------- */

/*
 * op_async_pending — number of tasks submitted but not yet completed
 * (either still running in a worker or waiting in the completion ring).
 */
size_t op_async_pending(void);

/*
 * op_async_active — returns true if op_async_init() has been called
 * successfully and the task port has not been shut down.
 */
bool op_async_active(void);

#endif /* LIBOP_ASYNC_H */
