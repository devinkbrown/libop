/*
 * libop: ophion support library.
 * op_async_log.h: Asynchronous log writer thread.
 *
 * Overview
 * ========
 * op_lib_log() by default calls the installed log_cb synchronously on the
 * calling thread.  For high-frequency log paths this can stall the event
 * loop while waiting for disk writes, syslog, or remote log sinks.
 *
 * When op_start_async_log() is called, op_lib_log() switches to queuing mode:
 *
 *   Calling thread (any)     Async log writer thread
 *   ─────────────────────    ──────────────────────────────
 *   vsnprintf into buffer    pop entries, call log_cb
 *   push to MPSC stack  ───> deliver in order
 *   condvar signal
 *
 * The queue is a lock-free Treiber stack (push is a single CAS from any
 * thread; drain atomically exchanges the head with NULL in the writer
 * thread, then reverses to restore chronological order).
 *
 * Entry lifecycle: each entry is op_malloc'd by the producer and op_free'd
 * by the writer after delivery.  No fixed-size pool; no bounded back-pressure.
 *
 * Shutdown: op_stop_async_log() drains all remaining entries before
 * joining the writer thread, so no messages are lost.
 *
 * Thread safety: op_start_async_log() / op_stop_async_log() must be called
 * from the main thread only.  op_lib_log() is callable from any thread.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_ASYNC_LOG_H
#define LIBOP_ASYNC_LOG_H

#include <stdbool.h>

/*
 * op_start_async_log — start the async log writer thread.
 *
 * cb: the log_cb to call from the writer thread for each delivered entry.
 *     Typically the same callback that was passed to op_lib_init().
 *
 * After this call, op_lib_log() queues entries instead of calling log_cb
 * directly.  The supplied cb is called from the writer thread.
 *
 * Calling more than once is a no-op (returns true).
 * Must be called after op_lib_init().
 *
 * Returns true on success.
 */
bool op_start_async_log(log_cb *cb);

/*
 * op_stop_async_log — flush and stop the async log writer thread.
 *
 * Drains all queued entries (calling cb for each), then stops the
 * writer thread.  After this call, op_lib_log() reverts to synchronous
 * delivery via the callback installed in op_lib_init().
 *
 * Must not be called from within a log callback or I/O handler.
 */
void op_stop_async_log(void);

/*
 * op_async_log_active — return true if the async writer is running.
 */
bool op_async_log_active(void);

/*
 * op_async_log_enqueue — internal entry point called by op_lib_log().
 * Not for direct use; called via the log-dispatch hook installed in op_lib.c.
 */
void op_async_log_enqueue(const char *msg);

#endif /* LIBOP_ASYNC_LOG_H */
