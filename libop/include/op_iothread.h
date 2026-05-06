/*
 * libop: ophion support library.
 * op_iothread.h: Dedicated I/O poll thread for epoll-based event loops.
 *
 * Architecture
 * ============
 * An IRC server's event loop has two distinct phases:
 *
 *   1. Kernel poll   — epoll_wait() blocks until fds are ready.
 *   2. Dispatch      — I/O handlers and timer callbacks run.
 *
 * In a single-threaded loop these run sequentially: while epoll_wait is
 * blocking, no timers can fire.  With a dedicated poll thread they run
 * concurrently: the poll thread always has epoll_wait in flight, while the
 * main thread dispatches handlers and fires timers at correct granularity.
 *
 * Design
 * ======
 *                      ┌──────────────────────────────────────┐
 *   Poll thread        │  epoll_wait() → push to ep_ring      │
 *   (owns epfd)        │  → write(notifyfd, 1) to wake main   │
 *                      └──────────────────────────────────────┘
 *                                          │  eventfd
 *                      ┌──────────────────────────────────────┐
 *   Main thread        │  poll(notifyfd, timeout) → read ring │
 *   (protocol/timers)  │  → call handlers → op_event_run()   │
 *                      └──────────────────────────────────────┘
 *
 * The ring is a lock-free SPSC queue of struct epoll_event values using C11
 * atomics with acquire/release ordering.  No allocation per event; the ring
 * is statically sized (OP_IOTHREAD_RING_CAP, power-of-two).
 *
 * Thread safety
 * =============
 * - Poll thread is the sole producer.
 * - Main thread is the sole consumer.
 * - Handler dispatch (ep_dispatch / ep_rearm in epoll.c) still runs on the
 *   main thread; it accesses F->pflags_lock just as before.
 * - op_setselect_epoll() may be called from worker threads (guarded by
 *   F->pflags_lock as always).
 *
 * Usage
 * =====
 *   // After op_lib_init():
 *   op_start_pollthread();         // enable threaded polling
 *
 *   // To stop (e.g. before fork/exec):
 *   op_stop_pollthread();
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_IOTHREAD_H
#define LIBOP_IOTHREAD_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ---- ring capacity ------------------------------------------------------- */

/*
 * OP_IOTHREAD_RING_CAP — maximum epoll_events the ring can hold.
 *
 * Must be a power of two.  4096 events × 12 bytes = 48 KiB (L2-friendly).
 * Sized to absorb a full EPOLL_EVENTS_MAX burst without back-pressure.
 * The poll thread drops events on overflow (they will re-fire on the next
 * epoll_wait call since EPOLLONESHOT is not set on the per-thread wait).
 *
 * Adjust upward if the server handles many thousands of connections.
 */
#define OP_IOTHREAD_RING_CAP  4096u

/* ---- opaque type --------------------------------------------------------- */

/*
 * op_iothread_t — returned by op_iothread_create(); owned by epoll.c.
 * Callers use only op_start_pollthread() / op_stop_pollthread().
 */
typedef struct op_iothread op_iothread_t;

/* ---- public API ---------------------------------------------------------- */

/*
 * op_start_pollthread — start the dedicated I/O poll thread.
 *
 * Must be called after op_lib_init() and only when the epoll backend is
 * active.  Safe to call at most once; subsequent calls are no-ops.
 *
 * After this call, op_select_epoll() switches to threaded mode: it blocks on
 * the notification eventfd (not epoll_wait) and drains the event ring.
 *
 * Returns true on success, false if the backend does not support threaded
 * mode or if a thread could not be created.
 */
bool op_start_pollthread(void);

/*
 * op_stop_pollthread — stop the dedicated I/O poll thread.
 *
 * Signals the poll thread to exit and joins it.  After this call,
 * op_select_epoll() reverts to inline (single-threaded) mode.
 *
 * Must NOT be called from within an I/O handler or timer callback.
 * Call before fork() / exec() or during graceful shutdown.
 */
void op_stop_pollthread(void);

/*
 * op_pollthread_active — return true if the poll thread is running.
 */
bool op_pollthread_active(void);

#endif /* LIBOP_IOTHREAD_H */
