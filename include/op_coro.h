/*
 * libop: ophion support library.
 * op_coro.h: Stackful coroutines for sequential async protocol code.
 *
 * Provides cooperative, stackful coroutines backed by POSIX ucontext_t.
 * Coroutines yield back to the event loop and are resumed when I/O is ready.
 *
 * Design:
 *   - Each coroutine has its own heap-allocated stack (default 64 KB).
 *   - Coroutines are cooperative: they must yield() explicitly; no preemption.
 *   - Only one coroutine runs at a time; the event loop is the "main" context.
 *   - Coroutines are NOT thread-safe; all calls must be on the event-loop thread.
 *
 * Typical use (ACME HTTP client, SASL exchange, etc.):
 *
 *   static void my_coro_fn(op_coro_t *self, void *arg) {
 *       // Do some I/O setup, register a read callback...
 *       op_coro_yield(self);        // suspend: wait for data
 *       // ...resumed by the read callback via op_coro_resume()...
 *       // Do more work, yield again if needed.
 *   }
 *
 *   op_coro_t *c = op_coro_new(my_coro_fn, arg, 0);
 *   op_coro_resume(c);   // start it; runs until first yield or completion
 *   // later, from a read callback:
 *   op_coro_resume(c);
 *   if (op_coro_done(c)) op_coro_free(c);
 *
 * Fallback: on platforms without <ucontext.h>, a minimal computed-goto
 * Duff's-device state machine is used instead (no separate stack; the
 * coroutine fn must not use local variables across yields in that mode).
 *
 * Copyright (C) 2026 ophion development team.  BSD 3-Clause.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_coro.h directly; include op_lib.h"
#endif

#ifndef LIBOP_CORO_H
#define LIBOP_CORO_H

typedef struct op_coro op_coro_t;
typedef void (*op_coro_fn)(op_coro_t *self, void *arg);

#define OP_CORO_DEFAULT_STACK_SZ  (65536)   /* 64 KB per coroutine */

/*
 * op_coro_new — allocate a coroutine.
 * @fn:       coroutine body; must call op_coro_yield() to suspend
 * @arg:      opaque argument passed to fn
 * @stack_sz: stack size in bytes; 0 → OP_CORO_DEFAULT_STACK_SZ
 * Returns NULL on allocation failure.
 */
op_coro_t *op_coro_new(op_coro_fn fn, void *arg, size_t stack_sz);

/* op_coro_free — destroy a coroutine.  Safe to call before it finishes
 * (e.g., on connection teardown), but only from outside the coroutine. */
void op_coro_free(op_coro_t *coro);

/*
 * op_coro_resume — transfer control into the coroutine.
 * Returns when the coroutine yields or finishes.
 * Must not be called from within a coroutine (no nested coros).
 */
void op_coro_resume(op_coro_t *coro);

/*
 * op_coro_yield — suspend the coroutine and return to the caller of
 * op_coro_resume().  Must only be called from within the coroutine body.
 */
void op_coro_yield(op_coro_t *coro);

/* op_coro_done — returns true after the coroutine body has returned. */
bool op_coro_done(const op_coro_t *coro);

/* op_coro_arg — retrieve the opaque arg passed to op_coro_new(). */
void *op_coro_arg(const op_coro_t *coro);

/* op_coro_set_data / op_coro_get_data — per-coroutine user pointer for
 * storing I/O state (e.g., partial HTTP response buffer). */
void  op_coro_set_data(op_coro_t *coro, void *data);
void *op_coro_get_data(const op_coro_t *coro);

#endif /* LIBOP_CORO_H */
