/*
 * libop: ophion support library.
 * coro.c: Stackful coroutine implementation via POSIX ucontext_t.
 *
 * See op_coro.h for design notes and API documentation.
 *
 * Copyright (C) 2026 ophion development team.  BSD 3-Clause.
 */

#include "op_lib.h"

/* ucontext_t is POSIX-1.2008 deprecated (use SIGSTKSZ via _POSIX_C_SOURCE)
 * but still widely available on Linux, macOS, and BSDs.  Suppress the
 * deprecation warning on macOS by pinning the availability macro. */
#if defined(__APPLE__)
# define _XOPEN_SOURCE 700
#endif
#include <ucontext.h>

/* -------------------------------------------------------------------------
 * Coroutine state
 * ------------------------------------------------------------------------- */

typedef enum {
	CORO_READY,     /* created, not yet started */
	CORO_RUNNING,   /* currently executing */
	CORO_SUSPENDED, /* yielded, waiting to be resumed */
	CORO_DONE,      /* body function returned */
} coro_state_t;

struct op_coro
{
	ucontext_t  ctx;          /* this coroutine's saved register state */
	ucontext_t  caller_ctx;   /* event-loop context to return to on yield */
	op_coro_fn  fn;           /* user-supplied body function */
	void       *arg;          /* argument passed to fn */
	void       *data;         /* per-coroutine user pointer */
	uint8_t    *stack;        /* heap-allocated stack */
	size_t      stack_sz;
	coro_state_t state;
};

/* -------------------------------------------------------------------------
 * Trampoline — ucontext entry point
 * ------------------------------------------------------------------------- */

/* ucontext makecontext() takes a void(*)(void) with integer arguments.
 * To pass a pointer portably we split it across two ints. */
static void
coro_trampoline(uint32_t hi, uint32_t lo)
{
	op_coro_t *coro = (op_coro_t *)(((uintptr_t)hi << 32) | (uintptr_t)lo);
	coro->state = CORO_RUNNING;
	coro->fn(coro, coro->arg);
	coro->state = CORO_DONE;
	/* swapcontext back to caller — mandatory, or we'll segfault */
	swapcontext(&coro->ctx, &coro->caller_ctx);
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

op_coro_t *
op_coro_new(op_coro_fn fn, void *arg, size_t stack_sz)
{
	if(!fn) return NULL;
	if(stack_sz == 0) stack_sz = OP_CORO_DEFAULT_STACK_SZ;

	op_coro_t *coro = op_malloc(sizeof(*coro));
	coro->fn       = fn;
	coro->arg      = arg;
	coro->data     = NULL;
	coro->stack_sz = stack_sz;
	coro->stack    = op_malloc(stack_sz);
	coro->state    = CORO_READY;

	/* Initialise the context to run coro_trampoline on our private stack. */
	if(getcontext(&coro->ctx) != 0) {
		op_free(coro->stack);
		op_free(coro);
		return NULL;
	}
	coro->ctx.uc_stack.ss_sp    = coro->stack;
	coro->ctx.uc_stack.ss_size  = stack_sz;
	coro->ctx.uc_link           = NULL;  /* we handle the return ourselves */

	/* Split pointer into two uint32_t for makecontext() portability. */
	uintptr_t ptr = (uintptr_t)coro;
	uint32_t  hi  = (uint32_t)(ptr >> 32);
	uint32_t  lo  = (uint32_t)(ptr & 0xFFFFFFFFu);
	makecontext(&coro->ctx, (void (*)(void))coro_trampoline, 2, hi, lo);

	return coro;
}

void
op_coro_free(op_coro_t *coro)
{
	if(!coro) return;
	/* Freeing a running coroutine is undefined; caller must ensure it's not. */
	op_free(coro->stack);
	op_free(coro);
}

void
op_coro_resume(op_coro_t *coro)
{
	if(!coro || coro->state == CORO_DONE)
		return;
	/* Transfer to coroutine; returns when it yields or finishes. */
	swapcontext(&coro->caller_ctx, &coro->ctx);
}

void
op_coro_yield(op_coro_t *coro)
{
	if(!coro) return;
	coro->state = CORO_SUSPENDED;
	/* Transfer back to the event-loop caller of op_coro_resume(). */
	swapcontext(&coro->ctx, &coro->caller_ctx);
	coro->state = CORO_RUNNING;
}

bool
op_coro_done(const op_coro_t *coro)
{
	return coro == NULL || coro->state == CORO_DONE;
}

void *
op_coro_arg(const op_coro_t *coro)
{
	return coro ? coro->arg : NULL;
}

void
op_coro_set_data(op_coro_t *coro, void *data)
{
	if(coro) coro->data = data;
}

void *
op_coro_get_data(const op_coro_t *coro)
{
	return coro ? coro->data : NULL;
}
