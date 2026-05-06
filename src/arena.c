/*
 * libop/src/arena.c — Arena (bump) allocator implementation.
 *
 * See libop/include/op_arena.h for the full design rationale.
 *
 * Copyright (C) 2026 ophion development team
 * Same licence as libop (ISC / BSD).
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_arena.h>
#include <string.h>
#include <stddef.h>

/* ── Global per-event arena ──────────────────────────────────────────────── */

/*
 * 64 KB inline buffer.  Static storage: never freed, never moved.
 * Allocated in BSS (zero-initialised) — no runtime cost.
 */
static char _event_arena_buf[OP_ARENA_DEFAULT_CAPACITY];

op_arena_t op_event_arena_g = {
	.base            = _event_arena_buf,
	.used            = 0,
	.capacity        = OP_ARENA_DEFAULT_CAPACITY,
	.overflow        = NULL,
	.overflow_bytes  = 0,
	.alloc_count     = 0,
};

/* ── Internal helpers ────────────────────────────────────────────────────── */

static inline size_t
align_up(size_t x)
{
	return (x + OP_ARENA_ALIGN - 1) & ~(size_t)(OP_ARENA_ALIGN - 1);
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

void
op_arena_init(op_arena_t *a, char *buf, size_t capacity)
{
	if (buf == NULL)
	{
		buf = op_malloc(capacity);
	}
	a->base           = buf;
	a->used           = 0;
	a->capacity       = capacity;
	a->overflow       = NULL;
	a->overflow_bytes = 0;
	a->alloc_count    = 0;
}

void
op_arena_fini(op_arena_t *a)
{
	/* Free all overflow blocks. */
	struct op_arena_overflow *blk = a->overflow;
	while (blk)
	{
		struct op_arena_overflow *next = blk->next;
		op_free(blk);
		blk = next;
	}
	a->overflow       = NULL;
	a->overflow_bytes = 0;
	a->used           = 0;

	/* If base was heap-allocated (capacity set and base != static buf),
	 * callers that used NULL buf in op_arena_init own the pointer.
	 * We free only if it is not the global static buffer. */
	if (a->base && a->base != _event_arena_buf)
	{
		op_free(a->base);
		a->base     = NULL;
		a->capacity = 0;
	}
}

void
op_arena_reset(op_arena_t *a)
{
	/* Rewind the inline pointer in one store. */
	a->used        = 0;
	a->alloc_count = 0;

	/* Free all overflow blocks. */
	struct op_arena_overflow *blk = a->overflow;
	while (blk)
	{
		struct op_arena_overflow *next = blk->next;
		op_free(blk);
		blk = next;
	}
	a->overflow       = NULL;
	a->overflow_bytes = 0;
}

/* ── Allocation ──────────────────────────────────────────────────────────── */

void *
op_arena_alloc(op_arena_t *a, size_t size)
{
	size_t aligned = align_up(size ? size : 1);

	a->alloc_count++;

	if (__builtin_expect(a->used + aligned <= a->capacity, 1))
	{
		/* Fast path: bump the inline pointer. */
		void *p = a->base + a->used;
		a->used += aligned;
		return p;
	}

	/*
	 * Slow path: inline slab exhausted.  Allocate a heap block.
	 *
	 * This should be extremely rare for the event arena (64 KB >> any
	 * single IRC message).  If it fires often, increase
	 * OP_ARENA_DEFAULT_CAPACITY.
	 */
	size_t total = sizeof(struct op_arena_overflow) + aligned;
	struct op_arena_overflow *blk = op_malloc(total);
	blk->next         = a->overflow;
	a->overflow       = blk;
	a->overflow_bytes += aligned;

	return (char *)blk + sizeof(struct op_arena_overflow);
}

void *
op_arena_calloc(op_arena_t *a, size_t size)
{
	void *p = op_arena_alloc(a, size);
	memset(p, 0, size);
	return p;
}

char *
op_arena_strdup(op_arena_t *a, const char *s)
{
	if (s == NULL)
		return NULL;
	size_t len = strlen(s);
	char *copy = op_arena_alloc(a, len + 1);
	memcpy(copy, s, len + 1);
	return copy;
}

char *
op_arena_strndup(op_arena_t *a, const char *s, size_t n)
{
	if (s == NULL)
		return NULL;
	size_t len = strnlen(s, n);
	char *copy = op_arena_alloc(a, len + 1);
	memcpy(copy, s, len);
	copy[len] = '\0';
	return copy;
}
