/*
 * libop/include/op_arena.h — Arena (bump) allocator tied to the event loop.
 *
 * An arena allocator services all short-lived allocations within a single
 * event loop tick using a single 64 KB contiguous memory block:
 *
 *   1. At the start of each epoll/io_uring event iteration, the arena pointer
 *      is reset to 0 (one CPU instruction).
 *   2. Every temporary string, token array, or scratch buffer is allocated by
 *      bumping a pointer forward in the 64 KB block — no malloc(), no lock.
 *   3. When the tick finishes, op_arena_reset() is called, freeing every
 *      allocation made during the tick in O(1) regardless of count.
 *
 * Because the lifetime of every arena allocation is bounded by the event
 * iteration, memory leaks in parsing/dispatch code are structurally
 * impossible — there is nothing to free and nothing to forget.
 *
 * Overflow safety
 * ───────────────
 * If the inline buffer is exhausted (rare: 64 KB handles ~128 full IRC
 * messages with room to spare), allocations fall through to the heap and
 * are tracked in a singly-linked list.  op_arena_reset() frees them all.
 *
 * Scope marks
 * ───────────
 * op_arena_save() / op_arena_restore() let callers cheaply sub-scope the
 * arena without a full reset.  Use this inside a tight loop over many small
 * objects: save before the loop body, restore after.  Note: marks only rewind
 * the inline buffer; overflow blocks are freed only on full reset.
 *
 * Global event arena
 * ──────────────────
 * op_event_arena() returns a pointer to the process-global per-tick arena.
 * It is reset automatically by op_lib_loop() / op_lib_loop_tick() at the
 * start of each iteration.  Module code should use this rather than managing
 * its own arena for common temporary allocations.
 *
 * Copyright (C) 2026 ophion development team
 * Same licence as libop (ISC / BSD).
 */

#pragma once
#ifndef OP_ARENA_H
#define OP_ARENA_H

#include <stddef.h>
#include <string.h>

/* Default inline buffer size (bytes). */
#define OP_ARENA_DEFAULT_CAPACITY  (64 * 1024)

/* All allocations are rounded up to this alignment. */
#define OP_ARENA_ALIGN             (sizeof(void *))

/* ── Types ───────────────────────────────────────────────────────────────── */

struct op_arena_overflow
{
	struct op_arena_overflow *next;
	/* allocated data begins immediately after this header */
};

/*
 * op_arena_t — the arena object.
 *
 * Embed one statically for the global event arena.  For ad-hoc scoped arenas,
 * declare on the stack and call op_arena_init() / op_arena_fini().
 */
typedef struct op_arena
{
	char                     *base;       /* inline slab start */
	size_t                    used;       /* bytes used in base[] */
	size_t                    capacity;   /* total bytes in base[] */
	struct op_arena_overflow *overflow;   /* heap fallback list */
	size_t                    overflow_bytes; /* total heap overflow bytes */
	size_t                    alloc_count;    /* total allocations since reset */
} op_arena_t;

/*
 * op_arena_mark_t — a saved position within the inline buffer.
 *
 * Marks DO NOT capture overflow state.  Code that may overflow should use
 * a full op_arena_reset() rather than mark/restore.
 */
typedef size_t op_arena_mark_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Initialise an arena backed by a caller-supplied or heap-allocated buffer.
 * If buf == NULL, a heap buffer of `capacity` bytes is allocated.
 */
void op_arena_init(op_arena_t *a, char *buf, size_t capacity);

/*
 * Release any heap resources held by the arena (overflow blocks + heap buf
 * if one was allocated by op_arena_init).  Does NOT free `a` itself.
 */
void op_arena_fini(op_arena_t *a);

/*
 * Reset the arena to empty: rewind the inline pointer to 0 and free all
 * overflow blocks.  The inline buffer is reused in the next tick.
 * This is O(number-of-overflow-blocks), typically O(1).
 */
void op_arena_reset(op_arena_t *a);

/* ── Allocation ──────────────────────────────────────────────────────────── */

/*
 * Allocate `size` bytes, pointer-aligned.  Never returns NULL (calls
 * op_lib_log and abort() on OOM — the same contract as op_malloc).
 */
void *op_arena_alloc(op_arena_t *a, size_t size);

/*
 * Allocate `size` bytes, zero-initialised.
 */
void *op_arena_calloc(op_arena_t *a, size_t size);

/*
 * Duplicate a NUL-terminated string into the arena.
 */
char *op_arena_strdup(op_arena_t *a, const char *s);

/*
 * Duplicate at most `n` bytes of `s` and NUL-terminate.
 */
char *op_arena_strndup(op_arena_t *a, const char *s, size_t n);

/* ── Scope marks ─────────────────────────────────────────────────────────── */

/*
 * Save the current arena position.  Use op_arena_restore() to reclaim all
 * allocations made since the save — cheap as setting a->used = mark.
 */
static inline op_arena_mark_t
op_arena_save(op_arena_t *a)
{
	return a->used;
}

/*
 * Restore the arena to the saved position.  All allocations made after the
 * save are invalidated.  Overflow blocks are NOT freed by this call; only
 * op_arena_reset() frees them.
 */
static inline void
op_arena_restore(op_arena_t *a, op_arena_mark_t mark)
{
	if (mark < a->used)
		a->used = mark;
}

/* ── Global per-event arena ──────────────────────────────────────────────── */

/*
 * The global arena backed by a 64 KB static buffer.
 * Reset automatically by op_lib_loop() / op_lib_loop_tick() each tick.
 */
extern op_arena_t op_event_arena_g;

static inline op_arena_t *
op_event_arena(void)
{
	return &op_event_arena_g;
}

/*
 * Convenience: allocate from the global per-event arena.
 */
static inline void *
op_ealloc(size_t size)
{
	return op_arena_alloc(&op_event_arena_g, size);
}

static inline char *
op_estrdup(const char *s)
{
	return op_arena_strdup(&op_event_arena_g, s);
}

static inline char *
op_estrndup(const char *s, size_t n)
{
	return op_arena_strndup(&op_event_arena_g, s, n);
}

/*
 * OP_WITH_ARENA_SCOPE(arena_ptr, statement) — execute `statement` with a
 * scoped arena mark that is automatically restored when the statement exits.
 * Useful for wrapping a single callback invocation:
 *
 *   OP_WITH_ARENA_SCOPE(op_event_arena(), hdl(F, data));
 */
#define OP_WITH_ARENA_SCOPE(arena_ptr, stmt)                      \
	do {                                                          \
		op_arena_mark_t _arena_mark_ = op_arena_save(arena_ptr); \
		(stmt);                                                   \
		op_arena_restore((arena_ptr), _arena_mark_);             \
	} while (0)

#endif /* OP_ARENA_H */
