/*
 *  libop: ophion support library.
 *  event.c: Event scheduler — binary min-heap implementation.
 *
 *  Replaces the legacy linear-scan dlink list with a proper binary min-heap
 *  ordered by ev_entry.when.  Complexity:
 *
 *    op_event_add / op_event_addonce / op_event_addish  O(log n)
 *    op_event_delete                                     O(log n)
 *    op_event_update                                     O(log n)
 *    op_event_run  (fire all due events)                 O(k log n) where k = fired
 *    op_event_next (time to next event)                  O(1)
 *
 *  The heap invariant: heap[i].when <= heap[2i+1].when && heap[i].when <= heap[2i+2].when
 *  (0-indexed).  Each ev_entry carries its heap index in .hidx so deletion is
 *  O(log n) without an O(n) search.
 *
 *  Copyright (C) 1998-2000 Regents of the University of California
 *  Copyright (C) 2001-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2026      ophion development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_arena.h>
#include <commio-int.h>
#include <event-int.h>

#define EV_NAME_LEN     33
#define HEAP_INIT_CAP   32

/* ---- min-heap state ------------------------------------------------------ */

static char last_event_ran[EV_NAME_LEN];

static struct ev_entry **heap;     /* array of pointers into ev_entry objects */
static size_t heap_len;            /* live entries in the heap                */
static size_t heap_cap;            /* allocated slots in heap[]               */

/*
 * op_current_loading_module — name of the module being registered right now.
 * Set by modules.c around mapi_regfn() calls; cleared immediately after.
 * op_event_add_common() and add_hook_prio() read this to auto-tag every
 * registered callback with its owning module, enabling safe purge on unload.
 *
 * NULL means "ircd core" — those entries are never purged.
 */
const char *op_current_loading_module = NULL;

/* ---- heap primitives ----------------------------------------------------- */

/*
 * heap_set — place ev at position i, keeping .hidx in sync.
 */
static inline void
heap_set(size_t i, struct ev_entry *ev)
{
	heap[i]      = ev;
	ev->hidx     = i;
}

/*
 * heap_sift_up — restore the heap invariant upward from index i.
 * Called after inserting a new entry at the end and after a swap that
 * decreased the key at position i.
 */
static void
heap_sift_up(size_t i)
{
	while (i > 0)
	{
		size_t parent = (i - 1) / 2;
		if (heap[parent]->when <= heap[i]->when)
			break;
		struct ev_entry *tmp = heap[parent];
		heap_set(parent, heap[i]);
		heap_set(i,      tmp);
		i = parent;
	}
}

/*
 * heap_sift_down — restore the heap invariant downward from index i.
 * Called after replacing the root with the last element (pop), or after
 * a swap that increased the key at position i.
 */
static void
heap_sift_down(size_t i)
{
	for (;;)
	{
		size_t left  = 2 * i + 1;
		size_t right = 2 * i + 2;
		size_t min   = i;

		if (left  < heap_len && heap[left]->when  < heap[min]->when)
			min = left;
		if (right < heap_len && heap[right]->when < heap[min]->when)
			min = right;

		if (min == i)
			break;

		struct ev_entry *tmp = heap[min];
		heap_set(min, heap[i]);
		heap_set(i,   tmp);
		i = min;
	}
}

/*
 * heap_push — add ev to the heap.  Grows the backing array as needed.
 */
static void
heap_push(struct ev_entry *ev)
{
	if (__builtin_expect(heap_len == heap_cap, 0))
	{
		heap_cap = heap_cap ? heap_cap * 2 : HEAP_INIT_CAP;
		heap     = op_realloc(heap, heap_cap * sizeof(*heap));
	}
	heap_set(heap_len++, ev);
	heap_sift_up(heap_len - 1);
}

/*
 * heap_remove — remove the entry at index i from the heap.
 * The last element is moved to fill the gap, then the heap invariant is
 * restored by sifting up or down as appropriate.
 */
static void
heap_remove(size_t i)
{
	if (i == heap_len - 1)
	{
		/* Last element — just shrink. */
		heap_len--;
		return;
	}

	struct ev_entry *last = heap[--heap_len];
	heap_set(i, last);

	/* The replacement may be smaller or larger than its new neighbours. */
	heap_sift_up(i);
	heap_sift_down(last->hidx);   /* hidx was updated by heap_set above */
}

/* ---- jitter helper ------------------------------------------------------- */

/*
 * op_event_frequency — compute effective delay.
 * Negative frequency means "apply ±1/3 jitter".
 */
static inline time_t
op_event_frequency(time_t frequency)
{
	if (__builtin_expect(frequency < 0, 0))
	{
		const time_t two_third = (2 * (time_t)llabs((long long)frequency)) / 3;
		frequency = two_third + ((time_t)(arc4random() % 1000u) * two_third) / 1000;
	}
	return frequency;
}

/* ---- common constructor -------------------------------------------------- */

static __attribute__((cold)) struct ev_entry *
op_event_add_common(const char *name, EVH *func, void *arg,
                    time_t when, time_t frequency)
{
	struct ev_entry *ev = op_malloc(sizeof(*ev));

	ev->func      = func;
	ev->name      = op_strndup(name, EV_NAME_LEN);
	ev->arg       = arg;
	ev->when      = op_current_time() + when;
	ev->next      = when;
	ev->frequency = frequency;
	ev->dead      = 0;
	ev->comm_ptr  = NULL;
	ev->hidx      = 0;   /* will be set properly by heap_push */
	/* Auto-tag with the module currently being loaded (NULL = ircd core). */
	ev->mod_name  = op_current_loading_module
	                ? op_strndup(op_current_loading_module, EV_NAME_LEN)
	                : NULL;

	heap_push(ev);
	op_io_sched_event(ev, (int)when);
	return ev;
}

/* ---- public API ---------------------------------------------------------- */

__attribute__((cold))
struct ev_entry *
op_event_add(const char *name, EVH *func, void *arg, time_t when)
{
	if (op_unlikely(when <= 0))
	{
		op_lib_log("op_event_add: tried to schedule %s event with a delay of "
		           "%" PRId64 " seconds", name, (int64_t)when);
		when = 1;
	}
	return op_event_add_common(name, func, arg, when, when);
}

__attribute__((cold))
struct ev_entry *
op_event_addonce(const char *name, EVH *func, void *arg, time_t when)
{
	if (op_unlikely(when <= 0))
	{
		op_lib_log("op_event_addonce: tried to schedule %s event to run in "
		           "%" PRId64 " seconds", name, (int64_t)when);
		when = 1;
	}
	return op_event_add_common(name, func, arg, when, 0);
}

__attribute__((cold))
struct ev_entry *
op_event_addish(const char *name, EVH *func, void *arg, time_t delta_ish)
{
	delta_ish = labs(delta_ish);
	if (delta_ish >= 3)
		delta_ish = -delta_ish;
	return op_event_add_common(name, func, arg,
	                           op_event_frequency(delta_ish), delta_ish);
}

__attribute__((cold))
void
op_event_delete(struct ev_entry *ev)
{
	if (__builtin_expect(ev == NULL, 0))
		return;

	ev->dead = 1;
	op_io_unsched_event(ev);
	/* Lazy removal: the dead entry will be reaped in op_event_run(). */
}

__attribute__((cold))
void
op_event_find_delete(EVH *func, void *arg)
{
	for (size_t i = 0; i < heap_len; i++)
	{
		if (heap[i]->func == func && heap[i]->arg == arg)
		{
			op_event_delete(heap[i]);
			return;
		}
	}
}

/*
 * op_run_one_event — fire ev immediately (called directly by I/O backends).
 *
 * After the callback:
 *   - If the event is one-shot (frequency == 0), or the callback called
 *     op_event_delete(ev) setting ev->dead, remove it from the heap and free.
 *   - Otherwise reschedule by updating ev->when and re-heapifying.
 *
 * Using ev->hidx for both removal and re-heap is mandatory: the callback may
 * call op_event_add() which pushes a new entry and may change ev's position
 * in the heap; relying on a stale position-0 assumption is incorrect.
 */
__attribute__((hot))
void
op_run_one_event(struct ev_entry *ev)
{
	op_strlcpy(last_event_ran, ev->name, sizeof(last_event_ran));
	OP_WITH_ARENA_SCOPE(op_event_arena(), ev->func(ev->arg));

	if (!ev->frequency || ev->dead)
	{
		/* One-shot or deleted by the callback — remove immediately. */
		if (!ev->dead)
			op_io_unsched_event(ev);
		heap_remove(ev->hidx);
		op_free(ev->name);
		op_free(ev->mod_name);
		op_free(ev);
		return;
	}

	ev->when = op_current_time() + op_event_frequency(ev->frequency);
	/* Sift up first (new when may be smaller — rare), then down (common). */
	heap_sift_up(ev->hidx);
	heap_sift_down(ev->hidx);
}

/*
 * op_event_run — dispatch all events whose deadline has passed.
 *
 * With the min-heap, heap[0] is always the earliest event.  We fire and
 * reschedule (or reap) events from the top until the heap is empty or the
 * minimum deadline is in the future.
 *
 * Only used when the I/O backend does not support native timer delivery.
 * Backends with timerfd/kqueue timers call op_run_one_event() directly.
 */
__attribute__((hot))
void
op_event_run(void)
{
	if (op_io_supports_event())
		return;

	time_t now = op_current_time();

	while (heap_len > 0)
	{
		struct ev_entry *ev = heap[0];

		if (__builtin_expect(ev->dead, 0))
		{
			/* Reap dead entries from the top of the heap. */
			heap_remove(0);
			op_free(ev->name);
			op_free(ev->mod_name);
			op_free(ev);
			continue;
		}

		if (ev->when > now)
			break;   /* Min deadline is in the future — done. */

		op_strlcpy(last_event_ran, ev->name, sizeof(last_event_ran));
		OP_WITH_ARENA_SCOPE(op_event_arena(), ev->func(ev->arg));

		if (ev->dead || !ev->frequency)
		{
			/* Dead or one-shot — remove using current hidx (callback may
			 * have changed ev's heap position via op_event_add). */
			heap_remove(ev->hidx);
			op_free(ev->name);
			op_free(ev->mod_name);
			op_free(ev);
		}
		else
		{
			ev->when = now + op_event_frequency(ev->frequency);
			/* Sift both directions: callback may have changed heap layout. */
			heap_sift_up(ev->hidx);
			heap_sift_down(ev->hidx);
		}
	}
}

/*
 * op_event_io_register_all — re-register all events with the I/O backend.
 * Called after a backend re-initialisation (e.g. signalfd re-setup).
 */
__attribute__((cold))
void
op_event_io_register_all(void)
{
	if (!op_io_supports_event())
		return;

	for (size_t i = 0; i < heap_len; i++)
	{
		struct ev_entry *ev = heap[i];
		time_t remaining    = ev->when - op_current_time();
		op_io_sched_event(ev, (int)(remaining > 0 ? remaining : 0));
	}
}

/*
 * op_event_purge_module — cancel and free every event registered by `mod_name`.
 *
 * Called synchronously from modules.c just before dlclose().  The heap is
 * compacted in-place: matching entries are freed immediately so no
 * callback pointer from the unloaded module remains in the heap.
 *
 * O(n) where n = number of live events (typically < 50 in a running ircd).
 */
__attribute__((cold))
void
op_event_purge_module(const char *mod_name)
{
	if (mod_name == NULL)
		return;

	size_t new_len = 0;

	for (size_t i = 0; i < heap_len; i++)
	{
		struct ev_entry *ev = heap[i];

		if (ev->mod_name != NULL && strcmp(ev->mod_name, mod_name) == 0)
		{
			/* Cancel from the I/O backend and free immediately. */
			op_io_unsched_event(ev);
			op_free(ev->name);
			op_free(ev->mod_name);
			op_free(ev);
		}
		else
		{
			heap[new_len] = ev;
			ev->hidx      = new_len;
			new_len++;
		}
	}

	heap_len = new_len;

	/* Rebuild heap invariant from the bottom up — O(n). */
	if (heap_len > 1)
	{
		for (ssize_t j = (ssize_t)(heap_len / 2) - 1; j >= 0; j--)
			heap_sift_down((size_t)j);
	}
}

__attribute__((cold))
void
op_event_init(void)
{
	op_strlcpy(last_event_ran, "NONE", sizeof(last_event_ran));
	heap     = NULL;
	heap_len = 0;
	heap_cap = 0;
}

/*
 * op_event_next — return the timestamp of the earliest pending event.
 * Returns -1 when no events are scheduled.  O(1): just peek at heap[0].
 */
__attribute__((hot))
time_t
op_event_next(void)
{
	return heap_len > 0 ? heap[0]->when : -1;
}

__attribute__((cold))
void
op_event_update(struct ev_entry *ev, time_t freq)
{
	if (__builtin_expect(ev == NULL, 0))
		return;

	ev->frequency = freq;

	time_t new_when = op_current_time() + op_event_frequency(freq);
	ev->when = new_when;
	/* New deadline may be earlier or later — sift both directions. */
	heap_sift_up(ev->hidx);
	heap_sift_down(ev->hidx);
}

__attribute__((cold))
void
op_dump_events(void (*func)(char *, void *), void *ptr)
{
	char buf[512];
	const size_t len = sizeof(buf);

	snprintf(buf, len, "Last event to run: %s", last_event_ran);
	func(buf, ptr);

	op_strlcpy(buf, "Operation                    Next Execution", len);
	func(buf, ptr);

	for (size_t i = 0; i < heap_len; i++)
	{
		struct ev_entry *ev = heap[i];
		snprintf(buf, len,
		         "%-28s %-4ld seconds (frequency=%d)",
		         ev->name,
		         (long)(ev->when - op_current_time()),
		         (int)ev->frequency);
		func(buf, ptr);
	}
}

__attribute__((cold))
void
op_set_back_events(time_t by)
{
	for (size_t i = 0; i < heap_len; i++)
	{
		struct ev_entry *ev = heap[i];
		if (ev->when > by)
			ev->when -= by;
		else
			ev->when = 0;
	}
	/* Rebuild heap after bulk key changes (Floyd's algorithm, O(n)). */
	for (size_t i = heap_len / 2; i-- > 0; )
		heap_sift_down(i);
}
