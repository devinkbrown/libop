/*
 * libop/src/lock_debug.c — lock ordering enforcement for OP_LOCK_DEBUG.
 *
 * Thread-local stack tracks which lock levels are currently held.
 * Acquiring a lock at a level <= max-held is a deadlock risk and triggers
 * a diagnostic message (and optionally an abort).
 *
 * Runtime globals are set by ircd from [debug] in ircd.toml after config
 * parse.  The initial values match the compile-time defaults so everything
 * works even if the ircd never calls the setters.
 *
 * When OP_LOCK_DEBUG is not defined, this file compiles to nothing.
 *
 * Copyright (C) 2026 ophion development team.  BSD 3-Clause.
 */

#define _GNU_SOURCE
#include <libop_config.h>

#ifdef OP_LOCK_DEBUG

#include <op_lock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Runtime-configurable globals.
 *
 * These are declared extern in op_lock.h and read by the inline lock
 * macros.  ircd pushes values from ConfigDebugEntry after config parse.
 * ---------------------------------------------------------------------- */

int64_t op_lock_slow_threshold_ns   = OP_LOCK_SLOW_NS_DEFAULT;
int     op_lock_deadlock_timeout_sec = OP_LOCK_DEADLOCK_SEC_DEFAULT;
int     op_lock_ordering_fatal       = 0;

/* Default thread name accessor.  The ircd overrides this via the strong
 * definition in logger.c (ilog_get_thread_name wraps this symbol).
 * Using a weak attribute so the linker picks the ircd's version if present. */
__attribute__((weak))
const char *
_op_lock_thread_name(void)
{
	static _Thread_local char _name[16] = "?";
	if (_name[0] == '?') {
		/* Try to get the OS-level thread name. */
#if defined(__linux__)
		pthread_getname_np(pthread_self(), _name, sizeof(_name));
#endif
	}
	return _name;
}

#define OP_LOCK_MAX_HELD  16

static _Thread_local int _held_levels[OP_LOCK_MAX_HELD];
static _Thread_local int _held_count = 0;

void
_op_lock_check_order(int level, const char *file, int line)
{
	for (int i = 0; i < _held_count; i++) {
		if (level <= _held_levels[i]) {
			if (_op_lock_order_cb)
				_op_lock_order_cb(file, line, level, _held_levels[i]);
			else
				fprintf(stderr,
				        "LOCK ORDER VIOLATION at %s:%d: "
				        "acquiring level %d while holding level %d\n",
				        file, line, level, _held_levels[i]);

			if (op_lock_ordering_fatal)
				abort();
		}
	}
}

int
_op_lock_held_count(void)
{
	return _held_count;
}

const int *
_op_lock_held_levels(void)
{
	return _held_levels;
}

void
_op_lock_push(int level)
{
	if (_held_count < OP_LOCK_MAX_HELD)
		_held_levels[_held_count++] = level;
}

void
_op_lock_pop(int level)
{
	/* Pop the most recent matching level (LIFO). */
	for (int i = _held_count - 1; i >= 0; i--) {
		if (_held_levels[i] == level) {
			_held_levels[i] = _held_levels[--_held_count];
			return;
		}
	}
}

#endif /* OP_LOCK_DEBUG */
