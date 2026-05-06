/*
 *  Ophion IRC Daemon
 *  libop/src/op_memory.c: Out-of-memory handler.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2024-2026 Ophion IRC Daemon contributors
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
#include <stdatomic.h>

/*
 * op_outofmemory — called when malloc/realloc returns NULL.
 *
 * Thread safety: if two threads exhaust memory simultaneously, exactly one
 * proceeds to log and restart; the other (or any re-entrant call that arrives
 * while the first is inside op_lib_restart) falls straight through to abort().
 *
 * We use atomic_exchange rather than a plain volatile int so the test-and-set
 * is a single indivisible operation across all cores with no compiler
 * reordering.  The acquire/release fencing of sequential-consistency (the
 * default for atomic_exchange) ensures the abort() in the loser path is
 * visible after the winner's store.
 *
 * op_lib_restart is declared __attribute__((noreturn)).  If it somehow
 * returns anyway (e.g. the restart callback was not installed), the trailing
 * abort() terminates the process regardless.
 */
__attribute__((cold, noreturn))
void
op_outofmemory(void)
{
	static atomic_int in_flight = 0;

	/* Only the first caller gets to log and restart; everyone else aborts. */
	if (atomic_exchange(&in_flight, 1) != 0)
		abort();

	op_lib_log("Out of memory: restarting server...");
	op_lib_restart("Out of Memory");

	/* op_lib_restart is [[noreturn]]; abort() is the belt to its suspenders. */
	abort();
}
