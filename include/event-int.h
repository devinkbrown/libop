/*
 *  libop: ophion support library.
 *  event-int.h: internal structs for events
 *
 *  Copyright (C) 2007 ircd-ratbox development team
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
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
 *
 */

struct ev_entry
{
	EVH    *func;
	void   *arg;
	char   *name;
	time_t  frequency;
	time_t  when;       /* absolute time of next firing                 */
	time_t  next;       /* raw (possibly jittered) delta, for reschedule */
	void   *data;
	void   *comm_ptr;
	int     dead;
	size_t  hidx;       /* index into the min-heap array (for O(log n) delete) */
	char   *mod_name;   /* owning module name (NULL = core) for safe unload    */
};
void op_event_io_register_all(void);
