/*
 *  libop: ophion support library.
 *  op_event.h: Event scheduler.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025-2026 ophion development team
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

#ifndef LIBOP_LIB_H
# error "Do not include op_event.h directly; include op_lib.h"
#endif

#ifndef LIBOP_EVENT_H
#define LIBOP_EVENT_H

struct ev_entry;
typedef void EVH(void *);

struct ev_entry *op_event_add(const char *name, EVH * func, void *arg, time_t when);
struct ev_entry *op_event_addonce(const char *name, EVH * func, void *arg, time_t when);
struct ev_entry *op_event_addish(const char *name, EVH * func, void *arg, time_t delta_ish);
void op_event_run(void);
void op_event_init(void);
void op_event_delete(struct ev_entry *);
void op_event_find_delete(EVH * func, void *);
void op_event_update(struct ev_entry *, time_t freq);
void op_set_back_events(time_t);
void op_dump_events(void (*func) (char *, void *), void *ptr);
void op_run_one_event(struct ev_entry *);
time_t op_event_next(void);
void op_event_purge_module(const char *mod_name);
extern const char *op_current_loading_module;

#endif /* LIBOP_EVENT_H */
