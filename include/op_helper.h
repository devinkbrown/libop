/*
 *  libop: ophion support library
 *  op_helper.h: Helper process management.
 *
 *  Copyright (C) 2006 Aaron Sethman <androsyn@ratbox.org>
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
# error "Do not include op_helper.h directly; include op_lib.h"
#endif

#ifndef LIBOP_HELPER_H
#define LIBOP_HELPER_H

struct _op_helper;
typedef struct _op_helper op_helper;

typedef void op_helper_cb(op_helper *);



op_helper *op_helper_start(const char *name, const char *fullpath, op_helper_cb * read_cb,
			   op_helper_cb * error_cb);

/* Start an in-process helper: creates a socketpair and spawns a pthread.
 * thread_fn(int *fd) receives ownership of a heap-allocated int containing
 * the thread-side fd.  The returned op_helper is backed by the other end. */
op_helper *op_helper_start_thread(const char *name,
				  void *(*thread_fn)(void *),
				  op_helper_cb *read_cb,
				  op_helper_cb *error_cb);

op_helper *op_helper_child(op_helper_cb * read_cb, op_helper_cb * error_cb,
			   log_cb * ilog, restart_cb * irestart, die_cb * idie,
			   size_t lb_heap_size, size_t dh_size, size_t fd_heap_size);

void op_helper_restart(op_helper *helper);
#ifdef __GNUC__
void op_helper_write(op_helper *helper, const char *format, ...)
     __attribute((format(printf, 2, 3)));
void op_helper_write_queue(op_helper *helper, const char *format, ...)
     __attribute((format(printf, 2, 3)));
#else
void op_helper_write(op_helper *helper, const char *format, ...);
void op_helper_write_queue(op_helper *helper, const char *format, ...);
#endif
void op_helper_write_flush(op_helper *helper);

void op_helper_run(op_helper *helper);
void op_helper_close(op_helper *helper);
int op_helper_read(op_helper *helper, void *buf, size_t bufsize);
OP_NORETURN void op_helper_loop(op_helper *helper, long delay);
#endif
