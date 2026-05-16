/*
 *  libop: ophion support library.
 *  op_rawbuf.h: Raw buffer management.
 *
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2007 ircd-ratbox development team
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
# error "Do not include op_rawbuf.h directly; include op_lib.h"
#endif

#ifndef LIBOP_RAWBUF_H
#define LIBOP_RAWBUF_H

typedef struct _rawbuf rawbuf_t;
typedef struct _rawbuf_head rawbuf_head_t;

void op_init_rawbuffers(size_t heapsize);
void op_free_rawbuffer(rawbuf_head_t *);
rawbuf_head_t *op_new_rawbuffer(void);
ssize_t op_rawbuf_get(rawbuf_head_t *, void *data, size_t len);
void op_rawbuf_append(rawbuf_head_t *, const void *data, size_t len);
int op_rawbuf_flush(rawbuf_head_t *, op_fde_t *F);
size_t op_rawbuf_length(rawbuf_head_t *rb);

#endif /* LIBOP_RAWBUF_H */
