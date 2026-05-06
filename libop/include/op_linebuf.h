/*
 *  libop: ophion support library.
 *  op_linebuf.h: Line buffer management.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025 ophion development team
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
# error "Do not include op_linebuf.h directly; include op_lib.h"
#endif

#ifndef LIBOP_LINEBUF_H
#define LIBOP_LINEBUF_H

#include <op_atomic.h>

#define LINEBUF_COMPLETE        0
#define LINEBUF_PARTIAL         1
#define LINEBUF_PARSED          0
#define LINEBUF_RAW             1

struct _buf_line;
struct _buf_head;

/* IRCv3 tags (4096 bytes, spec max 4095) + RFC1459 message (510 bytes) */
#define LINEBUF_TAGSLEN         4096    /* IRCv3 message tags */
#define LINEBUF_DATALEN         510     /* RFC1459 message data */
#define LINEBUF_SIZE            (LINEBUF_TAGSLEN + LINEBUF_DATALEN)
#define CRLF_LEN                2

typedef struct _buf_line
{
	char buf[LINEBUF_SIZE + CRLF_LEN + 1];
	uint8_t terminated;	/* Whether we've terminated the buffer */
	uint8_t raw;		/* Whether this linebuf may hold 8-bit data */
	size_t len;		/* How much data we've got */
	/* Reference count: 1 for buf_head_t ownership + 1 per sendbuf that
	 * holds a zero-copy reference.  Must be atomic because the I/O thread
	 * (sendbuf flush → op_linebuf_unref) and worker threads (fan-out →
	 * op_linebuf_ref) can race on the same buf_line_t. */
	atomic_uint refcount;
} buf_line_t;

typedef struct _buf_head
{
	op_dlink_list list;	/* the actual dlink list */
	size_t len;		/* length of all the data */
	size_t alloclen;	/* Actual allocated data length */
	size_t writeofs;	/* offset in the first line for the write */
	unsigned int numlines;	/* number of lines */
} buf_head_t;

/* they should be functions, but .. */
#define op_linebuf_len(x)		((x)->len)
#define op_linebuf_alloclen(x)	((x)->alloclen)
#define op_linebuf_numlines(x)	((x)->numlines)

void op_linebuf_init(size_t heap_size);
void op_linebuf_newbuf(buf_head_t *);
void op_linebuf_donebuf(buf_head_t *);
int op_linebuf_parse(buf_head_t *, char *, ssize_t, int);
int op_linebuf_get(buf_head_t *, char *, size_t, int, int);

/* Zero-copy RX: return a direct pointer into the first complete line without
 * copying.  The returned pointer is valid until op_linebuf_consume() is
 * called.  Returns NULL if no complete line is available. */
const buf_line_t *op_linebuf_peek(buf_head_t *bufhead);

/* Consume (remove) the first line from bufhead.  Pair with op_linebuf_peek. */
void op_linebuf_consume(buf_head_t *bufhead);

void op_linebuf_put(buf_head_t *, const op_strf_t *);
void op_linebuf_attach(buf_head_t *, buf_head_t *);
void op_count_op_linebuf_memory(size_t *, size_t *);
int op_linebuf_flush(op_fde_t *F, buf_head_t *);

/* Reference-counting helpers for buf_line_t (used by op_sendbuf for
 * zero-copy TX: sendbuf holds a ref so the line outlives its buf_head_t). */
static inline void
op_linebuf_ref(buf_line_t *line)
{
	/* Relaxed: we only need atomicity, not ordering.  The happens-before
	 * chain that prevents use-after-free is established by the
	 * acq_rel fetch_sub in op_linebuf_unref / op_linebuf_done_line. */
	atomic_fetch_add_explicit(&line->refcount, 1, memory_order_relaxed);
}

/* Drop one reference; the line is freed when refcount reaches zero. */
void op_linebuf_unref(buf_line_t *line);


#endif /* LIBOP_LINEBUF_H */
