/*
 *  libop: ophion support library.
 *  linebuf.c: IRC line buffer — CRLF-framed message assembly and fan-out.
 *
 *  Each buf_head_t is a doubly-linked list of buf_line_t slabs, ordered
 *  from oldest (head) to newest (tail).  A line is "terminated" when its
 *  CRLF boundary has been seen; unterminated lines grow as more data
 *  arrives from the network.
 *
 *  Reference counting (buf_line_t.refcount):
 *    - buf_head_t ownership:  1 reference (released by op_linebuf_done_line)
 *    - sendbuf zero-copy ref: 1 per fan-out recipient (op_linebuf_ref /
 *      op_linebuf_unref)
 *  A line is freed to the slab pool when refcount drops to zero.
 *
 *  Thread safety: the I/O thread (sendbuf flush) and worker threads
 *  (fan-out) may call op_linebuf_ref / op_linebuf_unref concurrently.
 *  All refcount operations use C11 atomics.  bufline_count is a diagnostic
 *  counter; relaxed ordering suffices (we only need atomicity, not fencing).
 *
 *  Copyright (C) 2001-2002 Adrian Chadd <adrian@creative.net.au>
 *  Copyright (C) 2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2026 ophion development team
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

#include <op_atomic.h>
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>

static op_bh *op_linebuf_heap;

/* Diagnostic counter — total live buf_line_t objects across all buf_head_t
 * and sendbuf references.  Relaxed ordering: we only need atomicity for the
 * counter itself; no happens-before relationship is required here. */
static atomic_int bufline_count = 0;

/* ---- slab allocation ----------------------------------------------------- */

__attribute__((cold))
void
op_linebuf_init(size_t heap_size)
{
	op_linebuf_heap = op_bh_create(sizeof(buf_line_t), heap_size,
	                               "libop_linebuf_heap");
}

static __attribute__((hot)) buf_line_t *
op_linebuf_allocate(void)
{
	return op_bh_alloc(op_linebuf_heap);
}

static __attribute__((hot)) void
op_linebuf_free(buf_line_t *restrict p)
{
	op_bh_free(op_linebuf_heap, p);
}

/* ---- buf_line_t lifecycle ------------------------------------------------- */

/*
 * op_linebuf_new_line — allocate a buf_line_t, link it at the tail of
 * bufhead, and return it with refcount = 1.
 */
static __attribute__((hot)) buf_line_t *
op_linebuf_new_line(buf_head_t *restrict bufhead)
{
	buf_line_t *bufline = op_linebuf_allocate();
	atomic_fetch_add_explicit(&bufline_count, 1, memory_order_relaxed);

	op_dlinkAddTailAlloc(bufline, &bufhead->list);
	bufline->refcount = 1;   /* sole owner: the buf_head_t */

	bufhead->alloclen++;
	bufhead->numlines++;

	return bufline;
}

/*
 * op_linebuf_done_line — unlink a buf_line_t from bufhead and drop the
 * buf_head_t's reference.  If the refcount reaches zero (no sendbuf
 * references outstanding), the line is freed to the slab pool.
 */
static __attribute__((hot)) void
op_linebuf_done_line(buf_head_t *restrict bufhead, buf_line_t *restrict bufline,
                     op_dlink_node *restrict node)
{
	op_dlinkDestroy(node, &bufhead->list);

	bufhead->alloclen--;
	bufhead->len     -= bufline->len;
	bufhead->numlines--;

	/* acq_rel: release our writes before a potential concurrent free;
	 * acquire visibility of all writes done by other threads before they
	 * dropped their reference (so the free sees a consistent object). */
	if (atomic_fetch_sub_explicit(&bufline->refcount, 1, memory_order_acq_rel) == 1)
	{
		atomic_fetch_sub_explicit(&bufline_count, 1, memory_order_relaxed);
		slop_assert(atomic_load_explicit(&bufline_count, memory_order_relaxed) >= 0);
		op_linebuf_free(bufline);
	}
}

/* ---- CRLF scanner --------------------------------------------------------- */

/*
 * linebuf_skip_crlf — return the number of bytes in [ch, ch+len) that form
 * one logical line (content + trailing CRLF).
 *
 * The scan has two phases:
 *   1. Skip non-CRLF content bytes until the first CR or LF.
 *   2. Skip the CR/LF run that terminates the line.
 *
 * The return value is the total bytes consumed (>= 1 when len > 0).
 * Called only with len > 0; callers enforce this invariant.
 */
static __attribute__((hot)) size_t
linebuf_skip_crlf(const char *restrict ch, size_t len)
{
	size_t orig = len;

	/* Phase 1: advance past content characters. */
	while (len && (*ch != '\r') & (*ch != '\n'))
	{
		ch++;
		len--;
	}

	/* Phase 2: swallow the CRLF terminator (may be more than two bytes on
	 * a malformed client that sends "\r\r\n" etc.). */
	while (len && ((*ch == '\r') | (*ch == '\n')))
	{
		ch++;
		len--;
	}

	return orig - len;
}

/* ---- line copy ------------------------------------------------------------ */

/*
 * linebuf_copy — copy one logical line from data[0..len) into bufline.
 *
 * raw == 0 (LINEBUF_PARSED): strip trailing CRLF before storing.
 * raw == 1 (LINEBUF_RAW):    preserve CRLF in the stored bytes.
 *
 * Returns the number of bytes consumed from data[] (always >= 1 when called
 * with len > 0 and bufline is not already terminated).  Returns 0 immediately
 * when bufline->terminated is set (line is full; caller must allocate a new
 * one).
 *
 * On overflow (more input than remaining capacity): truncates to capacity,
 * forces termination, and still returns the full consumed count so the caller
 * advances the input pointer past the whole logical line.
 */
static __attribute__((hot)) size_t
linebuf_copy(buf_head_t *restrict bufhead, buf_line_t *restrict bufline,
             const char *restrict data, size_t len, int raw)
{
	slop_assert(bufline->len <= LINEBUF_SIZE);

	if (__builtin_expect(bufline->terminated, 0))
		return 0;

	bufline->raw = (uint8_t)raw;

	size_t consumed = linebuf_skip_crlf(data, len);
	size_t cpylen   = consumed;
	size_t avail    = LINEBUF_SIZE - bufline->len;
	char  *dst      = bufline->buf + bufline->len;

	if (__builtin_expect(cpylen > avail, 0))
	{
		/* Overflow: truncate to avail bytes, force termination. */
		memcpy(dst, data, avail);
		bufline->buf[LINEBUF_SIZE] = '\0';

		if (!raw)
		{
			/* Strip any trailing CRLF from the truncated content. */
			char *p = bufline->buf + LINEBUF_SIZE - 1;
			size_t cl = avail;
			while (cl && (*p == '\r' || *p == '\n'))
			{
				*p-- = '\0';
				cl--;
			}
		}

		bufline->terminated = 1;
		/* Only add the delta — partial bytes were already counted. */
		bufhead->len       += LINEBUF_SIZE - bufline->len;
		bufline->len        = LINEBUF_SIZE;
		return consumed;
	}

	memcpy(dst, data, cpylen);
	dst[cpylen] = '\0';

	if (cpylen == 0 || (dst[cpylen - 1] != '\r' && dst[cpylen - 1] != '\n'))
	{
		/* No line terminator in this chunk — unterminated partial line. */
		bufline->len  += cpylen;
		bufhead->len  += cpylen;
		bufline->terminated = 0;
		return consumed;
	}

	if (!raw)
	{
		/* Strip trailing CRLF bytes (may be more than two on bad clients). */
		char *end = dst + cpylen - 1;
		while (cpylen && (*end == '\r' || *end == '\n'))
		{
			*end-- = '\0';
			cpylen--;
		}
	}

	bufline->terminated = 1;
	bufline->len       += cpylen;
	bufhead->len       += cpylen;
	return consumed;
}

/* ---- public API ---------------------------------------------------------- */

__attribute__((cold))
void
op_linebuf_newbuf(buf_head_t *restrict bufhead)
{
	memset(bufhead, 0, sizeof(buf_head_t));
}

__attribute__((hot))
void
op_linebuf_donebuf(buf_head_t *restrict bufhead)
{
	while (__builtin_expect(bufhead->list.head != NULL, 1))
	{
		op_linebuf_done_line(bufhead,
		                     (buf_line_t *)bufhead->list.head->data,
		                     bufhead->list.head);
	}
}

/*
 * op_linebuf_parse — break data[0..len) into buf_line_t objects, splitting
 * at CRLF boundaries.  If raw is zero, CRLF is stripped from each stored
 * line; if raw is non-zero, CRLF is preserved.
 *
 * Appends to any existing partial line at bufhead->tail before allocating
 * fresh lines.  Returns the number of lines written (>= 0), or -1 on error.
 *
 * len must be > 0; passing 0 or a negative value is a caller bug.
 */
__attribute__((hot))
int
op_linebuf_parse(buf_head_t *restrict bufhead, char *restrict data, ssize_t slen, int raw)
{
	if (__builtin_expect(slen <= 0, 0))
		return 0;

	size_t len = (size_t)slen;
	int    linecnt = 0;

	/* If there is an existing partial line at the tail, try to fill it
	 * before allocating a new one. */
	if (bufhead->list.tail != NULL)
	{
		buf_line_t *bufline = bufhead->list.tail->data;
		size_t cpylen = linebuf_copy(bufhead, bufline, data, len, raw);

		if (cpylen > 0)
		{
			linecnt++;
			if (cpylen >= len)
				return linecnt;
			len  -= cpylen;
			data += cpylen;
		}
		/* cpylen == 0: tail was already terminated; fall through to allocate. */
	}

	while (len > 0)
	{
		buf_line_t *bufline = op_linebuf_new_line(bufhead);
		size_t cpylen = linebuf_copy(bufhead, bufline, data, len, raw);

		len  -= cpylen;
		data += cpylen;
		linecnt++;
	}

	return linecnt;
}

/*
 * op_linebuf_get — copy the first complete (terminated) line into buf[0..buflen).
 * Returns the number of bytes copied (>= 1), or 0 if no complete line is
 * available.
 *
 * When partial is non-zero, also returns unterminated partial lines.
 * When raw is zero, leading/trailing CRLF is stripped from raw-mode lines.
 * When raw is non-zero, the bytes are returned as-is.
 */
__attribute__((hot))
int
op_linebuf_get(buf_head_t *restrict bufhead, char *restrict buf, size_t buflen,
               int partial, int raw)
{
	for (;;)
	{
		if (__builtin_expect(bufhead->list.head == NULL, 0))
			return 0;

		buf_line_t *bufline = bufhead->list.head->data;

		if (!(partial || bufline->terminated))
			return 0;

		if (buflen == 0)
			return 0;

		size_t cpylen = bufline->len < buflen - 1 ? bufline->len : buflen - 1;
		const char *start = bufline->buf;

		/* When caller wants parsed output but the line was stored raw,
		 * strip leading and trailing CRLF on the fly. */
		if (bufline->raw && !raw)
		{
			while (cpylen && (*start == '\r' || *start == '\n'))
			{
				start++;
				cpylen--;
			}
			const char *end = start + cpylen - 1;
			while (cpylen && (*end == '\r' || *end == '\n'))
			{
				end--;
				cpylen--;
			}
		}

		/* Bare CRLF lines produce cpylen == 0; silently discard. */
		if (__builtin_expect(cpylen == 0, 0))
		{
			op_linebuf_done_line(bufhead, bufline, bufhead->list.head);
			continue;
		}

		memcpy(buf, start, cpylen);
		if (!raw)
			buf[cpylen] = '\0';

		op_linebuf_done_line(bufhead, bufline, bufhead->list.head);
		return (int)cpylen;
	}
}

/*
 * op_linebuf_attach — reference-copy all lines from new into bufhead.
 * No data is duplicated; each line's refcount is incremented so both
 * buf_head_t objects share ownership.
 */
__attribute__((hot))
void
op_linebuf_attach(buf_head_t *restrict bufhead, buf_head_t *restrict new)
{
	op_dlink_node *ptr;
	OP_DLINK_FOREACH(ptr, new->list.head)
	{
		buf_line_t *line = ptr->data;
		op_dlinkAddTailAlloc(line, &bufhead->list);

		bufhead->alloclen++;
		bufhead->len += line->len;
		bufhead->numlines++;

		/* Relaxed: no ordering required for a reference-count bump that
		 * merely prevents premature free. */
		atomic_fetch_add_explicit(&line->refcount, 1, memory_order_relaxed);
	}
}

/*
 * op_linebuf_put — format strings via op_strf_t and append them as a new
 * terminated line (with CRLF).  The previous tail line must already be
 * terminated; this is asserted in debug builds.
 */
__attribute__((hot))
void
op_linebuf_put(buf_head_t *restrict bufhead, const op_strf_t *restrict strings)
{
	if (bufhead->list.tail)
	{
		buf_line_t *prev = bufhead->list.tail->data;
		slop_assert(prev->terminated);
	}

	buf_line_t *bufline = op_linebuf_new_line(bufhead);

	int ret = op_fsnprint(bufline->buf, LINEBUF_SIZE + 1, strings);
	size_t len = (ret > 0) ? (size_t)ret : 0;

	if (len > LINEBUF_SIZE)
		len = LINEBUF_SIZE;

	/* Append CRLF — buf is LINEBUF_SIZE + CRLF_LEN + 1 bytes. */
	bufline->buf[len++] = '\r';
	bufline->buf[len++] = '\n';
	bufline->buf[len]   = '\0';

	bufline->terminated = 1;
	bufline->len        = len;
	bufhead->len       += len;
}

/*
 * op_linebuf_unref — drop one reference held by a sendbuf.
 * Frees the line when no other references remain.
 */
__attribute__((hot))
void
op_linebuf_unref(buf_line_t *restrict line)
{
	if (atomic_fetch_sub_explicit(&line->refcount, 1, memory_order_acq_rel) == 1)
	{
		atomic_fetch_sub_explicit(&bufline_count, 1, memory_order_relaxed);
		slop_assert(atomic_load_explicit(&bufline_count, memory_order_relaxed) >= 0);
		op_linebuf_free(line);
	}
}

/*
 * op_linebuf_peek — return a read-only pointer to the first complete line
 * without consuming it.  Returns NULL if no terminated line is available.
 * The pointer is valid until the next op_linebuf_consume() call.
 */
__attribute__((hot))
const buf_line_t *
op_linebuf_peek(buf_head_t *restrict bufhead)
{
	if (__builtin_expect(bufhead->list.head == NULL, 0))
		return NULL;

	const buf_line_t *line = bufhead->list.head->data;
	return line->terminated ? line : NULL;
}

/*
 * op_linebuf_consume — remove and release the first line.  Pair with peek.
 */
__attribute__((hot))
void
op_linebuf_consume(buf_head_t *restrict bufhead)
{
	if (__builtin_expect(bufhead->list.head == NULL, 0))
		return;

	op_linebuf_done_line(bufhead,
	                     (buf_line_t *)bufhead->list.head->data,
	                     bufhead->list.head);
}

/*
 * op_linebuf_flush — write buffered lines to socket F, consuming each line
 * as it is fully sent.  Uses writev(2) scatter-gather when available to
 * batch multiple lines into one syscall, minimising context switches.
 *
 * Returns bytes written (> 0), 0 blocked (EWOULDBLOCK), or -1 on error.
 */
__attribute__((hot))
int
op_linebuf_flush(op_fde_t *restrict F, buf_head_t *restrict bufhead)
{
	buf_line_t *bufline;
	int retval;

#ifdef HAVE_WRITEV
	if (!op_fd_ssl(F))
	{
		op_dlink_node *ptr;
		int x = 0, y;
		size_t sxret;
		struct op_iovec vec[OP_UIO_MAXIOV];

		memset(vec, 0, sizeof(vec));

		if (__builtin_expect(bufhead->list.head == NULL, 0))
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		ptr     = bufhead->list.head;
		bufline = ptr->data;

		if (!bufline->terminated)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		vec[x].iov_base = bufline->buf + bufhead->writeofs;
		vec[x].iov_len  = bufline->len - bufhead->writeofs;
		x++;
		ptr = ptr->next;

		/* Batch up to OP_UIO_MAXIOV contiguous terminated lines. */
		while (x < OP_UIO_MAXIOV && ptr != NULL)
		{
			bufline = ptr->data;
			if (!bufline->terminated)
				break;
			vec[x].iov_base = bufline->buf;
			vec[x].iov_len  = bufline->len;
			ptr = ptr->next;
			x++;
		}

		if (__builtin_expect(x == 0, 0))
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		retval = op_writev(F, vec, x);
		if (retval <= 0)
			return retval;
		sxret = (size_t)retval;

		ptr = bufhead->list.head;
		for (y = 0; y < x; y++)
		{
			bufline = ptr->data;
			size_t remaining = bufline->len - bufhead->writeofs;

			if (sxret >= remaining)
			{
				sxret -= remaining;
				ptr    = ptr->next;
				op_linebuf_done_line(bufhead, bufline, bufhead->list.head);
				bufhead->writeofs = 0;
			}
			else
			{
				bufhead->writeofs += sxret;
				break;
			}
		}

		return retval;
	}
#endif /* HAVE_WRITEV */

	/* Non-writev / SSL path: write one line at a time. */
	if (__builtin_expect(bufhead->list.head == NULL, 0))
	{
		errno = EWOULDBLOCK;
		return -1;
	}

	bufline = bufhead->list.head->data;
	if (!bufline->terminated)
	{
		errno = EWOULDBLOCK;
		return -1;
	}

	retval = op_write(F, bufline->buf + bufhead->writeofs,
	                  bufline->len   - bufhead->writeofs);
	if (retval <= 0)
		return retval;

	bufhead->writeofs += (size_t)retval;
	if (bufhead->writeofs == bufline->len)
	{
		bufhead->writeofs = 0;
		op_linebuf_done_line(bufhead, bufline, bufhead->list.head);
	}

	return retval;
}

__attribute__((cold))
void
op_count_op_linebuf_memory(size_t *count, size_t *op_linebuf_memory_used)
{
	op_bh_usage(op_linebuf_heap, count, NULL, op_linebuf_memory_used, NULL);
}
