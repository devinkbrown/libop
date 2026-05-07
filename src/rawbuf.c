/*
 *  Ophion IRC Daemon
 *  libop/src/rawbuf.c: Raw buffer — non-line-oriented scatter/gather I/O.
 *
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2007 ircd-ratbox development team
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

/*
 * Buffer layout
 * -------------
 * A rawbuf_head_t is a linked list of fixed-size rawbuf_t chunks.  All data
 * is appended at the tail; consumption (flush to fd, or get to memory) always
 * proceeds from the head.
 *
 * rb->written tracks the byte offset into the HEAD chunk at which the next
 * flush/get operation begins.  It is always 0 for every chunk except the
 * head.  buf->flushing is a convenience flag meaning "rb->written is non-zero
 * for this chunk" — it is set when the head chunk has been partially consumed
 * and cleared when that chunk is freed.
 *
 * IMPORTANT: do not mix flush and get operations on the same rawbuf_head_t.
 * op_rawbuf_flush* and op_rawbuf_get both advance rb->written; using both
 * paths on the same head will produce incorrect offsets.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <commio-ssl.h>
#include <stdbool.h>
#ifdef HAVE_SENDMSG
# include <sys/socket.h>
#endif
#ifdef HAVE_WRITEV
# include <sys/uio.h>
#endif

/* 4 KiB per chunk — matches a typical page and maximises iov reuse. */
#define RAWBUF_SIZE 4096

struct _rawbuf
{
	op_dlink_node node;
	uint8_t       data[RAWBUF_SIZE];
	size_t        len;      /* bytes appended into data[]      */
	bool          flushing; /* rb->written is our start offset */
};

struct _rawbuf_head
{
	op_dlink_list list;
	size_t        len;     /* total bytes across all chunks */
	size_t        written; /* offset into head chunk        */
};

static op_bh *rawbuf_heap;

/* -------------------------------------------------------------------------
 * Internal allocation helpers
 * ---------------------------------------------------------------------- */

static rawbuf_t *
rawbuf_alloc(void)
{
	return op_bh_alloc(rawbuf_heap);
}

static rawbuf_t *
rawbuf_newchunk(rawbuf_head_t *rb)
{
	rawbuf_t *buf = rawbuf_alloc();
	op_dlinkAddTail(buf, &buf->node, &rb->list);
	return buf;
}

static void
rawbuf_free_head(rawbuf_head_t *rb, rawbuf_t *buf)
{
	op_dlinkDelete(&buf->node, &rb->list);
	op_bh_free(rawbuf_heap, buf);
}

/* -------------------------------------------------------------------------
 * op_rawbuf_flush_writev — scatter-gather write to fd (non-SSL).
 *
 * Builds an iovec array from the pending chunks and calls sendmsg()/writev()
 * directly on the raw fd, bypassing all op_ wrappers.  Using op_writev()
 * here would cause infinite recursion for WebSocket fds:
 *   op_rawbuf_flush → op_rawbuf_flush_writev → op_writev → op_fake_writev
 *   → op_write → op_ws_write → op_rawbuf_flush → …
 *
 * After a partial write, rb->written is advanced within the head chunk (not
 * reset to 0 + modifying buf->len).  Fully-written chunks are freed.
 * ---------------------------------------------------------------------- */
static int
op_rawbuf_flush_writev(rawbuf_head_t *rb, op_fde_t *F)
{
	op_dlink_node *ptr, *next;
	rawbuf_t *buf;
	int nvec = 0;
	int retval;
	size_t sxret;
	struct op_iovec vec[OP_UIO_MAXIOV];

	if (rb->list.head == NULL)
	{
		errno = EAGAIN;
		return -1;
	}

	OP_DLINK_FOREACH(ptr, rb->list.head)
	{
		if (nvec >= OP_UIO_MAXIOV)
			break;

		buf = ptr->data;
		if (buf->flushing)
		{
			/* Head chunk: start from current offset. */
			vec[nvec].iov_base = buf->data + rb->written;
			vec[nvec++].iov_len = buf->len - rb->written;
		}
		else
		{
			vec[nvec].iov_base = buf->data;
			vec[nvec++].iov_len = buf->len;
		}
	}

	if (nvec == 0)
	{
		errno = EAGAIN;
		return -1;
	}

	/*
	 * Write directly to the underlying socket fd, bypassing all op_ wrappers.
	 * op_writev() routes WebSocket fds through op_fake_writev → op_write →
	 * op_ws_write → op_rawbuf_flush → here: infinite recursion.  The frame
	 * bytes in `vec` are already encoded (WebSocket or plain); we just need
	 * them on the wire.
	 */
#ifdef HAVE_SENDMSG
	{
		struct msghdr _msg;
		memset(&_msg, 0, sizeof _msg);
		_msg.msg_iov    = (struct iovec *)vec;
		_msg.msg_iovlen = (size_t)nvec;
		retval = (int)sendmsg(op_get_fd(F), &_msg, MSG_NOSIGNAL);
	}
#elif defined(HAVE_WRITEV)
	retval = (int)writev(op_get_fd(F), (struct iovec *)vec, nvec);
#else
	/* Last resort: single send from head iovec only. */
	retval = (int)send(op_get_fd(F), vec[0].iov_base, vec[0].iov_len, MSG_NOSIGNAL);
#endif
	if (retval <= 0)
		return retval;
	sxret = (size_t)retval;

	OP_DLINK_FOREACH_SAFE(ptr, next, rb->list.head)
	{
		buf = ptr->data;
		if (buf->flushing)
		{
			/* Head chunk: sxret is counted from rb->written. */
			size_t remaining = buf->len - rb->written;
			if (sxret >= remaining)
			{
				sxret -= remaining;
				rb->len -= remaining;
				rawbuf_free_head(rb, buf);
				rb->written = 0; /* next chunk starts fresh */
				continue;
			}
			/* Partial write within this chunk. */
			rb->written += sxret;
			rb->len     -= sxret;
			break;
		}

		/* Non-head chunks always start at offset 0. */
		if (sxret >= buf->len)
		{
			sxret   -= buf->len;
			rb->len -= buf->len;
			rawbuf_free_head(rb, buf);
		}
		else
		{
			/* Start partial-write tracking for this chunk. */
			buf->flushing = true;
			rb->written   = sxret;
			rb->len      -= sxret;
			break;
		}
	}

	return retval;
}

/* -------------------------------------------------------------------------
 * op_rawbuf_flush — write buffered data to fd.
 *
 * For SSL fds we can only write one contiguous region at a time, so we
 * bypass writev and use op_write directly on the head chunk.
 * ---------------------------------------------------------------------- */
int
op_rawbuf_flush(rawbuf_head_t *rb, op_fde_t *F)
{
	rawbuf_t *buf;
	int retval;

	if (rb->list.head == NULL)
	{
		errno = EAGAIN;
		return -1;
	}

	if (!op_fd_ssl(F))
		return op_rawbuf_flush_writev(rb, F);

	buf = rb->list.head->data;
	if (!buf->flushing)
	{
		buf->flushing = true;
		rb->written   = 0;
	}

	/* Write directly through the SSL layer, bypassing any higher-level
	 * protocol wrapping (e.g. WebSocket).  op_write() would re-enter
	 * op_ws_write() for WebSocket fds, causing infinite recursion. */
	retval = op_ssl_write(F, buf->data + rb->written, buf->len - rb->written);
	if (retval <= 0)
		return retval;

	rb->written += (size_t)retval;
	rb->len     -= (size_t)retval;

	if (rb->written == buf->len)
	{
		rb->written = 0;
		rawbuf_free_head(rb, buf);
	}
	return retval;
}

/* -------------------------------------------------------------------------
 * op_rawbuf_append — append arbitrary data into the buffer.
 *
 * Fills any spare space in the tail chunk first, then allocates new chunks
 * as needed.  Never fails (calls op_outofmemory on allocation failure).
 * ---------------------------------------------------------------------- */
void
op_rawbuf_append(rawbuf_head_t *rb, const void *data, size_t len)
{
	rawbuf_t *tail = NULL;

	if (rb->list.tail != NULL)
		tail = rb->list.tail->data;

	/* Fill remaining space in the current tail chunk, unless it is
	 * already mid-flush (its data is being consumed from the front). */
	if (tail != NULL && tail->len < RAWBUF_SIZE && !tail->flushing)
	{
		size_t space = RAWBUF_SIZE - tail->len;
		size_t copy  = (len < space) ? len : space;
		memcpy(tail->data + tail->len, data, copy);
		tail->len += copy;
		rb->len   += copy;
		len       -= copy;
		data       = (const char *)data + copy;
	}

	while (len > 0)
	{
		size_t copy = (len >= RAWBUF_SIZE) ? RAWBUF_SIZE : len;
		rawbuf_t *buf = rawbuf_newchunk(rb);
		memcpy(buf->data, data, copy);
		buf->len += copy;
		rb->len  += copy;
		len      -= copy;
		data      = (const char *)data + copy;
	}
}

/* -------------------------------------------------------------------------
 * op_rawbuf_get — copy up to len bytes from the head of the buffer.
 *
 * Returns the number of bytes copied (may be less than len if fewer bytes
 * are available in the head chunk).  Returns 0 if the buffer is empty.
 *
 * Do not mix op_rawbuf_get with op_rawbuf_flush on the same rawbuf_head_t;
 * both advance rb->written and will corrupt each other's state.
 * ---------------------------------------------------------------------- */
ssize_t
op_rawbuf_get(rawbuf_head_t *rb, void *data, size_t len)
{
	rawbuf_t *buf;
	size_t    available, cpylen;
	const uint8_t *src;

	if (rb->list.head == NULL)
		return 0;

	buf = rb->list.head->data;

	/* Bytes available in the head chunk from the current read position. */
	available = buf->flushing ? (buf->len - rb->written) : buf->len;
	cpylen    = (len > available) ? available : len;
	src       = buf->flushing ? (buf->data + rb->written) : buf->data;

	memcpy(data, src, cpylen);

	if (cpylen == available)
	{
		/* Consumed all remaining data in the head chunk — free it. */
		rb->written = 0;
		rawbuf_free_head(rb, buf);
		rb->len -= cpylen;
	}
	else
	{
		/* Partial read: advance the offset within the head chunk. */
		buf->flushing = true;
		rb->written  += cpylen;
		rb->len      -= cpylen;
	}

	return (ssize_t)cpylen;
}

/* -------------------------------------------------------------------------
 * op_rawbuf_length — total bytes pending in the buffer.
 * ---------------------------------------------------------------------- */
size_t
op_rawbuf_length(rawbuf_head_t *rb)
{
	/* Consistency check: an empty list must have len == 0.
	 * lop_assert returns true when the assertion FAILS, so this branch
	 * self-heals a corrupted length counter.  */
	if (op_dlink_list_length(&rb->list) == 0 && lop_assert(rb->len == 0))
		rb->len = 0;
	return rb->len;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

rawbuf_head_t *
op_new_rawbuffer(void)
{
	return op_malloc(sizeof(rawbuf_head_t));
}

void
op_free_rawbuffer(rawbuf_head_t *rb)
{
	op_dlink_node *ptr, *next;
	OP_DLINK_FOREACH_SAFE(ptr, next, rb->list.head)
	{
		rawbuf_free_head(rb, ptr->data);
	}
	op_free(rb);
}

void
op_init_rawbuffers(size_t heap_size)
{
	if (rawbuf_heap == NULL)
		rawbuf_heap = op_bh_create(sizeof(rawbuf_t), heap_size,
		                           "libop_rawbuf_heap");
}
