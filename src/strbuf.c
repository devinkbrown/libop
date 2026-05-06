/*
 * libop: ophion support library.
 * strbuf.c: Dynamic string builder implementation.
 *
 * Small-string optimisation: strings up to OP_STRBUF_INLINE_CAP bytes live
 * entirely within the op_strbuf_t struct.  Strings that grow beyond that
 * limit are transparently promoted to a heap buffer.
 *
 * Growth strategy: capacity doubles each time until it covers the request.
 * The first heap allocation is at least 64 bytes regardless of the inline
 * capacity, avoiding trivially-small heap blocks after a single-byte append.
 *
 * Overflow safety: strbuf_grow aborts (consistent with op_malloc) when the
 * requested capacity would overflow size_t or the doubling loop.  Callers
 * that compute new lengths check for overflow before calling strbuf_grow.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>

/* ---- internal growth ----------------------------------------------------- */

/*
 * Ensure the buffer can hold at least need_cap bytes (excluding NUL).
 * Uses doubling growth to amortise allocation costs.
 *
 * Aborts when need_cap > SIZE_MAX/2: the doubling loop would otherwise
 * overflow size_t, and op_malloc(new_cap + 1) would wrap to a tiny
 * allocation that silently under-allocates.  Op_malloc already aborts on
 * allocation failure, so aborting here is consistent with that contract.
 */
static void
strbuf_grow(op_strbuf_t *sb, size_t need_cap)
{
	if (need_cap <= sb->cap)
		return;

	if (op_unlikely(need_cap > SIZE_MAX / 2))
		abort();   /* would overflow in the doubling loop or malloc arg */

	size_t new_cap = sb->cap > 64 ? sb->cap : 64;
	while (new_cap < need_cap)
		new_cap *= 2;   /* safe: need_cap <= SIZE_MAX/2, so new_cap <= SIZE_MAX */

	if (sb->ptr == sb->buf)
	{
		/* Promote from inline to heap. */
		char *heap = op_malloc(new_cap + 1);
		memcpy(heap, sb->buf, sb->len + 1);
		sb->ptr = heap;
	}
	else
	{
		sb->ptr = op_realloc(sb->ptr, new_cap + 1);
	}

	sb->cap = new_cap;
}

/* ---- public API ---------------------------------------------------------- */

void
op_strbuf_free(op_strbuf_t *sb)
{
	if (sb->ptr != sb->buf)
		op_free(sb->ptr);

	sb->ptr    = sb->buf;
	sb->len    = 0;
	sb->cap    = OP_STRBUF_INLINE_CAP;
	sb->buf[0] = '\0';
}

int
op_strbuf_append(op_strbuf_t *sb, const char *s, size_t len)
{
	if (op_unlikely(len == 0))
		return 0;

	/* Check for length overflow before growing. */
	if (op_unlikely(len > SIZE_MAX - sb->len))
		abort();

	strbuf_grow(sb, sb->len + len);
	memcpy(sb->ptr + sb->len, s, len);
	sb->len         += len;
	sb->ptr[sb->len] = '\0';
	return 0;
}

int
op_strbuf_appendc(op_strbuf_t *sb, char c)
{
	if (op_unlikely(sb->len >= SIZE_MAX - 1))
		abort();

	strbuf_grow(sb, sb->len + 1);
	sb->ptr[sb->len++] = c;
	sb->ptr[sb->len]   = '\0';
	return 0;
}

int
op_strbuf_vappendf(op_strbuf_t *sb, const char *fmt, va_list ap)
{
	for (;;)
	{
		size_t  avail = sb->cap - sb->len;
		va_list ap2;
		va_copy(ap2, ap);
		int n = vsnprintf(sb->ptr + sb->len, avail + 1, fmt, ap2);
		va_end(ap2);

		if (op_unlikely(n < 0))
			return -1;   /* encoding error */

		if ((size_t)n <= avail)
		{
			sb->len += (size_t)n;
			return 0;
		}

		/* Need more space — overflow-check then grow and retry. */
		if (op_unlikely((size_t)n > SIZE_MAX - sb->len))
			abort();
		strbuf_grow(sb, sb->len + (size_t)n);
	}
}

int
op_strbuf_appendf(op_strbuf_t *sb, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = op_strbuf_vappendf(sb, fmt, ap);
	va_end(ap);
	return r;
}

char *
op_strbuf_steal(op_strbuf_t *sb)
{
	char *ret;

	if (sb->ptr == sb->buf)
	{
		/* Inline — must copy to heap so caller can op_free() it.
		 * op_strbuf_t always NUL-terminates, so op_strdup is safe. */
		ret = op_strdup(sb->buf);
	}
	else
	{
		ret     = sb->ptr;
		sb->ptr = sb->buf;
		sb->cap = OP_STRBUF_INLINE_CAP;
	}

	sb->len    = 0;
	sb->buf[0] = '\0';
	return ret;
}

void
op_strbuf_truncate(op_strbuf_t *sb, size_t max_len)
{
	if (sb->len <= max_len)
		return;
	sb->len          = max_len;
	sb->ptr[max_len] = '\0';
}

/*
 * op_strbuf_ensure — guarantee at least `extra` bytes of unused capacity
 * beyond the current content length.
 *
 * Returns a pointer to the first unused byte.  The caller may write up to
 * `extra` bytes there, then call op_strbuf_advance() to record how many
 * were actually written.
 *
 * This avoids an extra copy for callers that produce output directly (e.g.
 * read(2), codec functions) without going through vsnprintf.
 */
char *
op_strbuf_ensure(op_strbuf_t *sb, size_t extra)
{
	if (op_unlikely(extra > SIZE_MAX - sb->len))
		abort();
	strbuf_grow(sb, sb->len + extra);
	return sb->ptr + sb->len;
}

/*
 * op_strbuf_advance — mark `n` bytes (written via op_strbuf_ensure) as used.
 * Appends the NUL terminator.  Behaviour is undefined if n > available slack.
 */
void
op_strbuf_advance(op_strbuf_t *sb, size_t n)
{
	sb->len         += n;
	sb->ptr[sb->len] = '\0';
}

/*
 * op_strbuf_trim_end — remove all trailing bytes that appear in `reject`.
 *
 * Example: op_strbuf_trim_end(&sb, "\r\n ") strips trailing CR, LF, and
 * spaces — a common need when consuming IRC protocol lines.
 */
void
op_strbuf_trim_end(op_strbuf_t *sb, const char *reject)
{
	while (sb->len > 0 && strchr(reject, (unsigned char)sb->ptr[sb->len - 1]))
		sb->len--;
	sb->ptr[sb->len] = '\0';
}

/*
 * op_strbuf_join — append `n` strings from `parts[]`, separated by `sep`.
 *
 * Equivalent to Python's sep.join(parts[:n]).  sep may be NULL or "" for
 * no separator.  NULL entries in parts[] are skipped silently.
 *
 * Example:
 *   const char *parts[] = { "nick", "user", "host" };
 *   op_strbuf_join(&sb, parts, 3, "!");  // → "nick!user!host"
 */
void
op_strbuf_join(op_strbuf_t *sb, const char * const *parts, size_t n,
               const char *sep)
{
	size_t sep_len = sep ? strlen(sep) : 0;
	bool first = true;

	for (size_t i = 0; i < n; i++)
	{
		if (parts[i] == NULL)
			continue;
		if (!first && sep_len > 0)
			op_strbuf_append(sb, sep, sep_len);
		op_strbuf_append_cstr(sb, parts[i]);
		first = false;
	}
}

/*
 * op_strbuf_repeat — append `s` repeated `count` times.
 *
 * Example: op_strbuf_repeat(&sb, "-", 40) appends 40 dashes.
 */
void
op_strbuf_repeat(op_strbuf_t *sb, const char *s, size_t count)
{
	if (!s || count == 0)
		return;
	size_t slen = strlen(s);
	for (size_t i = 0; i < count; i++)
		op_strbuf_append(sb, s, slen);
}
