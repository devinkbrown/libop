/*
 *  libop: ophion support library.
 *  tools.c: String, path, and formatting utility functions.
 *
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

#define _GNU_SOURCE 1
#include <libop_config.h>
#include <op_lib.h>
#include <op_tools.h>

/* -------------------------------------------------------------------------
 * dlink node heap
 * ---------------------------------------------------------------------- */

static op_bh *dnode_heap;

__attribute__((cold))
void
op_init_dlink_nodes(size_t dh_size)
{
	dnode_heap = op_bh_create(sizeof(op_dlink_node), dh_size, "libop_dnode_heap");
	if (__builtin_expect(dnode_heap == NULL, 0))
		op_outofmemory();
}

__attribute__((hot))
op_dlink_node *
op_make_dlink_node(void)
{
	return op_bh_alloc(dnode_heap);
}

__attribute__((hot))
void
op_free_dlink_node(op_dlink_node *restrict ptr)
{
	slop_assert(ptr != NULL);
	op_bh_free(dnode_heap, ptr);
}

/* -------------------------------------------------------------------------
 * op_string_to_array
 *
 * Split a string into IRC-protocol parameters.  The ':' prefix convention
 * marks the final parameter (which may contain spaces).
 * ---------------------------------------------------------------------- */
__attribute__((hot))
int
op_string_to_array(char *restrict string, char **restrict parv, int maxpara)
{
	char *p, *xbuf = string;
	int x = 0;

	if (__builtin_expect(string == NULL || string[0] == '\0', 0))
		return x;

	/* Compute the string end once so SIMD scans have a safe bound. */
	const char *str_end = string + strlen(string);

	/* Skip leading spaces — SIMD-accelerated. */
	xbuf += op_simd_count_leading(xbuf, str_end, ' ');
	if (__builtin_expect(*xbuf == '\0', 0))
		return x;

	do
	{
		if (*xbuf == ':')
		{
			/* Last parameter: everything after ':' */
			xbuf++;
			parv[x++] = xbuf;
			return x;
		}
		else
		{
			parv[x++] = xbuf;
			const char *sp = op_simd_find_delim(xbuf, str_end, ' ', '\0');
			if (*sp == ' ')
			{
				p    = (char *)sp;
				*p++ = '\0';
				xbuf = p;
			}
			else
				return x;
		}

		/* Skip consecutive spaces — SIMD count_leading avoids per-byte loop. */
		xbuf += op_simd_count_leading(xbuf, str_end, ' ');
		if (*xbuf == '\0')
			return x;
	}
	while (x < maxpara - 1);

	if (*xbuf == ':')
		xbuf++;

	parv[x++] = xbuf;
	return x;
}

/* -------------------------------------------------------------------------
 * Case-insensitive string functions
 * ---------------------------------------------------------------------- */

#ifndef HAVE_STRCASECMP
# ifndef _WIN32
/* Fallback from FreeBSD. */
int
op_strcasecmp(const char *restrict s1, const char *restrict s2)
{
	const unsigned char *us1 = (const unsigned char *)s1;
	const unsigned char *us2 = (const unsigned char *)s2;

	while (tolower(*us1) == tolower(*us2++))
	{
		if (*us1++ == '\0')
			return 0;
	}
	return (tolower(*us1) - tolower(*--us2));
}
# else /* _WIN32 */
int
op_strcasecmp(const char *s1, const char *s2)
{
	return stricmp(s1, s2);
}
# endif /* _WIN32 */
#else /* HAVE_STRCASECMP */
int
op_strcasecmp(const char *restrict s1, const char *restrict s2)
{
	return strcasecmp(s1, s2);
}
#endif

#ifndef HAVE_STRNCASECMP
# ifndef _WIN32
/* Fallback from FreeBSD. */
int
op_strncasecmp(const char *restrict s1, const char *restrict s2, size_t n)
{
	if (n != 0)
	{
		const unsigned char *us1 = (const unsigned char *)s1;
		const unsigned char *us2 = (const unsigned char *)s2;

		do
		{
			if (tolower(*us1) != tolower(*us2++))
				return (tolower(*us1) - tolower(*--us2));
			if (*us1++ == '\0')
				break;
		}
		while (--n != 0);
	}
	return 0;
}
# else /* _WIN32 */
int
op_strncasecmp(const char *s1, const char *s2, size_t n)
{
	return strnicmp(s1, s2, n);
}
# endif /* _WIN32 */
#else /* HAVE_STRNCASECMP */
int
op_strncasecmp(const char *restrict s1, const char *restrict s2, size_t n)
{
	return strncasecmp(s1, s2, n);
}
#endif

#ifndef HAVE_STRCASESTR
/* Fallback from FreeBSD. */
char *
op_strcasestr(const char *restrict s, const char *restrict find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0)
	{
		c = (char)tolower((unsigned char)c);
		len = strlen(find);
		do
		{
			do
			{
				if ((sc = *s++) == 0)
					return NULL;
			}
			while ((char)tolower((unsigned char)sc) != c);
		}
		while (op_strncasecmp(s, find, len) != 0);
		s--;
	}
	return (char *)s;
}
#else
char *
op_strcasestr(const char *restrict s, const char *restrict find)
{
	return strcasestr(s, find);
}
#endif

/* -------------------------------------------------------------------------
 * Safe string copy / concatenation
 * ---------------------------------------------------------------------- */

#ifndef HAVE_STRLCAT
__attribute__((hot))
size_t
op_strlcat(char *restrict dest, const char *restrict src, size_t count)
{
	size_t dsize = strlen(dest);
	size_t len   = strlen(src);
	size_t res   = dsize + len;

	/* If the buffer is already full or would overflow, return without
	 * touching dest (avoid unsigned wraparound in count - dsize). */
	if (count == 0 || dsize >= count)
		return res;

	dest  += dsize;
	count -= dsize;
	if (__builtin_expect(len >= count, 0))
		len = count - 1;
	memcpy(dest, src, len);
	dest[len] = '\0';
	return res;
}
#else
__attribute__((hot))
size_t
op_strlcat(char *restrict dest, const char *restrict src, size_t count)
{
	return strlcat(dest, src, count);
}
#endif

#ifndef HAVE_STRLCPY
__attribute__((hot))
size_t
op_strlcpy(char *restrict dest, const char *restrict src, size_t size)
{
	size_t ret = strlen(src);

	if (__builtin_expect(size != 0, 1))
	{
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
#else
__attribute__((hot))
size_t
op_strlcpy(char *restrict dest, const char *restrict src, size_t size)
{
	return strlcpy(dest, src, size);
}
#endif

#ifndef HAVE_STRNLEN
__attribute__((hot))
size_t
op_strnlen(const char *restrict s, size_t count)
{
	const char *sc;
	for (sc = s; count-- && *sc != '\0'; ++sc)
		;
	return (size_t)(sc - s);
}
#else
__attribute__((hot))
size_t
op_strnlen(const char *restrict s, size_t count)
{
	return strnlen(s, count);
}
#endif

/* -------------------------------------------------------------------------
 * Formatted string append helpers
 * ---------------------------------------------------------------------- */

int
op_snprintf_append(char *restrict str, size_t len, const char *restrict format, ...)
{
	if (__builtin_expect(len == 0, 0))
		return -1;

	size_t orig_len = strlen(str);

	if (len <= orig_len)
	{
		str[len - 1] = '\0';
		return (int)(len - 1);
	}

	va_list ap;
	va_start(ap, format);
	int append_len = vsnprintf(str + orig_len, len - orig_len, format, ap);
	va_end(ap);

	if (append_len < 0)
		return append_len;

	size_t total = orig_len + (size_t)append_len;
	if (total > (size_t)INT_MAX)
		return -1;
	return (int)total;
}

int
op_snprintf_try_append(char *restrict str, size_t len, const char *restrict format, ...)
{
	if (__builtin_expect(len == 0, 0))
		return -1;

	size_t orig_len = strlen(str);

	if (len <= orig_len)
	{
		str[len - 1] = '\0';
		return -1;
	}

	va_list ap;
	va_start(ap, format);
	int append_len = vsnprintf(str + orig_len, len - orig_len, format, ap);
	va_end(ap);

	if (append_len < 0)
		return append_len;

	size_t total = orig_len + (size_t)append_len;
	if (total >= len)
	{
		str[orig_len] = '\0';
		return -1;
	}

	if (total > (size_t)INT_MAX)
		return -1;
	return (int)total;
}

/* -------------------------------------------------------------------------
 * Path helpers
 * ---------------------------------------------------------------------- */

char *
op_basename(const char *restrict path)
{
	const char *s = strrchr(path, '/');
	if (!s)
		s = path;
	else
		s++;
	return op_strdup(s);
}

/*
 * op_dirname — return a heap-allocated copy of the directory component of
 * path (everything up to and including the last non-slash character before
 * the final '/').  Returns "." for bare filenames with no directory separator.
 *
 * Fix: the original code had +2 in the strndup size argument, causing one
 * byte past the intended end of the dirname to be included in the copy.
 * The correct size is (s - path + 1): s points to the last non-slash
 * character of the dirname, so we need (s - path) characters before it plus
 * one for the character itself, and op_strndup adds the NUL terminator.
 */
char *
op_dirname(const char *restrict path)
{
	const char *s = strrchr(path, '/');
	if (s == NULL)
		return op_strdup(".");

	/* Step back over trailing slashes to find the last non-slash. */
	while (s > path && *s == '/')
		--s;

	/* +1: include the character s points to; op_strndup NUL-terminates. */
	return op_strndup(path, (size_t)((uintptr_t)s - (uintptr_t)path) + 1);
}

/* -------------------------------------------------------------------------
 * op_fsnprint / op_fsnprintf
 *
 * Format a linked list of op_strf_t descriptors into a single buffer.
 * ---------------------------------------------------------------------- */

__attribute__((hot))
int
op_fsnprint(char *restrict buf, size_t len, const op_strf_t *restrict strings)
{
	size_t used = 0;
	size_t remaining = len;

	while (strings != NULL)
	{
		int ret = 0;

		if (strings->length != 0)
		{
			remaining = strings->length;
			if (remaining > len - used)
				remaining = len - used;
		}

		if (__builtin_expect(remaining == 0, 0))
			break;

		if (strings->format != NULL)
		{
			if (strings->format_args != NULL)
				ret = vsnprintf(buf + used, remaining, strings->format,
				                *strings->format_args);
			else
				ret = (int)op_strlcpy(buf + used, strings->format, remaining);
		}
		else if (strings->func != NULL)
		{
			ret = strings->func(buf + used, remaining, strings->func_args);
		}

		if (ret < 0)
			return ret;

		if ((size_t)ret >= remaining)
			used += remaining - 1;
		else
			used += (size_t)ret;

		if (used >= len - 1)
		{
			used = len - 1;
			break;
		}

		remaining = len - used;
		strings = strings->next;
	}

	return (int)used;
}

int
op_fsnprintf(char *restrict buf, size_t len, const op_strf_t *restrict strings,
             const char *restrict format, ...)
{
	va_list args;
	op_strf_t prepend_string = {
		.format      = format,
		.format_args = &args,
		.next        = strings,
	};
	int ret;

	va_start(args, format);
	ret = op_fsnprint(buf, len, &prepend_string);
	va_end(args);

	return ret;
}
