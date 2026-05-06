/*
 *  libop: ophion support library.
 *  op_memory.h: Memory allocation wrappers (always-succeeds: OOM calls op_outofmemory()).
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
#error "Do not include op_memory.h directly; include op_lib.h"
#endif

#ifndef LIBOP_MEMORY_H
#define LIBOP_MEMORY_H



void op_outofmemory(void) __attribute__((noreturn));

static inline void *
op_calloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

static inline void *
op_malloc(size_t size)
{
	void *ret = calloc(1, size);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

static inline void *
op_realloc(void *x, size_t y)
{
	void *ret = realloc(x, y);

	if (op_unlikely(ret == NULL))
		op_outofmemory();
	return (ret);
}

static inline char *
op_strndup(const char *x, size_t y)
{
	char *ret = malloc(y);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	op_strlcpy(ret, x, y);
	return (ret);
}

static inline char *
op_strdup(const char *x)
{
	char *ret = malloc(strlen(x) + 1);
	if (op_unlikely(ret == NULL))
		op_outofmemory();
	memcpy(ret, x, strlen(x) + 1);
	return (ret);
}


static inline void
op_free(void *ptr)
{
	if (op_likely(ptr != NULL))
		free(ptr);
}

#endif /* LIBOP_MEMORY_H */
