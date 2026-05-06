/*
 *  ircd-ratbox: A slightly useful ircd.
 *  tools.h: Header for the various tool functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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
# error "Do not use tools.h directly"
#endif

#ifndef __TOOLS_H__
#define __TOOLS_H__

int op_strcasecmp(const char *s1, const char *s2);
int op_strncasecmp(const char *s1, const char *s2, size_t n);
char *op_strcasestr(const char *s, const char *find);
size_t op_strlcpy(char *dst, const char *src, size_t siz);
size_t op_strlcat(char *dst, const char *src, size_t siz);
size_t op_strnlen(const char *s, size_t count);
int op_snprintf_append(char *str, size_t len, const char *format, ...) AFP(3,4);
int op_snprintf_try_append(char *str, size_t len, const char *format, ...) AFP(3,4);

char *op_basename(const char *);
char *op_dirname(const char *);

int op_string_to_array(char *string, char **parv, int maxpara);

/*
 * double-linked-list stuff
 */
typedef struct _op_dlink_node op_dlink_node;
typedef struct _op_dlink_list op_dlink_list;

struct _op_dlink_node
{
	void *data;
	op_dlink_node *prev;
	op_dlink_node *next;

};

struct _op_dlink_list
{
	op_dlink_node *head;
	op_dlink_node *tail;
	uint64_t length;
};

op_dlink_node *op_make_dlink_node(void);
void op_free_dlink_node(op_dlink_node *lp);
void op_init_dlink_nodes(size_t dh_size);

/* This macros are basically swiped from the linux kernel
 * they are simple yet effective
 */

/*
 * Walks forward of a list.
 * pos is your node
 * head is your list head
 */
#define OP_DLINK_FOREACH(pos, head) for (pos = (head); pos != NULL; pos = pos->next)

/*
 * Walks forward of a list safely while removing nodes
 * pos is your node
 * n is another list head for temporary storage
 * head is your list head
 */
#define OP_DLINK_FOREACH_SAFE(pos, n, head) for (pos = (head), n = pos ? pos->next : NULL; pos != NULL; pos = n, n = pos ? pos->next : NULL)

#define OP_DLINK_FOREACH_PREV(pos, head) for (pos = (head); pos != NULL; pos = pos->prev)


/* Returns the list length */
#define op_dlink_list_length(list) (list)->length

#define op_dlinkAddAlloc(data, list) op_dlinkAdd(data, op_make_dlink_node(), list)
#define op_dlinkAddTailAlloc(data, list) op_dlinkAddTail(data, op_make_dlink_node(), list)
#define op_dlinkDestroy(node, list) do { op_dlinkDelete(node, list); op_free_dlink_node(node); } while(0)


/*
 * dlink_ routines are stolen from squid, except for op_dlinkAddBefore,
 * which is mine.
 *   -- adrian
 */

static inline void
op_dlinkMoveNode(op_dlink_node *m, op_dlink_list *oldlist, op_dlink_list *newlist)
{
	/* Assumption: If m->next == NULL, then list->tail == m
	 *      and:   If m->prev == NULL, then list->head == m
	 */
	slop_assert(m != NULL);
	slop_assert(oldlist != NULL);
	slop_assert(newlist != NULL);

	if (m->next)
		m->next->prev = m->prev;
	else
		oldlist->tail = m->prev;

	if (m->prev)
		m->prev->next = m->next;
	else
		oldlist->head = m->next;

	m->prev = NULL;
	m->next = newlist->head;
	if (newlist->head != NULL)
		newlist->head->prev = m;
	else if(newlist->tail == NULL)
		newlist->tail = m;
	newlist->head = m;

	oldlist->length--;
	newlist->length++;
}

static inline void
op_dlinkAdd(void *data, op_dlink_node *m, op_dlink_list *list)
{
	slop_assert(data != NULL);
	slop_assert(m != NULL);
	slop_assert(list != NULL);

	m->data = data;
	m->prev = NULL;
	m->next = list->head;

	/* Assumption: If list->tail != NULL, list->head != NULL */
	if (list->head != NULL)
		list->head->prev = m;
	else if(list->tail == NULL)
		list->tail = m;

	list->head = m;
	list->length++;
}

static inline void
op_dlinkAddBefore(op_dlink_node *b, void *data, op_dlink_node *m, op_dlink_list *list)
{
	slop_assert(b != NULL);
	slop_assert(data != NULL);
	slop_assert(m != NULL);
	slop_assert(list != NULL);

	/* Shortcut - if its the first one, call op_dlinkAdd only */
	if (b == list->head)
	{
		op_dlinkAdd(data, m, list);
	}
	else
	{
		m->data = data;
		b->prev->next = m;
		m->prev = b->prev;
		b->prev = m;
		m->next = b;
		list->length++;
	}
}

static inline void
op_dlinkMoveTail(op_dlink_node *m, op_dlink_list *list)
{
	if (list->tail == m)
		return;

	/* From here assume that m->next != NULL as that can only
	 * be at the tail and assume that the node is on the list
	 */

	m->next->prev = m->prev;

	if (m->prev != NULL)
		m->prev->next = m->next;
	else
		list->head = m->next;

	list->tail->next = m;
	m->prev = list->tail;
	m->next = NULL;
	list->tail = m;
}

static inline void
op_dlinkAddTail(void *data, op_dlink_node *m, op_dlink_list *list)
{
	slop_assert(m != NULL);
	slop_assert(list != NULL);
	slop_assert(data != NULL);

	m->data = data;
	m->next = NULL;
	m->prev = list->tail;

	/* Assumption: If list->tail != NULL, list->head != NULL */
	if (list->tail != NULL)
		list->tail->next = m;
	else if(list->head == NULL)
		list->head = m;

	list->tail = m;
	list->length++;
}

/* Execution profiles show that this function is called the most
 * often of all non-spontaneous functions. So it had better be
 * efficient. */
static inline void
op_dlinkDelete(op_dlink_node *m, op_dlink_list *list)
{
	slop_assert(m != NULL);
	slop_assert(list != NULL);
	/* Assumption: If m->next == NULL, then list->tail == m
	 *      and:   If m->prev == NULL, then list->head == m
	 */
	if (m->next)
		m->next->prev = m->prev;
	else
		list->tail = m->prev;

	if (m->prev)
		m->prev->next = m->next;
	else
		list->head = m->next;

	m->next = m->prev = NULL;
	list->length--;
}

static inline op_dlink_node *
op_dlinkFindDelete(void *data, op_dlink_list *list)
{
	op_dlink_node *m;
	slop_assert(list != NULL);
	slop_assert(data != NULL);
	OP_DLINK_FOREACH(m, list->head)
	{
		if (m->data != data)
			continue;

		if (m->next)
			m->next->prev = m->prev;
		else
			list->tail = m->prev;

		if (m->prev)
			m->prev->next = m->next;
		else
			list->head = m->next;

		m->next = m->prev = NULL;
		list->length--;
		return m;
	}
	return NULL;
}

static inline int
op_dlinkFindDestroy(void *data, op_dlink_list *list)
{
	void *ptr;

	slop_assert(list != NULL);
	slop_assert(data != NULL);
	ptr = op_dlinkFindDelete(data, list);

	if (ptr != NULL)
	{
		op_free_dlink_node(ptr);
		return 1;
	}
	return 0;
}

/*
 * op_dlinkFind
 * inputs	- list to search
 *		- data
 * output	- pointer to link or NULL if not found
 * side effects	- Look for ptr in the linked listed pointed to by link.
 */
static inline op_dlink_node *
op_dlinkFind(void *data, op_dlink_list *list)
{
	op_dlink_node *ptr;
	slop_assert(list != NULL);
	slop_assert(data != NULL);

	OP_DLINK_FOREACH(ptr, list->head)
	{
		if (ptr->data == data)
			return (ptr);
	}
	return (NULL);
}

static inline void
op_dlinkMoveList(op_dlink_list *from, op_dlink_list *to)
{
	slop_assert(from != NULL);
	slop_assert(to != NULL);

	/* There are three cases */
	/* case one, nothing in from list */
	if (from->head == NULL)
		return;

	/* case two, nothing in to list */
	if (to->head == NULL)
	{
		to->head = from->head;
		to->tail = from->tail;
		from->head = from->tail = NULL;
		to->length = from->length;
		from->length = 0;
		return;
	}

	/* third case play with the links */
	from->tail->next = to->head;
	to->head->prev = from->tail;
	to->head = from->head;
	from->head = from->tail = NULL;
	to->length += from->length;
	from->length = 0;
}


typedef int (*op_strf_func_t)(char *buf, size_t len, void *args);

typedef struct _op_strf {
	size_t length;			/* length limit to apply to this string (and following strings if their length is 0) */
	const char *format;		/* string or format string */
	op_strf_func_t func;		/* function to print to string */
	union {
		va_list *format_args;	/* non-NULL if this is a format string */
		void *func_args;	/* args for a function */
	};
	const struct _op_strf *next;	/* next string to append */
} op_strf_t;

int op_fsnprint(char *buf, size_t len, const op_strf_t *strings);
int op_fsnprintf(char *buf, size_t len, const op_strf_t *strings, const char *format, ...) AFP(4, 5);


const char *op_path_to_self(void);

#endif /* __TOOLS_H__ */
