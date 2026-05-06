/*
 *  libop: ophion support library.
 *  poll.c: POSIX poll(2) I/O backend.
 *
 *  Thread safety
 *  -------------
 *  Handler pointer fields are serialised by F->pflags_lock.  The global
 *  pollfd_list (pollfds array, maxindex, allocated) is additionally
 *  protected by pollfd_lock so that worker-thread op_setselect_poll() calls
 *  don't race against the I/O thread reading pollfd_list in op_select_poll().
 *
 *  Lock order: F->pflags_lock THEN pollfd_lock (never the reverse).
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
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

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <pthread.h>

#if defined(HAVE_POLL)
#include <poll.h>

#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

struct _pollfd_list
{
	struct pollfd *pollfds;
	int maxindex;   /* highest registered fd index */
	int allocated;  /* current allocation */
};

typedef struct _pollfd_list pollfd_list_t;

static pollfd_list_t      pollfd_list;
static pthread_spinlock_t pollfd_lock;  /* guards pollfd_list */

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

__attribute__((cold))
int
op_setup_fd_poll(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

__attribute__((cold))
int
op_init_netio_poll(void)
{
	int fd;
	int maxconn = op_getmaxconnect();

	pollfd_list.pollfds   = op_malloc((size_t)maxconn * sizeof(struct pollfd));
	pollfd_list.allocated = maxconn;

	for (fd = 0; fd < maxconn; fd++)
		pollfd_list.pollfds[fd].fd = -1;

	pollfd_list.maxindex = 0;
	pthread_spin_init(&pollfd_lock, PTHREAD_PROCESS_PRIVATE);
	return 0;
}

/*
 * resize_pollarray — grow pollfds if fd exceeds the current allocation.
 * Caller MUST hold pollfd_lock.
 */
static __attribute__((cold)) void
resize_pollarray(int fd)
{
	if (__builtin_expect(fd >= pollfd_list.allocated, 0))
	{
		int old_value = pollfd_list.allocated;
		pollfd_list.allocated += 1024;
		pollfd_list.pollfds = op_realloc(pollfd_list.pollfds,
		                                 (size_t)pollfd_list.allocated *
		                                 sizeof(struct pollfd));
		memset(&pollfd_list.pollfds[old_value], 0,
		       sizeof(struct pollfd) * 1024);
		for (int x = old_value; x < pollfd_list.allocated; x++)
			pollfd_list.pollfds[x].fd = -1;
	}
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_poll
 *
 * Register or deregister read/write interest for F.  Both F->pflags_lock and
 * pollfd_lock are held so that the handler fields and the pollfds array are
 * updated atomically.
 */
__attribute__((hot))
void
op_setselect_poll(op_fde_t *restrict F, unsigned int type,
                  PF *handler, void *client_data)
{
	if (__builtin_expect(F == NULL, 0))
		return;

	pthread_spin_lock(&F->pflags_lock);
	pthread_spin_lock(&pollfd_lock);

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
		if (handler) F->pflags |=  POLLRDNORM;
		else         F->pflags &= ~POLLRDNORM;
	}

	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
		if (handler) F->pflags |=  POLLWRNORM;
		else         F->pflags &= ~POLLWRNORM;
	}

	resize_pollarray(F->fd);

	if (F->pflags == 0)
	{
		pollfd_list.pollfds[F->fd].events = 0;
		pollfd_list.pollfds[F->fd].fd     = -1;

		if (F->fd == pollfd_list.maxindex)
		{
			while (pollfd_list.maxindex >= 0
			       && pollfd_list.pollfds[pollfd_list.maxindex].fd == -1)
				pollfd_list.maxindex--;
		}
	}
	else
	{
		pollfd_list.pollfds[F->fd].events = (short)F->pflags;
		pollfd_list.pollfds[F->fd].fd     = F->fd;
		if (F->fd > pollfd_list.maxindex)
			pollfd_list.maxindex = F->fd;
	}

	pthread_spin_unlock(&pollfd_lock);
	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

__attribute__((hot))
int
op_select_poll(long delay)
{
	int num, ci;
	PF *hdl;
	void *data;
	int maxindex;

	/* Snapshot maxindex under pollfd_lock; the poll() call itself reads
	 * pollfds[] which may be concurrently written by worker setselect calls.
	 * The snapshot bounds our iteration; any new fds added after the snapshot
	 * will be picked up on the next op_select_poll() iteration. */
	pthread_spin_lock(&pollfd_lock);
	maxindex = pollfd_list.maxindex;
	pthread_spin_unlock(&pollfd_lock);

	num = poll(pollfd_list.pollfds, (nfds_t)(maxindex + 1), (int)delay);
	op_set_time();

	if (__builtin_expect(num < 0, 0))
	{
		if (!op_ignore_errno(errno))
			return OP_ERROR;
		return OP_OK;
	}
	if (num == 0)
		return OP_OK;

	for (ci = 0; ci <= maxindex; ci++)
	{
		op_fde_t *F;
		int revents, fd;

		pthread_spin_lock(&pollfd_lock);
		revents = pollfd_list.pollfds[ci].revents;
		fd      = pollfd_list.pollfds[ci].fd;
		pthread_spin_unlock(&pollfd_lock);

		if (__builtin_expect((revents == 0) | (fd == -1), 1))
			continue;

		F = op_find_fd(fd);
		if (__builtin_expect(F == NULL, 0))
			continue;

		if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
		{
			pthread_spin_lock(&F->pflags_lock);
			pthread_spin_lock(&pollfd_lock);
			hdl  = F->read_handler;  data = F->read_data;
			F->read_handler = NULL;  F->read_data = NULL;
			F->pflags &= ~POLLRDNORM;
			if (F->pflags == 0)
			{
				pollfd_list.pollfds[fd].events = 0;
				pollfd_list.pollfds[fd].fd     = -1;
			}
			else
				pollfd_list.pollfds[fd].events = (short)F->pflags;
			pthread_spin_unlock(&pollfd_lock);
			pthread_spin_unlock(&F->pflags_lock);
			if (hdl)
				hdl(F, data);
		}

		if (!IsFDOpen(F))
			continue;

		if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR))
		{
			pthread_spin_lock(&F->pflags_lock);
			pthread_spin_lock(&pollfd_lock);
			hdl  = F->write_handler; data = F->write_data;
			F->write_handler = NULL; F->write_data = NULL;
			F->pflags &= ~POLLWRNORM;
			if (F->pflags == 0)
			{
				pollfd_list.pollfds[fd].events = 0;
				pollfd_list.pollfds[fd].fd     = -1;
			}
			else
				pollfd_list.pollfds[fd].events = (short)F->pflags;
			pthread_spin_unlock(&pollfd_lock);
			pthread_spin_unlock(&F->pflags_lock);
			if (hdl)
				hdl(F, data);
		}
	}

	return OP_OK;
}

#else /* poll not supported */

__attribute__((cold)) int
op_init_netio_poll(void) { errno = ENOSYS; return -1; }

__attribute__((cold)) void
op_setselect_poll(op_fde_t *F __attribute__((unused)),
                  unsigned int type __attribute__((unused)),
                  PF *handler __attribute__((unused)),
                  void *client_data __attribute__((unused)))
{ errno = ENOSYS; }

__attribute__((cold)) int
op_select_poll(long delay __attribute__((unused)))
{ errno = ENOSYS; return -1; }

__attribute__((cold)) int
op_setup_fd_poll(op_fde_t *F __attribute__((unused)))
{ errno = ENOSYS; return -1; }

#endif /* HAVE_POLL */
