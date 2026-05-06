/*
 *  libop: ophion support library.
 *  select.c: select(2) I/O backend.
 *
 *  Thread safety
 *  -------------
 *  Handler pointer fields (read_handler, write_handler) are serialised by
 *  F->pflags_lock.  The global fd sets (select_readfds, select_writefds,
 *  op_maxfd) are additionally protected by the global select_lock spinlock.
 *  select_lock is acquired whenever the global sets are read or written.
 *
 *  Lock order: F->pflags_lock THEN select_lock (never the reverse).
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

#define FD_SETSIZE 65535
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <pthread.h>

#if defined(HAVE_SELECT) || defined(_WIN32)

#ifdef _WIN32
#define MY_FD_SET(x, y) FD_SET((SOCKET)x, y)
#define MY_FD_CLR(x, y) FD_CLR((SOCKET)x, y)
#else
#define MY_FD_SET(x, y) FD_SET(x, y)
#define MY_FD_CLR(x, y) FD_CLR(x, y)
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

static fd_set select_readfds;
static fd_set select_writefds;
static int    op_maxfd = -1;

/*
 * select_lock serialises access to select_readfds, select_writefds, and
 * op_maxfd from both the I/O thread (op_select_select) and worker threads
 * (op_setselect_select).
 */
static pthread_spinlock_t select_lock;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * select_update_fds — update the master fd sets and op_maxfd.
 * Caller MUST hold select_lock.
 */
static void
select_update_fds(op_fde_t *F, short event, PF *handler)
{
	if (event & OP_SELECT_READ)
	{
		if (handler)
		{
			MY_FD_SET(F->fd, &select_readfds);
			F->pflags |= OP_SELECT_READ;
		}
		else
		{
			MY_FD_CLR(F->fd, &select_readfds);
			F->pflags &= ~OP_SELECT_READ;
		}
	}

	if (event & OP_SELECT_WRITE)
	{
		if (handler)
		{
			MY_FD_SET(F->fd, &select_writefds);
			F->pflags |= OP_SELECT_WRITE;
		}
		else
		{
			MY_FD_CLR(F->fd, &select_writefds);
			F->pflags &= ~OP_SELECT_WRITE;
		}
	}

	if (F->pflags & (OP_SELECT_READ | OP_SELECT_WRITE))
	{
		if (F->fd > op_maxfd)
			op_maxfd = F->fd;
	}
	else if (F->fd <= op_maxfd)
	{
		/* Shrink maxfd down to the highest still-registered fd. */
		while (op_maxfd >= 0
		       && !FD_ISSET(op_maxfd, &select_readfds)
		       && !FD_ISSET(op_maxfd, &select_writefds))
			op_maxfd--;
	}
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

int
op_setup_fd_select(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

extern int op_maxconnections;

__attribute__((cold))
int
op_init_netio_select(void)
{
	if (op_maxconnections > FD_SETSIZE)
		op_maxconnections = FD_SETSIZE;
	FD_ZERO(&select_readfds);
	FD_ZERO(&select_writefds);
	pthread_spin_init(&select_lock, PTHREAD_PROCESS_PRIVATE);
	return 0;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_select
 *
 * Update handler interest and the master fd sets.
 * Both F->pflags_lock and select_lock are held for the update so that
 * F->pflags and the global fd sets are always consistent.
 */
__attribute__((hot))
void
op_setselect_select(op_fde_t *F, unsigned int type,
                    PF *handler, void *client_data)
{
	slop_assert(IsFDOpen(F));

	pthread_spin_lock(&F->pflags_lock);
	pthread_spin_lock(&select_lock);

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
		select_update_fds(F, OP_SELECT_READ, handler);
	}
	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
		select_update_fds(F, OP_SELECT_WRITE, handler);
	}

	pthread_spin_unlock(&select_lock);
	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

__attribute__((hot))
int
op_select_select(long delay)
{
	int num, fd;
	PF *hdl;
	void *hdata;
	op_fde_t *F;
	fd_set tmpreadfds, tmpwritefds;
	struct timeval to;
	struct timeval *top = NULL;
	int maxfd;

	if (delay >= 0)
	{
		to.tv_sec  =  delay / 1000;
		to.tv_usec = (delay % 1000) * 1000;
		top = &to;
	}
	/* delay < 0 → top remains NULL → select() blocks indefinitely */

	/* Snapshot the master fd sets under select_lock so we don't race with
	 * concurrent op_setselect_select calls from worker threads. */
	pthread_spin_lock(&select_lock);
	memcpy(&tmpreadfds,  &select_readfds,  sizeof(fd_set));
	memcpy(&tmpwritefds, &select_writefds, sizeof(fd_set));
	maxfd = op_maxfd;
	pthread_spin_unlock(&select_lock);

	for (;;)
	{
		num = select(maxfd + 1, &tmpreadfds, &tmpwritefds, NULL, top);
		if (num >= 0)
			break;
		if (op_ignore_errno(errno))
		{
			/* EINTR — re-snapshot and retry to pick up any setselect
			 * changes that arrived while we were waiting. */
			pthread_spin_lock(&select_lock);
			memcpy(&tmpreadfds,  &select_readfds,  sizeof(fd_set));
			memcpy(&tmpwritefds, &select_writefds, sizeof(fd_set));
			maxfd = op_maxfd;
			pthread_spin_unlock(&select_lock);
			continue;
		}
		op_set_time();
		return OP_ERROR;
	}

	op_set_time();

	if (num == 0)
		return OP_OK;

	for (fd = 0; fd <= maxfd; fd++)
	{
		if (!FD_ISSET(fd, &tmpreadfds) && !FD_ISSET(fd, &tmpwritefds))
			continue;

		F = op_find_fd(fd);
		if (__builtin_expect(F == NULL, 0))
			continue;

		if (FD_ISSET(fd, &tmpreadfds))
		{
			pthread_spin_lock(&F->pflags_lock);
			pthread_spin_lock(&select_lock);
			hdl   = F->read_handler;
			hdata = F->read_data;
			F->read_handler = NULL;
			F->read_data    = NULL;
			select_update_fds(F, OP_SELECT_READ, NULL);
			pthread_spin_unlock(&select_lock);
			pthread_spin_unlock(&F->pflags_lock);
			if (hdl)
				hdl(F, hdata);
		}

		if (!IsFDOpen(F))
			continue;

		if (FD_ISSET(fd, &tmpwritefds))
		{
			pthread_spin_lock(&F->pflags_lock);
			pthread_spin_lock(&select_lock);
			hdl   = F->write_handler;
			hdata = F->write_data;
			F->write_handler = NULL;
			F->write_data    = NULL;
			select_update_fds(F, OP_SELECT_WRITE, NULL);
			pthread_spin_unlock(&select_lock);
			pthread_spin_unlock(&F->pflags_lock);
			if (hdl)
				hdl(F, hdata);
		}
	}

	return OP_OK;
}

#else /* select not supported */

int
op_init_netio_select(void)
{
	return -1;
}

void
op_setselect_select(op_fde_t *F __attribute__((unused)),
                    unsigned int type __attribute__((unused)),
                    PF *handler __attribute__((unused)),
                    void *client_data __attribute__((unused)))
{
	errno = ENOSYS;
}

int
op_select_select(long delay __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

int
op_setup_fd_select(op_fde_t *F __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

#endif /* HAVE_SELECT || _WIN32 */
