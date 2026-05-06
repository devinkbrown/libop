/*
 *  libop: ophion support library.
 *  devpoll.c: /dev/poll I/O backend (Solaris, Illumos, HP-UX, AIX).
 *
 *  Thread safety
 *  -------------
 *  Handler pointer fields (read_handler, write_handler, etc.) and the
 *  per-fd kernel registration state (fdmask[]) are serialised by the
 *  per-fd F->pflags_lock spinlock.  dp_write() — a fixed-size write() to
 *  dpfd — is called while holding F->pflags_lock; the /dev/poll driver
 *  accepts concurrent single-pollfd writes from multiple threads for
 *  distinct fds, so no global dpfd serialisation is required.
 *
 *  Lock order: F->pflags_lock only (never nested with another lock).
 *
 *  One-shot dispatch model
 *  -----------------------
 *  /dev/poll is level-triggered and persistent: once registered an fd keeps
 *  firing until explicitly POLLREMOVE'd.  We implement the one-shot handler
 *  model used by every other libop backend: on dispatch we atomically clear
 *  the handler and remove (or narrow) the /dev/poll registration before
 *  invoking the handler.  Handlers that want further events must
 *  re-register via op_setselect_devpoll().
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
#include <fcntl.h>
#include <pthread.h>

#if defined(HAVE_DEVPOLL) && (HAVE_SYS_DEVPOLL_H)
#include <sys/devpoll.h>

#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

static int            dpfd;
static int            maxfd;
static short         *fdmask;      /* fdmask[fd]: current /dev/poll event mask   */
static struct pollfd *devpollfds;  /* pre-allocated DP_POLL output buffer        */

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

int
op_setup_fd_devpoll(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

int
op_init_netio_devpoll(void)
{
	dpfd = open("/dev/poll", O_RDWR | O_CLOEXEC);
	if (dpfd < 0)
		return errno;

	maxfd = getdtablesize();
	fdmask    = op_malloc(sizeof(*fdmask)    * (size_t)maxfd);
	devpollfds = op_malloc(sizeof(*devpollfds) * (size_t)maxfd);
	memset(fdmask, 0, sizeof(*fdmask) * (size_t)maxfd);

	op_open(dpfd, OP_FD_UNKNOWN, "/dev/poll file descriptor");
	return 0;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * dp_write — write a single pollfd update to the /dev/poll device.
 * Caller MUST hold F->pflags_lock for the fd being updated.
 * The write is a fixed-size kernel call; it will not block.
 */
static void
dp_write(int fd, short events)
{
	struct pollfd pfd;
	pfd.fd      = fd;
	pfd.events  = events;
	pfd.revents = 0;
	if (write(dpfd, &pfd, sizeof(pfd)) != (ssize_t)sizeof(pfd))
		op_lib_log("dp_write: fd %d events 0x%x: %s",
		           fd, (int)events, strerror(errno));
}

/*
 * dp_sync — bring the /dev/poll registration for fd into agreement with
 * desired_mask.  Caller MUST hold F->pflags_lock.
 *
 * If desired_mask differs from the currently-registered mask we issue a
 * POLLREMOVE (to clear the old entry) followed by a re-add if the new
 * mask is non-zero.  If they already match, this is a no-op.
 */
static void
dp_sync(int fd, short desired)
{
	short cur = fdmask[fd];
	if (cur == desired)
		return;
	if (cur != 0)
		dp_write(fd, POLLREMOVE);
	if (desired != 0)
		dp_write(fd, desired);
	fdmask[fd] = desired;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_devpoll
 *
 * Register or deregister read/write interest for F.  Handler fields are
 * updated first so that dp_sync() sees the authoritative state when it
 * computes the new event mask.  Both the handler update and the
 * /dev/poll write are serialised under F->pflags_lock.
 */
void
op_setselect_devpoll(op_fde_t *F, unsigned int type,
                     PF *handler, void *client_data)
{
	short new_mask;

	slop_assert(IsFDOpen(F));

	pthread_spin_lock(&F->pflags_lock);

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
	}
	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
	}

	new_mask = 0;
	if (F->read_handler  != NULL) new_mask |= POLLRDNORM;
	if (F->write_handler != NULL) new_mask |= POLLWRNORM;
	F->pflags = new_mask;

	dp_sync(F->fd, new_mask);

	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

/*
 * op_select_devpoll
 *
 * Poll for ready events via /dev/poll and dispatch read/write callbacks.
 *
 * For each ready fd we atomically capture the handler, clear it, and narrow
 * the /dev/poll registration (one-shot: remove the triggered direction) before
 * calling the handler outside the lock.  The handler may re-register via
 * op_setselect_devpoll() if it wants further events.
 */
int
op_select_devpoll(long delay)
{
	int i, num;
	struct dvpoll dopoll;

	dopoll.dp_timeout = (int)delay;
	dopoll.dp_nfds    = maxfd;
	dopoll.dp_fds     = devpollfds;

	num = ioctl(dpfd, DP_POLL, &dopoll);
	op_set_time();

	if (num < 0)
	{
		if (op_ignore_errno(errno))
			return OP_OK;
		return OP_ERROR;
	}

	for (i = 0; i < num; i++)
	{
		int       fd      = devpollfds[i].fd;
		short     revents = (short)devpollfds[i].revents;
		short     events  = (short)devpollfds[i].events;
		op_fde_t *F       = op_find_fd(fd);

		if (__builtin_expect(F == NULL || !IsFDOpen(F), 0))
			continue;

		if ((revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
		    && (events & (POLLRDNORM | POLLIN)))
		{
			PF   *hdl;
			void *hdata;
			short new_mask;

			pthread_spin_lock(&F->pflags_lock);
			hdl   = F->read_handler;
			hdata = F->read_data;
			F->read_handler = NULL;
			F->read_data    = NULL;
			/* Narrow /dev/poll to write-only (or remove) atomically. */
			new_mask  = 0;
			if (F->write_handler != NULL) new_mask |= POLLWRNORM;
			F->pflags = new_mask;
			dp_sync(fd, new_mask);
			pthread_spin_unlock(&F->pflags_lock);

			if (hdl != NULL)
				hdl(F, hdata);
		}

		if (!IsFDOpen(F))
			continue;

		if ((revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR))
		    && (events & (POLLWRNORM | POLLOUT)))
		{
			PF   *hdl;
			void *hdata;
			short new_mask;

			pthread_spin_lock(&F->pflags_lock);
			hdl   = F->write_handler;
			hdata = F->write_data;
			F->write_handler = NULL;
			F->write_data    = NULL;
			/* Narrow /dev/poll to read-only (or remove) atomically. */
			new_mask  = 0;
			if (F->read_handler != NULL) new_mask |= POLLRDNORM;
			F->pflags = new_mask;
			dp_sync(fd, new_mask);
			pthread_spin_unlock(&F->pflags_lock);

			if (hdl != NULL)
				hdl(F, hdata);
		}
	}

	return OP_OK;
}

#else /* /dev/poll not supported */

int
op_init_netio_devpoll(void) { errno = ENOSYS; return ENOSYS; }

void
op_setselect_devpoll(op_fde_t *F __attribute__((unused)),
                     unsigned int type __attribute__((unused)),
                     PF *handler __attribute__((unused)),
                     void *client_data __attribute__((unused)))
{ errno = ENOSYS; }

int
op_select_devpoll(long delay __attribute__((unused)))
{ errno = ENOSYS; return -1; }

int
op_setup_fd_devpoll(op_fde_t *F __attribute__((unused)))
{ errno = ENOSYS; return -1; }

#endif /* HAVE_DEVPOLL && HAVE_SYS_DEVPOLL_H */
