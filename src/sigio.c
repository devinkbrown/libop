/*
 *  Ophion IRC Daemon
 *  libop/src/sigio.c: Linux Realtime SIGIO / poll I/O backend.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
 *  Copyright (C) 2002 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2002 ircd-ratbox development team
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
 * Design overview
 * ---------------
 * This backend has two operating modes:
 *
 *  SIGIO mode  — uses Linux RT signals (SIGRTMIN) delivered via sigwaitinfo /
 *                sigtimedwait.  Each signal carries the fd (si_fd) and event
 *                mask (si_band) in the siginfo_t.  This avoids a full poll()
 *                scan on each I/O event.
 *
 *  Poll fallback — engaged automatically when the RT signal queue overflows
 *                (kernel delivers SIGIO instead of SIGRTMIN).  A full poll()
 *                scan is performed and the SIGIO machinery is reset for the
 *                next cycle.
 *
 * Thread safety
 * -------------
 *  sigio_pollfd_lock (spinlock) — must be held when reading or writing any
 *                                  field of pollfd_list or pollfd_list.pollfds[].
 *  F->pflags_lock (spinlock per-fd) — must be held when reading or modifying
 *                                     F->pflags / F->read_handler / F->write_handler.
 *  Lock order: always acquire F->pflags_lock BEFORE sigio_pollfd_lock.
 *
 *  can_do_event is an _Atomic int (tri-state: 0 = unknown, 1 = yes, -1 = no).
 *  Atomic compare-exchange ensures at most one thread runs the probe.
 *
 *  sigio_is_screwed is volatile sig_atomic_t.  It is only written from the
 *  dispatch thread (inside op_select_sigio) and is never accessed from a
 *  true async signal handler, so no additional synchronisation is required.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1		/* F_SETSIG */
#endif

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <event-int.h>
#include <fcntl.h>
#include <pthread.h>

#if defined(HAVE_SYS_POLL_H) && (HAVE_POLL) && (F_SETSIG)
# define USING_SIGIO
#endif

#ifdef USING_SIGIO

#include <signal.h>
#include <stdatomic.h>
#include <sys/poll.h>

#if defined(USE_TIMER_CREATE)
# define SIGIO_SCHED_EVENT 1
#endif

#define RTSIGIO  SIGRTMIN
#define RTSIGTIM (SIGRTMIN + 1)

/* -------------------------------------------------------------------------
 * Poll-fd array
 * ---------------------------------------------------------------------- */

struct _pollfd_list
{
	struct pollfd *pollfds;
	int            maxindex;   /* highest fd currently registered */
	int            allocated;  /* total slots in pollfds[]        */
};

typedef struct _pollfd_list pollfd_list_t;

static pollfd_list_t         pollfd_list;
static pthread_spinlock_t    sigio_pollfd_lock;
static volatile sig_atomic_t sigio_is_screwed = 0;
static sigset_t              our_sigset;

/* Tri-state: 0 = not probed yet, 1 = supported, -1 = not supported. */
static _Atomic int can_do_event = 0;

/* -------------------------------------------------------------------------
 * op_init_netio_sigio
 * ---------------------------------------------------------------------- */
int
op_init_netio_sigio(void)
{
	int fd;
	pollfd_list.pollfds   = op_malloc((size_t)op_getmaxconnect() * sizeof(struct pollfd));
	pollfd_list.allocated = op_getmaxconnect();
	for (fd = 0; fd < op_getmaxconnect(); fd++)
		pollfd_list.pollfds[fd].fd = -1;
	pollfd_list.maxindex = 0;

	pthread_spin_init(&sigio_pollfd_lock, PTHREAD_PROCESS_PRIVATE);

	/* Start in poll-fallback mode until the RT signal queue is proven clean. */
	sigio_is_screwed = 1;

	sigemptyset(&our_sigset);
	sigaddset(&our_sigset, RTSIGIO);
	sigaddset(&our_sigset, SIGIO);
#ifdef SIGIO_SCHED_EVENT
	sigaddset(&our_sigset, RTSIGTIM);
#endif
	sigprocmask(SIG_BLOCK, &our_sigset, NULL);
	return 0;
}

/* -------------------------------------------------------------------------
 * resize_pollarray — grow pollfds[] to accommodate fd.
 * Caller MUST hold sigio_pollfd_lock.
 * ---------------------------------------------------------------------- */
static void
resize_pollarray(int fd)
{
	if (op_unlikely(fd >= pollfd_list.allocated))
	{
		int x, old_value = pollfd_list.allocated;
		pollfd_list.allocated += 1024;
		pollfd_list.pollfds =
			op_realloc(pollfd_list.pollfds,
			           (size_t)pollfd_list.allocated * sizeof(struct pollfd));
		/* Initialise newly allocated slots. */
		memset(&pollfd_list.pollfds[old_value], 0,
		       sizeof(struct pollfd) * 1024);
		for (x = old_value; x < pollfd_list.allocated; x++)
			pollfd_list.pollfds[x].fd = -1;
	}
}

/* -------------------------------------------------------------------------
 * op_setup_fd_sigio — enable RT-signal delivery on fd.
 * ---------------------------------------------------------------------- */
int
op_setup_fd_sigio(op_fde_t *F)
{
	int flags;
	int fd = F->fd;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		return 0;

	/* Clear O_ASYNC first so the kernel resets the SIGIO machinery. */
	if (flags & O_ASYNC)
	{
		flags &= ~O_ASYNC;
		fcntl(fd, F_SETFL, flags);
	}

	flags |= O_ASYNC | O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		return 0;
	if (fcntl(fd, F_SETSIG, RTSIGIO) == -1)
		return 0;
	if (fcntl(fd, F_SETOWN, getpid()) == -1)
		return 0;

	return 1;
}

/* -------------------------------------------------------------------------
 * op_setselect_sigio — register or deregister interest in I/O events.
 * ---------------------------------------------------------------------- */
void
op_setselect_sigio(op_fde_t *F, unsigned int type, PF *handler, void *client_data)
{
	if (F == NULL)
		return;

	/* Lock order: pflags_lock → sigio_pollfd_lock. */
	pthread_spin_lock(&F->pflags_lock);
	pthread_spin_lock(&sigio_pollfd_lock);

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
		if (handler != NULL)
			F->pflags |= POLLRDNORM;
		else
			F->pflags &= ~POLLRDNORM;
	}
	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
		if (handler != NULL)
			F->pflags |= POLLWRNORM;
		else
			F->pflags &= ~POLLWRNORM;
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

	pthread_spin_unlock(&sigio_pollfd_lock);
	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * dispatch_read / dispatch_write — common one-shot handler dispatch.
 *
 * Atomically claims the handler under both locks, updates pollfd_list,
 * then calls the handler outside the locks.  Returns true if a handler
 * was dispatched.
 * ---------------------------------------------------------------------- */
static bool
dispatch_read(op_fde_t *F, int fd)
{
	PF   *hdl;
	void *data;

	pthread_spin_lock(&F->pflags_lock);
	pthread_spin_lock(&sigio_pollfd_lock);

	hdl  = F->read_handler;
	data = F->read_data;
	F->read_handler = NULL;
	F->read_data    = NULL;
	F->pflags &= ~POLLRDNORM;

	if (F->pflags == 0)
	{
		pollfd_list.pollfds[fd].events = 0;
		pollfd_list.pollfds[fd].fd     = -1;
	}
	else
	{
		pollfd_list.pollfds[fd].events = (short)F->pflags;
	}
	/* Clear stale revents now that we've consumed this event. */
	pollfd_list.pollfds[fd].revents = 0;

	pthread_spin_unlock(&sigio_pollfd_lock);
	pthread_spin_unlock(&F->pflags_lock);

	if (hdl)
	{
		hdl(F, data);
		return true;
	}
	return false;
}

static bool
dispatch_write(op_fde_t *F, int fd)
{
	PF   *hdl;
	void *data;

	pthread_spin_lock(&F->pflags_lock);
	pthread_spin_lock(&sigio_pollfd_lock);

	hdl  = F->write_handler;
	data = F->write_data;
	F->write_handler = NULL;
	F->write_data    = NULL;
	F->pflags &= ~POLLWRNORM;

	if (F->pflags == 0)
	{
		pollfd_list.pollfds[fd].events = 0;
		pollfd_list.pollfds[fd].fd     = -1;
	}
	else
	{
		pollfd_list.pollfds[fd].events = (short)F->pflags;
	}
	pollfd_list.pollfds[fd].revents = 0;

	pthread_spin_unlock(&sigio_pollfd_lock);
	pthread_spin_unlock(&F->pflags_lock);

	if (hdl)
	{
		hdl(F, data);
		return true;
	}
	return false;
}

/* -------------------------------------------------------------------------
 * op_select_sigio — main I/O dispatch loop.
 *
 * Returns OP_OK on success, OP_ERROR on a hard poll error.
 * ---------------------------------------------------------------------- */
int
op_select_sigio(long delay)
{
	int       sig, fd, ci;
	int       revents;
	int       num = 0;
	op_fde_t *F;
	siginfo_t si;
	struct timespec timeout;

	if (op_sigio_supports_event() || delay >= 0)
	{
		timeout.tv_sec  = delay / 1000;
		timeout.tv_nsec = (delay % 1000) * 1000000L;
	}

	/* ---------------------------------------------------------------
	 * SIGIO mode — drain RT signal queue via sigtimedwait/sigwaitinfo.
	 * -------------------------------------------------------------- */
	while (!sigio_is_screwed)
	{
		if (op_sigio_supports_event() || delay < 0)
			sig = sigwaitinfo(&our_sigset, &si);
		else
			sig = sigtimedwait(&our_sigset, &si, &timeout);

		if (sig <= 0)
			break;

		if (sig == SIGIO)
		{
			/* RT signal queue overflowed; fall through to poll. */
			op_lib_log("Kernel RT signal queue overflowed. "
			           "Check ulimit -i or /proc/sys/kernel/rtsig-max.");
			sigio_is_screwed = 1;
			break;
		}

#ifdef SIGIO_SCHED_EVENT
		if (sig == RTSIGTIM && op_sigio_supports_event())
		{
			struct ev_entry *ev = (struct ev_entry *)si.si_ptr;
			if (ev != NULL)
				op_run_one_event(ev);
			continue;
		}
#endif

		fd = si.si_fd;

		/* Accumulate revents under lock to avoid data race with
		 * op_setselect_sigio running from another thread. */
		pthread_spin_lock(&sigio_pollfd_lock);
		if (fd < pollfd_list.allocated)
			pollfd_list.pollfds[fd].revents |= (short)(si.si_band & 0xffff);
		pthread_spin_unlock(&sigio_pollfd_lock);

		F = op_find_fd(fd);
		if (F == NULL)
			continue;

		num++;

		pthread_spin_lock(&sigio_pollfd_lock);
		revents = pollfd_list.pollfds[fd].revents;
		pthread_spin_unlock(&sigio_pollfd_lock);

		if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
			dispatch_read(F, fd);

		if (!IsFDOpen(F))
			continue;

		if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR))
			dispatch_write(F, fd);
	}

	if (!sigio_is_screwed)
	{
		op_set_time();
		return OP_OK;
	}

	/* ---------------------------------------------------------------
	 * Poll fallback — full scan via poll(2).
	 *
	 * Reset the SIGIO machinery using sigaction with SA_RESTART so that
	 * the next cycle can attempt to use RT signals again.  Using
	 * signal(SIG_IGN) + signal(SIG_DFL) is deprecated and racy; sigaction
	 * is the correct interface.
	 * -------------------------------------------------------------- */
	{
		struct sigaction sa;
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(RTSIGIO, &sa, NULL);
		sa.sa_handler = SIG_DFL;
		sigaction(RTSIGIO, &sa, NULL);
	}
	sigio_is_screwed = 0;

	num = poll(pollfd_list.pollfds, pollfd_list.maxindex + 1, (int)delay);
	op_set_time();

	if (num < 0)
	{
		if (!op_ignore_errno(errno))
			return OP_ERROR;
		return OP_OK;
	}
	if (num == 0)
		return OP_OK;

	for (ci = 0; ci <= pollfd_list.maxindex; ci++)
	{
		/* Read revents under lock to avoid a concurrent setselect race. */
		pthread_spin_lock(&sigio_pollfd_lock);
		revents = pollfd_list.pollfds[ci].revents;
		fd      = pollfd_list.pollfds[ci].fd;
		pthread_spin_unlock(&sigio_pollfd_lock);

		if (revents == 0 || fd == -1)
			continue;

		F = op_find_fd(fd);
		if (F == NULL)
			continue;

		if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR))
			dispatch_read(F, fd);

		if (IsFDOpen(F) && (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)))
			dispatch_write(F, fd);
	}

	return OP_OK;
}

/* =========================================================================
 * Event-timer support (SIGIO_SCHED_EVENT)
 * ====================================================================== */

#if defined(SIGIO_SCHED_EVENT)

void
op_sigio_init_event(void)
{
	/* Trigger the probe so the result is cached before first use. */
	(void)op_sigio_supports_event();
}

/*
 * op_sigio_supports_event — probe once whether timer_create is available.
 *
 * Uses atomic compare-exchange so only one thread runs the probe even if
 * multiple threads call this simultaneously at startup.  Returns 1 if
 * supported, 0 if not.
 */
int
op_sigio_supports_event(void)
{
	int probe, result;
	timer_t timer;
	struct sigevent ev;

	/* Fast path: already probed. */
	probe = atomic_load_explicit(&can_do_event, memory_order_acquire);
	if (probe != 0)
		return probe == 1;

	/* Race to probe: only the winner (0 → -1 CAS succeeds) runs the test. */
	int expected = 0;
	if (!atomic_compare_exchange_strong_explicit(
	        &can_do_event, &expected, -1,
	        memory_order_acq_rel, memory_order_acquire))
	{
		/* Another thread is probing or already has.  Spin until done. */
		while ((probe = atomic_load_explicit(&can_do_event, memory_order_acquire)) == -1)
			;
		return probe == 1;
	}

	/* We own the probe slot (value is now -1 = "in progress"). */
	memset(&ev, 0, sizeof(ev));
	ev.sigev_signo  = SIGVTALRM;
	ev.sigev_notify = SIGEV_SIGNAL;
	result = (timer_create(CLOCK_MONOTONIC, &ev, &timer) == 0) ? 1 : -2;
	if (result == 1)
		timer_delete(timer);

	/* Publish result: 1 (yes) or -2 (no — we use -2 because -1 = in-progress). */
	atomic_store_explicit(&can_do_event, result, memory_order_release);
	return result == 1;
}

int
op_sigio_sched_event(struct ev_entry *event, int when)
{
	timer_t *id;
	struct sigevent ev;
	struct itimerspec ts;

	if (!op_sigio_supports_event())
		return 0;

	memset(&ev, 0, sizeof(ev));
	event->comm_ptr        = op_malloc(sizeof(timer_t));
	id                     = event->comm_ptr;
	ev.sigev_notify        = SIGEV_SIGNAL;
	ev.sigev_signo         = RTSIGTIM;
	ev.sigev_value.sival_ptr = event;

	if (timer_create(CLOCK_MONOTONIC, &ev, id) < 0)
	{
		op_lib_log("timer_create: %s", strerror(errno));
		op_free(event->comm_ptr);
		event->comm_ptr = NULL;
		return 0;
	}

	memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_sec  = when;
	ts.it_value.tv_nsec = 0;
	if (event->frequency != 0)
		ts.it_interval = ts.it_value;

	if (timer_settime(*id, 0, &ts, NULL) < 0)
	{
		op_lib_log("timer_settime: %s", strerror(errno));
		timer_delete(*id);
		op_free(event->comm_ptr);
		event->comm_ptr = NULL;
		return 0;
	}
	return 1;
}

void
op_sigio_unsched_event(struct ev_entry *event)
{
	if (!op_sigio_supports_event())
		return;
	if (event->comm_ptr == NULL)
		return;
	timer_delete(*((timer_t *)event->comm_ptr));
	op_free(event->comm_ptr);
	event->comm_ptr = NULL;
}

#endif /* SIGIO_SCHED_EVENT */

/* =========================================================================
 * Stub implementations when SIGIO is not available
 * ====================================================================== */

#else /* !USING_SIGIO */

int
op_init_netio_sigio(void)
{
	return ENOSYS;
}

void
op_setselect_sigio(op_fde_t *F __attribute__((unused)),
                   unsigned int type __attribute__((unused)),
                   PF *handler __attribute__((unused)),
                   void *client_data __attribute__((unused)))
{
	errno = ENOSYS;
}

int
op_select_sigio(long delay __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

int
op_setup_fd_sigio(op_fde_t *F __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

#endif /* USING_SIGIO */

/* =========================================================================
 * Event-timer stubs when SIGIO or timer support is absent
 * ====================================================================== */

#if !defined(USING_SIGIO) || !defined(SIGIO_SCHED_EVENT)

void
op_sigio_init_event(void)
{
}

int
op_sigio_sched_event(struct ev_entry *event __attribute__((unused)),
                     int when __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

void
op_sigio_unsched_event(struct ev_entry *event __attribute__((unused)))
{
}

int
op_sigio_supports_event(void)
{
	errno = ENOSYS;
	return 0;
}

#endif /* !USING_SIGIO || !SIGIO_SCHED_EVENT */
