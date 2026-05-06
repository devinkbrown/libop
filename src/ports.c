/*
 *  libop: ophion support library.
 *  ports.c: Solaris event ports I/O backend.
 *
 *  Event ports use an implicit one-shot model: each port_getn() event
 *  de-registers the fd.  Handlers must call op_setselect_ports() to
 *  re-register if they want further events.  This matches the handler
 *  lifecycle used by every other libop backend.
 *
 *  Thread safety
 *  -------------
 *  Handler pointer fields are serialised by F->pflags_lock.
 *  port_associate(3C) and port_dissociate(3C) are called OUTSIDE
 *  pflags_lock using a locally captured copy of the new flags.  The
 *  Solaris port API is itself thread-safe; holding a spinlock across
 *  those calls is unnecessary and harmful.
 *
 *  Lock order: F->pflags_lock only (never nested with another lock).
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
 *  Copyright (C) 2002-2004,2008 ircd-ratbox development team
 *  Copyright (C) 2005 Edward Brocklesby.
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
#include <event-int.h>
#include <pthread.h>

#if defined(HAVE_PORT_CREATE)

#include <port.h>

static int pe;
static struct timespec zero_timespec;
static port_event_t *pelst;
static int pemax;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

int
op_setup_fd_ports(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

int
op_init_netio_ports(void)
{
	if ((pe = port_create()) < 0)
		return errno;

	pemax = getdtablesize();
	pelst = op_malloc(sizeof(port_event_t) * (size_t)pemax);

	zero_timespec.tv_sec  = 0;
	zero_timespec.tv_nsec = 0;
	op_set_time();
	return 0;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_ports
 *
 * Update handler interest for F.  The new interest mask is computed under
 * pflags_lock; port_associate/dissociate is called outside the lock using
 * the captured new_flags value so no spinlock is held across a syscall.
 */
void
op_setselect_ports(op_fde_t *F, unsigned int type,
                   PF *handler, void *client_data)
{
	int old_flags, new_flags;

	slop_assert(IsFDOpen(F));

	pthread_spin_lock(&F->pflags_lock);

	old_flags = F->pflags;

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

	F->pflags  = 0;
	if (F->read_handler  != NULL) F->pflags |= POLLIN;
	if (F->write_handler != NULL) F->pflags |= POLLOUT;

	new_flags = F->pflags;

	pthread_spin_unlock(&F->pflags_lock);

	/* No-op if nothing changed. */
	if (old_flags == 0 && new_flags == 0)
		return;

	if (new_flags == 0)
	{
		port_dissociate(pe, PORT_SOURCE_FD, (uintptr_t)F->fd);
		return;
	}

	/* port_associate re-registers interest (also used as "MOD").
	 * F is stored as user data so the dispatch loop receives it directly. */
	port_associate(pe, PORT_SOURCE_FD, (uintptr_t)F->fd, new_flags, F);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

/*
 * op_select_ports
 *
 * Drain up to pemax events from the port.  Each event auto-de-registers
 * the fd; op_setselect_ports() is called by handlers that want further events.
 * After dispatching each CQE we re-associate the fd if any interest remains.
 */
int
op_select_ports(long delay)
{
	int i;
	unsigned int nget = (unsigned int)pemax;  /* drain as many as possible */
	struct timespec poll_time;
	struct timespec *p = NULL;
	struct ev_entry *ev;

	if (delay >= 0)
	{
		poll_time.tv_sec  =  delay / 1000;
		poll_time.tv_nsec = (delay % 1000) * 1000000L;
		p = &poll_time;
	}

	i = port_getn(pe, pelst, (uint_t)pemax, &nget, p);
	op_set_time();

	/* port_getn returns -1 on timeout (ETIME) or interrupt; both benign. */
	if (i == -1)
		return OP_OK;

	for (i = 0; (unsigned)i < nget; i++)
	{
		if (pelst[i].portev_source == PORT_SOURCE_FD)
		{
			int       pev_events = (int)pelst[i].portev_events;
			op_fde_t *F          = (op_fde_t *)pelst[i].portev_user;

			if (__builtin_expect(F == NULL || !IsFDOpen(F), 0))
				continue;

			if (pev_events & (POLLIN | POLLHUP | POLLERR))
			{
				PF   *hdl;
				void *hdata;
				pthread_spin_lock(&F->pflags_lock);
				hdl   = F->read_handler;
				hdata = F->read_data;
				F->read_handler = NULL;
				F->read_data    = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (hdl != NULL)
					hdl(F, hdata);
			}

			if (!IsFDOpen(F))
				continue;

			if (pev_events & (POLLOUT | POLLHUP | POLLERR))
			{
				PF   *hdl;
				void *hdata;
				pthread_spin_lock(&F->pflags_lock);
				hdl   = F->write_handler;
				hdata = F->write_data;
				F->write_handler = NULL;
				F->write_data    = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (hdl != NULL)
					hdl(F, hdata);
			}

			/*
			 * port_getn() auto-de-registers the fd on each event.
			 * Re-associate if any interest was re-registered during dispatch
			 * (handlers that want further events call op_setselect_ports which
			 * already calls port_associate).  If no interest remains the fd
			 * stays de-registered.
			 *
			 * Re-read pflags under the lock so we see any updates from
			 * handler-initiated op_setselect_ports calls.
			 */
			if (IsFDOpen(F))
			{
				int cur_flags;
				pthread_spin_lock(&F->pflags_lock);
				cur_flags = F->pflags;
				pthread_spin_unlock(&F->pflags_lock);
				/* If the handler already called op_setselect_ports, it has
				 * already re-associated.  If pflags is non-zero and no
				 * re-associate was done (e.g. the original event consumed
				 * only one direction), re-associate now. */
				if (cur_flags != 0)
					port_associate(pe, PORT_SOURCE_FD, (uintptr_t)F->fd,
					               cur_flags, F);
			}
		}
		else if (pelst[i].portev_source == PORT_SOURCE_TIMER)
		{
			ev = (struct ev_entry *)pelst[i].portev_user;
			if (__builtin_expect(ev != NULL, 1))
				op_run_one_event(ev);
		}
	}

	return OP_OK;
}

/* -------------------------------------------------------------------------
 * Event scheduling (Solaris SIGEV_PORT timer backend)
 * ---------------------------------------------------------------------- */

int
op_ports_supports_event(void)
{
	return 1;
}

void
op_ports_init_event(void)
{
	return;
}

int
op_ports_sched_event(struct ev_entry *event, int when)
{
	timer_t *id;
	struct sigevent sev;
	port_notify_t pnot;
	struct itimerspec ts;

	event->comm_ptr = op_malloc(sizeof(timer_t));
	id = event->comm_ptr;

	memset(&sev,  0, sizeof(sev));
	memset(&pnot, 0, sizeof(pnot));

	pnot.portnfy_port = pe;
	pnot.portnfy_user = event;

	sev.sigev_notify          = SIGEV_PORT;
	sev.sigev_value.sival_ptr = &pnot;

	if (timer_create(CLOCK_REALTIME, &sev, id) < 0)
	{
		op_lib_log("timer_create: %s", strerror(errno));
		op_free(event->comm_ptr);
		event->comm_ptr = NULL;
		return 0;
	}

	memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_sec = when;
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
op_ports_unsched_event(struct ev_entry *event)
{
	if (__builtin_expect(event->comm_ptr == NULL, 0))
		return;
	timer_delete(*((timer_t *)event->comm_ptr));
	op_free(event->comm_ptr);
	event->comm_ptr = NULL;
}

#else /* ports not supported */

int  op_ports_supports_event(void) { errno = ENOSYS; return 0; }
void op_ports_init_event(void)     { return; }

int
op_ports_sched_event(struct ev_entry *event __attribute__((unused)),
                     int when __attribute__((unused)))
{ errno = ENOSYS; return -1; }

void
op_ports_unsched_event(struct ev_entry *event __attribute__((unused)))
{ return; }

int  op_init_netio_ports(void) { return ENOSYS; }

void
op_setselect_ports(op_fde_t *F __attribute__((unused)),
                   unsigned int type __attribute__((unused)),
                   PF *handler __attribute__((unused)),
                   void *client_data __attribute__((unused)))
{ errno = ENOSYS; }

int
op_select_ports(long delay __attribute__((unused)))
{ errno = ENOSYS; return -1; }

int
op_setup_fd_ports(op_fde_t *F __attribute__((unused)))
{ errno = ENOSYS; return -1; }

#endif /* HAVE_PORT_CREATE */
