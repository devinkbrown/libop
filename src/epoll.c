/*
 *  libop: ophion support library.
 *  epoll.c: Linux epoll(2) I/O backend.
 *
 *  Design: EPOLLONESHOT
 *  --------------------
 *  Every fd registered with epoll uses EPOLLONESHOT so that each event fires
 *  exactly once.  After a CQE fires the fd is auto-silenced by the kernel;
 *  ep_rearm() re-arms it with EPOLL_CTL_MOD | EPOLLONESHOT after dispatch.
 *  This matches the one-shot handler model shared by all libop backends and
 *  eliminates the "must drain to EOF" contract that EPOLLET imposes on every
 *  handler implementation.
 *
 *  Thread safety
 *  -------------
 *  Worker threads may call op_setselect_epoll() concurrently with the I/O
 *  thread running op_select_epoll().  F->pflags_lock (a per-fd spinlock)
 *  guards F->pflags and the handler pointer fields.
 *
 *  epoll_ctl(2) is called while pflags_lock is held.  This keeps F->pflags
 *  and the kernel's epoll registration in sync atomically: there is never a
 *  window between updating the in-process flags and the kernel flags.
 *  epoll_ctl is a non-blocking syscall; holding a spinlock across it is safe.
 *
 *  Lock order: F->pflags_lock only (never nested with another lock).
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2002 Aaron Sethman <androsyn@ratbox.org>
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

#define _GNU_SOURCE 1

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <event-int.h>

#if defined(HAVE_EPOLL_CTL)
#define USING_EPOLL
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <sys/epoll.h>

#if defined(HAVE_SIGNALFD)
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/uio.h>
#define EPOLL_SCHED_EVENT 1
#endif

#if defined(HAVE_TIMERFD_CREATE)
#include <sys/timerfd.h>
#endif

/*
 * Maximum events returned per epoll_wait() call.  Scaled to the process fd
 * table at init time, capped here so the buffer stays L2-friendly.
 * 4096 * sizeof(struct epoll_event) = 48 KiB on 64-bit — fits easily.
 */
#define EPOLL_EVENTS_MAX  4096

#define RTSIGNAL SIGRTMIN

struct epoll_info
{
	int ep;
	struct epoll_event *pfd;
	int pfd_size;
};

static struct epoll_info *ep_info;
static int can_do_event;
static int can_do_timerfd;

/* ---- I/O poll thread state ----------------------------------------------- */

/*
 * ep_ring — lock-free SPSC ring of epoll_event values.
 *
 * The poll thread is the sole producer (writes head, reads tail).
 * The main thread is the sole consumer (writes tail, reads head).
 *
 * Both cursors are uint32_t; natural wrap-around at 2^32 is correct when
 * ring capacity is a power of two: (head - tail) gives the live count even
 * after wrap because the arithmetic is mod 2^32.
 *
 * Cache-line padding (64 B) separates head from tail to prevent false sharing.
 */
#define EP_RING_CAP  4096u  /* must be power of two; 4096×12B = 48 KiB */

typedef struct
{
	_Atomic(uint32_t)   head;           /* producer cursor (poll thread)   */
	char                _pad0[60];
	_Atomic(uint32_t)   tail;           /* consumer cursor (main thread)   */
	char                _pad1[60];
	struct epoll_event  slots[EP_RING_CAP];
} ep_ring_t;

/*
 * ep_notify_fd — eventfd written by the poll thread to wake the main thread.
 * Main thread reads it (EFD_SEMAPHORE not used; we drain until empty).
 */
static int               ep_notify_fd     = -1;

/* Poll thread pthread handle and its private event buffer. */
static pthread_t         ep_poll_tid;
static struct epoll_event *ep_thread_pfd  = NULL;  /* same size as ep_info->pfd */
static volatile int      ep_thread_stop   = 0;     /* set to 1 to request exit  */
static int               ep_thread_active = 0;     /* 1 once successfully started */

/* The ring itself — statically allocated, 64-byte aligned. */
static ep_ring_t         ep_ring __attribute__((aligned(64)));

/* ---- ring helpers (inline, no branching in hot path) --------------------- */

static inline bool
ep_ring_push(ep_ring_t *r, const struct epoll_event *ev)
{
	uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
	if (h - t >= EP_RING_CAP)
		return false;   /* full — caller retries next epoll_wait cycle */
	r->slots[h & (EP_RING_CAP - 1)] = *ev;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);
	return true;
}

static inline bool
ep_ring_pop(ep_ring_t *r, struct epoll_event *ev)
{
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
	if (t == h)
		return false;   /* empty */
	*ev = r->slots[t & (EP_RING_CAP - 1)];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);
	return true;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * ep_ctl — call epoll_ctl with EEXIST/ENOENT recovery.
 *
 * Must be called while F->pflags_lock is held so that F->pflags and the
 * kernel registration remain in sync.  Returns 0 on success, -1 on a
 * persistent error (already logged).
 */
static inline __attribute__((always_inline)) int
ep_ctl(int op, op_fde_t *F, struct epoll_event *ev)
{
	if (__builtin_expect(epoll_ctl(ep_info->ep, op, F->fd, ev) == 0, 1))
		return 0;

	switch (op)
	{
	case EPOLL_CTL_ADD:
		if (errno == EEXIST)
		{
			/* Already registered — retry as MOD. */
			if (epoll_ctl(ep_info->ep, EPOLL_CTL_MOD, F->fd, ev) == 0)
				return 0;
			op_lib_log("ep_ctl(): MOD retry after EEXIST failed fd=%d: %s",
			           F->fd, strerror(errno));
			return -1;
		}
		break;

	case EPOLL_CTL_MOD:
		if (errno == ENOENT)
		{
			/* Fell out of epoll (e.g. auto-removed after EPOLLONESHOT fired
			 * and fd was DELed by a concurrent op_setselect call) — re-add. */
			if (epoll_ctl(ep_info->ep, EPOLL_CTL_ADD, F->fd, ev) == 0)
				return 0;
			op_lib_log("ep_ctl(): ADD retry after ENOENT failed fd=%d: %s",
			           F->fd, strerror(errno));
			return -1;
		}
		break;

	case EPOLL_CTL_DEL:
		if (errno == ENOENT)
			return 0;  /* Already removed — benign. */
		break;
	}

	op_lib_log("ep_ctl(): op=%d failed fd=%d: %s", op, F->fd, strerror(errno));
	return -1;
}

/*
 * ep_build_arm_event — fill *ev for an ADD or MOD call.
 * EPOLLONESHOT ensures the fd is auto-silenced after one event.
 * EPOLLRDHUP is added alongside EPOLLIN to detect peer-close early.
 */
static inline __attribute__((always_inline)) void
ep_build_arm_event(struct epoll_event *ev, op_fde_t *F, int flags)
{
	ev->data.ptr = F;
	ev->events   = (uint32_t)flags | EPOLLONESHOT;
#ifdef EPOLLRDHUP
	if (flags & EPOLLIN)
		ev->events |= EPOLLRDHUP;
#endif
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

__attribute__((cold))
int
op_init_netio_epoll(void)
{
	int dtsize;

	can_do_event   = 0;
	can_do_timerfd = 0;

	ep_info = op_malloc(sizeof(struct epoll_info));

	/*
	 * epoll_create1(EPOLL_CLOEXEC) sets O_CLOEXEC atomically (Linux ≥2.6.27).
	 * Fall back to epoll_create() + fcntl() on older kernels.
	 */
#ifdef EPOLL_CLOEXEC
	ep_info->ep = epoll_create1(EPOLL_CLOEXEC);
	if (__builtin_expect(ep_info->ep < 0, 0))
	{
		ep_info->ep = epoll_create(1024);
		if (ep_info->ep >= 0)
			fcntl(ep_info->ep, F_SETFD, FD_CLOEXEC);
	}
#else
	ep_info->ep = epoll_create(1024);
	if (ep_info->ep >= 0)
		fcntl(ep_info->ep, F_SETFD, FD_CLOEXEC);
#endif

	if (__builtin_expect(ep_info->ep < 0, 0))
		return -1;

	op_open(ep_info->ep, OP_FD_UNKNOWN, "epoll file descriptor");

	/* Scale the event buffer to the server's fd table size, capped at
	 * EPOLL_EVENTS_MAX to keep heap usage bounded. */
	dtsize            = getdtablesize();
	ep_info->pfd_size = (dtsize < EPOLL_EVENTS_MAX) ? dtsize : EPOLL_EVENTS_MAX;
	ep_info->pfd      = op_malloc(sizeof(struct epoll_event)
	                              * (size_t)ep_info->pfd_size);
	return 0;
}

__attribute__((cold))
int
op_setup_fd_epoll(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_epoll
 *
 * Register or modify epoll interest for F.  EPOLLONESHOT is added to every
 * registration so that each event fires exactly once; handlers must call
 * op_setselect again to receive further events.
 *
 * Both F->pflags and the kernel registration are updated inside
 * F->pflags_lock so they are always consistent — no reconcile pass needed.
 */
__attribute__((hot))
void
op_setselect_epoll(op_fde_t *restrict F, unsigned int type,
                   PF *handler, void *client_data)
{
	int old_flags, new_flags, op;
	struct epoll_event ev;

	slop_assert(IsFDOpen(F));

	pthread_spin_lock(&F->pflags_lock);

	old_flags = F->pflags;

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
		if (handler) F->pflags |=  EPOLLIN;
		else         F->pflags &= ~EPOLLIN;
	}

	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
		if (handler) F->pflags |=  EPOLLOUT;
		else         F->pflags &= ~EPOLLOUT;
	}

	new_flags = F->pflags;

	if (old_flags == 0 && new_flags == 0)
	{
		pthread_spin_unlock(&F->pflags_lock);
		return;
	}
	else if (new_flags == 0)
		op = EPOLL_CTL_DEL;
	else if (old_flags == 0)
		op = EPOLL_CTL_ADD;
	else if (new_flags != old_flags)
		op = EPOLL_CTL_MOD;
	else
	{
		/* Interest unchanged — nothing to do. */
		pthread_spin_unlock(&F->pflags_lock);
		return;
	}

	ep_build_arm_event(&ev, F, new_flags);
	ep_ctl(op, F, &ev);  /* called under lock — pflags stays in sync */

	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Dispatch helpers
 * ---------------------------------------------------------------------- */

/*
 * ep_dispatch — capture + clear one handler under pflags_lock, call outside.
 *
 * The corresponding pflags bit is cleared together with the handler pointer
 * so that F->pflags reflects actual state at all times (any concurrent
 * op_setselect call will see the cleared bit and compute the correct epoll
 * operation).
 *
 * Returns 1 if F is still open after the handler, 0 if it was closed.
 */
static inline __attribute__((always_inline)) int
ep_dispatch(op_fde_t *F, int is_read)
{
	PF   *hdl;
	void *data;

	pthread_spin_lock(&F->pflags_lock);
	if (is_read)
	{
		hdl  = F->read_handler;  data = F->read_data;
		F->read_handler = NULL;  F->read_data = NULL;
		F->pflags &= ~EPOLLIN;   /* keep pflags in sync with cleared handler */
	}
	else
	{
		hdl  = F->write_handler; data = F->write_data;
		F->write_handler = NULL; F->write_data = NULL;
		F->pflags &= ~EPOLLOUT;
	}
	pthread_spin_unlock(&F->pflags_lock);

	if (hdl != NULL)
		hdl(F, data);

	return IsFDOpen(F);
}

/*
 * ep_rearm — re-arm the fd after EPOLLONESHOT silenced it.
 *
 * Called after all handlers for an event have been dispatched.  Reads the
 * current handler state under pflags_lock and calls EPOLL_CTL_MOD to
 * re-enable interest, or EPOLL_CTL_DEL if all interest has been removed.
 *
 * Because epoll_ctl is called under the lock, no separate reconcile pass
 * is needed: if a worker thread called op_setselect_epoll between our
 * dispatch and this re-arm, its epoll_ctl already updated the kernel and
 * F->pflags reflects the new state — our new_flags == F->pflags short-
 * circuit skips the redundant call.
 */
static void
ep_rearm(op_fde_t *F)
{
	int new_flags, op;
	struct epoll_event ev;

	pthread_spin_lock(&F->pflags_lock);

	new_flags = 0;
	if (F->read_handler  != NULL) new_flags |= EPOLLIN;
	if (F->write_handler != NULL) new_flags |= EPOLLOUT;

	if (new_flags == F->pflags)
	{
		/* Consistent — a worker already issued the matching epoll_ctl. */
		pthread_spin_unlock(&F->pflags_lock);
		return;
	}

	op        = (new_flags == 0) ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
	F->pflags = new_flags;

	ep_build_arm_event(&ev, F, new_flags);
	ep_ctl(op, F, &ev);

	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

/*
 * ep_dispatch_event — dispatch a single epoll_event (shared by inline and
 * threaded paths).
 */
static inline __attribute__((always_inline)) void
ep_dispatch_event(const struct epoll_event *e)
{
	uint32_t  evs = e->events;
	op_fde_t *F   = (op_fde_t *)e->data.ptr;

	if (__builtin_expect(F == NULL || !IsFDOpen(F), 0))
		return;

	if (evs & (EPOLLIN | EPOLLHUP | EPOLLERR
#ifdef EPOLLRDHUP
	           | EPOLLRDHUP
#endif
	           ))
	{
		if (!ep_dispatch(F, 1 /* read */))
			return;
	}

	if (evs & (EPOLLOUT | EPOLLHUP | EPOLLERR))
	{
		if (!ep_dispatch(F, 0 /* write */))
			return;
	}

	ep_rearm(F);
}

/*
 * ep_poll_thread_fn — the poll thread body.
 *
 * Loops calling epoll_wait() with a short ceiling (100 ms) so that the
 * ep_thread_stop flag is checked regularly during shutdown.  On each batch
 * of ready events: pushes them into the SPSC ring, then writes to
 * ep_notify_fd to wake the main thread.
 *
 * Overflow (ring full): events that don't fit are dropped.  They will
 * re-fire on the next epoll_wait cycle because EPOLLONESHOT has not fired
 * for those fds yet (they haven't been dispatched by the main thread).
 * Persistent high-load conditions should be addressed by increasing
 * EP_RING_CAP or raising server limits.
 */
static void *
ep_poll_thread_fn(void *arg)
{
	(void)arg;
	int pfd_size = ep_info->pfd_size;
	uint64_t one = 1;

	while (!ep_thread_stop)
	{
		int n = epoll_wait(ep_info->ep, ep_thread_pfd, pfd_size, 100 /* ms */);
		if (n <= 0)
			continue;

		bool any = false;
		for (int i = 0; i < n; i++)
		{
			if (ep_ring_push(&ep_ring, &ep_thread_pfd[i]))
				any = true;
			/* else ring full — event dropped; will re-fire */
		}

		/* Signal the main thread once per batch. */
		if (any)
		{
			ssize_t rc;
			do {
				rc = write(ep_notify_fd, &one, sizeof one);
			} while (rc < 0 && errno == EINTR);
		}
	}

	return NULL;
}

/*
 * op_select_epoll — threaded mode variant.
 *
 * Blocks on the notification eventfd (not epoll_wait) for up to |delay| ms,
 * then drains the SPSC ring and dispatches all pending events.
 *
 * The main thread never calls epoll_wait(); the poll thread owns it.
 */
static int
ep_select_threaded(long delay)
{
	int ms = (delay < 0) ? -1
	       : (delay > (long)INT_MAX ? INT_MAX : (int)delay);

	/* Wait for the poll thread's notification or timeout. */
	struct pollfd pf = { .fd = ep_notify_fd, .events = POLLIN };
	poll(&pf, 1, ms);

	/* Drain the notification counter so we don't immediately re-wake. */
	uint64_t count;
	ssize_t  r;
	do {
		r = read(ep_notify_fd, &count, sizeof count);
	} while (r < 0 && errno == EINTR);
	/* Ignore EAGAIN (nothing to drain) — normal when poll() timed out. */

	op_set_time();

	/* Dispatch all events currently in the ring. */
	struct epoll_event ev;
	while (ep_ring_pop(&ep_ring, &ev))
		ep_dispatch_event(&ev);

	return OP_OK;
}

/*
 * op_select_epoll
 *
 * Wait for I/O events and dispatch handlers.  EPOLLONESHOT means the fd is
 * silenced after each batch; ep_rearm() re-arms it for any remaining
 * interest after dispatch.
 *
 * When the poll thread is active (ep_thread_active == 1) this function
 * delegates to ep_select_threaded(); otherwise it runs the classic inline
 * epoll_wait() path.
 */
__attribute__((hot))
int
op_select_epoll(long delay)
{
	if (__builtin_expect(ep_thread_active, 0))
		return ep_select_threaded(delay);

	int num, o_errno;
	int ms = (delay < 0) ? -1
	       : (delay > (long)INT_MAX ? INT_MAX : (int)delay);

	num = epoll_wait(ep_info->ep, ep_info->pfd, ep_info->pfd_size, ms);

	o_errno = errno;
	op_set_time();
	errno = o_errno;

	if (__builtin_expect(num < 0 && !op_ignore_errno(o_errno), 0))
		return OP_ERROR;
	if (num <= 0)
		return OP_OK;

	for (int i = 0; i < num; i++)
	{
		/* Prefetch next FDE to overlap the cache miss with handler work. */
		if (__builtin_expect(i + 1 < num, 1))
			__builtin_prefetch(ep_info->pfd[i + 1].data.ptr, 0, 1);

		ep_dispatch_event(&ep_info->pfd[i]);
	}

	return OP_OK;
}

/* ---- poll thread lifecycle ----------------------------------------------- */

/*
 * op_epoll_start_pollthread — start the dedicated I/O poll thread.
 *
 * Creates the notification eventfd, allocates the poll thread's private
 * event buffer (same capacity as the main thread's buffer), then spawns
 * the thread.
 *
 * Safe to call only once; returns false if already started or on error.
 */
bool
op_epoll_start_pollthread(void)
{
	if (ep_thread_active)
		return true;   /* idempotent */

	/* Create the semaphore-style eventfd for poll → main notification. */
	ep_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ep_notify_fd < 0)
	{
		op_lib_log("op_epoll_start_pollthread: eventfd: %s", strerror(errno));
		return false;
	}

	/* Allocate the poll thread's private event buffer. */
	ep_thread_pfd = op_malloc(sizeof(struct epoll_event)
	                          * (size_t)ep_info->pfd_size);

	/* Initialise the ring. */
	atomic_init(&ep_ring.head, 0);
	atomic_init(&ep_ring.tail, 0);

	ep_thread_stop = 0;

	int rc = pthread_create(&ep_poll_tid, NULL, ep_poll_thread_fn, NULL);
	if (rc != 0)
	{
		op_lib_log("op_epoll_start_pollthread: pthread_create: %s",
		           strerror(rc));
		op_free(ep_thread_pfd);
		ep_thread_pfd = NULL;
		close(ep_notify_fd);
		ep_notify_fd = -1;
		return false;
	}

	/* Mark active *after* the thread is running. */
	ep_thread_active = 1;
	op_lib_log("I/O poll thread started (epoll backend)");
	return true;
}

/*
 * op_epoll_stop_pollthread — stop the I/O poll thread.
 *
 * Signals the thread to exit, joins it, and reverts op_select_epoll() to
 * inline mode.  Must not be called from within a handler or timer callback.
 */
void
op_epoll_stop_pollthread(void)
{
	if (!ep_thread_active)
		return;

	ep_thread_stop   = 1;
	ep_thread_active = 0;   /* revert to inline mode immediately */

	pthread_join(ep_poll_tid, NULL);

	op_free(ep_thread_pfd);
	ep_thread_pfd = NULL;

	if (ep_notify_fd >= 0)
	{
		close(ep_notify_fd);
		ep_notify_fd = -1;
	}

	op_lib_log("I/O poll thread stopped");
}

/* -------------------------------------------------------------------------
 * Timer / event scheduling (signalfd + timerfd backends)
 * ---------------------------------------------------------------------- */

#ifdef EPOLL_SCHED_EVENT

__attribute__((cold))
int
op_epoll_supports_event(void)
{
	struct stat st;
	int fd;

	if (can_do_event == 1)
		return 1;
	if (can_do_event == -1)
		return 0;

	/* OpenVZ has a broken timerfd implementation. */
	if (stat("/proc/user_beancounters", &st) == 0)
	{
		can_do_event = -1;
		return 0;
	}

#ifdef HAVE_TIMERFD_CREATE
	fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (fd >= 0)
	{
		close(fd);
		can_do_event   = 1;
		can_do_timerfd = 1;
		return 1;
	}
	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd >= 0)
	{
		close(fd);
		can_do_event   = 1;
		can_do_timerfd = 1;
		return 1;
	}
#endif

	/* Fall back to POSIX timer + signalfd. */
	{
		timer_t timer;
		struct sigevent sev;
		sigset_t set;

		sev.sigev_signo  = SIGVTALRM;
		sev.sigev_notify = SIGEV_SIGNAL;
		if (timer_create(CLOCK_REALTIME, &sev, &timer) != 0)
		{
			can_do_event = -1;
			return 0;
		}
		timer_delete(timer);

		sigemptyset(&set);
		fd = signalfd(-1, &set, 0);
		if (fd < 0)
		{
			can_do_event = -1;
			return 0;
		}
		close(fd);
		can_do_event = 1;
		return 1;
	}
}

/* Workaround for glibc signalfd_siginfo layout bug on 32-bit systems. */
struct our_signalfd_siginfo
{
	uint32_t signo;
	int32_t  err;
	int32_t  code;
	uint32_t pid;
	uint32_t uid;
	int32_t  fd;
	uint32_t tid;
	uint32_t band;
	uint32_t overrun;
	uint32_t trapno;
	int32_t  status;
	int32_t  svint;
	uint64_t svptr;
	uint64_t utime;
	uint64_t stime;
	uint64_t addr;
	uint8_t  pad[48];
};

/* Number of signalfd_siginfo records to drain per readv() call. */
#define SIGFDIOV_COUNT 16

/*
 * signalfd_handler
 *
 * Read pending POSIX timer signals from the signalfd.  Each record carries
 * the ev_entry pointer in svptr; dispatch it via op_run_one_event().
 *
 * Buffers are stack-allocated (not static) so that concurrent calls from
 * separate I/O threads are safe.
 */
static __attribute__((hot)) void
signalfd_handler(op_fde_t *restrict F, void *data __attribute__((unused)))
{
	struct our_signalfd_siginfo fdsig[SIGFDIOV_COUNT];
	struct iovec iov[SIGFDIOV_COUNT];
	ssize_t ret;
	size_t x;

	for (x = 0; x < SIGFDIOV_COUNT; x++)
	{
		iov[x].iov_base = &fdsig[x];
		iov[x].iov_len  = sizeof(struct our_signalfd_siginfo);
	}

	for (;;)
	{
		ret = readv(op_get_fd(F), iov, SIGFDIOV_COUNT);

		if (ret == 0 || (ret < 0 && !op_ignore_errno(errno)))
		{
			op_close(F);
			/* Re-initialise signalfd.  op_epoll_init_event() arms the new fd
			 * via op_setselect (does NOT call this handler directly), so this
			 * call is not recursive. */
			op_epoll_init_event();
			return;
		}

		if (ret < 0)
		{
			/* EAGAIN / EINTR — nothing left to read; re-arm. */
			op_setselect(F, OP_SELECT_READ, signalfd_handler, NULL);
			return;
		}

		/* Process only complete records; discard any trailing partial bytes. */
		size_t count = (size_t)ret / sizeof(struct our_signalfd_siginfo);
		for (x = 0; x < count; x++)
		{
			struct ev_entry *ev;
#if __WORDSIZE == 32 && defined(__sparc__)
			uint32_t *q = (uint32_t *)&fdsig[x].svptr;
			ev = (struct ev_entry *)q[0];
#else
			ev = (struct ev_entry *)(uintptr_t)(fdsig[x].svptr);
#endif
			if (__builtin_expect(ev == NULL, 0))
				continue;
			op_run_one_event(ev);
		}
	}
}

__attribute__((cold))
void
op_epoll_init_event(void)
{
	op_epoll_supports_event();

	if (!can_do_timerfd)
	{
		sigset_t ss;
		op_fde_t *F;
		int sfd;

		sigemptyset(&ss);
		sigaddset(&ss, RTSIGNAL);
		sigprocmask(SIG_BLOCK, &ss, NULL);

		sigemptyset(&ss);
		sigaddset(&ss, RTSIGNAL);
		sfd = signalfd(-1, &ss, SFD_CLOEXEC | SFD_NONBLOCK);
		if (sfd < 0)
			sfd = signalfd(-1, &ss, 0);
		if (__builtin_expect(sfd == -1, 0))
		{
			can_do_event = -1;
			return;
		}

		F = op_open(sfd, OP_FD_UNKNOWN, "signalfd");
		op_set_nb(F);
		/* Arm via op_setselect; the handler will be called when signals arrive.
		 * No immediate call here to avoid re-entrancy if the fd fails on
		 * first read. */
		op_setselect(F, OP_SELECT_READ, signalfd_handler, NULL);
	}
}

static __attribute__((cold)) int
op_epoll_sched_event_signalfd(struct ev_entry *restrict event, int when)
{
	timer_t *id;
	struct sigevent sev;
	struct itimerspec ts;

	event->comm_ptr = op_malloc(sizeof(timer_t));
	id = event->comm_ptr;

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify          = SIGEV_SIGNAL;
	sev.sigev_signo           = RTSIGNAL;
	sev.sigev_value.sival_ptr = event;

	if (__builtin_expect(timer_create(CLOCK_REALTIME, &sev, id) < 0, 0))
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

	if (__builtin_expect(timer_settime(*id, 0, &ts, NULL) < 0, 0))
	{
		op_lib_log("timer_settime: %s", strerror(errno));
		timer_delete(*id);
		op_free(event->comm_ptr);
		event->comm_ptr = NULL;
		return 0;
	}
	return 1;
}

#ifdef HAVE_TIMERFD_CREATE

/*
 * op_read_timerfd
 *
 * Called when a timerfd fires.  Reads the expiry count to reset the fd's
 * readability, then dispatches the associated event and re-arms the fd.
 * With EPOLLONESHOT the fd is silenced after each fire; op_setselect()
 * re-arms it.
 */
static __attribute__((hot)) void
op_read_timerfd(op_fde_t *restrict F, void *data)
{
	struct ev_entry *event = (struct ev_entry *)data;
	uint64_t count;
	ssize_t retlen;

	if (__builtin_expect(event == NULL, 0))
	{
		op_close(F);
		return;
	}

	retlen = op_read(F, &count, sizeof(count));

	if (retlen == 0 || (retlen < 0 && !op_ignore_errno(errno)))
	{
		event->comm_ptr = NULL;
		if (errno == EBADF)
			F->fd = -1;
		op_close(F);
		op_run_one_event(event);
		return;
	}

	if (event->frequency != 0)
	{
		/* Recurring: re-arm so the timerfd fires again next interval. */
		op_setselect(F, OP_SELECT_READ, op_read_timerfd, event);
	}
	else
	{
		/* One-shot: close the timerfd and detach it from the event BEFORE
		 * running the callback.  The callback (e.g. dot_connect) may call
		 * op_event_delete() which also tries to close the timerfd via
		 * op_io_unsched_event(); by clearing comm_ptr first we guarantee
		 * only one close path fires and eliminate the window where a
		 * stale fde entry can collide with a newly created timerfd that
		 * reuses the same kernel FD number. */
		event->comm_ptr = NULL;
		op_close(F);
	}
	op_run_one_event(event);
}

static __attribute__((cold)) int
op_epoll_sched_event_timerfd(struct ev_entry *restrict event, int when)
{
	struct itimerspec ts;
	char buf[FD_DESC_SZ + 8];  /* stack-allocated; safe for concurrent calls */
	int fd;
	op_fde_t *F;

#if defined(TFD_NONBLOCK) && defined(TFD_CLOEXEC)
	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0)
		fd = timerfd_create(CLOCK_REALTIME, 0);
#else
	fd = timerfd_create(CLOCK_REALTIME, 0);
#endif

	if (__builtin_expect(fd < 0, 0))
	{
		op_lib_log("timerfd_create: %s", strerror(errno));
		return 0;
	}

	memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_sec = when;
	if (event->frequency != 0)
		ts.it_interval = ts.it_value;

	if (__builtin_expect(timerfd_settime(fd, 0, &ts, NULL) < 0, 0))
	{
		op_lib_log("timerfd_settime: %s", strerror(errno));
		close(fd);
		return 0;
	}

	snprintf(buf, sizeof(buf), "timerfd: %s", event->name);
	F = op_open(fd, OP_FD_UNKNOWN, buf);
	if (__builtin_expect(F == NULL, 0))
	{
		/* Recovery: if a stale fde entry blocks the open, force-close it
		 * and retry once.  This prevents a leaked timerfd fde from causing
		 * a permanent spin loop (timerfd_create returns the same FD, op_open
		 * rejects it, close frees it, repeat). */
		op_fde_t *stale = op_find_fd(fd);
		if (stale != NULL && IsFDOpen(stale))
		{
			op_lib_log("op_epoll_sched_event_timerfd: recycling stale "
			           "fde %d (%s) for %s", fd,
			           stale->desc ? stale->desc : "?", event->name);
			op_close(stale);
			F = op_open(fd, OP_FD_UNKNOWN, buf);
		}
		if (__builtin_expect(F == NULL, 0))
		{
			op_lib_log("op_epoll_sched_event_timerfd: op_open failed "
			           "for %s", event->name);
			close(fd);
			return 0;
		}
	}

	op_set_nb(F);
	event->comm_ptr = F;
	op_setselect(F, OP_SELECT_READ, op_read_timerfd, event);
	return 1;
}

#endif /* HAVE_TIMERFD_CREATE */

__attribute__((cold))
int
op_epoll_sched_event(struct ev_entry *restrict event, int when)
{
#ifdef HAVE_TIMERFD_CREATE
	if (can_do_timerfd)
		return op_epoll_sched_event_timerfd(event, when);
#endif
	return op_epoll_sched_event_signalfd(event, when);
}

__attribute__((cold))
void
op_epoll_unsched_event(struct ev_entry *restrict event)
{
#ifdef HAVE_TIMERFD_CREATE
	if (can_do_timerfd)
	{
		if (__builtin_expect(event->comm_ptr != NULL, 1))
		{
			op_close((op_fde_t *)event->comm_ptr);
			event->comm_ptr = NULL;
		}
		return;
	}
#endif
	if (__builtin_expect(event->comm_ptr == NULL, 0))
		return;
	timer_delete(*((timer_t *)event->comm_ptr));
	op_free(event->comm_ptr);
	event->comm_ptr = NULL;
}

#endif /* EPOLL_SCHED_EVENT */

#else /* epoll not supported */

__attribute__((cold)) int
op_init_netio_epoll(void) { return -1; }

__attribute__((cold)) void
op_setselect_epoll(op_fde_t *F __attribute__((unused)),
                   unsigned int type __attribute__((unused)),
                   PF *handler __attribute__((unused)),
                   void *client_data __attribute__((unused)))
{ errno = ENOSYS; }

__attribute__((cold)) int
op_select_epoll(long delay __attribute__((unused)))
{ errno = ENOSYS; return -1; }

__attribute__((cold)) int
op_setup_fd_epoll(op_fde_t *F __attribute__((unused)))
{ errno = ENOSYS; return -1; }

__attribute__((cold)) bool
op_epoll_start_pollthread(void) { errno = ENOSYS; return false; }

__attribute__((cold)) void
op_epoll_stop_pollthread(void) { return; }

#endif /* HAVE_EPOLL_CTL */

/* -------------------------------------------------------------------------
 * Stubs for when epoll or EPOLL_SCHED_EVENT is absent
 * ---------------------------------------------------------------------- */

#if !defined(USING_EPOLL) || !defined(EPOLL_SCHED_EVENT)

__attribute__((cold)) void
op_epoll_init_event(void) { return; }

__attribute__((cold)) int
op_epoll_sched_event(struct ev_entry *event __attribute__((unused)),
                     int when __attribute__((unused)))
{ errno = ENOSYS; return -1; }

__attribute__((cold)) void
op_epoll_unsched_event(struct ev_entry *event __attribute__((unused)))
{ return; }

__attribute__((cold)) int
op_epoll_supports_event(void)
{ errno = ENOSYS; return 0; }

#endif /* !USING_EPOLL || !EPOLL_SCHED_EVENT */
