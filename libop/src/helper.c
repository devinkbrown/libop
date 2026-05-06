/*
 *  libop: ophion support library.
 *  helper.c: ircd helper process / in-process thread management.
 *
 *  Thread safety
 *  -------------
 *  op_helper_start() modifies the process environment (IFD/OFD/MAXFD) to
 *  pass fd numbers to the child.  setenv(3) is not thread-safe: concurrent
 *  calls from different threads corrupt the environ list.  spawn_env_lock
 *  serialises the setenv → spawn → unsetenv sequence; all callers of
 *  op_helper_start() that run from worker threads are safe.
 *
 *  Individual op_helper instances are single-threaded: their sendq/recvq
 *  linebuf queues are driven by the event-loop thread only.  If a worker
 *  thread needs to write to a helper it must marshal through the event loop
 *  (e.g. via an eventfd or a thread-pool callback).
 *
 *  Restart guard
 *  -------------
 *  Both the read and write callbacks detect I/O errors and call
 *  op_helper_restart().  op_helper_restart() sets helper->closing = true on
 *  first entry so that the second callback (if both fire in the same event
 *  loop turn) is a no-op.  This prevents the error_cb from being called
 *  twice and eliminates the resulting use-after-free when error_cb frees
 *  the helper.
 *
 *  Copyright (C) 2006 Aaron Sethman <androsyn@ratbox.org>
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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE   /* pthread_setname_np */
#endif

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

struct _op_helper
{
	buf_head_t    sendq;
	buf_head_t    recvq;
	op_fde_t     *ifd;
	op_fde_t     *ofd;
	pid_t         pid;
	int           fork_count;
	op_helper_cb *read_cb;
	op_helper_cb *error_cb;
	bool          is_thread; /* true = socketpair+pthread, no process to kill   */
	bool          closing;   /* true = restart/shutdown in progress; ignore errors */
};

/* Serialises setenv → spawn → unsetenv in op_helper_start(). */
static pthread_mutex_t spawn_env_lock = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * helper_close_env — remove IFD/OFD/MAXFD from the environment.
 * Called after op_spawn_process() regardless of success/failure so stale
 * values do not leak into future spawns.  No-op on Windows.
 */
static void
helper_clear_env(void)
{
#ifndef _WIN32
	unsetenv("IFD");
	unsetenv("OFD");
	unsetenv("MAXFD");
#endif
}

/* -------------------------------------------------------------------------
 * Child-side initialisation
 * ---------------------------------------------------------------------- */

/*
 * op_helper_child — initialise an exec'd helper process.
 *
 * Called by the child binary on startup.  Reads IFD, OFD, MAXFD from the
 * environment (set by the parent before spawning), closes all inherited fds
 * except ifd and ofd, redirects stdin/stdout/stderr to /dev/null, then
 * initialises the libop event loop.
 *
 * op_lib_init() is called BEFORE op_malloc() so the allocator subsystem is
 * ready before any heap allocation is made.
 */
op_helper *
op_helper_child(op_helper_cb *read_cb, op_helper_cb *error_cb, log_cb *ilog,
                restart_cb *irestart, die_cb *idie, size_t lb_heap_size,
                size_t dh_size, size_t fd_heap_size)
{
	op_helper *helper;
	int ifd, ofd, maxfd;
	const char *tifd   = getenv("IFD");
	const char *tofd   = getenv("OFD");
	const char *tmaxfd = getenv("MAXFD");

	if (tifd == NULL || tofd == NULL || tmaxfd == NULL)
		return NULL;

	char *end;
	ifd   = (int)strtol(tifd,   &end, 10);
	if (*end || ifd < 0)   return NULL;
	ofd   = (int)strtol(tofd,   &end, 10);
	if (*end || ofd < 0)   return NULL;
	maxfd = (int)strtol(tmaxfd, &end, 10);
	if (*end || maxfd <= 0) return NULL;

	/* Sanity: the fds the child is supposed to use must be in range. */
	if (ifd >= maxfd || ofd >= maxfd)
		return NULL;

#ifndef _WIN32
	/* Close every inherited fd except ifd and ofd.  All libop sockets in
	 * the parent are opened with O_CLOEXEC; this loop handles any fds that
	 * were not opened through libop (e.g. pre-exec fds, stdio). */
	for (int x = 0; x < maxfd; x++)
	{
		if (x != ifd && x != ofd)
			close(x);
	}

	/* Redirect stdin/stdout/stderr to /dev/null.  Open first so the fd
	 * lands as low as possible (ideally 0 if that slot was just closed). */
	int devnull = open("/dev/null", O_RDWR);
	if (devnull < 0)
		return NULL;  /* fatal: can't silence stdio in helper process */

	if (ifd != 0 && ofd != 0) dup2(devnull, 0);
	if (ifd != 1 && ofd != 1) dup2(devnull, 1);
	if (ifd != 2 && ofd != 2) dup2(devnull, 2);
	if (devnull > 2)
		close(devnull);
#endif /* !_WIN32 */

	/*
	 * Initialise the library BEFORE any op_malloc() call.  The custom
	 * allocator (balloc / arena) may not be usable before op_lib_init()
	 * runs op_init_bh() and op_fdlist_init().
	 */
	op_lib_init(ilog, irestart, idie, 0, maxfd, dh_size, fd_heap_size);
	op_linebuf_init(lb_heap_size);

	helper = op_malloc(sizeof(op_helper));

	op_linebuf_newbuf(&helper->sendq);
	op_linebuf_newbuf(&helper->recvq);

	helper->ifd        = op_open(ifd, OP_FD_PIPE, "helper incoming");
	helper->ofd        = op_open(ofd, OP_FD_PIPE, "helper outgoing");
	op_set_nb(helper->ifd);
	op_set_nb(helper->ofd);

	helper->read_cb    = read_cb;
	helper->error_cb   = error_cb;
	helper->pid        = -1;        /* child has no child of its own */
	helper->fork_count = 0;
	helper->is_thread  = false;
	helper->closing    = false;

	return helper;
}

/* -------------------------------------------------------------------------
 * Parent-side: spawn an external helper process
 * ---------------------------------------------------------------------- */

/*
 * op_helper_start — fork and exec a helper binary.
 *
 * The child-side pipe fds are passed via the IFD/OFD/MAXFD environment
 * variables.  The setenv→spawn→unsetenv sequence is serialised by
 * spawn_env_lock so that concurrent calls from multiple threads do not
 * corrupt each other's environment setup.
 */
op_helper *
op_helper_start(const char *name, const char *fullpath,
                op_helper_cb *read_cb, op_helper_cb *error_cb)
{
	op_helper  *helper;
	op_fde_t   *in_f[2];
	op_fde_t   *out_f[2];
	char        buf[128];
	char        fx[16], fy[16];
	const char *parv[2];
	pid_t       pid;

	if (access(fullpath, X_OK) == -1)
		return NULL;

	helper = op_malloc(sizeof(op_helper));

	snprintf(buf, sizeof(buf), "%s helper - read", name);
	if (op_pipe(&in_f[0], &in_f[1], buf) < 0)
	{
		op_free(helper);
		return NULL;
	}

	snprintf(buf, sizeof(buf), "%s helper - write", name);
	if (op_pipe(&out_f[0], &out_f[1], buf) < 0)
	{
		op_close(in_f[0]);
		op_close(in_f[1]);
		op_free(helper);
		return NULL;
	}

	/* in_f[1] = child reads from here  (IFD in child's env)
	 * out_f[0] = child writes to here  (OFD in child's env) */
	snprintf(fx, sizeof(fx), "%d", op_get_fd(in_f[1]));
	snprintf(fy, sizeof(fy), "%d", op_get_fd(out_f[0]));

	op_set_nb(in_f[0]);
	op_set_nb(in_f[1]);
	op_set_nb(out_f[0]);
	op_set_nb(out_f[1]);

	/* Argv[0] is the process title shown in ps(1). */
	snprintf(buf, sizeof(buf), "-ircd %s daemon", name);
	parv[0] = buf;
	parv[1] = NULL;

#ifdef _WIN32
	SetHandleInformation((HANDLE)op_get_fd(in_f[1]),  HANDLE_FLAG_INHERIT, 1);
	SetHandleInformation((HANDLE)op_get_fd(out_f[0]), HANDLE_FLAG_INHERIT, 1);
#endif

	/*
	 * Serialise setenv → spawn → unsetenv.  setenv(3) modifies the global
	 * environ list which is not thread-safe; without this lock two
	 * concurrent op_helper_start() calls would corrupt each other's IFD/OFD
	 * values and potentially spawn helpers with the wrong pipe ends.
	 *
	 * The env vars are always unset after spawn (success or failure) so
	 * stale values cannot influence future execs.
	 */
#define HELPER_CHILD_MAXFD "256"
	pthread_mutex_lock(&spawn_env_lock);
	op_setenv("IFD",   fy,                  1);
	op_setenv("OFD",   fx,                  1);
	op_setenv("MAXFD", HELPER_CHILD_MAXFD,  1);
	pid = op_spawn_process(fullpath, (const char **)parv);
	helper_clear_env();
	pthread_mutex_unlock(&spawn_env_lock);
#undef HELPER_CHILD_MAXFD

	if (pid == -1)
	{
		op_close(in_f[0]);
		op_close(in_f[1]);
		op_close(out_f[0]);
		op_close(out_f[1]);
		op_free(helper);
		return NULL;
	}

	/* Close the child-side ends; only the parent-side ends remain open. */
	op_close(in_f[1]);
	op_close(out_f[0]);

	op_linebuf_newbuf(&helper->sendq);
	op_linebuf_newbuf(&helper->recvq);

	helper->ifd        = in_f[0];    /* parent reads from helper */
	helper->ofd        = out_f[1];   /* parent writes to helper  */
	helper->read_cb    = read_cb;
	helper->error_cb   = error_cb;
	helper->pid        = pid;
	helper->fork_count = 0;
	helper->is_thread  = false;
	helper->closing    = false;

	return helper;
}

/* -------------------------------------------------------------------------
 * Parent-side: start an in-process thread helper
 * ---------------------------------------------------------------------- */

/*
 * op_helper_start_thread — start an in-process helper backed by a
 * socketpair + pthread instead of fork()+exec().
 *
 * The thread function receives a heap-allocated int* containing the
 * thread-side socketpair fd; the thread must free it on entry.  The
 * returned op_helper communicates over the other end.
 *
 * Two op_fde_t handles are created for the same socketpair end (via dup)
 * so that the event loop can register independent READ and WRITE interest
 * on each without one registration clobbering the other.
 */
op_helper *
op_helper_start_thread(const char *name,
                       void *(*thread_fn)(void *),
                       op_helper_cb *read_cb,
                       op_helper_cb *error_cb)
{
#ifdef _WIN32
	/* Requires AF_UNIX socketpair() and POSIX dup() — unavailable on Windows. */
	errno = ENOSYS;
	return NULL;
#else
	int      sv[2];
	int      sv1_dup;
	char     buf[128];
	int     *thread_arg;
	pthread_t tid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return NULL;

	/* sv[0] → thread side;  sv[1] → main (ircd) side */
	thread_arg  = op_malloc(sizeof(int));
	*thread_arg = sv[0];

	if (pthread_create(&tid, NULL, thread_fn, thread_arg) != 0)
	{
		close(sv[0]);
		close(sv[1]);
		op_free(thread_arg);
		return NULL;
	}

	/* Name the helper thread for debugger/top visibility. */
	{
		char tname[16];
		snprintf(tname, sizeof(tname), "op-%.12s", name);
#if defined(__linux__)
		pthread_setname_np(tid, tname);
#elif defined(__FreeBSD__) || defined(__NetBSD__)
		pthread_set_name_np(tid, tname);
#endif
		/* macOS: pthread_setname_np(name) can only set the calling thread's
		 * name, so helper threads on macOS must self-name. */
	}

	pthread_detach(tid);

	op_helper *helper = op_malloc(sizeof(op_helper));

	op_linebuf_newbuf(&helper->sendq);
	op_linebuf_newbuf(&helper->recvq);

	snprintf(buf, sizeof(buf), "%s thread-in", name);
	helper->ifd = op_open(sv[1], OP_FD_SOCKET, buf);
	op_set_nb(helper->ifd);

	/* dup() so op_setselect can register READ on ifd and WRITE on ofd
	 * independently; both fds refer to the same socketpair end.  On epoll
	 * they produce separate registrations that monitor independent events. */
	sv1_dup = dup(sv[1]);
	if (sv1_dup < 0)
	{
		op_close(helper->ifd);
		close(sv[0]);
		op_free(helper);
		return NULL;
	}

	snprintf(buf, sizeof(buf), "%s thread-out", name);
	helper->ofd = op_open(sv1_dup, OP_FD_SOCKET, buf);
	op_set_nb(helper->ofd);

	helper->read_cb    = read_cb;
	helper->error_cb   = error_cb;
	helper->pid        = -1;     /* no child process */
	helper->fork_count = 0;
	helper->is_thread  = true;
	helper->closing    = false;

	return helper;
#endif /* !_WIN32 */
}

/* -------------------------------------------------------------------------
 * Event callbacks
 * ---------------------------------------------------------------------- */

/*
 * op_helper_restart — invoke the error callback exactly once per error event.
 *
 * Sets helper->closing on first entry so that a second error (e.g. both read
 * and write fail in the same event-loop turn) is silently ignored rather than
 * causing a double-free or double-callback in the error_cb.
 */
void
op_helper_restart(op_helper *helper)
{
	op_helper_cb *cb;

	if (helper == NULL || helper->closing)
		return;

	helper->closing = true;
	cb = helper->error_cb;
	if (cb != NULL)
		cb(helper);
}

static void
op_helper_write_sendq(op_fde_t *F, void *helper_ptr)
{
	op_helper *helper = helper_ptr;
	int retlen;

	if (op_linebuf_len(&helper->sendq) > 0)
	{
		while ((retlen = op_linebuf_flush(F, &helper->sendq)) > 0)
			;
		if (retlen == 0 || (retlen < 0 && !op_ignore_errno(errno)))
		{
			op_helper_restart(helper);
			return;
		}
	}

	if (op_linebuf_len(&helper->sendq) > 0)
		op_setselect(helper->ofd, OP_SELECT_WRITE, op_helper_write_sendq, helper);
}

static void
op_helper_read_cb(op_fde_t *F __attribute__((unused)), void *data)
{
	op_helper *helper = (op_helper *)data;
	/* Stack-allocated: safe for concurrent event-loop iterations and avoids
	 * the data-race that a static buffer would have in a threaded event loop. */
	char buf[32768];
	int  length;

	if (helper == NULL)
		return;

	while ((length = op_read(helper->ifd, buf, sizeof(buf))) > 0)
	{
		op_linebuf_parse(&helper->recvq, buf, length, 0);
		helper->read_cb(helper);
	}

	if (length == 0 || (length < 0 && !op_ignore_errno(errno)))
	{
		op_helper_restart(helper);
		return;
	}

	op_setselect(helper->ifd, OP_SELECT_READ, op_helper_read_cb, helper);
}

/* -------------------------------------------------------------------------
 * Public write API
 * ---------------------------------------------------------------------- */

void
op_helper_write_queue(op_helper *helper, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	op_strf_t strings = { .format = format, .format_args = &ap, .next = NULL };
	op_linebuf_put(&helper->sendq, &strings);
	va_end(ap);
}

void
op_helper_write_flush(op_helper *helper)
{
	op_helper_write_sendq(helper->ofd, helper);
}

void
op_helper_write(op_helper *helper, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	op_strf_t strings = { .format = format, .format_args = &ap, .next = NULL };
	op_linebuf_put(&helper->sendq, &strings);
	va_end(ap);

	op_helper_write_flush(helper);
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

void
op_helper_run(op_helper *helper)
{
	if (helper == NULL)
		return;
	op_helper_read_cb(helper->ifd, helper);
}

/*
 * op_helper_close — shut down a helper and free all resources.
 *
 * Drains and frees both linebuf queues, kills the child process (for
 * process-backed helpers), closes the fds, and frees the struct.
 * Safe to call with helper == NULL.
 */
void
op_helper_close(op_helper *helper)
{
	if (helper == NULL)
		return;

	/* Free linebuf queues before closing fds in case flush is still pending. */
	op_linebuf_donebuf(&helper->sendq);
	op_linebuf_donebuf(&helper->recvq);

	/* Kill the child process.  Guard against pid == -1 (thread helpers and
	 * uninitialised structs) — kill(-1, SIGKILL) would kill the whole process
	 * group, which is catastrophic. */
	if (!helper->is_thread && helper->pid > 0)
		op_kill(helper->pid, SIGKILL);

	op_close(helper->ifd);
	if (helper->ofd != NULL && helper->ofd != helper->ifd)
		op_close(helper->ofd);

	op_free(helper);
}

int
op_helper_read(op_helper *helper, void *buf, size_t bufsize)
{
	return op_linebuf_get(&helper->recvq, buf, bufsize,
	                      LINEBUF_COMPLETE, LINEBUF_PARSED);
}

void
op_helper_loop(op_helper *helper, long delay)
{
	op_helper_run(helper);
	while (1)
		op_lib_loop(delay);
}
