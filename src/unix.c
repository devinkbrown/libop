/*
 *  libop: ophion support library.
 *  unix.c: Unix process and time utility functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 2005 ircd-ratbox development team
 *  Copyright (C) 2005 Aaron Sethman <androsyn@ratbox.org>
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

#ifndef _WIN32

#include <sys/wait.h>

#ifdef HAVE_DLINFO
# include <link.h>
# include <dlfcn.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <crt_externs.h>
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

/* -------------------------------------------------------------------------
 * Process spawning
 *
 * posix_spawn() is preferred: it avoids the async-signal-safety hazards of
 * fork() in multi-threaded processes and has cleaner semantics.  The vfork()
 * fallback is retained for platforms without posix_spawn; it is safe here
 * because the child does nothing between vfork() and execv()/_exit() other
 * than a single execv() call.
 *
 * Note on inherited file descriptors: libop opens all sockets with O_CLOEXEC
 * / SOCK_CLOEXEC so they are automatically closed in the child on exec.
 * Callers that pass stdio replacement fds must set them up themselves via
 * posix_spawn_file_actions_t or dup2() in a fork/exec pattern.
 * ---------------------------------------------------------------------- */

#if defined(HAVE_SPAWN_H) && defined(HAVE_POSIX_SPAWN)
#include <spawn.h>

#ifndef __APPLE__
extern char **environ;
#endif

pid_t
op_spawn_process(const char *path, const char **argv)
{
	pid_t pid = -1;
	int   err;
	char **myenviron;
	posix_spawnattr_t spattr;

	err = posix_spawnattr_init(&spattr);
	if (err != 0)
	{
		errno = err;
		return -1;
	}

	/* No extra spawn flags needed: POSIX_SPAWN_USEVFORK was a glibc
	 * extension that is deprecated and ignored on modern kernels; the
	 * kernel makes the clone() vs vfork() decision itself. */

#ifdef __APPLE__
	myenviron = *_NSGetEnviron();
#else
	myenviron = environ;
#endif

	/* posix_spawn() requires char *const argv[], but our callers pass
	 * const char **.  The cast is safe: posix_spawn does not modify argv
	 * or its strings; the signature merely omits the outer const for
	 * historical C compatibility reasons (cf. POSIX rationale for execv). */
	err = posix_spawn(&pid, path, NULL, &spattr,
	                  (char *const *)argv, myenviron);
	posix_spawnattr_destroy(&spattr);

	if (err != 0)
	{
		errno = err;
		return -1;
	}
	return pid;
}

#else /* no posix_spawn — fall back to vfork/execv */

pid_t
op_spawn_process(const char *path, const char **argv)
{
	pid_t pid = vfork();
	if (pid < 0)
		return -1;        /* vfork failed; errno already set */
	if (pid == 0)
	{
		/* Child: only async-signal-safe operations between vfork()
		 * and execv()/_exit().  execv() does not modify *argv; the
		 * cast drops the outer const for the same reason as above. */
		execv(path, (char *const *)argv);
		_exit(1);
	}
	return pid;
}

#endif /* HAVE_SPAWN_H && HAVE_POSIX_SPAWN */

/* -------------------------------------------------------------------------
 * Time
 * ---------------------------------------------------------------------- */

int
op_gettimeofday(struct timeval *tv, void *tz __attribute__((unused)))
{
	if (tv == NULL)
	{
		errno = EFAULT;
		return -1;
	}
#if defined(HAVE_CLOCK_GETTIME)
	/* clock_gettime(CLOCK_REALTIME) is a vDSO call on Linux/BSD —
	 * no kernel entry, nanosecond resolution, proper POSIX standard. */
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		return -1;
	tv->tv_sec  = ts.tv_sec;
	tv->tv_usec = (suseconds_t)(ts.tv_nsec / 1000);
	return 0;
#elif defined(HAVE_GETTIMEOFDAY)
	return gettimeofday(tv, NULL);
#else
	tv->tv_usec = 0;
	return (time(&tv->tv_sec) == -1) ? -1 : 0;
#endif
}

/*
 * op_sleep — sleep for (seconds + useconds microseconds).
 *
 * Loops automatically on EINTR so the full requested duration is slept even
 * when signals arrive mid-sleep.  Callers that want interruptible sleep
 * should use nanosleep() or clock_nanosleep() directly.
 */
void
op_sleep(unsigned int seconds, unsigned int useconds)
{
	struct timespec rem = {
		.tv_sec  = seconds,
		.tv_nsec = (long)useconds * 1000L,
	};

#if defined(HAVE_CLOCK_NANOSLEEP)
	/* CLOCK_MONOTONIC sleep is immune to NTP wall-clock adjustments.
	 * Pass TIMER_ABSTIME=0 (relative), loop on EINTR with remaining. */
	int rc;
	struct timespec next = rem;
	while ((rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &next, &next)) != 0)
	{
		if (rc != EINTR)
			break;
	}
#elif defined(HAVE_NANOSLEEP)
	struct timespec next = rem;
	while (nanosleep(&next, &next) == -1)
	{
		if (errno != EINTR)
			break;
	}
#else
	(void)rem;
	/* Last resort: select() with a timeout.  Signal interruption is
	 * not retried here because select() does not return remaining time. */
	struct timeval tv = { .tv_sec = seconds, .tv_usec = useconds };
	select(0, NULL, NULL, NULL, &tv);
#endif
}

/* -------------------------------------------------------------------------
 * Miscellaneous wrappers
 * ---------------------------------------------------------------------- */

char *
op_strerror(int error)
{
	static _Thread_local char buf[256];
	/* GNU strerror_r returns char* — may point to buf or a static literal. */
	return strerror_r(error, buf, sizeof(buf));
}

int
op_kill(pid_t pid, int sig)
{
	return kill(pid, sig);
}

int
op_setenv(const char *name, const char *value, int overwrite)
{
	return setenv(name, value, overwrite);
}

pid_t
op_waitpid(pid_t pid, int *status, int options)
{
	return waitpid(pid, status, options);
}

pid_t
op_getpid(void)
{
	return getpid();
}

/* -------------------------------------------------------------------------
 * op_path_to_self — return the absolute path of the running executable.
 *
 * Returns a pointer to a per-thread static buffer; the result is valid
 * until the next call from the same thread.  Returns NULL if the path
 * cannot be determined on this platform.
 *
 * Buffer is _Thread_local so concurrent calls from different threads
 * do not clobber each other.
 *
 * readlink(2) does not NUL-terminate; we use sizeof(buf)-1 as the limit
 * and NUL-terminate explicitly.  realpath(3) return value is checked; if
 * it fails we fall back to the raw (possibly relative) link target.
 * ---------------------------------------------------------------------- */

const char *
op_path_to_self(void)
{
	/* Per-thread storage: safe for concurrent callers. */
	static _Thread_local char path_buf[4096];

#if defined(HAVE_GETEXECNAME)
	/* Solaris / Illumos */
	const char *s = getexecname();
	if (s == NULL)
		return NULL;
	if (realpath(s, path_buf) == NULL)
		op_strlcpy(path_buf, s, sizeof(path_buf));
	return path_buf;

#elif defined(__linux__) || (defined(__FreeBSD__) && !defined(KERN_PROC_PATHNAME))
	/* Linux: /proc/self/exe — readlink does NOT NUL-terminate. */
	ssize_t len = readlink("/proc/self/exe", path_buf, sizeof(path_buf) - 1);
	if (len == -1)
		return NULL;
	path_buf[len] = '\0';
	return path_buf;

#elif defined(__FreeBSD__) || defined(__DragonFly__)
	size_t path_len = sizeof(path_buf);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	if (sysctl(mib, 4, path_buf, &path_len, NULL, 0) != 0)
		return NULL;
	/* sysctl KERN_PROC_PATHNAME NUL-terminates; path_len includes NUL. */
	return path_buf;

#elif defined(__APPLE__)
	char tmp_path[4096];
	uint32_t pathlen = (uint32_t)sizeof(tmp_path);
	if (_NSGetExecutablePath(tmp_path, &pathlen) != 0)
		return NULL;
	/* Resolve symlinks and . / .. components. */
	if (realpath(tmp_path, path_buf) == NULL)
		op_strlcpy(path_buf, tmp_path, sizeof(path_buf));
	return path_buf;

#elif defined(HAVE_DLINFO)
	struct link_map *map = NULL;
	dlinfo(RTLD_SELF, RTLD_DI_LINKMAP, &map);
	if (map == NULL || map->l_name == NULL || map->l_name[0] == '\0')
		return NULL;
	if (realpath(map->l_name, path_buf) == NULL)
		op_strlcpy(path_buf, map->l_name, sizeof(path_buf));
	return path_buf;

#else
	return NULL;
#endif
}

#endif /* !_WIN32 */
