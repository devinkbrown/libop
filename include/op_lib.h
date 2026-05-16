/*
 * libop: ophion support library.
 * op_lib.h: Master umbrella header — always include this, never sub-headers directly.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2002-2005 ircd-ratbox development team
 * Copyright (C) 2025-2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LIBOP_LIB_H
#define LIBOP_LIB_H

#include <libop-config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>

/* -------------------------------------------------------------------------
 * C23 compatibility layer — must come before any declarations using OP_* macros
 * ---------------------------------------------------------------------- */

#include <op_c23.h>

/* -------------------------------------------------------------------------
 * Branch-prediction hints
 * ---------------------------------------------------------------------- */

#ifdef __GNUC__
# define op_likely(x)    __builtin_expect(!!(x), 1)
# define op_unlikely(x)  __builtin_expect(!!(x), 0)
#else
# define op_likely(x)    (x)
# define op_unlikely(x)  (x)
#endif

/* -------------------------------------------------------------------------
 * Platform-specific I/O types and errno helpers
 * ---------------------------------------------------------------------- */

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
# include <windows.h>
# include <process.h>
# include <BaseTsd.h>    /* SSIZE_T */
# include <direct.h>     /* _chdir, _getcwd */
# include <io.h>         /* _access, _open, _close */

# define op_get_errno()  do { errno = WSAGetLastError(); WSASetLastError(errno); } while (0)

typedef SOCKET op_platform_fd_t;
typedef int    op_socklen_t;

# define OP_PATH_SEPARATOR '\\'

# ifndef PATH_MAX
#  define PATH_MAX 260   /* MAX_PATH on Windows */
# endif

/* MSVC does not provide these POSIX types. */
# ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#  define _SSIZE_T_DEFINED
# endif
# ifndef _MODE_T_DEFINED
typedef unsigned int mode_t;
#  define _MODE_T_DEFINED
# endif
# ifndef _PID_T_DEFINED
typedef int pid_t;
#  define _PID_T_DEFINED
# endif
# ifndef _UID_T_DEFINED
typedef int uid_t;
#  define _UID_T_DEFINED
# endif
# ifndef _GID_T_DEFINED
typedef int gid_t;
#  define _GID_T_DEFINED
# endif

/* Suppress GCC/Clang-specific attributes on MSVC. */
# if defined(_MSC_VER) && !defined(__clang__)
#  define __attribute__(x)
#  define __builtin_expect(e, v) (e)
#  define __extension__
# endif

/*
 * _Thread_local — C11 keyword for thread-local storage.
 * VS 2022 17.5+ (_MSC_VER >= 1935) supports _Thread_local natively with
 * /std:c17.  Older MSVC (and VS2022 < 17.5 in older /std modes) require
 * __declspec(thread).  Clang-CL supports _Thread_local natively.
 */
# if defined(_MSC_VER) && !defined(__clang__) && _MSC_VER < 1935
#  define _Thread_local __declspec(thread)
# endif

/* Map BSD socket errno names to Winsock equivalents. */
# undef  ENOBUFS
# define ENOBUFS       WSAENOBUFS
# undef  EINPROGRESS
# define EINPROGRESS   WSAEINPROGRESS
# undef  EWOULDBLOCK
# define EWOULDBLOCK   WSAEWOULDBLOCK
# undef  EMSGSIZE
# define EMSGSIZE      WSAEMSGSIZE
# undef  EALREADY
# define EALREADY      WSAEALREADY
# undef  EISCONN
# define EISCONN       WSAEISCONN
# undef  EADDRINUSE
# define EADDRINUSE    WSAEADDRINUSE
# undef  EAFNOSUPPORT
# define EAFNOSUPPORT  WSAEAFNOSUPPORT

# define pipe(x)        _pipe((x), 1024, O_BINARY)
# define ioctl(x, y, z) ioctlsocket((x), (y), (unsigned long *)(z))

/* POSIX function name aliases — MSVC uses underscore-prefixed versions. */
# ifndef F_OK
#  define F_OK 0
# endif
# ifndef R_OK
#  define R_OK 4
# endif
# ifndef W_OK
#  define W_OK 2
# endif
# ifndef X_OK
#  define X_OK 0   /* Windows has no execute permission; treat as existence */
# endif
# define access(p, m)        _access((p), (m))
# define unlink(p)           _unlink(p)
# define mkdir(p, m)         _mkdir(p)    /* Windows _mkdir takes no mode arg */
# define chdir(p)            _chdir(p)
# define getcwd(b, s)        _getcwd((b), (s))
# define umask(m)            _umask(m)
# define getpid()            _getpid()

# ifndef WNOHANG
#  define WNOHANG 1
# endif
# ifndef SIGKILL
#  define SIGKILL SIGTERM
# endif

# ifdef strerror
#  undef strerror
# endif
# define strerror(x)  op_strerror(x)
char *op_strerror(int error);

#else  /* !_WIN32 */

char *op_strerror(int error);
# define op_get_errno()

typedef int        op_platform_fd_t;
typedef socklen_t  op_socklen_t;

# define OP_PATH_SEPARATOR '/'

#endif /* _WIN32 */

/* -------------------------------------------------------------------------
 * printf-format attribute (guard against redefinition from ircd_defs.h)
 * ---------------------------------------------------------------------- */

#ifndef AFP
# ifdef __GNUC__
#  define AFP(a, b)  __attribute__((format(printf, a, b)))
# else
#  define AFP(a, b)
# endif
#endif

/* -------------------------------------------------------------------------
 * Soft assertions (log instead of aborting)
 *
 * slop_assert(expr)    — evaluates to 1 if the assertion PASSES.
 * lop_assert(expr)     — evaluates to 1 if the assertion FAILS.
 *                        Used in boolean conditions for recovery paths:
 *                        if (list_empty && lop_assert(len == 0)) { fix(); }
 * op_lib_assert(expr)  — primary API name; same as slop_assert.
 * ---------------------------------------------------------------------- */

/* __func__ is standard since C99; __PRETTY_FUNCTION__ is a GCC extension. */
#define slop_assert(expr) \
    (op_likely(expr) || \
     (op_lib_log("assert failed: %s (%s:%d in %s)", \
                 #expr, __FILE__, __LINE__, __func__), 0))

#define lop_assert(expr)    (!slop_assert(expr))
#define op_lib_assert(expr) slop_assert(expr)

/* -------------------------------------------------------------------------
 * sockaddr helpers (family, port, length)
 * ---------------------------------------------------------------------- */

#ifndef _WIN32
# include <netinet/in.h>
#endif

#define GET_SS_FAMILY(x)     (((const struct sockaddr *)(x))->sa_family)
#define SET_SS_FAMILY(x, y)  (((struct sockaddr *)(x))->sa_family = (y))

#ifdef OP_SOCKADDR_HAS_SA_LEN
# define GET_SS_LEN(x)        (((const struct sockaddr *)(x))->sa_len)
# define SET_SS_LEN(x, y)     (((struct sockaddr *)(x))->sa_len = (y))
#else
# define GET_SS_LEN(x)        (GET_SS_FAMILY(x) == AF_INET \
                               ? (socklen_t)sizeof(struct sockaddr_in) \
                               : (socklen_t)sizeof(struct sockaddr_in6))
# define SET_SS_LEN(x, y)     ((void)(y))
#endif

#define GET_SS_PORT(x)  (GET_SS_FAMILY(x) == AF_INET \
    ? ((const struct sockaddr_in  *)(x))->sin_port  \
    : ((const struct sockaddr_in6 *)(x))->sin6_port)

#define SET_SS_PORT(x, y)  do { \
    if (GET_SS_FAMILY(x) == AF_INET) \
        ((struct sockaddr_in  *)(x))->sin_port = (y); \
    else \
        ((struct sockaddr_in6 *)(x))->sin6_port = (y); \
} while (0)

/* -------------------------------------------------------------------------
 * Size constants
 * ---------------------------------------------------------------------- */

#ifndef HOSTIPLEN
# define HOSTIPLEN   53     /* max length of textual IP address (IPv6 + scope) */
#endif

#ifndef INADDRSZ
# define INADDRSZ    4
#endif

#ifndef IN6ADDRSZ
# define IN6ADDRSZ   16
#endif

#ifndef INT16SZ
# define INT16SZ     2
#endif

/* -------------------------------------------------------------------------
 * Callback typedefs used by op_lib_init()
 * ---------------------------------------------------------------------- */

typedef void log_cb    (const char *msg);
typedef void restart_cb(const char *msg);
typedef void die_cb    (const char *msg);

/* -------------------------------------------------------------------------
 * Core library API
 * ---------------------------------------------------------------------- */

char       *op_ctime(time_t t, char *buf, size_t len);
char       *op_date(time_t t, char *buf, size_t len);
void        op_lib_log(const char *fmt, ...) AFP(1, 2);
void        op_lib_set_log_hook(void (*hook)(const char *msg));
OP_NORETURN void op_lib_restart(const char *fmt, ...) AFP(1, 2);
void        op_lib_die(const char *fmt, ...) AFP(1, 2);
void        op_set_time(void);
const char *op_lib_version(void);

/*
 * op_build_info_t — structured build identity record populated at link time
 * from meson-injected macros.  Retrieve via op_build_info(); do not declare
 * or access the underlying static directly.
 */
typedef struct op_build_info {
	const char *product;      /* e.g. "ophion"                          */
	const char *version;      /* meson project_version(), e.g. "1.71"  */
	uint64_t    build_date;   /* Unix timestamp of last git commit      */
	const char *copyright;    /* Multi-line copyright string            */
	const char *license;      /* License summary (GPL-2+)               */
	const char *credits;      /* Lineage / credits note                 */
} op_build_info_t;

const op_build_info_t *op_build_info(void);

void        op_lib_init(log_cb *ilog, restart_cb *irestart, die_cb *idie,
                        int closeall, int maxfds,
                        size_t dh_size, size_t fd_heap_size);
OP_NORETURN void op_lib_loop(long delay);

/*
 * op_lib_loop_tick — run exactly one I/O + timer cycle and return.
 *
 * timeout_ms: maximum time to block waiting for I/O events (milliseconds).
 *   -1  block until the next scheduled timer fires
 *    0  non-blocking poll
 *   >0  block for at most this many milliseconds
 *
 * Used by the shim hot-patch path: the shim owns the outer loop and calls
 * this every iteration so it can check for upgrade signals between ticks.
 *
 * Safe to call from a thread that exclusively owns the event loop.
 */
void        op_lib_loop_tick(int timeout_ms);

time_t               op_current_time(void);
const struct timeval *op_current_time_tv(void);
pid_t                op_spawn_process(const char *path, const char **argv);
int                  op_gettimeofday(struct timeval *tv, void *tz);
void                 op_sleep(unsigned int seconds, unsigned int useconds);

char          *op_crypt(const char *key, const char *salt);
unsigned char *op_base64_encode(const unsigned char *src, size_t len);
unsigned char *op_base64_decode(const unsigned char *src, size_t len, size_t *out_len);

/*
 * op_base64url_encode — RFC 4648 §5 base64url (uses - and _ instead of + and /,
 * no padding).  Returns a heap-allocated NUL-terminated string (op_free when done).
 * Used by WebSocket handshake (Sec-WebSocket-Accept), PASETO, and similar protocols.
 */
unsigned char *op_base64url_encode(const unsigned char *src, size_t len);

/*
 * op_base64url_decode — decode a base64url string (with or without padding).
 * Returns a heap-allocated buffer; sets *out_len.  Returns NULL on error.
 */
unsigned char *op_base64url_decode(const unsigned char *src, size_t len, size_t *out_len);

int   op_kill(pid_t pid, int sig);
int   op_setenv(const char *name, const char *value, int overwrite);
pid_t op_waitpid(pid_t pid, int *status, int options);
pid_t op_getpid(void);

char *op_strtok_r(char *s, const char *delim, char **save);

/* -------------------------------------------------------------------------
 * Sub-headers (always pulled in via op_lib.h — do not include directly)
 * ---------------------------------------------------------------------- */

#include <op_tools.h>
#include <op_memory.h>
#include <op_arena.h>
#include <op_commio.h>
#include <op_balloc.h>
#include <op_linebuf.h>
#include <op_sendbuf.h>
#include <op_event.h>
#include <op_shm_ring.h>
#include <op_simd_scan.h>
#include <op_helper.h>
#include <op_rawbuf.h>
#include <op_htab.h>
#include <op_bloom.h>
#include <op_coro.h>
#include <op_strbuf.h>
#include <op_ringbuf.h>
#include <op_utf8.h>
#include <op_ratelimit.h>
#include <op_lru.h>
#include <op_pqueue.h>
#include <op_vec.h>
#include <op_bitset.h>
#include <op_iothread.h>
#include <op_async_log.h>
#include <op_async.h>
#include <op_str_intern.h>
#include <op_rbt.h>
#include <op_cidr_tbl.h>
#include <op_deque.h>
#include <op_itree.h>
#include <op_trie.h>
#include <op_skiplist.h>
#include <op_graph.h>
#include <op_hll.h>
#include <op_wm.h>
#include <arc4random.h>

#endif /* LIBOP_LIB_H */
