/*
 *  Ophion IRC Daemon
 *  commio.c: Network/file related functions
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
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
 *
 */

#define _GNU_SOURCE 1   /* accept4(), pipe2() */

#include <pthread.h>
#include <stdatomic.h>
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <commio-ssl.h>
#include <event-int.h>

/* Forward declarations for in-process WebSocket (websocket.c) */
ssize_t op_ws_read(op_fde_t *F, void *buf, size_t count);
ssize_t op_ws_write(op_fde_t *F, const void *buf, size_t count);
void    op_ws_shutdown(op_fde_t *F);
#ifdef HAVE_WRITEV
#include <sys/uio.h>
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Maximum number of connections accepted per event-loop iteration per
 * listener.  After this many successive accept4() calls we yield back to
 * the event loop so that existing-client I/O (reads, writes, timers) gets
 * a turn before we drain the next batch.  64 is enough to absorb typical
 * connection bursts without starving connected clients.               */
#define ACCEPT_BATCH_MAX 64


struct timeout_data
{
	op_fde_t *F;
	op_dlink_node node;
	time_t timeout;
	PF *timeout_handler;
	void *timeout_data;
};

op_dlink_list *op_fd_table;
static op_bh *fd_heap;
static op_bh *timeout_heap;
static op_bh *conn_heap;
static op_bh *accept_heap;

static op_dlink_list closed_list;

/* Backend-specific fd cleanup hook — set by try_uring(), NULL for other backends.
 * Declared here (above op_close) because the full io_ops_t vtable lives further
 * down in the file.  The vtable copy in g_io mirrors this pointer. */
static void (*io_close_fd)(op_fde_t *) = NULL;

/*
 * Sharded timeout lists — 16 shards, each with its own spinlock.
 * op_settimeout() acquires only the shard for the target fd, reducing
 * contention by 16x compared to a single global lock.
 * op_checktimeouts() iterates all shards, locking each individually.
 */
#define TIMEOUT_SHARDS     16
#define TIMEOUT_SHARD_MASK (TIMEOUT_SHARDS - 1)
#define TIMEOUT_SHARD(fd)  ((unsigned)(fd) & TIMEOUT_SHARD_MASK)

struct timeout_shard {
	pthread_spinlock_t lock;
	op_dlink_list      list;
	char               _pad[48]; /* avoid false sharing between shards */
};

static struct timeout_shard timeout_shards[TIMEOUT_SHARDS];
static _Atomic int          timeout_total_count; /* sum across all shards */
static struct ev_entry     *op_timeout_ev;


static const char *op_err_str[] = { "Comm OK", "Error during bind()",
	"Error during DNS lookup", "connect timeout",
	"Error during connect()",
	"Comm Error",
	"Error with SSL"
};

/* Number of currently open file descriptors.
 * Written from op_open() (accept / connect path) and op_close_pending_fds()
 * (event-loop cleanup), read from op_get_open_fd_count() which may be called
 * from any thread.  _Atomic int gives correct visibility with no locks. */
static _Atomic int number_fd = 0;
int op_maxconnections = 0;

static PF op_connect_timeout;
static PF op_connect_outcome;
static void mangle_mapped_sockaddr(struct sockaddr *in);

#ifndef HAVE_SOCKETPAIR
static int op_inet_socketpair(int d, int type, int protocol, op_platform_fd_t sv[2]);
static int op_inet_socketpair_udp(op_fde_t **newF1, op_fde_t **newF2);
#endif

static inline op_fde_t *
add_fd(op_platform_fd_t fd)
{
	op_fde_t *F = op_find_fd(fd);

	/* look up to see if we have it already */
	if (F != NULL)
		return F;

	F = op_bh_alloc(fd_heap);
	F->fd = fd;
	op_dlinkAdd(F, &F->node, &op_fd_table[op_hash_fd(fd)]);
	return (F);
}

static inline void
remove_fd(op_fde_t *F)
{
	if (F == NULL || !IsFDOpen(F))
		return;

	op_dlinkMoveNode(&F->node, &op_fd_table[op_hash_fd(F->fd)], &closed_list);
}

void
op_close_pending_fds(void)
{
	op_fde_t *F;
	op_dlink_node *ptr, *next;
	OP_DLINK_FOREACH_SAFE(ptr, next, closed_list.head)
	{
		F = ptr->data;

		/*
		 * If this fde is still in the io_uring dirty inbox (Treiber
		 * stack), we must not free it yet — uring_flush_dirty() needs
		 * to traverse the intrusive linked list through uring_dirty_next.
		 * Close the underlying fd immediately so we don't leak it, but
		 * defer freeing the fde memory.  uring_flush_dirty() will clear
		 * the dirty flag, and we will free the block on the next call.
		 */
		if (atomic_load_explicit(&F->uring_dirty, memory_order_acquire))
		{
			if (F->fd >= 0)
			{
#ifdef _WIN32
				if (F->type & (OP_FD_SOCKET | OP_FD_PIPE))
					closesocket(F->fd);
				else
#endif
					close(F->fd);
				F->fd = -1;
			}
			continue;
		}

		/* number_fd is decremented in op_close_pending_fds after the fd is closed. */
		if (F->fd >= 0)
		{
#ifdef _WIN32
			if (F->type & (OP_FD_SOCKET | OP_FD_PIPE))
				closesocket(F->fd);
			else
#endif
				close(F->fd);
		}

		op_dlinkDelete(ptr, &closed_list);
		op_bh_free(fd_heap, F);
		atomic_fetch_sub_explicit(&number_fd, 1, memory_order_relaxed);
	}
}


/* close_all_connections() can be used *before* the system come up! */

static void
op_close_all(void)
{
#ifndef _WIN32
	int i;

	/* fds 0-2 are stdin/stdout/stderr; close everything above that.
	 * (fd 3 was historically reserved for the profiler, but that is
	 *  not the case here — close it along with all other inherited fds.) */
	for (i = 3; i < op_maxconnections; ++i)
	{
		close(i);
	}
#endif
}

/*
 * get_sockerr - get the error value from the socket or the current errno
 *
 * Get the *real* error from the socket (well try to anyway..).
 * This may only work when SO_DEBUG is enabled but its worth the
 * gamble anyway.
 */
int
op_get_sockerr(const op_fde_t *F)
{
	int errtmp;
	int err = 0;
	op_socklen_t len = sizeof(err);

	if (!(F->type & OP_FD_SOCKET))
		return errno;

	op_get_errno();
	errtmp = errno;

#ifdef SO_ERROR
	if (!getsockopt(op_get_fd(F), SOL_SOCKET, SO_ERROR, (char *)&err, (op_socklen_t *) & len))
	{
		if (err)
			errtmp = err;
	}
	errno = errtmp;
#endif
	return errtmp;
}

/*
 * op_getmaxconnect - return the max number of connections allowed
 */
int
op_getmaxconnect(void)
{
	return (op_maxconnections);
}

/*
 * op_get_open_fd_count - return the number of currently open file descriptors
 */
int
op_get_open_fd_count(void)
{
	return atomic_load_explicit(&number_fd, memory_order_relaxed);
}

/*
 * set_sock_buffers - set send and receive buffers for socket
 *
 * inputs	- fd file descriptor
 * 		- size to set
 * output       - returns true (1) if successful, false (0) otherwise
 * side effects -
 */
int
op_set_buffers(const op_fde_t *F, int size)
{
	if (F == NULL)
		return 0;
	if (setsockopt
	   (F->fd, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(size))
	   || setsockopt(F->fd, SOL_SOCKET, SO_SNDBUF, (char *)&size, sizeof(size)))
		return 0;
	return 1;
}

/*
 * set_non_blocking - Set the client connection into non-blocking mode.
 *
 * inputs	- fd to set into non blocking mode
 * output	- 1 if successful 0 if not
 * side effects - use POSIX compliant non blocking and
 *                be done with it.
 */
int
op_set_nb(op_fde_t *F)
{
	int nonb = 0;
	int res;
	op_platform_fd_t fd;
	if (F == NULL)
		return 0;
	fd = F->fd;

	if ((res = op_setup_fd(F)))
		return res;
#ifdef O_NONBLOCK
	nonb |= O_NONBLOCK;
	res = fcntl(fd, F_GETFL, 0);
	if (-1 == res || fcntl(fd, F_SETFL, res | nonb) == -1)
		return 0;
#else
	nonb = 1;
	res = 0;
	if (ioctl(fd, FIONBIO, (char *)&nonb) == -1)
		return 0;
#endif

	return 1;
}

/*
 * op_settimeout() - set the socket timeout
 *
 * Set the timeout for the fd
 */
void
op_settimeout(op_fde_t *F, time_t timeout, PF * callback, void *cbdata)
{
	struct timeout_data *td;

	if (F == NULL)
		return;

	slop_assert(IsFDOpen(F));

	unsigned int shard = TIMEOUT_SHARD(F->fd);
	struct timeout_shard *ts = &timeout_shards[shard];

	if (callback == NULL)	/* user wants to remove */
	{
		pthread_spin_lock(&ts->lock);
		td = F->timeout;
		if (td == NULL)
		{
			pthread_spin_unlock(&ts->lock);
			return;
		}
		op_dlinkDelete(&td->node, &ts->list);
		op_bh_free(timeout_heap, td);
		F->timeout = NULL;
		pthread_spin_unlock(&ts->lock);

		/* If the total count drops to zero, delete the timer event.
		 * fetch_sub returns the PREVIOUS value. */
		if (atomic_fetch_sub_explicit(&timeout_total_count, 1,
		                              memory_order_relaxed) == 1)
		{
			struct ev_entry *ev = op_timeout_ev;
			op_timeout_ev = NULL;
			if (ev != NULL)
				op_event_delete(ev);
		}
		return;
	}

	/* Clamp runaway timeouts.  A timeout larger than one week is almost
	 * certainly a bug (e.g. passing an uninitialized variable or a negative
	 * value that was cast to time_t), and would effectively disable the
	 * timeout for the lifetime of the process. */
#define OP_TIMEOUT_MAX ((time_t)(86400 * 7))
	if (timeout <= 0 || timeout > OP_TIMEOUT_MAX)
		timeout = OP_TIMEOUT_MAX;
#undef OP_TIMEOUT_MAX

	pthread_spin_lock(&ts->lock);

	td = F->timeout;
	if (td == NULL)
	{
		td = F->timeout = op_bh_alloc(timeout_heap);
		td->F = F;
		td->timeout = op_current_time() + timeout;
		td->timeout_handler = callback;
		td->timeout_data = cbdata;
		op_dlinkAdd(td, &td->node, &ts->list);
		pthread_spin_unlock(&ts->lock);

		/* If old total was 0, this is the first timeout — create the
		 * timer event.  fetch_add returns the PREVIOUS value. */
		if (atomic_fetch_add_explicit(&timeout_total_count, 1,
		                              memory_order_relaxed) == 0)
		{
			/* op_event_add may itself call op_settimeout on some backends;
			 * safe because we've already released the shard lock. */
			if (op_timeout_ev == NULL)
				op_timeout_ev = op_event_add("op_checktimeouts",
				                             op_checktimeouts, NULL, 5);
		}
	}
	else
	{
		/* Update in place — node is already linked, do not re-add. */
		td->timeout = op_current_time() + timeout;
		td->timeout_handler = callback;
		td->timeout_data = cbdata;
		pthread_spin_unlock(&ts->lock);
	}
}

/*
 * op_checktimeouts() - check the socket timeouts
 *
 * All this routine does is call the given callback/cbdata, without closing
 * down the file descriptor. When close handlers have been implemented,
 * this will happen.
 */
void
op_checktimeouts(void *notused __attribute__((unused)))
{
	op_dlink_node *ptr, *next;
	struct timeout_data *td;
	/* Collect expired entries from all shards into a local list, then
	 * dispatch handlers without holding any shard lock.  This avoids
	 * deadlock when a handler calls op_settimeout() to re-register. */
	op_dlink_list dispatch = { NULL, NULL, 0 };
	time_t now = op_current_time();
	int expired_count = 0;

	for (int s = 0; s < TIMEOUT_SHARDS; s++)
	{
		struct timeout_shard *ts = &timeout_shards[s];

		pthread_spin_lock(&ts->lock);
		OP_DLINK_FOREACH_SAFE(ptr, next, ts->list.head)
		{
			td = ptr->data;
			if (td->F == NULL || !IsFDOpen(td->F))
				continue;
			if (td->timeout < now)
			{
				op_dlinkDelete(&td->node, &ts->list);
				td->F->timeout = NULL;
				op_dlinkAdd(td, &td->node, &dispatch);
				expired_count++;
			}
		}
		pthread_spin_unlock(&ts->lock);
	}

	/* Adjust total count outside any shard lock. */
	if (expired_count > 0)
		atomic_fetch_sub_explicit(&timeout_total_count, expired_count,
		                          memory_order_relaxed);

	OP_DLINK_FOREACH_SAFE(ptr, next, dispatch.head)
	{
		td = ptr->data;
		PF   *hdl  = td->timeout_handler;
		void *data = td->timeout_data;
		op_fde_t *F = td->F;
		op_dlinkDelete(&td->node, &dispatch);
		op_bh_free(timeout_heap, td);
		if (hdl != NULL)
			hdl(F, data);
	}
}

static int
op_setsockopt_reuseaddr(const op_fde_t *F)
{
	int opt_one = 1;
	int ret;

	ret = setsockopt(F->fd, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof(opt_one));
	if (ret) {
		op_lib_log("op_setsockopt_reuseaddr: Cannot set SO_REUSEADDR for FD %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	return 0;
}

int
op_setsockopt_reuseport(const op_fde_t *F)
{
#ifdef SO_REUSEPORT
	int opt_one = 1;
	int ret;

	ret = setsockopt(F->fd, SOL_SOCKET, SO_REUSEPORT, &opt_one, sizeof(opt_one));
	if (ret) {
		op_lib_log("op_setsockopt_reuseport: Cannot set SO_REUSEPORT for FD %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	return 0;
#else
	(void)F;
	return 0;
#endif
}

#ifdef HAVE_LIBSCTP
static int
op_setsockopt_sctp(op_fde_t *F)
{
	int opt_zero = 0;
	int opt_one = 1;
	/* workaround for https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/sctp?id=299ee123e19889d511092347f5fc14db0f10e3a6 */
	char *env_mapped = getenv("SCTP_I_WANT_MAPPED_V4_ADDR");
	int opt_mapped;
	if (env_mapped != NULL) {
		char *_em;
		long _emv = strtol(env_mapped, &_em, 10);
		opt_mapped = (*_em || _em == env_mapped) ? opt_zero : (int)_emv;
	} else {
		opt_mapped = opt_zero;
	}
	int ret;
	struct sctp_initmsg initmsg;
	struct sctp_rtoinfo rtoinfo;
	struct sctp_paddrparams paddrparams;
	struct sctp_assocparams assocparams;

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_NODELAY, &opt_one, sizeof(opt_one));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot set SCTP_NODELAY for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, &opt_mapped, sizeof(opt_mapped));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot unset SCTP_I_WANT_MAPPED_V4_ADDR for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	/* Configure INIT message to specify that we only want one stream */
	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.sinit_num_ostreams = 1;
	initmsg.sinit_max_instreams = 1;

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot set SCTP_INITMSG for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	/* Configure RTO values to reduce the maximum timeout */
	memset(&rtoinfo, 0, sizeof(rtoinfo));
	rtoinfo.srto_initial = 3000;
	rtoinfo.srto_min = 1000;
	rtoinfo.srto_max = 10000;

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_RTOINFO, &rtoinfo, sizeof(rtoinfo));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot set SCTP_RTOINFO for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	/*
	 * Configure peer address parameters to ensure that we monitor the connection
	 * more often than the default and don't timeout retransmit attempts before
	 * the ping timeout does.
	 *
	 * Each peer address will timeout reachability in about 750s.
	 */
	memset(&paddrparams, 0, sizeof(paddrparams));
	paddrparams.spp_assoc_id = 0;
	memcpy(&paddrparams.spp_address, &in6addr_any, sizeof(in6addr_any));
	paddrparams.spp_pathmaxrxt = 50;
	paddrparams.spp_hbinterval = 5000;
	paddrparams.spp_flags |= SPP_HB_ENABLE;

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &paddrparams, sizeof(paddrparams));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot set SCTP_PEER_ADDR_PARAMS for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	/* Configure association parameters for retransmit attempts as above */
	memset(&assocparams, 0, sizeof(assocparams));
	assocparams.sasoc_assoc_id = 0;
	assocparams.sasoc_asocmaxrxt = 50;

	ret = setsockopt(F->fd, SOL_SCTP, SCTP_ASSOCINFO, &assocparams, sizeof(assocparams));
	if (ret) {
		op_lib_log("op_setsockopt_sctp: Cannot set SCTP_ASSOCINFO for fd %d: %s",
				F->fd, strerror(op_get_sockerr(F)));
		return ret;
	}

	return 0;
}
#endif

int
op_bind(const op_fde_t *F, const struct sockaddr *addr)
{
	int ret;

	ret = op_setsockopt_reuseaddr(F);
	if (ret)
		return ret;

	ret = bind(F->fd, addr, GET_SS_LEN(addr));
	if (ret)
		return ret;

	return 0;
}

#ifdef HAVE_LIBSCTP
static int
op_sctp_bindx_only(const op_fde_t *F, const struct sockaddr_storage *addrs, size_t len)
{
	int ret;

	for (size_t i = 0; i < len; i++) {
		if (GET_SS_FAMILY(&addrs[i]) == AF_UNSPEC)
			continue;

		ret = sctp_bindx(F->fd, (struct sockaddr *)&addrs[i], 1, SCTP_BINDX_ADD_ADDR);
		if (ret)
			return ret;
	}

	return 0;
}
#endif

int
op_sctp_bindx(const op_fde_t *F, const struct sockaddr_storage *addrs, size_t len)
{
#ifdef HAVE_LIBSCTP
	int ret;

	if ((F->type & OP_FD_SCTP) == 0)
		return -1;

	ret = op_setsockopt_reuseaddr(F);
	if (ret)
		return ret;

	ret = op_sctp_bindx_only(F, addrs, len);
	if (ret)
		return ret;

	return 0;
#else
	return -1;
#endif
}

int
op_inet_get_proto(const op_fde_t *F)
{
#ifdef HAVE_LIBSCTP
	if (F->type & OP_FD_SCTP)
		return IPPROTO_SCTP;
#endif
	return IPPROTO_TCP;
}

static void op_accept_tryaccept(op_fde_t *F, void *data __attribute__((unused))) {
	struct op_sockaddr_storage st;
	op_fde_t *new_F;
	op_socklen_t addrlen;
	int new_fd;
	unsigned int batch = 0;

	while (1)
	{
		/* Batch cap: after ACCEPT_BATCH_MAX accepts, yield to the event
		 * loop so existing clients get to send/receive before we process
		 * more new connections.  The accept interest is re-registered so
		 * we'll be woken again on the very next event-loop tick if the
		 * backlog still has pending connections.                        */
		if (batch >= ACCEPT_BATCH_MAX)
		{
			op_setselect(F, OP_SELECT_ACCEPT, op_accept_tryaccept, NULL);
			return;
		}

		memset(&st, 0, sizeof(st));
		addrlen = sizeof(st);

		/* accept4() atomically sets SOCK_NONBLOCK + SOCK_CLOEXEC,
		 * saving two fcntl() syscalls per incoming connection.         */
#ifdef HAVE_ACCEPT4
		new_fd = accept4(F->fd, (struct sockaddr *)&st, &addrlen,
		                 SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
		new_fd = accept(F->fd, (struct sockaddr *)&st, &addrlen);
#endif
		op_get_errno();
		if (new_fd < 0)
		{
			if (errno == EINVAL || errno == ENOTSOCK
			    || errno == EOPNOTSUPP)
				return;
			op_setselect(F, OP_SELECT_ACCEPT, op_accept_tryaccept, NULL);
			return;
		}

		batch++;

		new_F = op_open(new_fd, OP_FD_SOCKET | (F->type & OP_FD_INHERIT_TYPES), "Incoming Connection");

		if (new_F == NULL)
		{
			op_lib_log
				("op_accept: new_F == NULL on incoming connection. Closing new_fd == %d",
				 new_fd);
			close(new_fd);
			continue;
		}

		if (op_unlikely(!op_set_nb(new_F)))
		{
			op_get_errno();
			op_lib_log("op_accept: Couldn't set FD %d non blocking!", new_F->fd);
			op_close(new_F);
			continue;  /* don't pass a closed fd to the accept callback */
		}

		/* For plain TCP connections: disable Nagle (low latency for small
		 * IRC messages), enable keepalives (detect dead clients before the
		 * application-level PING timeout fires), and request IPTOS_LOWDELAY
		 * so the OS schedules these packets with minimum queuing delay.
		 * All three are best-effort; failures are silently ignored.       */
		if (!(new_F->type & OP_FD_SCTP))
		{
			/* SO_ZEROCOPY is intentionally disabled: the kernel pins
			 * user-space pages during sendmsg(MSG_ZEROCOPY) and reads
			 * from them asynchronously.  Our slab allocator reuses
			 * buf_line_t memory immediately after sendbuf_advance()
			 * frees it, corrupting in-flight data.  IRC messages are
			 * too small to benefit from pinning anyway (the kernel
			 * threshold is ~10 KB). */
#ifdef TCP_NODELAY
			{
				int optval = 1;
				setsockopt(new_F->fd, IPPROTO_TCP, TCP_NODELAY,
				           &optval, sizeof(optval));
			}
#endif
#ifdef SO_KEEPALIVE
			{
				int optval = 1;
				setsockopt(new_F->fd, SOL_SOCKET, SO_KEEPALIVE,
				           &optval, sizeof(optval));
			}
#endif
/* After enabling keepalives, tune the intervals so dead clients are
 * detected within ~2 minutes: 60 s idle before first probe, 6 probes
 * 10 s apart → drops at 120 s with no response.  Values are advisory;
 * setsockopt() errors are silently ignored on systems that lack them. */
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
			{
				int idle = 60, intvl = 10, cnt = 6;
				setsockopt(new_F->fd, IPPROTO_TCP, TCP_KEEPIDLE,
				           &idle, sizeof(idle));
				setsockopt(new_F->fd, IPPROTO_TCP, TCP_KEEPINTVL,
				           &intvl, sizeof(intvl));
				setsockopt(new_F->fd, IPPROTO_TCP, TCP_KEEPCNT,
				           &cnt, sizeof(cnt));
			}
#endif
#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
			{
				int tos = IPTOS_LOWDELAY;
				setsockopt(new_F->fd, IPPROTO_IP, IP_TOS,
				           &tos, sizeof(tos));
			}
#endif
		}

		mangle_mapped_sockaddr((struct sockaddr *)&st);

		if (F->accept->precb != NULL)
		{
			if (!F->accept->precb(new_F, (struct sockaddr *)&st, addrlen, F->accept->data))	/* pre-callback decided to drop it */
				continue;
		}
		if (F->type & OP_FD_SSL)
		{
			op_ssl_accept_setup(F, new_F, (struct sockaddr *)&st, addrlen, false);
		}
		else
		{
			F->accept->callback(new_F, OP_OK, (struct sockaddr *)&st, addrlen,
					    F->accept->data);
		}
	}

}

/* try to accept a TCP connection */
void
op_accept_tcp(op_fde_t *F, ACPRE * precb, ACCB * callback, void *data)
{
	if (F == NULL)
		return;
	slop_assert(callback);

	F->accept = op_acceptdata_alloc();
	F->accept->callback = callback;
	F->accept->data = data;
	F->accept->precb = precb;
	op_accept_tryaccept(F, NULL);
}

/*
 * void op_connect_tcp(op_platform_fd_t fd, struct sockaddr *dest,
 *                       struct sockaddr *clocal,
 *                       CNCB *callback, void *data, int timeout)
 * Input: An fd to connect with, a host and port to connect to,
 *        a local sockaddr to connect from (or NULL to use the
 *        default), a callback, the data to pass into the callback, the
 *        address family.
 * Output: None.
 * Side-effects: A non-blocking connection to the host is started, and
 *               if necessary, set up for selection. The callback given
 *               may be called now, or it may be called later.
 */
void
op_connect_tcp(op_fde_t *F, struct sockaddr *dest,
	       struct sockaddr *clocal, CNCB * callback, void *data, int timeout)
{
	int retval;

	if (F == NULL)
		return;

	slop_assert(callback);
	F->connect = op_conndata_alloc();
	F->connect->callback = callback;
	F->connect->data = data;

	memcpy(&F->connect->hostaddr, dest, sizeof(F->connect->hostaddr));

	/* Bind to a specific local address if provided.  When clocal is
	 * NULL the OS picks the source address (default route / any). */
	if ((clocal != NULL) && (bind(F->fd, clocal, GET_SS_LEN(clocal)) < 0))
	{
		/* Failure, call the callback with OP_ERR_BIND */
		op_connect_callback(F, OP_ERR_BIND);
		/* ... and quit */
		return;
	}

	/* We have a valid IP, so we just call tryconnect */
	/* Make sure we actually set the timeout here .. */
	op_settimeout(F, timeout, op_connect_timeout, NULL);

	retval = connect(F->fd,
			 (struct sockaddr *)&F->connect->hostaddr,
			 GET_SS_LEN(&F->connect->hostaddr));
	/* Error? */
	if (retval < 0) {
		/*
		 * If we get EISCONN, then we've already connect()ed the socket,
		 * which is a good thing.
		 *   -- adrian
		 */
		op_get_errno();
		if (errno == EISCONN) {
			op_connect_callback(F, OP_OK);
		} else if (op_ignore_errno(errno)) {
			/* Ignore error? Reschedule */
			op_setselect(F, OP_SELECT_CONNECT, op_connect_outcome, NULL);
		} else {
			/* Error? Fail with OP_ERR_CONNECT */
			op_connect_callback(F, OP_ERR_CONNECT);
		}
		return;
	}
	/* If we get here, we've succeeded, so call with OP_OK */
	op_connect_callback(F, OP_OK);
}

void
op_connect_sctp(op_fde_t *F, struct sockaddr_storage *dest, size_t dest_len,
	struct sockaddr_storage *clocal, size_t clocal_len,
	CNCB *callback, void *data, int timeout)
{
#ifdef HAVE_LIBSCTP
	/* Fixed-size packed SCTP address buffer (16 destinations maximum).
	 * The original code used a caller-size-controlled VLA which is a
	 * stack-overflow risk when dest_len is large or attacker-supplied. */
	uint8_t packed_dest[sizeof(struct sockaddr_storage) * 16];
	uint8_t *p;
	size_t n;
	int retval;

	if (F == NULL)
		return;

	if (dest_len == 0 || dest_len > 16)
	{
		op_lib_log("op_connect_sctp: dest_len %zu out of range (max 16)", dest_len);
		op_connect_callback(F, OP_ERR_CONNECT);
		return;
	}
	p = packed_dest;
	n = 0;

	slop_assert(callback);
	F->connect = op_conndata_alloc();
	F->connect->callback = callback;
	F->connect->data = data;

	if ((F->type & OP_FD_SCTP) == 0) {
		op_connect_callback(F, OP_ERR_CONNECT);
		return;
	}

	for (size_t i = 0; i < dest_len; i++) {
		if (GET_SS_FAMILY(&dest[i]) == AF_INET6) {
			memcpy(p, &dest[i], sizeof(struct sockaddr_in6));
			n++;
			p += sizeof(struct sockaddr_in6);
		} else if (GET_SS_FAMILY(&dest[i]) == AF_INET) {
			memcpy(p, &dest[i], sizeof(struct sockaddr_in));
			n++;
			p += sizeof(struct sockaddr_in);
		}
	}
	dest_len = n;

	memcpy(&F->connect->hostaddr, &dest[0], sizeof(F->connect->hostaddr));

	if ((clocal_len > 0) && (op_sctp_bindx_only(F, clocal, clocal_len) < 0)) {
		/* Failure, call the callback with OP_ERR_BIND */
		op_connect_callback(F, OP_ERR_BIND);
		/* ... and quit */
		return;
	}

	op_settimeout(F, timeout, op_connect_timeout, NULL);

	retval = sctp_connectx(F->fd, (struct sockaddr *)packed_dest, dest_len, NULL);
	/* Error? */
	if (retval < 0) {
		/*
		 * If we get EISCONN, then we've already connect()ed the socket,
		 * which is a good thing.
		 *   -- adrian
		 */
		op_get_errno();
		if (errno == EISCONN) {
			op_connect_callback(F, OP_OK);
		} else if (op_ignore_errno(errno)) {
			/* Ignore error? Reschedule */
			op_setselect(F, OP_SELECT_CONNECT, op_connect_outcome, NULL);
		} else {
			/* Error? Fail with OP_ERR_CONNECT */
			op_connect_callback(F, OP_ERR_CONNECT);
		}
		return;
	}
	/* If we get here, we've succeeded, so call with OP_OK */
	op_connect_callback(F, OP_OK);
#else
	op_connect_callback(F, OP_ERR_CONNECT);
#endif
}

/*
 * op_connect_callback() - call the callback, and continue with life
 */
void
op_connect_callback(op_fde_t *F, int status)
{
	CNCB *hdl;
	void *data;
	int errtmp = errno;	/* save errno as op_settimeout clobbers it sometimes */

	/* This check is gross..but probably necessary */
	if (F == NULL || F->connect == NULL || F->connect->callback == NULL)
		return;
	/* Clear the connect flag + handler */
	hdl = F->connect->callback;
	data = F->connect->data;
	F->connect->callback = NULL;


	/* Clear the timeout handler */
	op_settimeout(F, 0, NULL, NULL);
	errno = errtmp;
	/* Call the handler */
	hdl(F, status, data);
}


/*
 * op_connect_timeout() - this gets called when the socket connection
 * times out. This *only* can be called once connect() is initially
 * called ..
 */
static void
op_connect_timeout(op_fde_t *F, void *notused __attribute__((unused)))
{
	/* error! */
	op_connect_callback(F, OP_ERR_TIMEOUT);
}

static void
op_connect_outcome(op_fde_t *F, void *notused __attribute__((unused)))
{
	int retval;
	int err = 0;
	socklen_t len = sizeof(err);

	if (F == NULL || F->connect == NULL || F->connect->callback == NULL)
		return;
	retval = getsockopt(F->fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (retval < 0) {
		op_get_errno();
	} else if (err != 0) {
		errno = err;
		retval = -1;
	}
	if (retval < 0) {
		/* Error? Fail with OP_ERR_CONNECT */
		op_connect_callback(F, OP_ERR_CONNECT);
		return;
	}
	/* If we get here, we've succeeded, so call with OP_OK */
	op_connect_callback(F, OP_OK);
}


int
op_connect_sockaddr(const op_fde_t *F, struct sockaddr *addr, int len)
{
	if (F == NULL || F->connect == NULL)
		return 0;

	memcpy(addr, &F->connect->hostaddr, len);
	return 1;
}

/*
 * op_error_str() - return an error string for the given error condition
 */
const char *
op_errstr(int error)
{
	if (error < 0 || error >= OP_ERR_MAX)
		return "Invalid error number!";
	return op_err_str[error];
}


int
op_socketpair(int family, int sock_type, int proto, op_fde_t **F1, op_fde_t **F2, const char *note)
{
	op_platform_fd_t nfd[2];
	if (atomic_load_explicit(&number_fd, memory_order_relaxed) >= op_maxconnections)
	{
		errno = ENFILE;
		return -1;
	}

/* Use SOCK_NONBLOCK|SOCK_CLOEXEC atomically when available (Linux/BSDs),
 * saving 4 fcntl() syscalls (2 per end) vs. the op_set_nb() path.     */
#ifdef HAVE_SOCKETPAIR
# ifdef SOCK_NONBLOCK
	if (socketpair(family, sock_type | SOCK_NONBLOCK | SOCK_CLOEXEC, proto, nfd))
# else
	if (socketpair(family, sock_type, proto, nfd))
# endif
#else
	if (sock_type == SOCK_DGRAM)
	{
		return op_inet_socketpair_udp(F1, F2);
	}

	if (op_inet_socketpair(AF_INET, sock_type, proto, nfd))
#endif
		return -1;

	*F1 = op_open(nfd[0], OP_FD_SOCKET, note);
	*F2 = op_open(nfd[1], OP_FD_SOCKET, note);

	if (*F1 == NULL)
	{
		if (*F2 != NULL)
			op_close(*F2);
		return -1;
	}

	if (*F2 == NULL)
	{
		op_close(*F1);
		return -1;
	}

	/* Set the socket non-blocking, and other wonderful bits */
	if (op_unlikely(!op_set_nb(*F1)))
	{
		op_lib_log("op_open: Couldn't set FD %d non blocking: %s", nfd[0], strerror(errno));
		op_close(*F1);
		op_close(*F2);
		return -1;
	}

	if (op_unlikely(!op_set_nb(*F2)))
	{
		op_lib_log("op_open: Couldn't set FD %d non blocking: %s", nfd[1], strerror(errno));
		op_close(*F1);
		op_close(*F2);
		return -1;
	}

	return 0;
}


int
op_pipe(op_fde_t **F1, op_fde_t **F2, const char *desc)
{
#ifndef _WIN32
	op_platform_fd_t fd[2];
	if (atomic_load_explicit(&number_fd, memory_order_relaxed) >= op_maxconnections)
	{
		errno = ENFILE;
		return -1;
	}
#ifdef HAVE_PIPE2
	/* O_NONBLOCK only — no O_CLOEXEC.  These fds may be passed to child
	 * processes (e.g. iplist downloader forks in authproc.c) that need
	 * them to survive exec(); O_CLOEXEC would close them before the child
	 * starts.  If a caller wants CLOEXEC it should set it explicitly via
	 * fcntl(fd, F_SETFD, FD_CLOEXEC) after verifying the fd won't be
	 * inherited. */
	if (pipe2(fd, O_NONBLOCK) == -1)
		return -1;
#else
	if (pipe(fd) == -1)
		return -1;
#endif

	*F1 = op_open(fd[0], OP_FD_PIPE, desc);
	*F2 = op_open(fd[1], OP_FD_PIPE, desc);

	if (op_unlikely(!op_set_nb(*F1)))
	{
		op_lib_log("op_open: Couldn't set FD %d non blocking: %s", fd[0], strerror(errno));
		op_close(*F1);
		op_close(*F2);
		return -1;
	}

	if (op_unlikely(!op_set_nb(*F2)))
	{
		op_lib_log("op_open: Couldn't set FD %d non blocking: %s", fd[1], strerror(errno));
		op_close(*F1);
		op_close(*F2);
		return -1;
	}


	return 0;
#else
	/* Its not a pipe..but its selectable.  I'll take dirty hacks
	 * for $500 Alex.
	 */
	return op_socketpair(AF_INET, SOCK_STREAM, 0, F1, F2, desc);
#endif
}

/*
 * op_socket() - open a socket
 *
 * This is a highly highly cut down version of squid's op_open() which
 * for the most part emulates socket(), *EXCEPT* it fails if we're about
 * to run out of file descriptors.
 */
op_fde_t *
op_socket(int family, int sock_type, int proto, const char *note)
{
	op_fde_t *F;
	op_platform_fd_t fd;
	/* First, make sure we aren't going to run out of file descriptors */
	if (op_unlikely(atomic_load_explicit(&number_fd, memory_order_relaxed) >= op_maxconnections))
	{
		errno = ENFILE;
		return NULL;
	}

	/* Atomically set O_NONBLOCK + FD_CLOEXEC on the new socket when
	 * the kernel supports it (Linux ≥ 2.6.27 / FreeBSD ≥ 10 / BSDs),
	 * saving the two fcntl() calls that op_set_nb() would otherwise
	 * make per connection.  Fall back to plain socket() on older kernels. */
#ifdef HAVE_ACCEPT4
	/* HAVE_ACCEPT4 implies SOCK_NONBLOCK + SOCK_CLOEXEC are available. */
	fd = socket(family, sock_type | SOCK_NONBLOCK | SOCK_CLOEXEC, proto);
#elif defined(SOCK_CLOEXEC)
	fd = socket(family, sock_type | SOCK_CLOEXEC, proto);
#else
	fd = socket(family, sock_type, proto);
#endif
	if (op_unlikely(fd < 0))
		return NULL;	/* errno will be passed through, yay.. */

	/*
	 * Make sure we can take both IPv4 and IPv6 connections
	 * on an AF_INET6 SCTP socket, otherwise keep them separate
	 */
	if (family == AF_INET6)
	{
#ifdef HAVE_LIBSCTP
		int v6only = (proto == IPPROTO_SCTP) ? 0 : 1;
#else
		int v6only = 1;
#endif
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &v6only, sizeof(v6only)) == -1)
		{
			op_lib_log("op_socket: Could not set IPV6_V6ONLY option to %d on FD %d: %s",
				   v6only, fd, strerror(errno));
			close(fd);
			return NULL;
		}
	}

	F = op_open(fd, OP_FD_SOCKET, note);
	if (F == NULL)
	{
		op_lib_log("op_socket: op_open returns NULL on FD %d: %s, closing fd", fd,
			   strerror(errno));
		close(fd);
		return NULL;
	}

#ifdef HAVE_LIBSCTP
	if (proto == IPPROTO_SCTP) {
		F->type |= OP_FD_SCTP;

		if (op_setsockopt_sctp(F)) {
			op_lib_log("op_socket: Could not set SCTP socket options on FD %d: %s",
				fd, strerror(errno));
			close(fd);
			return NULL;
		}
	}
#endif

	/* Set the socket non-blocking, and other wonderful bits */
	if (op_unlikely(!op_set_nb(F)))
	{
		op_lib_log("op_open: Couldn't set FD %d non blocking: %s", fd, strerror(errno));
		op_close(F);
		return NULL;
	}

	return F;
}

/*
 * If a sockaddr_storage is AF_INET6 but is a mapped IPv4
 * socket manged the sockaddr.
 */
static void
mangle_mapped_sockaddr(struct sockaddr *in)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)in;

	if (in->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
	{
		struct sockaddr_in in4;
		memset(&in4, 0, sizeof(struct sockaddr_in));
		in4.sin_family = AF_INET;
		in4.sin_port = in6->sin6_port;
		in4.sin_addr.s_addr = ((uint32_t *)&in6->sin6_addr)[3];
		memcpy(in, &in4, sizeof(struct sockaddr_in));
	}
}

/*
 * op_listen() - listen on a port
 */
int
op_listen(op_fde_t *F, int backlog, int defer_accept)
{
	int result;

	F->type = OP_FD_SOCKET | OP_FD_LISTEN | (F->type & OP_FD_INHERIT_TYPES);

/* SO_REUSEPORT lets the kernel distribute incoming connections across
 * multiple listener sockets on the same port (e.g. separate accept-loop
 * threads or helper processes) without the thundering-herd problem.
 * Best-effort: silently ignored on kernels that don't support it.     */
#ifdef SO_REUSEPORT
	{
		int opt = 1;
		(void)setsockopt(F->fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	}
#endif

	result = listen(F->fd, backlog);

#ifdef TCP_DEFER_ACCEPT
	if (defer_accept && !result)
	{
		(void)setsockopt(F->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &backlog, sizeof(int));
	}
#endif
#ifdef SO_ACCEPTFILTER
	if (defer_accept && !result)
	{
		struct accept_filter_arg afa;

		memset(&afa, '\0', sizeof afa);
		op_strlcpy(afa.af_name, "dataready", sizeof afa.af_name);
		(void)setsockopt(F->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa,
				sizeof afa);
	}
#endif

/* TCP Fast Open (Linux ≥ 3.7, macOS ≥ 10.11) allows data to be sent in
 * the SYN/SYN-ACK exchange, cutting one full round-trip from the IRC
 * connection handshake.  The kernel queues the cookie negotiation
 * transparently; connections that don't use TFO fall back normally.
 * A queue depth of 128 is plenty for an IRC listener.                  */
#if defined(TCP_FASTOPEN) && !defined(__APPLE__)
	if (!result && !(F->type & OP_FD_SCTP))
	{
		int tfo_qlen = 128;
		(void)setsockopt(F->fd, IPPROTO_TCP, TCP_FASTOPEN,
		                 &tfo_qlen, sizeof(tfo_qlen));
	}
#elif defined(TCP_FASTOPEN) && defined(__APPLE__)
	if (!result && !(F->type & OP_FD_SCTP))
	{
		int enabled = 1;
		(void)setsockopt(F->fd, IPPROTO_TCP, TCP_FASTOPEN,
		                 &enabled, sizeof(enabled));
	}
#endif

	return result;
}

/* One-time OS-specific initialisation (WSAStartup on Windows, fd-clobbering
 * on Unix).  Protected by pthread_once so re-entrant calls from test code
 * or accidental double-init are harmless.                                 */
static int     _fdlist_closeall;
static int     _fdlist_maxfds;
static pthread_once_t _fdlist_once = PTHREAD_ONCE_INIT;

static void
_fdlist_once_fn(void)
{
#ifdef _WIN32
	WSADATA wsaData;
	int vers = MAKEWORD(2, 0);
	if (WSAStartup(vers, &wsaData) != 0)
		op_lib_die("WSAStartup failed");
#endif
	op_maxconnections = _fdlist_maxfds;
	if (_fdlist_closeall)
		op_close_all();
}

void
op_fdlist_init(int closeall, int maxfds, size_t heapsize)
{
	_fdlist_closeall = closeall;
	_fdlist_maxfds   = maxfds;
	pthread_once(&_fdlist_once, _fdlist_once_fn);

	fd_heap = op_bh_create(sizeof(op_fde_t), heapsize, "libop_fd_heap");
	/* timeout_data is allocated/freed for every connection that sets a
	 * timeout (effectively every client).  Pool-allocating avoids the
	 * per-call malloc overhead on the hot accept→settimeout path.      */
	timeout_heap = op_bh_create(sizeof(struct timeout_data), heapsize, "libop_timeout_heap");
	for (int i = 0; i < TIMEOUT_SHARDS; i++)
		pthread_spin_init(&timeout_shards[i].lock, PTHREAD_PROCESS_PRIVATE);
	atomic_init(&timeout_total_count, 0);
	/* conndata/acceptdata are allocated per outgoing/incoming connection
	 * attempt.  Pool-allocating avoids per-connect malloc overhead.    */
	conn_heap   = op_bh_create(sizeof(struct conndata),   heapsize, "libop_conn_heap");
	accept_heap = op_bh_create(sizeof(struct acceptdata), heapsize, "libop_accept_heap");

}

struct conndata *
op_conndata_alloc(void)
{
	return op_bh_alloc(conn_heap);
}

void
op_conndata_free(struct conndata *cd)
{
	op_bh_free(conn_heap, cd);
}

struct acceptdata *
op_acceptdata_alloc(void)
{
	return op_bh_alloc(accept_heap);
}

void
op_acceptdata_free(struct acceptdata *ad)
{
	op_bh_free(accept_heap, ad);
}

/* Called to open a given filedescriptor */
op_fde_t *
op_open(op_platform_fd_t fd, uint16_t type, const char *desc)
{
	op_fde_t *F;
	slop_assert(fd >= 0);

	F = add_fd(fd);

	slop_assert(!IsFDOpen(F));
	if (op_unlikely(IsFDOpen(F)))
	{
		const char *fdesc;
		if (F != NULL && F->desc != NULL)
			fdesc = F->desc;
		else
			fdesc = "NULL";
		op_lib_log("Trying to op_open an already open FD: %d desc: %s", fd, fdesc);
		return NULL;
	}
	F->fd = fd;
	F->type = type;
	F->uring_fixed_idx = -1;
	pthread_spin_init(&F->pflags_lock, PTHREAD_PROCESS_PRIVATE);
	SetFDOpen(F);

#ifdef HAVE_SO_NOSIGPIPE
	/* BSD: suppress SIGPIPE at the socket level so MSG_NOSIGNAL=0 is safe.
	 * On Linux, MSG_NOSIGNAL on send() handles this; on BSD it doesn't exist. */
	if (type & OP_FD_SOCKET)
	{
		int on = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	}
#endif

	if (desc != NULL)
		F->desc = op_strndup(desc, FD_DESC_SZ);
	atomic_fetch_add_explicit(&number_fd, 1, memory_order_relaxed);
	return F;
}


/* Called to close a given filedescriptor */
void
op_close(op_fde_t *F)
{
	uint16_t type;
	int fd;

	if (F == NULL)
		return;

	if (!IsFDOpen(F))
	{
		/* slop_assert logs the failure; guard against continuing into
		 * op_free(F->desc) a second time which would double-free the
		 * descriptor string and corrupt the heap. */
		slop_assert(IsFDOpen(F));
		return;
	}

	fd = F->fd;
	type = F->type;

	slop_assert(!(type & OP_FD_FILE));
	if (op_unlikely(type & OP_FD_FILE))
	{
		slop_assert(F->read_handler == NULL);
		slop_assert(F->write_handler == NULL);
	}

	if (type & OP_FD_LISTEN) {
		listen(F->fd, 0);
	}

	op_setselect(F, OP_SELECT_WRITE | OP_SELECT_READ, NULL, NULL);
	op_settimeout(F, 0, NULL, NULL);
	if (io_close_fd != NULL)
		io_close_fd(F);
	if (F->accept)  { op_bh_free(accept_heap, F->accept);  F->accept  = NULL; }
	if (F->connect) { op_bh_free(conn_heap,   F->connect); F->connect = NULL; }
	op_free(F->desc);
	F->desc = NULL;
	if (type & OP_FD_SSL)
	{
		op_ssl_shutdown(F);
	}
	if (type & OP_FD_WEBSOCKET)
	{
		op_ws_shutdown(F);
	}
	if (IsFDOpen(F))
	{
		remove_fd(F);
		ClearFDOpen(F);
		pthread_spin_destroy(&F->pflags_lock);
	}

	if (type & OP_FD_LISTEN)
		shutdown(fd, SHUT_RDWR);
}


/*
 * op_dump_fd() - dump the list of active filedescriptors
 */
void
op_dump_fd(DUMPCB * cb, void *data)
{
	static const char *empty = "";
	op_dlink_node *ptr;
	op_dlink_list *bucket;
	op_fde_t *F;
	unsigned int i;

	for (i = 0; i < OP_FD_HASH_SIZE; i++)
	{
		bucket = &op_fd_table[i];

		if (op_dlink_list_length(bucket) <= 0)
			continue;

		OP_DLINK_FOREACH(ptr, bucket->head)
		{
			F = ptr->data;
			if (F == NULL || !IsFDOpen(F))
				continue;

			cb(F->fd, F->desc ? F->desc : empty, data);
		}
	}
}

/*
 * op_note() - set the fd note
 *
 * Note: must be careful not to overflow op_fd_table[fd].desc when
 *       calling.
 */
void
op_note(op_fde_t *F, const char *string)
{
	if (F == NULL)
		return;

	op_free(F->desc);
	F->desc = op_strndup(string, FD_DESC_SZ);
}

void
op_set_type(op_fde_t *F, uint16_t type)
{
	/* if the caller is calling this, lets assume they have a clue */
	F->type = type;
}

uint16_t
op_get_type(const op_fde_t *F)
{
	return F->type;
}

int
op_fd_ssl(const op_fde_t *F)
{
	if (F == NULL)
		return 0;
	if (F->type & OP_FD_SSL)
		return 1;
	return 0;
}

op_platform_fd_t
op_get_fd(const op_fde_t *F)
{
	if (F == NULL)
		return -1;
	return (F->fd);
}

op_fde_t *
op_get_fde(op_platform_fd_t fd)
{
	return op_find_fd(fd);
}

ssize_t
op_read(op_fde_t *F, void *buf, size_t count)
{
	ssize_t ret;
	if (F == NULL)
		return 0;

	/* Check WebSocket and SSL before plain socket path */
	if (F->type & OP_FD_WEBSOCKET)
	{
		return op_ws_read(F, buf, count);
	}
	if (F->type & OP_FD_SSL)
	{
		return op_ssl_read(F, buf, count);
	}
	if (F->type & OP_FD_SOCKET)
	{
		ret = recv(F->fd, buf, count, 0);
		if (ret < 0)
		{
			op_get_errno();
		}
		return ret;
	}


	/* default case */
	return read(F->fd, buf, count);
}

/*
 * op_pending — return the number of already-decrypted bytes buffered inside
 * the TLS library for F.  Returns 0 for plain sockets, kTLS sockets, or
 * when no data is pending.
 *
 * Use this after a short read from op_read() on a TLS socket: if op_pending()
 * returns > 0, the caller must read again immediately rather than waiting for
 * POLLIN — the data is in the TLS library buffer, not the kernel socket buffer.
 */
int
op_pending(op_fde_t *F)
{
	if (F == NULL)
		return 0;
	if (F->type & OP_FD_SSL)
		return op_ssl_pending(F);
	return 0;
}

/*
 * op_fd_cork — enable or disable TCP_CORK (Linux) / TCP_NOPUSH (BSD) on a
 * plain TCP socket.  on=1 starts coalescing; on=0 flushes immediately.
 *
 * Does nothing on SSL sockets (kernel can't see the plaintext).
 * Safe to call on non-TCP fds; setsockopt() will simply return ENOPROTOOPT.
 */
void
op_fd_cork(op_fde_t *F, int on)
{
	if (F == NULL || (F->type & (OP_FD_SSL | OP_FD_WEBSOCKET)))
		return;
#if defined(TCP_CORK)
	setsockopt(F->fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
	/* Clearing TCP_CORK on Linux immediately flushes coalesced data;
	 * no extra action is needed here beyond the setsockopt above. */
#elif defined(TCP_NOPUSH)
	setsockopt(F->fd, IPPROTO_TCP, TCP_NOPUSH, &on, sizeof(on));
	if (!on)
	{
		/* BSD flush: clear TCP_NOPUSH then toggle TCP_NODELAY */
#  ifdef TCP_NODELAY
		int one = 1, zero = 0;
		setsockopt(F->fd, IPPROTO_TCP, TCP_NODELAY, &one,  sizeof(one));
		setsockopt(F->fd, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
#  endif
	}
#endif
}

/*
 * op_zerocopy_drain — consume pending MSG_ZEROCOPY completion notifications
 * from the socket error queue.  Must be called periodically on sockets with
 * FLAG_ZEROCOPY set to prevent the error queue from filling up.
 *
 * Each sendmsg(MSG_ZEROCOPY) generates one SO_EE_ORIGIN_ZEROCOPY notification
 * (or SO_EE_ORIGIN_NONE if the kernel chose to copy instead of pin).  We drain
 * all available notifications in a non-blocking loop.
 *
 * Safe to call even if SO_ZEROCOPY is not supported — returns 0 immediately.
 */
void
op_zerocopy_drain(op_fde_t *F)
{
#if defined(__linux__) && defined(MSG_ERRQUEUE)
	if (F == NULL || !(F->flags & FLAG_ZEROCOPY))
		return;

	char ctrl[256];
	struct msghdr msg;
	struct iovec iov;
	char dummy[1];

	iov.iov_base = dummy;
	iov.iov_len  = sizeof(dummy);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = ctrl;
	msg.msg_controllen = sizeof(ctrl);

	/* Non-blocking loop: drain all queued notifications. */
	while (recvmsg(F->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) > 0)
	{
		msg.msg_controllen = sizeof(ctrl);
		msg.msg_flags      = 0;
	}
#else
	(void)F;
#endif
}

ssize_t
op_write(op_fde_t *F, const void *buf, size_t count)
{
	ssize_t ret;
	if (F == NULL)
		return 0;

	if (F->type & OP_FD_WEBSOCKET)
	{
		return op_ws_write(F, buf, count);
	}
	if (F->type & OP_FD_SSL)
	{
		return op_ssl_write(F, buf, count);
	}
	if (F->type & OP_FD_SOCKET)
	{
		int flags = MSG_NOSIGNAL;
		ret = send(F->fd, buf, count, flags);
		if (ret < 0)
		{
			op_get_errno();
		}
		return ret;
	}

	return write(F->fd, buf, count);
}

/* op_fake_writev — sequential per-iovec fallback for op_writev.
 * Needed whenever we cannot use writev() directly: no system writev (Windows /
 * old platforms), SSL (TLS context needed per-call), and WebSocket
 * (RFC 6455 framing must be applied per-message via op_write).  Define it
 * unconditionally so all builds have the symbol; the compiler will dead-strip
 * it where unused. */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static ssize_t
op_fake_writev(op_fde_t *F, const struct op_iovec *vp, size_t vpcount)
{
	ssize_t count = 0;

	while (vpcount-- > 0)
	{
		ssize_t written = op_write(F, vp->iov_base, vp->iov_len);

		if (written <= 0)
		{
			if (count > 0)
				return count;
			else
				return written;
		}
		count += written;
		vp++;
	}
	return (count);
}

#if defined(_WIN32) || !defined(HAVE_WRITEV)
ssize_t
op_writev(op_fde_t *F, struct op_iovec * vecount, int count)
{
	return op_fake_writev(F, vecount, count);
}

#else
ssize_t
op_writev(op_fde_t *F, struct op_iovec * vector, int count)
{
	if (F == NULL)
	{
		errno = EBADF;
		return -1;
	}

	/* WebSocket framing must be applied per-message; route through
	 * op_write (via op_fake_writev) so each iovec gets framed correctly.
	 * This handles plain ws:// connections (OP_FD_WEBSOCKET without SSL).
	 * wss:// (OP_FD_WEBSOCKET + OP_FD_SSL) is caught by the SSL branch
	 * below, which also routes through op_fake_writev → op_write → WS. */
	if (F->type & OP_FD_WEBSOCKET)
	{
		return op_fake_writev(F, vector, count);
	}
	if (F->type & OP_FD_SSL)
	{
		return op_fake_writev(F, vector, count);
	}
#ifdef HAVE_SENDMSG
	if (F->type & OP_FD_SOCKET)
	{
		struct msghdr msg;
		int flags = MSG_NOSIGNAL;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = (struct iovec *)vector;
		msg.msg_iovlen = (size_t)count;
		return sendmsg(F->fd, &msg, flags);
	}
#endif /* HAVE_SENDMSG */
	return writev(F->fd, (struct iovec *)vector, count);

}
#endif


/*
 * From: Thomas Helvey <tomh@inxpress.net>
 */
static const char *IpQuadTab[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	"10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
	"20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
	"30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
	"40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
	"50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
	"60", "61", "62", "63", "64", "65", "66", "67", "68", "69",
	"70", "71", "72", "73", "74", "75", "76", "77", "78", "79",
	"80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
	"90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
	"100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
	"110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
	"120", "121", "122", "123", "124", "125", "126", "127", "128", "129",
	"130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
	"140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
	"150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
	"160", "161", "162", "163", "164", "165", "166", "167", "168", "169",
	"170", "171", "172", "173", "174", "175", "176", "177", "178", "179",
	"180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
	"190", "191", "192", "193", "194", "195", "196", "197", "198", "199",
	"200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
	"210", "211", "212", "213", "214", "215", "216", "217", "218", "219",
	"220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
	"230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
	"240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
	"250", "251", "252", "253", "254", "255"
};

/*
 * inetntoa - in_addr to string
 *      changed name to remove collision possibility and
 *      so behaviour is guaranteed to take a pointer arg.
 *      -avalon 23/11/92
 *  inet_ntoa --  returned the dotted notation of a given
 *      internet number
 *      argv 11/90).
 *  inet_ntoa --  its broken on some Ultrix/Dynix too. -avalon
 */

static const char *
inetntoa(const char *in)
{
	/* Thread-local buffer: concurrent calls from different threads
	 * each get their own copy; no synchronisation required.        */
	static _Thread_local char buf[16];
	char *bufptr = buf;
	const unsigned char *a = (const unsigned char *)in;
	const char *n;

	n = IpQuadTab[*a++];
	while (*n)
		*bufptr++ = *n++;
	*bufptr++ = '.';
	n = IpQuadTab[*a++];
	while (*n)
		*bufptr++ = *n++;
	*bufptr++ = '.';
	n = IpQuadTab[*a++];
	while (*n)
		*bufptr++ = *n++;
	*bufptr++ = '.';
	n = IpQuadTab[*a];
	while (*n)
		*bufptr++ = *n++;
	*bufptr = '\0';
	return buf;
}

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4(const unsigned char *src, char *dst, size_t size);
static const char *inet_ntop6(const unsigned char *src, char *dst, size_t size);

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a unsigned char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
	if (size < 16)
		return NULL;
	op_strlcpy(dst, inetntoa((const char *)src), size);
	return dst;
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct
	{
		int base, len;
	}
	best, cur;
	unsigned int words[IN6ADDRSZ / INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *      Copy the input (bytewise) array into a wordwise array.
	 *      Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i += 2)
		words[i / 2] = (src[i] << 8) | src[i + 1];
	best.base = -1;
	best.len = 0;
	cur.base = -1;
	cur.len = 0;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		}
		else
		{
			if (cur.base != -1)
			{
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1)
	{
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
	{
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
			{
				if (i == 0)
					*tp++ = '0';
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		   (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
		{
			if (!inet_ntop4(src + 12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		{
			size_t avail = sizeof(tmp) - (size_t)(tp - tmp);
			int n = snprintf(tp, avail, "%x", words[i]);
			if(n > 0) {
				if((size_t)n >= avail) n = (int)(avail > 0 ? avail - 1 : 0);
				tp += n;
			}
		}
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */

	if ((size_t)(tp - tmp) > size)
	{
		return (NULL);
	}
	return memcpy(dst, tmp, tp - tmp);
}

int
op_inet_pton_sock(const char *src, struct sockaddr_storage *dst)
{
	memset(dst, 0, sizeof(*dst));
	if (op_inet_pton(AF_INET, src, &((struct sockaddr_in *)dst)->sin_addr))
	{
		SET_SS_FAMILY(dst, AF_INET);
		SET_SS_PORT(dst, 0);
		SET_SS_LEN(dst, sizeof(struct sockaddr_in));
		return 1;
	}
	else if (op_inet_pton(AF_INET6, src, &((struct sockaddr_in6 *)dst)->sin6_addr))
	{
		SET_SS_FAMILY(dst, AF_INET6);
		SET_SS_PORT(dst, 0);
		SET_SS_LEN(dst, sizeof(struct sockaddr_in6));
		return 1;
	}
	return 0;
}

const char *
op_inet_ntop_sock(const struct sockaddr *src, char *dst, size_t size)
{
	switch (src->sa_family)
	{
	case AF_INET:
		return (op_inet_ntop(AF_INET, &((const struct sockaddr_in *)src)->sin_addr, dst, size));
	case AF_INET6:
		return (op_inet_ntop
			(AF_INET6, &((const struct sockaddr_in6 *)src)->sin6_addr, dst, size));
	default:
		return NULL;
	}
}

/* char *
 * op_inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
op_inet_ntop(int af, const void *src, char *dst, size_t size)
{
	switch (af)
	{
	case AF_INET:
		return (inet_ntop4(src, dst, size));
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)src) ||
		   IN6_IS_ADDR_V4COMPAT((const struct in6_addr *)src))
			return (inet_ntop4
				((const unsigned char *)&((const struct in6_addr *)src)->
				 s6_addr[12], dst, size));
		else
			return (inet_ntop6(src, dst, size));
	default:
		return (NULL);
	}
}

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

/* int
 * op_inet_pton(af, src, dst)
 *	convert from presentation format (which usually means ASCII printable)
 *	to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *	Paul Vixie, 1996.
 */

/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, unsigned char *dst)
{
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0')
	{

		if (ch >= '0' && ch <= '9')
		{
			unsigned int new = *tp * 10 + (ch - '0');

			if (new > 255)
				return (0);
			*tp = new;
			if (!saw_digit)
			{
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		}
		else if (ch == '.' && saw_digit)
		{
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		}
		else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */

static int
inet_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits[] = "0123456789abcdef";
	unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	const char *curtok;
	int ch, saw_xdigit;
	unsigned int val;

	tp = memset(tmp, '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = tolower((unsigned char)*src++)) != '\0')
	{
		const char *pch;

		pch = strchr(xdigits, ch);
		if (pch != NULL)
		{
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':')
		{
			curtok = src;
			if (!saw_xdigit)
			{
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			else if (*src == '\0')
			{
				return (0);
			}
			if (tp + INT16SZ > endp)
				return (0);
			*tp++ = (unsigned char)(val >> 8) & 0xff;
			*tp++ = (unsigned char)val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (*src != '\0' && ch == '.')
		{
			if (((tp + INADDRSZ) <= endp) && inet_pton4(curtok, tp) > 0)
			{
				tp += INADDRSZ;
				saw_xdigit = 0;
				break;	/* '\0' was seen by inet_pton4(). */
			}
		}
		else
			continue;
		return (0);
	}
	if (saw_xdigit)
	{
		if (tp + INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char)(val >> 8) & 0xff;
		*tp++ = (unsigned char)val & 0xff;
	}
	if (colonp != NULL)
	{
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++)
		{
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}

int
op_inet_pton(int af, const char *src, void *dst)
{
	switch (af)
	{
	case AF_INET:
		return (inet_pton4(src, dst));
	case AF_INET6:
		/* Somebody might have passed as an IPv4 address this is sick but it works */
		if (inet_pton4(src, dst))
		{
			char tmp[HOSTIPLEN];
			snprintf(tmp, sizeof(tmp), "::ffff:%s", src);
			return (inet_pton6(tmp, dst));
		}
		else
			return (inet_pton6(src, dst));
	default:
		return (-1);
	}
}


#ifndef HAVE_SOCKETPAIR

/* mostly based on perl's emulation of socketpair udp */
static int
op_inet_socketpair_udp(op_fde_t **newF1, op_fde_t **newF2)
{
	struct sockaddr_in addr[2];
	op_socklen_t size = sizeof(struct sockaddr_in);
	op_fde_t *F[2];
	op_platform_fd_t fd[2];
	int i, got;
	unsigned short port;
	struct timeval wait = { 0, 100000 };
	int max;
	fd_set rset;
	struct sockaddr_in readfrom;
	unsigned short buf[2];
	int o_errno;

	memset(&addr, 0, sizeof(addr));

	for (i = 0; i < 2; i++)
	{
		F[i] = op_socket(AF_INET, SOCK_DGRAM, 0, "udp socketpair");
		if (F[i] == NULL)
			goto failed;
		addr[i].sin_family = AF_INET;
		addr[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr[i].sin_port = 0;
		if (bind(op_get_fd(F[i]), (struct sockaddr *)&addr[i], sizeof(struct sockaddr_in)))
			goto failed;
		fd[i] = op_get_fd(F[i]);
	}

	for (i = 0; i < 2; i++)
	{
		if (getsockname(fd[i], (struct sockaddr *)&addr[i], &size))
			goto failed;
		if (size != sizeof(struct sockaddr_in))
			goto failed;
		if (connect(fd[!i], (struct sockaddr *)&addr[i], sizeof(struct sockaddr_in)) == -1)
			goto failed;
	}

	for (i = 0; i < 2; i++)
	{
		port = addr[i].sin_port;
		got = op_write(F[i], &port, sizeof(port));
		if (got != sizeof(port))
		{
			if (got == -1)
				goto failed;
			goto abort_failed;
		}
	}

	max = fd[1] > fd[0] ? fd[1] : fd[0];
	FD_ZERO(&rset);
	FD_SET(fd[0], &rset);
	FD_SET(fd[1], &rset);
	got = select(max + 1, &rset, NULL, NULL, &wait);
	if (got != 2 || !FD_ISSET(fd[0], &rset) || !FD_ISSET(fd[1], &rset))
	{
		if (got == -1)
			goto failed;
		goto abort_failed;
	}

	for (i = 0; i < 2; i++)
	{
#ifdef MSG_DONTWAIT
		int flag = MSG_DONTWAIT;
#else
		int flag = 0;
#endif
		got = recvfrom(op_get_fd(F[i]), (char *)&buf, sizeof(buf), flag,
			       (struct sockaddr *)&readfrom, &size);
		if (got == -1)
			goto failed;
		if (got != sizeof(port)
		   || size != sizeof(struct sockaddr_in)
		   || buf[0] != (unsigned short)addr[!i].sin_port
		   || readfrom.sin_family != addr[!i].sin_family
		   || readfrom.sin_addr.s_addr != addr[!i].sin_addr.s_addr
		   || readfrom.sin_port != addr[!i].sin_port)
			goto abort_failed;
	}

	*newF1 = F[0];
	*newF2 = F[1];
	return 0;

#ifdef _WIN32
#ifndef ECONNABORTED
#define	ECONNABORTED WSAECONNABORTED
#endif
#endif

      abort_failed:
	op_get_errno();
	errno = ECONNABORTED;
      failed:
	if (errno != ECONNABORTED)
		op_get_errno();
	o_errno = errno;
	if (F[0] != NULL)
		op_close(F[0]);
	if (F[1] != NULL)
		op_close(F[1]);
	errno = o_errno;
	return -1;
}


int
op_inet_socketpair(int family, int type, int protocol, op_platform_fd_t fd[2])
{
	int listener = -1;
	int connector = -1;
	int acceptor = -1;
	struct sockaddr_in listen_addr;
	struct sockaddr_in connect_addr;
	op_socklen_t size;

	if (protocol || family != AF_INET)
	{
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (!fd)
	{
		errno = EINVAL;
		return -1;
	}

	listener = socket(AF_INET, type, 0);
	if (listener == -1)
		return -1;
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listen_addr.sin_port = 0;	/* kernel choses port.  */
	if (bind(listener, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) == -1)
		goto tidy_up_and_fail;
	if (listen(listener, 1) == -1)
		goto tidy_up_and_fail;

	connector = socket(AF_INET, type, 0);
	if (connector == -1)
		goto tidy_up_and_fail;
	/* We want to find out the port number to connect to.  */
	size = sizeof(connect_addr);
	if (getsockname(listener, (struct sockaddr *)&connect_addr, &size) == -1)
		goto tidy_up_and_fail;
	if (size != sizeof(connect_addr))
		goto abort_tidy_up_and_fail;
	if (connect(connector, (struct sockaddr *)&connect_addr, sizeof(connect_addr)) == -1)
		goto tidy_up_and_fail;

	size = sizeof(listen_addr);
	acceptor = accept(listener, (struct sockaddr *)&listen_addr, &size);
	if (acceptor == -1)
		goto tidy_up_and_fail;
	if (size != sizeof(listen_addr))
		goto abort_tidy_up_and_fail;
	close(listener);
	/* Now check we are talking to ourself by matching port and host on the
	   two sockets.  */
	if (getsockname(connector, (struct sockaddr *)&connect_addr, &size) == -1)
		goto tidy_up_and_fail;
	if (size != sizeof(connect_addr)
	   || listen_addr.sin_family != connect_addr.sin_family
	   || listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
	   || listen_addr.sin_port != connect_addr.sin_port)
	{
		goto abort_tidy_up_and_fail;
	}
	fd[0] = connector;
	fd[1] = acceptor;
	return 0;

      abort_tidy_up_and_fail:
	errno = EINVAL;		/* I hope this is portable and appropriate.  */

      tidy_up_and_fail:
	{
		int save_errno = errno;
		if (listener != -1)
			close(listener);
		if (connector != -1)
			close(connector);
		if (acceptor != -1)
			close(acceptor);
		errno = save_errno;
		return -1;
	}
}

#endif


/* I/O backend descriptor — populated once by op_init_netio().
 * All fields are written before any public API is called and
 * read-only thereafter; no locking is required.               */
typedef struct {
	void (*setselect)(op_fde_t *, unsigned int, PF *, void *);
	int  (*select)(long);
	int  (*setup_fd)(op_fde_t *);
	int  (*sched_event)(struct ev_entry *, int);
	void (*unsched_event)(struct ev_entry *);
	int  (*supports_event)(void);
	void (*init_event)(void);
	void (*close_fd)(op_fde_t *);     /* optional; cleanup before fd close */
	bool (*start_pollthread)(void);   /* optional; NULL if not supported */
	void (*stop_pollthread)(void);    /* optional; NULL if not supported */
	char  name[25];
} io_ops_t;

/* Active I/O backend — zeroed until the first successful try_*(). */
static io_ops_t g_io;

const char *
op_get_iotype(void)
{
	return g_io.name;
}

static int
try_kqueue(void)
{
	if (!op_init_netio_kqueue())
	{
		g_io = (io_ops_t){
			.setselect        = op_setselect_kqueue,
			.select           = op_select_kqueue,
			.setup_fd         = op_setup_fd_kqueue,
			.sched_event      = op_kqueue_sched_event,
			.unsched_event    = op_kqueue_unsched_event,
			.init_event       = op_kqueue_init_event,
			.supports_event   = op_kqueue_supports_event,
			.start_pollthread = op_kqueue_start_pollthread,
			.stop_pollthread  = op_kqueue_stop_pollthread,
			.name             = "kqueue",
		};
		return 0;
	}
	return -1;
}

static int
try_uring(void)
{
	if (!op_init_netio_uring())
	{
		io_close_fd = op_close_fd_uring;
		g_io = (io_ops_t){
			.setselect        = op_setselect_uring,
			.select           = op_select_uring,
			.setup_fd         = op_setup_fd_uring,
			.close_fd         = op_close_fd_uring,
			.sched_event      = op_uring_sched_event,
			.unsched_event    = op_uring_unsched_event,
			.supports_event   = op_uring_supports_event,
			.init_event       = op_uring_init_event,
			.start_pollthread = op_uring_start_pollthread,
			.stop_pollthread  = op_uring_stop_pollthread,
			.name             = "uring",
		};
		return 0;
	}
	return -1;
}

static int
try_epoll(void)
{
	if (!op_init_netio_epoll())
	{
		g_io = (io_ops_t){
			.setselect        = op_setselect_epoll,
			.select           = op_select_epoll,
			.setup_fd         = op_setup_fd_epoll,
			.sched_event      = op_epoll_sched_event,
			.unsched_event    = op_epoll_unsched_event,
			.supports_event   = op_epoll_supports_event,
			.init_event       = op_epoll_init_event,
			.start_pollthread = op_epoll_start_pollthread,
			.stop_pollthread  = op_epoll_stop_pollthread,
			.name             = "epoll",
		};
		return 0;
	}
	return -1;
}

static int
try_ports(void)
{
	if (!op_init_netio_ports())
	{
		g_io = (io_ops_t){
			.setselect      = op_setselect_ports,
			.select         = op_select_ports,
			.setup_fd       = op_setup_fd_ports,
			.sched_event    = op_ports_sched_event,
			.unsched_event  = op_ports_unsched_event,
			.init_event     = op_ports_init_event,
			.supports_event = op_ports_supports_event,
			.name           = "ports",
		};
		return 0;
	}
	return -1;
}

static int
try_devpoll(void)
{
	if (!op_init_netio_devpoll())
	{
		g_io = (io_ops_t){
			.setselect = op_setselect_devpoll,
			.select    = op_select_devpoll,
			.setup_fd  = op_setup_fd_devpoll,
			.name      = "devpoll",
		};
		return 0;
	}
	return -1;
}

static int
try_sigio(void)
{
	if (!op_init_netio_sigio())
	{
		g_io = (io_ops_t){
			.setselect      = op_setselect_sigio,
			.select         = op_select_sigio,
			.setup_fd       = op_setup_fd_sigio,
			.sched_event    = op_sigio_sched_event,
			.unsched_event  = op_sigio_unsched_event,
			.supports_event = op_sigio_supports_event,
			.init_event     = op_sigio_init_event,
			.name           = "sigio",
		};
		return 0;
	}
	return -1;
}

static int
try_poll(void)
{
	if (!op_init_netio_poll())
	{
		g_io = (io_ops_t){
			.setselect = op_setselect_poll,
			.select    = op_select_poll,
			.setup_fd  = op_setup_fd_poll,
			.name      = "poll",
		};
		return 0;
	}
	return -1;
}

static int
try_iocp(void)
{
	if (!op_init_netio_iocp())
	{
		g_io = (io_ops_t){
			.setselect = op_setselect_iocp,
			.select    = op_select_iocp,
			.setup_fd  = op_setup_fd_iocp,
			.name      = "iocp",
		};
		return 0;
	}
	return -1;
}


static int
try_select(void)
{
	if (!op_init_netio_select())
	{
		g_io = (io_ops_t){
			.setselect = op_setselect_select,
			.select    = op_select_select,
			.setup_fd  = op_setup_fd_select,
			.name      = "select",
		};
		return 0;
	}
	return -1;
}


int
op_io_sched_event(struct ev_entry *ev, int when)
{
	if (ev == NULL || g_io.supports_event == NULL || g_io.sched_event == NULL
	   || !g_io.supports_event())
		return 0;
	return g_io.sched_event(ev, when);
}

void
op_io_unsched_event(struct ev_entry *ev)
{
	if (ev == NULL || g_io.supports_event == NULL || g_io.unsched_event == NULL
	   || !g_io.supports_event())
		return;
	g_io.unsched_event(ev);
}

int
op_io_supports_event(void)
{
	if (g_io.supports_event == NULL)
		return 0;
	return g_io.supports_event();
}

void
op_io_init_event(void)
{
	if (g_io.init_event != NULL)
		g_io.init_event();
	op_event_io_register_all();
}

/* Tracks whether the poll thread is currently running. */
static _Atomic(bool) g_poll_thread_active = false;

bool
op_start_pollthread(void)
{
	if (g_io.start_pollthread == NULL)
	{
		op_lib_log("op_start_pollthread: backend '%s' does not support "
		           "threaded polling", g_io.name);
		return false;
	}
	bool ok = g_io.start_pollthread();
	if (ok)
		atomic_store_explicit(&g_poll_thread_active, true, memory_order_release);
	return ok;
}

void
op_stop_pollthread(void)
{
	if (g_io.stop_pollthread != NULL)
		g_io.stop_pollthread();
	atomic_store_explicit(&g_poll_thread_active, false, memory_order_release);
}

bool
op_pollthread_active(void)
{
	return atomic_load_explicit(&g_poll_thread_active, memory_order_acquire);
}

void
op_init_netio(void)
{
	char *ioenv = getenv("LIBOP_USE_IOTYPE");
	op_fd_table = op_malloc(OP_FD_HASH_SIZE * sizeof(op_dlink_list));
	op_init_ssl();

	if (ioenv != NULL)
	{
		if (!strcmp("uring", ioenv))
		{
			if (!try_uring())
				return;
		}
		else if (!strcmp("epoll", ioenv))
		{
			if (!try_epoll())
				return;
		}
		else if (!strcmp("kqueue", ioenv))
		{
			if (!try_kqueue())
				return;
		}
		else if (!strcmp("ports", ioenv))
		{
			if (!try_ports())
				return;
		}
		else if (!strcmp("poll", ioenv))
		{
			if (!try_poll())
				return;
		}
		else if (!strcmp("devpoll", ioenv))
		{
			if (!try_devpoll())
				return;
		}
		else if (!strcmp("sigio", ioenv))
		{
			if (!try_sigio())
				return;
		}
		else if (!strcmp("select", ioenv))
		{
			if (!try_select())
				return;
		}
		else if (!strcmp("iocp", ioenv))
		{
			if (!try_iocp())
				return;
		}
	}

	if (!try_kqueue())
		return;
	if (!try_uring())
		return;
	if (!try_epoll())
		return;
	if (!try_ports())
		return;
	if (!try_devpoll())
		return;
	if (!try_sigio())
		return;
	if (!try_poll())
		return;
	if (!try_iocp())
		return;
	if (!try_select())
		return;

	op_lib_log("op_init_netio: Could not find any io handlers...giving up");

	abort();
}

void
op_setselect(op_fde_t *F, unsigned int type, PF * handler, void *client_data)
{
	g_io.setselect(F, type, handler, client_data);
}

int
op_select(long timeout)
{
	int ret = g_io.select(timeout);
	op_close_pending_fds();
	return ret;
}

int
op_setup_fd(op_fde_t *F)
{
	return g_io.setup_fd(F);
}


int
op_ignore_errno(int error)
{
	switch (error)
	{
#ifdef EINPROGRESS
	case EINPROGRESS:
#endif
#if defined EWOULDBLOCK
	case EWOULDBLOCK:
#endif
#if defined(EAGAIN) && (EWOULDBLOCK != EAGAIN)
	case EAGAIN:
#endif
#ifdef EINTR
	case EINTR:
#endif
#ifdef ERESTART
	case ERESTART:
#endif
#ifdef ENOBUFS
	case ENOBUFS:
#endif
		return 1;
	default:
		break;
	}
	return 0;
}


#if defined(HAVE_SENDMSG) && !defined(_WIN32)
int
op_recv_fd_buf(op_fde_t *F, void *data, size_t datasize, op_fde_t **xF, int nfds)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	struct stat st;
	uint8_t stype = OP_FD_UNKNOWN;
	const char *desc;
	op_platform_fd_t fd, len, x, rfds;

	/* Cap nfds to prevent an unbounded stack allocation.
	 * alloca(CMSG_SPACE(n * sizeof(int))) was here before; a large or
	 * attacker-controlled nfds would overflow the stack.  16 fds per
	 * message is far more than any caller needs.                      */
#define RECV_FD_MAX 16
	if (nfds <= 0 || nfds > RECV_FD_MAX)
	{
		errno = EINVAL;
		return -1;
	}
	char ctrl_buf[CMSG_SPACE(sizeof(int) * RECV_FD_MAX)];
	size_t control_len = CMSG_SPACE(sizeof(int) * (size_t)nfds);
#undef RECV_FD_MAX

	iov[0].iov_base = data;
	iov[0].iov_len = datasize;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	cmsg = (struct cmsghdr *)ctrl_buf;
	msg.msg_control = ctrl_buf;
	msg.msg_controllen = control_len;

	if ((len = recvmsg(op_get_fd(F), &msg, 0)) <= 0)
		return len;

	if (msg.msg_controllen > 0 && msg.msg_control != NULL
	   && (cmsg = CMSG_FIRSTHDR(&msg)) != NULL)
	{
		rfds = ((unsigned char *)cmsg + cmsg->cmsg_len - CMSG_DATA(cmsg)) / sizeof(int);

		for (x = 0; x < nfds && x < rfds; x++)
		{
			fd = ((int *)CMSG_DATA(cmsg))[x];
			stype = OP_FD_UNKNOWN;
			desc = "remote unknown";
			if (!fstat(fd, &st))
			{
				if (S_ISSOCK(st.st_mode))
				{
					stype = OP_FD_SOCKET;
					desc = "remote socket";
				}
				else if (S_ISFIFO(st.st_mode))
				{
					stype = OP_FD_PIPE;
					desc = "remote pipe";
				}
				else if (S_ISREG(st.st_mode))
				{
					stype = OP_FD_FILE;
					desc = "remote file";
				}
			}
			xF[x] = op_open(fd, stype, desc);
		}
	}
	else
		*xF = NULL;
	return len;
}


int
op_send_fd_buf(op_fde_t *xF, op_fde_t **F, int count, void *data, size_t datasize, pid_t pid __attribute__((unused)))
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	char empty = '0';

	memset(&msg, 0, sizeof(msg));
	if (datasize == 0)
	{
		iov[0].iov_base = &empty;
		iov[0].iov_len = 1;
	}
	else
	{
		iov[0].iov_base = data;
		iov[0].iov_len = datasize;
	}
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	if (count > 0)
	{
		size_t ucount = (size_t)count;
		size_t len = CMSG_SPACE(sizeof(int) * ucount);
		/* Fixed-size buffer large enough for any realistic FD count. */
		char buf[CMSG_SPACE(sizeof(int) * 16)];
		if (len > sizeof(buf)) { errno = EINVAL; return -1; }

		msg.msg_control = buf;
		msg.msg_controllen = len;
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL) { errno = EINVAL; return -1; }
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * ucount);

		for (size_t i = 0; i < ucount; i++)
		{
			((int *)CMSG_DATA(cmsg))[i] = op_get_fd(F[i]);
		}
		msg.msg_controllen = cmsg->cmsg_len;
		return sendmsg(op_get_fd(xF), &msg, MSG_NOSIGNAL);
	}
	return sendmsg(op_get_fd(xF), &msg, MSG_NOSIGNAL);
}
#else /* defined(HAVE_SENDMSG) && !defined(_WIN32) */
#ifndef _WIN32
/* Platform has no sendmsg and is not Windows — fd passing unavailable. */
int
op_recv_fd_buf(op_fde_t *F, void *data, size_t datasize, op_fde_t **xF, int nfds)
{
	(void)F; (void)data; (void)datasize; (void)xF; (void)nfds;
	errno = ENOSYS;
	return -1;
}

int
op_send_fd_buf(op_fde_t *xF, op_fde_t **F, int count, void *data, size_t datasize, pid_t pid)
{
	(void)xF; (void)F; (void)count; (void)data; (void)datasize; (void)pid;
	errno = ENOSYS;
	return -1;
}
#endif /* _WIN32 — Windows implementation is in iocp.c */
#endif /* defined(HAVE_SENDMSG) && !defined(_WIN32) */

/*
 * op_recv_fd - receive a single file descriptor from a Unix domain socket.
 *
 * A convenience wrapper around op_recv_fd_buf for the common single-FD case.
 * Returns the newly opened op_fde_t on success, or NULL if no FD was received
 * or an error occurred.
 */
op_fde_t *
op_recv_fd(op_fde_t *F)
{
	op_fde_t *xF = NULL;
	char buf[1];
	op_recv_fd_buf(F, buf, sizeof(buf), &xF, 1);
	return xF;
}

/*
 * op_pass_fd_to_process - send a single file descriptor to a helper process.
 *
 * Sends fd_to_pass over the control_sock Unix domain socket, targeting
 * the process identified by target_pid.  On Linux/BSD (SCM_RIGHTS) the
 * pid argument is unused; on Windows it is forwarded to DuplicateHandle.
 *
 * Returns the result of sendmsg(2) on success (bytes sent), or -1 on error
 * with errno set.
 */
int
op_pass_fd_to_process(op_fde_t *control_sock, pid_t target_pid, op_fde_t *fd_to_pass)
{
	return op_send_fd_buf(control_sock, &fd_to_pass, 1, NULL, 0, target_pid);
}

int
op_ipv4_from_ipv6(const struct sockaddr_in6 *restrict ip6, struct sockaddr_in *restrict ip4)
{
	int i;

	if (!memcmp(ip6->sin6_addr.s6_addr, "\x20\x02", 2))
	{
		/* 6to4 and similar */
		memcpy(&ip4->sin_addr, ip6->sin6_addr.s6_addr + 2, 4);
	}
	else if (!memcmp(ip6->sin6_addr.s6_addr, "\x20\x01\x00\x00", 4))
	{
		/* Teredo */
		for (i = 0; i < 4; i++)
			((uint8_t *)&ip4->sin_addr)[i] = 0xFF ^
				ip6->sin6_addr.s6_addr[12 + i];
	}
	else
		return 0;
	SET_SS_LEN(ip4, sizeof(struct sockaddr_in));
	ip4->sin_family = AF_INET;
	ip4->sin_port = 0;
	return 1;
}
