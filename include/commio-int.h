/*
 *  libop: ophion support library.
 *  commio-int.h: A header for the network subsystem.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2007 ircd-ratbox development team
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

#ifndef _COMMIO_INT_H
#define _COMMIO_INT_H 1

#include <op_atomic.h>

#define OP_FD_HASH_BITS 12
#define OP_FD_HASH_SIZE (1UL << OP_FD_HASH_BITS)
#define OP_FD_HASH_MASK (OP_FD_HASH_SIZE-1)

#define FD_DESC_SZ 128		/* hostlen + comment */

#define op_hash_fd(x) ((x ^ (x >> OP_FD_HASH_BITS) ^ (x >> (OP_FD_HASH_BITS * 2))) & OP_FD_HASH_MASK)

#ifdef HAVE_WRITEV
#ifndef UIO_MAXIOV
# if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__)
			/* FreeBSD 4.7 defines it in sys/uio.h only if _KERNEL is specified */
#  define OP_UIO_MAXIOV 1024
# elif defined(__sgi)
			/* IRIX 6.5 has sysconf(_SC_IOV_MAX) which might return 512 or bigger */
#  define OP_UIO_MAXIOV 512
# elif defined(__sun)
			/* Solaris (and SunOS?) defines IOV_MAX instead */
#  ifndef IOV_MAX
#   define OP_UIO_MAXIOV 16
#  else
#   define OP_UIO_MAXIOV IOV_MAX
#  endif

# elif defined(IOV_MAX)
#  define OP_UIO_MAXIOV IOV_MAX
# else
#  define OP_UIO_MAXIOV 16
# endif
#else
#define OP_UIO_MAXIOV UIO_MAXIOV
#endif
#else
#define OP_UIO_MAXIOV 16
#endif
struct conndata
{
	struct op_sockaddr_storage S;
	struct op_sockaddr_storage hostaddr;
	time_t t;
	CNCB *callback;
	void *data;
};

struct acceptdata
{
	struct op_sockaddr_storage S;
	op_socklen_t addrlen;
	ACCB *callback;
	ACPRE *precb;
	void *data;
};

/* Internal per-fd flags */
#define FLAG_OPEN       0x1   /* fd is live */
#define FLAG_ZEROCOPY   0x2   /* SO_ZEROCOPY set; use MSG_ZEROCOPY for sends */
#define IsFDOpen(F)     (F->flags & FLAG_OPEN)
#define SetFDOpen(F)    (F->flags |= FLAG_OPEN)
#define ClearFDOpen(F)  (F->flags &= ~FLAG_OPEN)

#if !defined(SHUT_RDWR) && defined(_WIN32)
# define SHUT_RDWR SD_BOTH
#endif

struct _fde
{
	/*
	 * One pending read and one pending write per file descriptor.
	 *
	 * pflags_lock serialises op_setselect() so worker threads can safely
	 * arm WRITE interest (e.g. after filling a client send queue) while
	 * the I/O thread may concurrently modify the same fields.
	 */
	op_dlink_node node;
	op_platform_fd_t fd;			/* So we can use the op_fde_t as a callback ptr */
	uint8_t  flags;
	uint16_t type;
	int pflags;
	pthread_spinlock_t pflags_lock;
	char *desc;
	PF *read_handler;
	void *read_data;
	PF *write_handler;
	void *write_data;
	struct timeout_data *timeout;
	struct conndata *connect;
	struct acceptdata *accept;
	void *ssl;
	void *ws;
	bool ktls;         /* true: kernel TLS active; I/O bypasses opssl */
	bool tls_outgoing; /* true: TLS was initiated outgoing (client side) */
	unsigned int handshake_count;
	uint64_t ssl_errno;  /* SSL error code; uint64_t for portability (matches ERR_get_error size) */
	/* Incremented on each io_uring POLL_ADD submission; packed into sqe
	 * user_data so stale CQEs for a recycled op_fde_t can be discarded. */
	uint32_t uring_gen;
	/* Deferred SQE submission: workers push dirty fdes to a Treiber stack
	 * instead of acquiring uring_sqlock.  The I/O thread drains the stack
	 * and batch-submits all pending SQEs. */
	_Atomic(struct _fde *) uring_dirty_next;
	_Atomic(uint8_t)       uring_dirty;
	int                    uring_fixed_idx;  /* registered file slot, or -1 */
	time_t                 uring_last_cqe_time;  /* timestamp of last CQE for staleness detection */
};

typedef void (*comm_event_cb_t) (void *);

#ifdef USE_TIMER_CREATE
typedef struct timer_data
{
	timer_t td_timer_id;
	comm_event_cb_t td_cb;
	void *td_udata;
	int td_repeat;
} *comm_event_id;
#endif

extern op_dlink_list *op_fd_table;

static inline op_fde_t *
op_find_fd(op_platform_fd_t fd)
{
	op_dlink_list *hlist;
	op_dlink_node *ptr;

	if (op_unlikely(fd < 0))
		return NULL;

	hlist = &op_fd_table[op_hash_fd(fd)];

	if (hlist->head == NULL)
		return NULL;

	OP_DLINK_FOREACH(ptr, hlist->head)
	{
		op_fde_t *F = ptr->data;
		if (F->fd == fd)
			return F;
	}
	return NULL;
}


int op_setup_fd(op_fde_t *F);
void op_connect_callback(op_fde_t *F, int status);
struct conndata *op_conndata_alloc(void);
void op_conndata_free(struct conndata *cd);
struct acceptdata *op_acceptdata_alloc(void);
void op_acceptdata_free(struct acceptdata *ad);


int op_io_sched_event(struct ev_entry *ev, int when);
void op_io_unsched_event(struct ev_entry *ev);
int op_io_supports_event(void);
void op_io_init_event(void);
bool op_start_pollthread(void);
void op_stop_pollthread(void);
bool op_pollthread_active(void);

/* io_uring versions */
void op_setselect_uring(op_fde_t *F, unsigned int type, PF *handler, void *client_data);
int  op_init_netio_uring(void);
int  op_select_uring(long);
int  op_setup_fd_uring(op_fde_t *F);
void op_close_fd_uring(op_fde_t *F);

void op_uring_init_event(void);
int  op_uring_sched_event(struct ev_entry *event, int when);
void op_uring_unsched_event(struct ev_entry *event);
int  op_uring_supports_event(void);
bool op_uring_start_pollthread(void);
void op_uring_stop_pollthread(void);


/* epoll versions */
void op_setselect_epoll(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_epoll(void);
int op_select_epoll(long);
int op_setup_fd_epoll(op_fde_t *F);

void op_epoll_init_event(void);
int op_epoll_sched_event(struct ev_entry *event, int when);
void op_epoll_unsched_event(struct ev_entry *event);
int op_epoll_supports_event(void);
bool op_epoll_start_pollthread(void);
void op_epoll_stop_pollthread(void);


/* poll versions */
void op_setselect_poll(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_poll(void);
int op_select_poll(long);
int op_setup_fd_poll(op_fde_t *F);

/* devpoll versions */
void op_setselect_devpoll(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_devpoll(void);
int op_select_devpoll(long);
int op_setup_fd_devpoll(op_fde_t *F);

/* sigio versions */
void op_setselect_sigio(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_sigio(void);
int op_select_sigio(long);
int op_setup_fd_sigio(op_fde_t *F);

void op_sigio_init_event(void);
int op_sigio_sched_event(struct ev_entry *event, int when);
void op_sigio_unsched_event(struct ev_entry *event);
int op_sigio_supports_event(void);


/* ports versions */
void op_setselect_ports(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_ports(void);
int op_select_ports(long);
int op_setup_fd_ports(op_fde_t *F);

void op_ports_init_event(void);
int op_ports_sched_event(struct ev_entry *event, int when);
void op_ports_unsched_event(struct ev_entry *event);
int op_ports_supports_event(void);


/* kqueue versions */
void op_setselect_kqueue(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_kqueue(void);
int op_select_kqueue(long);
int op_setup_fd_kqueue(op_fde_t *F);

void op_kqueue_init_event(void);
int op_kqueue_sched_event(struct ev_entry *event, int when);
void op_kqueue_unsched_event(struct ev_entry *event);
int op_kqueue_supports_event(void);
bool op_kqueue_start_pollthread(void);
void op_kqueue_stop_pollthread(void);


/* select versions */
void op_setselect_select(op_fde_t *F, unsigned int type, PF * handler, void *client_data);
int op_init_netio_select(void);
int op_select_select(long);
int op_setup_fd_select(op_fde_t *F);

/* iocp versions (Windows I/O Completion Ports) */
void op_setselect_iocp(op_fde_t *F, unsigned int type, PF *handler, void *client_data);
int  op_init_netio_iocp(void);
int  op_select_iocp(long);
int  op_setup_fd_iocp(op_fde_t *F);
#endif

