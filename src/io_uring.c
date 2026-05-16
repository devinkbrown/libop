/*
 * libop: ophion support library.
 * io_uring.c: Linux io_uring event backend (POLL_ADD + kTLS peek-recv).
 *
 * Uses io_uring's IORING_OP_POLL_ADD in oneshot or multishot mode as a
 * drop-in replacement for epoll.  Each op_fde_t with read or write
 * interest gets a POLL_ADD SQE; the CQE fires when the fd is ready,
 * the handler is dispatched, and the fd is re-armed if interest still
 * exists after dispatch.
 *
 * For kTLS sockets on kernels where POLL_ADD stalls (kernel 6.x), a
 * transparent fallback submits io_uring_prep_recv(MSG_PEEK) instead.
 * The kernel holds the recv SQE async until data arrives, bypassing
 * the broken poll wakeup path.  See URING_F_KTLS_PEEK.
 *
 * Event scheduling (timers, signals) delegates to the epoll backend's
 * timerfd/signalfd infrastructure — timerfd is just another pollable fd.
 *
 * Thread safety
 * -------------
 * Worker threads may call op_setselect_uring() concurrently with the I/O
 * thread running op_select_uring().
 *
 *   F->pflags_lock  — per-fd spinlock; guards handler pointers, F->pflags,
 *                     and the URING_F_PENDING flag within F->pflags.
 *
 *   uring_sqlock    — global spinlock; serialises SQ ring access between
 *                     the I/O thread (uring_flush_dirty) and the CQ poll
 *                     thread (io_uring_submit + io_uring_wait_cqe_timeout).
 *
 * Workers NEVER acquire uring_sqlock.  Instead, op_setselect_uring() pushes
 * the fde to a lock-free Treiber stack (uring_dirty_inbox).  The I/O thread
 * drains the stack in uring_flush_dirty(), batch-submits SQEs under
 * uring_sqlock, and calls io_uring_submit() once for the entire batch.
 *
 * Lock order: F->pflags_lock THEN uring_sqlock (never the reverse).
 *
 * Generation numbers
 * ------------------
 * Each POLL_ADD SQE embeds a (fd, gen) pair as its user_data.  The
 * generation counter (F->uring_gen, uint32_t) is incremented on every
 * submission.  A CQE is discarded if its generation does not match the
 * current F->uring_gen, preventing stale events from firing handlers on
 * an fd that has been recycled or re-registered.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1

#include <pthread.h>
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <event-int.h>

#if defined(HAVE_LIBURING)
#define USING_URING

#include <liburing.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <sys/utsname.h>

/*
 * URING_F_PENDING: set in F->pflags while a POLL_ADD CQE is in-flight.
 * Prevents duplicate submissions from op_arm_uring.
 * Stored in a high bit of pflags that POLLIN/POLLOUT never occupy.
 *
 * URING_F_MULTISHOT: set when the in-flight POLL_ADD is multi-shot.
 * Multi-shot polls stay armed across CQEs — no re-arm needed.
 * Cancel + re-arm only when the interest mask changes.
 *
 * URING_ARMED_MASK: bits 18-19 store the armed POLLIN/POLLOUT mask
 * so we can detect interest changes without an extra field.
 */
#define URING_F_PENDING    (1U << 16)
#define URING_F_MULTISHOT  (1U << 17)
#define URING_F_KTLS_PEEK  (1U << 20)  /* armed via recv(MSG_PEEK), not POLL_ADD */
#define URING_ARMED_SHIFT  18
#define URING_ARMED_MASK   (0x3U << URING_ARMED_SHIFT)
#define URING_ARMED_IN     (1U << URING_ARMED_SHIFT)   /* POLLIN was armed */
#define URING_ARMED_OUT    (1U << (URING_ARMED_SHIFT+1)) /* POLLOUT was armed */

/*
 * Ring depth.  Rounded up to the nearest power-of-two at init time based
 * on getdtablesize(); capped at URING_RING_DEPTH_MAX.  The ring must hold
 * at least one SQE per fd that could be simultaneously armed.
 */
#define URING_RING_DEPTH_MAX  65536
#define URING_RING_DEPTH_MIN  256

static struct io_uring uring;
static pthread_spinlock_t uring_sqlock;
static int uring_has_defer_taskrun  = 0;  /* set if DEFER_TASKRUN is active */
static int uring_has_sqpoll        = 0;  /* set if SQPOLL kernel thread is active */
static int uring_has_fixed_files   = 0;  /* set if registered file table active */
static int uring_has_multishot     = 0;  /* set if IORING_POLL_ADD_MULTI works */
static unsigned int uring_fixed_file_cap = 0;  /* number of slots in fixed table */

/* ---- Worker → I/O thread wake-up ---------------------------------------- */

/*
 * With DEFER_TASKRUN the I/O thread blocks in io_uring_wait_cqe() and only
 * wakes when a CQE arrives.  Worker threads that mark fdes dirty via
 * uring_mark_dirty() need a way to wake the I/O thread so it flushes the
 * dirty list promptly.
 *
 * We create an eventfd and register a POLL_ADD for it in the io_uring ring.
 * Workers write to the eventfd, generating a POLLIN CQE that breaks the
 * I/O thread out of io_uring_wait_cqe().  The CQE dispatch loop recognises
 * the sentinel tag (URING_WAKEUP_TAG) and consumes the eventfd counter.
 */
static int               uring_wakeup_fd   = -1;
static pthread_t         uring_io_tid;       /* I/O thread that calls op_select_uring */
static int               uring_io_tid_set  = 0;

/* Sentinel user_data for the eventfd wake-up CQE. */
#define URING_WAKEUP_TAG  (UINT64_MAX - 1)

/* Arm a POLL_ADD for the wake-up eventfd.  Called from the I/O thread
 * during init and after each wake-up CQE (re-arm for oneshot mode). */
static void
uring_arm_wakeup(void)
{
	if (uring_wakeup_fd < 0)
		return;

	struct io_uring_sqe *sqe = io_uring_get_sqe(&uring);
	if (sqe == NULL)
	{
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
	}
	if (sqe == NULL)
		return;

	io_uring_prep_poll_add(sqe, uring_wakeup_fd, POLLIN);
#if defined(IORING_POLL_ADD_MULTI)
	if (uring_has_multishot)
		sqe->len |= IORING_POLL_ADD_MULTI;
#endif
	io_uring_sqe_set_data64(sqe, URING_WAKEUP_TAG);
}

/* ---- Deferred SQE submission (Treiber stack) ----------------------------- */

/*
 * Workers mark fdes "dirty" via a lock-free Treiber stack instead of directly
 * accessing the SQ ring.  The I/O thread drains the stack before each
 * io_uring_wait_cqe() and batch-submits all pending SQEs under uring_sqlock.
 *
 * This eliminates uring_sqlock from the worker hot path entirely.  The lock
 * is only contended between the I/O thread and the CQ poll thread (2 threads
 * instead of N+2).
 */
static _Atomic(op_fde_t *) uring_dirty_inbox = NULL;

/* Push F to the dirty list if not already there (idempotent).
 *
 * Guard against closed/freed FDEs: worker threads may hold stale op_fde_t
 * pointers after close_connection() runs on the main thread.  The IsFDOpen
 * check is racy (flags is not atomic), but the worst case is a benign push
 * of a closed-but-not-yet-freed FDE — uring_flush_dirty() skips it, and
 * op_close_pending_fds() defers freeing while uring_dirty is set.
 */
static inline void
uring_mark_dirty(op_fde_t *F)
{
	if (!IsFDOpen(F))
		return;

	if (atomic_exchange_explicit(&F->uring_dirty, 1, memory_order_relaxed))
		return;  /* already in the dirty list */

	op_fde_t *old_top = atomic_load_explicit(&uring_dirty_inbox,
	                                         memory_order_relaxed);
	do {
		atomic_store_explicit(&F->uring_dirty_next, old_top,
		                      memory_order_relaxed);
	} while (!atomic_compare_exchange_weak_explicit(
		&uring_dirty_inbox, &old_top, F,
		memory_order_release, memory_order_relaxed));
}

/* ---- io_uring CQ poll thread --------------------------------------------- */

/*
 * uring_event_t — packed CQE snapshot for the inter-thread ring.
 *
 * The CQ poll thread extracts these fields and calls io_uring_cq_advance()
 * while still owning the CQ.  The main thread reconstructs op_fde_t * from
 * the fd/gen pair and dispatches the handler.
 */
typedef struct
{
	uint64_t tag;     /* (cqe_fd << 32 | cqe_gen) — matches op_arm_uring encoding */
	int      res;     /* cqe->res                                                  */
	uint32_t flags;   /* cqe->flags (for IORING_CQE_F_MORE multi-shot detection)   */
} uring_event_t;

/*
 * URING_RING_CAP — capacity of the SPSC event ring.
 * Must be a power of two.  Sized to absorb a full burst without blocking.
 */
#define URING_RING_CAP  65536u

typedef struct
{
	_Atomic(uint32_t)  head;          /* producer cursor (CQ thread)  */
	char               _pad0[60];
	_Atomic(uint32_t)  tail;          /* consumer cursor (main thread) */
	char               _pad1[60];
	uring_event_t      slots[URING_RING_CAP];
} uring_cq_ring_t;

static uring_cq_ring_t   uring_cq_ring __attribute__((aligned(64)));
static int               uring_notify_fd    = -1;
static pthread_t         uring_poll_tid;
static volatile int      uring_thread_stop  = 0;
static int               uring_thread_active = 0;

/* Forward declaration — defined after op_select_uring. */
static void uring_dispatch_from_ring(void);

static inline bool
uring_ring_push(uring_cq_ring_t *r, const uring_event_t *ev)
{
	uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
	if (h - t >= URING_RING_CAP)
		return false;
	r->slots[h & (URING_RING_CAP - 1)] = *ev;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);
	return true;
}

static inline bool
uring_ring_pop(uring_cq_ring_t *r, uring_event_t *ev)
{
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
	if (t == h)
		return false;
	*ev = r->slots[t & (URING_RING_CAP - 1)];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);
	return true;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Round n up to the next power of two (n > 0). */
static __attribute__((const)) unsigned int
round_pow2(unsigned int n)
{
	n--;
	n |= n >> 1; n |= n >> 2; n |= n >> 4;
	n |= n >> 8; n |= n >> 16;
	return n + 1;
}

/*
 * op_arm_uring — submit a POLL_ADD SQE for F.
 *
 * Caller MUST hold F->pflags_lock AND uring_sqlock.
 *
 * Returns 1 if the SQE was queued, 0 if the ring was full and the arm
 * could not be completed (logged as a warning; the fd will be retried
 * on the next dirty-list drain cycle).
 */
static int
op_arm_uring(op_fde_t *F)
{
	struct io_uring_sqe *sqe;
	unsigned int mask = 0;

	if (F->read_handler  != NULL) mask |= POLLIN;
	if (F->write_handler != NULL) mask |= POLLOUT;
	if (mask == 0)
		return 1;  /* Nothing to arm — not an error. */

	/*
	 * kTLS peek-recv path: on kernel 6.x the poll wakeup path is broken
	 * for kTLS sockets — POLL_ADD CQEs silently stall.  Instead, submit
	 * a zero-copy recv(MSG_PEEK) that the kernel holds async until data
	 * (or EOF/error) arrives.  The CQE fires with res>0 (data available),
	 * res==0 (EOF), or res<0 (error).
	 *
	 * Only used when:
	 *  - The fd has kTLS active
	 *  - The kernel does NOT have working multishot (i.e. kernel < 7.0)
	 *  - POLLIN interest exists (read_handler set)
	 *
	 * POLLOUT interest is handled by a separate regular poll SQE if needed,
	 * since writes don't go through kTLS recv path.
	 */
	if (F->ktls && !uring_has_multishot && (mask & POLLIN))
	{
		/* Submit peek-recv for read notification. */
		sqe = io_uring_get_sqe(&uring);
		if (sqe == NULL)
		{
			io_uring_submit(&uring);
			sqe = io_uring_get_sqe(&uring);
		}
		if (__builtin_expect(sqe == NULL, 0))
		{
			op_lib_log("op_arm_uring: SQ ring full (ktls peek); fd=%d",
			           F->fd);
			return 0;
		}

		F->uring_gen++;

		if (F->uring_fixed_idx >= 0)
		{
			io_uring_prep_recv(sqe, F->uring_fixed_idx, NULL, 1, MSG_PEEK);
			sqe->flags |= IOSQE_FIXED_FILE;
		}
		else
		{
			io_uring_prep_recv(sqe, F->fd, NULL, 1, MSG_PEEK);
		}

		io_uring_sqe_set_data64(sqe,
		    ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen);

		F->pflags |= URING_F_PENDING | URING_F_KTLS_PEEK;
		F->pflags &= ~(URING_F_MULTISHOT | URING_ARMED_MASK);
		F->pflags |= URING_ARMED_IN;

		/* If POLLOUT interest also exists, submit a separate poll SQE.
		 * Write readiness uses normal poll (not affected by kTLS bug). */
		if (mask & POLLOUT)
		{
			struct io_uring_sqe *wsqe = io_uring_get_sqe(&uring);
			if (wsqe == NULL)
			{
				io_uring_submit(&uring);
				wsqe = io_uring_get_sqe(&uring);
			}
			if (wsqe != NULL)
			{
				if (F->uring_fixed_idx >= 0)
				{
					io_uring_prep_poll_add(wsqe, F->uring_fixed_idx, POLLOUT);
					wsqe->flags |= IOSQE_FIXED_FILE;
				}
				else
				{
					io_uring_prep_poll_add(wsqe, F->fd, POLLOUT);
				}
				/* Share same user_data — the CQE dispatch checks
				 * KTLS_PEEK flag to distinguish. Poll CQE has
				 * res with POLLOUT bitmask set. */
				io_uring_sqe_set_data64(wsqe,
				    ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen);
				F->pflags |= URING_ARMED_OUT;
			}
		}

		return 1;
	}

	sqe = io_uring_get_sqe(&uring);
	if (sqe == NULL)
	{
		/* SQ ring full — flush and retry once. */
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
	}

	if (__builtin_expect(sqe == NULL, 0))
	{
		op_lib_log("op_arm_uring: SQ ring full after flush; fd=%d will not be armed",
		           F->fd);
		return 0;
	}

	F->uring_gen++;

	if (F->uring_fixed_idx >= 0)
	{
		io_uring_prep_poll_add(sqe, F->uring_fixed_idx, mask);
		sqe->flags |= IOSQE_FIXED_FILE;
	}
	else
	{
		io_uring_prep_poll_add(sqe, F->fd, mask);
	}

#if defined(IORING_POLL_ADD_MULTI)
	if (uring_has_multishot)
		sqe->len |= IORING_POLL_ADD_MULTI;
#endif

	io_uring_sqe_set_data64(sqe,
	    ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen);

	F->pflags |= URING_F_PENDING;
	F->pflags &= ~URING_F_KTLS_PEEK;  /* ensure peek flag is clear for poll path */

	/* Record armed interest so we can detect changes later. */
	F->pflags &= ~URING_ARMED_MASK;
	if (mask & POLLIN)  F->pflags |= URING_ARMED_IN;
	if (mask & POLLOUT) F->pflags |= URING_ARMED_OUT;

#if defined(IORING_POLL_ADD_MULTI)
	if (uring_has_multishot)
	{
		F->pflags |= URING_F_MULTISHOT;
		/* Initialize staleness timer for multishot polls. */
		F->uring_last_cqe_time = op_current_time();
	}
	else
		F->pflags &= ~URING_F_MULTISHOT;
#endif

	return 1;
}

/*
 * op_cancel_uring — cancel an in-flight POLL_ADD for F.
 *
 * Called when all handlers are cleared while URING_F_PENDING is set.
 * Submits IORING_OP_ASYNC_CANCEL targeting the specific (fd, gen) user_data
 * to avoid cancelling a re-arm that raced ahead.
 *
 * Caller MUST hold F->pflags_lock AND uring_sqlock.
 *
 * Cancellation is best-effort: if the CQE has already landed in the ring,
 * the cancel CQE arrives with -ENOENT and the original CQE is processed
 * normally (the generation check then discards it since we increment gen).
 */
static void
op_cancel_uring(op_fde_t *F)
{
	struct io_uring_sqe *sqe;
	uint64_t target;

	/* Record the user_data we want to cancel BEFORE incrementing gen so the
	 * cancel targets the in-flight SQE, then bump gen to invalidate it. */
	target = ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen;
	F->uring_gen++;           /* invalidate any arriving CQE for old gen */
	F->pflags &= ~URING_F_PENDING;

	sqe = io_uring_get_sqe(&uring);
	if (sqe == NULL)
	{
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
	}

	if (__builtin_expect(sqe != NULL, 1))
	{
#if defined(IORING_ASYNC_CANCEL_USERDATA)
		io_uring_prep_cancel64(sqe, target, 0);
#else
		/* Older kernels: cancel by user_data (best-effort). */
		io_uring_prep_cancel(sqe, (void *)(uintptr_t)target, 0);
#endif
		/* Use a sentinel data value so the cancel CQE is identifiable
		 * and silently discarded in the dispatch loop. */
		io_uring_sqe_set_data64(sqe, UINT64_MAX);

#if defined(IOSQE_CQE_SKIP_SUCCESS)
		/* Skip CQE generation on successful cancel — the sentinel tag
		 * is only needed if the cancel fails (CQE with -ENOENT).
		 * This reduces CQ traffic under heavy interest-change load. */
		sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
#endif
	}
}

/*
 * uring_flush_dirty — drain the deferred-arm Treiber stack and batch-submit.
 *
 * Called by the I/O thread before io_uring_wait_cqe() and after CQE dispatch.
 * Acquires uring_sqlock once for the entire batch, processes all dirty fdes,
 * then calls io_uring_submit() to flush everything to the kernel.
 *
 * Workers never touch uring_sqlock — they only mark dirty and push to the
 * atomic inbox.  The only uring_sqlock contention is between this function
 * (I/O thread) and the CQ poll thread's io_uring_submit (2 threads, not N+2).
 */
static void
uring_flush_dirty(void)
{
	op_fde_t *list = atomic_exchange_explicit(&uring_dirty_inbox, NULL,
	                                          memory_order_acquire);
	if (list == NULL)
		return;

	/* Reverse Treiber stack (LIFO → FIFO) for submission fairness. */
	op_fde_t *rev = NULL;
	while (list)
	{
		op_fde_t *next = atomic_load_explicit(&list->uring_dirty_next,
		                                      memory_order_relaxed);
		atomic_store_explicit(&list->uring_dirty_next, rev,
		                      memory_order_relaxed);
		rev = list;
		list = next;
	}

	pthread_spin_lock(&uring_sqlock);

	while (rev)
	{
		op_fde_t *F = rev;
		rev = atomic_load_explicit(&F->uring_dirty_next,
		                           memory_order_relaxed);
		atomic_store_explicit(&F->uring_dirty, 0, memory_order_relaxed);

		if (!IsFDOpen(F))
			continue;

		pthread_spin_lock(&F->pflags_lock);

		int has_handlers = (F->read_handler != NULL
		                 || F->write_handler != NULL);
		int is_pending   = (F->pflags & URING_F_PENDING) != 0;

		if (has_handlers && !is_pending)
		{
			F->pflags &= ~URING_F_KTLS_PEEK;
			if (!op_arm_uring(F))
				uring_mark_dirty(F);
		}
		else if (!has_handlers && is_pending)
		{
			F->pflags &= ~URING_F_KTLS_PEEK;
			op_cancel_uring(F);
		}
		else if (has_handlers && is_pending
		         && (F->pflags & URING_F_KTLS_PEEK))
		{
			/* kTLS peek-recv active but interest changed (e.g. write
			 * handler added/removed).  Cancel the in-flight recv and
			 * re-arm with current interest. */
			unsigned int want = 0;
			if (F->read_handler  != NULL) want |= URING_ARMED_IN;
			if (F->write_handler != NULL) want |= URING_ARMED_OUT;
			unsigned int have = F->pflags & URING_ARMED_MASK;
			if (want != have)
			{
				op_cancel_uring(F);
				F->pflags &= ~URING_F_KTLS_PEEK;
				if (!op_arm_uring(F))
					uring_mark_dirty(F);
			}
		}
		else if (has_handlers && is_pending
		         && (F->pflags & URING_F_MULTISHOT))
		{
			/* Multi-shot poll active: keep the kernel poll mask exactly
			 * aligned with active handlers.  POLLOUT is level-triggered
			 * on almost every TCP socket; arming it without a write
			 * handler creates a permanent CQE storm that starves the IRC
			 * loop and makes both plain and TLS clients appear to hang. */
			unsigned int want = 0;
			if (F->read_handler  != NULL) want |= URING_ARMED_IN;
			if (F->write_handler != NULL) want |= URING_ARMED_OUT;
			unsigned int have = F->pflags & URING_ARMED_MASK;
			if (want != have)
			{
				op_cancel_uring(F);
				if (!op_arm_uring(F))
					uring_mark_dirty(F);
			}
			/* Safety net: if multishot poll has been silent for too long,
			 * force a cancel+re-arm to recover from silently dead polls.
			 * This handles the case where the final CQE (without CQE_F_MORE)
			 * was dropped due to SPSC ring overflow or other issue. */
			else if (op_current_time() - F->uring_last_cqe_time > 30)
			{
				op_cancel_uring(F);
				if (!op_arm_uring(F))
					uring_mark_dirty(F);
			}
		}
		/* else: oneshot pending (CQE in-flight, will re-arm on arrival)
		 * or both clear (nothing to do). */

		pthread_spin_unlock(&F->pflags_lock);
	}

	/* Batch-submit all queued SQEs in one syscall. */
	io_uring_submit(&uring);

	pthread_spin_unlock(&uring_sqlock);
}


/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

int
op_init_netio_uring(void)
{
	unsigned int depth;
	unsigned int flags = 0;

	/* Scale ring depth to the fd table size, rounded to power-of-two. */
	{
		int dtsize = getdtablesize();
		unsigned int want = (unsigned int)(dtsize > 0 ? dtsize : 1024) * 2;
		depth = round_pow2(want);
		if (depth < URING_RING_DEPTH_MIN) depth = URING_RING_DEPTH_MIN;
		if (depth > URING_RING_DEPTH_MAX) depth = URING_RING_DEPTH_MAX;
	}

	/*
	 * IORING_SETUP_COOP_TASKRUN (Linux 5.19): defer task_work to the
	 * io_uring submission/wait path, reducing context-switch overhead.
	 *
	 * IORING_SETUP_TASKRUN_FLAG (Linux 5.19): must accompany COOP_TASKRUN
	 * when IORING_SETUP_DEFER_TASKRUN is not set.
	 *
	 * IORING_SETUP_CLAMP (Linux 5.6): silently clamp ring size if the
	 * requested depth exceeds the kernel's internal limit.
	 *
	 * Each flag is guarded by its own HAVE_ test (set by configure) so the
	 * code degrades gracefully on older kernels.
	 */
#if defined(IORING_SETUP_CLAMP)
	flags |= IORING_SETUP_CLAMP;
#endif

#if defined(IORING_SETUP_SUBMIT_ALL)
	/* Process all SQEs even if one fails, instead of stopping at the first
	 * error.  Prevents a bad cancel or stale SQE from blocking valid arms. */
	flags |= IORING_SETUP_SUBMIT_ALL;
#endif

#if defined(IORING_SETUP_NO_SQARRAY)
	/* Remove the SQ index array indirection.  Since we always fill SQEs
	 * sequentially (never reorder), the array is pure overhead.  Linux 6.6+. */
	flags |= IORING_SETUP_NO_SQARRAY;
#endif

	/*
	 * IORING_SETUP_SINGLE_ISSUER (6.0): promise that only one thread submits
	 * SQEs, allowing the kernel to skip cross-thread bookkeeping.
	 *
	 * IORING_SETUP_DEFER_TASKRUN (6.1): defer all async completion work to
	 * the submitter's io_uring_enter() call instead of using IPIs/task_work.
	 * Requires SINGLE_ISSUER.  Dramatically reduces interrupt overhead under
	 * load — completions are batched and processed synchronously.
	 *
	 * IORING_SETUP_SQPOLL (5.1): kernel-side SQ polling thread eliminates
	 * io_uring_enter() for submissions.  Incompatible with DEFER_TASKRUN;
	 * used as a fallback when DEFER_TASKRUN is unavailable.
	 *
	 * IORING_SETUP_COOP_TASKRUN (5.19): cooperative task_work delivery as a
	 * fallback when neither DEFER_TASKRUN nor SQPOLL is available.
	 */
#if defined(IORING_SETUP_COOP_TASKRUN) && defined(IORING_SETUP_TASKRUN_FLAG)
	/* COOP_TASKRUN: completions delivered cooperatively on the next kernel
	 * entry rather than via IPIs.  Lower overhead than plain mode while
	 * avoiding the missed-wakeup issues observed with DEFER_TASKRUN on
	 * kernel 6.12 (polls silently stall despite data being available).
	 * SINGLE_ISSUER enables additional kernel optimisations. */
	flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
#if defined(IORING_SETUP_SINGLE_ISSUER)
	flags |= IORING_SETUP_SINGLE_ISSUER;
#endif
#elif defined(IORING_SETUP_SQPOLL)
	flags |= IORING_SETUP_SQPOLL;
#endif

	unsigned int init_flags = flags;
	if (io_uring_queue_init(depth, &uring, flags) < 0)
	{
		/* Retry without performance flags in case the kernel rejects them.
		 * SQPOLL requires CAP_SYS_NICE or root on older kernels; fall back
		 * to COOP_TASKRUN or plain mode. */
		if (flags != 0)
		{
#if defined(IORING_SETUP_COOP_TASKRUN) && defined(IORING_SETUP_TASKRUN_FLAG)
			init_flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
#if defined(IORING_SETUP_CLAMP)
			init_flags |= IORING_SETUP_CLAMP;
#endif
			if (io_uring_queue_init(depth, &uring, init_flags) < 0)
#endif
			{
				init_flags = 0;
				if (io_uring_queue_init(depth, &uring, 0) < 0)
					return -1;
			}
		}
		else
			return -1;
	}

#if defined(IORING_SETUP_DEFER_TASKRUN)
	uring_has_defer_taskrun = (init_flags & IORING_SETUP_DEFER_TASKRUN) != 0;
#endif
#if defined(IORING_SETUP_SQPOLL)
	uring_has_sqpoll = (init_flags & IORING_SETUP_SQPOLL) != 0;
#endif

#if defined(IORING_POLL_ADD_MULTI)
	/* Multishot poll is broken on kernel 6.x: CQEs silently stop
	 * firing for level-triggered polls regardless of task delivery mode.
	 * Kernel 7.0+ fixes this.  Probe at runtime via uname(). */
	{
		struct utsname uts;
		int kmajor = 0;

		if (uname(&uts) == 0)
			kmajor = atoi(uts.release);
		uring_has_multishot = (kmajor >= 7);
	}
#endif

	pthread_spin_init(&uring_sqlock, PTHREAD_PROCESS_PRIVATE);

	/* Register a sparse fixed file table.  This eliminates the kernel's
	 * fget/fput (atomic refcount + RCU) on every SQE that uses IOSQE_FIXED_FILE.
	 * We use the fd number as the slot index for O(1) lookup. */
#if defined(IORING_REGISTER_FILES2) || defined(IORING_REGISTER_FILES)
	{
		int dtsize = getdtablesize();
		if (dtsize > 0 && (unsigned)dtsize <= URING_RING_DEPTH_MAX)
		{
			/* io_uring_register_files_sparse: all slots start empty (-1). */
			int rc = io_uring_register_files_sparse(&uring, (unsigned)dtsize);
			if (rc == 0)
			{
				uring_has_fixed_files  = 1;
				uring_fixed_file_cap   = (unsigned)dtsize;
			}
		}
	}
#endif

	/* NAPI busy-poll: spin on the NIC's receive queue before sleeping.
	 * Reduces network latency by ~5-15 µs by avoiding the interrupt →
	 * softirq → wakeup chain.  Requires NET_RX_BUSY_POLL sysctl and
	 * a NIC driver that supports NAPI.  Best-effort: silently ignored
	 * if the kernel or driver doesn't support it. */
#if defined(IORING_REGISTER_NAPI)
	{
		struct io_uring_napi napi = {
			.busy_poll_to = 50,  /* µs to spin before sleeping */
			.prefer_busy_poll = 1,
		};
		(void)io_uring_register_napi(&uring, &napi);
	}
#endif

	/* Create the worker → I/O thread wake-up eventfd.
	 * In DEFER_TASKRUN mode (no CQ poll thread), this is the only way for
	 * worker threads to wake the I/O thread after marking fdes dirty.
	 * In poll-thread mode the eventfd created here is superseded by the one
	 * created in op_uring_start_pollthread(). */
	uring_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (uring_wakeup_fd >= 0)
	{
		uring_arm_wakeup();
		io_uring_submit(&uring);
	}

	/* Record the I/O thread identity for the wake-up fast path. */
	uring_io_tid     = pthread_self();
	uring_io_tid_set = 1;

	op_lib_log("io_uring: ring depth=%u flags=0x%x defer_taskrun=%d "
	           "sqpoll=%d fixed_files=%u/%u multishot=%d wakeup_fd=%d",
	           depth, init_flags, uring_has_defer_taskrun,
	           uring_has_sqpoll, uring_has_fixed_files ? uring_fixed_file_cap : 0,
	           uring_fixed_file_cap, uring_has_multishot, uring_wakeup_fd);

	return 0;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_uring
 *
 * Register or update handler interest for F.  Handler pointers are set under
 * pflags_lock, then the fde is pushed to the deferred-arm Treiber stack so
 * the I/O thread can batch-submit SQEs.
 *
 * Workers NEVER acquire uring_sqlock — only pflags_lock and the lock-free
 * dirty-list push.  This eliminates global SQ contention from the worker
 * hot path.
 *
 * In threaded mode, the eventfd is signalled to wake the main thread so it
 * drains the dirty list promptly.
 */
void
op_setselect_uring(op_fde_t *F, unsigned int type, PF *handler,
                   void *client_data)
{
	if (!IsFDOpen(F))
		return;

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

	pthread_spin_unlock(&F->pflags_lock);

	/* Defer the arm/cancel decision to the I/O thread. */
	uring_mark_dirty(F);

	/* Wake the I/O thread so it flushes dirty fdes promptly.
	 *
	 * In DEFER_TASKRUN mode (uring_thread_active == 0) the I/O thread
	 * sleeps in io_uring_wait_cqe() and won't process the dirty list
	 * until something generates a CQE.  The wake-up eventfd provides
	 * that CQE.  Skip the write when we ARE the I/O thread — it will
	 * flush dirty entries at the top of op_select_uring(). */
	if (uring_thread_active && uring_notify_fd >= 0)
	{
		uint64_t one = 1;
		ssize_t rc;
		do { rc = write(uring_notify_fd, &one, sizeof one); }
		while (rc < 0 && errno == EINTR);
	}
	else if (uring_wakeup_fd >= 0 &&
		 uring_io_tid_set &&
		 !pthread_equal(pthread_self(), uring_io_tid))
	{
		uint64_t one = 1;
		ssize_t rc;
		do { rc = write(uring_wakeup_fd, &one, sizeof one); }
		while (rc < 0 && errno == EINTR);
	}
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

/* ---- Periodic sweep for silently dead multishot polls -------------------- */

static time_t uring_last_sweep = 0;

/*
 * uring_sweep_stale_polls — scan all fds for multishot polls that have gone
 * silent.  If an fd has URING_F_PENDING|URING_F_MULTISHOT set and its
 * uring_last_cqe_time is more than 30 seconds ago, push it to the dirty
 * inbox for cancel+re-arm.
 *
 * Called from op_select_uring every 10 seconds.  This catches the case where
 * a multishot poll died (final CQE lost due to SPSC overflow) and no handler
 * activity re-marks the fd dirty.
 */
static void
uring_sweep_stale_polls(void)
{
	time_t now = op_current_time();

	/* On kernels without multishot (6.x), polls can silently stall
	 * due to kTLS wakeup bugs.  Sweep every 2 seconds with a 5-second
	 * staleness threshold to keep latency tight.  On healthy kernels
	 * (7.x with multishot), sweep every 10s / 30s threshold. */
	int sweep_interval = uring_has_multishot ? 10 : 1;
	int stale_threshold = uring_has_multishot ? 30 : 2;

	if (now - uring_last_sweep < sweep_interval)
		return;
	uring_last_sweep = now;

	for (unsigned int bucket = 0; bucket < OP_FD_HASH_SIZE; bucket++)
	{
		op_dlink_list *hlist = &op_fd_table[bucket];
		op_dlink_node *ptr;

		if (hlist->head == NULL)
			continue;

		OP_DLINK_FOREACH(ptr, hlist->head)
		{
			op_fde_t *F = ptr->data;

			if (F == NULL || !IsFDOpen(F))
				continue;

			pthread_spin_lock(&F->pflags_lock);

			unsigned int pf = F->pflags;
			int is_pending = (pf & URING_F_PENDING) != 0;
			int has_handlers = (F->read_handler != NULL || F->write_handler != NULL);

			/* Skip kTLS peek-recv fds: they're async-waiting on the
			 * kernel recv path which reliably completes when data
			 * arrives.  The sweep is only needed for broken polls. */
			if (pf & URING_F_KTLS_PEEK)
			{
				pthread_spin_unlock(&F->pflags_lock);
				continue;
			}

			if (is_pending && has_handlers
			    && (now - F->uring_last_cqe_time > stale_threshold))
			{
				/* Stale poll: probe for pending data with a
				 * non-blocking peek.  If data is available,
				 * synthesize a POLLIN dispatch. If not, just
				 * cancel and re-arm the poll. */
				PF *h = F->read_handler;
				void *d = F->read_data;
				int fd = F->fd;
				pthread_spin_unlock(&F->pflags_lock);

				char probe;
				ssize_t r = recv(fd, &probe, 1,
				                 MSG_PEEK | MSG_DONTWAIT);
				if (r > 0 && h != NULL)
				{
					/* Data waiting — cancel stale poll and
					 * dispatch handler directly. */
					pthread_spin_lock(&uring_sqlock);
					pthread_spin_lock(&F->pflags_lock);
					if (F->pflags & URING_F_PENDING)
					{
						op_cancel_uring(F);
						F->pflags &= ~(URING_F_MULTISHOT
						             | URING_ARMED_MASK);
					}
					F->read_handler = NULL;
					F->read_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					pthread_spin_unlock(&uring_sqlock);

					h(F, d);
				}
				else
				{
					/* No data (or not a data socket) —
					 * cancel stale poll and re-arm. */
					pthread_spin_lock(&uring_sqlock);
					pthread_spin_lock(&F->pflags_lock);
					if (F->pflags & URING_F_PENDING)
					{
						op_cancel_uring(F);
						F->pflags &= ~(URING_F_MULTISHOT
						             | URING_ARMED_MASK);
					}
					pthread_spin_unlock(&F->pflags_lock);
					pthread_spin_unlock(&uring_sqlock);

					uring_mark_dirty(F);
				}
			}
			else
			{
				pthread_spin_unlock(&F->pflags_lock);
			}
		}
	}
}

/*
 * op_select_uring
 *
 * Flush all queued SQEs, wait for CQEs, then dispatch handlers.
 * Re-arms each fd for any remaining interest after dispatch.
 *
 * When uring_thread_active == 1, the CQ drain thread owns io_uring_wait_cqe().
 * This function instead blocks on the notification eventfd and dispatches
 * from the SPSC ring.
 */
int
op_select_uring(long delay)
{
	if (__builtin_expect(uring_thread_active, 0))
	{
		/* Threaded mode: wait on the notification eventfd, drain ring. */
		int ms = (delay < 0) ? -1
		       : (delay > (long)INT_MAX ? INT_MAX : (int)delay);

		/* Flush deferred arms/cancels before sleeping. */
		uring_flush_dirty();

		struct pollfd pf = { .fd = uring_notify_fd, .events = POLLIN };
		poll(&pf, 1, ms);

		/* Drain the counter without caring about the value. */
		uint64_t notify_val;
		ssize_t r;
		do { r = read(uring_notify_fd, &notify_val, sizeof notify_val); }
		while (r < 0 && errno == EINTR);

		op_set_time();

		/* Flush any dirty fdes marked while we slept. */
		uring_flush_dirty();
		uring_dispatch_from_ring();
		/* Flush re-arms generated by dispatched handlers. */
		uring_flush_dirty();

		/* Periodic sweep for silently dead multishot polls. */
		uring_sweep_stale_polls();
		uring_flush_dirty();

		return OP_OK;
	}
	/* else: fall through to inline path */
	static unsigned long spin_count;
	static time_t        spin_last_log;

	struct io_uring_cqe  *cqe;
	struct __kernel_timespec ts;
	unsigned int          head;
	unsigned int          count = 0;
	int ret;

	/* Flush deferred arms/cancels — batch-submit all queued SQEs. */
	uring_flush_dirty();

	/* On kernels without multishot (6.x), kTLS sockets can silently
	 * stall poll completions.  Cap the wait to 500ms so the sweep
	 * runs frequently and re-arms stale polls promptly. */
	if (!uring_has_multishot && (delay < 0 || delay > 500))
		delay = 500;

	/* Wait for at least one CQE, with optional timeout. */
	if (delay >= 0)
	{
		ts.tv_sec  =  delay / 1000;
		ts.tv_nsec = (delay % 1000) * 1000000L;
		ret = io_uring_wait_cqe_timeout(&uring, &cqe, &ts);
	}
	else
	{
		ret = io_uring_wait_cqe(&uring, &cqe);
	}

	/* Save errno before op_set_time() can clobber it. */
	int o_errno = errno;
	op_set_time();
	errno = o_errno;

	if (ret < 0 && ret != -ETIME && ret != -EINTR)
	{
		op_lib_log("op_select_uring: wait_cqe failed: %s", strerror(-ret));
		return OP_ERROR;
	}

	/* Drain all available CQEs. */
	io_uring_for_each_cqe(&uring, head, cqe)
	{
		uint64_t tag     = io_uring_cqe_get_data64(cqe);
		int      cqe_fd;
		uint32_t cqe_gen;
		op_fde_t *F;

		count++;

		/* Sentinel value used by op_cancel_uring's cancel SQE — discard. */
		if (__builtin_expect(tag == UINT64_MAX, 0))
			continue;

		/* Worker wake-up eventfd CQE — consume the counter and re-arm.
		 * The actual work happens later when uring_flush_dirty() runs. */
		if (__builtin_expect(tag == URING_WAKEUP_TAG, 0))
		{
			uint64_t val;
			ssize_t r;
			do { r = read(uring_wakeup_fd, &val, sizeof val); }
			while (r < 0 && errno == EINTR);
#if defined(IORING_POLL_ADD_MULTI)
			if (!uring_has_multishot)
#endif
				uring_arm_wakeup();
			continue;
		}

		cqe_fd  = (int)(uint32_t)(tag >> 32);
		cqe_gen = (uint32_t)tag;

		F = op_find_fd(cqe_fd);
		if (F == NULL || !IsFDOpen(F) || F->uring_gen != cqe_gen)
			continue;

		/* Update timestamp for staleness detection. */
		F->uring_last_cqe_time = op_current_time();

		/*
		 * kTLS peek-recv CQE: res is the recv return value, not a poll mask.
		 *   res > 0 : data available (1 byte peeked)
		 *   res == 0: EOF
		 *   res < 0 : error (negative errno)
		 *
		 * Dispatch read handler and re-arm.  The POLLOUT companion SQE
		 * (if any) uses the same gen but has a poll bitmask in res — it
		 * falls through to the normal poll dispatch below (KTLS_PEEK is
		 * cleared after the peek CQE clears PENDING).
		 */
		if (F->pflags & URING_F_KTLS_PEEK)
		{
			int res = cqe->res;

			/* Distinguish peek-recv CQE from companion POLLOUT poll CQE:
			 * poll CQEs have res with POLLOUT/POLLIN bits set (≥4),
			 * peek-recv has res ∈ {-errno, 0, 1}. */
			if (res > 1 || (res > 0 && (res & (POLLOUT | POLLIN | POLLHUP | POLLERR))))
			{
				/* This is the companion POLLOUT poll CQE. */
				goto poll_dispatch;
			}

			pthread_spin_lock(&F->pflags_lock);
			F->pflags &= ~(URING_F_PENDING | URING_F_KTLS_PEEK);
			pthread_spin_unlock(&F->pflags_lock);

			if (res > 0 || res == 0)
			{
				/* Data available or EOF — dispatch read handler. */
				PF   *h = NULL;
				void *d = NULL;

				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL)
					h(F, d);
			}
			else
			{
				/* Error (res < 0) — dispatch read handler as error. */
				PF   *h = NULL;
				void *d = NULL;

				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL)
					h(F, d);

				if (IsFDOpen(F))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->write_handler; d = F->write_data;
					F->write_handler = NULL; F->write_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}
			}

			if (IsFDOpen(F))
				uring_mark_dirty(F);
			continue;
		}

poll_dispatch:;
		/* Multi-shot poll: if IORING_CQE_F_MORE is set, the kernel will
		 * send more CQEs from this POLL_ADD — keep PENDING set.
		 * Otherwise (oneshot or final multi-shot CQE), clear PENDING
		 * so the next op_setselect triggers a fresh arm. */
		bool multishot_alive = false;
#if defined(IORING_CQE_F_MORE)
		multishot_alive = (cqe->flags & IORING_CQE_F_MORE) != 0;
#endif

		if (!multishot_alive)
		{
			pthread_spin_lock(&F->pflags_lock);
			F->pflags &= ~(URING_F_PENDING | URING_F_MULTISHOT);
			pthread_spin_unlock(&F->pflags_lock);
		}

		{
			int res = cqe->res;

			if (res < 0 || (res & (POLLHUP | POLLERR | POLLNVAL)))
			{
				/* Error or hangup — dispatch both handlers. */
				PF   *h = NULL;
				void *d = NULL;

				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL)
					h(F, d);

				if (IsFDOpen(F))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->write_handler; d = F->write_data;
					F->write_handler = NULL; F->write_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}
			}
			else
			{
				PF   *h = NULL;
				void *d = NULL;

				if (res & (POLLIN | POLLRDHUP))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->read_handler; d = F->read_data;
					F->read_handler = NULL; F->read_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}

				if (IsFDOpen(F) && (res & POLLOUT))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->write_handler; d = F->write_data;
					F->write_handler = NULL; F->write_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}
			}
		}

		/* Defer re-arm to the next uring_flush_dirty() cycle.
		 * With multi-shot polls, the handler's op_setselect call
		 * will mark dirty; flush_dirty detects the poll is still
		 * active (PENDING+MULTISHOT) and skips the re-arm SQE. */
		if (IsFDOpen(F) && !multishot_alive)
			uring_mark_dirty(F);
	}

	io_uring_cq_advance(&uring, count);

	/* Flush re-arms generated by dispatched handlers.  Without this,
	 * dirty fdes from handler callbacks (e.g. POLLOUT set during burst
	 * send, which triggers a multi-shot cancel+re-arm) sit unprocessed
	 * until the next iteration.  This matches the threaded-mode path
	 * which does three flushes per iteration. */
	uring_flush_dirty();

	/* Periodic sweep for silently dead multishot polls. */
	uring_sweep_stale_polls();
	uring_flush_dirty();

	spin_count++;
	{
		time_t now = op_current_time();
		if (now != spin_last_log)
		{
			if (spin_count > 100)
				op_lib_log("uring_spin: %lu iter/s  cqe_this=%u",
				           spin_count, count);
			spin_count = 0;
			spin_last_log = now;
		}
	}

	return OP_OK;
}

int
op_setup_fd_uring(op_fde_t *F)
{
	F->uring_fixed_idx = -1;
	F->uring_last_cqe_time = op_current_time();

	if (uring_has_fixed_files && F->fd >= 0
	    && (unsigned)F->fd < uring_fixed_file_cap)
	{
		int rc = io_uring_register_files_update(&uring, (unsigned)F->fd,
		                                        &F->fd, 1);
		if (rc >= 0)
			F->uring_fixed_idx = F->fd;
	}
	return 0;
}

/*
 * op_close_fd_uring — unregister a fixed file slot before close.
 * Called from op_close() before the fd is actually closed.
 */
void
op_close_fd_uring(op_fde_t *F)
{
	if (F->uring_fixed_idx >= 0 && uring_has_fixed_files)
	{
		int skip = IORING_REGISTER_FILES_SKIP;
		io_uring_register_files_update(&uring, (unsigned)F->uring_fixed_idx,
		                               &skip, 1);
		F->uring_fixed_idx = -1;
	}
}

/* -------------------------------------------------------------------------
 * io_uring CQ poll thread
 * -------------------------------------------------------------------------
 *
 * uring_cq_poll_thread_fn — dedicated thread that drains the io_uring CQ.
 *
 * Waits for CQEs with a short timeout (100 ms) so ep_thread_stop is checked
 * at regular intervals.  For each batch:
 *   1. Packs (tag, res) from each CQE into uring_cq_ring (SPSC, no lock).
 *   2. Advances the CQ with io_uring_cq_advance() — must happen here while
 *      we own the CQ.
 *   3. Writes to uring_notify_fd to wake the main thread.
 *
 * The main thread reconstructs op_fde_t * from tag and dispatches handlers.
 */
static void *
uring_cq_poll_thread_fn(void *arg)
{
	(void)arg;
	uint64_t one = 1;

	while (!uring_thread_stop)
	{
		struct io_uring_cqe  *cqe = NULL;
		struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 100000000LL }; /* 100 ms */

		/* First flush any pending SQEs so submitted arms actually fire. */
		pthread_spin_lock(&uring_sqlock);
		io_uring_submit(&uring);
		pthread_spin_unlock(&uring_sqlock);

		int ret = io_uring_wait_cqe_timeout(&uring, &cqe, &ts);
		if (ret < 0 || cqe == NULL)
			continue;  /* timeout or signal */

		/* Drain all available CQEs in one pass. */
		unsigned int head;
		unsigned int consumed = 0;
		bool any = false;

		io_uring_for_each_cqe(&uring, head, cqe)
		{
			uint64_t tag = io_uring_cqe_get_data64(cqe);

			/* Skip cancel sentinel (see op_cancel_uring). */
			if (__builtin_expect(tag == UINT64_MAX, 0))
			{
				consumed++;  /* sentinels carry no data, safe to consume */
				continue;
			}

			uring_event_t ev = { .tag = tag, .res = cqe->res, .flags = cqe->flags };
			if (uring_ring_push(&uring_cq_ring, &ev))
			{
				any = true;
				consumed++;
			}
			else
			{
				/* Ring full — break to preserve remaining CQEs for next iteration */
				break;
			}
		}

		io_uring_cq_advance(&uring, consumed);

		if (any)
		{
			ssize_t rc;
			do { rc = write(uring_notify_fd, &one, sizeof one); }
			while (rc < 0 && errno == EINTR);
		}
	}

	return NULL;
}

/*
 * uring_dispatch_from_ring — drain the SPSC ring and dispatch handlers.
 * Called from the main thread (op_select_uring threaded mode).
 */
static void
uring_dispatch_from_ring(void)
{
	uring_event_t ev;

	while (uring_ring_pop(&uring_cq_ring, &ev))
	{
		int      cqe_fd  = (int)(uint32_t)(ev.tag >> 32);
		uint32_t cqe_gen = (uint32_t)ev.tag;
		int      res     = ev.res;

		op_fde_t *F = op_find_fd(cqe_fd);
		if (F == NULL || !IsFDOpen(F) || F->uring_gen != cqe_gen)
			continue;

		/* Update timestamp for staleness detection. */
		F->uring_last_cqe_time = op_current_time();

		bool multishot_alive = false;
#if defined(IORING_CQE_F_MORE)
		multishot_alive = (ev.flags & IORING_CQE_F_MORE) != 0;
#endif

		if (!multishot_alive)
		{
			pthread_spin_lock(&F->pflags_lock);
			F->pflags &= ~(URING_F_PENDING | URING_F_MULTISHOT);
			pthread_spin_unlock(&F->pflags_lock);
		}

		if (res < 0 || (res & (POLLHUP | POLLERR | POLLNVAL)))
		{
			PF *h; void *d;

			pthread_spin_lock(&F->pflags_lock);
			h = F->read_handler; d = F->read_data;
			F->read_handler = NULL; F->read_data = NULL;
			pthread_spin_unlock(&F->pflags_lock);
			if (h != NULL) h(F, d);

			if (IsFDOpen(F))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->write_handler; d = F->write_data;
				F->write_handler = NULL; F->write_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}
		}
		else
		{
			PF *h; void *d;

			if (res & (POLLIN | POLLRDHUP))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}

			if (IsFDOpen(F) && (res & POLLOUT))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->write_handler; d = F->write_data;
				F->write_handler = NULL; F->write_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}
		}

		if (IsFDOpen(F) && !multishot_alive)
			uring_mark_dirty(F);
	}
}

/*
 * op_uring_start_pollthread — start the dedicated io_uring CQ drain thread.
 * Idempotent: returns true if already running.
 */
bool
op_uring_start_pollthread(void)
{
	if (uring_thread_active)
		return true;

	/* DEFER_TASKRUN requires the submitter thread to process completions.
	 * A separate CQ poll thread cannot see deferred work.  The inline
	 * dispatch path in op_select_uring handles everything. */
	if (uring_has_defer_taskrun)
	{
		op_lib_log("io_uring: DEFER_TASKRUN active, using inline CQ dispatch");
		return true;
	}

	uring_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (uring_notify_fd < 0)
	{
		op_lib_log("op_uring_start_pollthread: eventfd: %s", strerror(errno));
		return false;
	}

	atomic_init(&uring_cq_ring.head, 0);
	atomic_init(&uring_cq_ring.tail, 0);
	uring_thread_stop = 0;

	int rc = pthread_create(&uring_poll_tid, NULL, uring_cq_poll_thread_fn, NULL);
	if (rc != 0)
	{
		op_lib_log("op_uring_start_pollthread: pthread_create: %s", strerror(rc));
		close(uring_notify_fd);
		uring_notify_fd = -1;
		return false;
	}

	uring_thread_active = 1;
	op_lib_log("I/O poll thread started (io_uring backend)");
	return true;
}

/*
 * op_uring_stop_pollthread — stop the CQ drain thread and revert to inline.
 */
void
op_uring_stop_pollthread(void)
{
	if (!uring_thread_active)
		return;

	uring_thread_stop   = 1;
	uring_thread_active = 0;
	pthread_join(uring_poll_tid, NULL);

	if (uring_notify_fd >= 0)
	{
		close(uring_notify_fd);
		uring_notify_fd = -1;
	}

	op_lib_log("I/O poll thread stopped (io_uring backend)");
}

/* -------------------------------------------------------------------------
 * Event scheduling — delegates to epoll's timerfd/signalfd path.
 * timerfd is just another pollable fd; io_uring polls it the same way.
 * ---------------------------------------------------------------------- */

void
op_uring_init_event(void)
{
	op_epoll_init_event();
}

int
op_uring_sched_event(struct ev_entry *event, int when)
{
	return op_epoll_sched_event(event, when);
}

void
op_uring_unsched_event(struct ev_entry *event)
{
	op_epoll_unsched_event(event);
}

int
op_uring_supports_event(void)
{
	return op_epoll_supports_event();
}

#else  /* !HAVE_LIBURING */

int  op_init_netio_uring(void) { return -1; }
void op_setselect_uring(op_fde_t *F __attribute__((unused)),
                        unsigned int type __attribute__((unused)),
                        PF *handler __attribute__((unused)),
                        void *client_data __attribute__((unused))) {}
int  op_select_uring(long delay __attribute__((unused))) { return -1; }
int  op_setup_fd_uring(op_fde_t *F __attribute__((unused))) { return 0; }
void op_close_fd_uring(op_fde_t *F __attribute__((unused))) {}
void op_uring_init_event(void) {}
int  op_uring_sched_event(struct ev_entry *event __attribute__((unused)),
                          int when __attribute__((unused))) { return 0; }
void op_uring_unsched_event(struct ev_entry *event __attribute__((unused))) {}
int  op_uring_supports_event(void) { return 0; }
bool op_uring_start_pollthread(void) { return false; }
void op_uring_stop_pollthread(void) {}

#endif /* HAVE_LIBURING */
