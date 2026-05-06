/*
 * ophion: a slightly less ancient ircd.
 * kqueue.c: BSD kqueue I/O and timer event backend.
 *
 * Architecture:
 *   op_setselect_kqueue queues kevent change entries into a local changelist
 *   buffer (kqlst) protected by kqlst_lock.  op_select_kqueue flushes those
 *   changes to the kernel in a dedicated call, then blocks on a separate call
 *   that only harvests events.  Separating the two calls eliminates the
 *   silent-truncation bug where the kernel stops processing changelist entries
 *   when the combined event-output buffer fills.
 *
 * Lock ordering (must always be acquired in this order to prevent deadlock):
 *   F->pflags_lock  →  kqlst_lock
 *
 * pflags_lock (per-fd)  guards F->read_handler, F->write_handler and their
 *                       associated data pointers.
 * kqlst_lock  (global)  guards the changelist buffer: kqlst[] and kqoff.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2001 Adrian Chadd <adrian@creative.net.au>
 * Copyright (C) 2002-2005 ircd-ratbox development team
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <event-int.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>

#if defined(HAVE_KEVENT)

#include <sys/event.h>

/* Compatibility: EV_SET was not added until FreeBSD 4.3. */
#ifndef EV_SET
# define EV_SET(kevp, a, b, c, d, e, f) do { \
    (kevp)->ident  = (a); (kevp)->filter = (b); \
    (kevp)->flags  = (c); (kevp)->fflags = (d); \
    (kevp)->data   = (e); (kevp)->udata  = (f); \
} while (0)
#endif

/* EVFILT_TIMER: enables native timer delivery through kqueue. */
#ifdef EVFILT_TIMER
# define KQUEUE_SCHED_EVENT
#endif

/*
 * EV_RECEIPT (FreeBSD 8+, macOS 10.6+): when added to a changelist entry's
 * flags, kevent() immediately returns a synthetic completion event for that
 * entry rather than a real I/O event.  Each receipt has EV_ERROR set and
 * data == 0 on success, or an errno value on failure.  This provides
 * per-entry error status for the whole changelist in one call.
 *
 * Without EV_RECEIPT we fall back to: try the whole batch at once; if it
 * fails (first-error semantics), retry entry-by-entry so one bad fd does
 * not abort the remaining changes.
 */
#ifdef EV_RECEIPT
# define KQ_HAVE_RECEIPT 1
#else
# define KQ_HAVE_RECEIPT 0
#endif

/*
 * KQ_CHANGELIST_CAP: maximum pending changes buffered between flushes.
 * Must be a compile-time constant (used to size the static receipt buffer).
 * 512 entries × ~32 bytes each = 16 KiB — well within reason.
 */
#define KQ_CHANGELIST_CAP  512

/*
 * KQ_EVENTLIST_CAP: upper bound on the event output buffer allocated at
 * initialisation.  The actual size is min(getdtablesize(), cap) so a single
 * kevent() call can drain all ready events on a fully-loaded server.
 */
#define KQ_EVENTLIST_CAP  4096

/* ---- module-level state -------------------------------------------------- */

static int kq = -1;
static struct timespec zero_timespec;

/*
 * Changelist buffer.
 * Protected by kqlst_lock; sized statically to avoid per-call allocation.
 * Lock order: F->pflags_lock → kqlst_lock.
 */
static struct kevent      kqlst[KQ_CHANGELIST_CAP];
static int                kqoff;       /* next free slot in kqlst   */
static pthread_spinlock_t kqlst_lock;  /* guards kqlst and kqoff    */

/* Event output buffer: allocated once in op_init_netio_kqueue. */
static struct kevent *kqout;
static int            kqout_cap;

/* ---- kqueue SPSC event ring (poll thread → main thread) ------------------ */

#define KQ_RING_CAP  4096u   /* must be power of two */

typedef struct
{
    _Atomic(uint32_t)  head;
    char               _pad0[60];
    _Atomic(uint32_t)  tail;
    char               _pad1[60];
    struct kevent      slots[KQ_RING_CAP];
} kq_event_ring_t;

/* Notification pipe: poll thread writes to [1], main thread reads from [0]. */
static int               kq_notify_pipe[2] = { -1, -1 };
static pthread_t         kq_poll_tid;
static volatile int      kq_thread_stop  = 0;
static int               kq_thread_active = 0;
static kq_event_ring_t   kq_ring __attribute__((aligned(64)));

/* Forward declaration. */
static void kq_dispatch_event(const struct kevent *ev);

static inline bool
kq_ring_push(kq_event_ring_t *r, const struct kevent *ev)
{
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    if (h - t >= KQ_RING_CAP)
        return false;
    r->slots[h & (KQ_RING_CAP - 1)] = *ev;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
    return true;
}

static inline bool
kq_ring_pop(kq_event_ring_t *r, struct kevent *ev)
{
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    if (t == h)
        return false;
    *ev = r->slots[t & (KQ_RING_CAP - 1)];
    atomic_store_explicit(&r->tail, t + 1, memory_order_release);
    return true;
}

#if KQ_HAVE_RECEIPT
/* Static receipt buffer for EV_RECEIPT confirmation events.
 * Used only inside kq_flush_changes; one slot per changelist entry. */
static struct kevent kq_rcpt[KQ_CHANGELIST_CAP];
#endif

/* ---- kq_flush_changes ---------------------------------------------------- */

/*
 * Submit all pending changelist entries to the kernel.
 * MUST be called with kqlst_lock held.
 *
 * EV_RECEIPT path (FreeBSD 8+ / macOS 10.6+):
 *   Sets EV_RECEIPT on every entry and makes one kevent() call that returns
 *   per-entry status in kq_rcpt[].  This is fully reliable and handles any
 *   mix of ADD, DELETE, and ONESHOT entries without silent truncation.
 *
 * Fallback path:
 *   Attempts the whole batch in one call with a NULL eventlist so the kernel
 *   applies the full changelist atomically (no output-buffer truncation risk).
 *   On failure (first-error semantics) retries one entry at a time, skipping
 *   EBADF (fd closed) and ENOENT (DELETE for unregistered event) as benign.
 */
static void
kq_flush_changes(void)
{
    int i;

    if (kqoff == 0)
        return;

#if KQ_HAVE_RECEIPT
    for (i = 0; i < kqoff; i++)
        kqlst[i].flags |= EV_RECEIPT;

    int n = kevent(kq, kqlst, kqoff, kq_rcpt, kqoff, &zero_timespec);
    if (__builtin_expect(n >= 0, 1))
    {
        for (i = 0; i < n; i++)
        {
            if ((kq_rcpt[i].flags & EV_ERROR) && kq_rcpt[i].data != 0)
            {
                int err = (int)kq_rcpt[i].data;
                if (err != EBADF && err != ENOENT)
                    op_lib_log("kq_flush_changes: fd %d filter %d: %s",
                               (int)(intptr_t)kq_rcpt[i].ident,
                               (int)kq_rcpt[i].filter,
                               strerror(err));
            }
        }
    }
    else if (errno != EBADF)
    {
        op_lib_log("kq_flush_changes: kevent (receipt): %s", strerror(errno));
    }

#else  /* !KQ_HAVE_RECEIPT */

    /*
     * Try the batch in one shot first.  The NULL eventlist prevents the
     * silent-truncation problem where a full output buffer stops change
     * processing mid-list.  If the batch fails (one bad fd or similar),
     * fall back to one-by-one so we don't lose the rest.
     */
    if (kevent(kq, kqlst, kqoff, NULL, 0, &zero_timespec) < 0)
    {
        for (i = 0; i < kqoff; i++)
        {
            if (kevent(kq, &kqlst[i], 1, NULL, 0, &zero_timespec) < 0)
            {
                if (errno != EBADF && errno != ENOENT)
                    op_lib_log("kq_flush_changes: fd %d filter %d: %s",
                               (int)(intptr_t)kqlst[i].ident,
                               (int)kqlst[i].filter,
                               strerror(errno));
            }
        }
    }

#endif /* KQ_HAVE_RECEIPT */

    kqoff = 0;
}

/* ---- kq_arm_event -------------------------------------------------------- */

/*
 * Queue a kevent changelist entry for F and the given filter.
 *
 * MUST be called with F->pflags_lock held so the old-handler read (used to
 * detect the NULL↔non-NULL transition) is atomic with the new assignment.
 * Acquires kqlst_lock internally.
 * Lock order: F->pflags_lock (caller) → kqlst_lock (here).
 *
 * Transition table:
 *   NULL    → handler   EV_ADD | EV_ONESHOT   register new interest
 *   handler → NULL      EV_DELETE             cancel interest
 *   handler → handler   (no kevent issued)    EV_ONESHOT still live in kernel;
 *                                             new handler fetched from F at
 *                                             dispatch time, no re-arm needed
 *   NULL    → NULL      (no-op)
 */
static void
kq_arm_event(op_fde_t *F, short filter, PF *new_handler)
{
    PF  *old_handler;
    int  kep_flags;

    switch (filter)
    {
    case EVFILT_READ:   old_handler = F->read_handler;  break;
    case EVFILT_WRITE:  old_handler = F->write_handler; break;
    default:
        op_lib_log("kq_arm_event: unrecognised filter %d for fd %d",
                   (int)filter, F->fd);
        return;
    }

    /* No kernel interaction needed for no-op or in-place handler replacement. */
    if (old_handler == new_handler)
        return;
    /* handler→handler (both non-NULL): EV_ONESHOT live; handler resolved at dispatch. */
    if (old_handler != NULL && new_handler != NULL)
        return;

    kep_flags = (new_handler != NULL) ? (EV_ADD | EV_ONESHOT) : EV_DELETE;

    pthread_spin_lock(&kqlst_lock);

    /* If the buffer is full, flush immediately to make room. */
    if (kqoff == KQ_CHANGELIST_CAP)
        kq_flush_changes();

    EV_SET(&kqlst[kqoff++], F->fd, filter, kep_flags, 0, 0, F);

    pthread_spin_unlock(&kqlst_lock);
}

/* ---- kq_dispatch --------------------------------------------------------- */

/*
 * Capture and invoke one filter's handler for fd F.
 *
 * The handler pointer and its data are captured and the handler field cleared
 * atomically under pflags_lock.  The handler is then called outside the lock
 * to avoid re-entrant deadlock when the callback calls op_setselect.
 *
 * The IsFDOpen check inside the lock guards against fds that were closed by
 * an earlier handler in the same event batch.
 *
 * Returns 1 if a handler was fired, 0 otherwise.
 *
 * Marked always_inline: the filter parameter is a compile-time constant at
 * every call site, so the inlined switch is optimised away by the compiler.
 */
static __attribute__((always_inline)) inline int
kq_dispatch(op_fde_t *F, short filter)
{
    PF   *hdl  = NULL;
    void *data = NULL;

    pthread_spin_lock(&F->pflags_lock);

    if (!IsFDOpen(F))
    {
        pthread_spin_unlock(&F->pflags_lock);
        return 0;
    }

    switch (filter)
    {
    case EVFILT_READ:
        hdl  = F->read_handler;
        data = F->read_data;
        F->read_handler = NULL;
        break;
    case EVFILT_WRITE:
        hdl  = F->write_handler;
        data = F->write_data;
        F->write_handler = NULL;
        break;
    default:
        pthread_spin_unlock(&F->pflags_lock);
        return 0;
    }

    pthread_spin_unlock(&F->pflags_lock);

    if (hdl == NULL)
        return 0;

    hdl(F, data);
    return 1;
}

/* ---- Public functions ---------------------------------------------------- */

__attribute__((cold))
int
op_setup_fd_kqueue(op_fde_t *F __attribute__((unused)))
{
    return 0;
}

__attribute__((cold))
int
op_init_netio_kqueue(void)
{
#ifdef HAVE_KQUEUE1
    /* kqueue1() sets O_CLOEXEC atomically, eliminating the fork-between-
     * kqueue-and-fcntl race that could leak the fd into child processes. */
    kq = kqueue1(O_CLOEXEC);
    if (kq < 0)
        return errno;
#else
    kq = kqueue();
    if (kq < 0)
        return errno;
    /* Best-effort: set close-on-exec so the kqueue fd is not inherited by
     * helper processes (ssld, wsockd, authd).  Non-atomic but benign in
     * practice since helpers are not spawned during this window. */
    (void)fcntl(kq, F_SETFD, FD_CLOEXEC);
#endif

    kqoff = 0;
    pthread_spin_init(&kqlst_lock, PTHREAD_PROCESS_PRIVATE);

    /*
     * Size the event output buffer to getdtablesize() so one kevent() call
     * drains all ready events on a busy server, capped to KQ_EVENTLIST_CAP.
     * A minimum of 64 entries is always guaranteed.
     */
    kqout_cap = getdtablesize();
    if (kqout_cap > KQ_EVENTLIST_CAP)
        kqout_cap = KQ_EVENTLIST_CAP;
    if (kqout_cap < 64)
        kqout_cap = 64;
    kqout = op_malloc(sizeof(struct kevent) * (size_t)kqout_cap);

    zero_timespec.tv_sec  = 0;
    zero_timespec.tv_nsec = 0;

    op_open(kq, OP_FD_UNKNOWN, "kqueue fd");
    return 0;
}

/*
 * op_setselect_kqueue — register or deregister read/write interest for F.
 *
 * Safe to call from worker threads.  pflags_lock is held across the
 * transition-detection read and the handler assignment so the two are
 * atomic w.r.t. concurrent calls on the same fd.
 */
void
op_setselect_kqueue(op_fde_t *F, unsigned int type, PF *handler, void *client_data)
{
    slop_assert(IsFDOpen(F));

    pthread_spin_lock(&F->pflags_lock);

    if (type & OP_SELECT_READ)
    {
        kq_arm_event(F, EVFILT_READ, handler);
        F->read_handler = handler;
        F->read_data    = client_data;
    }
    if (type & OP_SELECT_WRITE)
    {
        kq_arm_event(F, EVFILT_WRITE, handler);
        F->write_handler = handler;
        F->write_data    = client_data;
    }

    pthread_spin_unlock(&F->pflags_lock);
}

/*
 * op_select_kqueue — flush pending changes, wait for I/O events, dispatch.
 *
 * The changelist flush and the event wait are intentionally separate kevent()
 * calls.  If both are done in the same call, a full event-output buffer can
 * silently prevent later changelist entries from being processed.
 */
__attribute__((hot))
int
op_select_kqueue(long delay)
{
    if (__builtin_expect(kq_thread_active, 0))
        return kq_select_threaded(delay);

    struct timespec  poll_time;
    struct timespec *pt;
    int num, i;

    /* Step 1: flush all pending changes to the kernel before blocking. */
    pthread_spin_lock(&kqlst_lock);
    kq_flush_changes();
    pthread_spin_unlock(&kqlst_lock);

    /* Step 2: wait for I/O events (pure harvest, no changelist). */
    if (delay < 0)
    {
        pt = NULL;
    }
    else
    {
        pt = &poll_time;
        poll_time.tv_sec  = delay / 1000;
        poll_time.tv_nsec = (delay % 1000) * 1000000L;
    }

    num = kevent(kq, NULL, 0, kqout, kqout_cap, pt);
    op_set_time();

    if (num < 0)
    {
        /* EINTR and EAGAIN are not errors; anything else is. */
        if (op_ignore_errno(errno))
            return OP_OK;
        return OP_ERROR;
    }
    if (num == 0)
        return OP_OK;

    /* Step 3: dispatch each returned event. */
    for (i = 0; i < num; i++)
        kq_dispatch_event(&kqout[i]);

    return OP_OK;
}

/*
 * kq_dispatch_event — dispatch a single struct kevent (shared by inline and
 * threaded paths).
 */
static void
kq_dispatch_event(const struct kevent *ev)
{
    op_fde_t *F;

    if (ev->flags & EV_ERROR)
    {
        int err = (int)ev->data;
        if (err == EBADF || err == ENOENT)
            return;
        F = ev->udata;
        if (F == NULL || !IsFDOpen(F))
            return;
        op_lib_log("op_select_kqueue: EV_ERROR fd %d filter %d: %s",
                   F->fd, (int)ev->filter, strerror(err));
        kq_dispatch(F, (short)ev->filter);
        return;
    }

    switch (ev->filter)
    {
    case EVFILT_READ:
        F = ev->udata;
        if (F != NULL)
            kq_dispatch(F, EVFILT_READ);
        break;

    case EVFILT_WRITE:
        F = ev->udata;
        if (F != NULL)
            kq_dispatch(F, EVFILT_WRITE);
        break;

#if defined(EVFILT_TIMER)
    case EVFILT_TIMER:
        op_run_one_event(ev->udata);
        break;
#endif

    default:
        break;
    }
}

/*
 * kq_poll_thread_fn — dedicated kqueue poll thread.
 *
 * Flushes pending changelist entries then calls kevent() with a 100 ms
 * ceiling.  On each batch: pushes events into kq_ring, writes one byte
 * to kq_notify_pipe[1] to wake the main thread.
 */
static void *
kq_poll_thread_fn(void *arg)
{
    (void)arg;
    char one = 1;
    struct timespec ts100ms = { .tv_sec = 0, .tv_nsec = 100000000L };

    while (!kq_thread_stop)
    {
        /* Flush changelist so newly armed fds are monitored. */
        pthread_spin_lock(&kqlst_lock);
        kq_flush_changes();
        pthread_spin_unlock(&kqlst_lock);

        int n = kevent(kq, NULL, 0, kqout, kqout_cap, &ts100ms);
        if (n <= 0)
            continue;

        bool any = false;
        for (int i = 0; i < n; i++)
        {
            if (kq_ring_push(&kq_ring, &kqout[i]))
                any = true;
        }

        if (any)
        {
            ssize_t rc;
            do { rc = write(kq_notify_pipe[1], &one, 1); }
            while (rc < 0 && errno == EINTR);
        }
    }

    return NULL;
}

/*
 * kq_select_threaded — threaded-mode implementation of op_select_kqueue.
 * Blocks on the notification pipe and dispatches from the SPSC ring.
 */
static int
kq_select_threaded(long delay)
{
    int ms = (delay < 0) ? -1
           : (delay > (long)INT_MAX ? INT_MAX : (int)delay);

    struct pollfd pf = { .fd = kq_notify_pipe[0], .events = POLLIN };
    poll(&pf, 1, ms);

    /* Drain the pipe (discard byte count; we drain the ring fully). */
    char buf[64];
    ssize_t r;
    do { r = read(kq_notify_pipe[0], buf, sizeof buf); }
    while (r > 0 || (r < 0 && errno == EINTR));
    /* EAGAIN is normal when timed out with nothing to read. */

    op_set_time();

    struct kevent ev;
    while (kq_ring_pop(&kq_ring, &ev))
        kq_dispatch_event(&ev);

    return OP_OK;
}

/*
 * op_kqueue_start_pollthread — start the dedicated kqueue poll thread.
 */
bool
op_kqueue_start_pollthread(void)
{
    if (kq_thread_active)
        return true;

    if (pipe(kq_notify_pipe) < 0)
    {
        op_lib_log("op_kqueue_start_pollthread: pipe: %s", strerror(errno));
        return false;
    }

    /* Make read end non-blocking so drain loop doesn't hang. */
    fcntl(kq_notify_pipe[0], F_SETFL, O_NONBLOCK);

    atomic_init(&kq_ring.head, 0);
    atomic_init(&kq_ring.tail, 0);
    kq_thread_stop = 0;

    int rc = pthread_create(&kq_poll_tid, NULL, kq_poll_thread_fn, NULL);
    if (rc != 0)
    {
        op_lib_log("op_kqueue_start_pollthread: pthread_create: %s", strerror(rc));
        close(kq_notify_pipe[0]);
        close(kq_notify_pipe[1]);
        kq_notify_pipe[0] = kq_notify_pipe[1] = -1;
        return false;
    }

    kq_thread_active = 1;
    op_lib_log("I/O poll thread started (kqueue backend)");
    return true;
}

/*
 * op_kqueue_stop_pollthread — stop the kqueue poll thread.
 */
void
op_kqueue_stop_pollthread(void)
{
    if (!kq_thread_active)
        return;

    kq_thread_stop   = 1;
    kq_thread_active = 0;
    pthread_join(kq_poll_tid, NULL);

    close(kq_notify_pipe[0]);
    close(kq_notify_pipe[1]);
    kq_notify_pipe[0] = kq_notify_pipe[1] = -1;

    op_lib_log("I/O poll thread stopped (kqueue backend)");
}

/* ---- EVFILT_TIMER event scheduling --------------------------------------- */

#if defined(KQUEUE_SCHED_EVENT)

static int can_do_event = 0;

int
op_kqueue_supports_event(void)
{
    struct kevent kv;
    int xkq;

    if (can_do_event == 1)
        return 1;
    if (can_do_event == -1)
        return 0;

    xkq = kqueue();
    if (xkq < 0)
    {
        can_do_event = -1;
        return 0;
    }

    /* Probe: schedule a 1 ms one-shot timer and verify the kernel accepts it. */
    EV_SET(&kv, (uintptr_t)0x1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 1, NULL);
    if (kevent(xkq, &kv, 1, NULL, 0, NULL) < 0)
    {
        can_do_event = -1;
        close(xkq);
        return 0;
    }

    close(xkq);
    can_do_event = 1;
    return 1;
}

int
op_kqueue_sched_event(struct ev_entry *event, int when)
{
    struct kevent kev;
    int kep_flags;

    /* Timer event ident is the event pointer cast to uintptr_t.
     * Assumes sizeof(void *) == sizeof(uintptr_t), which holds on all
     * currently supported BSD/macOS targets. */
    kep_flags = EV_ADD;
    if (event->frequency == 0)
        kep_flags |= EV_ONESHOT;

    /* EVFILT_TIMER data is in milliseconds on FreeBSD and macOS. */
    EV_SET(&kev, (uintptr_t)event, EVFILT_TIMER, kep_flags, 0,
           (intptr_t)when * 1000, event);

    if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0)
        return 0;
    return 1;
}

void
op_kqueue_unsched_event(struct ev_entry *event)
{
    struct kevent kev;
    EV_SET(&kev, (uintptr_t)event, EVFILT_TIMER, EV_DELETE, 0, 0, event);
    (void)kevent(kq, &kev, 1, NULL, 0, NULL);
}

void
op_kqueue_init_event(void)
{
    return;
}

#endif /* KQUEUE_SCHED_EVENT */

/* ---- Stub implementations for platforms without kqueue ------------------- */

#else /* !HAVE_KEVENT */

__attribute__((cold)) int
op_init_netio_kqueue(void)
{
    errno = ENOSYS;
    return -1;
}

__attribute__((cold)) void
op_setselect_kqueue(op_fde_t *F __attribute__((unused)),
                    unsigned int type __attribute__((unused)),
                    PF *handler __attribute__((unused)),
                    void *client_data __attribute__((unused)))
{
    errno = ENOSYS;
}

__attribute__((cold)) int
op_select_kqueue(long delay __attribute__((unused)))
{
    errno = ENOSYS;
    return OP_ERROR;
}

__attribute__((cold)) int
op_setup_fd_kqueue(op_fde_t *F __attribute__((unused)))
{
    errno = ENOSYS;
    return -1;
}

__attribute__((cold)) bool
op_kqueue_start_pollthread(void) { errno = ENOSYS; return false; }

__attribute__((cold)) void
op_kqueue_stop_pollthread(void) { return; }

#endif /* HAVE_KEVENT */

/* ---- Stubs for platforms without EVFILT_TIMER ---------------------------- */

#if !defined(HAVE_KEVENT) || !defined(KQUEUE_SCHED_EVENT)

__attribute__((cold)) void
op_kqueue_init_event(void)
{
    return;
}

__attribute__((cold)) int
op_kqueue_sched_event(struct ev_entry *event __attribute__((unused)),
                      int when __attribute__((unused)))
{
    errno = ENOSYS;
    return -1;
}

__attribute__((cold)) void
op_kqueue_unsched_event(struct ev_entry *event __attribute__((unused)))
{
    return;
}

__attribute__((cold)) int
op_kqueue_supports_event(void)
{
    errno = ENOSYS;
    return 0;
}

#endif /* !HAVE_KEVENT || !KQUEUE_SCHED_EVENT */
