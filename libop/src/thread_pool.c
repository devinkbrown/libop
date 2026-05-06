/*
 * libop/src/thread_pool.c — work-stealing thread pool.
 *
 * Design: each worker owns a chase-lev deque (lock-free for the owner,
 * CAS-based stealing for thieves).  External submitters push to a
 * per-worker MPSC Treiber stack ("inbox") via CAS — fully lock-free.
 * Workers drain their inbox into the local deque at the start of each
 * work cycle, then pop locally or steal from random peers.
 *
 * Wakeup: each worker sleeps on its own eventfd (Linux) or pipe (POSIX
 * fallback).  Submitters write to the target worker's wakeup fd after
 * pushing to its inbox.  No global mutex exists in the submit or
 * dispatch hot paths.
 *
 * The chase-lev deque is described in:
 *   "Dynamic Circular Work-Stealing Deque" — Chase & Lev, SPAA 2005.
 *
 * Two implementations:
 *   _WIN32   — Win32 threads + Interlocked* atomics
 *   POSIX    — pthreads + C11 atomics
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE   /* pthread_setname_np */
#endif

#include <libop_config.h>
#include <op_thread_pool.h>
#include <op_lib.h>          /* op_malloc, op_free */

#include <string.h>
#include <stdio.h>           /* snprintf for tname */

/* =========================================================================
 * Chase-Lev deque — shared by both platforms
 *
 * The deque is a circular buffer of void* slots.  The owner pushes/pops
 * at the "top" end; thieves pop from the "bottom" end.
 *
 * Invariants:
 *   - top >= bottom  (empty when top == bottom)
 *   - The owner is the only thread that modifies `top`.
 *   - Multiple thieves may race on `bottom` via CAS.
 *
 * The buffer grows when full (double capacity, copy, swap pointer).
 * Shrinking is not implemented — deques only grow.
 * ====================================================================== */

#define DEQUE_INIT_CAP  256   /* must be power of two */

typedef struct {
	void   **slots;
	int      capacity;   /* always power of two */
} deque_buf_t;

/* =========================================================================
 * Windows implementation
 * ====================================================================== */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef struct {
	volatile LONG64  top;       /* owner push/pop end */
	volatile LONG64  bottom;    /* thief steal end    */
	deque_buf_t     *buf;       /* current buffer     */
	char             _pad[40];  /* avoid false sharing */
} deque_t;

static void
deque_init(deque_t *d)
{
	d->top    = 0;
	d->bottom = 0;
	d->buf    = op_malloc(sizeof(deque_buf_t));
	d->buf->capacity = DEQUE_INIT_CAP;
	d->buf->slots    = op_malloc(sizeof(void *) * DEQUE_INIT_CAP);
	memset(d->buf->slots, 0, sizeof(void *) * DEQUE_INIT_CAP);
}

static void
deque_destroy(deque_t *d)
{
	op_free(d->buf->slots);
	op_free(d->buf);
}

/* Owner push — ONLY called by the owning worker thread.
 * External submitters use the per-worker MPSC inbox instead. */
static void
deque_push(deque_t *d, void *item)
{
	LONG64 t = d->top;
	LONG64 b = d->bottom;
	deque_buf_t *buf = d->buf;

	if (t - b >= buf->capacity) {
		/* Grow: allocate new buffer, copy, swap. */
		int newcap = buf->capacity * 2;
		deque_buf_t *nb = op_malloc(sizeof(deque_buf_t));
		nb->capacity = newcap;
		nb->slots    = op_malloc(sizeof(void *) * (size_t)newcap);
		memset(nb->slots, 0, sizeof(void *) * (size_t)newcap);
		for (LONG64 i = b; i < t; i++)
			nb->slots[i & (newcap - 1)] = buf->slots[i & (buf->capacity - 1)];
		/* Old buffer is leaked intentionally — thieves may still be reading
		 * it during steal.  In practice grows are extremely rare (once or
		 * twice total) and the old buffer is small. */
		d->buf = nb;
		buf = nb;
	}

	buf->slots[t & (buf->capacity - 1)] = item;
	MemoryBarrier();
	InterlockedExchange64(&d->top, t + 1);
}

/* Owner pop — returns NULL if empty. */
static void *
deque_pop(deque_t *d)
{
	LONG64 t = InterlockedDecrement64(&d->top);
	LONG64 b = d->bottom;

	if (t < b) {
		/* Empty — restore top. */
		InterlockedExchange64(&d->top, b);
		return NULL;
	}

	void *item = d->buf->slots[t & (d->buf->capacity - 1)];

	if (t > b)
		return item;   /* More than one item was present — no race. */

	/* Last item — race with thieves. */
	if (InterlockedCompareExchange64(&d->bottom, b + 1, b) != b)
		item = NULL;   /* Thief got it. */

	InterlockedExchange64(&d->top, b + 1);
	return item;
}

/* Thief steal — returns NULL if empty or contended. */
static void *
deque_steal(deque_t *d)
{
	LONG64 b = d->bottom;
	MemoryBarrier();
	LONG64 t = d->top;

	if (b >= t)
		return NULL;   /* Empty. */

	void *item = d->buf->slots[b & (d->buf->capacity - 1)];

	if (InterlockedCompareExchange64(&d->bottom, b + 1, b) != b)
		return NULL;   /* Lost the race. */

	return item;
}

/* ---- work item (Windows) ------------------------------------------------ */

typedef struct work_item_w32 {
	void (*fn)(void *);
	void *arg;
	struct work_item_w32 *volatile next;   /* Treiber stack link for inbox */
} work_item_w32_t;

static inline work_item_w32_t *
work_item_new_w32(void (*fn)(void *), void *arg)
{
	work_item_w32_t *item = op_malloc(sizeof(*item));
	item->fn   = fn;
	item->arg  = arg;
	item->next = NULL;
	return item;
}

static inline void
work_item_run_w32(work_item_w32_t *item)
{
	void (*fn)(void *) = item->fn;
	void *arg          = item->arg;
	op_free(item);
	fn(arg);
}

/* ---- pool structure (Windows) ------------------------------------------- */

typedef struct {
	deque_t                      deque;
	work_item_w32_t *volatile    inbox;   /* MPSC Treiber stack */
	HANDLE                       wake_ev; /* auto-reset event for wakeup */
	HANDLE                       thread;
	struct op_thread_pool       *pool;
	int                          id;
} worker_ctx_w32_t;

struct op_thread_pool {
	volatile int       stop;
	volatile LONG      submit_rr;   /* round-robin counter */
	int                nthreads;
	op_tpool_thread_start_fn on_thread_start;
	worker_ctx_w32_t   workers[];
};

static op_tpool_thread_start_fn g_thread_start_cb_w32 = NULL;

void
op_tpool_set_on_thread_start(op_tpool_thread_start_fn fn)
{
	g_thread_start_cb_w32 = fn;
}

static unsigned __int32
xorshift32(unsigned __int32 *state)
{
	unsigned __int32 x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

/*
 * inbox_push_w32 — lock-free MPSC push via Interlocked CAS.
 */
static void
inbox_push_w32(worker_ctx_w32_t *w, work_item_w32_t *item)
{
	work_item_w32_t *old;
	do {
		old = w->inbox;
		item->next = old;
	} while (InterlockedCompareExchangePointer(
	             (volatile PVOID *)&w->inbox, item, old) != old);
}

/*
 * inbox_drain_w32 — atomically harvest the entire inbox, reverse to FIFO,
 * push into the local deque.
 */
static void
inbox_drain_w32(worker_ctx_w32_t *w)
{
	work_item_w32_t *batch = InterlockedExchangePointer(
	                             (volatile PVOID *)&w->inbox, NULL);
	if (batch == NULL)
		return;

	/* Reverse LIFO → FIFO. */
	work_item_w32_t *rev = NULL;
	while (batch) {
		work_item_w32_t *next = batch->next;
		batch->next = rev;
		rev = batch;
		batch = next;
	}

	/* Push all into local deque (owner-only, no contention). */
	while (rev) {
		work_item_w32_t *next = rev->next;
		deque_push(&w->deque, rev);
		rev = next;
	}
}

static DWORD WINAPI
worker_entry(LPVOID arg)
{
	worker_ctx_w32_t *ctx = arg;
	struct op_thread_pool *pool = ctx->pool;
	int my_id = ctx->id;
	unsigned __int32 rng = (unsigned __int32)(my_id + 1) * 2654435761u;

	char tname[16];
	snprintf(tname, sizeof(tname), "opw-%d", my_id);
	if (pool->on_thread_start)
		pool->on_thread_start(tname, my_id);

	for (;;) {
		/* 0. Drain inbox into local deque. */
		inbox_drain_w32(ctx);

		/* 1. Try own deque (LIFO — cache-warm items first). */
		void *item = deque_pop(&ctx->deque);

		/* 2. Try stealing from random peers. */
		if (item == NULL) {
			for (int attempts = 0; attempts < pool->nthreads * 2; attempts++) {
				int victim = (int)(xorshift32(&rng) % (unsigned)pool->nthreads);
				if (victim == my_id) continue;
				item = deque_steal(&pool->workers[victim].deque);
				if (item != NULL) break;
			}
		}

		if (item != NULL) {
			work_item_run_w32(item);
			continue;
		}

		/* 3. Nothing to do — wait on per-worker event (1 ms timeout for
		 *    steal retries). */
		if (pool->stop)
			return 0;
		WaitForSingleObject(ctx->wake_ev, 1 /* ms */);
	}
}

op_thread_pool_t *
op_tpool_create(int nthreads)
{
	if (nthreads <= 0) {
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		nthreads = (int)si.dwNumberOfProcessors;
		if (nthreads < 1)  nthreads = 1;
		if (nthreads > 16) nthreads = 16;
	}

	size_t sz = sizeof(op_thread_pool_t) +
		(size_t)nthreads * sizeof(worker_ctx_w32_t);
	op_thread_pool_t *pool = op_malloc(sz);
	memset(pool, 0, sz);
	pool->nthreads = nthreads;
	pool->on_thread_start = g_thread_start_cb_w32;

	for (int i = 0; i < nthreads; i++) {
		pool->workers[i].pool    = pool;
		pool->workers[i].id      = i;
		pool->workers[i].inbox   = NULL;
		pool->workers[i].wake_ev = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (pool->workers[i].wake_ev == NULL) abort();
		deque_init(&pool->workers[i].deque);
		pool->workers[i].thread = CreateThread(NULL, 0, worker_entry,
			&pool->workers[i], 0, NULL);
		if (pool->workers[i].thread == NULL) abort();
	}

	return pool;
}

static void
submit_to_worker(op_thread_pool_t *pool, int idx, void (*fn)(void *), void *arg)
{
	work_item_w32_t *item = work_item_new_w32(fn, arg);
	inbox_push_w32(&pool->workers[idx], item);
	SetEvent(pool->workers[idx].wake_ev);
}

void
op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg)
{
	int idx = (int)(InterlockedIncrement(&pool->submit_rr) % (unsigned)pool->nthreads);
	submit_to_worker(pool, idx, fn, arg);
}

void
op_tpool_submit_affinity(op_thread_pool_t *pool, void (*fn)(void *), void *arg,
                         uintptr_t key)
{
	int idx = (int)(key % (uintptr_t)pool->nthreads);
	submit_to_worker(pool, idx, fn, arg);
}

void
op_tpool_shutdown(op_thread_pool_t *pool)
{
	pool->stop = 1;
	MemoryBarrier();

	/* Wake all workers so they see the stop flag. */
	for (int i = 0; i < pool->nthreads; i++)
		SetEvent(pool->workers[i].wake_ev);

	for (int i = 0; i < pool->nthreads; i++)
		WaitForSingleObject(pool->workers[i].thread, INFINITE);

	for (int i = 0; i < pool->nthreads; i++) {
		CloseHandle(pool->workers[i].thread);
		CloseHandle(pool->workers[i].wake_ev);
		/* Drain any remaining items. */
		inbox_drain_w32(&pool->workers[i]);
		void *item;
		while ((item = deque_pop(&pool->workers[i].deque)) != NULL)
			work_item_run_w32(item);
		deque_destroy(&pool->workers[i].deque);
	}

	op_free(pool);
}

int
op_tpool_nthreads(const op_thread_pool_t *pool)
{
	return pool->nthreads;
}

#else /* !_WIN32 — POSIX pthreads */

/* =========================================================================
 * POSIX implementation
 * ====================================================================== */

#include <pthread.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>          /* sysconf, pipe, read, write */
#include <poll.h>            /* poll (worker sleep) */
#include <fcntl.h>           /* O_NONBLOCK, O_CLOEXEC */
#include <errno.h>

#ifdef __linux__
# include <sys/eventfd.h>
# define TPOOL_USE_EVENTFD 1
#endif

typedef struct {
	_Atomic(int64_t) top;       /* owner push/pop end */
	_Atomic(int64_t) bottom;    /* thief steal end    */
	deque_buf_t     *buf;       /* current circular buffer */
	char             _pad[40];  /* avoid false sharing */
} deque_t;

static void
deque_init(deque_t *d)
{
	atomic_store_explicit(&d->top, 0, memory_order_relaxed);
	atomic_store_explicit(&d->bottom, 0, memory_order_relaxed);
	d->buf           = op_malloc(sizeof(deque_buf_t));
	d->buf->capacity = DEQUE_INIT_CAP;
	d->buf->slots    = op_malloc(sizeof(void *) * DEQUE_INIT_CAP);
	memset(d->buf->slots, 0, sizeof(void *) * DEQUE_INIT_CAP);
}

static void
deque_destroy(deque_t *d)
{
	op_free(d->buf->slots);
	op_free(d->buf);
}

/*
 * deque_push — push an item to the top of the deque.
 *
 * ONLY called by the owning worker thread.  External submitters use the
 * per-worker MPSC inbox (Treiber stack) instead.  Single-writer means
 * no serialisation is needed for the `top` update.
 */
static void
deque_push(deque_t *d, void *item)
{
	int64_t t = atomic_load_explicit(&d->top, memory_order_relaxed);
	int64_t b = atomic_load_explicit(&d->bottom, memory_order_acquire);
	deque_buf_t *buf = d->buf;

	if (t - b >= buf->capacity) {
		int newcap = buf->capacity * 2;
		deque_buf_t *nb = op_malloc(sizeof(deque_buf_t));
		nb->capacity = newcap;
		nb->slots    = op_malloc(sizeof(void *) * (size_t)newcap);
		memset(nb->slots, 0, sizeof(void *) * (size_t)newcap);
		for (int64_t i = b; i < t; i++)
			nb->slots[i & (newcap - 1)] = buf->slots[i & (buf->capacity - 1)];
		/* Old buffer is leaked — thieves may still reference it.
		 * In practice this happens at most log2(N/256) times total. */
		d->buf = nb;
		buf = nb;
	}

	buf->slots[t & (buf->capacity - 1)] = item;
	atomic_store_explicit(&d->top, t + 1, memory_order_release);
}

/*
 * deque_pop — owner pops from the top.  Returns NULL if empty.
 *
 * The owner decrements top, then checks if the deque is empty or if
 * there's a race with a thief on the last element.
 */
static void *
deque_pop(deque_t *d)
{
	int64_t t = atomic_load_explicit(&d->top, memory_order_relaxed) - 1;
	atomic_store_explicit(&d->top, t, memory_order_relaxed);
	atomic_thread_fence(memory_order_seq_cst);
	int64_t b = atomic_load_explicit(&d->bottom, memory_order_relaxed);

	if (t < b) {
		/* Empty — restore top. */
		atomic_store_explicit(&d->top, b, memory_order_relaxed);
		return NULL;
	}

	void *item = d->buf->slots[t & (d->buf->capacity - 1)];

	if (t > b)
		return item;   /* More than one item — no race with thieves. */

	/* Last item — race with steal(). */
	int64_t expected = b;
	if (!atomic_compare_exchange_strong_explicit(
	        &d->bottom, &expected, b + 1,
	        memory_order_seq_cst, memory_order_relaxed))
		item = NULL;   /* Thief won. */

	atomic_store_explicit(&d->top, b + 1, memory_order_relaxed);
	return item;
}

/*
 * deque_steal — thief steals from the bottom.  Returns NULL if empty
 * or if another thief won the race.
 */
static void *
deque_steal(deque_t *d)
{
	int64_t b = atomic_load_explicit(&d->bottom, memory_order_acquire);
	atomic_thread_fence(memory_order_seq_cst);
	int64_t t = atomic_load_explicit(&d->top, memory_order_acquire);

	if (b >= t)
		return NULL;   /* Empty. */

	void *item = d->buf->slots[b & (d->buf->capacity - 1)];

	int64_t expected = b;
	if (!atomic_compare_exchange_strong_explicit(
	        &d->bottom, &expected, b + 1,
	        memory_order_seq_cst, memory_order_relaxed))
		return NULL;   /* Lost the CAS race. */

	return item;
}

/* ---- work item encoding -------------------------------------------------- */

/*
 * Work items carry function + argument, plus a 'next' pointer used by the
 * per-worker MPSC inbox (Treiber stack).  Once drained into the local deque
 * the next pointer is unused.  The deque stores void* — work_item_t* cast.
 */

typedef struct work_item {
	void (*fn)(void *);
	void  *arg;
	_Atomic(struct work_item *) next;   /* Treiber stack link (inbox) */
} work_item_t;

static inline work_item_t *
work_item_new(void (*fn)(void *), void *arg)
{
	work_item_t *item = op_malloc(sizeof(*item));
	item->fn  = fn;
	item->arg = arg;
	atomic_init(&item->next, NULL);
	return item;
}

static inline void
work_item_run(void *opaque)
{
	work_item_t *item = opaque;
	void (*fn)(void *) = item->fn;
	void *arg          = item->arg;
	op_free(item);
	fn(arg);
}

/* ---- per-worker wakeup fd ----------------------------------------------- */

/*
 * On Linux, eventfd(2) gives a single-fd counter that is cheap to write and
 * poll.  On other POSIX systems, a pipe provides the same semantics (write
 * end → read end) at the cost of one extra fd per worker.
 */

typedef struct {
	int rfd;   /* read end  (worker polls this)   */
	int wfd;   /* write end (submitter writes this) */
} wake_fd_t;

static inline int
wake_fd_init(wake_fd_t *w)
{
#ifdef TPOOL_USE_EVENTFD
	int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0)
		return -1;
	w->rfd = fd;
	w->wfd = fd;   /* eventfd is bidirectional */
	return 0;
#else
	int fds[2];
#ifdef __linux__
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) < 0)
		return -1;
#else
	if (pipe(fds) < 0)
		return -1;
	fcntl(fds[0], F_SETFL, O_NONBLOCK);
	fcntl(fds[1], F_SETFL, O_NONBLOCK);
	fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);
#endif
	w->rfd = fds[0];
	w->wfd = fds[1];
	return 0;
#endif
}

static inline void
wake_fd_signal(const wake_fd_t *w)
{
	uint64_t one = 1;
	ssize_t rc;
	do {
		rc = write(w->wfd, &one, sizeof one);
	} while (rc < 0 && errno == EINTR);
	/* EAGAIN is fine — the counter is already non-zero, worker will wake. */
}

static inline void
wake_fd_drain(const wake_fd_t *w)
{
	uint64_t buf;
	ssize_t rc;
	do {
		rc = read(w->rfd, &buf, sizeof buf);
	} while (rc < 0 && errno == EINTR);
	/* EAGAIN is fine — nothing to drain. */
}

static inline void
wake_fd_destroy(const wake_fd_t *w)
{
#ifdef TPOOL_USE_EVENTFD
	close(w->rfd);
#else
	close(w->rfd);
	close(w->wfd);
#endif
}

/* ---- pool structure ------------------------------------------------------ */

typedef struct worker_ctx {
	deque_t                    deque;
	_Atomic(work_item_t *)     inbox;     /* MPSC Treiber stack */
	wake_fd_t                  wake;      /* per-worker wakeup fd */
	_Atomic(uint8_t)           awake;     /* 1 while processing; skip eventfd write */
	pthread_t                  tid;
	struct op_thread_pool     *pool;
	int                        id;
	/* --- debug/introspection state --- */
	_Atomic(uint8_t)           state;     /* op_worker_state_t */
	uint64_t                   stat_dispatched;
	uint64_t                   stat_stolen;
	uint64_t                   stat_fast_path;
	uint64_t                   stat_inbox_drained;
	char                       _pad[8];   /* avoid false sharing */
} worker_ctx_t;

struct op_thread_pool {
	_Atomic int       stop;
	int               nthreads;
	_Atomic(uint32_t) submit_rr;    /* round-robin submit counter */
	op_tpool_thread_start_fn on_thread_start;  /* optional callback */
	worker_ctx_t      workers[];    /* flexible array */
};

/* Global thread-start callback set before pool creation. */
static op_tpool_thread_start_fn g_thread_start_cb = NULL;

void
op_tpool_set_on_thread_start(op_tpool_thread_start_fn fn)
{
	g_thread_start_cb = fn;
}

/* Simple xorshift32 PRNG for steal-victim selection. */
static inline uint32_t
xorshift32(uint32_t *state)
{
	uint32_t x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

/* ---- MPSC inbox (Treiber stack) ----------------------------------------- */

/*
 * inbox_push — lock-free multi-producer push.
 *
 * Multiple submitters (including the I/O thread and potentially workers
 * doing cross-submit) can push concurrently without any lock.
 */
static inline void
inbox_push(worker_ctx_t *w, work_item_t *item)
{
	work_item_t *old = atomic_load_explicit(&w->inbox, memory_order_relaxed);
	do {
		atomic_store_explicit(&item->next, old, memory_order_relaxed);
	} while (!atomic_compare_exchange_weak_explicit(
	             &w->inbox, &old, item,
	             memory_order_release, memory_order_relaxed));
}

/*
 * inbox_drain — atomically harvest the entire inbox, reverse to FIFO order,
 * push all items into the local deque (owner-only, no contention).
 */
static inline void
inbox_drain(worker_ctx_t *w)
{
	work_item_t *batch = atomic_exchange_explicit(&w->inbox, NULL,
	                                              memory_order_acquire);
	if (batch == NULL)
		return;

	/* Reverse Treiber stack from LIFO to FIFO. */
	work_item_t *rev = NULL;
	while (batch) {
		work_item_t *next = atomic_load_explicit(&batch->next,
		                                         memory_order_relaxed);
		atomic_store_explicit(&batch->next, rev, memory_order_relaxed);
		rev = batch;
		batch = next;
	}

	/* Push all into local deque. */
	while (rev) {
		work_item_t *next = atomic_load_explicit(&rev->next,
		                                         memory_order_relaxed);
		deque_push(&w->deque, rev);
		rev = next;
	}
}

/* ---- worker thread ------------------------------------------------------ */

static void *
worker_entry(void *arg)
{
	worker_ctx_t *ctx = arg;
	struct op_thread_pool *pool = ctx->pool;
	int my_id = ctx->id;
	uint32_t rng = (uint32_t)(my_id + 1) * 2654435761u;

	/* Set the kernel thread name so this worker is identifiable in
	 * top -H, gdb, /proc/self/task/<tid>/comm, perf, etc. */
	char tname[16];  /* pthread_setname_np limit is 16 bytes including NUL */
	snprintf(tname, sizeof(tname), "opw-%d", my_id);
#if defined(__linux__)
	pthread_setname_np(pthread_self(), tname);
#elif defined(__APPLE__)
	pthread_setname_np(tname);
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	pthread_set_name_np(pthread_self(), tname);
#endif

	/* Fire the application-level thread-start callback (e.g. to set up
	 * thread-local log identity, per-worker arenas, etc.). */
	if (pool->on_thread_start)
		pool->on_thread_start(tname, my_id);

	for (;;) {
		void *item;
		bool was_stolen = false;

		/* 0. Drain MPSC inbox into local deque (lock-free harvest). */
		atomic_store_explicit(&ctx->state, OP_WORKER_DRAINING, memory_order_relaxed);
		inbox_drain(ctx);
		ctx->stat_inbox_drained++;

		/* 1. Try own deque (LIFO — cache-warm items first). */
		item = deque_pop(&ctx->deque);

		/* 2. Try stealing from random peers. */
		if (item == NULL) {
			atomic_store_explicit(&ctx->state, OP_WORKER_STEALING, memory_order_relaxed);
			int attempts = pool->nthreads * 2;
			for (int a = 0; a < attempts; a++) {
				int victim = (int)(xorshift32(&rng) % (unsigned)pool->nthreads);
				if (victim == my_id)
					continue;
				item = deque_steal(&pool->workers[victim].deque);
				if (item != NULL) {
					was_stolen = true;
					break;
				}
			}
		}

		if (item != NULL) {
			/* Mark awake so submitters skip the eventfd write
			 * (we'll drain the inbox on the next iteration). */
			atomic_store_explicit(&ctx->awake, 1, memory_order_relaxed);
			atomic_store_explicit(&ctx->state, OP_WORKER_DISPATCHING, memory_order_relaxed);
			ctx->stat_dispatched++;
			if (was_stolen)
				ctx->stat_stolen++;
			else
				ctx->stat_fast_path++;
			work_item_run(item);
			continue;
		}

		/* 3. Nothing found — transition to sleep.
		 *
		 * Clear the awake flag BEFORE the final inbox check so that
		 * a concurrent submitter that sees awake==0 will write the
		 * eventfd.  The acquire fence ensures we see the inbox push
		 * that happened before the submitter checked our awake flag. */
		atomic_store_explicit(&ctx->state, OP_WORKER_IDLE, memory_order_relaxed);
		atomic_store_explicit(&ctx->awake, 0, memory_order_release);

		/* Re-check inbox after clearing awake (close the race window
		 * where a submitter pushed between our drain and the flag clear). */
		if (atomic_load_explicit(&ctx->inbox, memory_order_acquire) != NULL)
			continue;

		if (atomic_load_explicit(&pool->stop, memory_order_relaxed))
			return NULL;

		{
			struct pollfd pf = { .fd = ctx->wake.rfd, .events = POLLIN };
			poll(&pf, 1, 1 /* ms */);
		}
		wake_fd_drain(&ctx->wake);
	}
}

/* ---- public API --------------------------------------------------------- */

op_thread_pool_t *
op_tpool_create(int nthreads)
{
	if (nthreads <= 0)
	{
#ifdef _SC_NPROCESSORS_ONLN
		nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
#else
		nthreads = 2;
#endif
		if (nthreads < 1)  nthreads = 1;
		if (nthreads > 16) nthreads = 16;
	}

	size_t sz = sizeof(op_thread_pool_t) + (size_t)nthreads * sizeof(worker_ctx_t);
	op_thread_pool_t *pool = op_malloc(sz);
	memset(pool, 0, sz);
	pool->nthreads = nthreads;
	pool->on_thread_start = g_thread_start_cb;
	atomic_store_explicit(&pool->stop, 0, memory_order_relaxed);
	atomic_store_explicit(&pool->submit_rr, 0, memory_order_relaxed);

	for (int i = 0; i < nthreads; i++)
	{
		pool->workers[i].pool = pool;
		pool->workers[i].id   = i;
		atomic_init(&pool->workers[i].inbox, NULL);
		atomic_init(&pool->workers[i].awake, 0);
		if (wake_fd_init(&pool->workers[i].wake) < 0)
			abort();
		deque_init(&pool->workers[i].deque);
	}

	for (int i = 0; i < nthreads; i++)
	{
		if (pthread_create(&pool->workers[i].tid, NULL, worker_entry,
		                   &pool->workers[i]) != 0)
			abort();
	}

	return pool;
}

/*
 * submit_to_worker — lock-free submit via MPSC inbox + eventfd wakeup.
 *
 * The entire submit path is lock-free: a CAS push to the target worker's
 * Treiber stack inbox, followed by an eventfd/pipe write to wake the worker
 * (skipped when the worker is already awake and will drain its inbox
 * naturally on the next iteration).
 *
 * No mutex, no condvar, no contention between submitters targeting different
 * workers.
 */
static void
submit_to_worker(op_thread_pool_t *pool, int idx, void (*fn)(void *), void *arg)
{
	work_item_t *item = work_item_new(fn, arg);
	worker_ctx_t *w = &pool->workers[idx];

	inbox_push(w, item);

	/* Skip the eventfd/pipe write if the worker is already processing.
	 * It will drain the inbox at the top of its next loop iteration.
	 * The release in inbox_push pairs with the acquire in inbox_drain. */
	if (!atomic_load_explicit(&w->awake, memory_order_acquire))
		wake_fd_signal(&w->wake);
}

void
op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg)
{
	uint32_t rr = atomic_fetch_add_explicit(&pool->submit_rr, 1, memory_order_relaxed);
	int idx = (int)(rr % (unsigned)pool->nthreads);
	submit_to_worker(pool, idx, fn, arg);
}

void
op_tpool_submit_affinity(op_thread_pool_t *pool,
                         void (*fn)(void *), void *arg,
                         uintptr_t key)
{
	int idx = (int)(key % (uintptr_t)pool->nthreads);
	submit_to_worker(pool, idx, fn, arg);
}

void
op_tpool_shutdown(op_thread_pool_t *pool)
{
	atomic_store_explicit(&pool->stop, 1, memory_order_release);

	/* Wake all workers so they see the stop flag. */
	for (int i = 0; i < pool->nthreads; i++)
		wake_fd_signal(&pool->workers[i].wake);

	for (int i = 0; i < pool->nthreads; i++)
		pthread_join(pool->workers[i].tid, NULL);

	/* Drain any remaining items from all inboxes + deques. */
	for (int i = 0; i < pool->nthreads; i++) {
		inbox_drain(&pool->workers[i]);
		void *item;
		while ((item = deque_pop(&pool->workers[i].deque)) != NULL)
			work_item_run(item);
		deque_destroy(&pool->workers[i].deque);
		wake_fd_destroy(&pool->workers[i].wake);
	}

	op_free(pool);
}

int
op_tpool_nthreads(const op_thread_pool_t *pool)
{
	return pool->nthreads;
}

int
op_tpool_get_stats(const op_thread_pool_t *pool,
                   op_tpool_worker_stats_t *out, int max)
{
	int n = pool->nthreads;
	if (n > max)
		n = max;
	for (int i = 0; i < n; i++) {
		const worker_ctx_t *w = &pool->workers[i];
		out[i].id             = w->id;
		out[i].state          = (op_worker_state_t)atomic_load_explicit(
		                            &w->state, memory_order_relaxed);
		out[i].dispatched     = w->stat_dispatched;
		out[i].stolen         = w->stat_stolen;
		out[i].fast_path      = w->stat_fast_path;
		out[i].inbox_drained  = w->stat_inbox_drained;
	}
	return n;
}

#endif /* _WIN32 */
