/*
 * libop: ophion support library.
 * async.c: Generic async task executor with main-thread completion callbacks.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_async.h>
#include <op_thread_pool.h>

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#ifdef __linux__
# include <sys/eventfd.h>
# define HAVE_EVENTFD 1
#else
# include <unistd.h>   /* pipe */
#endif

/* ---- completion ring (MPSC) ---------------------------------------------- */

/*
 * We need an MPSC queue because multiple worker threads may post completions
 * concurrently.  The main thread is the sole consumer.
 *
 * Implementation: Michael-Scott-style linked list.  Each node is heap-allocated
 * per completion (acceptable — completions are infrequent compared to I/O).
 * No fixed capacity; no back-pressure.
 *
 * Push (worker, lockfree via CAS on tail):
 *   - Allocate node, set data, set node->next = NULL.
 *   - Atomically swing tail->next from NULL to node.
 *   - Advance tail to node.
 *
 * Pop (main thread, no CAS needed — single consumer):
 *   - If head->next == NULL → empty.
 *   - Otherwise read head->next->data, advance head, free old node.
 *
 * Sentinel: head and tail start pointing at a dummy node.
 */

typedef struct async_node
{
	op_async_done_t       done_fn;
	void                 *ctx;
	struct async_node    *next;     /* _Atomic in push path */
} async_node_t;

/* tail is written by producers; head is written by the main thread.
 * Both are protected by separate concerns so no shared lock is needed. */
static _Atomic(async_node_t *) async_tail = NULL;  /* producer writes */
static async_node_t *async_head = NULL;            /* consumer reads (main thread only) */

/* ---- notification fd ----------------------------------------------------- */

#ifdef HAVE_EVENTFD
static int async_notify_fd = -1;
#else
static int async_notify_pipe[2] = { -1, -1 };
# define async_notify_fd async_notify_pipe[0]
#endif

static op_fde_t *async_fde = NULL;   /* registered with the I/O backend */

/* ---- thread pool --------------------------------------------------------- */

static op_thread_pool_t *async_pool = NULL;

/* Number of tasks submitted but not yet drained. */
static _Atomic(size_t) async_pending_count = 0;

/* ---- internal task wrapper ----------------------------------------------- */

typedef struct
{
	op_async_work_t work_fn;
	op_async_done_t done_fn;
	void           *ctx;
} async_task_t;

/*
 * async_post_completion — push a completion node from a worker thread.
 */
static void
async_post_completion(op_async_done_t done_fn, void *ctx)
{
	async_node_t *node = op_malloc(sizeof(*node));
	node->done_fn = done_fn;
	node->ctx     = ctx;
	node->next    = NULL;  /* will be set atomically */

	/* MS-queue push: atomically swing old tail's next from NULL to node,
	 * then advance tail. */
	async_node_t *old_tail = atomic_exchange_explicit(
	    &async_tail, node, memory_order_acq_rel);
	/* old_tail->next was NULL (invariant); set it to node. */
	/* This single store is safe because old_tail is unreachable by other
	 * producers once we've swung async_tail past it. */
	atomic_store_explicit(
	    (volatile _Atomic(async_node_t *) *)&old_tail->next,
	    node,
	    memory_order_release);

	/* Wake the main thread via the notification fd. */
#ifdef HAVE_EVENTFD
	uint64_t one = 1;
	ssize_t rc;
	do { rc = write(async_notify_fd, &one, sizeof one); }
	while (rc < 0 && errno == EINTR);
#else
	char one = 1;
	ssize_t rc;
	do { rc = write(async_notify_pipe[1], &one, 1); }
	while (rc < 0 && errno == EINTR);
#endif
}

/*
 * async_worker_fn — called by the thread pool for each submitted task.
 */
static void
async_worker_fn(void *arg)
{
	async_task_t *t = arg;
	t->work_fn(t->ctx);
	if (t->done_fn != NULL)
		async_post_completion(t->done_fn, t->ctx);
	else
		atomic_fetch_sub_explicit(&async_pending_count, 1, memory_order_relaxed);
	op_free(t);
}

/* ---- event handler ------------------------------------------------------- */

/*
 * async_notify_handler — I/O handler for the notification fd.
 * Called by the event loop when the fd becomes readable.
 * Drains completions and re-arms the fd.
 */
static void
async_notify_handler(op_fde_t *F, void *data)
{
	(void)data;

	/* Drain the notification counter. */
#ifdef HAVE_EVENTFD
	uint64_t count;
	ssize_t r;
	do { r = read(async_notify_fd, &count, sizeof count); }
	while (r < 0 && errno == EINTR);
#else
	char buf[64];
	ssize_t r;
	do { r = read(async_notify_pipe[0], buf, sizeof buf); }
	while (r > 0 || (r < 0 && errno == EINTR));
#endif

	op_async_drain();

	/* Re-arm for the next batch. */
	op_setselect(F, OP_SELECT_READ, async_notify_handler, NULL);
}

/* ---- public API ---------------------------------------------------------- */

bool
op_async_init(int nthreads)
{
	if (async_pool != NULL)
		return true;   /* already initialised */

	/* Allocate sentinel node for the MS-queue. */
	async_node_t *sentinel = op_malloc(sizeof(*sentinel));
	sentinel->done_fn = NULL;
	sentinel->ctx     = NULL;
	sentinel->next    = NULL;
	async_head = sentinel;
	atomic_store_explicit(&async_tail, sentinel, memory_order_release);

#ifdef HAVE_EVENTFD
	async_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (async_notify_fd < 0)
	{
		op_lib_log("op_async_init: eventfd: %s", strerror(errno));
		op_free(sentinel);
		async_head = NULL;
		return false;
	}
#else
	if (pipe(async_notify_pipe) < 0)
	{
		op_lib_log("op_async_init: pipe: %s", strerror(errno));
		op_free(sentinel);
		async_head = NULL;
		return false;
	}
	fcntl(async_notify_pipe[0], F_SETFL, O_NONBLOCK);
#endif

	/* Register the notification fd with the I/O backend. */
	async_fde = op_open(async_notify_fd, OP_FD_UNKNOWN, "async-completion");
	if (async_fde == NULL)
	{
		op_lib_log("op_async_init: op_open failed for completion fd");
#ifdef HAVE_EVENTFD
		close(async_notify_fd);
		async_notify_fd = -1;
#else
		close(async_notify_pipe[0]);
		close(async_notify_pipe[1]);
		async_notify_pipe[0] = async_notify_pipe[1] = -1;
#endif
		op_free(sentinel);
		async_head = NULL;
		return false;
	}
	op_setselect(async_fde, OP_SELECT_READ, async_notify_handler, NULL);

	async_pool = op_tpool_create(nthreads);
	atomic_store_explicit(&async_pending_count, 0, memory_order_relaxed);

	op_lib_log("async task pool started (%d threads)", op_tpool_nthreads(async_pool));
	return true;
}

void
op_async_shutdown(void)
{
	if (async_pool == NULL)
		return;

	/* Wait for all workers to finish. */
	op_tpool_shutdown(async_pool);
	async_pool = NULL;

	/* Drain remaining completions. */
	op_async_drain();

	/* Deregister and close the notification fd. */
	if (async_fde != NULL)
	{
		op_close(async_fde);
		async_fde = NULL;
	}
#ifdef HAVE_EVENTFD
	if (async_notify_fd >= 0)
	{
		close(async_notify_fd);
		async_notify_fd = -1;
	}
#else
	if (async_notify_pipe[0] >= 0)
	{
		close(async_notify_pipe[0]);
		close(async_notify_pipe[1]);
		async_notify_pipe[0] = async_notify_pipe[1] = -1;
	}
#endif

	/* Free sentinel. */
	if (async_head != NULL)
	{
		op_free(async_head);
		async_head = NULL;
	}
	atomic_store_explicit(&async_tail, NULL, memory_order_relaxed);
}

void
op_async_submit(op_async_work_t work_fn, op_async_done_t done_fn, void *ctx)
{
	async_task_t *t = op_malloc(sizeof(*t));
	t->work_fn = work_fn;
	t->done_fn = done_fn;
	t->ctx     = ctx;

	atomic_fetch_add_explicit(&async_pending_count, 1, memory_order_relaxed);
	op_tpool_submit(async_pool, async_worker_fn, t);
}

int
op_async_drain(void)
{
	int count = 0;

	/* MS-queue pop: read from head->next until empty. */
	for (;;)
	{
		async_node_t *next = atomic_load_explicit(
		    (volatile _Atomic(async_node_t *) *)&async_head->next,
		    memory_order_acquire);

		if (next == NULL)
			break;   /* queue is empty */

		/* Advance head past the sentinel. */
		async_node_t *old_head = async_head;
		async_head = next;
		op_free(old_head);   /* free old sentinel */

		/* Deliver the completion. */
		if (next->done_fn != NULL)
			next->done_fn(next->ctx);

		atomic_fetch_sub_explicit(&async_pending_count, 1, memory_order_relaxed);
		count++;

		/* next becomes the new sentinel — don't free it yet. */
		/* Its done_fn/ctx have been consumed; zero them out for safety. */
		next->done_fn = NULL;
		next->ctx     = NULL;
	}

	return count;
}

size_t
op_async_pending(void)
{
	return atomic_load_explicit(&async_pending_count, memory_order_relaxed);
}

bool
op_async_active(void)
{
	return async_pool != NULL;
}
