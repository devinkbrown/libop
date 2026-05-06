/*
 * libop/include/op_thread_pool.h — work-stealing thread pool.
 *
 * Each worker owns a chase-lev deque.  External submitters push to a
 * per-worker MPSC inbox (Treiber stack) via CAS — fully lock-free —
 * then signal the worker's eventfd/pipe.  Workers drain their inbox
 * into the local deque, pop locally, or steal from random peers.
 *
 * The entire submit + dispatch hot path is lock-free: no mutex, no
 * condvar, no spinlock.
 *
 * Usage:
 *   op_thread_pool_t *pool = op_tpool_create(0);   // 0 = auto (# CPUs, max 16)
 *   op_tpool_submit(pool, my_fn, my_arg);
 *   op_tpool_submit_affinity(pool, my_fn, my_arg, key);
 *   op_tpool_shutdown(pool);                        // waits for all workers
 */

#ifndef OP_THREAD_POOL_H
#define OP_THREAD_POOL_H

#include <stddef.h>
#include <stdint.h>

typedef struct op_thread_pool op_thread_pool_t;

/*
 * Thread-start callback type.  If set via op_tpool_set_on_thread_start(),
 * the callback is invoked once on each worker thread immediately after
 * it starts, receiving the worker's name (e.g. "opw-3") and its index.
 * The callback runs before the worker processes any work items.
 */
typedef void (*op_tpool_thread_start_fn)(const char *name, int worker_id);

/*
 * op_tpool_create — create a thread pool with work-stealing.
 *
 * nthreads: number of worker threads to spawn.
 *           Pass 0 to auto-detect (sysconf(_SC_NPROCESSORS_ONLN), capped at 16).
 *
 * Returns a pointer to the pool (never NULL; aborts on OOM/pthread failure).
 */
op_thread_pool_t *op_tpool_create(int nthreads);

/*
 * op_tpool_set_on_thread_start — register a callback invoked at thread start.
 *
 * Must be called BEFORE op_tpool_create() if you want the callback to fire
 * for all workers, or call it and then create the pool.  If workers are
 * already running, the callback only fires for subsequently-created workers.
 *
 * Set to NULL to disable.  Not thread-safe vs op_tpool_create().
 */
void op_tpool_set_on_thread_start(op_tpool_thread_start_fn fn);

/*
 * op_tpool_submit — enqueue a work item (round-robin target selection).
 *
 * fn(arg) will be called exactly once on an arbitrary worker thread.
 * This function is safe to call from any thread.
 * It is NOT safe to call after op_tpool_shutdown().
 */
void op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg);

/*
 * op_tpool_submit_affinity — enqueue a work item with worker affinity.
 *
 * The worker is selected by (key % nthreads), so repeated submits with
 * the same key always target the same worker.  This gives cache-locality
 * benefits when the same client's commands are always handled by the same
 * worker thread (hot L1/L2 for that client's data structures).
 *
 * The work item may still be stolen by an idle worker if the target is
 * overloaded, so ordering is NOT guaranteed — the caller must use its
 * own synchronisation (e.g. dispatch_mutex) for per-client ordering.
 */
void op_tpool_submit_affinity(op_thread_pool_t *pool,
                              void (*fn)(void *), void *arg,
                              uintptr_t key);

/*
 * op_tpool_shutdown — drain the queue and destroy the pool.
 *
 * Blocks until all queued work items have completed and all worker threads
 * have exited.  The pool pointer is invalid after this call.
 */
void op_tpool_shutdown(op_thread_pool_t *pool);

/*
 * op_tpool_nthreads — return the number of worker threads in the pool.
 */
int op_tpool_nthreads(const op_thread_pool_t *pool);

/* -------------------------------------------------------------------------
 * Worker state introspection
 *
 * Per-worker state and statistics for debugging and performance analysis.
 * Use op_tpool_get_stats() to snapshot all workers' stats into a caller-
 * supplied array.
 * ---------------------------------------------------------------------- */

typedef enum {
	OP_WORKER_IDLE,        /* Sleeping on eventfd/pipe, waiting for work   */
	OP_WORKER_DRAINING,    /* Draining MPSC inbox into local deque         */
	OP_WORKER_DISPATCHING, /* Executing a work item callback               */
	OP_WORKER_STEALING,    /* Scanning peer deques for stealable items     */
} op_worker_state_t;

typedef struct {
	int              id;          /* Worker index (0..nthreads-1)          */
	op_worker_state_t state;     /* Current state snapshot                 */
	uint64_t         dispatched;  /* Total work items executed              */
	uint64_t         stolen;      /* Items stolen from other workers        */
	uint64_t         fast_path;   /* Items taken from own deque (no steal)  */
	uint64_t         inbox_drained; /* Total inbox drain operations         */
} op_tpool_worker_stats_t;

/*
 * op_tpool_get_stats — snapshot per-worker stats into `out`.
 *
 * `out` must have room for at least op_tpool_nthreads(pool) entries.
 * Returns the number of entries written.
 *
 * The snapshot is not atomic across workers — each worker's counters are
 * individually consistent but may represent slightly different points in
 * time.  This is acceptable for monitoring and debugging.
 */
int op_tpool_get_stats(const op_thread_pool_t *pool,
                       op_tpool_worker_stats_t *out, int max);

#endif /* OP_THREAD_POOL_H */
