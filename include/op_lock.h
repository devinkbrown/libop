/*
 * libop/include/op_lock.h — thin locking wrappers for Ophion.
 *
 * Three types:
 *   op_mutex_t    — general-purpose mutex
 *   op_rwlock_t   — readers-writer lock
 *   op_spinlock_t — spin lock for hot paths
 *
 * On POSIX platforms (Linux, *BSD, macOS) the implementation uses pthreads.
 * On Windows (_WIN32) it uses native Win32 synchronisation objects:
 *   op_mutex_t    → CRITICAL_SECTION  (spins briefly before blocking)
 *   op_rwlock_t   → SRWLOCK           (Slim Reader/Writer Lock; Vista+)
 *   op_spinlock_t → CRITICAL_SECTION  (alias to op_mutex_t)
 *
 * All init functions abort on error (same policy as op_malloc).
 */

#ifndef OP_LOCK_H
#define OP_LOCK_H

#ifdef _WIN32

/* =========================================================================
 * Windows native implementation
 * ====================================================================== */

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * op_mutex_t — CRITICAL_SECTION
 *
 * CRITICAL_SECTION spins for a short burst before blocking, which is
 * ideal for the briefly-held locks in Ophion.  It also supports
 * TryEnterCriticalSection for non-blocking trylock.
 * ---------------------------------------------------------------------- */

typedef struct { CRITICAL_SECTION cs; } op_mutex_t;

static inline void
op_mutex_init(op_mutex_t *lk)
{
	InitializeCriticalSection(&lk->cs);
}

static inline void
op_mutex_destroy(op_mutex_t *lk)
{
	DeleteCriticalSection(&lk->cs);
}

static inline void
op_mutex_lock(op_mutex_t *lk)
{
	EnterCriticalSection(&lk->cs);
}

static inline void
op_mutex_unlock(op_mutex_t *lk)
{
	LeaveCriticalSection(&lk->cs);
}

static inline int
op_mutex_trylock(op_mutex_t *lk)
{
	return TryEnterCriticalSection(&lk->cs) != 0;
}

/* -------------------------------------------------------------------------
 * op_rwlock_t — SRWLOCK (Slim Reader/Writer Lock, Vista+/2008+)
 *
 * SRWLOCK has separate release functions for shared (reader) and exclusive
 * (writer) modes.  We track which mode is active in a volatile flag that
 * is written before any unlock: the writer is alone by SRWLOCK guarantee,
 * and concurrent readers all write the same value (false), so there is no
 * data race on the flag itself.
 * ---------------------------------------------------------------------- */

typedef struct {
	SRWLOCK       rw;
	volatile bool exclusive;  /* true while a writer holds the lock */
} op_rwlock_t;

static inline void
op_rwlock_init(op_rwlock_t *lk)
{
	InitializeSRWLock(&lk->rw);
	lk->exclusive = false;
}

static inline void
op_rwlock_destroy(op_rwlock_t *lk)
{
	(void)lk;  /* SRWLock has no destructor */
}

static inline void
op_rwlock_rdlock(op_rwlock_t *lk)
{
	AcquireSRWLockShared(&lk->rw);
	lk->exclusive = false;
}

static inline void
op_rwlock_wrlock(op_rwlock_t *lk)
{
	AcquireSRWLockExclusive(&lk->rw);
	lk->exclusive = true;
}

static inline void
op_rwlock_unlock(op_rwlock_t *lk)
{
	if (lk->exclusive)
		ReleaseSRWLockExclusive(&lk->rw);
	else
		ReleaseSRWLockShared(&lk->rw);
}

/* -------------------------------------------------------------------------
 * op_spinlock_t — alias to op_mutex_t on Windows
 *
 * Windows has no direct equivalent of pthread_spinlock_t.  CRITICAL_SECTION
 * already spins for a configurable number of iterations (default 0 for UP,
 * usually 4000 on SMP) before entering the kernel, so it is the closest
 * practical equivalent.
 * ---------------------------------------------------------------------- */

typedef op_mutex_t op_spinlock_t;
# define op_spinlock_init    op_mutex_init
# define op_spinlock_destroy op_mutex_destroy
# define op_spinlock_lock    op_mutex_lock
# define op_spinlock_unlock  op_mutex_unlock

#else /* !_WIN32 — POSIX pthreads */

/* =========================================================================
 * POSIX pthreads implementation (Linux, *BSD, macOS)
 * ====================================================================== */

#include <pthread.h>
#include <stdlib.h>   /* abort() */
#include <errno.h>

/* -------------------------------------------------------------------------
 * op_mutex_t
 * ---------------------------------------------------------------------- */

typedef struct { pthread_mutex_t m; } op_mutex_t;

static inline void
op_mutex_init(op_mutex_t *lk)
{
	if (pthread_mutex_init(&lk->m, NULL) != 0)
		abort();
}

static inline void
op_mutex_destroy(op_mutex_t *lk)
{
	pthread_mutex_destroy(&lk->m);
}

static inline void
op_mutex_lock(op_mutex_t *lk)
{
	if (pthread_mutex_lock(&lk->m) != 0)
		abort();
}

static inline void
op_mutex_unlock(op_mutex_t *lk)
{
	pthread_mutex_unlock(&lk->m);
}

static inline int
op_mutex_trylock(op_mutex_t *lk)
{
	return pthread_mutex_trylock(&lk->m) == 0;
}

/* -------------------------------------------------------------------------
 * op_rwlock_t
 * ---------------------------------------------------------------------- */

typedef struct { pthread_rwlock_t rw; } op_rwlock_t;

static inline void
op_rwlock_init(op_rwlock_t *lk)
{
	if (pthread_rwlock_init(&lk->rw, NULL) != 0)
		abort();
}

static inline void
op_rwlock_destroy(op_rwlock_t *lk)
{
	pthread_rwlock_destroy(&lk->rw);
}

static inline void
op_rwlock_rdlock(op_rwlock_t *lk)
{
	if (pthread_rwlock_rdlock(&lk->rw) != 0)
		abort();
}

static inline void
op_rwlock_wrlock(op_rwlock_t *lk)
{
	if (pthread_rwlock_wrlock(&lk->rw) != 0)
		abort();
}

static inline void
op_rwlock_unlock(op_rwlock_t *lk)
{
	pthread_rwlock_unlock(&lk->rw);
}

/* -------------------------------------------------------------------------
 * op_spinlock_t
 *
 * pthread_spinlock_t is available on Linux/glibc and most BSDs.
 * On platforms that lack it we fall back to a mutex.
 * ---------------------------------------------------------------------- */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
# define OP_HAVE_SPINLOCK 1
#endif

#ifdef OP_HAVE_SPINLOCK

typedef struct { pthread_spinlock_t s; } op_spinlock_t;

static inline void
op_spinlock_init(op_spinlock_t *lk)
{
	if (pthread_spin_init(&lk->s, PTHREAD_PROCESS_PRIVATE) != 0)
		abort();
}

static inline void
op_spinlock_destroy(op_spinlock_t *lk)
{
	pthread_spin_destroy(&lk->s);
}

static inline void
op_spinlock_lock(op_spinlock_t *lk)
{
	pthread_spin_lock(&lk->s);
}

static inline void
op_spinlock_unlock(op_spinlock_t *lk)
{
	pthread_spin_unlock(&lk->s);
}

#else  /* fallback: use a mutex */

typedef op_mutex_t op_spinlock_t;
# define op_spinlock_init    op_mutex_init
# define op_spinlock_destroy op_mutex_destroy
# define op_spinlock_lock    op_mutex_lock
# define op_spinlock_unlock  op_mutex_unlock

#endif /* OP_HAVE_SPINLOCK */

#endif /* _WIN32 */

/* =========================================================================
 * Lock contention tracking (debug mode)
 *
 * When OP_LOCK_DEBUG is defined, lock operations are wrapped with timing
 * instrumentation that detects slow acquisitions.  A lock that takes longer
 * than OP_LOCK_SLOW_NS nanoseconds to acquire triggers a callback with the
 * caller's file/line and the wait duration.
 *
 * Usage:
 *   Build with -DOP_LOCK_DEBUG to enable.
 *   Use OP_MUTEX_LOCK(lk), OP_RWLOCK_RDLOCK(lk), etc. instead of the
 *   lowercase functions.  In non-debug builds these expand to the bare
 *   lock calls with zero overhead.
 * ====================================================================== */

/* Default compile-time values — used as initial values for the runtime
 * globals below.  The macros are retained for backward compatibility. */
#ifndef OP_LOCK_SLOW_NS_DEFAULT
# define OP_LOCK_SLOW_NS_DEFAULT  (1000000L)   /* 1 ms */
#endif
#ifndef OP_LOCK_DEADLOCK_SEC_DEFAULT
# define OP_LOCK_DEADLOCK_SEC_DEFAULT  30
#endif

/* Backward compat aliases. */
#ifndef OP_LOCK_SLOW_NS
# define OP_LOCK_SLOW_NS  OP_LOCK_SLOW_NS_DEFAULT
#endif
#ifndef OP_LOCK_DEADLOCK_SEC
# define OP_LOCK_DEADLOCK_SEC  OP_LOCK_DEADLOCK_SEC_DEFAULT
#endif

#ifdef OP_LOCK_DEBUG

/* Runtime-configurable globals — ircd sets these from [debug] in ircd.toml.
 * Defined in lock_debug.c with the compile-time defaults as initial values. */
extern int64_t op_lock_slow_threshold_ns;
extern int     op_lock_deadlock_timeout_sec;
extern int     op_lock_ordering_fatal;

#include <time.h>
#include <stdio.h>
#include <inttypes.h>

/* Callback type for slow-lock notifications.  Set via op_lock_set_slow_cb().
 * If NULL, slow locks are printed to stderr. */
typedef void (*op_lock_slow_cb_t)(const char *type, const char *file,
                                   int line, int64_t wait_ns);

/* Extended callback for slow locks with holder info. */
typedef void (*op_lock_slow_held_cb_t)(const char *type, const char *file,
                                       int line, int64_t wait_ns,
                                       const char *holder_thread,
                                       const char *holder_file,
                                       int holder_line);

/* Callback for lock ordering violations. */
typedef void (*op_lock_order_cb_t)(const char *file, int line,
                                   int new_level, int held_level);

/* Callback for deadlock detection (called before abort). */
typedef void (*op_lock_deadlock_cb_t)(const char *file, int line,
                                      const char *holder_thread,
                                      const char *holder_file,
                                      int holder_line, int timeout_sec);

/* Set/get the slow-lock callback.  Not thread-safe vs itself. */
static op_lock_slow_cb_t      _op_lock_slow_cb;
static op_lock_slow_held_cb_t _op_lock_slow_held_cb;
static op_lock_order_cb_t     _op_lock_order_cb;
static op_lock_deadlock_cb_t  _op_lock_deadlock_cb;

static inline void
op_lock_set_slow_cb(op_lock_slow_cb_t cb)
{
	_op_lock_slow_cb = cb;
}

static inline void
op_lock_set_slow_held_cb(op_lock_slow_held_cb_t cb)
{
	_op_lock_slow_held_cb = cb;
}

static inline void
op_lock_set_order_cb(op_lock_order_cb_t cb)
{
	_op_lock_order_cb = cb;
}

static inline void
op_lock_set_deadlock_cb(op_lock_deadlock_cb_t cb)
{
	_op_lock_deadlock_cb = cb;
}

static inline void
_op_lock_report_slow(const char *type, const char *file, int line,
                     int64_t wait_ns)
{
	if (_op_lock_slow_cb)
		_op_lock_slow_cb(type, file, line, wait_ns);
	else
		fprintf(stderr, "SLOW LOCK [%s] %s:%d — waited %" PRId64 " us\n",
		        type, file, line, wait_ns / 1000);
}

static inline int64_t
_op_lock_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* -------------------------------------------------------------------------
 * Lock holder tracking.
 *
 * Each lock can optionally have a companion op_lock_holder_t that records
 * who currently holds it (file, line, thread name).  When a slow-lock
 * event fires we can report both the waiter and the current holder.
 *
 * For mutexes this tracks the single holder.  For rwlocks it tracks the
 * exclusive (write) holder — readers are many and cheap, so we only care
 * about the writer for contention diagnosis.
 *
 * Usage: declare an op_lock_holder_t next to the lock; pass it to the
 * _TRACKED macros.  Or use the plain OP_MUTEX_LOCK(lk) macros which
 * don't track holders.
 * ---------------------------------------------------------------------- */

typedef struct {
	const char *file;
	int         line;
	char        thread[16];
} op_lock_holder_t;

/* Thread name accessor — defined in logger.c for ircd, or provide a stub. */
const char *_op_lock_thread_name(void);

static inline void
_op_lock_holder_set(op_lock_holder_t *h, const char *file, int line)
{
	h->file = file;
	h->line = line;
	const char *tn = _op_lock_thread_name();
	/* Safe copy: always NUL-terminated. */
	int i;
	for (i = 0; i < 15 && tn[i]; i++)
		h->thread[i] = tn[i];
	h->thread[i] = '\0';
}

static inline void
_op_lock_holder_clear(op_lock_holder_t *h)
{
	h->file = NULL;
	h->line = 0;
	h->thread[0] = '\0';
}

static inline void
_op_lock_report_slow_held(const char *type, const char *file, int line,
                          int64_t wait_ns, const op_lock_holder_t *holder)
{
	if (holder && holder->file) {
		if (_op_lock_slow_held_cb)
			_op_lock_slow_held_cb(type, file, line, wait_ns,
			                     holder->thread, holder->file, holder->line);
		else
			fprintf(stderr,
			        "SLOW LOCK [%s] %s:%d — waited %" PRId64 " us"
			        " (held by %s at %s:%d)\n",
			        type, file, line, wait_ns / 1000,
			        holder->thread, holder->file, holder->line);
	} else {
		_op_lock_report_slow(type, file, line, wait_ns);
	}
}

/* --- Plain (non-tracked) macros ---------------------------------------- */

#define OP_MUTEX_LOCK(lk) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_mutex_lock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("mutex", __FILE__, __LINE__, _dt); \
} while (0)

#define OP_RWLOCK_RDLOCK(lk) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_rdlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("rwlock-rd", __FILE__, __LINE__, _dt); \
} while (0)

#define OP_RWLOCK_WRLOCK(lk) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_wrlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("rwlock-wr", __FILE__, __LINE__, _dt); \
} while (0)

#define OP_SPINLOCK_LOCK(lk) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_spinlock_lock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("spinlock", __FILE__, __LINE__, _dt); \
} while (0)

#define OP_MUTEX_UNLOCK(lk)    op_mutex_unlock(lk)
#define OP_RWLOCK_UNLOCK(lk)   op_rwlock_unlock(lk)
#define OP_SPINLOCK_UNLOCK(lk) op_spinlock_unlock(lk)

/* --- Tracked macros: report current holder on contention --------------- */

#define OP_MUTEX_LOCK_TRACKED(lk, holder) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_mutex_lock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow_held("mutex", __FILE__, __LINE__, _dt, (holder)); \
	_op_lock_holder_set((holder), __FILE__, __LINE__); \
} while (0)

#define OP_MUTEX_UNLOCK_TRACKED(lk, holder) do { \
	_op_lock_holder_clear(holder); \
	op_mutex_unlock(lk); \
} while (0)

#define OP_RWLOCK_WRLOCK_TRACKED(lk, holder) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_wrlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow_held("rwlock-wr", __FILE__, __LINE__, _dt, (holder)); \
	_op_lock_holder_set((holder), __FILE__, __LINE__); \
} while (0)

#define OP_RWLOCK_RDLOCK_TRACKED(lk, holder) do { \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_rdlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow_held("rwlock-rd", __FILE__, __LINE__, _dt, (holder)); \
} while (0)

#define OP_RWLOCK_UNLOCK_TRACKED(lk, holder) do { \
	_op_lock_holder_clear(holder); \
	op_rwlock_unlock(lk); \
} while (0)

/* --- Deadlock detection: timed mutex with abort ------------------------ */

static inline void
_op_lock_deadlock_die(const char *file, int line, const op_lock_holder_t *holder)
{
	/* Route through the structured logging callback if registered. */
	if (_op_lock_deadlock_cb) {
		_op_lock_deadlock_cb(file, line,
		                     (holder && holder->file) ? holder->thread : "?",
		                     (holder && holder->file) ? holder->file : "?",
		                     (holder && holder->file) ? holder->line : 0,
		                     op_lock_deadlock_timeout_sec);
	}
	/* Always also write to stderr as a safety net (log system may be stuck). */
	if (holder && holder->file) {
		fprintf(stderr,
		        "\n*** PROBABLE DEADLOCK at %s:%d ***\n"
		        "    Mutex held by thread '%s' at %s:%d\n"
		        "    Waited %d seconds — aborting.\n\n",
		        file, line, holder->thread, holder->file, holder->line,
		        op_lock_deadlock_timeout_sec);
	} else {
		fprintf(stderr,
		        "\n*** PROBABLE DEADLOCK at %s:%d ***\n"
		        "    Waited %d seconds — aborting.\n\n",
		        file, line, op_lock_deadlock_timeout_sec);
	}
	abort();
}

/* Try to acquire a mutex with a timeout.  On timeout, report the holder
 * (if tracked) and abort.  On success, behave like OP_MUTEX_LOCK_TRACKED. */
#define OP_MUTEX_LOCK_DEADLOCK(lk, holder) do { \
	struct timespec _dl_ts; \
	clock_gettime(CLOCK_REALTIME, &_dl_ts); \
	_dl_ts.tv_sec += op_lock_deadlock_timeout_sec; \
	int _dl_rc = pthread_mutex_timedlock(&(lk)->m, &_dl_ts); \
	if (_dl_rc != 0) \
		_op_lock_deadlock_die(__FILE__, __LINE__, (holder)); \
	_op_lock_holder_set((holder), __FILE__, __LINE__); \
} while (0)

/* -------------------------------------------------------------------------
 * Lock ordering assertions.
 *
 * Assign each lock class a numeric level.  Thread-local state tracks the
 * highest level currently held.  Acquiring a lock with a level <= the
 * current maximum is a lock-ordering violation (potential deadlock).
 *
 * Levels (lower = acquired first):
 *   10  dispatch_mutex   (per-client)
 *   20  chan_rwlock       (per-channel)
 *   30  hash rwlocks     (per-table)
 *   40  dead_list_lock
 *   50  timeout spinlocks
 *   60  pflags_lock
 *   70  uring_sqlock
 *   80  balloc heap mutex
 *   90  (reserved)
 *
 * Usage:
 *   OP_MUTEX_LOCK_ORDERED(lk, 10)  — lock + assert ordering
 * ---------------------------------------------------------------------- */

#define OP_LOCK_MAX_HELD  16

/* _op_lock_check_order — validate that `level` is strictly greater than
 * all currently held locks.  Called automatically by the ORDERED macros. */
void _op_lock_check_order(int level, const char *file, int line);
void _op_lock_push(int level);
void _op_lock_pop(int level);

/* Introspection for crash handlers: get the thread-local held-lock state. */
int        _op_lock_held_count(void);
const int *_op_lock_held_levels(void);

#define OP_MUTEX_LOCK_ORDERED(lk, level) do { \
	_op_lock_check_order((level), __FILE__, __LINE__); \
	int64_t _t0 = _op_lock_now_ns(); \
	op_mutex_lock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("mutex", __FILE__, __LINE__, _dt); \
	_op_lock_push(level); \
} while (0)

#define OP_MUTEX_UNLOCK_ORDERED(lk, level) do { \
	_op_lock_pop(level); \
	op_mutex_unlock(lk); \
} while (0)

#define OP_RWLOCK_RDLOCK_ORDERED(lk, level) do { \
	_op_lock_check_order((level), __FILE__, __LINE__); \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_rdlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("rwlock-rd", __FILE__, __LINE__, _dt); \
	_op_lock_push(level); \
} while (0)

#define OP_RWLOCK_WRLOCK_ORDERED(lk, level) do { \
	_op_lock_check_order((level), __FILE__, __LINE__); \
	int64_t _t0 = _op_lock_now_ns(); \
	op_rwlock_wrlock(lk); \
	int64_t _dt = _op_lock_now_ns() - _t0; \
	if (_dt > op_lock_slow_threshold_ns) \
		_op_lock_report_slow("rwlock-wr", __FILE__, __LINE__, _dt); \
	_op_lock_push(level); \
} while (0)

#define OP_RWLOCK_UNLOCK_ORDERED(lk, level) do { \
	_op_lock_pop(level); \
	op_rwlock_unlock(lk); \
} while (0)

#else /* !OP_LOCK_DEBUG — zero overhead */

typedef struct { int _unused; } op_lock_holder_t;

#define OP_MUTEX_LOCK(lk)      op_mutex_lock(lk)
#define OP_MUTEX_UNLOCK(lk)    op_mutex_unlock(lk)
#define OP_RWLOCK_RDLOCK(lk)   op_rwlock_rdlock(lk)
#define OP_RWLOCK_WRLOCK(lk)   op_rwlock_wrlock(lk)
#define OP_RWLOCK_UNLOCK(lk)   op_rwlock_unlock(lk)
#define OP_SPINLOCK_LOCK(lk)   op_spinlock_lock(lk)
#define OP_SPINLOCK_UNLOCK(lk) op_spinlock_unlock(lk)

#define OP_MUTEX_LOCK_TRACKED(lk, holder)       op_mutex_lock(lk)
#define OP_MUTEX_UNLOCK_TRACKED(lk, holder)     op_mutex_unlock(lk)
#define OP_MUTEX_LOCK_DEADLOCK(lk, holder)      op_mutex_lock(lk)
#define OP_RWLOCK_WRLOCK_TRACKED(lk, holder)    op_rwlock_wrlock(lk)
#define OP_RWLOCK_RDLOCK_TRACKED(lk, holder)    op_rwlock_rdlock(lk)
#define OP_RWLOCK_UNLOCK_TRACKED(lk, holder)    op_rwlock_unlock(lk)

#define OP_MUTEX_LOCK_ORDERED(lk, level)      op_mutex_lock(lk)
#define OP_MUTEX_UNLOCK_ORDERED(lk, level)    op_mutex_unlock(lk)
#define OP_RWLOCK_RDLOCK_ORDERED(lk, level)   op_rwlock_rdlock(lk)
#define OP_RWLOCK_WRLOCK_ORDERED(lk, level)   op_rwlock_wrlock(lk)
#define OP_RWLOCK_UNLOCK_ORDERED(lk, level)   op_rwlock_unlock(lk)

static inline void
op_lock_set_slow_cb(void *cb) { (void)cb; }
static inline void
op_lock_set_slow_held_cb(void *cb) { (void)cb; }
static inline void
op_lock_set_order_cb(void *cb) { (void)cb; }
static inline void
op_lock_set_deadlock_cb(void *cb) { (void)cb; }

#endif /* OP_LOCK_DEBUG */

#endif /* OP_LOCK_H */
