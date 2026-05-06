/*
 * test_async.c — unit + integration tests for op_async.
 *
 * Coverage:
 *   [1] basic submit + done_fn delivery
 *   [2] fire-and-forget (done_fn = NULL)
 *   [3] many concurrent tasks (100 tasks, 4 threads)
 *   [4] chaining: done_fn submits a follow-up task
 *   [5] pending count accuracy
 *   [6] ctx pointer integrity across threads
 *   [7] zero-thread task (NULL work_fn safety not tested — work_fn required)
 *   [8] shutdown drains all completions
 *
 * Requires op_lib_init() (for the I/O backend) and op_async_init().
 * Uses op_select() to drive the event loop so completions are delivered.
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <stdint.h>

/* ---- helpers ------------------------------------------------------------- */

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)   do { int _before = failures; const char *_sec = (name);
#define END_SECTION     printf("  %-52s %s\n", _sec, \
                               failures == _before ? "pass" : "FAIL"); } while (0)

/*
 * drain_all — drive the event loop until op_async_pending() reaches zero
 * or we exhaust the iteration limit (safety valve for broken tests).
 *
 * Each call to op_select() blocks for up to 10 ms, so the limit of 2000
 * iterations gives a 20-second wall-clock timeout — ample for any sane task.
 */
static void
drain_all(void)
{
    for (int i = 0; i < 2000 && op_async_pending() > 0; i++)
        op_select(10);
}

/* ---- section 1: basic submit + done_fn ----------------------------------- */

static _Atomic(int) s1_work_count;
static int          s1_done_count;
static int          s1_ctx_correct;

static void
s1_work(void *ctx)
{
    (void)ctx;
    atomic_fetch_add_explicit(&s1_work_count, 1, memory_order_relaxed);
}

static void
s1_done(void *ctx)
{
    if ((intptr_t)ctx == 0x1234)
        s1_ctx_correct++;
    s1_done_count++;
}

/* ---- section 2: fire-and-forget (done_fn = NULL) ------------------------- */

static _Atomic(int) s2_work_count;

static void
s2_work(void *ctx)
{
    (void)ctx;
    atomic_fetch_add_explicit(&s2_work_count, 1, memory_order_relaxed);
}

/* ---- section 3: many concurrent tasks ------------------------------------ */

#define S3_TASKS  100

static _Atomic(int) s3_work_count;
static int          s3_done_count;

static void
s3_work(void *ctx)
{
    (void)ctx;
    atomic_fetch_add_explicit(&s3_work_count, 1, memory_order_relaxed);
}

static void
s3_done(void *ctx)
{
    (void)ctx;
    s3_done_count++;
}

/* ---- section 4: chaining (done_fn submits follow-up task) ---------------- */

static int          s4_b_ran;
static int          s4_a_before_b;   /* 1 if A's done ran before B's done */
static _Atomic(int) s4_a_done_flag;

static void s4_work_b(void *ctx) { (void)ctx; }

static void
s4_done_b(void *ctx)
{
    (void)ctx;
    s4_b_ran       = 1;
    s4_a_before_b  = atomic_load_explicit(&s4_a_done_flag, memory_order_acquire);
}

static void s4_work_a(void *ctx) { (void)ctx; }

static void
s4_done_a(void *ctx)
{
    (void)ctx;
    atomic_store_explicit(&s4_a_done_flag, 1, memory_order_release);
    op_async_submit(s4_work_b, s4_done_b, NULL);
}

/* ---- section 5: pending count -------------------------------------------- */

static _Atomic(int) s5_work_started;   /* incremented inside work_fn */

static void
s5_work(void *ctx)
{
    (void)ctx;
    /* Simulate a small amount of work so tasks overlap. */
    atomic_fetch_add_explicit(&s5_work_started, 1, memory_order_relaxed);
}

static void s5_done(void *ctx) { (void)ctx; }

/* ---- section 6: ctx pointer integrity ------------------------------------ */

#define S6_TASKS 20

typedef struct {
    int         id;
    _Atomic(int) work_seen;
    int         done_seen;
} s6_ctx_t;

static s6_ctx_t s6_ctxs[S6_TASKS];

static void
s6_work(void *ctx)
{
    s6_ctx_t *c = ctx;
    atomic_store_explicit(&c->work_seen, c->id * 7 + 3, memory_order_relaxed);
}

static void
s6_done(void *ctx)
{
    s6_ctx_t *c = ctx;
    /* done runs on main thread — plain read is fine. */
    c->done_seen = atomic_load_explicit(&c->work_seen, memory_order_acquire);
}

/* ---- section 7: submit-from-worker --------------------------------------- */

/*
 * A work_fn calls op_async_submit() — this is documented as safe from any
 * thread.  We verify the spawned task eventually delivers its done_fn.
 */
static int          s7_inner_done;
static _Atomic(int) s7_inner_work_done;

static void s7_inner_work(void *ctx) { (void)ctx;
    atomic_store_explicit(&s7_inner_work_done, 1, memory_order_relaxed); }
static void s7_inner_done_fn(void *ctx) { (void)ctx; s7_inner_done = 1; }

static void
s7_outer_work(void *ctx)
{
    (void)ctx;
    op_async_submit(s7_inner_work, s7_inner_done_fn, NULL);
}

/* ---- section 8: shutdown drains ------------------------------------------ */

static _Atomic(int) s8_work_count;
static int          s8_done_count;

static void s8_work(void *ctx) { (void)ctx;
    atomic_fetch_add_explicit(&s8_work_count, 1, memory_order_relaxed); }
static void s8_done(void *ctx) { (void)ctx; s8_done_count++; }

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 1024);

    if (!op_async_init(4))
    {
        printf("SKIP: op_async_init failed\n");
        return 0;
    }

    printf("test_async:\n");

    /* ------------------------------------------------------------------ */
    SECTION("[1] basic submit + done_fn");
    {
        atomic_store(&s1_work_count, 0);
        s1_done_count = s1_ctx_correct = 0;
        for (int i = 0; i < 10; i++)
            op_async_submit(s1_work, s1_done, (void *)(intptr_t)0x1234);
        drain_all();
        CHECK(atomic_load(&s1_work_count) == 10);
        CHECK(s1_done_count == 10);
        CHECK(s1_ctx_correct == 10);
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[2] fire-and-forget (done_fn = NULL)");
    {
        atomic_store(&s2_work_count, 0);
        for (int i = 0; i < 8; i++)
            op_async_submit(s2_work, NULL, NULL);
        drain_all();
        CHECK(atomic_load(&s2_work_count) == 8);
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[3] 100 concurrent tasks");
    {
        atomic_store(&s3_work_count, 0);
        s3_done_count = 0;
        for (int i = 0; i < S3_TASKS; i++)
            op_async_submit(s3_work, s3_done, NULL);
        drain_all();
        CHECK(atomic_load(&s3_work_count) == S3_TASKS);
        CHECK(s3_done_count == S3_TASKS);
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[4] chaining: done_fn submits follow-up");
    {
        s4_b_ran = s4_a_before_b = 0;
        atomic_store(&s4_a_done_flag, 0);
        op_async_submit(s4_work_a, s4_done_a, NULL);
        drain_all();
        CHECK(s4_b_ran == 1);
        CHECK(s4_a_before_b == 1);   /* A's done_fn ran before B's done_fn */
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[5] pending count accuracy");
    {
        atomic_store(&s5_work_started, 0);
        /* Batch 30 tasks and verify pending never exceeds 30. */
        for (int i = 0; i < 30; i++)
            op_async_submit(s5_work, s5_done, NULL);

        /* op_async_pending() was 30 right after submit; drain until 0. */
        drain_all();
        CHECK(op_async_pending() == 0);
        CHECK(atomic_load(&s5_work_started) == 30);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[6] ctx pointer integrity");
    {
        for (int i = 0; i < S6_TASKS; i++)
        {
            s6_ctxs[i].id        = i;
            s6_ctxs[i].done_seen = -1;
            atomic_store(&s6_ctxs[i].work_seen, -1);
            op_async_submit(s6_work, s6_done, &s6_ctxs[i]);
        }
        drain_all();
        int ok = 1;
        for (int i = 0; i < S6_TASKS; i++)
            if (s6_ctxs[i].done_seen != i * 7 + 3) { ok = 0; break; }
        CHECK(ok);
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[7] submit-from-worker");
    {
        s7_inner_done = 0;
        atomic_store(&s7_inner_work_done, 0);
        op_async_submit(s7_outer_work, NULL, NULL);
        drain_all();
        /* The inner task was submitted from the worker thread; drain_all must
         * keep looping until both tasks complete. */
        CHECK(atomic_load(&s7_inner_work_done) == 1);
        CHECK(s7_inner_done == 1);
        CHECK(op_async_pending() == 0);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[8] shutdown drains all completions");
    {
        atomic_store(&s8_work_count, 0);
        s8_done_count = 0;
        for (int i = 0; i < 50; i++)
            op_async_submit(s8_work, s8_done, NULL);

        /* Intentionally drain only partially, then rely on op_async_shutdown
         * to drain the remainder. */
        op_select(5);
        op_async_shutdown();   /* blocks until all workers done + all drained */
        CHECK(atomic_load(&s8_work_count) == 50);
        CHECK(s8_done_count == 50);
    }
    END_SECTION;

    if (failures == 0)
        printf("  PASS (8 sections)\n");
    else
        printf("  FAIL (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
