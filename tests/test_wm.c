/*
 * test_wm.c — unit tests for op_wm_t (sliding-window rate meter).
 *
 * Wall-clock time is used internally, so tests that verify counts rely on
 * op_sleep() to advance time between windows.
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

/* ======================================================================== */

int
main(void)
{
    printf("test_wm\n");

    /* [1] create / destroy */
    SECTION("create-destroy");
    {
        op_wm_t *wm = op_wm_create(5000, 50);
        CHECK(wm != NULL);
        CHECK(op_wm_window_ms(wm) == 5000);
        CHECK(op_wm_n_buckets(wm) == 50);
        CHECK(op_wm_bucket_ms(wm) == 100);
        CHECK(op_wm_count(wm) == 0);
        op_wm_destroy(wm);
    }

    /* [2] add and count within window */
    SECTION("add-count");
    {
        op_wm_t *wm = op_wm_create(10000, 100);  /* 10 s window */
        op_wm_add(wm, 5);
        op_wm_add(wm, 3);
        uint64_t cnt = op_wm_count(wm);
        /* Both adds happened within the window — should see at least 8. */
        CHECK(cnt >= 8);
        op_wm_destroy(wm);
    }

    /* [3] reset → count drops to 0 */
    SECTION("reset");
    {
        op_wm_t *wm = op_wm_create(10000, 100);
        for (int i = 0; i < 20; i++)
            op_wm_add(wm, 1);
        CHECK(op_wm_count(wm) >= 20);
        op_wm_reset(wm);
        CHECK(op_wm_count(wm) == 0);
        op_wm_destroy(wm);
    }

    /* [4] rate — events per second */
    SECTION("rate");
    {
        /* Add 100 events into a 10-second window → rate ≈ 10/s. */
        op_wm_t *wm = op_wm_create(10000, 100);
        op_wm_add(wm, 100);
        double r = op_wm_rate(wm);
        /* rate = count * 1000 / window_ms = 100 * 1000 / 10000 = 10. */
        CHECK(r >= 9.0 && r <= 11.0);
        op_wm_destroy(wm);
    }

    /* [5] stack-allocated init / fini */
    SECTION("init-fini");
    {
        op_wm_t wm;
        op_wm_init(&wm, 1000, 10);
        CHECK(op_wm_window_ms(&wm) == 1000);
        CHECK(op_wm_n_buckets(&wm) == 10);
        op_wm_add(&wm, 7);
        CHECK(op_wm_count(&wm) >= 7);
        op_wm_fini(&wm);
    }

    /* [6] expiry — events fall out after window elapses */
    SECTION("expiry");
    {
        /*
         * Window = 200 ms, 2 buckets (100 ms each).
         * Add events, sleep 300 ms, count should drop to 0.
         */
        op_wm_t *wm = op_wm_create(200, 2);
        op_wm_add(wm, 50);
        CHECK(op_wm_count(wm) >= 50);

        op_sleep(0, 300000);   /* 300 ms */

        CHECK(op_wm_count(wm) == 0);
        op_wm_destroy(wm);
    }

    /* [7] add after expiry — fresh counts */
    SECTION("add-after-expiry");
    {
        op_wm_t *wm = op_wm_create(200, 2);
        op_wm_add(wm, 10);
        op_sleep(0, 300000);   /* let it expire */
        op_wm_add(wm, 3);
        uint64_t cnt = op_wm_count(wm);
        CHECK(cnt >= 3 && cnt <= 5);
        op_wm_destroy(wm);
    }

    /* [8] tick — advances clock without adding */
    SECTION("tick");
    {
        op_wm_t *wm = op_wm_create(200, 2);
        op_wm_add(wm, 20);
        op_sleep(0, 300000);
        op_wm_tick(wm);
        CHECK(op_wm_count(wm) == 0);
        op_wm_destroy(wm);
    }

    /* [9] add 0 — no-op */
    SECTION("add-zero");
    {
        op_wm_t *wm = op_wm_create(5000, 50);
        op_wm_add(wm, 0);
        CHECK(op_wm_count(wm) == 0);
        op_wm_destroy(wm);
    }

    /* [10] high-frequency — 10k adds in one window */
    SECTION("high-frequency");
    {
        op_wm_t *wm = op_wm_create(60000, 600);  /* 60 s, 100 ms buckets */
        for (int i = 0; i < 10000; i++)
            op_wm_add(wm, 1);
        uint64_t cnt = op_wm_count(wm);
        CHECK(cnt >= 10000);   /* all within the window */
        op_wm_destroy(wm);
    }

    printf("ALL PASS\n");
    return 0;
}
