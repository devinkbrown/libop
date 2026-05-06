/*
 * test_itree.c — unit tests for op_itree_t (augmented interval tree).
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

/* ---- foreach helpers ----------------------------------------------------- */

typedef struct
{
    int64_t lo[64];
    int64_t hi[64];
    void   *val[64];
    size_t  n;
} result_t;

static bool
collect_cb(int64_t lo, int64_t hi, void *val, void *ud)
{
    result_t *r = ud;
    if (r->n < 64)
    {
        r->lo[r->n]  = lo;
        r->hi[r->n]  = hi;
        r->val[r->n] = val;
        r->n++;
    }
    return true;
}

static bool
stop_first_cb(int64_t lo, int64_t hi, void *val, void *ud)
{
    (void)lo; (void)hi; (void)val;
    (*(size_t *)ud)++;
    return false;
}

static bool
count_cb(int64_t lo, int64_t hi, void *val, void *ud)
{
    (void)lo; (void)hi; (void)val;
    (*(size_t *)ud)++;
    return true;
}

/* ---- free callback ------------------------------------------------------- */

static size_t g_freed = 0;
static void free_cb(void *val, void *ud)
{
    (void)val; (void)ud;
    g_freed++;
}

/* ======================================================================== */

int
main(void)
{
    printf("test_itree\n");

    /* [1] create / destroy empty */
    SECTION("create-destroy");
    {
        op_itree_t *t = op_itree_create("test");
        CHECK(t != NULL);
        CHECK(op_itree_count(t) == 0);
        CHECK(strcmp(op_itree_name(t), "test") == 0);
        op_itree_destroy(t, NULL, NULL);
    }

    /* [2] single interval — stab hit and miss */
    SECTION("single-stab");
    {
        op_itree_t *t = op_itree_create("t");
        CHECK(op_itree_insert(t, 10, 20, (void *)1) == 1);
        CHECK(op_itree_count(t) == 1);

        /* stab inside */
        CHECK(op_itree_first_stab(t, 10) == (void *)1);
        CHECK(op_itree_first_stab(t, 15) == (void *)1);
        CHECK(op_itree_first_stab(t, 20) == (void *)1);

        /* stab outside */
        CHECK(op_itree_first_stab(t,  9) == NULL);
        CHECK(op_itree_first_stab(t, 21) == NULL);

        op_itree_destroy(t, NULL, NULL);
    }

    /* [3] reject hi < lo */
    SECTION("reject-invalid");
    {
        op_itree_t *t = op_itree_create("t");
        CHECK(op_itree_insert(t, 10, 9, (void *)1) == -1);
        CHECK(op_itree_count(t) == 0);
        op_itree_destroy(t, NULL, NULL);
    }

    /* [4] point interval [x, x] */
    SECTION("point-interval");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, 7, 7, (void *)42);
        CHECK(op_itree_first_stab(t, 7)  == (void *)42);
        CHECK(op_itree_first_stab(t, 6)  == NULL);
        CHECK(op_itree_first_stab(t, 8)  == NULL);
        op_itree_destroy(t, NULL, NULL);
    }

    /* [5] multiple non-overlapping intervals — stab selects correct one */
    SECTION("non-overlapping");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t,  0, 10, (void *)1);
        op_itree_insert(t, 20, 30, (void *)2);
        op_itree_insert(t, 40, 50, (void *)3);
        CHECK(op_itree_first_stab(t,  5) == (void *)1);
        CHECK(op_itree_first_stab(t, 25) == (void *)2);
        CHECK(op_itree_first_stab(t, 45) == (void *)3);
        CHECK(op_itree_first_stab(t, 15) == NULL);   /* gap */
        CHECK(op_itree_first_stab(t, 35) == NULL);   /* gap */
        op_itree_destroy(t, NULL, NULL);
    }

    /* [6] overlapping intervals — stab returns all */
    SECTION("overlapping-stab");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, 1, 10, (void *)10);
        op_itree_insert(t, 5, 15, (void *)15);
        op_itree_insert(t, 8, 20, (void *)20);

        result_t r; memset(&r, 0, sizeof(r));
        op_itree_stab(t, 9, collect_cb, &r);
        CHECK(r.n == 3);   /* all three contain 9 */

        r.n = 0;
        op_itree_stab(t, 2, collect_cb, &r);
        CHECK(r.n == 1);   /* only [1,10] contains 2 */

        r.n = 0;
        op_itree_stab(t, 18, collect_cb, &r);
        CHECK(r.n == 1);   /* only [8,20] contains 18 */

        op_itree_destroy(t, NULL, NULL);
    }

    /* [7] same-lo intervals (chaining) */
    SECTION("same-lo");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, 10, 20, (void *)1);
        op_itree_insert(t, 10, 30, (void *)2);
        op_itree_insert(t, 10, 15, (void *)3);
        CHECK(op_itree_count(t) == 3);

        size_t cnt = 0;
        op_itree_stab(t, 12, count_cb, &cnt);
        CHECK(cnt == 3);   /* all three start at 10 and contain 12 */

        cnt = 0;
        op_itree_stab(t, 18, count_cb, &cnt);
        CHECK(cnt == 2);   /* [10,20] and [10,30] but not [10,15] */

        cnt = 0;
        op_itree_stab(t, 25, count_cb, &cnt);
        CHECK(cnt == 1);   /* only [10,30] */

        op_itree_destroy(t, NULL, NULL);
    }

    /* [8] op_itree_overlap */
    SECTION("overlap");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t,  0, 10, (void *)1);
        op_itree_insert(t, 15, 25, (void *)2);
        op_itree_insert(t, 20, 35, (void *)3);
        op_itree_insert(t, 50, 60, (void *)4);

        size_t cnt;

        /* [12, 22] overlaps [15,25] and [20,35] */
        cnt = 0;
        op_itree_overlap(t, 12, 22, count_cb, &cnt);
        CHECK(cnt == 2);

        /* [0, 35] overlaps all but [50,60] */
        cnt = 0;
        op_itree_overlap(t, 0, 35, count_cb, &cnt);
        CHECK(cnt == 3);

        /* [40, 45] overlaps nothing */
        cnt = 0;
        op_itree_overlap(t, 40, 45, count_cb, &cnt);
        CHECK(cnt == 0);

        /* [55, 55] overlaps [50,60] */
        cnt = 0;
        op_itree_overlap(t, 55, 55, count_cb, &cnt);
        CHECK(cnt == 1);

        op_itree_destroy(t, NULL, NULL);
    }

    /* [9] early stop via return false */
    SECTION("early-stop");
    {
        op_itree_t *t = op_itree_create("t");
        for (int i = 0; i < 10; i++)
            op_itree_insert(t, 0, 100, (void *)(intptr_t)i);

        size_t cnt = 0;
        op_itree_stab(t, 50, stop_first_cb, &cnt);
        CHECK(cnt == 1);

        op_itree_destroy(t, NULL, NULL);
    }

    /* [10] delete — found and not-found */
    SECTION("delete");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, 10, 20, (void *)1);
        op_itree_insert(t, 10, 30, (void *)2);
        op_itree_insert(t, 40, 50, (void *)3);

        /* Delete one of the same-lo segments */
        CHECK(op_itree_delete(t, 10, 20, (void *)1) == 1);
        CHECK(op_itree_count(t) == 2);

        /* That segment is gone */
        size_t cnt = 0;
        op_itree_stab(t, 15, count_cb, &cnt);
        CHECK(cnt == 1);   /* only [10,30] remains */

        /* Delete a non-existent interval */
        CHECK(op_itree_delete(t, 10, 20, (void *)1) == 0);

        /* Delete the last interval at lo=10 */
        CHECK(op_itree_delete(t, 10, 30, (void *)2) == 1);
        CHECK(op_itree_count(t) == 1);

        /* [40,50] still there */
        CHECK(op_itree_first_stab(t, 45) == (void *)3);

        op_itree_destroy(t, NULL, NULL);
    }

    /* [11] destroy calls free_fn on all values */
    SECTION("destroy-free");
    {
        g_freed = 0;
        op_itree_t *t = op_itree_create("t");
        for (int i = 0; i < 10; i++)
            op_itree_insert(t, i, i + 5, (void *)(intptr_t)i);
        op_itree_destroy(t, free_cb, NULL);
        CHECK(g_freed == 10);
    }

    /* [12] negative endpoints (Unix timestamps, signed int64) */
    SECTION("negative-endpoints");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, -100, -50, (void *)1);
        op_itree_insert(t,  -60,  10, (void *)2);
        op_itree_insert(t,    0,  50, (void *)3);

        CHECK(op_itree_first_stab(t, -75) == (void *)1);
        CHECK(op_itree_first_stab(t, -55) != NULL);   /* 1 or 2 */

        size_t cnt = 0;
        op_itree_stab(t, 0, count_cb, &cnt);
        CHECK(cnt == 2);   /* [−60,10] and [0,50] */

        op_itree_destroy(t, NULL, NULL);
    }

    /* [13] stress — 1000 intervals, stab at every integer 0..99 */
    SECTION("stress");
    {
        op_itree_t *t = op_itree_create("t");
        /* Insert 1000 intervals [lo, lo+9] for lo in 0..99 (every 10) */
        for (int i = 0; i < 100; i++)
            for (int j = 0; j < 10; j++)
                op_itree_insert(t, i, i + 9, (void *)(intptr_t)(i * 10 + j));
        CHECK(op_itree_count(t) == 1000);

        /* Every point 0..108 should be covered by at least some intervals */
        for (int64_t x = 0; x <= 99; x++)
        {
            size_t cnt = 0;
            op_itree_stab(t, x, count_cb, &cnt);
            /* Each interval [i, i+9] covers x when i <= x <= i+9,
             * i.e. x-9 <= i <= x.  That's at most 10 values of i,
             * each with 10 segments = 100 overlapping intervals max. */
            CHECK(cnt > 0);
        }

        /* Outside range — nothing */
        CHECK(op_itree_first_stab(t, 109) == NULL);

        op_itree_destroy(t, NULL, NULL);
    }

    /* [14] IRC ban-expiry use case: time-based stab */
    SECTION("irc-ban-expiry");
    {
        op_itree_t *t = op_itree_create("bans");
        /* Insert bans that expire at different times (lo=created, hi=expires) */
        int64_t now = 1000;
        op_itree_insert(t, now - 300, now - 1,   (void *)1);  /* already expired */
        op_itree_insert(t, now - 100, now + 200, (void *)2);  /* active */
        op_itree_insert(t, now,       now + 500, (void *)3);  /* active */
        op_itree_insert(t, now + 10,  now + 600, (void *)4);  /* not yet started */

        /* Find all bans active at 'now' (lo <= now <= hi) */
        size_t active = 0;
        op_itree_stab(t, now, count_cb, &active);
        CHECK(active == 2);   /* bans 2 and 3 */

        /* Find all bans that will still be active at now+300 */
        size_t future = 0;
        op_itree_stab(t, now + 300, count_cb, &future);
        CHECK(future == 2);   /* bans 3 and 4 */

        op_itree_destroy(t, NULL, NULL);
    }

    /* [15] overlap query on reversed range is a no-op */
    SECTION("overlap-reversed-noop");
    {
        op_itree_t *t = op_itree_create("t");
        op_itree_insert(t, 10, 20, (void *)1);
        size_t cnt = 0;
        op_itree_overlap(t, 15, 5, count_cb, &cnt);   /* a > b → ignored */
        CHECK(cnt == 0);
        op_itree_destroy(t, NULL, NULL);
    }

    printf("ALL PASS\n");
    return 0;
}
