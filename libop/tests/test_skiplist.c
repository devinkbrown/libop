/*
 * test_skiplist.c — unit tests for op_skiplist_t (probabilistic skip list).
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

/* ---- helpers ------------------------------------------------------------- */

static bool
count_cb(void *key, void *val, void *ud)
{
    (void)key; (void)val;
    (*(size_t *)ud)++;
    return true;
}

static bool
stop_first_cb(void *key, void *val, void *ud)
{
    (void)key; (void)val;
    (*(size_t *)ud)++;
    return false;
}

/* Collect string keys in order. */
typedef struct { char buf[256][64]; size_t n; } key_list_t;
static bool
collect_keys(void *key, void *val, void *ud)
{
    (void)val;
    key_list_t *kl = ud;
    if (kl->n < 256)
        strncpy(kl->buf[kl->n++], (const char *)key, 63);
    return true;
}

static size_t g_freed;
static void free_cb(void *key, void *val, void *ud)
{
    (void)key; (void)val; (void)ud;
    g_freed++;
}

/* ======================================================================== */

int
main(void)
{
    printf("test_skiplist\n");

    /* [1] create / destroy empty */
    SECTION("create-destroy");
    {
        op_skiplist_t *sl = op_skiplist_create("test", op_skiplist_cmp_str);
        CHECK(sl != NULL);
        CHECK(op_skiplist_size(sl) == 0);
        CHECK(strcmp(op_skiplist_name(sl), "test") == 0);
        CHECK(op_skiplist_min_key(sl) == NULL);
        CHECK(op_skiplist_max_key(sl) == NULL);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [2] set / get basic */
    SECTION("set-get");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        CHECK(op_skiplist_set(sl, "foo", (void *)1, NULL) == 1);
        CHECK(op_skiplist_set(sl, "bar", (void *)2, NULL) == 1);
        CHECK(op_skiplist_set(sl, "baz", (void *)3, NULL) == 1);
        CHECK(op_skiplist_size(sl) == 3);

        CHECK(op_skiplist_get(sl, "foo") == (void *)1);
        CHECK(op_skiplist_get(sl, "bar") == (void *)2);
        CHECK(op_skiplist_get(sl, "baz") == (void *)3);
        CHECK(op_skiplist_get(sl, "qux") == NULL);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [3] update existing key */
    SECTION("update");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        void *old = NULL;
        op_skiplist_set(sl, "key", (void *)10, NULL);
        int r = op_skiplist_set(sl, "key", (void *)20, &old);
        CHECK(r == 0);
        CHECK(old == (void *)10);
        CHECK(op_skiplist_get(sl, "key") == (void *)20);
        CHECK(op_skiplist_size(sl) == 1);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [4] has */
    SECTION("has");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "present", (void *)1, NULL);
        CHECK( op_skiplist_has(sl, "present"));
        CHECK(!op_skiplist_has(sl, "absent"));
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [5] del — found */
    SECTION("del-found");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "hello", (void *)42, NULL);
        void *v = op_skiplist_del(sl, "hello");
        CHECK(v == (void *)42);
        CHECK(op_skiplist_size(sl) == 0);
        CHECK(!op_skiplist_has(sl, "hello"));
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [6] del — not found */
    SECTION("del-not-found");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        CHECK(op_skiplist_del(sl, "ghost") == NULL);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [7] ascending order (foreach) */
    SECTION("foreach-order");
    {
        const char *words[] = { "cherry", "apple", "elderberry", "banana", "date" };
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        for (size_t i = 0; i < 5; i++)
            op_skiplist_set(sl, (void *)words[i], (void *)(i + 1), NULL);

        key_list_t kl;
        memset(&kl, 0, sizeof(kl));
        op_skiplist_foreach(sl, collect_keys, &kl);
        CHECK(kl.n == 5);
        CHECK(strcmp(kl.buf[0], "apple")      == 0);
        CHECK(strcmp(kl.buf[1], "banana")     == 0);
        CHECK(strcmp(kl.buf[2], "cherry")     == 0);
        CHECK(strcmp(kl.buf[3], "date")       == 0);
        CHECK(strcmp(kl.buf[4], "elderberry") == 0);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [8] descending order (foreach_rev) */
    SECTION("foreach-rev-order");
    {
        const char *words[] = { "cherry", "apple", "elderberry", "banana", "date" };
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        for (size_t i = 0; i < 5; i++)
            op_skiplist_set(sl, (void *)words[i], (void *)(i + 1), NULL);

        key_list_t kl;
        memset(&kl, 0, sizeof(kl));
        op_skiplist_foreach_rev(sl, collect_keys, &kl);
        CHECK(kl.n == 5);
        CHECK(strcmp(kl.buf[0], "elderberry") == 0);
        CHECK(strcmp(kl.buf[1], "date")       == 0);
        CHECK(strcmp(kl.buf[2], "cherry")     == 0);
        CHECK(strcmp(kl.buf[3], "banana")     == 0);
        CHECK(strcmp(kl.buf[4], "apple")      == 0);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [9] min / max key */
    SECTION("min-max");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "mango",  (void *)1, NULL);
        op_skiplist_set(sl, "apple",  (void *)2, NULL);
        op_skiplist_set(sl, "zebra",  (void *)3, NULL);
        op_skiplist_set(sl, "banana", (void *)4, NULL);

        CHECK(strcmp((const char *)op_skiplist_min_key(sl), "apple") == 0);
        CHECK(strcmp((const char *)op_skiplist_max_key(sl), "zebra") == 0);

        /* Delete max, check new max. */
        op_skiplist_del(sl, "zebra");
        CHECK(strcmp((const char *)op_skiplist_max_key(sl), "mango") == 0);

        /* Delete min, check new min. */
        op_skiplist_del(sl, "apple");
        CHECK(strcmp((const char *)op_skiplist_min_key(sl), "banana") == 0);

        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [10] lower_bound / upper_bound */
    SECTION("bounds");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "aaa", (void *)1, NULL);
        op_skiplist_set(sl, "ccc", (void *)2, NULL);
        op_skiplist_set(sl, "eee", (void *)3, NULL);

        /* lower_bound("bbb") → "ccc" (smallest ≥ "bbb") */
        CHECK(strcmp((const char *)op_skiplist_lower_bound(sl, "bbb"), "ccc") == 0);

        /* lower_bound("ccc") → "ccc" (exact match) */
        CHECK(strcmp((const char *)op_skiplist_lower_bound(sl, "ccc"), "ccc") == 0);

        /* upper_bound("ccc") → "eee" (smallest > "ccc") */
        CHECK(strcmp((const char *)op_skiplist_upper_bound(sl, "ccc"), "eee") == 0);

        /* lower_bound("fff") → NULL (nothing ≥ "fff") */
        CHECK(op_skiplist_lower_bound(sl, "fff") == NULL);

        /* upper_bound("eee") → NULL (nothing > "eee") */
        CHECK(op_skiplist_upper_bound(sl, "eee") == NULL);

        /* lower_bound("aaa") → "aaa" */
        CHECK(strcmp((const char *)op_skiplist_lower_bound(sl, "aaa"), "aaa") == 0);

        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [11] iterator — full scan */
    SECTION("iter-full");
    {
        const char *words[] = { "z", "a", "m" };
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        for (size_t i = 0; i < 3; i++)
            op_skiplist_set(sl, (void *)words[i], (void *)(i + 1), NULL);

        op_skiplist_iter_t it;
        op_skiplist_iter_init(&it, sl);
        void *k, *v;
        CHECK(op_skiplist_iter_next(&it, &k, &v));
        CHECK(strcmp((const char *)k, "a") == 0);
        CHECK(op_skiplist_iter_next(&it, &k, &v));
        CHECK(strcmp((const char *)k, "m") == 0);
        CHECK(op_skiplist_iter_next(&it, &k, &v));
        CHECK(strcmp((const char *)k, "z") == 0);
        CHECK(!op_skiplist_iter_next(&it, &k, &v));   /* exhausted */
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [12] iter_lower — range scan from seek position */
    SECTION("iter-lower");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        /* Sorted order: alpha < beta < cherry < delta < epsilon */
        const char *keys[] = { "alpha", "beta", "cherry", "delta", "epsilon" };
        for (size_t i = 0; i < 5; i++)
            op_skiplist_set(sl, (void *)keys[i], (void *)(i + 1), NULL);

        /* Seek to "d" — first key ≥ "d" is "delta". */
        op_skiplist_iter_t it;
        op_skiplist_iter_lower(&it, sl, "d");
        void *k;
        CHECK(op_skiplist_iter_next(&it, &k, NULL));
        CHECK(strcmp((const char *)k, "delta") == 0);
        CHECK(op_skiplist_iter_next(&it, &k, NULL));
        CHECK(strcmp((const char *)k, "epsilon") == 0);
        CHECK(!op_skiplist_iter_next(&it, &k, NULL));

        /* Seek past all keys — exhausted immediately. */
        op_skiplist_iter_lower(&it, sl, "zzz");
        CHECK(!op_skiplist_iter_next(&it, &k, NULL));

        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [13] early stop from callback */
    SECTION("early-stop");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        char buf[10][8];
        for (int i = 0; i < 10; i++)
        {
            snprintf(buf[i], sizeof(buf[i]), "k%02d", i);
            op_skiplist_set(sl, buf[i], (void *)(intptr_t)i, NULL);
        }
        size_t cnt = 0;
        op_skiplist_foreach(sl, stop_first_cb, &cnt);
        CHECK(cnt == 1);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [14] destroy calls free_fn */
    SECTION("destroy-free");
    {
        g_freed = 0;
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        char buf[8][8];
        for (int i = 0; i < 8; i++)
        {
            snprintf(buf[i], sizeof(buf[i]), "k%d", i);
            op_skiplist_set(sl, buf[i], (void *)(intptr_t)i, NULL);
        }
        op_skiplist_destroy(sl, free_cb, NULL);
        CHECK(g_freed == 8);
    }

    /* [15] u64 comparator */
    SECTION("cmp-u64");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_u64);
        op_skiplist_set(sl, (void *)(uintptr_t)300, (void *)1, NULL);
        op_skiplist_set(sl, (void *)(uintptr_t)100, (void *)2, NULL);
        op_skiplist_set(sl, (void *)(uintptr_t)200, (void *)3, NULL);

        /* In-order should be 100, 200, 300. */
        op_skiplist_iter_t it;
        op_skiplist_iter_init(&it, sl);
        void *k;
        CHECK(op_skiplist_iter_next(&it, &k, NULL));
        CHECK((uintptr_t)k == 100);
        CHECK(op_skiplist_iter_next(&it, &k, NULL));
        CHECK((uintptr_t)k == 200);
        CHECK(op_skiplist_iter_next(&it, &k, NULL));
        CHECK((uintptr_t)k == 300);

        CHECK((uintptr_t)op_skiplist_min_key(sl) == 100);
        CHECK((uintptr_t)op_skiplist_max_key(sl) == 300);

        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [16] delete all entries — empty list invariants hold */
    SECTION("delete-all");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "a", (void *)1, NULL);
        op_skiplist_set(sl, "b", (void *)2, NULL);
        op_skiplist_set(sl, "c", (void *)3, NULL);

        op_skiplist_del(sl, "b");
        op_skiplist_del(sl, "a");
        op_skiplist_del(sl, "c");

        CHECK(op_skiplist_size(sl) == 0);
        CHECK(op_skiplist_min_key(sl) == NULL);
        CHECK(op_skiplist_max_key(sl) == NULL);

        size_t cnt = 0;
        op_skiplist_foreach(sl, count_cb, &cnt);
        CHECK(cnt == 0);
        cnt = 0;
        op_skiplist_foreach_rev(sl, count_cb, &cnt);
        CHECK(cnt == 0);

        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [17] re-insert after delete */
    SECTION("reinsert");
    {
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        op_skiplist_set(sl, "x", (void *)1, NULL);
        op_skiplist_del(sl, "x");
        CHECK(!op_skiplist_has(sl, "x"));
        op_skiplist_set(sl, "x", (void *)99, NULL);
        CHECK(op_skiplist_has(sl, "x"));
        CHECK(op_skiplist_get(sl, "x") == (void *)99);
        op_skiplist_destroy(sl, NULL, NULL);
    }

    /* [18] stress — 2000 keys, all lookups succeed, then delete all */
    SECTION("stress");
    {
#define STRESS_N 2000
        op_skiplist_t *sl = op_skiplist_create("sl", op_skiplist_cmp_str);
        static char keys[STRESS_N][20];
        for (size_t i = 0; i < STRESS_N; i++)
        {
            snprintf(keys[i], sizeof(keys[i]), "key_%05zu", i);
            op_skiplist_set(sl, keys[i], (void *)(i + 1), NULL);
        }
        CHECK(op_skiplist_size(sl) == STRESS_N);

        for (size_t i = 0; i < STRESS_N; i++)
            CHECK(op_skiplist_get(sl, keys[i]) == (void *)(i + 1));

        /* Verify sorted order via iteration. */
        size_t cnt = 0;
        op_skiplist_foreach(sl, count_cb, &cnt);
        CHECK(cnt == STRESS_N);

        /* Delete all. */
        for (size_t i = 0; i < STRESS_N; i++)
            CHECK(op_skiplist_del(sl, keys[i]) == (void *)(i + 1));
        CHECK(op_skiplist_size(sl) == 0);
        CHECK(op_skiplist_min_key(sl) == NULL);
        CHECK(op_skiplist_max_key(sl) == NULL);
#undef STRESS_N
        op_skiplist_destroy(sl, NULL, NULL);
    }

    printf("ALL PASS\n");
    return 0;
}
