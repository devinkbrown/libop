/*
 * test_rbt.c — unit tests for op_rbt (LLRB ordered map).
 *
 * Coverage:
 *   [1]  empty tree: get/has/del/min/max return NULL/false
 *   [2]  single element insert + get
 *   [3]  ordered insert (ascending keys): in-order traversal correct
 *   [4]  reverse insert (descending keys): still sorted on output
 *   [5]  random-order insert: sorted traversal
 *   [6]  update existing key: old value returned, count unchanged
 *   [7]  delete non-existent key: NULL returned, tree intact
 *   [8]  delete leaf node
 *   [9]  delete internal node (successor replacement)
 *  [10]  delete root
 *  [11]  delete all elements one by one: tree empties
 *  [12]  min/max key queries
 *  [13]  lower_bound / upper_bound
 *  [14]  iterator: full ascending walk
 *  [15]  iterator: lower-bound seek
 *  [16]  foreach: ascending order, early stop
 *  [17]  foreach_rev: descending order
 *  [18]  case-insensitive comparator (op_rbt_cmp_istr)
 *  [19]  u64 comparator
 *  [20]  large tree (10 000 elements): structure + correctness
 *  [21]  destroy with free_fn
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* ---- helpers ------------------------------------------------------------- */

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)  do { int _before = failures; const char *_sec = (name);
#define END_SECTION    printf("  %-52s %s\n", _sec, \
                             failures == _before ? "pass" : "FAIL"); } while(0)

/* ---- foreach tracking ---------------------------------------------------- */

static int    fe_count;
static char   fe_last_key[64];
static bool   fe_sorted;
static char   fe_prev_key[64];

static bool
fe_asc(void *key, void *val, void *ud)
{
    (void)val; (void)ud;
    if (fe_count > 0 && strcmp((char *)key, fe_prev_key) <= 0)
        fe_sorted = false;
    op_strlcpy(fe_prev_key, (char *)key, sizeof(fe_prev_key));
    op_strlcpy(fe_last_key, (char *)key, sizeof(fe_last_key));
    fe_count++;
    return true;
}

static int fe_stop_at;
static bool
fe_early_stop(void *key, void *val, void *ud)
{
    (void)val; (void)ud; (void)key;
    fe_count++;
    return fe_count < fe_stop_at;
}

static bool
fe_desc(void *key, void *val, void *ud)
{
    (void)val; (void)ud;
    if (fe_count > 0 && strcmp((char *)key, fe_prev_key) >= 0)
        fe_sorted = false;
    op_strlcpy(fe_prev_key, (char *)key, sizeof(fe_prev_key));
    fe_count++;
    return true;
}

/* ---- tests --------------------------------------------------------------- */

static void
test_empty(void)
{
    op_rbt_t *t = op_rbt_create("empty", op_rbt_cmp_str);

    SECTION("[1] empty tree");
    CHECK(op_rbt_size(t) == 0);
    CHECK(op_rbt_get(t, "x") == NULL);
    CHECK(!op_rbt_has(t, "x"));
    CHECK(op_rbt_del(t, "x") == NULL);
    CHECK(op_rbt_min_key(t) == NULL);
    CHECK(op_rbt_max_key(t) == NULL);
    CHECK(op_rbt_lower_bound(t, "x") == NULL);
    CHECK(op_rbt_upper_bound(t, "x") == NULL);
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_single(void)
{
    op_rbt_t *t = op_rbt_create("single", op_rbt_cmp_str);

    SECTION("[2] single element");
    op_rbt_set(t, "hello", (void *)42, NULL);
    CHECK(op_rbt_size(t) == 1);
    CHECK((intptr_t)op_rbt_get(t, "hello") == 42);
    CHECK(op_rbt_has(t, "hello"));
    CHECK(!op_rbt_has(t, "world"));
    CHECK(strcmp(op_rbt_min_key(t), "hello") == 0);
    CHECK(strcmp(op_rbt_max_key(t), "hello") == 0);
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_ordered_insert(void)
{
    op_rbt_t *t = op_rbt_create("asc", op_rbt_cmp_str);

    SECTION("[3] ascending insert + in-order traversal");
    {
        const char *keys[] = { "aaa", "bbb", "ccc", "ddd", "eee" };
        int n = 5;
        for (int i = 0; i < n; i++)
            op_rbt_set(t, (void *)keys[i], (void *)(intptr_t)i, NULL);
        CHECK(op_rbt_size(t) == (size_t)n);

        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach(t, fe_asc, NULL);
        CHECK(fe_count == n);
        CHECK(fe_sorted);
        CHECK(strcmp(fe_last_key, "eee") == 0);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_reverse_insert(void)
{
    op_rbt_t *t = op_rbt_create("rev", op_rbt_cmp_str);

    SECTION("[4] descending insert → sorted traversal");
    {
        const char *keys[] = { "eee", "ddd", "ccc", "bbb", "aaa" };
        for (int i = 0; i < 5; i++)
            op_rbt_set(t, (void *)keys[i], NULL, NULL);

        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach(t, fe_asc, NULL);
        CHECK(fe_count == 5);
        CHECK(fe_sorted);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

/* Simple deterministic shuffle (Fisher-Yates with fixed seed). */
static void
shuffle(const char **arr, int n)
{
    unsigned seed = 42;
    for (int i = n - 1; i > 0; i--)
    {
        seed = seed * 1664525u + 1013904223u;
        int j = (int)((seed >> 16) % (unsigned)(i + 1));
        const char *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

static void
test_random_insert(void)
{
    op_rbt_t *t = op_rbt_create("rand", op_rbt_cmp_str);

    SECTION("[5] random-order insert → sorted traversal");
    {
        const char *keys[] = {
            "mango", "apple", "cherry", "banana", "date", "elderberry",
            "fig", "grape", "honeydew", "kiwi", "lemon", "nectarine"
        };
        int n = 12;
        const char *shuf[12];
        memcpy(shuf, keys, sizeof(shuf));
        shuffle(shuf, n);

        for (int i = 0; i < n; i++)
            op_rbt_set(t, (void *)shuf[i], NULL, NULL);

        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach(t, fe_asc, NULL);
        CHECK(fe_count == n);
        CHECK(fe_sorted);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_update(void)
{
    op_rbt_t *t = op_rbt_create("upd", op_rbt_cmp_str);

    SECTION("[6] update existing key");
    {
        op_rbt_set(t, "k", (void *)1, NULL);
        void *old = NULL;
        int r = op_rbt_set(t, "k", (void *)2, &old);
        CHECK(r == 0);                      /* 0 = update, not insert */
        CHECK((intptr_t)old == 1);
        CHECK((intptr_t)op_rbt_get(t, "k") == 2);
        CHECK(op_rbt_size(t) == 1);         /* count unchanged */
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_delete(void)
{
    op_rbt_t *t = op_rbt_create("del", op_rbt_cmp_str);

    SECTION("[7] delete non-existent");
    {
        op_rbt_set(t, "x", (void *)1, NULL);
        CHECK(op_rbt_del(t, "zzz") == NULL);
        CHECK(op_rbt_size(t) == 1);
    }
    END_SECTION;

    SECTION("[8] delete leaf");
    {
        /* t has only "x" which is now the root leaf. */
        void *v = op_rbt_del(t, "x");
        CHECK((intptr_t)v == 1);
        CHECK(op_rbt_size(t) == 0);
        CHECK(!op_rbt_has(t, "x"));
    }
    END_SECTION;

    SECTION("[9] delete internal node");
    {
        op_rbt_set(t, "b", (void *)2, NULL);
        op_rbt_set(t, "a", (void *)1, NULL);
        op_rbt_set(t, "c", (void *)3, NULL);
        /* "b" is the root with left "a" and right "c". */
        void *v = op_rbt_del(t, "b");
        CHECK((intptr_t)v == 2);
        CHECK(op_rbt_size(t) == 2);
        CHECK(!op_rbt_has(t, "b"));
        CHECK(op_rbt_has(t, "a"));
        CHECK(op_rbt_has(t, "c"));
    }
    END_SECTION;

    SECTION("[10] delete root (only element)");
    {
        op_rbt_del(t, "a");
        op_rbt_del(t, "c");
        /* Empty now. */
        op_rbt_set(t, "r", (void *)99, NULL);
        void *v = op_rbt_del(t, "r");
        CHECK((intptr_t)v == 99);
        CHECK(op_rbt_size(t) == 0);
    }
    END_SECTION;

    SECTION("[11] insert 20 elements, delete all one by one");
    {
        char keys[20][8];
        for (int i = 0; i < 20; i++)
        {
            snprintf(keys[i], sizeof(keys[i]), "k%02d", i);
            op_rbt_set(t, keys[i], (void *)(intptr_t)i, NULL);
        }
        CHECK(op_rbt_size(t) == 20);

        /* Delete in a non-sequential order to stress the tree. */
        int order[] = { 5, 15, 0, 19, 10, 3, 17, 7, 12, 1,
                        18, 8, 4, 14, 6, 11, 2, 16, 9, 13 };
        for (int i = 0; i < 20; i++)
        {
            char *k = keys[order[i]];
            void *v = op_rbt_del(t, k);
            CHECK((intptr_t)v == order[i]);
        }
        CHECK(op_rbt_size(t) == 0);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_min_max(void)
{
    op_rbt_t *t = op_rbt_create("minmax", op_rbt_cmp_str);

    SECTION("[12] min/max key");
    {
        op_rbt_set(t, "dog", NULL, NULL);
        op_rbt_set(t, "cat", NULL, NULL);
        op_rbt_set(t, "zebra", NULL, NULL);
        op_rbt_set(t, "ant", NULL, NULL);
        CHECK(strcmp(op_rbt_min_key(t), "ant") == 0);
        CHECK(strcmp(op_rbt_max_key(t), "zebra") == 0);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_bounds(void)
{
    op_rbt_t *t = op_rbt_create("bounds", op_rbt_cmp_str);

    SECTION("[13] lower_bound / upper_bound");
    {
        const char *keys[] = { "a", "c", "e", "g", "i" };
        for (int i = 0; i < 5; i++)
            op_rbt_set(t, (void *)keys[i], NULL, NULL);

        /* lower_bound: smallest key >= query */
        CHECK(strcmp(op_rbt_lower_bound(t, "a"), "a") == 0);
        CHECK(strcmp(op_rbt_lower_bound(t, "b"), "c") == 0);  /* next key */
        CHECK(strcmp(op_rbt_lower_bound(t, "e"), "e") == 0);
        CHECK(strcmp(op_rbt_lower_bound(t, "f"), "g") == 0);
        CHECK(op_rbt_lower_bound(t, "z") == NULL);             /* past end */

        /* upper_bound: smallest key > query */
        CHECK(strcmp(op_rbt_upper_bound(t, "a"), "c") == 0);
        CHECK(strcmp(op_rbt_upper_bound(t, "b"), "c") == 0);
        CHECK(strcmp(op_rbt_upper_bound(t, "e"), "g") == 0);
        CHECK(op_rbt_upper_bound(t, "i") == NULL);             /* no key > "i" */
        CHECK(op_rbt_upper_bound(t, "z") == NULL);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_iterator(void)
{
    op_rbt_t *t = op_rbt_create("iter", op_rbt_cmp_str);

    SECTION("[14] iterator: full ascending walk");
    {
        const char *keys[] = { "bravo", "alpha", "delta", "charlie", "echo" };
        for (int i = 0; i < 5; i++)
            op_rbt_set(t, (void *)keys[i], (void *)(intptr_t)i, NULL);

        op_rbt_iter_t it;
        op_rbt_iter_init(&it, t);

        const char *expected[] = { "alpha", "bravo", "charlie", "delta", "echo" };
        int count = 0;
        void *k, *v;
        while (op_rbt_iter_next(&it, &k, &v))
        {
            if (count < 5)
                CHECK(strcmp((char *)k, expected[count]) == 0);
            count++;
        }
        CHECK(count == 5);
    }
    END_SECTION;

    SECTION("[15] iterator: lower-bound seek");
    {
        op_rbt_iter_t it;
        op_rbt_iter_lower(&it, t, "charlie");

        void *k;
        op_rbt_iter_next(&it, &k, NULL);
        CHECK(strcmp((char *)k, "charlie") == 0);

        op_rbt_iter_next(&it, &k, NULL);
        CHECK(strcmp((char *)k, "delta") == 0);

        op_rbt_iter_next(&it, &k, NULL);
        CHECK(strcmp((char *)k, "echo") == 0);

        CHECK(!op_rbt_iter_next(&it, &k, NULL));   /* exhausted */
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_foreach(void)
{
    op_rbt_t *t = op_rbt_create("fe", op_rbt_cmp_str);

    SECTION("[16] foreach: ascending + early stop");
    {
        const char *keys[] = { "e", "b", "d", "a", "c" };
        for (int i = 0; i < 5; i++)
            op_rbt_set(t, (void *)keys[i], NULL, NULL);

        /* Full walk — must be sorted */
        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach(t, fe_asc, NULL);
        CHECK(fe_count == 5);
        CHECK(fe_sorted);

        /* Early stop after 3 */
        fe_count = 0; fe_stop_at = 3;
        op_rbt_foreach(t, fe_early_stop, NULL);
        CHECK(fe_count == 3);
    }
    END_SECTION;

    SECTION("[17] foreach_rev: descending order");
    {
        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach_rev(t, fe_desc, NULL);
        CHECK(fe_count == 5);
        CHECK(fe_sorted);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_icase(void)
{
    op_rbt_t *t = op_rbt_create("icase", op_rbt_cmp_istr);

    SECTION("[18] case-insensitive comparator");
    {
        op_rbt_set(t, "Nick", (void *)1, NULL);
        CHECK((intptr_t)op_rbt_get(t, "nick") == 1);
        CHECK((intptr_t)op_rbt_get(t, "NICK") == 1);

        void *old = NULL;
        op_rbt_set(t, "NICK", (void *)2, &old);
        CHECK((intptr_t)old == 1);         /* update, not insert */
        CHECK(op_rbt_size(t) == 1);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_u64(void)
{
    op_rbt_t *t = op_rbt_create("u64", op_rbt_cmp_u64);

    SECTION("[19] u64 comparator");
    {
        uint64_t keys[] = { 500, 100, 900, 1, 9999, 42 };
        for (int i = 0; i < 6; i++)
            op_rbt_set(t, &keys[i], (void *)(uintptr_t)keys[i], NULL);

        /* min should be 1, max should be 9999 */
        CHECK(*(uint64_t *)op_rbt_min_key(t) == 1);
        CHECK(*(uint64_t *)op_rbt_max_key(t) == 9999);
        CHECK(op_rbt_size(t) == 6);

        /* lookup 42 */
        uint64_t q = 42;
        CHECK((uintptr_t)op_rbt_get(t, &q) == 42);

        /* delete 500 */
        uint64_t d = 500;
        CHECK((uintptr_t)op_rbt_del(t, &d) == 500);
        CHECK(op_rbt_size(t) == 5);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static void
test_large(void)
{
    op_rbt_t *t = op_rbt_create("large", op_rbt_cmp_str);

    SECTION("[20] 10 000 elements: insert + traversal + delete");
    {
        /* Insert 10 000 keys in a deterministic pseudo-random order. */
        char **keys = op_malloc(10000 * sizeof(char *));
        unsigned seed = 123456789;
        for (int i = 0; i < 10000; i++)
        {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "key_%08u", i);
            keys[i] = op_strdup(tmp);
        }

        /* Shuffle keys for insertion order. */
        for (int i = 9999; i > 0; i--)
        {
            seed = seed * 1664525u + 1013904223u;
            int j = (int)((seed >> 16) % (unsigned)(i + 1));
            char *tmp = keys[i]; keys[i] = keys[j]; keys[j] = tmp;
        }

        for (int i = 0; i < 10000; i++)
            op_rbt_set(t, keys[i], (void *)(intptr_t)i, NULL);

        CHECK(op_rbt_size(t) == 10000);

        /* Verify sorted traversal. */
        fe_count = 0; fe_sorted = true; fe_prev_key[0] = '\0';
        op_rbt_foreach(t, fe_asc, NULL);
        CHECK(fe_count == 10000);
        CHECK(fe_sorted);

        /* Delete all keys.  Note: i=0 has val=(void*)0 (NULL) which is a
         * valid value, so we use op_rbt_has() before/after to verify. */
        for (int i = 0; i < 10000; i++)
        {
            bool was_present = op_rbt_has(t, keys[i]);
            op_rbt_del(t, keys[i]);
            CHECK(was_present);
        }
        CHECK(op_rbt_size(t) == 0);

        for (int i = 0; i < 10000; i++)
            op_free(keys[i]);
        op_free(keys);
    }
    END_SECTION;

    op_rbt_destroy(t, NULL, NULL);
}

static int destroy_count = 0;
static void
on_destroy(void *key, void *val, void *ud)
{
    (void)key; (void)val; (void)ud;
    destroy_count++;
}

static void
test_destroy(void)
{
    op_rbt_t *t = op_rbt_create("dtroy", op_rbt_cmp_str);

    SECTION("[21] destroy with free_fn");
    {
        op_rbt_set(t, "a", NULL, NULL);
        op_rbt_set(t, "b", NULL, NULL);
        op_rbt_set(t, "c", NULL, NULL);
        destroy_count = 0;
        op_rbt_destroy(t, on_destroy, NULL);
        CHECK(destroy_count == 3);
        t = NULL;
    }
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("test_rbt:\n");

    test_empty();
    test_single();
    test_ordered_insert();
    test_reverse_insert();
    test_random_insert();
    test_update();
    test_delete();
    test_min_max();
    test_bounds();
    test_iterator();
    test_foreach();
    test_icase();
    test_u64();
    test_large();
    test_destroy();

    if (failures == 0)
        printf("  PASS (21 sections)\n");
    else
        printf("  FAIL (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
