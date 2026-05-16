/*
 * libop/tests/test_vec.c — unit tests for op_vec.h / vec.c
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_vec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ---- test harness -------------------------------------------------------- */

static int g_pass, g_fail;

#define SECTION(name)  do { printf("  %s\n", name); } while (0)
#define CHECK(expr)                                              \
    do {                                                         \
        if (expr) { g_pass++; }                                 \
        else {                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n",                 \
                    __FILE__, __LINE__, #expr);                  \
            g_fail++;                                            \
        }                                                        \
    } while (0)

/* ---- helpers ------------------------------------------------------------- */

#define INT2PTR(n)  ((void *)(intptr_t)(n))
#define PTR2INT(p)  ((int)(intptr_t)(p))

/* ---- tests --------------------------------------------------------------- */

static void
test_init_empty(void)
{
    SECTION("init / empty state");
    op_vec_t v;
    op_vec_init(&v, 0);
    CHECK(op_vec_empty(&v));
    CHECK(op_vec_size(&v) == 0);
    CHECK(v.cap > 0);
    op_vec_fini(&v, NULL, NULL);
}

static void
test_push_pop(void)
{
    SECTION("push / pop");
    op_vec_t v;
    op_vec_init(&v, 4);

    op_vec_push(&v, INT2PTR(10));
    op_vec_push(&v, INT2PTR(20));
    op_vec_push(&v, INT2PTR(30));

    CHECK(op_vec_size(&v) == 3);
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 10);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 20);
    CHECK(PTR2INT(op_vec_get(&v, 2)) == 30);

    CHECK(PTR2INT(op_vec_pop(&v)) == 30);
    CHECK(PTR2INT(op_vec_pop(&v)) == 20);
    CHECK(PTR2INT(op_vec_pop(&v)) == 10);
    CHECK(op_vec_pop(&v) == NULL);   /* empty */
    CHECK(op_vec_empty(&v));
    op_vec_fini(&v, NULL, NULL);
}

static void
test_insert_remove(void)
{
    SECTION("insert / remove (ordered)");
    op_vec_t v;
    op_vec_init(&v, 0);

    op_vec_push(&v, INT2PTR(1));
    op_vec_push(&v, INT2PTR(3));
    op_vec_insert(&v, 1, INT2PTR(2));   /* [1, 2, 3] */

    CHECK(op_vec_size(&v) == 3);
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 1);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 2);
    CHECK(PTR2INT(op_vec_get(&v, 2)) == 3);

    /* Remove middle element */
    void *removed = op_vec_remove(&v, 1);
    CHECK(PTR2INT(removed) == 2);
    CHECK(op_vec_size(&v) == 2);
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 1);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 3);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_remove_fast(void)
{
    SECTION("remove_fast (unordered swap-with-last)");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(10));
    op_vec_push(&v, INT2PTR(20));
    op_vec_push(&v, INT2PTR(30));

    /* Remove index 0 — last element (30) fills the hole */
    void *elem = op_vec_remove_fast(&v, 0);
    CHECK(PTR2INT(elem) == 10);
    CHECK(op_vec_size(&v) == 2);
    /* The new [0] should be 30 (swapped in from end) */
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 30);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 20);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_set(void)
{
    SECTION("op_vec_set");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(1));
    op_vec_push(&v, INT2PTR(2));
    op_vec_set(&v, 1, INT2PTR(99));
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 99);
    op_vec_fini(&v, NULL, NULL);
}

static void
test_growth(void)
{
    SECTION("growth — 1000 elements");
    op_vec_t v;
    op_vec_init(&v, 1);   /* deliberately tiny initial cap */

    for (int i = 0; i < 1000; i++)
        op_vec_push(&v, INT2PTR(i));

    CHECK(op_vec_size(&v) == 1000);
    for (int i = 0; i < 1000; i++)
        CHECK(PTR2INT(op_vec_get(&v, i)) == i);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_clear(void)
{
    SECTION("op_vec_clear");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(1));
    op_vec_push(&v, INT2PTR(2));
    op_vec_clear(&v, NULL, NULL);
    CHECK(op_vec_size(&v) == 0);
    CHECK(op_vec_empty(&v));
    /* backing buffer still usable after clear */
    op_vec_push(&v, INT2PTR(42));
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 42);
    op_vec_fini(&v, NULL, NULL);
}

static int g_freed_sum;

static void
free_sum_cb(void *e, void *ud)
{
    (void)ud;
    g_freed_sum += PTR2INT(e);
}

static void
test_fini_with_cb(void)
{
    SECTION("op_vec_fini calls free_cb for each element");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(10));
    op_vec_push(&v, INT2PTR(20));
    op_vec_push(&v, INT2PTR(30));

    g_freed_sum = 0;
    op_vec_fini(&v, free_sum_cb, NULL);
    CHECK(g_freed_sum == 60);
}

static void
test_reserve_shrink(void)
{
    SECTION("reserve / shrink");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_reserve(&v, 256);
    CHECK(v.cap >= 256);
    op_vec_push(&v, INT2PTR(1));
    op_vec_shrink(&v);
    CHECK(v.cap == 1);
    op_vec_fini(&v, NULL, NULL);
}

static int
cmp_int(const void *a, const void *b)
{
    intptr_t ia = (intptr_t)a;
    intptr_t ib = (intptr_t)b;
    return (ia > ib) - (ia < ib);
}

static int
qsort_cmp(const void *a, const void *b)
{
    /* a and b are pointers to void* elements */
    return cmp_int(*(const void * const *)a, *(const void * const *)b);
}

static void
test_find(void)
{
    SECTION("op_vec_find — linear search");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(5));
    op_vec_push(&v, INT2PTR(3));
    op_vec_push(&v, INT2PTR(8));

    CHECK(op_vec_find(&v, INT2PTR(3), cmp_int) == 1);
    CHECK(op_vec_find(&v, INT2PTR(8), cmp_int) == 2);
    CHECK(op_vec_find(&v, INT2PTR(99), cmp_int) == (size_t)-1);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_bsearch_sort(void)
{
    SECTION("op_vec_sort + op_vec_bsearch");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(7));
    op_vec_push(&v, INT2PTR(1));
    op_vec_push(&v, INT2PTR(4));
    op_vec_push(&v, INT2PTR(2));
    op_vec_push(&v, INT2PTR(9));

    op_vec_sort(&v, qsort_cmp);

    /* After sort, elements should be ascending */
    CHECK(PTR2INT(op_vec_get(&v, 0)) == 1);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 2);
    CHECK(PTR2INT(op_vec_get(&v, 2)) == 4);
    CHECK(PTR2INT(op_vec_get(&v, 3)) == 7);
    CHECK(PTR2INT(op_vec_get(&v, 4)) == 9);

    CHECK(op_vec_bsearch(&v, INT2PTR(4), cmp_int) == 2);
    CHECK(op_vec_bsearch(&v, INT2PTR(1), cmp_int) == 0);
    CHECK(op_vec_bsearch(&v, INT2PTR(9), cmp_int) == 4);
    CHECK(op_vec_bsearch(&v, INT2PTR(6), cmp_int) == (size_t)-1);

    op_vec_fini(&v, NULL, NULL);
}

static int
foreach_sum_cb(void *e, void *ud)
{
    int *sum = ud;
    *sum += PTR2INT(e);
    return 0;
}

static void
test_foreach(void)
{
    SECTION("op_vec_foreach");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(10));
    op_vec_push(&v, INT2PTR(20));
    op_vec_push(&v, INT2PTR(30));

    int sum = 0;
    op_vec_foreach(&v, foreach_sum_cb, &sum);
    CHECK(sum == 60);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_macro_foreach(void)
{
    SECTION("OP_VEC_FOREACH macro");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(5));
    op_vec_push(&v, INT2PTR(10));
    op_vec_push(&v, INT2PTR(15));

    int sum = 0;
    size_t idx;
    void *elem;
    OP_VEC_FOREACH(&v, idx, elem)
        sum += PTR2INT(elem);
    CHECK(sum == 30);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_heap_create_destroy(void)
{
    SECTION("op_vec_create / op_vec_destroy");
    op_vec_t *v = op_vec_create(4);
    CHECK(v != NULL);
    op_vec_push(v, INT2PTR(100));
    op_vec_push(v, INT2PTR(200));
    CHECK(op_vec_size(v) == 2);
    CHECK(PTR2INT(op_vec_get(v, 0)) == 100);
    op_vec_destroy(v, NULL, NULL);
}

static void
test_insert_at_end(void)
{
    SECTION("insert at end == push");
    op_vec_t v;
    op_vec_init(&v, 0);
    op_vec_push(&v, INT2PTR(1));
    op_vec_insert(&v, 1, INT2PTR(2));   /* insert at size == push */
    CHECK(op_vec_size(&v) == 2);
    CHECK(PTR2INT(op_vec_get(&v, 1)) == 2);
    op_vec_fini(&v, NULL, NULL);
}

static void
test_remove_ptr(void)
{
    SECTION("op_vec_remove_ptr");
    op_vec_t v;
    op_vec_init(&v, 0);

    void *a = INT2PTR(10);
    void *b = INT2PTR(20);
    void *c = INT2PTR(30);
    op_vec_push(&v, a);
    op_vec_push(&v, b);
    op_vec_push(&v, c);

    op_vec_remove_ptr(&v, b);
    CHECK(op_vec_size(&v) == 2);
    CHECK(op_vec_get(&v, 0) == a || op_vec_get(&v, 0) == c);
    CHECK(op_vec_get(&v, 1) == a || op_vec_get(&v, 1) == c);

    /* remove_ptr on element not present is a no-op */
    op_vec_remove_ptr(&v, INT2PTR(999));
    CHECK(op_vec_size(&v) == 2);

    /* remove all remaining */
    op_vec_remove_ptr(&v, a);
    op_vec_remove_ptr(&v, c);
    CHECK(op_vec_empty(&v));

    /* remove_ptr on empty vec is safe */
    op_vec_remove_ptr(&v, INT2PTR(1));
    CHECK(op_vec_empty(&v));

    op_vec_fini(&v, NULL, NULL);
}

static void
test_contains(void)
{
    SECTION("op_vec_contains");
    op_vec_t v;
    op_vec_init(&v, 0);

    void *a = INT2PTR(10);
    void *b = INT2PTR(20);
    void *c = INT2PTR(30);
    op_vec_push(&v, a);
    op_vec_push(&v, b);

    CHECK(op_vec_contains(&v, a) == true);
    CHECK(op_vec_contains(&v, b) == true);
    CHECK(op_vec_contains(&v, c) == false);
    CHECK(op_vec_contains(&v, NULL) == false);

    /* after removal, no longer contains */
    op_vec_remove_ptr(&v, a);
    CHECK(op_vec_contains(&v, a) == false);
    CHECK(op_vec_contains(&v, b) == true);

    /* empty vec contains nothing */
    op_vec_clear(&v, NULL, NULL);
    CHECK(op_vec_contains(&v, b) == false);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_move_ptr(void)
{
    SECTION("op_vec_move_ptr");
    op_vec_t src, dst;
    op_vec_init(&src, 0);
    op_vec_init(&dst, 0);

    void *a = INT2PTR(10);
    void *b = INT2PTR(20);
    void *c = INT2PTR(30);
    op_vec_push(&src, a);
    op_vec_push(&src, b);
    op_vec_push(&src, c);

    op_vec_move_ptr(&src, &dst, b);
    CHECK(op_vec_size(&src) == 2);
    CHECK(op_vec_size(&dst) == 1);
    CHECK(op_vec_contains(&src, b) == false);
    CHECK(op_vec_contains(&dst, b) == true);

    /* move remaining elements */
    op_vec_move_ptr(&src, &dst, a);
    op_vec_move_ptr(&src, &dst, c);
    CHECK(op_vec_empty(&src));
    CHECK(op_vec_size(&dst) == 3);
    CHECK(op_vec_contains(&dst, a) == true);
    CHECK(op_vec_contains(&dst, c) == true);

    /* move_ptr for element not in src still pushes to dst */
    size_t dst_before = op_vec_size(&dst);
    op_vec_move_ptr(&src, &dst, INT2PTR(999));
    CHECK(op_vec_size(&dst) == dst_before + 1);

    op_vec_fini(&src, NULL, NULL);
    op_vec_fini(&dst, NULL, NULL);
}

static void
test_backwards_iteration(void)
{
    SECTION("backwards iteration with remove_fast (migration pattern)");
    op_vec_t v;
    op_vec_init(&v, 0);

    for (int i = 0; i < 10; i++)
        op_vec_push(&v, INT2PTR(i));

    /* Remove all even numbers using the backwards iteration pattern */
    for (size_t i = op_vec_size(&v); i-- > 0; )
    {
        int val = PTR2INT(op_vec_get(&v, i));
        if (val % 2 == 0)
            op_vec_remove_fast(&v, i);
    }

    CHECK(op_vec_size(&v) == 5);
    /* All remaining should be odd */
    for (size_t i = 0; i < op_vec_size(&v); i++)
        CHECK(PTR2INT(op_vec_get(&v, i)) % 2 == 1);

    op_vec_fini(&v, NULL, NULL);
}

static void
test_nested_foreach(void)
{
    SECTION("nested OP_VEC_FOREACH (shadow-safe)");
    op_vec_t outer, inner;
    op_vec_init(&outer, 0);
    op_vec_init(&inner, 0);

    op_vec_push(&outer, INT2PTR(1));
    op_vec_push(&outer, INT2PTR(2));
    op_vec_push(&inner, INT2PTR(10));
    op_vec_push(&inner, INT2PTR(20));

    int total = 0;
    size_t _i; void *_e;
    OP_VEC_FOREACH(&outer, _i, _e)
    {
        size_t _j; void *_je;
        OP_VEC_FOREACH(&inner, _j, _je)
        {
            total += PTR2INT(_e) * PTR2INT(_je);
        }
    }
    /* (1*10 + 1*20) + (2*10 + 2*20) = 30 + 60 = 90 */
    CHECK(total == 90);

    op_vec_fini(&outer, NULL, NULL);
    op_vec_fini(&inner, NULL, NULL);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("test_vec\n");
    test_init_empty();
    test_push_pop();
    test_insert_remove();
    test_remove_fast();
    test_set();
    test_growth();
    test_clear();
    test_fini_with_cb();
    test_reserve_shrink();
    test_find();
    test_bsearch_sort();
    test_foreach();
    test_macro_foreach();
    test_heap_create_destroy();
    test_insert_at_end();
    test_remove_ptr();
    test_contains();
    test_move_ptr();
    test_backwards_iteration();
    test_nested_foreach();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
