/*
 * libop/tests/test_pqueue.c — unit tests for op_pqueue.h / pqueue.c
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_pqueue.h>
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

/* ---- comparison functions ------------------------------------------------ */

/* Compare integers stored as pointers (intptr_t). */
static int
cmp_int(const void *a, const void *b)
{
    intptr_t ia = (intptr_t)a;
    intptr_t ib = (intptr_t)b;
    return (ia > ib) - (ia < ib);
}

/* Reverse comparison — max-heap when used with min-heap. */
static int
cmp_int_rev(const void *a, const void *b)
{
    return cmp_int(b, a);
}

/* ---- helpers ------------------------------------------------------------- */

/* Pack integer n as a void pointer (avoids malloc per element). */
#define INT2PTR(n)  ((void *)(intptr_t)(n))
#define PTR2INT(p)  ((int)(intptr_t)(p))

/* ---- tests --------------------------------------------------------------- */

static void
test_basic(void)
{
    SECTION("basic push/pop ordering");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    CHECK(op_pqueue_empty(pq));
    CHECK(op_pqueue_size(pq) == 0);
    CHECK(op_pqueue_peek(pq) == NULL);
    CHECK(op_pqueue_pop(pq) == NULL);

    op_pqueue_push(pq, INT2PTR(5));
    op_pqueue_push(pq, INT2PTR(3));
    op_pqueue_push(pq, INT2PTR(8));
    op_pqueue_push(pq, INT2PTR(1));
    op_pqueue_push(pq, INT2PTR(7));

    CHECK(op_pqueue_size(pq) == 5);
    CHECK(!op_pqueue_empty(pq));
    CHECK(PTR2INT(op_pqueue_peek(pq)) == 1);

    CHECK(PTR2INT(op_pqueue_pop(pq)) == 1);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 3);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 5);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 7);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 8);
    CHECK(op_pqueue_empty(pq));

    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_reverse_cmp(void)
{
    SECTION("max-heap via reverse comparison");
    op_pqueue_t *pq = op_pqueue_create(cmp_int_rev, 0);

    op_pqueue_push(pq, INT2PTR(4));
    op_pqueue_push(pq, INT2PTR(2));
    op_pqueue_push(pq, INT2PTR(9));
    op_pqueue_push(pq, INT2PTR(6));

    CHECK(PTR2INT(op_pqueue_peek(pq)) == 9);
    CHECK(PTR2INT(op_pqueue_pop(pq))  == 9);
    CHECK(PTR2INT(op_pqueue_pop(pq))  == 6);
    CHECK(PTR2INT(op_pqueue_pop(pq))  == 4);
    CHECK(PTR2INT(op_pqueue_pop(pq))  == 2);
    CHECK(op_pqueue_empty(pq));

    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_single_element(void)
{
    SECTION("single-element push/pop");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(42));
    CHECK(op_pqueue_size(pq) == 1);
    CHECK(PTR2INT(op_pqueue_peek(pq)) == 42);
    CHECK(PTR2INT(op_pqueue_pop(pq))  == 42);
    CHECK(op_pqueue_empty(pq));
    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_duplicates(void)
{
    SECTION("duplicate values");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(5));
    op_pqueue_push(pq, INT2PTR(5));
    op_pqueue_push(pq, INT2PTR(5));
    CHECK(op_pqueue_size(pq) == 3);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 5);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 5);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 5);
    CHECK(op_pqueue_empty(pq));
    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_remove(void)
{
    SECTION("op_pqueue_remove — remove by pointer");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(10));
    op_pqueue_push(pq, INT2PTR(20));
    op_pqueue_push(pq, INT2PTR(30));

    bool removed = op_pqueue_remove(pq, INT2PTR(20));
    CHECK(removed);
    CHECK(op_pqueue_size(pq) == 2);

    /* 10 and 30 remain; order correct */
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 10);
    CHECK(PTR2INT(op_pqueue_pop(pq)) == 30);

    /* Remove non-existent element */
    CHECK(!op_pqueue_remove(pq, INT2PTR(99)));

    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_remove_root(void)
{
    SECTION("op_pqueue_remove — remove minimum (root)");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(1));
    op_pqueue_push(pq, INT2PTR(2));
    op_pqueue_push(pq, INT2PTR(3));

    op_pqueue_remove(pq, INT2PTR(1));
    CHECK(PTR2INT(op_pqueue_peek(pq)) == 2);
    CHECK(op_pqueue_size(pq) == 2);

    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_large(void)
{
    SECTION("large queue — sorted output");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 4);

    /* Insert 1000 values in reverse order */
    for (int i = 1000; i >= 1; i--)
        op_pqueue_push(pq, INT2PTR(i));

    CHECK(op_pqueue_size(pq) == 1000);
    CHECK(PTR2INT(op_pqueue_peek(pq)) == 1);

    int prev = 0;
    bool sorted = true;
    while (!op_pqueue_empty(pq))
    {
        int v = PTR2INT(op_pqueue_pop(pq));
        if (v < prev)
            sorted = false;
        prev = v;
    }
    CHECK(sorted);
    CHECK(op_pqueue_empty(pq));

    op_pqueue_destroy(pq, NULL, NULL);
}

static int
foreach_cb(void *e, void *ud)
{
    int *sum = ud;
    *sum += PTR2INT(e);
    return 0;
}

static void
free_sum_cb(void *e, void *ud)
{
    int *sum = ud;
    *sum += PTR2INT(e);
}

static void
test_foreach_c(void)
{
    SECTION("op_pqueue_foreach — C callback version");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(10));
    op_pqueue_push(pq, INT2PTR(20));
    op_pqueue_push(pq, INT2PTR(30));

    int sum = 0;
    op_pqueue_foreach(pq, foreach_cb, &sum);
    CHECK(sum == 60);

    op_pqueue_destroy(pq, NULL, NULL);
}

static void
test_destroy_with_callback(void)
{
    SECTION("op_pqueue_destroy calls free_cb for each element");
    op_pqueue_t *pq = op_pqueue_create(cmp_int, 0);
    op_pqueue_push(pq, INT2PTR(1));
    op_pqueue_push(pq, INT2PTR(2));
    op_pqueue_push(pq, INT2PTR(3));

    int freed_sum = 0;
    op_pqueue_destroy(pq, free_sum_cb, &freed_sum);
    CHECK(freed_sum == 6);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("test_pqueue\n");
    test_basic();
    test_reverse_cmp();
    test_single_element();
    test_duplicates();
    test_remove();
    test_remove_root();
    test_large();
    test_foreach_c();
    test_destroy_with_callback();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
