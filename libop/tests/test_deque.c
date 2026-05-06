/*
 * test_deque.c — unit tests for op_deque_t.
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

/* ---- foreach callback ---------------------------------------------------- */

typedef struct { size_t *arr; size_t idx; } each_state_t;

static bool
collect_cb(void *item, void *ud)
{
    each_state_t *s = ud;
    s->arr[s->idx++] = (size_t)(uintptr_t)item;
    return true;
}

static bool
stop_at_3_cb(void *item, void *ud)
{
    each_state_t *s = ud;
    s->arr[s->idx++] = (size_t)(uintptr_t)item;
    return (s->idx < 3);
}

/* ---- helpers ------------------------------------------------------------- */

#define PTR(n) ((void *)(uintptr_t)(n))
#define VAL(p) ((size_t)(uintptr_t)(p))

/* ======================================================================== */

int
main(void)
{
    printf("test_deque\n");

    /* [1] create / destroy */
    SECTION("create-destroy");
    {
        op_deque_t *d = op_deque_create(0);
        CHECK(d != NULL);
        CHECK(op_deque_empty(d));
        CHECK(op_deque_size(d) == 0);
        CHECK(op_deque_cap(d) >= 8);
        op_deque_destroy(d);
    }

    /* [2] push_back / pop_front — FIFO order */
    SECTION("push-back pop-front");
    {
        op_deque_t *d = op_deque_create(4);
        for (size_t i = 1; i <= 5; i++)
            op_deque_push_back(d, PTR(i));
        CHECK(op_deque_size(d) == 5);
        for (size_t i = 1; i <= 5; i++)
            CHECK(VAL(op_deque_pop_front(d)) == i);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [3] push_front / pop_back — FIFO order (stack-push = reversed) */
    SECTION("push-front pop-back");
    {
        op_deque_t *d = op_deque_create(4);
        for (size_t i = 1; i <= 5; i++)
            op_deque_push_front(d, PTR(i));
        /* front is 5, back is 1 */
        CHECK(VAL(op_deque_front(d)) == 5);
        CHECK(VAL(op_deque_back(d))  == 1);
        for (size_t i = 1; i <= 5; i++)
            CHECK(VAL(op_deque_pop_back(d)) == i);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [4] push_front / pop_front — stack order */
    SECTION("push-front pop-front (stack)");
    {
        op_deque_t *d = op_deque_create(4);
        for (size_t i = 1; i <= 4; i++)
            op_deque_push_front(d, PTR(i));
        for (size_t i = 4; i >= 1; i--)
            CHECK(VAL(op_deque_pop_front(d)) == i);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [5] pop on empty returns NULL */
    SECTION("pop-empty");
    {
        op_deque_t *d = op_deque_create(0);
        CHECK(op_deque_pop_front(d) == NULL);
        CHECK(op_deque_pop_back(d)  == NULL);
        CHECK(op_deque_front(d)     == NULL);
        CHECK(op_deque_back(d)      == NULL);
        op_deque_destroy(d);
    }

    /* [6] random access — op_deque_at */
    SECTION("at");
    {
        op_deque_t *d = op_deque_create(0);
        for (size_t i = 0; i < 8; i++)
            op_deque_push_back(d, PTR(i * 10));
        for (size_t i = 0; i < 8; i++)
            CHECK(VAL(op_deque_at(d, i)) == i * 10);
        CHECK(op_deque_at(d, 8) == NULL);  /* out of bounds */
        op_deque_destroy(d);
    }

    /* [7] op_deque_set modifies in place */
    SECTION("set");
    {
        op_deque_t *d = op_deque_create(4);
        for (size_t i = 0; i < 4; i++)
            op_deque_push_back(d, PTR(i));
        op_deque_set(d, 2, PTR(99));
        CHECK(VAL(op_deque_at(d, 2)) == 99);
        op_deque_set(d, 100, PTR(0));  /* silent no-op */
        op_deque_destroy(d);
    }

    /* [8] growth across boundary — head wraps, then grows */
    SECTION("wrap-and-grow");
    {
        op_deque_t *d = op_deque_create(4);  /* cap=8 after rounding */
        /* Push 4, pop 2 (head advances), push many to force growth */
        for (size_t i = 0; i < 4; i++)
            op_deque_push_back(d, PTR(i));
        op_deque_pop_front(d);
        op_deque_pop_front(d);  /* head=2 */
        /* push 14 more to force multiple doublings */
        for (size_t i = 4; i < 18; i++)
            op_deque_push_back(d, PTR(i));
        /* verify all remaining: 2,3,4..17 */
        CHECK(op_deque_size(d) == 16);
        for (size_t i = 2; i < 18; i++)
            CHECK(VAL(op_deque_pop_front(d)) == i);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [9] interleaved push-front and push-back */
    SECTION("interleaved");
    {
        op_deque_t *d = op_deque_create(0);
        /* Build: front→ [5, 3, 1, 2, 4] ←back */
        op_deque_push_back(d,  PTR(1));
        op_deque_push_back(d,  PTR(2));
        op_deque_push_front(d, PTR(3));
        op_deque_push_back(d,  PTR(4));
        op_deque_push_front(d, PTR(5));
        CHECK(op_deque_size(d) == 5);
        CHECK(VAL(op_deque_pop_front(d)) == 5);
        CHECK(VAL(op_deque_pop_front(d)) == 3);
        CHECK(VAL(op_deque_pop_back(d))  == 4);
        CHECK(VAL(op_deque_pop_back(d))  == 2);
        CHECK(VAL(op_deque_pop_front(d)) == 1);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [10] clear */
    SECTION("clear");
    {
        op_deque_t *d = op_deque_create(0);
        for (size_t i = 0; i < 10; i++)
            op_deque_push_back(d, PTR(i));
        op_deque_clear(d);
        CHECK(op_deque_empty(d));
        CHECK(op_deque_size(d) == 0);
        /* reuse after clear */
        op_deque_push_back(d, PTR(42));
        CHECK(VAL(op_deque_pop_front(d)) == 42);
        op_deque_destroy(d);
    }

    /* [11] reserve pre-allocates without data loss */
    SECTION("reserve");
    {
        op_deque_t *d = op_deque_create(2);
        op_deque_push_back(d, PTR(7));
        op_deque_push_back(d, PTR(8));
        op_deque_reserve(d, 1024);
        CHECK(op_deque_cap(d) >= 1024);
        CHECK(op_deque_size(d) == 2);
        CHECK(VAL(op_deque_at(d, 0)) == 7);
        CHECK(VAL(op_deque_at(d, 1)) == 8);
        op_deque_destroy(d);
    }

    /* [12] foreach — full traversal */
    SECTION("foreach");
    {
        op_deque_t *d = op_deque_create(0);
        for (size_t i = 0; i < 6; i++)
            op_deque_push_back(d, PTR(i * 2));

        size_t arr[6];
        each_state_t s = { .arr = arr, .idx = 0 };
        op_deque_foreach(d, collect_cb, &s);
        for (size_t i = 0; i < 6; i++)
            CHECK(arr[i] == i * 2);
        op_deque_destroy(d);
    }

    /* [13] foreach — early stop */
    SECTION("foreach-early-stop");
    {
        op_deque_t *d = op_deque_create(0);
        for (size_t i = 1; i <= 10; i++)
            op_deque_push_back(d, PTR(i));

        size_t arr[10] = {0};
        each_state_t s = { .arr = arr, .idx = 0 };
        op_deque_foreach(d, stop_at_3_cb, &s);
        CHECK(s.idx == 3);
        CHECK(arr[0] == 1 && arr[1] == 2 && arr[2] == 3);
        op_deque_destroy(d);
    }

    /* [14] stack-allocated (init/fini) */
    SECTION("init-fini");
    {
        op_deque_t d;
        op_deque_init(&d, 0);
        for (size_t i = 0; i < 5; i++)
            op_deque_push_back(&d, PTR(i));
        CHECK(op_deque_size(&d) == 5);
        op_deque_fini(&d);
        CHECK(d.slots == NULL);
    }

    /* [15] large stress — 100,000 push/pop round-trip */
    SECTION("stress");
    {
        op_deque_t *d = op_deque_create(0);
        const size_t N = 100000;
        for (size_t i = 0; i < N; i++)
            op_deque_push_back(d, PTR(i));
        for (size_t i = 0; i < N; i++)
            CHECK(VAL(op_deque_pop_front(d)) == i);
        CHECK(op_deque_empty(d));
        op_deque_destroy(d);
    }

    /* [16] alternating push_front and pop_back preserves order */
    SECTION("front-push back-pop");
    {
        op_deque_t *d = op_deque_create(0);
        /* Push 1..5 to front: gives 5,4,3,2,1 */
        for (size_t i = 1; i <= 5; i++)
            op_deque_push_front(d, PTR(i));
        /* Pop from back: 1,2,3,4,5 */
        for (size_t i = 1; i <= 5; i++)
            CHECK(VAL(op_deque_pop_back(d)) == i);
        op_deque_destroy(d);
    }

    printf("ALL PASS\n");
    return 0;
}
