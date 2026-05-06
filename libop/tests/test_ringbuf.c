/*
 * test_ringbuf.c — unit tests for op_ringbuf_t (SPSC lock-free ring buffer).
 *
 * op_ringbuf is header-only; no link dependency beyond op_lib needed for
 * its inlined functions, but we link libop for op_malloc/op_free.
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

#define PTR(n) ((void *)(uintptr_t)(n))
#define VAL(p) ((size_t)(uintptr_t)(p))

/* ======================================================================== */

int
main(void)
{
    printf("test_ringbuf\n");

    /* [1] create / destroy */
    SECTION("create-destroy");
    {
        op_ringbuf_t *rb = op_ringbuf_create(8);
        CHECK(rb != NULL);
        CHECK(op_ringbuf_cap(rb) == 8);
        CHECK(op_ringbuf_empty(rb));
        CHECK(!op_ringbuf_full(rb));
        CHECK(op_ringbuf_count(rb) == 0);
        op_ringbuf_destroy(rb);
    }

    /* [2] capacity rounds up to power of two */
    SECTION("capacity-pow2");
    {
        op_ringbuf_t *rb3  = op_ringbuf_create(3);
        op_ringbuf_t *rb5  = op_ringbuf_create(5);
        op_ringbuf_t *rb9  = op_ringbuf_create(9);
        CHECK(op_ringbuf_cap(rb3) == 4);
        CHECK(op_ringbuf_cap(rb5) == 8);
        CHECK(op_ringbuf_cap(rb9) == 16);
        op_ringbuf_destroy(rb3);
        op_ringbuf_destroy(rb5);
        op_ringbuf_destroy(rb9);
    }

    /* [3] minimum capacity = 2 */
    SECTION("min-capacity");
    {
        op_ringbuf_t *rb = op_ringbuf_create(0);
        CHECK(op_ringbuf_cap(rb) == 2);
        op_ringbuf_destroy(rb);
        rb = op_ringbuf_create(1);
        CHECK(op_ringbuf_cap(rb) == 2);
        op_ringbuf_destroy(rb);
    }

    /* [4] basic push / pop FIFO */
    SECTION("push-pop-fifo");
    {
        op_ringbuf_t *rb = op_ringbuf_create(8);
        void *out;
        for (size_t i = 1; i <= 7; i++)
            CHECK(op_ringbuf_push(rb, PTR(i)));
        CHECK(op_ringbuf_count(rb) == 7);
        for (size_t i = 1; i <= 7; i++)
        {
            CHECK(op_ringbuf_pop(rb, &out));
            CHECK(VAL(out) == i);
        }
        CHECK(op_ringbuf_empty(rb));
        op_ringbuf_destroy(rb);
    }

    /* [5] push returns false when full */
    SECTION("full");
    {
        op_ringbuf_t *rb = op_ringbuf_create(4);  /* cap=4, max items=3 */
        CHECK(op_ringbuf_push(rb, PTR(1)));
        CHECK(op_ringbuf_push(rb, PTR(2)));
        CHECK(op_ringbuf_push(rb, PTR(3)));
        CHECK(op_ringbuf_full(rb));
        CHECK(!op_ringbuf_push(rb, PTR(4)));       /* full — rejected */
        CHECK(op_ringbuf_count(rb) == 3);
        op_ringbuf_destroy(rb);
    }

    /* [6] pop returns false when empty */
    SECTION("empty");
    {
        op_ringbuf_t *rb = op_ringbuf_create(4);
        void *out = PTR(0xDEAD);
        CHECK(!op_ringbuf_pop(rb, &out));
        CHECK(VAL(out) == 0xDEAD);  /* unchanged */
        op_ringbuf_destroy(rb);
    }

    /* [7] wrap-around — push/pop cycles that cross the end of the buffer */
    SECTION("wrap-around");
    {
        op_ringbuf_t *rb = op_ringbuf_create(4);  /* cap=4, 3 usable */
        void *out;
        /* Fill to 3, drain to 0, fill again — exercises wrap */
        for (int round = 0; round < 3; round++)
        {
            CHECK(op_ringbuf_push(rb, PTR(round * 10 + 1)));
            CHECK(op_ringbuf_push(rb, PTR(round * 10 + 2)));
            CHECK(op_ringbuf_push(rb, PTR(round * 10 + 3)));
            CHECK(op_ringbuf_full(rb));
            CHECK(op_ringbuf_pop(rb, &out));
            CHECK(VAL(out) == (size_t)(round * 10 + 1));
            CHECK(op_ringbuf_pop(rb, &out));
            CHECK(VAL(out) == (size_t)(round * 10 + 2));
            CHECK(op_ringbuf_pop(rb, &out));
            CHECK(VAL(out) == (size_t)(round * 10 + 3));
            CHECK(op_ringbuf_empty(rb));
        }
        op_ringbuf_destroy(rb);
    }

    /* [8] count tracks live elements correctly */
    SECTION("count");
    {
        op_ringbuf_t *rb = op_ringbuf_create(8);
        void *out;
        for (size_t i = 0; i < 5; i++)
            op_ringbuf_push(rb, PTR(i));
        CHECK(op_ringbuf_count(rb) == 5);
        op_ringbuf_pop(rb, &out);
        op_ringbuf_pop(rb, &out);
        CHECK(op_ringbuf_count(rb) == 3);
        op_ringbuf_destroy(rb);
    }

    /* [9] NULL item is accepted */
    SECTION("null-item");
    {
        op_ringbuf_t *rb = op_ringbuf_create(4);
        void *out = PTR(0xFF);
        CHECK(op_ringbuf_push(rb, NULL));
        CHECK(op_ringbuf_pop(rb, &out));
        CHECK(out == NULL);
        op_ringbuf_destroy(rb);
    }

    /* [10] large buffer — 1 Mi-1 elements at cap 1 Mi */
    SECTION("large");
    {
        const size_t N = (1 << 20);
        op_ringbuf_t *rb = op_ringbuf_create(N);
        CHECK(op_ringbuf_cap(rb) == N);
        /* Fill N-1 (max usable) */
        for (size_t i = 0; i < N - 1; i++)
            CHECK(op_ringbuf_push(rb, PTR(i & 0xFFFF)));
        CHECK(op_ringbuf_full(rb));
        /* Drain and verify */
        void *out;
        for (size_t i = 0; i < N - 1; i++)
        {
            CHECK(op_ringbuf_pop(rb, &out));
            CHECK(VAL(out) == (i & 0xFFFF));
        }
        CHECK(op_ringbuf_empty(rb));
        op_ringbuf_destroy(rb);
    }

    /* [11] single-threaded producer/consumer simulation */
    SECTION("simulated-spsc");
    {
        const size_t N   = 10000;
        op_ringbuf_t *rb = op_ringbuf_create(64);
        void *out;
        size_t pushed = 0, popped = 0;

        while (popped < N)
        {
            /* Producer: push up to 16 items */
            for (int batch = 0; batch < 16 && pushed < N; batch++)
            {
                if (!op_ringbuf_push(rb, PTR(pushed + 1)))
                    break;
                pushed++;
            }
            /* Consumer: pop up to 16 items */
            for (int batch = 0; batch < 16 && popped < pushed; batch++)
            {
                if (!op_ringbuf_pop(rb, &out))
                    break;
                popped++;
                CHECK(VAL(out) == popped);
            }
        }
        CHECK(op_ringbuf_empty(rb));
        op_ringbuf_destroy(rb);
    }

    printf("ALL PASS\n");
    return 0;
}
