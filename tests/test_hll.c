/*
 * test_hll.c — unit tests for op_hll_t (HyperLogLog cardinality estimator).
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

/* Check that estimate is within pct% of expected. */
#define CHECK_ESTIMATE(est, expected, pct) \
    do { \
        double _e = (est); \
        double _x = (expected); \
        double _err = fabs(_e - _x) / _x * 100.0; \
        if (_err > (pct)) { \
            fprintf(stderr, "[FAIL] %s:%d: estimate %.0f expected %.0f err %.1f%% > %.0f%%\n", \
                    __FILE__, __LINE__, _e, _x, _err, (double)(pct)); \
            exit(1); \
        } \
    } while (0)

/* ======================================================================== */

int
main(void)
{
    printf("test_hll\n");

    /* [1] create / destroy */
    SECTION("create-destroy");
    {
        op_hll_t *h = op_hll_create(12);
        CHECK(h != NULL);
        CHECK(op_hll_precision(h) == 12);
        CHECK(op_hll_register_count(h) == 4096);
        CHECK(op_hll_count(h) == 0);
        op_hll_destroy(h);
    }

    /* [2] precision clamping */
    SECTION("precision-clamp");
    {
        op_hll_t *lo = op_hll_create(1);   /* clamped to 4 */
        op_hll_t *hi = op_hll_create(99);  /* clamped to 16 */
        CHECK(op_hll_precision(lo) == 4);
        CHECK(op_hll_precision(hi) == 16);
        op_hll_destroy(lo);
        op_hll_destroy(hi);
    }

    /* [3] single add → count ≥ 1 */
    SECTION("single-add");
    {
        op_hll_t *h = op_hll_create(12);
        op_hll_add(h, "hello", 5);
        CHECK(op_hll_count(h) >= 1);
        op_hll_destroy(h);
    }

    /* [4] add same element many times → count stays near 1 */
    SECTION("duplicate");
    {
        op_hll_t *h = op_hll_create(12);
        for (int i = 0; i < 1000; i++)
            op_hll_add(h, "duplicate", 9);
        uint64_t cnt = op_hll_count(h);
        CHECK(cnt >= 1 && cnt <= 5);   /* generous bound for hash collisions */
        op_hll_destroy(h);
    }

    /* [5] small cardinality (100 distinct strings) */
    SECTION("small-cardinality");
    {
        op_hll_t *h = op_hll_create(12);
        char buf[32];
        for (int i = 0; i < 100; i++) {
            snprintf(buf, sizeof(buf), "element_%d", i);
            op_hll_add(h, buf, strlen(buf));
        }
        /* Within 20% of 100. */
        CHECK_ESTIMATE(op_hll_count(h), 100.0, 20.0);
        op_hll_destroy(h);
    }

    /* [6] medium cardinality (10 000 distinct strings, b=12 ~1.6% err) */
    SECTION("medium-cardinality");
    {
        op_hll_t *h = op_hll_create(12);
        char buf[32];
        for (int i = 0; i < 10000; i++) {
            snprintf(buf, sizeof(buf), "user_%05d", i);
            op_hll_add(h, buf, strlen(buf));
        }
        /* Within 5% of 10000. */
        CHECK_ESTIMATE(op_hll_count(h), 10000.0, 5.0);
        op_hll_destroy(h);
    }

    /* [7] add_hash interface — exercise the raw-hash path.
     * Use strings hashed via op_hll_add as reference, then replicate by
     * calling op_hll_add_hash with the same values fed in as bytes. */
    SECTION("add-hash");
    {
        op_hll_t *h = op_hll_create(12);
        char buf[32];
        /* Add 1000 distinct strings via the add_hash path (bytes of string).
         * Using the same byte-loop the internal hll_hash uses lets us test
         * add_hash without relying on structured mathematical sequences. */
        for (int i = 0; i < 1000; i++) {
            snprintf(buf, sizeof(buf), "hash_item_%d", i);
            /* Mix via a simple XOR-shift to get a well-distributed uint64.
             * We're testing that add_hash accepts arbitrary hashes, not that
             * the hash function is perfect — use a wide tolerance here. */
            uint64_t h64 = 0;
            for (int j = 0; buf[j]; j++) {
                h64 ^= (uint64_t)(unsigned char)buf[j] << ((j & 7) * 8);
                h64 *= UINT64_C(0x9e3779b97f4a7c15);
                h64 ^= h64 >> 32;
            }
            op_hll_add_hash(h, h64);
        }
        /* ~20% tolerance: add_hash receives pre-hashed values; quality depends
         * on the caller's hash — we verify the register logic works at all. */
        CHECK_ESTIMATE(op_hll_count(h), 1000.0, 20.0);
        op_hll_destroy(h);
    }

    /* [8] reset → count back to 0 */
    SECTION("reset");
    {
        op_hll_t *h = op_hll_create(12);
        for (int i = 0; i < 500; i++) {
            char buf[16];
            snprintf(buf, sizeof(buf), "e%d", i);
            op_hll_add(h, buf, strlen(buf));
        }
        CHECK(op_hll_count(h) > 0);
        op_hll_reset(h);
        CHECK(op_hll_count(h) == 0);
        op_hll_destroy(h);
    }

    /* [9] merge — union of two disjoint sets */
    SECTION("merge");
    {
        op_hll_t *a = op_hll_create(12);
        op_hll_t *b = op_hll_create(12);
        char buf[32];

        for (int i = 0;    i < 5000; i++) {
            snprintf(buf, sizeof(buf), "set_a_%d", i);
            op_hll_add(a, buf, strlen(buf));
        }
        for (int i = 5000; i < 10000; i++) {
            snprintf(buf, sizeof(buf), "set_b_%d", i);
            op_hll_add(b, buf, strlen(buf));
        }

        op_hll_merge(a, b);  /* a now estimates |A ∪ B| */
        CHECK_ESTIMATE(op_hll_count(a), 10000.0, 5.0);

        op_hll_destroy(a);
        op_hll_destroy(b);
    }

    /* [10] merge ignored if precisions differ */
    SECTION("merge-precision-mismatch");
    {
        op_hll_t *a = op_hll_create(10);
        op_hll_t *b = op_hll_create(12);
        op_hll_add(b, "test", 4);
        op_hll_merge(a, b);
        /* a should still be 0 — merge was rejected */
        CHECK(op_hll_count(a) == 0);
        op_hll_destroy(a);
        op_hll_destroy(b);
    }

    /* [11] large cardinality (100k distinct, b=14 ~0.8% err) */
    SECTION("large-cardinality");
    {
        op_hll_t *h = op_hll_create(14);
        char buf[32];
        for (int i = 0; i < 100000; i++) {
            snprintf(buf, sizeof(buf), "ip_%d", i);
            op_hll_add(h, buf, strlen(buf));
        }
        CHECK_ESTIMATE(op_hll_count(h), 100000.0, 3.0);
        op_hll_destroy(h);
    }

    printf("ALL PASS\n");
    return 0;
}
