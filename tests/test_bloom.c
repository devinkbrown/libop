/*
 * test_bloom.c — unit tests for op_bloom counting Bloom filter.
 *
 * Coverage:
 *   - add / test / remove lifecycle
 *   - false-positive rate stays within declared bound
 *   - deletion without underflow on absent elements
 *   - op_bloom_reset clears the filter
 *   - op_bloom_params reports sensible m and k
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)  do { int _before = failures; const char *_sec = (name);
#define END_SECTION    printf("  %-48s %s\n", _sec, failures == _before ? "pass" : "FAIL"); } while (0)

/* ---- helpers ------------------------------------------------------------- */

/* Generate a simple key string from an integer. */
static void
make_key(int i, char *buf, size_t len)
{
    snprintf(buf, len, "nick!user@host-%d.example.com", i);
}

/* ---- tests --------------------------------------------------------------- */

static void
test_basic(void)
{
    SECTION("basic: add + test + remove");
    op_bloom_t *b = op_bloom_new(1000, 0.01);
    CHECK(b != NULL);

    const char *key = "nick!user@host.example.com";
    size_t klen = strlen(key);

    CHECK(!op_bloom_test(b, key, klen));   /* not yet added */
    op_bloom_add(b, key, klen);
    CHECK(op_bloom_test(b, key, klen));    /* now present */
    op_bloom_remove(b, key, klen);
    CHECK(!op_bloom_test(b, key, klen));   /* removed */

    op_bloom_free(b);
    END_SECTION;
}

static void
test_false_positive_rate(void)
{
    SECTION("false-positive rate within declared bound");
    const int N = 1000;
    const double fp_rate = 0.01;
    op_bloom_t *b = op_bloom_new((size_t)N, fp_rate);
    CHECK(b != NULL);

    char key[64];

    /* Insert N distinct keys. */
    for (int i = 0; i < N; i++) {
        make_key(i, key, sizeof(key));
        op_bloom_add(b, key, strlen(key));
    }

    /* Query N distinct keys that were NOT inserted; count false positives. */
    int fp = 0;
    for (int i = N; i < 2 * N; i++) {
        make_key(i, key, sizeof(key));
        if (op_bloom_test(b, key, strlen(key)))
            fp++;
    }

    /* Allow 3× the declared FP rate as slack for small filter sizes. */
    double observed = (double)fp / N;
    CHECK(observed <= fp_rate * 3.0);

    op_bloom_free(b);
    END_SECTION;
}

static void
test_no_false_negatives(void)
{
    SECTION("no false negatives after add");
    op_bloom_t *b = op_bloom_new(500, 0.01);
    CHECK(b != NULL);

    char key[64];
    const int N = 500;

    for (int i = 0; i < N; i++) {
        make_key(i, key, sizeof(key));
        op_bloom_add(b, key, strlen(key));
    }

    /* Every inserted key must test positive. */
    for (int i = 0; i < N; i++) {
        make_key(i, key, sizeof(key));
        CHECK(op_bloom_test(b, key, strlen(key)));
    }

    op_bloom_free(b);
    END_SECTION;
}

static void
test_remove_absent(void)
{
    SECTION("remove: no-op on absent key (no underflow)");
    op_bloom_t *b = op_bloom_new(100, 0.01);
    CHECK(b != NULL);

    const char *present = "present";
    const char *absent  = "absent";
    op_bloom_add(b, present, strlen(present));

    /* Remove an absent key — must not corrupt the filter. */
    op_bloom_remove(b, absent, strlen(absent));

    /* The present key should still test positive. */
    CHECK(op_bloom_test(b, present, strlen(present)));

    op_bloom_free(b);
    END_SECTION;
}

static void
test_reset(void)
{
    SECTION("reset: clears all entries");
    op_bloom_t *b = op_bloom_new(100, 0.01);
    CHECK(b != NULL);

    const char *key = "testkey";
    op_bloom_add(b, key, strlen(key));
    CHECK(op_bloom_test(b, key, strlen(key)));

    op_bloom_reset(b);
    CHECK(!op_bloom_test(b, key, strlen(key)));

    op_bloom_free(b);
    END_SECTION;
}

static void
test_params(void)
{
    SECTION("params: sensible m and k values");
    op_bloom_t *b = op_bloom_new(1000, 0.01);
    CHECK(b != NULL);

    size_t m;
    unsigned k;
    op_bloom_params(b, &m, &k);

    /* For 1000 items at 1% FP: optimal m ≈ 9585 bits, k ≈ 7. */
    CHECK(m > 1000);   /* filter must be larger than capacity */
    CHECK(k >= 3 && k <= 20);  /* sane hash count */

    op_bloom_free(b);
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("op_bloom tests\n");

    test_basic();
    test_false_positive_rate();
    test_no_false_negatives();
    test_remove_absent();
    test_reset();
    test_params();

    printf("\n%s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
