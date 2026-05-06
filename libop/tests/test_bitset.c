/*
 * libop/tests/test_bitset.c — unit tests for op_bitset.h
 */

#include <libop_config.h>
#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ---- test harness -------------------------------------------------------- */

static int g_pass, g_fail;

#define SECTION(name)   do { printf("  %s\n", name); } while (0)
#define CHECK(expr)                                              \
    do {                                                         \
        if (expr) { g_pass++; }                                 \
        else {                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n",                 \
                    __FILE__, __LINE__, #expr);                  \
            g_fail++;                                            \
        }                                                        \
    } while (0)

/* ---- bitset types used in tests ----------------------------------------- */

/* Small: 64 bits (1 word) */
OP_BITSET_DEFINE(bs64, 64);

/* Medium: 128 bits (2 words) */
OP_BITSET_DEFINE(bs128, 128);

/* Large: 256 bits (4 words) — like a channel mode bitmask */
OP_BITSET_DEFINE(bs256, 256);

/* ---- tests --------------------------------------------------------------- */

static void
test_basic_ops(void)
{
    SECTION("basic set/clear/test on 64-bit bitset");
    bs64 s;
    op_bs_zero(&s);
    CHECK(op_bs_none(&s));
    CHECK(!op_bs_test(&s, 0));
    CHECK(!op_bs_test(&s, 63));

    op_bs_set(&s, 0);
    CHECK(op_bs_test(&s, 0));
    CHECK(op_bs_any(&s));

    op_bs_set(&s, 63);
    CHECK(op_bs_test(&s, 63));
    CHECK(op_bs_count(&s) == 2);

    op_bs_clear(&s, 0);
    CHECK(!op_bs_test(&s, 0));
    CHECK(op_bs_test(&s, 63));
    CHECK(op_bs_count(&s) == 1);

    op_bs_clear(&s, 63);
    CHECK(op_bs_none(&s));
}

static void
test_fill_and_not(void)
{
    SECTION("fill and not on 64-bit bitset");
    bs64 s;
    op_bs_fill(&s);
    CHECK(op_bs_test(&s, 0));
    CHECK(op_bs_test(&s, 31));
    CHECK(op_bs_test(&s, 63));
    CHECK(op_bs_count(&s) == 64);

    op_bs_not(&s);
    CHECK(op_bs_none(&s));
    CHECK(op_bs_count(&s) == 0);
}

static void
test_flip(void)
{
    SECTION("flip (toggle) bit");
    bs64 s;
    op_bs_zero(&s);
    op_bs_flip(&s, 7);
    CHECK(op_bs_test(&s, 7));
    op_bs_flip(&s, 7);
    CHECK(!op_bs_test(&s, 7));
}

static void
test_multi_word(void)
{
    SECTION("multi-word bitset (128 bits)");
    bs128 s;
    op_bs_zero(&s);
    op_bs_set(&s, 64);   /* first bit of second word */
    op_bs_set(&s, 127);  /* last bit */
    CHECK(op_bs_test(&s, 64));
    CHECK(op_bs_test(&s, 127));
    CHECK(!op_bs_test(&s, 63));
    CHECK(!op_bs_test(&s, 0));
    CHECK(op_bs_count(&s) == 2);
}

static void
test_aggregate_ops(void)
{
    SECTION("bitwise OR / AND / XOR / andnot");
    bs64 a, b;
    op_bs_zero(&a);
    op_bs_zero(&b);
    op_bs_set(&a, 1);
    op_bs_set(&a, 3);
    op_bs_set(&b, 3);
    op_bs_set(&b, 5);

    bs64 c = a;
    op_bs_or(&c, &b);
    CHECK(op_bs_test(&c, 1));
    CHECK(op_bs_test(&c, 3));
    CHECK(op_bs_test(&c, 5));
    CHECK(!op_bs_test(&c, 0));
    CHECK(op_bs_count(&c) == 3);

    bs64 d = a;
    op_bs_and(&d, &b);
    CHECK(!op_bs_test(&d, 1));
    CHECK(op_bs_test(&d, 3));
    CHECK(!op_bs_test(&d, 5));
    CHECK(op_bs_count(&d) == 1);

    bs64 e = a;
    op_bs_xor(&e, &b);
    CHECK(op_bs_test(&e, 1));   /* in a only */
    CHECK(!op_bs_test(&e, 3));  /* in both → cancel */
    CHECK(op_bs_test(&e, 5));   /* in b only */

    bs64 f = a;
    op_bs_andnot(&f, &b);
    CHECK(op_bs_test(&f, 1));   /* in a but not b */
    CHECK(!op_bs_test(&f, 3));  /* in both → cleared */
    CHECK(!op_bs_test(&f, 5));  /* in b only → not in a */
}

static void
test_eq_subset_intersects(void)
{
    SECTION("eq / subset / intersects predicates");
    bs64 a, b, c;
    op_bs_zero(&a);
    op_bs_zero(&b);
    op_bs_zero(&c);

    op_bs_set(&a, 2);
    op_bs_set(&a, 4);
    b = a;
    CHECK(op_bs_eq(&a, &b));

    op_bs_set(&c, 2);
    CHECK(op_bs_subset(&c, &a));   /* c = {2} ⊆ a = {2,4} */
    CHECK(!op_bs_subset(&a, &c));  /* a ⊄ c */

    bs64 d;
    op_bs_zero(&d);
    op_bs_set(&d, 7);
    CHECK(!op_bs_intersects(&a, &d));  /* disjoint */
    op_bs_set(&d, 4);
    CHECK(op_bs_intersects(&a, &d));   /* share bit 4 */
}

static void
test_iteration(void)
{
    SECTION("op_bs_next iteration on 256-bit bitset");
    bs256 s;
    op_bs_zero(&s);

    /* Set some scattered bits */
    const int bits[] = { 0, 1, 63, 64, 65, 127, 128, 200, 255 };
    const int nbits = (int)(sizeof bits / sizeof bits[0]);
    for (int i = 0; i < nbits; i++)
        op_bs_set(&s, bits[i]);

    /* Iterate and collect */
    int found[16];
    int nfound = 0;
    int b;
    OP_BS_FOREACH(&s, b)
    {
        assert(nfound < 16);
        found[nfound++] = b;
    }

    CHECK(nfound == nbits);
    for (int i = 0; i < nbits; i++)
        CHECK(found[i] == bits[i]);
}

static void
test_iteration_empty(void)
{
    SECTION("OP_BS_FOREACH on empty bitset yields no iterations");
    bs64 s;
    op_bs_zero(&s);
    int count = 0;
    int b;
    OP_BS_FOREACH(&s, b)
        count++;
    CHECK(count == 0);
}

static void
test_iteration_full(void)
{
    SECTION("OP_BS_FOREACH on full 64-bit bitset yields 64 bits");
    bs64 s;
    op_bs_fill(&s);
    int count = 0;
    int b;
    OP_BS_FOREACH(&s, b)
        count++;
    CHECK(count == 64);
}

static void
test_sizeof_words(void)
{
    SECTION("OP_BITSET_DEFINE sizes are correct via sizeof");
    bs64  a64;
    bs128 a128;
    bs256 a256;
    CHECK(sizeof(a64.w)  / sizeof(uint64_t) == 1);
    CHECK(sizeof(a128.w) / sizeof(uint64_t) == 2);
    CHECK(sizeof(a256.w) / sizeof(uint64_t) == 4);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("test_bitset\n");
    test_basic_ops();
    test_fill_and_not();
    test_flip();
    test_multi_word();
    test_aggregate_ops();
    test_eq_subset_intersects();
    test_iteration();
    test_iteration_empty();
    test_iteration_full();
    test_sizeof_words();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
