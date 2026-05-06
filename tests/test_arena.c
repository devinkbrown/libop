/*
 * test_arena.c — unit tests for op_arena bump allocator.
 *
 * Coverage:
 *   - Basic alloc / reset cycle
 *   - Alignment guarantee (all allocs are pointer-aligned)
 *   - Strdup / strndup
 *   - Save / restore marks (inline only)
 *   - Overflow: allocations beyond OP_ARENA_DEFAULT_CAPACITY fall to heap
 *   - op_ealloc / op_estrdup convenience wrappers
 *   - Repeated reset drains overflow list
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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

static bool
is_aligned(const void *p)
{
    return ((uintptr_t)p % sizeof(void *)) == 0;
}

/* ---- tests --------------------------------------------------------------- */

static void
test_basic_alloc(void)
{
    SECTION("alloc: returns non-NULL, zeroed memory");
    op_arena_t a;
    op_arena_init(&a, NULL, 4096);

    void *p = op_arena_alloc(&a, 64);
    CHECK(p != NULL);
    CHECK(is_aligned(p));
    /* op_arena_calloc should zero-initialise. */
    void *q = op_arena_calloc(&a, 64);
    CHECK(q != NULL);
    for (int i = 0; i < 64; i++)
        CHECK(((char *)q)[i] == 0);

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_alignment(void)
{
    SECTION("alloc: all sizes are pointer-aligned");
    op_arena_t a;
    op_arena_init(&a, NULL, 4096);

    for (size_t sz = 1; sz <= 33; sz++) {
        void *p = op_arena_alloc(&a, sz);
        CHECK(is_aligned(p));
    }

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_strdup(void)
{
    SECTION("strdup / strndup");
    op_arena_t a;
    op_arena_init(&a, NULL, 4096);

    const char *orig = "hello, IRC!";
    char *copy = op_arena_strdup(&a, orig);
    CHECK(copy != NULL && strcmp(copy, orig) == 0);

    char *partial = op_arena_strndup(&a, orig, 5);
    CHECK(partial != NULL && strcmp(partial, "hello") == 0);

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_reset(void)
{
    SECTION("reset: rewinds inline pointer");
    op_arena_t a;
    op_arena_init(&a, NULL, 4096);

    void *p1 = op_arena_alloc(&a, 128);
    op_arena_reset(&a);

    void *p2 = op_arena_alloc(&a, 128);
    /* After reset the arena can reuse the same region. */
    CHECK(p2 == p1);   /* same start address after reset */

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_save_restore(void)
{
    SECTION("save/restore: sub-scope reuse");
    op_arena_t a;
    op_arena_init(&a, NULL, 4096);

    void *base = op_arena_alloc(&a, 16);
    op_arena_mark_t mark = op_arena_save(&a);

    op_arena_alloc(&a, 64);
    op_arena_alloc(&a, 64);

    op_arena_restore(&a, mark);

    /* Next allocation should reuse the position after base. */
    void *after = op_arena_alloc(&a, 16);
    CHECK((char *)after == (char *)base + 16);  /* immediately after base */

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_overflow(void)
{
    SECTION("overflow: >4 KB falls to heap");
    op_arena_t a;
    /* Use a tiny 1 KB arena so we overflow quickly. */
    op_arena_init(&a, NULL, 1024);

    /* Exhaust the inline buffer with 1 KB. */
    op_arena_alloc(&a, 1024);

    /* This allocation must overflow to heap — it must still succeed. */
    void *heap_alloc = op_arena_alloc(&a, 256);
    CHECK(heap_alloc != NULL);
    CHECK(is_aligned(heap_alloc));

    /* Write to the overflow allocation to prove it's valid memory. */
    memset(heap_alloc, 0xAB, 256);
    CHECK(((uint8_t *)heap_alloc)[0] == 0xAB);

    /* Reset must free the overflow block without crashing. */
    op_arena_reset(&a);

    op_arena_fini(&a);
    END_SECTION;
}

static void
test_global_arena(void)
{
    SECTION("global arena: op_ealloc / op_estrdup");
    op_arena_reset(op_event_arena());

    void *p = op_ealloc(32);
    CHECK(p != NULL && is_aligned(p));

    char *s = op_estrdup("test string");
    CHECK(s != NULL && strcmp(s, "test string") == 0);

    op_arena_reset(op_event_arena());
    END_SECTION;
}

static void
test_many_small_allocs(void)
{
    SECTION("many small allocs: 1000x4-byte allocs then reset");
    op_arena_t a;
    op_arena_init(&a, NULL, OP_ARENA_DEFAULT_CAPACITY);

    for (int i = 0; i < 1000; i++) {
        int *n = op_arena_alloc(&a, sizeof(int));
        CHECK(n != NULL);
        *n = i;
    }

    /* Reset must drain everything cleanly. */
    op_arena_reset(&a);
    /* First alloc after reset should be at the beginning of the buffer. */
    void *p = op_arena_alloc(&a, 4);
    CHECK(p == (void *)a.base);

    op_arena_fini(&a);
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("op_arena tests\n");

    test_basic_alloc();
    test_alignment();
    test_strdup();
    test_reset();
    test_save_restore();
    test_overflow();
    test_global_arena();
    test_many_small_allocs();

    printf("\n%s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
