/*
 * test_strbuf.c — unit tests for op_strbuf dynamic string builder.
 *
 * Coverage:
 *   - Empty init state
 *   - append_cstr (stays inline, then promotes to heap)
 *   - appendc (single character)
 *   - appendf (printf-style)
 *   - op_strbuf_clear (reuse buffer without dealloc)
 *   - op_strbuf_steal (ownership transfer)
 *   - op_strbuf_truncate
 *   - op_strbuf_trim_end
 *   - op_strbuf_ensure / op_strbuf_advance
 *   - Large string (forces many doublings)
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)  do { int _before = failures; const char *_sec = (name);
#define END_SECTION    printf("  %-44s %s\n", _sec, failures == _before ? "pass" : "FAIL"); } while (0)

/* ---- tests --------------------------------------------------------------- */

static void
test_init(void)
{
    SECTION("init: empty state");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    CHECK(op_strbuf_len(&sb) == 0);
    CHECK(op_strbuf_empty(&sb));
    CHECK(op_strbuf_str(&sb)[0] == '\0');
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_inline_append(void)
{
    SECTION("append: stays inline (< 175 bytes)");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_append_cstr(&sb, "Hello");
    op_strbuf_append_cstr(&sb, ", ");
    op_strbuf_append_cstr(&sb, "world!");
    CHECK(op_strbuf_len(&sb) == 13);
    CHECK(strcmp(op_strbuf_str(&sb), "Hello, world!") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_heap_promotion(void)
{
    SECTION("append: promotes to heap (> 175 bytes)");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    /* Build a 200-character string, forcing heap promotion. */
    for (int i = 0; i < 40; i++)
        op_strbuf_append_cstr(&sb, "hello ");
    CHECK(op_strbuf_len(&sb) == 240);
    /* Verify content integrity across multiple appends. */
    const char *s = op_strbuf_str(&sb);
    CHECK(strncmp(s, "hello hello ", 12) == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_appendc(void)
{
    SECTION("appendc: single character");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    for (char c = 'A'; c <= 'Z'; c++)
        op_strbuf_appendc(&sb, c);
    CHECK(op_strbuf_len(&sb) == 26);
    CHECK(strcmp(op_strbuf_str(&sb), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_appendf(void)
{
    SECTION("appendf: formatted append");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "user=%s host=%s port=%d", "nick", "example.com", 6667);
    CHECK(strcmp(op_strbuf_str(&sb), "user=nick host=example.com port=6667") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_clear(void)
{
    SECTION("clear: reuses buffer without deallocation");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_append_cstr(&sb, "before");
    op_strbuf_clear(&sb);
    CHECK(op_strbuf_len(&sb) == 0);
    CHECK(op_strbuf_empty(&sb));
    CHECK(op_strbuf_str(&sb)[0] == '\0');
    op_strbuf_append_cstr(&sb, "after");
    CHECK(strcmp(op_strbuf_str(&sb), "after") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_steal(void)
{
    SECTION("steal: ownership transfer");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_append_cstr(&sb, "stolen");
    char *p = op_strbuf_steal(&sb);
    CHECK(p != NULL);
    CHECK(strcmp(p, "stolen") == 0);
    CHECK(op_strbuf_empty(&sb));
    op_free(p);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_truncate(void)
{
    SECTION("truncate: shorten without realloc");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_append_cstr(&sb, "Hello, world!");
    op_strbuf_truncate(&sb, 5);
    CHECK(op_strbuf_len(&sb) == 5);
    CHECK(strcmp(op_strbuf_str(&sb), "Hello") == 0);
    /* Truncating to >= current length is a no-op. */
    op_strbuf_truncate(&sb, 100);
    CHECK(op_strbuf_len(&sb) == 5);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_trim_end(void)
{
    SECTION("trim_end: strip trailing characters");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_append_cstr(&sb, "  hello  \r\n");
    op_strbuf_trim_end(&sb, "\r\n ");
    CHECK(strcmp(op_strbuf_str(&sb), "  hello") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_ensure_advance(void)
{
    SECTION("ensure/advance: direct write interface");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    char *buf = op_strbuf_ensure(&sb, 10);
    memcpy(buf, "direct", 6);
    op_strbuf_advance(&sb, 6);
    CHECK(op_strbuf_len(&sb) == 6);
    CHECK(strcmp(op_strbuf_str(&sb), "direct") == 0);
    op_strbuf_free(&sb);
    END_SECTION;
}

static void
test_large(void)
{
    SECTION("large: 64KB string (many doublings)");
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    const size_t target = 65536;
    for (size_t i = 0; i < target; i++)
        op_strbuf_appendc(&sb, 'x');
    CHECK(op_strbuf_len(&sb) == target);
    /* Every character should be 'x'. */
    const char *s = op_strbuf_str(&sb);
    bool all_x = true;
    for (size_t i = 0; i < target && all_x; i++)
        if (s[i] != 'x') all_x = false;
    CHECK(all_x);
    op_strbuf_free(&sb);
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("op_strbuf tests\n");

    test_init();
    test_inline_append();
    test_heap_promotion();
    test_appendc();
    test_appendf();
    test_clear();
    test_steal();
    test_truncate();
    test_trim_end();
    test_ensure_advance();
    test_large();

    printf("\n%s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
