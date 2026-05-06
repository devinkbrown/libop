/*
 * test_str_intern.c — unit tests for op_str_intern.
 *
 * Coverage:
 *   [1] basic get: same pointer returned for identical string
 *   [2] distinct strings get distinct pointers
 *   [3] reference count: put releases when count reaches zero
 *   [4] put then re-intern: new pointer but equal string
 *   [5] getn: intern by length, no NUL required in source
 *   [6] peek: returns pointer without incrementing refcount
 *   [7] case-insensitive table: "Nick" == "nick" share one entry
 *   [8] case-insensitive irc: { [ ] } | ^ ~ treated as { [ ] } (RFC 1459)
 *   [9] multiple references: string lives until last put
 *  [10] introspection: count, bytes, stats string
 *  [11] destroy: table with live entries does not leak (no crash)
 *  [12] empty string interning
 *  [13] large string (> 511 bytes, triggers heap path in getn)
 *  [14] high churn: 1000 unique strings inserted and removed
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/* ---- helpers ------------------------------------------------------------- */

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define CHECK_STR(a, b)  CHECK(strcmp((a), (b)) == 0)

#define SECTION(name)   do { int _before = failures; const char *_sec = (name);
#define END_SECTION     printf("  %-52s %s\n", _sec, \
                               failures == _before ? "pass" : "FAIL"); } while (0)

/* ---- tests --------------------------------------------------------------- */

static void
test_basic(void)
{
    op_str_intern_t *tbl = op_str_intern_create("basic", false, 0);

    SECTION("[1] same pointer for identical string");
    {
        const char *a = op_str_intern_get(tbl, "hello");
        const char *b = op_str_intern_get(tbl, "hello");
        CHECK(a == b);           /* pointer equality */
        CHECK_STR(a, "hello");
        /* Release both references. */
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[2] distinct strings get distinct pointers");
    {
        const char *a = op_str_intern_get(tbl, "foo");
        const char *b = op_str_intern_get(tbl, "bar");
        const char *c = op_str_intern_get(tbl, "baz");
        CHECK(a != b);
        CHECK(b != c);
        CHECK(a != c);
        CHECK_STR(a, "foo");
        CHECK_STR(b, "bar");
        CHECK_STR(c, "baz");
        CHECK(op_str_intern_count(tbl) == 3);
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        op_str_intern_put(tbl, c);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[3] put releases when count reaches zero");
    {
        const char *a = op_str_intern_get(tbl, "ephemeral");
        CHECK(op_str_intern_count(tbl) == 1);
        op_str_intern_put(tbl, a);
        CHECK(op_str_intern_count(tbl) == 0);
        /* After release, peek must return NULL. */
        CHECK(op_str_intern_peek(tbl, "ephemeral") == NULL);
    }
    END_SECTION;

    SECTION("[4] put then re-intern: new pointer, equal string");
    {
        const char *a = op_str_intern_get(tbl, "cycle");
        op_str_intern_put(tbl, a);
        const char *b = op_str_intern_get(tbl, "cycle");
        /* b is a fresh allocation — may or may not alias a (impl detail).
         * What matters: the string content is correct and count is 1. */
        CHECK_STR(b, "cycle");
        CHECK(op_str_intern_count(tbl) == 1);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[5] getn: intern by length");
    {
        /* Source is not NUL-terminated at the end of the relevant slice. */
        const char src[] = "worldXXX";
        const char *a = op_str_intern_getn(tbl, src, 5);   /* "world" */
        CHECK_STR(a, "world");
        const char *b = op_str_intern_get(tbl, "world");
        CHECK(a == b);   /* same entry */
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[6] peek: no refcount side-effects");
    {
        /* peek on absent key returns NULL. */
        CHECK(op_str_intern_peek(tbl, "ghost") == NULL);

        const char *a = op_str_intern_get(tbl, "present");
        const char *p = op_str_intern_peek(tbl, "present");
        CHECK(p == a);   /* same stable pointer */
        /* Only one put needed (peek didn't increment). */
        op_str_intern_put(tbl, a);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[9] multiple refs: string lives until last put");
    {
        const char *refs[10];
        for (int i = 0; i < 10; i++)
            refs[i] = op_str_intern_get(tbl, "shared");

        /* All 10 refs are the same pointer. */
        for (int i = 1; i < 10; i++)
            CHECK(refs[i] == refs[0]);

        CHECK(op_str_intern_count(tbl) == 1);

        /* Release 9 — string must still be present. */
        for (int i = 0; i < 9; i++)
            op_str_intern_put(tbl, refs[i]);
        CHECK(op_str_intern_count(tbl) == 1);
        CHECK(op_str_intern_peek(tbl, "shared") != NULL);

        /* Release the last one — string must be gone. */
        op_str_intern_put(tbl, refs[9]);
        CHECK(op_str_intern_count(tbl) == 0);
        CHECK(op_str_intern_peek(tbl, "shared") == NULL);
    }
    END_SECTION;

    SECTION("[10] introspection");
    {
        const char *a = op_str_intern_get(tbl, "abc");    /* 3 bytes */
        const char *b = op_str_intern_get(tbl, "defghi"); /* 6 bytes */
        const char *c = op_str_intern_get(tbl, "abc");    /* +1 ref, no new bytes */

        CHECK(op_str_intern_count(tbl) == 2);
        CHECK(op_str_intern_bytes(tbl) == 9);             /* 3 + 6 */
        CHECK_STR(op_str_intern_name(tbl), "basic");

        char statbuf[256];
        int n = op_str_intern_stats(tbl, statbuf, sizeof(statbuf));
        CHECK(n > 0);
        CHECK(strstr(statbuf, "basic") != NULL);
        CHECK(strstr(statbuf, "2 strings") != NULL);

        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        op_str_intern_put(tbl, c);
        CHECK(op_str_intern_count(tbl) == 0);
        CHECK(op_str_intern_bytes(tbl) == 0);
    }
    END_SECTION;

    SECTION("[12] empty string");
    {
        const char *a = op_str_intern_get(tbl, "");
        const char *b = op_str_intern_get(tbl, "");
        CHECK(a == b);
        CHECK(*a == '\0');
        CHECK(op_str_intern_count(tbl) == 1);
        CHECK(op_str_intern_bytes(tbl) == 0);
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[13] large string (>511 bytes triggers getn heap path)");
    {
        /* Build a 600-byte string. */
        char big[601];
        memset(big, 'A', 600);
        big[600] = '\0';

        const char *a = op_str_intern_getn(tbl, big, 600);
        CHECK(a != NULL);
        CHECK(strlen(a) == 600);
        CHECK(memcmp(a, big, 600) == 0);

        const char *b = op_str_intern_get(tbl, big);
        CHECK(a == b);   /* same entry */

        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[14] high churn: 1000 unique strings");
    {
        const char **ptrs = op_malloc(1000 * sizeof(char *));
        char buf[32];
        for (int i = 0; i < 1000; i++)
        {
            snprintf(buf, sizeof(buf), "str_%04d", i);
            ptrs[i] = op_str_intern_get(tbl, buf);
        }
        CHECK(op_str_intern_count(tbl) == 1000);

        for (int i = 0; i < 1000; i++)
            op_str_intern_put(tbl, ptrs[i]);
        CHECK(op_str_intern_count(tbl) == 0);
        CHECK(op_str_intern_bytes(tbl) == 0);
        op_free(ptrs);
    }
    END_SECTION;

    SECTION("[11] destroy with live entries (no crash)");
    {
        /* Intentionally don't release these before destroy. */
        (void)op_str_intern_get(tbl, "dangling1");
        (void)op_str_intern_get(tbl, "dangling2");
        CHECK(op_str_intern_count(tbl) == 2);
        /* destroy() frees all entries regardless of refcount. */
        op_str_intern_destroy(tbl);
        tbl = NULL;
    }
    END_SECTION;
}

static void
test_icase(void)
{
    op_str_intern_t *tbl = op_str_intern_create("icase", true, 0);

    SECTION("[7] case-insensitive: Nick == nick");
    {
        const char *a = op_str_intern_get(tbl, "Nick");
        const char *b = op_str_intern_get(tbl, "nick");
        const char *c = op_str_intern_get(tbl, "NICK");
        CHECK(a == b);
        CHECK(b == c);
        CHECK_STR(a, "Nick");   /* first insertion's case is preserved */
        CHECK(op_str_intern_count(tbl) == 1);
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        op_str_intern_put(tbl, c);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    SECTION("[8] IRC case: [ \\ ] { | } are equivalent pairs");
    {
        /* In IRC (RFC 1459) case mapping: '[' == '{', '\\' == '|', ']' == '}' */
        const char *a = op_str_intern_get(tbl, "[abc]");
        const char *b = op_str_intern_get(tbl, "{abc}");
        CHECK(a == b);
        op_str_intern_put(tbl, a);
        op_str_intern_put(tbl, b);
        CHECK(op_str_intern_count(tbl) == 0);
    }
    END_SECTION;

    op_str_intern_destroy(tbl);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("test_str_intern:\n");
    test_basic();
    test_icase();

    if (failures == 0)
        printf("  PASS\n");
    else
        printf("  FAIL (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
