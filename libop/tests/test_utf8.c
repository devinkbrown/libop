/*
 * test_utf8.c — unit tests for op_utf8 validation, truncation, and sanitisation.
 *
 * Coverage:
 *   - ASCII (trivially valid)
 *   - 2-byte, 3-byte, 4-byte sequences
 *   - Overlong encodings (reject)
 *   - Surrogate halves U+D800–U+DFFF (reject)
 *   - Code points > U+10FFFF (reject)
 *   - Truncated sequences at end of buffer (reject)
 *   - op_utf8_truncate: safe truncation without splitting multi-byte
 *   - op_utf8_sanitise: replacement character insertion
 *   - op_utf8_next: code point iteration
 *   - op_utf8_strlen: character count with invalid byte handling
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

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

/* ---- valid inputs -------------------------------------------------------- */

static void
test_valid_ascii(void)
{
    SECTION("valid: ASCII");
    CHECK(op_utf8_valid("", 0));
    CHECK(op_utf8_valid("hello", 5));
    CHECK(op_utf8_valid("PRIVMSG #chan :hi\r\n", 19));
    END_SECTION;
}

static void
test_valid_2byte(void)
{
    SECTION("valid: 2-byte sequences");
    /* é = U+00E9 → 0xC3 0xA9 */
    const char s[] = "\xC3\xA9";
    CHECK(op_utf8_valid(s, 2));
    /* ñ = U+00F1 → 0xC3 0xB1 */
    const char t[] = "ma\xC3\xB1" "ana";
    CHECK(op_utf8_valid(t, 7));
    END_SECTION;
}

static void
test_valid_3byte(void)
{
    SECTION("valid: 3-byte sequences");
    /* € = U+20AC → 0xE2 0x82 0xAC */
    const char s[] = "\xE2\x82\xAC";
    CHECK(op_utf8_valid(s, 3));
    /* ☃ = U+2603 → 0xE2 0x98 0x83 */
    const char t[] = "\xE2\x98\x83";
    CHECK(op_utf8_valid(t, 3));
    END_SECTION;
}

static void
test_valid_4byte(void)
{
    SECTION("valid: 4-byte sequences (supplementary)");
    /* 𝄞 (musical score) = U+1D11E → 0xF0 0x9D 0x84 0x9E */
    const char s[] = "\xF0\x9D\x84\x9E";
    CHECK(op_utf8_valid(s, 4));
    /* U+10FFFF (highest valid) → 0xF4 0x8F 0xBF 0xBF */
    const char t[] = "\xF4\x8F\xBF\xBF";
    CHECK(op_utf8_valid(t, 4));
    END_SECTION;
}

/* ---- invalid inputs ------------------------------------------------------ */

static void
test_invalid_continuation_solo(void)
{
    SECTION("invalid: bare continuation byte");
    /* 0x80 alone is invalid (no lead byte). */
    CHECK(!op_utf8_valid("\x80", 1));
    CHECK(!op_utf8_valid("\xBF", 1));
    END_SECTION;
}

static void
test_invalid_overlong(void)
{
    SECTION("invalid: overlong encodings");
    /* Overlong '/' (U+002F) in 2-byte form: 0xC0 0xAF */
    CHECK(!op_utf8_valid("\xC0\xAF", 2));
    /* Overlong NUL in 2-byte form: 0xC0 0x80 */
    CHECK(!op_utf8_valid("\xC0\x80", 2));
    /* Overlong in 3-byte form: 0xE0 0x80 0x80 */
    CHECK(!op_utf8_valid("\xE0\x80\x80", 3));
    END_SECTION;
}

static void
test_invalid_surrogate(void)
{
    SECTION("invalid: surrogate halves (U+D800–U+DFFF)");
    /* U+D800 → 0xED 0xA0 0x80 */
    CHECK(!op_utf8_valid("\xED\xA0\x80", 3));
    /* U+DFFF → 0xED 0xBF 0xBF */
    CHECK(!op_utf8_valid("\xED\xBF\xBF", 3));
    END_SECTION;
}

static void
test_invalid_above_10ffff(void)
{
    SECTION("invalid: code points > U+10FFFF");
    /* U+110000 → 0xF4 0x90 0x80 0x80 */
    CHECK(!op_utf8_valid("\xF4\x90\x80\x80", 4));
    /* 5-byte sequences are always invalid in UTF-8. */
    CHECK(!op_utf8_valid("\xF8\x80\x80\x80\x80", 5));
    END_SECTION;
}

static void
test_invalid_truncated(void)
{
    SECTION("invalid: truncated sequence at end");
    /* 2-byte lead with no continuation. */
    CHECK(!op_utf8_valid("\xC3", 1));
    /* 3-byte lead with only one continuation. */
    CHECK(!op_utf8_valid("\xE2\x82", 2));
    /* 4-byte lead with two continuations. */
    CHECK(!op_utf8_valid("\xF0\x9D\x84", 3));
    END_SECTION;
}

/* ---- op_utf8_validate error position ------------------------------------- */

static void
test_validate_error_position(void)
{
    SECTION("validate: error position reporting");
    op_utf8_error_t err;
    const char s[] = "hello\x80world";  /* invalid at offset 5 */
    bool ok = op_utf8_validate(s, sizeof(s) - 1, &err);
    CHECK(!ok);
    CHECK(err.byte_offset == 5);
    CHECK(err.byte_value == 0x80);
    END_SECTION;
}

/* ---- op_utf8_truncate ---------------------------------------------------- */

static void
test_truncate(void)
{
    SECTION("truncate: does not split 2-byte sequence");
    /* "aé" = 0x61 0xC3 0xA9 — truncate to 2 bytes should give "a" (1 byte),
     * not "a\xC3" (which would be an incomplete sequence). */
    const char s[] = "a\xC3\xA9";
    size_t n = op_utf8_truncate(s, 3, 2);
    CHECK(n == 1);
    END_SECTION;

    SECTION("truncate: fits exactly on boundary");
    /* "é" = 2 bytes; truncate to 2 → include it. */
    const char t[] = "\xC3\xA9" "x";
    size_t m = op_utf8_truncate(t, 3, 2);
    CHECK(m == 2);
    END_SECTION;

    SECTION("truncate: max >= len is a no-op");
    const char u[] = "hello";
    CHECK(op_utf8_truncate(u, 5, 100) == 5);
    END_SECTION;

    SECTION("truncate: 3-byte sequence not split");
    /* "€" = 3 bytes. Truncate to 2 → 0 bytes (can't include partial). */
    const char v[] = "\xE2\x82\xAC";
    CHECK(op_utf8_truncate(v, 3, 2) == 0);
    END_SECTION;
}

/* ---- op_utf8_sanitise ---------------------------------------------------- */

static void
test_sanitise(void)
{
    char dst[64];

    SECTION("sanitise: valid input unchanged");
    {
        size_t n = op_utf8_sanitise("hello", 5, dst, sizeof(dst));
        CHECK(n == 5);
        CHECK(memcmp(dst, "hello", 5) == 0);
    }
    END_SECTION;

    SECTION("sanitise: single invalid byte → U+FFFD");
    {
        size_t m = op_utf8_sanitise("\x80", 1, dst, sizeof(dst));
        CHECK(m == 3);  /* EF BF BD */
        CHECK((uint8_t)dst[0] == 0xEF);
        CHECK((uint8_t)dst[1] == 0xBF);
        CHECK((uint8_t)dst[2] == 0xBD);
    }
    END_SECTION;

    SECTION("sanitise: mixed valid and invalid");
    {
        /* "hi\x80ok" → "hi" + U+FFFD + "ok" = 2+3+2 = 7 bytes */
        size_t p = op_utf8_sanitise("hi\x80ok", 5, dst, sizeof(dst));
        CHECK(p == 7);
        CHECK(memcmp(dst, "hi", 2) == 0);
        CHECK((uint8_t)dst[2] == 0xEF);
        CHECK(memcmp(dst + 5, "ok", 2) == 0);
    }
    END_SECTION;
}

/* ---- op_utf8_next -------------------------------------------------------- */

static void
test_next(void)
{
    SECTION("next: iterate ASCII");
    const char s[] = "abc";
    const char *p = s, *end = s + 3;
    uint32_t cp;
    p = op_utf8_next(p, end, &cp);
    CHECK(p != NULL && cp == 'a');
    p = op_utf8_next(p, end, &cp);
    CHECK(p != NULL && cp == 'b');
    p = op_utf8_next(p, end, &cp);
    CHECK(p != NULL && cp == 'c');
    p = op_utf8_next(p, end, &cp);
    CHECK(p == NULL);
    END_SECTION;

    SECTION("next: iterate multi-byte");
    /* "é€" = 0xC3 0xA9 0xE2 0x82 0xAC */
    const char t[] = "\xC3\xA9\xE2\x82\xAC";
    const char *q = t, *qend = t + 5;
    uint32_t c1, c2;
    q = op_utf8_next(q, qend, &c1);
    CHECK(q != NULL && c1 == 0x00E9u);
    q = op_utf8_next(q, qend, &c2);
    CHECK(q != NULL && c2 == 0x20ACu);
    END_SECTION;

    SECTION("next: returns NULL on invalid byte");
    const char bad[] = "\x80";
    uint32_t c;
    CHECK(op_utf8_next(bad, bad + 1, &c) == NULL);
    END_SECTION;
}

/* ---- op_utf8_strlen ------------------------------------------------------ */

static void
test_strlen(void)
{
    SECTION("strlen: ASCII");
    CHECK(op_utf8_strlen("hello", 5) == 5);
    END_SECTION;

    SECTION("strlen: multi-byte");
    /* "éàü" = 3 code points, 6 bytes */
    CHECK(op_utf8_strlen("\xC3\xA9\xC3\xA0\xC3\xBC", 6) == 3);
    END_SECTION;

    SECTION("strlen: invalid bytes count as 1 each");
    /* "\x80\x81" — 2 invalid bytes → 2 code points */
    CHECK(op_utf8_strlen("\x80\x81", 2) == 2);
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("op_utf8 tests\n");

    test_valid_ascii();
    test_valid_2byte();
    test_valid_3byte();
    test_valid_4byte();
    test_invalid_continuation_solo();
    test_invalid_overlong();
    test_invalid_surrogate();
    test_invalid_above_10ffff();
    test_invalid_truncated();
    test_validate_error_position();
    test_truncate();
    test_sanitise();
    test_next();
    test_strlen();

    printf("\n%s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
