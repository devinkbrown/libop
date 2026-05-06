/*
 * libop: ophion support library.
 * op_utf8.h: UTF-8 validation and scanning primitives.
 *
 * Provides fast, correct UTF-8 validation for IRC protocol enforcement
 * (utf8-only CAP) and safe truncation without splitting multi-byte sequences.
 *
 * Design
 * ------
 * The validator is a DFA (deterministic finite automaton) based on the
 * Bjoern Hoehrmann / Markus Kuhn approach.  It processes one byte at a time
 * using two 256-entry lookup tables (character class and state transitions)
 * that fit entirely in L1 cache.  This is faster than branchy byte-by-byte
 * checks and simpler than SIMD for byte-sequence validation where the output
 * is a boolean, not a position.
 *
 * All functions accept arbitrary binary buffers (not NUL-terminated) via an
 * explicit `len` parameter.  Embedded NUL bytes are valid UTF-8 U+0000 and
 * are not treated as string terminators.
 *
 * Error recovery
 * --------------
 * op_utf8_sanitise() replaces each maximal invalid byte sequence with the
 * U+FFFD REPLACEMENT CHARACTER (EF BF BD in UTF-8), as recommended by the
 * Unicode standard (§3.9 best-practice).  The output is always valid UTF-8
 * and never longer than 3× the input.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_utf8.h directly; include op_lib.h"
#endif

#ifndef LIBOP_UTF8_H
#define LIBOP_UTF8_H

/* ---- types --------------------------------------------------------------- */

/* Returned by op_utf8_validate when the input is invalid. */
typedef struct op_utf8_error
{
	size_t  byte_offset; /* index of first invalid byte */
	uint8_t byte_value;  /* value of the offending byte */
} op_utf8_error_t;

/* ---- validation ---------------------------------------------------------- */

/*
 * op_utf8_valid — return true if [buf, buf+len) is valid UTF-8.
 *
 * Rejects overlong encodings, surrogate halves (U+D800–U+DFFF), and
 * code points above U+10FFFF.
 *
 * Pass len = strlen(buf) for NUL-terminated strings.
 */
bool op_utf8_valid(const char *buf, size_t len);

/*
 * op_utf8_validate — like op_utf8_valid but populates *err on failure.
 *
 * If the input is valid *err is not written.  If invalid, *err describes the
 * first offending byte.  err may be NULL (behaves like op_utf8_valid).
 */
bool op_utf8_validate(const char *buf, size_t len, op_utf8_error_t *err);

/* ---- code-point iteration ------------------------------------------------ */

/*
 * op_utf8_next — decode the next code point from [p, end).
 *
 * On success populates *cp and returns a pointer past the decoded sequence.
 * On invalid input returns NULL and leaves *cp undefined.
 *
 * Typical usage:
 *
 *   const char *p = buf, *end = buf + len;
 *   uint32_t cp;
 *   while (p < end) {
 *       p = op_utf8_next(p, end, &cp);
 *       if (!p) { handle_error(); break; }
 *       process_codepoint(cp);
 *   }
 */
const char *op_utf8_next(const char *p, const char *end, uint32_t *cp);

/* ---- safe truncation ----------------------------------------------------- */

/*
 * op_utf8_truncate — find the largest prefix of [buf, buf+len) that is at
 * most `max_bytes` bytes long and does not end in the middle of a multi-byte
 * sequence.
 *
 * Returns the byte length of the prefix (always <= max_bytes and <= len).
 * The result is safe to pass to memcpy / strndup without further checks.
 *
 * Example — truncate a topic to TOPICLEN bytes without splitting UTF-8:
 *
 *   size_t safe_len = op_utf8_truncate(topic, strlen(topic), TOPICLEN);
 *   char short_topic[TOPICLEN + 1];
 *   memcpy(short_topic, topic, safe_len);
 *   short_topic[safe_len] = '\0';
 */
size_t op_utf8_truncate(const char *buf, size_t len, size_t max_bytes);

/* ---- sanitisation -------------------------------------------------------- */

/*
 * op_utf8_sanitise — copy [src, src+src_len) to dst, replacing every maximal
 * invalid byte sequence with U+FFFD (EF BF BD).
 *
 * dst must point to a buffer of at least src_len * 3 bytes (worst case: every
 * byte is invalid → replaced by a 3-byte U+FFFD).
 *
 * Returns the number of bytes written to dst (not including a NUL terminator;
 * callers should NUL-terminate if needed).
 *
 * If src is already valid UTF-8 the output is identical to the input and the
 * return value equals src_len.
 */
size_t op_utf8_sanitise(const char *src, size_t src_len,
                         char *dst, size_t dst_cap);

/* ---- character-count helpers --------------------------------------------- */

/*
 * op_utf8_strlen — count the number of Unicode code points in [buf, buf+len).
 *
 * Invalid bytes each count as 1 code point (U+FFFD semantics).  This matches
 * the visual width reported by terminals for invalid sequences.
 */
size_t op_utf8_strlen(const char *buf, size_t len);

#endif /* LIBOP_UTF8_H */
