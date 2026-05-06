/*
 * libop: ophion support library.
 * utf8.c: UTF-8 validation and scanning implementation.
 *
 * Uses a direct byte-by-byte decoder that is unambiguously correct against
 * RFC 3629, Unicode 15.1 §3.9, and the W3C WHATWG encoding specification.
 *
 * Validated properties:
 *   - No overlong encodings (rejects 0xC0-0xC1 leads and under-range sequences)
 *   - No surrogate halves (U+D800–U+DFFF)
 *   - No code points above U+10FFFF
 *   - No truncated sequences (sequence continues past end of buffer)
 *   - No bare continuation bytes (0x80–0xBF without a lead byte)
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_utf8.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- internal decoder ---------------------------------------------------- */

/*
 * utf8_decode_one — decode the next code point from [p, end).
 *
 * On success: returns pointer past the decoded sequence, populates *cp.
 * On error:   returns NULL, *cp is undefined.
 *
 * This is the single authoritative decode function used by all public APIs.
 */
static const uint8_t *
utf8_decode_one(const uint8_t *p, const uint8_t *end, uint32_t *cp)
{
    if (p >= end)
        return NULL;

    uint8_t b = *p++;

    if (b < 0x80)
    {
        /* ASCII: U+0000–U+007F */
        *cp = b;
        return p;
    }

    if (b < 0xC2)
        return NULL;  /* bare continuation (0x80–0xBF) or overlong (0xC0–0xC1) */

    uint32_t codepoint;
    int      extra;

    if (b < 0xE0)
    {
        /* 2-byte sequence: U+0080–U+07FF */
        codepoint = b & 0x1Fu;
        extra = 1;
    }
    else if (b < 0xF0)
    {
        /* 3-byte sequence: U+0800–U+FFFF */
        codepoint = b & 0x0Fu;
        extra = 2;
    }
    else if (b <= 0xF4)
    {
        /* 4-byte sequence: U+10000–U+10FFFF */
        codepoint = b & 0x07u;
        extra = 3;
    }
    else
    {
        return NULL;  /* 0xF5–0xFF: always invalid */
    }

    /* Consume continuation bytes. */
    for (int i = 0; i < extra; i++)
    {
        if (p >= end)
            return NULL;   /* truncated sequence */
        uint8_t c = *p++;
        if (c < 0x80u || c > 0xBFu)
            return NULL;   /* not a continuation byte */
        codepoint = (codepoint << 6) | (c & 0x3Fu);
    }

    /*
     * Reject overlong encodings.  A valid multi-byte sequence must encode a
     * code point strictly larger than the range of the next shorter form:
     *   2-byte: must be >= U+0080 (already guaranteed by filtering 0xC0-0xC1 above,
     *           since 0xC2 << 6 | 0x80 = 0x80, minimum valid is 0x80)
     *   3-byte: must be >= U+0800
     *   4-byte: must be >= U+10000
     */
    if (extra == 2 && codepoint < 0x0800u)
        return NULL;
    if (extra == 3 && codepoint < 0x10000u)
        return NULL;

    /* Reject surrogate halves. */
    if (codepoint >= 0xD800u && codepoint <= 0xDFFFu)
        return NULL;

    /* Reject code points above U+10FFFF. */
    if (codepoint > 0x10FFFFu)
        return NULL;

    *cp = codepoint;
    return p;
}

/* ---- op_utf8_validate ---------------------------------------------------- */

bool
op_utf8_validate(const char *buf, size_t len, op_utf8_error_t *err)
{
    const uint8_t *p   = (const uint8_t *)buf;
    const uint8_t *end = p + len;

    while (p < end)
    {
        const uint8_t *prev = p;
        uint32_t cp;
        p = utf8_decode_one(p, end, &cp);
        if (!p)
        {
            if (err)
            {
                err->byte_offset = (size_t)(prev - (const uint8_t *)buf);
                err->byte_value  = *prev;
            }
            return false;
        }
    }
    return true;
}

bool
op_utf8_valid(const char *buf, size_t len)
{
    return op_utf8_validate(buf, len, NULL);
}

/* ---- op_utf8_next -------------------------------------------------------- */

const char *
op_utf8_next(const char *p, const char *end, uint32_t *cp)
{
    if (p >= end)
        return NULL;
    const uint8_t *next = utf8_decode_one((const uint8_t *)p,
                                           (const uint8_t *)end, cp);
    return (const char *)next;
}

/* ---- op_utf8_truncate ---------------------------------------------------- */

size_t
op_utf8_truncate(const char *buf, size_t len, size_t max_bytes)
{
    if (len <= max_bytes)
        return len;

    /*
     * Walk backwards from max_bytes to find the start of the last
     * (possibly incomplete) multi-byte sequence.
     */
    size_t safe = max_bytes;

    /* Skip over trailing continuation bytes (0x80–0xBF). */
    while (safe > 0 && ((uint8_t)buf[safe] & 0xC0u) == 0x80u)
        safe--;

    if (safe == max_bytes)
        return safe;   /* max_bytes points exactly at an ASCII byte */

    /*
     * We backed up to a lead byte (or ASCII byte).  Check whether the
     * sequence it starts fits entirely within [0, max_bytes).
     */
    uint8_t lead = (uint8_t)buf[safe];
    size_t seq_len;
    if      (lead < 0x80u)              seq_len = 1;   /* ASCII */
    else if ((lead & 0xE0u) == 0xC0u)  seq_len = 2;   /* 2-byte lead */
    else if ((lead & 0xF0u) == 0xE0u)  seq_len = 3;   /* 3-byte lead */
    else if ((lead & 0xF8u) == 0xF0u)  seq_len = 4;   /* 4-byte lead */
    else                                seq_len = 1;   /* invalid — treat as 1 */

    if (safe + seq_len <= max_bytes)
        return safe + seq_len;   /* complete sequence fits: include it */

    return safe;   /* incomplete: exclude the lead byte */
}

/* ---- op_utf8_sanitise ---------------------------------------------------- */

size_t
op_utf8_sanitise(const char *src, size_t src_len, char *dst, size_t dst_cap)
{
    const uint8_t *p     = (const uint8_t *)src;
    const uint8_t *end   = p + src_len;
    uint8_t       *out   = (uint8_t *)dst;
    uint8_t const *olim  = out + dst_cap;

    /* U+FFFD in UTF-8: EF BF BD */
    static const uint8_t replacement[3] = { 0xEFu, 0xBFu, 0xBDu };

    while (p < end)
    {
        const uint8_t *prev = p;
        uint32_t cp;
        p = utf8_decode_one(p, end, &cp);
        if (p)
        {
            /* Valid sequence: copy verbatim. */
            size_t slen = (size_t)(p - prev);
            if (out + slen <= olim)
            {
                memcpy(out, prev, slen);
                out += slen;
            }
        }
        else
        {
            /* Invalid byte: emit one U+FFFD and advance one byte. */
            if (out + 3 <= olim)
            {
                memcpy(out, replacement, 3);
                out += 3;
            }
            p = prev + 1;   /* skip exactly the invalid byte */
        }
    }

    return (size_t)(out - (uint8_t *)dst);
}

/* ---- op_utf8_strlen ------------------------------------------------------ */

size_t
op_utf8_strlen(const char *buf, size_t len)
{
    const uint8_t *p   = (const uint8_t *)buf;
    const uint8_t *end = p + len;
    size_t count = 0;

    while (p < end)
    {
        const uint8_t *prev = p;
        uint32_t cp;
        p = utf8_decode_one(p, end, &cp);
        if (p)
        {
            count++;
        }
        else
        {
            /* One invalid byte → one replacement character. */
            count++;
            p = prev + 1;
        }
    }

    return count;
}
