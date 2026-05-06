/*
 * libop/src/simd_scan.c — SIMD-accelerated byte-scan primitives.
 *
 * See libop/include/op_simd_scan.h for the API contract.
 *
 * Dispatch hierarchy (evaluated once per call via __builtin_cpu_supports):
 *
 *   x86-64
 *     AVX2  (GCC/Clang: __attribute__((target("avx2"))))   — 32 B/iter
 *     SSE2  (always available on x86-64)                   — 16 B/iter
 *   AArch64
 *     NEON  (always available on AArch64)                  — 16 B/iter
 *   Scalar fallback — 1 B/iter
 *
 * Using __attribute__((target)) per-function avoids the need for -mavx2 as a
 * global flag; the compiler emits the wider ISA only for those functions.
 *
 * Copyright (C) 2026 ophion development team
 * Licence: same as libop (GPL-2+).
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_simd_scan.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ── x86 / x86-64 paths ─────────────────────────────────────────────────── */

#if defined(__x86_64__) || defined(__i386__)
# include <immintrin.h>

/* ---- AVX2 (32 bytes per iteration) -------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
static const char *
_find_delim_avx2(const char *p, const char *end,
                 unsigned char d1, unsigned char d2)
{
	const __m256i v1  = _mm256_set1_epi8((char)d1);
	const __m256i v2  = _mm256_set1_epi8((char)d2);

	/* Process 32 bytes per iteration while at least 32 bytes remain. */
	while (p + 32 <= end)
	{
		__m256i chunk = _mm256_loadu_si256((const __m256i *)p);
		__m256i eq1   = _mm256_cmpeq_epi8(chunk, v1);
		__m256i eq2   = _mm256_cmpeq_epi8(chunk, v2);
		uint32_t mask = (uint32_t)_mm256_movemask_epi8(_mm256_or_si256(eq1, eq2));
		if (mask)
			return p + __builtin_ctz(mask);
		p += 32;
	}
	/* Scalar tail for the last < 32 bytes. */
	while (p < end)
	{
		unsigned char c = (unsigned char)*p;
		if (c == d1 || c == d2)
			return p;
		p++;
	}
	return end;
}

__attribute__((target("avx2")))
static size_t
_count_leading_avx2(const char *p, const char *end, unsigned char c)
{
	const char   *start = p;
	const __m256i vc    = _mm256_set1_epi8((char)c);

	while (p + 32 <= end)
	{
		__m256i chunk  = _mm256_loadu_si256((const __m256i *)p);
		__m256i eq     = _mm256_cmpeq_epi8(chunk, vc);
		uint32_t mask  = ~(uint32_t)_mm256_movemask_epi8(eq);
		if (mask)
			return (size_t)(p - start) + (size_t)__builtin_ctz(mask);
		p += 32;
	}
	while (p < end && (unsigned char)*p == c)
		p++;
	return (size_t)(p - start);
}
#endif /* GCC/Clang */

/* ---- SSE2 (16 bytes per iteration, always available on x86-64) ---------- */

static const char *
_find_delim_sse2(const char *p, const char *end,
                 unsigned char d1, unsigned char d2)
{
	const __m128i v1 = _mm_set1_epi8((char)d1);
	const __m128i v2 = _mm_set1_epi8((char)d2);

	while (p + 16 <= end)
	{
		__m128i chunk = _mm_loadu_si128((const __m128i *)p);
		__m128i eq1   = _mm_cmpeq_epi8(chunk, v1);
		__m128i eq2   = _mm_cmpeq_epi8(chunk, v2);
		int     mask  = _mm_movemask_epi8(_mm_or_si128(eq1, eq2));
		if (mask)
			return p + __builtin_ctz((unsigned)mask);
		p += 16;
	}
	while (p < end)
	{
		unsigned char c = (unsigned char)*p;
		if (c == d1 || c == d2)
			return p;
		p++;
	}
	return end;
}

static size_t
_count_leading_sse2(const char *p, const char *end, unsigned char c)
{
	const char  *start = p;
	const __m128i vc   = _mm_set1_epi8((char)c);

	while (p + 16 <= end)
	{
		__m128i chunk  = _mm_loadu_si128((const __m128i *)p);
		__m128i eq     = _mm_cmpeq_epi8(chunk, vc);
		int     mask   = ~_mm_movemask_epi8(eq);
		if (mask & 0xFFFF)
			return (size_t)(p - start) + (size_t)__builtin_ctz((unsigned)(mask & 0xFFFF));
		p += 16;
	}
	while (p < end && (unsigned char)*p == c)
		p++;
	return (size_t)(p - start);
}

/* ── AArch64 NEON path ──────────────────────────────────────────────────── */

#elif defined(__aarch64__)
# include <arm_neon.h>

static const char *
_find_delim_neon(const char *p, const char *end,
                 unsigned char d1, unsigned char d2)
{
	const uint8x16_t v1 = vdupq_n_u8(d1);
	const uint8x16_t v2 = vdupq_n_u8(d2);

	while (p + 16 <= end)
	{
		uint8x16_t chunk = vld1q_u8((const uint8_t *)p);
		uint8x16_t eq    = vorrq_u8(vceqq_u8(chunk, v1), vceqq_u8(chunk, v2));

		/* Collapse 16-byte mask to a 64-bit integer for CTZ. */
		uint64_t mask;
		vst1_u8((uint8_t *)&mask, vshrn_n_u16(vreinterpretq_u16_u8(eq), 4));
		if (mask)
			return p + (__builtin_ctzll(mask) >> 2);
		p += 16;
	}
	while (p < end)
	{
		unsigned char c = (unsigned char)*p;
		if (c == d1 || c == d2)
			return p;
		p++;
	}
	return end;
}

static size_t
_count_leading_neon(const char *p, const char *end, unsigned char c)
{
	const char      *start = p;
	const uint8x16_t vc    = vdupq_n_u8(c);

	while (p + 16 <= end)
	{
		uint8x16_t chunk = vld1q_u8((const uint8_t *)p);
		uint8x16_t neq   = vmvnq_u8(vceqq_u8(chunk, vc));
		uint64_t   mask;
		vst1_u8((uint8_t *)&mask, vshrn_n_u16(vreinterpretq_u16_u8(neq), 4));
		if (mask)
			return (size_t)(p - start) + (size_t)(__builtin_ctzll(mask) >> 2);
		p += 16;
	}
	while (p < end && (unsigned char)*p == c)
		p++;
	return (size_t)(p - start);
}

#endif /* arch */

/* ── Scalar fallback ────────────────────────────────────────────────────── */

static __attribute__((unused)) const char *
_find_delim_scalar(const char *p, const char *end,
                   unsigned char d1, unsigned char d2)
{
	while (p < end)
	{
		unsigned char c = (unsigned char)*p;
		if (c == d1 || c == d2)
			return p;
		p++;
	}
	return end;
}

static __attribute__((unused)) size_t
_count_leading_scalar(const char *p, const char *end, unsigned char c)
{
	const char *start = p;
	while (p < end && (unsigned char)*p == c)
		p++;
	return (size_t)(p - start);
}

/* ── Public dispatch functions ──────────────────────────────────────────── */

const char *
op_simd_find_delim(const char *p, const char *end,
                   unsigned char d1, unsigned char d2)
{
	ptrdiff_t len = end - p;
	if (__builtin_expect(len <= 0, 0))
		return end;

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
	if (__builtin_cpu_supports("avx2"))
		return _find_delim_avx2(p, end, d1, d2);
	/* SSE2 is baseline for x86-64 — no runtime check needed. */
	return _find_delim_sse2(p, end, d1, d2);
#elif defined(__aarch64__)
	return _find_delim_neon(p, end, d1, d2);
#else
	return _find_delim_scalar(p, end, d1, d2);
#endif
}

size_t
op_simd_count_leading(const char *p, const char *end, unsigned char c)
{
	if (__builtin_expect(p >= end, 0))
		return 0;

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
	if (__builtin_cpu_supports("avx2"))
		return _count_leading_avx2(p, end, c);
	return _count_leading_sse2(p, end, c);
#elif defined(__aarch64__)
	return _count_leading_neon(p, end, c);
#else
	return _count_leading_scalar(p, end, c);
#endif
}
