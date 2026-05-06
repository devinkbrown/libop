/*
 * libop: ophion support library.
 * bloom.c: Counting Bloom filter implementation.
 *
 * See op_bloom.h for design notes.
 *
 * Copyright (C) 2026 ophion development team.  BSD 3-Clause.
 */

#include "op_lib.h"
#include <math.h>

/* -------------------------------------------------------------------------
 * Internal structure
 * ------------------------------------------------------------------------- */

struct op_bloom
{
	size_t   m;       /* number of counter slots (each slot = 4 bits) */
	unsigned k;       /* number of hash positions per element */
	size_t   n;       /* approximate count of inserted elements */
	uint8_t *cells;   /* packed 4-bit counters: 2 per byte, m/2 bytes */
};

/* -------------------------------------------------------------------------
 * Hash functions
 * ------------------------------------------------------------------------- */

/* FNV-1a 64-bit — fast, good avalanche for short keys */
static inline uint64_t
fnv1a_64(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint64_t h = UINT64_C(14695981039346656037);
	for(size_t i = 0; i < len; i++)
		h = (h ^ p[i]) * UINT64_C(1099511628211);
	return h;
}

/* SipHash-1-3 with compile-time key — fast, collision-resistant */
#define SIP_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND(v0,v1,v2,v3)         \
	do {                               \
		(v0) += (v1); (v1) = SIP_ROTL((v1), 13); (v1) ^= (v0); (v0) = SIP_ROTL((v0), 32); \
		(v2) += (v3); (v3) = SIP_ROTL((v3), 16); (v3) ^= (v2);                             \
		(v0) += (v3); (v3) = SIP_ROTL((v3), 21); (v3) ^= (v0);                             \
		(v2) += (v1); (v1) = SIP_ROTL((v1), 17); (v1) ^= (v2); (v2) = SIP_ROTL((v2), 32); \
	} while(0)

static const uint64_t BLOOM_K0 = UINT64_C(0x736f6d6570736575);
static const uint64_t BLOOM_K1 = UINT64_C(0x646f72616e646f6d);

static uint64_t
siphash13(const void *data, size_t inlen)
{
	const uint8_t *p = data;
	uint64_t v0 = BLOOM_K0 ^ UINT64_C(0x736f6d6570736575);
	uint64_t v1 = BLOOM_K1 ^ UINT64_C(0x646f72616e646f6d);
	uint64_t v2 = BLOOM_K0 ^ UINT64_C(0x6c7967656e657261);
	uint64_t v3 = BLOOM_K1 ^ UINT64_C(0x7465646279746573);
	uint64_t m;

	size_t left = inlen & 7;
	size_t blocks = inlen - left;

	for(size_t i = 0; i < blocks; i += 8) {
		memcpy(&m, p + i, 8);
		v3 ^= m;
		SIP_ROUND(v0,v1,v2,v3);
		v0 ^= m;
	}

	uint64_t b = (uint64_t)inlen << 56;
	switch(left) {
	case 7: b |= (uint64_t)p[blocks+6] << 48; /* fall through */
	case 6: b |= (uint64_t)p[blocks+5] << 40; /* fall through */
	case 5: b |= (uint64_t)p[blocks+4] << 32; /* fall through */
	case 4: b |= (uint64_t)p[blocks+3] << 24; /* fall through */
	case 3: b |= (uint64_t)p[blocks+2] << 16; /* fall through */
	case 2: b |= (uint64_t)p[blocks+1] <<  8; /* fall through */
	case 1: b |= (uint64_t)p[blocks+0];       /* fall through */
	default: break;
	}
	v3 ^= b;
	SIP_ROUND(v0,v1,v2,v3);
	v0 ^= b;
	v2 ^= 0xff;
	SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

/* -------------------------------------------------------------------------
 * Counter accessors (4-bit packed: 2 counters per byte)
 * Counter i: byte = cells[i/2], nibble = (i & 1) ? high : low
 * ------------------------------------------------------------------------- */

static inline unsigned
cell_get(const uint8_t *cells, size_t i)
{
	return (i & 1) ? (cells[i >> 1] >> 4) & 0xF
	               :  cells[i >> 1]        & 0xF;
}

static inline void
cell_inc(uint8_t *cells, size_t i)
{
	if((i & 1)) {
		uint8_t hi = (cells[i >> 1] >> 4) & 0xF;
		if(hi < 15) cells[i >> 1] += 0x10;
	} else {
		uint8_t lo = cells[i >> 1] & 0xF;
		if(lo < 15) cells[i >> 1]++;
	}
}

static inline void
cell_dec(uint8_t *cells, size_t i)
{
	if((i & 1)) {
		uint8_t hi = (cells[i >> 1] >> 4) & 0xF;
		if(hi > 0) cells[i >> 1] -= 0x10;
	} else {
		uint8_t lo = cells[i >> 1] & 0xF;
		if(lo > 0) cells[i >> 1]--;
	}
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

op_bloom_t *
op_bloom_new(size_t capacity, double fp_rate)
{
	if(capacity == 0 || fp_rate <= 0.0 || fp_rate >= 1.0)
		return NULL;

	/* m = -(n * ln(p)) / (ln 2)^2  — round up to even */
	double ln2  = log(2.0);
	double bits = -((double)capacity * log(fp_rate)) / (ln2 * ln2);
	size_t m = (size_t)ceil(bits);
	if(m < 16) m = 16;
	if(m & 1) m++;  /* keep even for nibble alignment */

	/* k = (m/n) * ln 2 — at least 1 */
	unsigned k = (unsigned)ceil(((double)m / (double)capacity) * ln2);
	if(k < 1) k = 1;
	if(k > 32) k = 32;

	op_bloom_t *b = op_malloc(sizeof(*b));
	b->m     = m;
	b->k     = k;
	b->n     = 0;
	b->cells = op_calloc(m >> 1, 1);  /* m/2 bytes, zeroed */
	return b;
}

void
op_bloom_free(op_bloom_t *b)
{
	if(!b) return;
	op_free(b->cells);
	op_free(b);
}

void
op_bloom_reset(op_bloom_t *b)
{
	if(!b) return;
	memset(b->cells, 0, b->m >> 1);
	b->n = 0;
}

void
op_bloom_params(const op_bloom_t *b, size_t *out_bits, unsigned *out_k)
{
	if(out_bits) *out_bits = b ? b->m : 0;
	if(out_k)    *out_k    = b ? b->k : 0;
}

bool
op_bloom_add(op_bloom_t *b, const void *key, size_t len)
{
	uint64_t h1 = siphash13(key, len);
	uint64_t h2 = fnv1a_64(key, len) | 1;  /* ensure h2 is odd (coprime with m) */
	bool was_present = true;

	for(unsigned i = 0; i < b->k; i++) {
		size_t pos = (size_t)((h1 + (uint64_t)i * h2) % (uint64_t)b->m);
		if(cell_get(b->cells, pos) == 0)
			was_present = false;
		cell_inc(b->cells, pos);
	}
	if(!was_present)
		b->n++;
	return was_present;
}

bool
op_bloom_test(const op_bloom_t *b, const void *key, size_t len)
{
	uint64_t h1 = siphash13(key, len);
	uint64_t h2 = fnv1a_64(key, len) | 1;

	for(unsigned i = 0; i < b->k; i++) {
		size_t pos = (size_t)((h1 + (uint64_t)i * h2) % (uint64_t)b->m);
		if(cell_get(b->cells, pos) == 0)
			return false;
	}
	return true;
}

void
op_bloom_remove(op_bloom_t *b, const void *key, size_t len)
{
	/* Only remove if we know it was present (all counters > 0). */
	if(!op_bloom_test(b, key, len))
		return;

	uint64_t h1 = siphash13(key, len);
	uint64_t h2 = fnv1a_64(key, len) | 1;

	for(unsigned i = 0; i < b->k; i++) {
		size_t pos = (size_t)((h1 + (uint64_t)i * h2) % (uint64_t)b->m);
		cell_dec(b->cells, pos);
	}
	if(b->n > 0)
		b->n--;
}
