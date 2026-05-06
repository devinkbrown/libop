/*
 * crypt.c: SHA-256 and SHA-512 crypt implementations for Ophion IRC Daemon.
 *
 * Copyright (C) 2024 Ophion IRC Daemon contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * SHA-256 and SHA-512 crypt implementations are derived from Ulrich Drepper's
 * public domain implementation <drepper@redhat.com>.
 */

#include <libop_config.h>
#include <op_lib.h>

static char *op_sha256_crypt(const char *key, const char *salt);
static char *op_sha512_crypt(const char *key, const char *salt);

char *
op_crypt(const char *key, const char *salt)
{
	if (salt[0] != '$' || (salt[2] != '$' && salt[3] != '$'))
		return NULL;  /* DES not supported */
	switch (salt[1]) {
	case '5': return op_sha256_crypt(key, salt);
	case '6': return op_sha512_crypt(key, salt);
	default:  return NULL;
	}
}

/*
 * b64_from_24bit: encode 24 bits into base64 characters using the crypt
 * alphabet.  Writes up to N characters into the buffer pointed to by cp,
 * decrementing buflen accordingly.
 */
static const char ascii64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define b64_from_24bit(B2, B1, B0, N)					\
	do								\
	{								\
		unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);	\
		int n = (N);						\
		while (n-- > 0 && buflen > 0)				\
		{							\
			*cp++ = ascii64[w & 0x3f];			\
			--buflen;					\
			w >>= 6;					\
		}							\
	} while (0)

#ifndef MAX
#	define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#	define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* Zero a buffer in a way the optimiser cannot eliminate as a dead store
 * when the buffer is about to go out of scope.                           */
static void
secure_zero(void *s, size_t n)
{
	volatile unsigned char *p = (unsigned char *)s;
	while (n--)
		*p++ = 0;
}

/* -------------------------------------------------------------------------
 * SHA-256 crypt ($5$)
 * Derived from Ulrich Drepper's public domain implementation.
 * ------------------------------------------------------------------------- */

struct sha256_ctx
{
	uint32_t H[8];
	uint32_t total[2];
	uint32_t buflen;
	char buffer[128];	/* always correctly aligned for uint32_t */
};

#ifndef WORDS_BIGENDIAN
#	define SHA256_SWAP(n) \
		(((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
#	define SHA256_SWAP(n) (n)
#endif

static const unsigned char SHA256_fillbuf[64] = { 0x80, 0 };

static const uint32_t SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void
op_sha256_process_block(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	const uint32_t *words = buffer;
	size_t nwords = len / sizeof(uint32_t);
	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];

	ctx->total[0] += len;
	if (ctx->total[0] < len)
		++ctx->total[1];

#define SHA256_CYCLIC(w, s) ((w >> s) | (w << (32 - s)))
#define SHA256_Ch(x, y, z)  ((x & y) ^ (~x & z))
#define SHA256_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_S0(x) (SHA256_CYCLIC(x, 2)  ^ SHA256_CYCLIC(x, 13) ^ SHA256_CYCLIC(x, 22))
#define SHA256_S1(x) (SHA256_CYCLIC(x, 6)  ^ SHA256_CYCLIC(x, 11) ^ SHA256_CYCLIC(x, 25))
#define SHA256_R0(x) (SHA256_CYCLIC(x, 7)  ^ SHA256_CYCLIC(x, 18) ^ (x >> 3))
#define SHA256_R1(x) (SHA256_CYCLIC(x, 17) ^ SHA256_CYCLIC(x, 19) ^ (x >> 10))

	while (nwords > 0)
	{
		uint32_t W[64];
		uint32_t a_save = a, b_save = b, c_save = c, d_save = d;
		uint32_t e_save = e, f_save = f, g_save = g, h_save = h;
		unsigned int t;

		for (t = 0; t < 16; ++t)
		{
			W[t] = SHA256_SWAP(*words);
			++words;
		}
		for (t = 16; t < 64; ++t)
			W[t] = SHA256_R1(W[t - 2]) + W[t - 7] + SHA256_R0(W[t - 15]) + W[t - 16];

		for (t = 0; t < 64; ++t)
		{
			uint32_t T1 = h + SHA256_S1(e) + SHA256_Ch(e, f, g) + SHA256_K[t] + W[t];
			uint32_t T2 = SHA256_S0(a) + SHA256_Maj(a, b, c);
			h = g; g = f; f = e; e = d + T1;
			d = c; c = b; b = a; a = T1 + T2;
		}

		a += a_save; b += b_save; c += c_save; d += d_save;
		e += e_save; f += f_save; g += g_save; h += h_save;

		nwords -= 16;
	}

#undef SHA256_CYCLIC
#undef SHA256_Ch
#undef SHA256_Maj
#undef SHA256_S0
#undef SHA256_S1
#undef SHA256_R0
#undef SHA256_R1

	ctx->H[0] = a; ctx->H[1] = b; ctx->H[2] = c; ctx->H[3] = d;
	ctx->H[4] = e; ctx->H[5] = f; ctx->H[6] = g; ctx->H[7] = h;
}

/* Initialize structure containing state of computation.  (FIPS 180-2:5.3.2) */
static void
op_sha256_init_ctx(struct sha256_ctx *ctx)
{
	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;
	ctx->total[0] = ctx->total[1] = 0;
	ctx->buflen = 0;
}

/* Process the remaining bytes and write the result to RESBUF. */
static void *
op_sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf)
{
	uint32_t bytes = ctx->buflen, *ptr;
	size_t pad;
	unsigned int i;

	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes)
		++ctx->total[1];

	pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
	memcpy(&ctx->buffer[bytes], SHA256_fillbuf, pad);

	ptr = (uint32_t *)&ctx->buffer[bytes + pad + 4];
	*ptr = SHA256_SWAP(ctx->total[0] << 3);

	ptr = (uint32_t *)&ctx->buffer[bytes + pad];
	*ptr = SHA256_SWAP((ctx->total[1] << 3) | (ctx->total[0] >> 29));

	op_sha256_process_block(ctx->buffer, bytes + pad + 8, ctx);

	for (i = 0; i < 8; ++i)
		((uint32_t *)resbuf)[i] = SHA256_SWAP(ctx->H[i]);

	return resbuf;
}

static void
op_sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	if (ctx->buflen != 0)
	{
		size_t left_over = ctx->buflen;
		size_t add = 128 - left_over > len ? len : 128 - left_over;

		memcpy(&ctx->buffer[left_over], buffer, add);
		ctx->buflen += add;

		if (ctx->buflen > 64)
		{
			op_sha256_process_block(ctx->buffer, ctx->buflen & ~63, ctx);
			ctx->buflen &= 63;
			memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63], ctx->buflen);
		}

		buffer = (const char *)buffer + add;
		len -= add;
	}

	if (len >= 64)
	{
#if __GNUC__ >= 2
#	define SHA256_UNALIGNED_P(p) (((uintptr_t)(p)) % __alignof__(uint32_t) != 0)
#else
#	define SHA256_UNALIGNED_P(p) (((uintptr_t)(p)) % sizeof(uint32_t) != 0)
#endif
		if (SHA256_UNALIGNED_P(buffer))
			while (len > 64)
			{
				op_sha256_process_block(memcpy(ctx->buffer, buffer, 64), 64, ctx);
				buffer = (const char *)buffer + 64;
				len -= 64;
			}
		else
		{
			op_sha256_process_block(buffer, len & ~63, ctx);
			buffer = (const char *)buffer + (len & ~63);
			len &= 63;
		}
#undef SHA256_UNALIGNED_P
	}

	if (len > 0)
	{
		size_t left_over = ctx->buflen;

		memcpy(&ctx->buffer[left_over], buffer, len);
		left_over += len;
		if (left_over >= 64)
		{
			op_sha256_process_block(ctx->buffer, 64, ctx);
			left_over -= 64;
			memcpy(ctx->buffer, &ctx->buffer[64], left_over);
		}
		ctx->buflen = left_over;
	}
}

static const char sha256_salt_prefix[] = "$5$";
static const char sha256_rounds_prefix[] = "rounds=";

#define SHA256_SALT_LEN_MAX  16
#define SHA256_ROUNDS_DEFAULT 5000
#define SHA256_ROUNDS_MIN    1000
#define SHA256_ROUNDS_MAX    999999999

static char *
op_sha256_crypt_r(const char *key, const char *salt, char *buffer, size_t buflen)
{
	unsigned char alt_result[32]  __attribute__((__aligned__(__alignof__(uint32_t))));
	unsigned char temp_result[32] __attribute__((__aligned__(__alignof__(uint32_t))));
	struct sha256_ctx ctx;
	struct sha256_ctx alt_ctx;
	size_t salt_len;
	size_t key_len;
	size_t cnt;
	char *cp;
	char *p_bytes = NULL;
	char  s_bytes[SHA256_SALT_LEN_MAX];   /* salt_len <= 16, fits on stack */
	size_t rounds = SHA256_ROUNDS_DEFAULT;
	int rounds_custom = 0;

	if (strncmp(sha256_salt_prefix, salt, sizeof(sha256_salt_prefix) - 1) == 0)
		salt += sizeof(sha256_salt_prefix) - 1;

	if (strncmp(salt, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1) == 0)
	{
		const char *num = salt + sizeof(sha256_rounds_prefix) - 1;
		char *endp;
		unsigned int srounds = (unsigned int)strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			salt = endp + 1;
			rounds = MAX(SHA256_ROUNDS_MIN, MIN(srounds, SHA256_ROUNDS_MAX));
			rounds_custom = 1;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SHA256_SALT_LEN_MAX);
	key_len = strlen(key);

	/* op_sha256_process_bytes handles misaligned buffers internally
	 * (via its SHA256_UNALIGNED_P bounce path), so no alignment copies
	 * are needed here.                                                   */

	/* Prepare for the real work.  */
	op_sha256_init_ctx(&ctx);
	op_sha256_process_bytes(key, key_len, &ctx);
	op_sha256_process_bytes(salt, salt_len, &ctx);

	/* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  */
	op_sha256_init_ctx(&alt_ctx);
	op_sha256_process_bytes(key, key_len, &alt_ctx);
	op_sha256_process_bytes(salt, salt_len, &alt_ctx);
	op_sha256_process_bytes(key, key_len, &alt_ctx);
	op_sha256_finish_ctx(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum.  */
	for (cnt = key_len; cnt > 32; cnt -= 32)
		op_sha256_process_bytes(alt_result, 32, &ctx);
	op_sha256_process_bytes(alt_result, cnt, &ctx);

	/* For every 1 in binary length add alternate sum, for every 0 add key.  */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			op_sha256_process_bytes(alt_result, 32, &ctx);
		else
			op_sha256_process_bytes(key, key_len, &ctx);

	op_sha256_finish_ctx(&ctx, alt_result);

	/* Compute P byte sequence.  */
	op_sha256_init_ctx(&alt_ctx);
	for (cnt = 0; cnt < key_len; ++cnt)
		op_sha256_process_bytes(key, key_len, &alt_ctx);
	op_sha256_finish_ctx(&alt_ctx, temp_result);

	/* Heap-allocate p_bytes: key_len is attacker-controlled; alloca() of
	 * arbitrary size is a stack-overflow risk.  op_malloc aborts on OOM. */
	p_bytes = op_malloc(key_len);
	cp = p_bytes;
	for (cnt = key_len; cnt >= 32; cnt -= 32)
	{
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Compute S byte sequence.  */
	op_sha256_init_ctx(&alt_ctx);
	for (cnt = 0; cnt < (size_t)(16 + alt_result[0]); ++cnt)
		op_sha256_process_bytes(salt, salt_len, &alt_ctx);
	op_sha256_finish_ctx(&alt_ctx, temp_result);

	/* salt_len <= SHA256_SALT_LEN_MAX (16) < 32 so the pattern loop never
	 * executes; a single memcpy into the fixed s_bytes stack buffer suffices. */
	memcpy(s_bytes, temp_result, salt_len);

	/* Repeatedly run the collected hash value through SHA256.  */
	for (cnt = 0; cnt < rounds; ++cnt)
	{
		op_sha256_init_ctx(&ctx);

		if ((cnt & 1) != 0)
			op_sha256_process_bytes(p_bytes, key_len, &ctx);
		else
			op_sha256_process_bytes(alt_result, 32, &ctx);

		if (cnt % 3 != 0)
			op_sha256_process_bytes(s_bytes, salt_len, &ctx);

		if (cnt % 7 != 0)
			op_sha256_process_bytes(p_bytes, key_len, &ctx);

		if ((cnt & 1) != 0)
			op_sha256_process_bytes(alt_result, 32, &ctx);
		else
			op_sha256_process_bytes(p_bytes, key_len, &ctx);

		op_sha256_finish_ctx(&ctx, alt_result);
	}

	/* Construct the result string using memcpy + explicit pointer arithmetic.
	 * strncpy + strchr(buffer, '\0') is fragile and unnecessary here.      */
	cp = buffer;
	memcpy(cp, sha256_salt_prefix, sizeof(sha256_salt_prefix) - 1);
	cp     += sizeof(sha256_salt_prefix) - 1;
	buflen -= sizeof(sha256_salt_prefix) - 1;

	if (rounds_custom)
	{
		int n = snprintf(cp, buflen, "%s%zu$", sha256_rounds_prefix, rounds);
		cp     += n;
		buflen -= (size_t)n;
	}

	memcpy(cp, salt, salt_len);
	cp     += salt_len;
	buflen -= salt_len;

	if (buflen > 0)
	{
		*cp++ = '$';
		--buflen;
	}

	b64_from_24bit(alt_result[ 0], alt_result[10], alt_result[20], 4);
	b64_from_24bit(alt_result[21], alt_result[ 1], alt_result[11], 4);
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[ 2], 4);
	b64_from_24bit(alt_result[ 3], alt_result[13], alt_result[23], 4);
	b64_from_24bit(alt_result[24], alt_result[ 4], alt_result[14], 4);
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[ 5], 4);
	b64_from_24bit(alt_result[ 6], alt_result[16], alt_result[26], 4);
	b64_from_24bit(alt_result[27], alt_result[ 7], alt_result[17], 4);
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[ 8], 4);
	b64_from_24bit(alt_result[ 9], alt_result[19], alt_result[29], 4);
	b64_from_24bit(             0, alt_result[31], alt_result[30], 3);

	if (buflen == 0)
	{
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';

	/* Wipe intermediate state.  secure_zero() is not eliminated by the
	 * optimiser as a dead store when these variables go out of scope.   */
	secure_zero(alt_result,  sizeof(alt_result));
	secure_zero(temp_result, sizeof(temp_result));
	secure_zero(p_bytes, key_len);
	op_free(p_bytes);
	p_bytes = NULL;
	secure_zero(s_bytes, salt_len);
	secure_zero(&ctx,     sizeof(ctx));
	secure_zero(&alt_ctx, sizeof(alt_ctx));

	return buffer;
}

static char *
op_sha256_crypt(const char *key, const char *salt)
{
	/* _Thread_local: each thread owns its output buffer independently;
	 * concurrent calls from different threads cannot race.              */
	static _Thread_local char   *buffer = NULL;
	static _Thread_local size_t  buflen = 0;

	size_t needed = (sizeof(sha256_salt_prefix) - 1
		      + sizeof(sha256_rounds_prefix) + 9 + 1
		      + strlen(salt) + 1 + 43 + 1);

	/* Use a growable static buffer so callers never need to free the
	 * returned pointer. op_realloc dies on OOM; no NULL check needed. */
	if (buflen < needed)
	{
		buffer = op_realloc(buffer, needed);
		buflen = needed;
	}

	return op_sha256_crypt_r(key, salt, buffer, buflen);
}

/* -------------------------------------------------------------------------
 * SHA-512 crypt ($6$)
 * Derived from Ulrich Drepper's public domain implementation.
 * ------------------------------------------------------------------------- */

struct sha512_ctx
{
	uint64_t H[8];
	uint64_t total[2];
	uint64_t buflen;
	char buffer[256];	/* always correctly aligned for uint64_t */
};

#ifndef WORDS_BIGENDIAN
#	define SHA512_SWAP(n)			\
		(((n) << 56)			\
		| (((n) & 0xff00) << 40)	\
		| (((n) & 0xff0000) << 24)	\
		| (((n) & 0xff000000) << 8)	\
		| (((n) >> 8) & 0xff000000)	\
		| (((n) >> 24) & 0xff0000)	\
		| (((n) >> 40) & 0xff00)	\
		| ((n) >> 56))
#else
#	define SHA512_SWAP(n) (n)
#endif

static const unsigned char SHA512_fillbuf[128] = { 0x80, 0 };

static const uint64_t SHA512_K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 128 == 0.  */
static void
op_sha512_process_block(const void *buffer, size_t len, struct sha512_ctx *ctx)
{
	const uint64_t *words = buffer;
	size_t nwords = len / sizeof(uint64_t);
	uint64_t a = ctx->H[0];
	uint64_t b = ctx->H[1];
	uint64_t c = ctx->H[2];
	uint64_t d = ctx->H[3];
	uint64_t e = ctx->H[4];
	uint64_t f = ctx->H[5];
	uint64_t g = ctx->H[6];
	uint64_t h = ctx->H[7];

	ctx->total[0] += len;
	if (ctx->total[0] < len)
		++ctx->total[1];

#define SHA512_CYCLIC(w, s) ((w >> s) | (w << (64 - s)))
#define SHA512_Ch(x, y, z)  ((x & y) ^ (~x & z))
#define SHA512_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_S0(x) (SHA512_CYCLIC(x, 28) ^ SHA512_CYCLIC(x, 34) ^ SHA512_CYCLIC(x, 39))
#define SHA512_S1(x) (SHA512_CYCLIC(x, 14) ^ SHA512_CYCLIC(x, 18) ^ SHA512_CYCLIC(x, 41))
#define SHA512_R0(x) (SHA512_CYCLIC(x,  1) ^ SHA512_CYCLIC(x,  8) ^ (x >> 7))
#define SHA512_R1(x) (SHA512_CYCLIC(x, 19) ^ SHA512_CYCLIC(x, 61) ^ (x >> 6))

	while (nwords > 0)
	{
		uint64_t W[80];
		uint64_t a_save = a, b_save = b, c_save = c, d_save = d;
		uint64_t e_save = e, f_save = f, g_save = g, h_save = h;
		unsigned int t;

		for (t = 0; t < 16; ++t)
		{
			W[t] = SHA512_SWAP(*words);
			++words;
		}
		for (t = 16; t < 80; ++t)
			W[t] = SHA512_R1(W[t - 2]) + W[t - 7] + SHA512_R0(W[t - 15]) + W[t - 16];

		for (t = 0; t < 80; ++t)
		{
			uint64_t T1 = h + SHA512_S1(e) + SHA512_Ch(e, f, g) + SHA512_K[t] + W[t];
			uint64_t T2 = SHA512_S0(a) + SHA512_Maj(a, b, c);
			h = g; g = f; f = e; e = d + T1;
			d = c; c = b; b = a; a = T1 + T2;
		}

		a += a_save; b += b_save; c += c_save; d += d_save;
		e += e_save; f += f_save; g += g_save; h += h_save;

		nwords -= 16;
	}

#undef SHA512_CYCLIC
#undef SHA512_Ch
#undef SHA512_Maj
#undef SHA512_S0
#undef SHA512_S1
#undef SHA512_R0
#undef SHA512_R1

	ctx->H[0] = a; ctx->H[1] = b; ctx->H[2] = c; ctx->H[3] = d;
	ctx->H[4] = e; ctx->H[5] = f; ctx->H[6] = g; ctx->H[7] = h;
}

/* Initialize structure containing state of computation.  (FIPS 180-2:5.3.3) */
static void
op_sha512_init_ctx(struct sha512_ctx *ctx)
{
	ctx->H[0] = 0x6a09e667f3bcc908ULL;
	ctx->H[1] = 0xbb67ae8584caa73bULL;
	ctx->H[2] = 0x3c6ef372fe94f82bULL;
	ctx->H[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->H[4] = 0x510e527fade682d1ULL;
	ctx->H[5] = 0x9b05688c2b3e6c1fULL;
	ctx->H[6] = 0x1f83d9abfb41bd6bULL;
	ctx->H[7] = 0x5be0cd19137e2179ULL;
	ctx->total[0] = ctx->total[1] = 0;
	ctx->buflen = 0;
}

/* Process the remaining bytes and write the result to RESBUF. */
static void *
op_sha512_finish_ctx(struct sha512_ctx *ctx, void *resbuf)
{
	uint64_t bytes = ctx->buflen, *ptr;
	size_t pad;
	unsigned int i;

	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes)
		++ctx->total[1];

	pad = bytes >= 112 ? 128 + 112 - bytes : 112 - bytes;
	memcpy(&ctx->buffer[bytes], SHA512_fillbuf, pad);

	ptr = (uint64_t *)&ctx->buffer[bytes + pad + 8];
	*ptr = SHA512_SWAP(ctx->total[0] << 3);

	ptr = (uint64_t *)&ctx->buffer[bytes + pad];
	*ptr = SHA512_SWAP((ctx->total[1] << 3) | (ctx->total[0] >> 61));

	op_sha512_process_block(ctx->buffer, bytes + pad + 16, ctx);

	for (i = 0; i < 8; ++i)
		((uint64_t *)resbuf)[i] = SHA512_SWAP(ctx->H[i]);

	return resbuf;
}

static void
op_sha512_process_bytes(const void *buffer, size_t len, struct sha512_ctx *ctx)
{
	if (ctx->buflen != 0)
	{
		size_t left_over = ctx->buflen;
		size_t add = 256 - left_over > len ? len : 256 - left_over;

		memcpy(&ctx->buffer[left_over], buffer, add);
		ctx->buflen += add;

		if (ctx->buflen > 128)
		{
			op_sha512_process_block(ctx->buffer, ctx->buflen & ~127, ctx);
			ctx->buflen &= 127;
			memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~127], ctx->buflen);
		}

		buffer = (const char *)buffer + add;
		len -= add;
	}

	if (len >= 128)
	{
#if __GNUC__ >= 2
#	define SHA512_UNALIGNED_P(p) (((uintptr_t)(p)) % __alignof__(uint64_t) != 0)
#else
#	define SHA512_UNALIGNED_P(p) (((uintptr_t)(p)) % sizeof(uint64_t) != 0)
#endif
		if (SHA512_UNALIGNED_P(buffer))
			while (len > 128)
			{
				op_sha512_process_block(memcpy(ctx->buffer, buffer, 128), 128, ctx);
				buffer = (const char *)buffer + 128;
				len -= 128;
			}
		else
		{
			op_sha512_process_block(buffer, len & ~127, ctx);
			buffer = (const char *)buffer + (len & ~127);
			len &= 127;
		}
#undef SHA512_UNALIGNED_P
	}

	if (len > 0)
	{
		size_t left_over = ctx->buflen;

		memcpy(&ctx->buffer[left_over], buffer, len);
		left_over += len;
		if (left_over >= 128)
		{
			op_sha512_process_block(ctx->buffer, 128, ctx);
			left_over -= 128;
			memcpy(ctx->buffer, &ctx->buffer[128], left_over);
		}
		ctx->buflen = left_over;
	}
}

static const char sha512_salt_prefix[] = "$6$";
static const char sha512_rounds_prefix[] = "rounds=";

#define SHA512_SALT_LEN_MAX   16
#define SHA512_ROUNDS_DEFAULT 5000
#define SHA512_ROUNDS_MIN     1000
#define SHA512_ROUNDS_MAX     999999999

static char *
op_sha512_crypt_r(const char *key, const char *salt, char *buffer, size_t buflen)
{
	unsigned char alt_result[64]  __attribute__((__aligned__(__alignof__(uint64_t))));
	unsigned char temp_result[64] __attribute__((__aligned__(__alignof__(uint64_t))));
	struct sha512_ctx ctx;
	struct sha512_ctx alt_ctx;
	size_t salt_len;
	size_t key_len;
	size_t cnt;
	char *cp;
	char *p_bytes = NULL;
	char  s_bytes[SHA512_SALT_LEN_MAX];   /* salt_len <= 16, fits on stack */
	size_t rounds = SHA512_ROUNDS_DEFAULT;
	int rounds_custom = 0;

	if (strncmp(sha512_salt_prefix, salt, sizeof(sha512_salt_prefix) - 1) == 0)
		salt += sizeof(sha512_salt_prefix) - 1;

	if (strncmp(salt, sha512_rounds_prefix, sizeof(sha512_rounds_prefix) - 1) == 0)
	{
		const char *num = salt + sizeof(sha512_rounds_prefix) - 1;
		char *endp;
		unsigned int srounds = (unsigned int)strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			salt = endp + 1;
			rounds = MAX(SHA512_ROUNDS_MIN, MIN(srounds, SHA512_ROUNDS_MAX));
			rounds_custom = 1;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SHA512_SALT_LEN_MAX);
	key_len = strlen(key);

	/* op_sha512_process_bytes handles misaligned buffers internally. */

	/* Prepare for the real work.  */
	op_sha512_init_ctx(&ctx);
	op_sha512_process_bytes(key, key_len, &ctx);
	op_sha512_process_bytes(salt, salt_len, &ctx);

	/* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  */
	op_sha512_init_ctx(&alt_ctx);
	op_sha512_process_bytes(key, key_len, &alt_ctx);
	op_sha512_process_bytes(salt, salt_len, &alt_ctx);
	op_sha512_process_bytes(key, key_len, &alt_ctx);
	op_sha512_finish_ctx(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum.  */
	for (cnt = key_len; cnt > 64; cnt -= 64)
		op_sha512_process_bytes(alt_result, 64, &ctx);
	op_sha512_process_bytes(alt_result, cnt, &ctx);

	/* For every 1 in binary length add alternate sum, for every 0 add key.  */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			op_sha512_process_bytes(alt_result, 64, &ctx);
		else
			op_sha512_process_bytes(key, key_len, &ctx);

	op_sha512_finish_ctx(&ctx, alt_result);

	/* Compute P byte sequence.  */
	op_sha512_init_ctx(&alt_ctx);
	for (cnt = 0; cnt < key_len; ++cnt)
		op_sha512_process_bytes(key, key_len, &alt_ctx);
	op_sha512_finish_ctx(&alt_ctx, temp_result);

	p_bytes = op_malloc(key_len);
	cp = p_bytes;
	for (cnt = key_len; cnt >= 64; cnt -= 64)
	{
		memcpy(cp, temp_result, 64);
		cp += 64;
	}
	memcpy(cp, temp_result, cnt);

	/* Compute S byte sequence.  */
	op_sha512_init_ctx(&alt_ctx);
	for (cnt = 0; cnt < (size_t)(16 + alt_result[0]); ++cnt)
		op_sha512_process_bytes(salt, salt_len, &alt_ctx);
	op_sha512_finish_ctx(&alt_ctx, temp_result);

	/* salt_len <= SHA512_SALT_LEN_MAX (16) < 64 so the pattern loop never
	 * executes; a single memcpy into the fixed s_bytes stack buffer suffices. */
	memcpy(s_bytes, temp_result, salt_len);

	/* Repeatedly run the collected hash value through SHA512.  */
	for (cnt = 0; cnt < rounds; ++cnt)
	{
		op_sha512_init_ctx(&ctx);

		if ((cnt & 1) != 0)
			op_sha512_process_bytes(p_bytes, key_len, &ctx);
		else
			op_sha512_process_bytes(alt_result, 64, &ctx);

		if (cnt % 3 != 0)
			op_sha512_process_bytes(s_bytes, salt_len, &ctx);

		if (cnt % 7 != 0)
			op_sha512_process_bytes(p_bytes, key_len, &ctx);

		if ((cnt & 1) != 0)
			op_sha512_process_bytes(alt_result, 64, &ctx);
		else
			op_sha512_process_bytes(p_bytes, key_len, &ctx);

		op_sha512_finish_ctx(&ctx, alt_result);
	}

	/* Construct the result string.  */
	cp = buffer;
	memcpy(cp, sha512_salt_prefix, sizeof(sha512_salt_prefix) - 1);
	cp     += sizeof(sha512_salt_prefix) - 1;
	buflen -= sizeof(sha512_salt_prefix) - 1;

	if (rounds_custom)
	{
		int n = snprintf(cp, buflen, "%s%zu$", sha512_rounds_prefix, rounds);
		cp     += n;
		buflen -= (size_t)n;
	}

	memcpy(cp, salt, salt_len);
	cp     += salt_len;
	buflen -= salt_len;

	if (buflen > 0)
	{
		*cp++ = '$';
		--buflen;
	}

	b64_from_24bit(alt_result[ 0], alt_result[21], alt_result[42], 4);
	b64_from_24bit(alt_result[22], alt_result[43], alt_result[ 1], 4);
	b64_from_24bit(alt_result[44], alt_result[ 2], alt_result[23], 4);
	b64_from_24bit(alt_result[ 3], alt_result[24], alt_result[45], 4);
	b64_from_24bit(alt_result[25], alt_result[46], alt_result[ 4], 4);
	b64_from_24bit(alt_result[47], alt_result[ 5], alt_result[26], 4);
	b64_from_24bit(alt_result[ 6], alt_result[27], alt_result[48], 4);
	b64_from_24bit(alt_result[28], alt_result[49], alt_result[ 7], 4);
	b64_from_24bit(alt_result[50], alt_result[ 8], alt_result[29], 4);
	b64_from_24bit(alt_result[ 9], alt_result[30], alt_result[51], 4);
	b64_from_24bit(alt_result[31], alt_result[52], alt_result[10], 4);
	b64_from_24bit(alt_result[53], alt_result[11], alt_result[32], 4);
	b64_from_24bit(alt_result[12], alt_result[33], alt_result[54], 4);
	b64_from_24bit(alt_result[34], alt_result[55], alt_result[13], 4);
	b64_from_24bit(alt_result[56], alt_result[14], alt_result[35], 4);
	b64_from_24bit(alt_result[15], alt_result[36], alt_result[57], 4);
	b64_from_24bit(alt_result[37], alt_result[58], alt_result[16], 4);
	b64_from_24bit(alt_result[59], alt_result[17], alt_result[38], 4);
	b64_from_24bit(alt_result[18], alt_result[39], alt_result[60], 4);
	b64_from_24bit(alt_result[40], alt_result[61], alt_result[19], 4);
	b64_from_24bit(alt_result[62], alt_result[20], alt_result[41], 4);
	b64_from_24bit(             0,              0, alt_result[63], 2);

	if (buflen == 0)
	{
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';

	/* Wipe intermediate state. */
	secure_zero(alt_result,  sizeof(alt_result));
	secure_zero(temp_result, sizeof(temp_result));
	secure_zero(p_bytes, key_len);
	op_free(p_bytes);
	p_bytes = NULL;
	secure_zero(s_bytes, salt_len);
	secure_zero(&ctx,     sizeof(ctx));
	secure_zero(&alt_ctx, sizeof(alt_ctx));

	return buffer;
}

static char *
op_sha512_crypt(const char *key, const char *salt)
{
	static _Thread_local char   *buffer = NULL;
	static _Thread_local size_t  buflen = 0;
	size_t needed = (sizeof(sha512_salt_prefix) - 1
		      + sizeof(sha512_rounds_prefix) + 9 + 1
		      + strlen(salt) + 1 + 86 + 1);

	/* op_realloc dies on OOM; no NULL check needed. */
	if (buflen < needed)
	{
		buffer = op_realloc(buffer, needed);
		buflen = needed;
	}

	return op_sha512_crypt_r(key, salt, buffer, buflen);
}
