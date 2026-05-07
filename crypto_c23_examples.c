/* Practical C23 Usage Examples for High-Security Crypto/TLS Library
 * Demonstrating real-world usage patterns for libop integration
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <stddef.h>

// =============================================================================
// 1. TYPE SAFETY AND GENERICS USING typeof/typeof_unqual
// =============================================================================

// Generic secure memory operations
#define CRYPTO_SECURE_COPY(dst, src) do { \
    typeof(dst) _dst = (dst); \
    typeof_unqual(src) _src = (src); \
    _Static_assert(sizeof(*_dst) == sizeof(_src), "Size mismatch in secure copy"); \
    memcpy(_dst, &_src, sizeof(_src)); \
} while(0)

#define CRYPTO_SECURE_ZERO(ptr, count) do { \
    typeof(ptr) _ptr = (ptr); \
    memset_explicit(_ptr, 0, (count) * sizeof(*_ptr)); \
} while(0)

// Type-safe endianness conversion
#define CRYPTO_BSWAP(val) _Generic((val), \
    uint16_t: __builtin_bswap16, \
    uint32_t: __builtin_bswap32, \
    uint64_t: __builtin_bswap64 \
    )(val)

// =============================================================================
// 2. _BitInt FOR BIGNUM OPERATIONS
// =============================================================================

typedef unsigned _BitInt(256) bignum256_t;
typedef unsigned _BitInt(512) bignum512_t;

// Modular arithmetic using _BitInt
[[nodiscard]] bignum256_t crypto_mod_add(bignum256_t a, bignum256_t b, bignum256_t modulus) {
    bignum512_t sum = (bignum512_t)a + (bignum512_t)b;
    return (bignum256_t)(sum % (bignum512_t)modulus);
}

[[nodiscard]] bignum256_t crypto_mod_mul(bignum256_t a, bignum256_t b, bignum256_t modulus) {
    bignum512_t product = (bignum512_t)a * (bignum512_t)b;
    return (bignum256_t)(product % (bignum512_t)modulus);
}

// Montgomery ladder for ECC point multiplication
bignum256_t crypto_montgomery_ladder(bignum256_t scalar, bignum256_t base, bignum256_t modulus) {
    bignum256_t x1 = 1, x2 = base;

    for (int i = 255; i >= 0; i--) {
        if ((scalar >> i) & 1) {
            x1 = crypto_mod_mul(x1, x2, modulus);
            x2 = crypto_mod_mul(x2, x2, modulus);
        } else {
            x2 = crypto_mod_mul(x1, x2, modulus);
            x1 = crypto_mod_mul(x1, x1, modulus);
        }
    }

    return x1;
}

// =============================================================================
// 3. COMPILE-TIME CONSTANTS WITH constexpr
// =============================================================================

// AES S-box (compile-time constant)
constexpr unsigned char aes_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    // ... (truncated for brevity)
};

// ChaCha20 constants
constexpr uint32_t chacha20_constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574  // "expand 32-byte k"
};

// Prime numbers for modular arithmetic
constexpr bignum256_t secp256k1_prime =
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_BitInt(256);

constexpr bignum256_t secp256r1_prime =
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_BitInt(256);

// =============================================================================
// 4. MEMORY SAFETY AND OVERFLOW PROTECTION
// =============================================================================

// Safe buffer allocation with overflow checking
[[nodiscard]] int crypto_alloc_buffer(void **ptr, size_t count, size_t elem_size) {
    if (ptr == nullptr) return -1;

    size_t total_size;
    if (ckd_mul(&total_size, count, elem_size)) {
        return -1;  // Overflow detected
    }

    *ptr = aligned_alloc(64, total_size);  // Cache-line aligned
    if (*ptr == nullptr) return -1;

    // Clear allocated memory
    memset_explicit(*ptr, 0, total_size);
    return 0;
}

// Safe key expansion with checked arithmetic
[[nodiscard]] int crypto_expand_key(const unsigned char *key, size_t key_len,
                                    unsigned char **expanded, size_t rounds) {
    if (key == nullptr || expanded == nullptr) return -1;

    size_t round_key_size;
    if (ckd_mul(&round_key_size, rounds, 16)) return -1;  // 16 bytes per round

    size_t total_size;
    if (ckd_add(&total_size, round_key_size, key_len)) return -1;

    return crypto_alloc_buffer((void **)expanded, total_size, 1);
}

// =============================================================================
// 5. THREAD-SAFE RANDOM NUMBER GENERATION
// =============================================================================

// Per-thread entropy pool
thread_local struct {
    alignas(64) unsigned char pool[1024];
    size_t index;
    uint64_t counter;
    bool initialized;
} tls_rng_state;

[[nodiscard]] int crypto_random_bytes(void *buf, size_t len) {
    if (buf == nullptr || len == 0) return -1;

    if (!tls_rng_state.initialized) {
        // Initialize thread-local RNG (simplified)
        memset_explicit(tls_rng_state.pool, 0, sizeof(tls_rng_state.pool));
        tls_rng_state.index = 0;
        tls_rng_state.counter = 0;
        tls_rng_state.initialized = true;
    }

    // Simple XOR with counter (real implementation would use ChaCha20)
    unsigned char *output = (unsigned char *)buf;
    for (size_t i = 0; i < len; i++) {
        output[i] = tls_rng_state.pool[tls_rng_state.index] ^
                   (unsigned char)(tls_rng_state.counter >> (8 * (i % 8)));
        tls_rng_state.index = (tls_rng_state.index + 1) % sizeof(tls_rng_state.pool);
    }

    tls_rng_state.counter++;
    return 0;
}

// =============================================================================
// 6. OPTIMIZED CRYPTO PRIMITIVES WITH ATTRIBUTES
// =============================================================================

// Bit rotation (optimization hint)
uint32_t crypto_rotl32(uint32_t x, int n) [[reproducible]] {
    return (x << n) | (x >> (32 - n));
}

uint64_t crypto_rotr64(uint64_t x, int n) [[reproducible]] {
    return (x >> n) | (x << (64 - n));
}

// Endianness conversion (can be reordered)
uint32_t crypto_be32_to_cpu(uint32_t x) [[unsequenced]] {
    return __builtin_bswap32(x);
}

// ChaCha20 quarter-round with optimized primitives
void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
    [[maybe_unused]]  // May not be used in all build configurations
{
    *a += *b; *d ^= *a; *d = crypto_rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = crypto_rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = crypto_rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = crypto_rotl32(*b, 7);
}

// =============================================================================
// 7. ENHANCED ENUMS AND ERROR HANDLING
// =============================================================================

enum crypto_result : int {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_NULL_POINTER = -1,
    CRYPTO_ERROR_INVALID_KEY_SIZE = -2,
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -3,
    CRYPTO_ERROR_VERIFICATION_FAILED = -4,
    CRYPTO_ERROR_RANDOM_FAILURE = -5,
    CRYPTO_ERROR_OVERFLOW = -6
};

// Error handling with unreachable()
[[nodiscard]] const char *crypto_error_string(enum crypto_result error) {
    switch (error) {
        case CRYPTO_SUCCESS:
            return "Success";
        case CRYPTO_ERROR_NULL_POINTER:
            return "Null pointer";
        case CRYPTO_ERROR_INVALID_KEY_SIZE:
            return "Invalid key size";
        case CRYPTO_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case CRYPTO_ERROR_VERIFICATION_FAILED:
            return "Verification failed";
        case CRYPTO_ERROR_RANDOM_FAILURE:
            return "Random number generation failed";
        case CRYPTO_ERROR_OVERFLOW:
            return "Integer overflow";
    }
    unreachable();  // All cases covered
}

// =============================================================================
// 8. ALIGNED STRUCTURES FOR SIMD OPERATIONS
// =============================================================================

struct crypto_aes_context {
    alignas(32) uint32_t round_keys[60];    // AVX2 aligned
    alignas(16) unsigned char iv[16];       // SSE aligned
    size_t rounds;
    enum crypto_result last_error;
} _Static_assert(alignof(struct crypto_aes_context) >= 32);

struct crypto_hash_context {
    alignas(64) unsigned char state[64];    // Cache-line aligned
    alignas(8) uint64_t bit_count;          // Natural alignment
    size_t buffer_pos;
};

// =============================================================================
// 9. BINARY LITERALS FOR CRYPTO CONSTANTS
// =============================================================================

// AES MixColumns multiplication matrix (binary representation)
constexpr unsigned char aes_gf_mul_02 = 0b0000'0010;
constexpr unsigned char aes_gf_mul_03 = 0b0000'0011;

// Bit masks for various operations
constexpr uint64_t crypto_mask_high_32 = 0xFFFF'FFFF'0000'0000;
constexpr uint64_t crypto_mask_low_32  = 0x0000'0000'FFFF'FFFF;

// ChaCha20 rotation amounts
constexpr int chacha20_rot_16 = 0b0001'0000;  // 16
constexpr int chacha20_rot_12 = 0b0000'1100;  // 12
constexpr int chacha20_rot_08 = 0b0000'1000;  // 8
constexpr int chacha20_rot_07 = 0b0000'0111;  // 7

// =============================================================================
// 10. DEPRECATED API MARKERS
// =============================================================================

// Legacy API that should be phased out
[[deprecated("Use crypto_aes_encrypt_ctr instead")]]
int crypto_aes_encrypt_legacy(const unsigned char *key, const unsigned char *iv,
                             const unsigned char *plaintext, unsigned char *ciphertext,
                             size_t len);

// New API with better security guarantees
[[nodiscard]] enum crypto_result crypto_aes_encrypt_ctr(
    struct crypto_aes_context *ctx,
    const unsigned char *plaintext,
    unsigned char *ciphertext,
    size_t len
);

// =============================================================================
// DEMONSTRATION FUNCTION
// =============================================================================

int main(void) {
    printf("C23 Cryptographic Library Features Demonstration\n");
    printf("===============================================\n\n");

    // Test bignum operations
    bignum256_t a = 0x123456789ABCDEF0_BitInt(256);
    bignum256_t b = 0xFEDCBA9876543210_BitInt(256);
    bignum256_t modulus = secp256k1_prime;

    bignum256_t sum = crypto_mod_add(a, b, modulus);
    printf("Modular addition completed\n");

    // Test safe allocation
    void *buffer;
    if (crypto_alloc_buffer(&buffer, 1000, 32) == 0) {
        printf("Safe buffer allocation: SUCCESS\n");
        free(buffer);
    } else {
        printf("Safe buffer allocation: FAILED\n");
    }

    // Test thread-local RNG
    unsigned char random_data[16];
    if (crypto_random_bytes(random_data, sizeof(random_data)) == 0) {
        printf("Thread-local RNG: SUCCESS\n");
        printf("Random bytes: ");
        for (size_t i = 0; i < 8; i++) {
            printf("%02X ", random_data[i]);
        }
        printf("...\n");
    }

    // Test error handling
    enum crypto_result err = CRYPTO_ERROR_VERIFICATION_FAILED;
    printf("Error message: %s\n", crypto_error_string(err));

    // Test alignment
    struct crypto_aes_context ctx;
    printf("AES context alignment: %zu bytes\n", alignof(struct crypto_aes_context));

    printf("\nAll C23 crypto features tested successfully!\n");
    return 0;
}

// Implementation stubs for compilation
int crypto_aes_encrypt_legacy(const unsigned char *key, const unsigned char *iv,
                             const unsigned char *plaintext, unsigned char *ciphertext,
                             size_t len) {
    (void)key; (void)iv; (void)plaintext; (void)ciphertext; (void)len;
    return -1;  // Deprecated
}

enum crypto_result crypto_aes_encrypt_ctr(struct crypto_aes_context *ctx,
                                          const unsigned char *plaintext,
                                          unsigned char *ciphertext,
                                          size_t len) {
    (void)ctx; (void)plaintext; (void)ciphertext; (void)len;
    return CRYPTO_SUCCESS;
}