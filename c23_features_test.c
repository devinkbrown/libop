/* C23 Features Test for Cryptographic Library
 * Testing compiler support and practical usage patterns
 */

// Feature detection
#if __STDC_VERSION__ >= 202311L
    #define C23_AVAILABLE 1
    #if __has_include(<stdckdint.h>)
        #include <stdckdint.h>
        #define HAS_CHECKED_ARITHMETIC 1
    #endif
#else
    #define C23_AVAILABLE 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef C23_AVAILABLE
    // C23 includes
    #include <stdbit.h>
    #include <stdatomic.h>
#endif

// Test 1: typeof and typeof_unqual for generic crypto macros
#ifdef C23_AVAILABLE
    #define SECURE_ZERO(ptr, size) do { \
        typeof(ptr) _ptr = (ptr); \
        memset_explicit(_ptr, 0, (size)); \
    } while(0)

    #define CRYPTO_SWAP(a, b) do { \
        typeof_unqual(a) _temp = (a); \
        (a) = (b); \
        (b) = _temp; \
    } while(0)
#else
    // Fallback for pre-C23
    #define SECURE_ZERO(ptr, size) do { \
        volatile char *_ptr = (volatile char *)(ptr); \
        for (size_t _i = 0; _i < (size); _i++) { \
            _ptr[_i] = 0; \
        } \
    } while(0)
#endif

// Test 2: _BitInt(N) for bignum operations
#ifdef C23_AVAILABLE
    typedef _BitInt(128) int128_t;
    typedef unsigned _BitInt(128) uint128_t;
    typedef _BitInt(256) int256_t;
    typedef unsigned _BitInt(256) uint256_t;
    typedef _BitInt(512) int512_t;
    typedef unsigned _BitInt(512) uint512_t;

    // Crypto operation example
    uint256_t bignum_add_256(uint256_t a, uint256_t b) {
        return a + b;  // Hardware-accelerated on supported platforms
    }
#endif

// Test 3: nullptr and nullptr_t
#ifdef C23_AVAILABLE
    #include <stddef.h>

    int crypto_init(void *ctx) {
        if (ctx == nullptr) {
            return -1;
        }
        return 0;
    }
#endif

// Test 4: constexpr for compile-time constants
#ifdef C23_AVAILABLE
    // AES S-box as constexpr
    constexpr unsigned char aes_sbox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        // ... truncated for brevity
    };

    // Round constants
    constexpr uint32_t rcon[10] = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1B000000, 0x36000000
    };
#endif

// Test 5: [[nodiscard]] attribute for crypto functions
#ifdef C23_AVAILABLE
    [[nodiscard]] int crypto_hash_init(void *ctx);
    [[nodiscard]] int crypto_encrypt(void *ctx, const void *plain, void *cipher);
    [[nodiscard]] int crypto_verify_signature(const void *sig, const void *data);
#endif

// Test 6: memset_explicit for secure memory clearing
void secure_memzero(void *ptr, size_t len) {
#ifdef C23_AVAILABLE
    memset_explicit(ptr, 0, len);
#else
    // Fallback: volatile to prevent optimization
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
#endif
}

// Test 7: unreachable() for exhaustive switches
#ifdef C23_AVAILABLE
    enum crypto_algorithm {
        CRYPTO_AES_128,
        CRYPTO_AES_256,
        CRYPTO_CHACHA20
    };

    int get_key_size(enum crypto_algorithm alg) {
        switch (alg) {
            case CRYPTO_AES_128:
                return 16;
            case CRYPTO_AES_256:
                return 32;
            case CRYPTO_CHACHA20:
                return 32;
        }
        unreachable();  // Tells compiler this is impossible
    }
#endif

// Test 8: Checked integer arithmetic
#ifdef HAS_CHECKED_ARITHMETIC
    int safe_buffer_alloc(size_t count, size_t size, void **result) {
        size_t total;
        if (ckd_mul(&total, count, size)) {
            return -1;  // Overflow detected
        }

        *result = malloc(total);
        return *result ? 0 : -1;
    }
#endif

// Test 9: alignas/alignof as keywords
#ifdef C23_AVAILABLE
    struct crypto_context {
        alignas(64) unsigned char state[64];  // Cache line aligned
        alignas(32) unsigned char key[32];    // AVX aligned
    };

    _Static_assert(alignof(struct crypto_context) >= 64);
#endif

// Test 10: Thread-local storage
#ifdef C23_AVAILABLE
    thread_local struct {
        unsigned char random_pool[1024];
        size_t pool_index;
    } tls_entropy;
#endif

// Test 11: Attributes
#ifdef C23_AVAILABLE
    [[deprecated("Use crypto_new_api instead")]]
    int crypto_legacy_function(void);

    [[maybe_unused]] static void debug_print_hex(const void *data, size_t len) {
        // Only used in debug builds
    }

    [[noreturn]] void crypto_fatal_error(const char *msg) {
        fprintf(stderr, "FATAL: %s\n", msg);
        abort();
    }

    // Optimization hints for pure crypto functions
    [[reproducible]] uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    [[unsequenced]] uint64_t bswap64(uint64_t x) {
        return __builtin_bswap64(x);
    }
#endif

// Test 12: Binary literals and digit separators
#ifdef C23_AVAILABLE
    constexpr uint64_t crypto_magic = 0b1010'1100'0011'0101'1111'0000'1010'1010'1100'0011'0101'1111'0000'1010'1010'1100;
    constexpr size_t large_prime = 1'000'000'007;
    constexpr uint32_t aes_const = 0x1B'00'00'00;
#endif

// Test 13: Enhanced enums
#ifdef C23_AVAILABLE
    enum crypto_result : int {
        CRYPTO_SUCCESS = 0,
        CRYPTO_ERROR_INVALID_PARAM = -1,
        CRYPTO_ERROR_BUFFER_TOO_SMALL = -2,
        CRYPTO_ERROR_VERIFICATION_FAILED = -3
    };
#endif

// Test 14: __int128 status check
void test_int128_support(void) {
    printf("Testing __int128 support:\n");

#ifdef __SIZEOF_INT128__
    printf("  __int128 available (size: %d bytes)\n", (int)sizeof(__int128));
    __int128 large_val = (__int128)1 << 100;
    printf("  2^100 = %lld (low 64 bits)\n", (long long)(uint64_t)large_val);
#else
    printf("  __int128 not available\n");
#endif

#ifdef C23_AVAILABLE
    #ifdef _BitInt_MAXWIDTH
        printf("  _BitInt max width: %d\n", _BitInt_MAXWIDTH);
    #endif
#endif
}

int main(void) {
    printf("C23 Features Test for Cryptographic Library\n");
    printf("==========================================\n\n");

    printf("C standard version: %ld\n", __STDC_VERSION__);

#ifdef C23_AVAILABLE
    printf("C23 features: AVAILABLE\n\n");
#else
    printf("C23 features: NOT AVAILABLE\n\n");
#endif

    test_int128_support();

    // Test secure memory clearing
    unsigned char sensitive_data[32];
    memset(sensitive_data, 0xFF, sizeof(sensitive_data));
    printf("\nBefore secure clear: %02X%02X%02X%02X\n",
           sensitive_data[0], sensitive_data[1], sensitive_data[2], sensitive_data[3]);

    secure_memzero(sensitive_data, sizeof(sensitive_data));
    printf("After secure clear:  %02X%02X%02X%02X\n",
           sensitive_data[0], sensitive_data[1], sensitive_data[2], sensitive_data[3]);

#ifdef HAS_CHECKED_ARITHMETIC
    printf("\nChecked arithmetic: AVAILABLE\n");
    void *test_ptr;
    if (safe_buffer_alloc(1000, 1000, &test_ptr) == 0) {
        printf("Safe allocation succeeded\n");
        free(test_ptr);
    }
#endif

    return 0;
}