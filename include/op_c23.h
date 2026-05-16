/*
 * libop: ophion support library.
 * op_c23.h: C23 compatibility layer and modern safety primitives.
 *
 * Provides portable wrappers for C23 features with fallbacks for C11/C17.
 * Always included via op_lib.h — do not include directly.
 *
 * Copyright (C) 2026 ophion development team.  GPL v2.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_c23.h directly; include op_lib.h"
#endif

#ifndef LIBOP_C23_H
#define LIBOP_C23_H

/* =========================================================================
 * Standard attributes — portable wrappers
 *
 * Use C23 [[attr]] when available, fall back to GCC/Clang __attribute__.
 * ========================================================================= */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
  /* C23 mode — use standard attributes directly */
  #define OP_NODISCARD        [[nodiscard]]
  #define OP_MAYBE_UNUSED     [[maybe_unused]]
  #define OP_DEPRECATED(msg)  [[deprecated(msg)]]
  #define OP_FALLTHROUGH      [[fallthrough]]
  /* [[noreturn]] has placement constraints in C23; _Noreturn works everywhere */
  #define OP_NORETURN         _Noreturn
#elif defined(__GNUC__)
  #define OP_NODISCARD        __attribute__((warn_unused_result))
  #define OP_MAYBE_UNUSED     __attribute__((unused))
  #define OP_DEPRECATED(msg)  __attribute__((deprecated(msg)))
  #define OP_FALLTHROUGH      __attribute__((fallthrough))
  #define OP_NORETURN         __attribute__((noreturn))
#elif defined(_MSC_VER)
  #define OP_NODISCARD        _Check_return_
  #define OP_MAYBE_UNUSED
  #define OP_DEPRECATED(msg)  __declspec(deprecated(msg))
  #define OP_FALLTHROUGH
  #define OP_NORETURN         __declspec(noreturn)
#else
  #define OP_NODISCARD
  #define OP_MAYBE_UNUSED
  #define OP_DEPRECATED(msg)
  #define OP_FALLTHROUGH
  #define OP_NORETURN
#endif

/* =========================================================================
 * Optimisation and analysis attributes (GCC/Clang only)
 * ========================================================================= */

#ifdef __GNUC__
  #define OP_PURE             __attribute__((pure))
  #define OP_CONST_FN         __attribute__((const))
  #define OP_HOT              __attribute__((hot))
  #define OP_COLD             __attribute__((cold))
  #define OP_RETURNS_NONNULL  __attribute__((returns_nonnull))
  #define OP_MALLOC_LIKE      __attribute__((malloc))
  #define OP_NONNULL(...)     __attribute__((nonnull(__VA_ARGS__)))
  #define OP_PRINTF(fmt, va)  __attribute__((format(printf, fmt, va)))
  #define OP_CLEANUP(fn)      __attribute__((cleanup(fn)))
  #define OP_PACKED           __attribute__((packed))
  #define OP_ALIGNED(n)       __attribute__((aligned(n)))
#else
  #define OP_PURE
  #define OP_CONST_FN
  #define OP_HOT
  #define OP_COLD
  #define OP_RETURNS_NONNULL
  #define OP_MALLOC_LIKE
  #define OP_NONNULL(...)
  #define OP_PRINTF(fmt, va)
  #define OP_CLEANUP(fn)
  #define OP_PACKED
  #define OP_ALIGNED(n)
#endif

/* =========================================================================
 * nullptr compatibility
 * ========================================================================= */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
  /* nullptr is a keyword in C23 */
#elif !defined(nullptr)
  #define nullptr NULL
#endif

/* =========================================================================
 * static_assert — C23 allows no message; C11 requires one
 * ========================================================================= */

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
  #ifndef static_assert
    #define static_assert _Static_assert
  #endif
#endif

/* =========================================================================
 * unreachable() — optimisation hint for impossible code paths
 * ========================================================================= */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
  /* unreachable() is a keyword/builtin in C23 (via <stdlib.h>) */
#elif defined(__GNUC__)
  #define unreachable() __builtin_unreachable()
#elif defined(_MSC_VER)
  #define unreachable() __assume(0)
#else
  #define unreachable() abort()
#endif

/* =========================================================================
 * Checked integer arithmetic — overflow-safe add/sub/mul
 *
 * Returns true on overflow, false on success (matches C23 <stdckdint.h>).
 * ========================================================================= */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L && \
    defined(__has_include) && __has_include(<stdckdint.h>)
  #include <stdckdint.h>
  #define op_ckd_add(res, a, b) ckd_add((res), (a), (b))
  #define op_ckd_sub(res, a, b) ckd_sub((res), (a), (b))
  #define op_ckd_mul(res, a, b) ckd_mul((res), (a), (b))
#elif defined(__GNUC__) && __GNUC__ >= 5
  #define op_ckd_add(res, a, b) __builtin_add_overflow((a), (b), (res))
  #define op_ckd_sub(res, a, b) __builtin_sub_overflow((a), (b), (res))
  #define op_ckd_mul(res, a, b) __builtin_mul_overflow((a), (b), (res))
#else
  /* Fallback: manual check for unsigned size_t only (the common case) */
  static inline bool
  _op_ckd_add_sz(size_t *res, size_t a, size_t b)
  {
    *res = a + b;
    return *res < a;
  }
  static inline bool
  _op_ckd_mul_sz(size_t *res, size_t a, size_t b)
  {
    if (a != 0 && b > SIZE_MAX / a) { *res = 0; return true; }
    *res = a * b;
    return false;
  }
  #define op_ckd_add(res, a, b) _op_ckd_add_sz((res), (a), (b))
  #define op_ckd_sub(res, a, b) ((*(res) = (a) - (b)), ((b) > (a)))
  #define op_ckd_mul(res, a, b) _op_ckd_mul_sz((res), (a), (b))
#endif

/* =========================================================================
 * Secure memory wipe — guaranteed not optimised away
 * ========================================================================= */

static inline void
op_memzero(void *ptr, size_t len)
{
  if (!ptr || len == 0)
    return;
#if defined(__STDC_LIB_EXT1__) || \
    (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L)
  memset_explicit(ptr, 0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero(ptr, len);
#elif defined(__GNUC__)
  memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--)
    *p++ = 0;
#endif
}

#endif /* LIBOP_C23_H */
