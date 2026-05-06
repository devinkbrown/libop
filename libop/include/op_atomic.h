/*
 * libop/include/op_atomic.h — portable C11 atomics wrapper.
 *
 * On GCC, Clang, and Clang-CL: includes <stdatomic.h> directly.
 *
 * On MSVC (cl.exe) without the Clang frontend, <stdatomic.h> is only
 * available in VS 2022 17.5+ (/std:c17).  For earlier toolchains this
 * header provides a minimal shim backed by Windows Interlocked intrinsics.
 *
 * Only the types and operations actually used in Ophion are covered:
 *   Types:   atomic_int, atomic_uint_fast64_t, atomic_size_t,
 *            atomic_uint_fast32_t, atomic_uint64_t, atomic_uint32_t
 *   Ops:     atomic_load / atomic_load_explicit
 *            atomic_store / atomic_store_explicit
 *            atomic_fetch_add / atomic_fetch_add_explicit
 *            atomic_fetch_sub / atomic_fetch_sub_explicit
 *            atomic_thread_fence
 *            atomic_compare_exchange_strong / _weak
 *   Macro:   _Atomic(T)  — type-specifier with parens form
 *            ATOMIC_VAR_INIT
 *
 * Note: the _Atomic T (qualifier form, no parens) is NOT macro-replaceable
 * on MSVC.  All declarations in Ophion use the atomic_T typedef names
 * (e.g. atomic_int) when targeting MSVC.
 */

#ifndef OP_ATOMIC_H
#define OP_ATOMIC_H

#if !defined(_MSC_VER) || defined(__clang__)

/* =========================================================================
 * GCC / Clang / Clang-CL: use the real stdatomic.h
 * ====================================================================== */
# include <stdatomic.h>

#else /* _MSC_VER && !__clang__ */

/* =========================================================================
 * MSVC (cl.exe) shim using Windows Interlocked intrinsics
 * ====================================================================== */

# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <intrin.h>
# include <stdint.h>

/* -------------------------------------------------------------------------
 * Memory order enum
 * On x86/x64 the hardware provides strong ordering; we emit a compiler
 * fence for acquire/release and a full MemoryBarrier() for seq_cst.
 * ---------------------------------------------------------------------- */

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

/* -------------------------------------------------------------------------
 * _Atomic(T) — type-specifier with parens (e.g. _Atomic(size_t) head)
 * Expands to volatile T.  On x86/x64 volatile reads/writes are
 * sequentially consistent at the hardware level; the compiler fence
 * prevents compile-time reordering.
 * ---------------------------------------------------------------------- */

# define _Atomic(T)  volatile T

/* -------------------------------------------------------------------------
 * Standard atomic type aliases (matching <stdatomic.h> names)
 * ---------------------------------------------------------------------- */

typedef volatile int                 atomic_int;
typedef volatile unsigned int        atomic_uint;
typedef volatile long                atomic_long;
typedef volatile unsigned long       atomic_ulong;
typedef volatile long long           atomic_llong;
typedef volatile unsigned long long  atomic_ullong;

/* Fast/least width types used in Ophion */
typedef volatile int32_t             atomic_int_fast32_t;
typedef volatile uint32_t            atomic_uint_fast32_t;
typedef volatile int64_t             atomic_int_fast64_t;
typedef volatile uint64_t            atomic_uint_fast64_t;
typedef volatile int32_t             atomic_int_least32_t;
typedef volatile uint32_t            atomic_uint_least32_t;
typedef volatile int64_t             atomic_int_least64_t;
typedef volatile uint64_t            atomic_uint_least64_t;
typedef volatile int64_t             atomic_intmax_t;
typedef volatile uint64_t            atomic_uintmax_t;

/* Pointer-width types */
typedef volatile size_t              atomic_size_t;
typedef volatile ptrdiff_t           atomic_ptrdiff_t;

/* Boolean */
typedef volatile int                 atomic_bool;
# define ATOMIC_BOOL_LOCK_FREE  2

/* Convenient aliases for 32 and 64 bit */
typedef volatile uint32_t            atomic_uint32_t;
typedef volatile uint64_t            atomic_uint64_t;
typedef volatile int32_t             atomic_int32_t;
typedef volatile int64_t             atomic_int64_t;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

# define ATOMIC_VAR_INIT(v)  (v)

/* -------------------------------------------------------------------------
 * Load
 *
 * On x86/x64, plain volatile reads have acquire semantics at the hardware
 * level.  _ReadBarrier() prevents compiler reordering.
 * ---------------------------------------------------------------------- */

static __forceinline void _op_compiler_barrier(void) { _ReadWriteBarrier(); }

# define atomic_load(obj)                 \
    ((_op_compiler_barrier()), (*(obj)))
# define atomic_load_explicit(obj, order) \
    ((_op_compiler_barrier()), (*(obj)))

/* -------------------------------------------------------------------------
 * Store
 *
 * On x86/x64, volatile stores have release semantics at the hardware level.
 * _WriteBarrier() prevents compiler reordering.  For seq_cst we also emit
 * a full MemoryBarrier() after the store.
 * ---------------------------------------------------------------------- */

# define atomic_store(obj, val) \
    do { _ReadWriteBarrier(); *(obj) = (val); MemoryBarrier(); } while (0)
# define atomic_store_explicit(obj, val, order) \
    do { _ReadWriteBarrier(); *(obj) = (val); \
         if ((order) == memory_order_seq_cst) MemoryBarrier(); \
         else _ReadWriteBarrier(); } while (0)

/* -------------------------------------------------------------------------
 * atomic_fetch_add / atomic_fetch_sub
 *
 * Returns the value BEFORE the addition (same as C11 semantics).
 * Dispatches on pointer type via _Generic (available in VS 2015+).
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_fetch_add_32(volatile long *p, long v)
{
    return InterlockedAdd(p, v) - v;
}

static __forceinline long long
_op_fetch_add_64(volatile long long *p, long long v)
{
    return InterlockedAdd64(p, v) - v;
}

/* For unsigned types we alias through a signed pointer cast — safe on x86. */

# define atomic_fetch_add(obj, val)                            \
    _Generic((obj),                                            \
        volatile int *:               _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile long *:              _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile unsigned int *:      _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile unsigned long *:     _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile long long *:         _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile unsigned long long *:_op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile int64_t *:           _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile uint64_t *:          _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)) \
    )

# define atomic_fetch_add_explicit(obj, val, order) \
    atomic_fetch_add((obj), (val))

# define atomic_fetch_sub(obj, val) \
    atomic_fetch_add((obj), (0 - (val)))
# define atomic_fetch_sub_explicit(obj, val, order) \
    atomic_fetch_sub((obj), (val))

/* -------------------------------------------------------------------------
 * atomic_fetch_or / atomic_fetch_and
 *
 * Returns the value BEFORE the operation (same as C11 semantics).
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_fetch_or_32(volatile long *p, long v)
{
    return InterlockedOr(p, v);
}

static __forceinline long long
_op_fetch_or_64(volatile long long *p, long long v)
{
    return InterlockedOr64(p, v);
}

static __forceinline long
_op_fetch_and_32(volatile long *p, long v)
{
    return InterlockedAnd(p, v);
}

static __forceinline long long
_op_fetch_and_64(volatile long long *p, long long v)
{
    return InterlockedAnd64(p, v);
}

# define atomic_fetch_or(obj, val)                                 \
    _Generic((obj),                                                \
        volatile int *:               _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile uint64_t *:          _op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_fetch_or_explicit(obj, val, order) \
    atomic_fetch_or((obj), (val))

# define atomic_fetch_and(obj, val)                                \
    _Generic((obj),                                                \
        volatile int *:               _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile uint64_t *:          _op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_fetch_and_explicit(obj, val, order) \
    atomic_fetch_and((obj), (val))

/* -------------------------------------------------------------------------
 * atomic_compare_exchange_strong / _weak
 *
 * Returns 1 on success, 0 on failure (updates *expected on failure).
 * ---------------------------------------------------------------------- */

static __forceinline int
_op_cas_32(volatile long *p, long *expected, long desired)
{
    long old = InterlockedCompareExchange(p, desired, *expected);
    if (old == *expected)
        return 1;
    *expected = old;
    return 0;
}

static __forceinline int
_op_cas_64(volatile long long *p, long long *expected, long long desired)
{
    long long old = InterlockedCompareExchange64(p, desired, *expected);
    if (old == *expected)
        return 1;
    *expected = old;
    return 0;
}

# define atomic_compare_exchange_strong(obj, expected, desired) \
    _Generic((obj),                                              \
        volatile int *:                _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile long *:               _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile unsigned int *:       _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile long long *:          _op_cas_64(              \
                (volatile long long *)(obj),                    \
                (long long *)(expected), (long long)(desired)), \
        volatile unsigned long long *: _op_cas_64(              \
                (volatile long long *)(obj),                    \
                (long long *)(expected), (long long)(desired))  \
    )

# define atomic_compare_exchange_strong_explicit(obj, exp, des, succ, fail) \
    atomic_compare_exchange_strong((obj), (exp), (des))
# define atomic_compare_exchange_weak                  atomic_compare_exchange_strong
# define atomic_compare_exchange_weak_explicit         atomic_compare_exchange_strong_explicit

/* -------------------------------------------------------------------------
 * atomic_exchange
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_exchange_32(volatile long *p, long val)
{
    return InterlockedExchange(p, val);
}

static __forceinline long long
_op_exchange_64(volatile long long *p, long long val)
{
    return InterlockedExchange64(p, val);
}

# define atomic_exchange(obj, val)                                 \
    _Generic((obj),                                                \
        volatile int *:               _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_exchange_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_exchange_64(             \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_exchange_explicit(obj, val, order) \
    atomic_exchange((obj), (val))

/* -------------------------------------------------------------------------
 * Fence
 * ---------------------------------------------------------------------- */

# define atomic_thread_fence(order) \
    (((order) == memory_order_relaxed) ? _ReadWriteBarrier() : (void)MemoryBarrier())

# define atomic_signal_fence(order)  _ReadWriteBarrier()

/* -------------------------------------------------------------------------
 * Lock-free query (everything above is lock-free on x86/x64)
 * ---------------------------------------------------------------------- */

# define ATOMIC_INT_LOCK_FREE    2
# define ATOMIC_LONG_LOCK_FREE   2
# define ATOMIC_LLONG_LOCK_FREE  2
# define ATOMIC_POINTER_LOCK_FREE 2

#endif /* _MSC_VER && !__clang__ */

#endif /* OP_ATOMIC_H */
