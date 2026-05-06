/*
 * libop: ophion support library.
 * op_str_intern.h: Reference-counted string interning table.
 *
 * Overview
 * ========
 * String interning deduplicates identical strings so that each unique value
 * is stored exactly once in the table.  Every call to op_str_intern_get()
 * returns the same stable pointer for the same string value:
 *
 *   const char *h1 = op_str_intern_get(tbl, "irc.example.org");
 *   const char *h2 = op_str_intern_get(tbl, "irc.example.org");
 *   assert(h1 == h2);   // pointer equality, not just strcmp equality
 *
 * This is extremely useful in an IRC server where thousands of clients share
 * a small set of hostnames, server names, and channel names:
 *
 *   - Memory: 5 000 clients on the same /24 → one copy of their hostname.
 *   - Comparison: pointer equality instead of strcmp (O(1) vs O(n)).
 *   - Cache locality: frequently-used strings stay hot.
 *
 * Reference counting
 * ==================
 * Each op_str_intern_get() call increments the entry's reference count.
 * The caller must call op_str_intern_put() exactly once when it is done
 * with the pointer.  When the count drops to zero the string is removed
 * from the table and freed.
 *
 *   client->hostname = op_str_intern_get(g_intern, resolve_hostname(c));
 *   ...
 *   op_str_intern_put(g_intern, client->hostname);
 *   client->hostname = NULL;
 *
 * Pointer stability
 * =================
 * The returned char * is valid until the last op_str_intern_put() for that
 * string is called.  The table may grow (rehash) without invalidating live
 * interned pointers because pointers point into individually heap-allocated
 * entry structs, not into the hash table's internal slot array.
 *
 * Case sensitivity
 * ================
 * Pass icase = true to get IRC-semantics case-insensitive interning
 * (A-Z ≡ a-z plus [ \ ] { | } ~ ^ per RFC 1459).  All lookups and equality
 * checks use the same case folding, so "Nick" and "nick" share one entry.
 * The stored string preserves the case of the first insertion.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_str_intern.h directly; include op_lib.h"
#endif

#ifndef LIBOP_STR_INTERN_H
#define LIBOP_STR_INTERN_H

/* ---- opaque handle ------------------------------------------------------- */

typedef struct op_str_intern op_str_intern_t;

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_str_intern_create — create an interning table.
 *
 * name:  diagnostic label shown in stats output.
 * icase: true for IRC case-insensitive comparison; false for exact-case.
 * hint:  expected number of unique strings (0 = small default).
 *        Used to size the initial hash table; the table grows automatically.
 *
 * Never returns NULL; aborts on OOM.
 */
op_str_intern_t *op_str_intern_create(const char *name, bool icase, size_t hint);

/*
 * op_str_intern_destroy — destroy the table.
 *
 * All remaining entries are freed regardless of their reference count.
 * Any pointers previously returned by op_str_intern_get() become invalid.
 *
 * Call this only when no interned pointers are still in use (e.g., at
 * shutdown after all clients and channels have been freed).
 */
void op_str_intern_destroy(op_str_intern_t *tbl);

/* ---- lookup / intern ----------------------------------------------------- */

/*
 * op_str_intern_get — intern a NUL-terminated string.
 *
 * If s is already in the table, increments its reference count and returns
 * the existing stable pointer.
 *
 * If s is new, allocates a copy, inserts it with refcount = 1, and returns
 * a pointer to the copy.
 *
 * Never returns NULL; aborts on OOM.
 */
const char *op_str_intern_get(op_str_intern_t *tbl, const char *s);

/*
 * op_str_intern_getn — intern the first len bytes of s (s need not be
 * NUL-terminated).
 *
 * Equivalent to NUL-terminating s[0..len-1] and calling op_str_intern_get().
 */
const char *op_str_intern_getn(op_str_intern_t *tbl, const char *s, size_t len);

/*
 * op_str_intern_put — release one reference to an interned string.
 *
 * s must be a pointer previously returned by op_str_intern_get() on this
 * table.  When the reference count reaches zero the string is removed from
 * the table and freed; s must not be used after this call.
 *
 * Calling op_str_intern_put() on an unknown pointer is a programming error
 * and is silently ignored (logged in debug builds).
 */
void op_str_intern_put(op_str_intern_t *tbl, const char *s);

/*
 * op_str_intern_peek — look up s without incrementing the reference count.
 *
 * Returns the interned pointer if present, NULL otherwise.  The returned
 * pointer must not be stored — the string could be freed at any point if
 * the reference count drops to zero from another code path.
 *
 * Useful only for existence checks ("is this hostname already interned?")
 * when the caller holds at least one existing reference to it.
 */
const char *op_str_intern_peek(const op_str_intern_t *tbl, const char *s);

/* ---- introspection ------------------------------------------------------- */

/* Number of unique strings currently in the table. */
size_t op_str_intern_count(const op_str_intern_t *tbl);

/*
 * Total bytes occupied by interned string data (not counting struct overhead
 * or the hash table itself).  Useful for capacity-planning diagnostics.
 */
size_t op_str_intern_bytes(const op_str_intern_t *tbl);

/* Diagnostic name passed to op_str_intern_create(). */
const char *op_str_intern_name(const op_str_intern_t *tbl);

/*
 * op_str_intern_stats — write a one-line diagnostic to buf.
 *
 *   "intern[hostnames]: 1234 strings, 45678 bytes, 5.3 avg refcount"
 *
 * Returns the number of bytes written (excluding the NUL terminator).
 */
int op_str_intern_stats(const op_str_intern_t *tbl, char *buf, size_t bufsz);

#endif /* LIBOP_STR_INTERN_H */
