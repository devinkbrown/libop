/*
 * libop: ophion support library.
 * op_toml.h: Minimal TOML configuration parser.
 *
 * Supports a practical subset of TOML sufficient for IRC server configuration:
 *   - [table] sections
 *   - [[array_of_tables]] sections (repeatable; each creates a new entry)
 *   - key = "string", key = 42, key = true/false
 *   - key = ["a", "b"] and key = [1, 2, 3]
 *   - # comments
 *
 * NOT supported: multi-line strings, inline tables {}, floats, dates,
 * dotted keys, multi-line arrays (commas between items are fine; the array
 * value itself may span lines, but string/int literals must be single-line).
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef OP_TOML_H
#define OP_TOML_H

#include <stddef.h>

/* ---- opaque types -------------------------------------------------------- */

typedef struct op_toml_table op_toml_table_t;
typedef struct op_toml_arr   op_toml_arr_t;

/* ---- parsing ------------------------------------------------------------- */

/*
 * op_toml_parse_file — parse a TOML file at path.
 *
 * Returns the root table on success, or NULL on error.  On error, a
 * human-readable message (including the line number) is written into errbuf.
 * The caller must free the returned table with op_toml_free().
 */
op_toml_table_t *op_toml_parse_file(const char *path,
                                     char *errbuf, size_t errsz);

/*
 * op_toml_parse — parse TOML from an in-memory buffer of length len.
 *
 * The buffer does not need to be NUL-terminated; the parser uses len as the
 * boundary.  Intended for fuzzing and unit tests.  Same return/error
 * semantics as op_toml_parse_file().
 */
op_toml_table_t *op_toml_parse(const char *buf, size_t len,
                                char *errbuf, size_t errsz);

/*
 * op_toml_free — release all memory associated with a parsed TOML document.
 *
 * Passing NULL is a safe no-op.
 */
void op_toml_free(op_toml_table_t *root);

/* ---- table lookups ------------------------------------------------------- */
/*
 * All lookup functions return:
 *   1  — key found and type matches; *out populated
 *   0  — key not found
 *  -1  — key found but type does not match
 */

int              op_toml_str  (const op_toml_table_t *t, const char *k,
                                const char **out);
int              op_toml_int  (const op_toml_table_t *t, const char *k,
                                long *out);
int              op_toml_bool (const op_toml_table_t *t, const char *k,
                                int *out);

/* Returns the sub-table for key k, or NULL if not found or wrong type. */
op_toml_table_t *op_toml_table(const op_toml_table_t *t, const char *k);

/* Returns the array for key k, or NULL if not found or wrong type. */
op_toml_arr_t   *op_toml_arr  (const op_toml_table_t *t, const char *k);

/* ---- array access -------------------------------------------------------- */

/* Number of elements in the array. */
int              op_toml_arr_len  (const op_toml_arr_t *a);

/*
 * Element accessors — same 1/0/-1 return convention as table lookups.
 * i is zero-based; out-of-range i returns 0.
 */
int              op_toml_arr_str  (const op_toml_arr_t *a, int i,
                                   const char **out);
int              op_toml_arr_int  (const op_toml_arr_t *a, int i,
                                   long *out);

/* Returns the table at index i, or NULL if not a table or out of range. */
op_toml_table_t *op_toml_arr_table(const op_toml_arr_t *a, int i);

/* ---- key iteration ------------------------------------------------------- */

typedef void (*op_toml_iter_fn)(const char *key, void *ud);

/*
 * op_toml_iter — call fn(key, ud) for every key in table t.
 *
 * Iteration order is the insertion order of keys.  Useful for walking
 * unknown sections (e.g. dynamic server blocks) without knowing key names
 * in advance.
 */
void op_toml_iter(const op_toml_table_t *t, op_toml_iter_fn fn, void *ud);

#endif /* OP_TOML_H */
