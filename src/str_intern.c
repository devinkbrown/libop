/*
 * libop: ophion support library.
 * str_intern.c: Reference-counted string interning table.
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

#include <string.h>
#include <stdio.h>

/* ---- internal entry type ------------------------------------------------- */

/*
 * Each unique interned string is stored in a heap-allocated intern_entry_t.
 * The flexible array member str[] holds the string data; its address is also
 * used as the hash table key, so the key remains valid for the entire life of
 * the entry.
 */
typedef struct intern_entry
{
    size_t  refcount;   /* number of outstanding op_str_intern_get() calls */
    size_t  len;        /* strlen(str) — cached to avoid repeated strlen()  */
    char    str[];      /* NUL-terminated string data (key into htab)       */
} intern_entry_t;

/* ---- table type ---------------------------------------------------------- */

struct op_str_intern
{
    op_htab    *htab;          /* string keys → intern_entry_t * values     */
    size_t      total_bytes;   /* sum of all entry->len                     */
    size_t      total_refs;    /* sum of all entry->refcount (for stats)    */
    char       *name;          /* diagnostic label                          */
};

/* ---- construction / destruction ------------------------------------------ */

op_str_intern_t *
op_str_intern_create(const char *name, bool icase, size_t hint)
{
    op_str_intern_t *tbl = op_malloc(sizeof(*tbl));
    tbl->htab        = icase ? op_htab_create_istr(name, hint)
                             : op_htab_create_str (name, hint);
    tbl->total_bytes = 0;
    tbl->total_refs  = 0;
    tbl->name        = op_strdup(name);
    return tbl;
}

static void
destroy_entry_cb(void *key, void *val, void *ud)
{
    (void)key;
    (void)ud;
    op_free(val);   /* frees intern_entry_t, which contains str[] */
}

void
op_str_intern_destroy(op_str_intern_t *tbl)
{
    op_htab_destroy(tbl->htab, destroy_entry_cb, NULL);
    op_free(tbl->name);
    op_free(tbl);
}

/* ---- intern helpers ------------------------------------------------------ */

/*
 * intern_insert — allocate a new entry and add it to the table.
 * The caller guarantees the key is NOT already present.
 */
static const char *
intern_insert(op_str_intern_t *tbl, const char *s, size_t len)
{
    intern_entry_t *e = op_malloc(sizeof(*e) + len + 1);
    e->refcount = 1;
    e->len      = len;
    memcpy(e->str, s, len);
    e->str[len] = '\0';

    op_htab_set(tbl->htab, e->str, e, NULL);
    tbl->total_bytes += len;
    tbl->total_refs  += 1;
    return e->str;
}

/* ---- public API ---------------------------------------------------------- */

const char *
op_str_intern_get(op_str_intern_t *tbl, const char *s)
{
    intern_entry_t *e = op_htab_get(tbl->htab, s);
    if (e != NULL)
    {
        e->refcount++;
        tbl->total_refs++;
        return e->str;
    }
    return intern_insert(tbl, s, strlen(s));
}

const char *
op_str_intern_getn(op_str_intern_t *tbl, const char *s, size_t len)
{
    /*
     * We need a NUL-terminated key for the hash table lookup.
     * For short strings (≤ 511 bytes) use a stack buffer.
     * For longer strings fall back to a heap allocation.
     */
    if (len <= 511)
    {
        char tmp[512];
        memcpy(tmp, s, len);
        tmp[len] = '\0';
        return op_str_intern_get(tbl, tmp);
    }

    char *tmp = op_malloc(len + 1);
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    const char *result = op_str_intern_get(tbl, tmp);
    op_free(tmp);
    return result;
}

const char *
op_str_intern_peek(const op_str_intern_t *tbl, const char *s)
{
    intern_entry_t *e = op_htab_get(tbl->htab, s);
    return e ? e->str : NULL;
}

void
op_str_intern_put(op_str_intern_t *tbl, const char *s)
{
    if (s == NULL)
        return;

    intern_entry_t *e = op_htab_get(tbl->htab, s);
    if (e == NULL)
    {
        op_lib_log("op_str_intern_put: unknown pointer %p (table %s) — leaked?",
                   (const void *)s, tbl->name);
        return;
    }

    slop_assert(e->refcount > 0);
    tbl->total_refs--;

    if (--e->refcount == 0)
    {
        tbl->total_bytes -= e->len;
        /*
         * op_htab_del removes the entry by its key.  e->str is the key and
         * is valid until after op_htab_del returns (we haven't freed e yet).
         */
        op_htab_del(tbl->htab, e->str);
        op_free(e);
    }
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_str_intern_count(const op_str_intern_t *tbl)
{
    return op_htab_size(tbl->htab);
}

size_t
op_str_intern_bytes(const op_str_intern_t *tbl)
{
    return tbl->total_bytes;
}

const char *
op_str_intern_name(const op_str_intern_t *tbl)
{
    return tbl->name;
}

int
op_str_intern_stats(const op_str_intern_t *tbl, char *buf, size_t bufsz)
{
    size_t count = op_htab_size(tbl->htab);
    double avg_ref = count > 0 ? (double)tbl->total_refs / (double)count : 0.0;
    return snprintf(buf, bufsz,
                    "intern[%s]: %zu strings, %zu bytes, %.1f avg refcount",
                    tbl->name, count, tbl->total_bytes, avg_ref);
}
