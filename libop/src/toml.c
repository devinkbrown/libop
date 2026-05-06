/*
 * libop: ophion support library.
 * toml.c: Minimal TOML configuration parser.
 *
 * Supports a practical subset of TOML sufficient for IRC server configuration:
 *   - [table] sections
 *   - [[array_of_tables]] sections (repeatable; each creates a new entry)
 *   - key = "string", key = 42, key = true/false
 *   - key = ["a", "b"] and key = [1, 2, 3]
 *   - # comments
 *
 * Uses malloc/realloc/free/strdup directly (not op_malloc) so that fuzz
 * targets that #include this file compile standalone without the full
 * libop build tree.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "op_toml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

/* ---- internal value types ------------------------------------------------ */

typedef enum { TV_STR, TV_INT, TV_BOOL, TV_TABLE, TV_ARR } tv_type_t;

typedef struct {
    tv_type_t type;
    union {
        char            *s;
        long             n;
        int              b;
        op_toml_table_t *tab;
        op_toml_arr_t   *arr;
    } u;
} tv_t;

typedef struct { char *key; tv_t val; } kv_t;

struct op_toml_table { kv_t *kv; int n; int cap; };
struct op_toml_arr   { tv_t *items; int n; int cap; };

/* ---- parser state -------------------------------------------------------- */

typedef struct {
    const char      *src;
    const char      *cur;
    const char      *end;
    int              line;
    char            *errbuf;
    size_t           errsz;
    op_toml_table_t *root;
    op_toml_table_t *cur_tab;
} parser_t;

/* ---- forward declarations ------------------------------------------------ */

static int        parse_value(parser_t *p, tv_t *out);
static void       free_tv(tv_t *v);
static void       free_table(op_toml_table_t *t);
static void       free_arr(op_toml_arr_t *a);

/* ---- error helpers ------------------------------------------------------- */

static void
set_err(parser_t *p, const char *msg)
{
    if (p->errbuf && p->errsz > 0)
        snprintf(p->errbuf, p->errsz, "line %d: %s", p->line, msg);
}

static void
set_errf(parser_t *p, const char *fmt, ...)
{
    if (!p->errbuf || p->errsz == 0)
        return;
    /* write "line N: " prefix then the formatted message */
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    snprintf(p->errbuf, p->errsz, "line %d: %s", p->line, tmp);
}

/* ---- memory helpers ------------------------------------------------------ */

static op_toml_table_t *
table_new(void)
{
    op_toml_table_t *t = malloc(sizeof(*t));
    if (!t) return NULL;
    t->kv  = NULL;
    t->n   = 0;
    t->cap = 0;
    return t;
}

static op_toml_arr_t *
arr_new(void)
{
    op_toml_arr_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->items = NULL;
    a->n     = 0;
    a->cap   = 0;
    return a;
}

static int
table_grow(op_toml_table_t *t)
{
    if (t->n < t->cap)
        return 1;
    int newcap = t->cap ? t->cap * 2 : 8;
    kv_t *nkv = realloc(t->kv, (size_t)newcap * sizeof(kv_t));
    if (!nkv) return 0;
    t->kv  = nkv;
    t->cap = newcap;
    return 1;
}

static int
arr_grow(op_toml_arr_t *a)
{
    if (a->n < a->cap)
        return 1;
    int newcap = a->cap ? a->cap * 2 : 8;
    tv_t *ni = realloc(a->items, (size_t)newcap * sizeof(tv_t));
    if (!ni) return 0;
    a->items = ni;
    a->cap   = newcap;
    return 1;
}

/* ---- free helpers -------------------------------------------------------- */

static void
free_tv(tv_t *v)
{
    switch (v->type) {
    case TV_STR:
        free(v->u.s);
        break;
    case TV_TABLE:
        free_table(v->u.tab);
        break;
    case TV_ARR:
        free_arr(v->u.arr);
        break;
    case TV_INT:
    case TV_BOOL:
        break;
    }
}

static void
free_table(op_toml_table_t *t)
{
    if (!t) return;
    for (int i = 0; i < t->n; i++) {
        free(t->kv[i].key);
        free_tv(&t->kv[i].val);
    }
    free(t->kv);
    free(t);
}

static void
free_arr(op_toml_arr_t *a)
{
    if (!a) return;
    for (int i = 0; i < a->n; i++)
        free_tv(&a->items[i]);
    free(a->items);
    free(a);
}

/* ---- table operations ---------------------------------------------------- */

/* Find a kv entry by key; returns pointer or NULL. */
static kv_t *
table_find(const op_toml_table_t *t, const char *key)
{
    for (int i = 0; i < t->n; i++) {
        if (strcmp(t->kv[i].key, key) == 0)
            return &t->kv[i];
    }
    return NULL;
}

/*
 * Insert a new key+value into table t.
 * Returns 1 on success, 0 on allocation failure.
 * Assumes caller has already checked for duplicate keys.
 */
static int
table_insert(op_toml_table_t *t, const char *key, tv_t val)
{
    if (!table_grow(t)) return 0;
    char *k = strdup(key);
    if (!k) return 0;
    t->kv[t->n].key = k;
    t->kv[t->n].val = val;
    t->n++;
    return 1;
}

/* ---- character-level parser helpers ------------------------------------- */

static void
skip_ws(parser_t *p)
{
    while (p->cur < p->end && (*p->cur == ' ' || *p->cur == '\t'))
        p->cur++;
}

static void
skip_ws_and_newlines(parser_t *p)
{
    while (p->cur < p->end) {
        char c = *p->cur;
        if (c == ' ' || c == '\t') {
            p->cur++;
        } else if (c == '\n') {
            p->line++;
            p->cur++;
        } else if (c == '\r') {
            p->cur++;
            if (p->cur < p->end && *p->cur == '\n') {
                p->cur++;
            }
            p->line++;
        } else if (c == '#') {
            /* skip comment to end of line */
            while (p->cur < p->end && *p->cur != '\n' && *p->cur != '\r')
                p->cur++;
        } else {
            break;
        }
    }
}

/* Skip to end of line (past the newline). */
static void
skip_line(parser_t *p)
{
    while (p->cur < p->end && *p->cur != '\n' && *p->cur != '\r')
        p->cur++;
    /* consume the newline */
    if (p->cur < p->end) {
        if (*p->cur == '\r') {
            p->cur++;
            if (p->cur < p->end && *p->cur == '\n')
                p->cur++;
        } else {
            p->cur++; /* '\n' */
        }
        p->line++;
    }
}

/* ---- value parsers ------------------------------------------------------- */

/*
 * parse_string — parse a double-quoted string at p->cur.
 * On success, sets *out to a heap-allocated string and returns 1.
 * On error, sets errbuf and returns 0.
 */
static int
parse_string(parser_t *p, char **out)
{
    if (p->cur >= p->end || *p->cur != '"') {
        set_err(p, "expected '\"'");
        return 0;
    }
    p->cur++; /* skip opening quote */

    /* worst-case output length == input length */
    size_t maxlen = (size_t)(p->end - p->cur) + 1;
    char *buf = malloc(maxlen);
    if (!buf) {
        set_err(p, "out of memory");
        return 0;
    }
    size_t pos = 0;

    while (p->cur < p->end) {
        char c = *p->cur;
        if (c == '"') {
            p->cur++; /* skip closing quote */
            buf[pos] = '\0';
            *out = buf;
            return 1;
        }
        if (c == '\n' || c == '\r') {
            set_err(p, "unterminated string (newline inside quoted string)");
            free(buf);
            return 0;
        }
        if (c == '\\') {
            p->cur++;
            if (p->cur >= p->end) {
                set_err(p, "unterminated escape sequence");
                free(buf);
                return 0;
            }
            char esc = *p->cur++;
            switch (esc) {
            case '"':  buf[pos++] = '"';  break;
            case '\\': buf[pos++] = '\\'; break;
            case 'n':  buf[pos++] = '\n'; break;
            case 't':  buf[pos++] = '\t'; break;
            case 'r':  buf[pos++] = '\r'; break;
            case '0':  buf[pos++] = '\0'; break;
            default:
                set_errf(p, "unknown escape sequence '\\%c'", esc);
                free(buf);
                return 0;
            }
        } else {
            buf[pos++] = c;
            p->cur++;
        }
    }

    set_err(p, "unterminated string");
    free(buf);
    return 0;
}

/*
 * parse_integer — parse an optional '-' followed by decimal digits.
 * Returns 1 on success, 0 on error.
 */
static int
parse_integer(parser_t *p, long *out)
{
    if (p->cur >= p->end) {
        set_err(p, "expected integer");
        return 0;
    }
    int neg = 0;
    if (*p->cur == '-') {
        neg = 1;
        p->cur++;
    }
    if (p->cur >= p->end || !isdigit((unsigned char)*p->cur)) {
        set_err(p, "expected digit after '-'");
        return 0;
    }
    long val = 0;
    while (p->cur < p->end && isdigit((unsigned char)*p->cur)) {
        int d = *p->cur - '0';
        /* overflow guard */
        if (val > (LONG_MAX - d) / 10) {
            set_err(p, "integer overflow");
            return 0;
        }
        val = val * 10 + d;
        p->cur++;
    }
    *out = neg ? -val : val;
    return 1;
}

/*
 * parse_array — parse a TOML array value [ ... ].
 * Elements may be strings or integers (mixed arrays are a TOML error).
 * Returns a heap-allocated op_toml_arr_t on success, NULL on error.
 */
static op_toml_arr_t *
parse_array(parser_t *p)
{
    if (p->cur >= p->end || *p->cur != '[') {
        set_err(p, "expected '['");
        return NULL;
    }
    p->cur++; /* skip '[' */

    op_toml_arr_t *a = arr_new();
    if (!a) {
        set_err(p, "out of memory");
        return NULL;
    }

    /* track the element type to detect mixed arrays */
    int have_type = 0;
    tv_type_t arr_type = TV_STR; /* initialised to silence compiler */

    while (1) {
        skip_ws_and_newlines(p);
        if (p->cur >= p->end) {
            set_err(p, "unterminated array");
            free_arr(a);
            return NULL;
        }
        if (*p->cur == ']') {
            p->cur++; /* skip ']' */
            return a;
        }

        tv_t item;
        memset(&item, 0, sizeof(item));

        if (*p->cur == '"') {
            /* string element */
            char *s = NULL;
            if (!parse_string(p, &s)) {
                free_arr(a);
                return NULL;
            }
            item.type  = TV_STR;
            item.u.s   = s;
        } else if (*p->cur == '-' || isdigit((unsigned char)*p->cur)) {
            /* integer element */
            long n = 0;
            if (!parse_integer(p, &n)) {
                free_arr(a);
                return NULL;
            }
            item.type  = TV_INT;
            item.u.n   = n;
        } else {
            set_errf(p, "unexpected character '%c' in array", *p->cur);
            free_arr(a);
            return NULL;
        }

        /* enforce homogeneous arrays */
        if (!have_type) {
            arr_type  = item.type;
            have_type = 1;
        } else if (item.type != arr_type) {
            free_tv(&item);
            set_err(p, "mixed-type arrays are not supported");
            free_arr(a);
            return NULL;
        }

        /* append item to array */
        if (!arr_grow(a)) {
            free_tv(&item);
            set_err(p, "out of memory");
            free_arr(a);
            return NULL;
        }
        a->items[a->n++] = item;

        skip_ws_and_newlines(p);
        if (p->cur >= p->end) {
            set_err(p, "unterminated array");
            free_arr(a);
            return NULL;
        }
        if (*p->cur == ',') {
            p->cur++; /* consume comma; trailing comma before ']' is fine */
        } else if (*p->cur != ']') {
            set_errf(p, "expected ',' or ']' in array, got '%c'", *p->cur);
            free_arr(a);
            return NULL;
        }
    }
}

/*
 * parse_value — parse a TOML value (string, integer, boolean, array).
 * Returns 1 on success (out populated), 0 on error (errbuf set).
 */
static int
parse_value(parser_t *p, tv_t *out)
{
    skip_ws(p);
    if (p->cur >= p->end) {
        set_err(p, "expected value");
        return 0;
    }

    char c = *p->cur;

    if (c == '"') {
        char *s = NULL;
        if (!parse_string(p, &s)) return 0;
        out->type = TV_STR;
        out->u.s  = s;
        return 1;
    }

    if (c == '[') {
        op_toml_arr_t *a = parse_array(p);
        if (!a) return 0;
        out->type  = TV_ARR;
        out->u.arr = a;
        return 1;
    }

    /* boolean: true / false */
    size_t remaining = (size_t)(p->end - p->cur);
    if (remaining >= 4 && memcmp(p->cur, "true", 4) == 0) {
        /* make sure it's not a bare key prefix (must be followed by
         * whitespace, comment, newline, or end of input) */
        char nx = (remaining > 4) ? p->cur[4] : '\0';
        if (remaining == 4 || nx == ' ' || nx == '\t' || nx == '\r' ||
            nx == '\n' || nx == '#') {
            p->cur += 4;
            out->type = TV_BOOL;
            out->u.b  = 1;
            return 1;
        }
    }
    if (remaining >= 5 && memcmp(p->cur, "false", 5) == 0) {
        char nx = (remaining > 5) ? p->cur[5] : '\0';
        if (remaining == 5 || nx == ' ' || nx == '\t' || nx == '\r' ||
            nx == '\n' || nx == '#') {
            p->cur += 5;
            out->type = TV_BOOL;
            out->u.b  = 0;
            return 1;
        }
    }

    /* integer: optional '-' then digits */
    if (c == '-' || isdigit((unsigned char)c)) {
        long n = 0;
        if (!parse_integer(p, &n)) return 0;
        out->type = TV_INT;
        out->u.n  = n;
        return 1;
    }

    set_errf(p, "unexpected character '%c' in value", c);
    return 0;
}

/*
 * parse_key — parse a bare or quoted key into a heap-allocated string.
 * Returns 1 on success, 0 on error.
 */
static int
parse_key(parser_t *p, char **out)
{
    skip_ws(p);
    if (p->cur >= p->end) {
        set_err(p, "expected key");
        return 0;
    }

    if (*p->cur == '"') {
        return parse_string(p, out);
    }

    /* bare key: [a-zA-Z0-9_-]+ */
    const char *start = p->cur;
    while (p->cur < p->end) {
        char c = *p->cur;
        if (isalnum((unsigned char)c) || c == '_' || c == '-')
            p->cur++;
        else
            break;
    }
    if (p->cur == start) {
        set_errf(p, "invalid key character '%c'", *p->cur);
        return 0;
    }
    size_t len = (size_t)(p->cur - start);
    char *k = malloc(len + 1);
    if (!k) {
        set_err(p, "out of memory");
        return 0;
    }
    memcpy(k, start, len);
    k[len] = '\0';
    *out = k;
    return 1;
}

/*
 * parse_header_name — parse a bare key between '[' and ']' (already consumed
 * the leading '[' or '[[').  Returns heap-allocated name.
 */
static int
parse_header_name(parser_t *p, char **out)
{
    skip_ws(p);
    const char *start = p->cur;
    while (p->cur < p->end) {
        char c = *p->cur;
        if (c == ']' || c == '\n' || c == '\r')
            break;
        p->cur++;
    }
    /* trim trailing whitespace */
    const char *end = p->cur;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        end--;
    if (end == start) {
        set_err(p, "empty table name");
        return 0;
    }
    size_t len = (size_t)(end - start);
    char *k = malloc(len + 1);
    if (!k) {
        set_err(p, "out of memory");
        return 0;
    }
    memcpy(k, start, len);
    k[len] = '\0';
    *out = k;
    return 1;
}

/* ---- top-level parser ---------------------------------------------------- */

/*
 * parse_document — main parse loop.
 * Returns 1 on success, 0 on error (errbuf set, root partially built).
 */
static int
parse_document(parser_t *p)
{
    while (1) {
        skip_ws_and_newlines(p);
        if (p->cur >= p->end)
            break;

        char c = *p->cur;

        /* ---- section header ---- */
        if (c == '[') {
            p->cur++; /* consume first '[' */
            int is_aot = (p->cur < p->end && *p->cur == '[');
            if (is_aot) p->cur++; /* consume second '[' */

            char *name = NULL;
            if (!parse_header_name(p, &name))
                return 0;

            /* expect ']' (and ']]' for aot) */
            if (p->cur >= p->end || *p->cur != ']') {
                free(name);
                set_err(p, "expected ']' after table name");
                return 0;
            }
            p->cur++; /* consume ']' */
            if (is_aot) {
                if (p->cur >= p->end || *p->cur != ']') {
                    free(name);
                    set_err(p, "expected ']]' after array-of-tables name");
                    return 0;
                }
                p->cur++; /* consume second ']' */
            }

            /* optional trailing comment / whitespace then newline */
            skip_ws(p);
            if (p->cur < p->end && *p->cur == '#')
                skip_line(p);
            else if (p->cur < p->end && *p->cur != '\n' && *p->cur != '\r' &&
                     p->cur < p->end) {
                /* non-comment, non-newline after header is an error */
                free(name);
                set_err(p, "unexpected characters after table header");
                return 0;
            }

            if (is_aot) {
                /* [[name]]: look up or create array in root */
                kv_t *existing = table_find(p->root, name);
                op_toml_arr_t *a;
                if (existing) {
                    if (existing->val.type != TV_ARR) {
                        free(name);
                        set_errf(p, "key '%s' already exists and is not an array", name);
                        return 0;
                    }
                    a = existing->val.u.arr;
                } else {
                    a = arr_new();
                    if (!a) {
                        free(name);
                        set_err(p, "out of memory");
                        return 0;
                    }
                    tv_t av;
                    av.type  = TV_ARR;
                    av.u.arr = a;
                    if (!table_insert(p->root, name, av)) {
                        free(name);
                        free_arr(a);
                        set_err(p, "out of memory");
                        return 0;
                    }
                }
                /* append a new empty table to the array */
                if (!arr_grow(a)) {
                    free(name);
                    set_err(p, "out of memory");
                    return 0;
                }
                op_toml_table_t *new_tab = table_new();
                if (!new_tab) {
                    free(name);
                    set_err(p, "out of memory");
                    return 0;
                }
                a->items[a->n].type    = TV_TABLE;
                a->items[a->n].u.tab   = new_tab;
                a->n++;
                p->cur_tab = new_tab;
            } else {
                /* [name]: look up or create sub-table in root */
                kv_t *existing = table_find(p->root, name);
                if (existing) {
                    if (existing->val.type != TV_TABLE) {
                        free(name);
                        set_errf(p, "key '%s' already exists and is not a table", name);
                        return 0;
                    }
                    p->cur_tab = existing->val.u.tab;
                } else {
                    op_toml_table_t *sub = table_new();
                    if (!sub) {
                        free(name);
                        set_err(p, "out of memory");
                        return 0;
                    }
                    tv_t tv;
                    tv.type  = TV_TABLE;
                    tv.u.tab = sub;
                    if (!table_insert(p->root, name, tv)) {
                        free(name);
                        free_table(sub);
                        set_err(p, "out of memory");
                        return 0;
                    }
                    p->cur_tab = sub;
                }
            }
            free(name);
            continue;
        }

        /* ---- comment: skip line ---- */
        if (c == '#') {
            skip_line(p);
            continue;
        }

        /* ---- key = value line ---- */
        char *key = NULL;
        if (!parse_key(p, &key))
            return 0;

        skip_ws(p);
        if (p->cur >= p->end || *p->cur != '=') {
            free(key);
            set_err(p, "expected '=' after key");
            return 0;
        }
        p->cur++; /* consume '=' */
        skip_ws(p);

        /* check for duplicate key */
        if (table_find(p->cur_tab, key)) {
            set_errf(p, "duplicate key '%s'", key);
            free(key);
            return 0;
        }

        tv_t val;
        memset(&val, 0, sizeof(val));
        if (!parse_value(p, &val)) {
            free(key);
            return 0;
        }

        if (!table_insert(p->cur_tab, key, val)) {
            free(key);
            free_tv(&val);
            set_err(p, "out of memory");
            return 0;
        }
        free(key);

        /* expect end of line (optional whitespace + optional comment) */
        skip_ws(p);
        if (p->cur < p->end && *p->cur == '#') {
            skip_line(p);
            continue;
        }
        if (p->cur < p->end && *p->cur != '\n' && *p->cur != '\r') {
            set_err(p, "unexpected characters after value");
            return 0;
        }
    }
    return 1;
}

/* ---- public API ---------------------------------------------------------- */

op_toml_table_t *
op_toml_parse(const char *buf, size_t len, char *errbuf, size_t errsz)
{
    op_toml_table_t *root = table_new();
    if (!root) {
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "out of memory");
        return NULL;
    }

    parser_t p;
    p.src     = buf;
    p.cur     = buf;
    p.end     = buf + len;
    p.line    = 1;
    p.errbuf  = errbuf;
    p.errsz   = errsz;
    p.root    = root;
    p.cur_tab = root;

    if (!parse_document(&p)) {
        free_table(root);
        return NULL;
    }
    return root;
}

op_toml_table_t *
op_toml_parse_file(const char *path, char *errbuf, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "cannot open '%s': %s", path, strerror(errno));
        return NULL;
    }

    /* determine file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "fseek failed on '%s': %s", path, strerror(errno));
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "ftell failed on '%s': %s", path, strerror(errno));
        return NULL;
    }
    rewind(f);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "out of memory reading '%s'", path);
        return NULL;
    }

    size_t nr = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if ((long)nr != sz) {
        free(buf);
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "short read on '%s'", path);
        return NULL;
    }
    buf[sz] = '\0';

    op_toml_table_t *root = op_toml_parse(buf, (size_t)sz, errbuf, errsz);
    free(buf);
    return root;
}

void
op_toml_free(op_toml_table_t *root)
{
    free_table(root);
}

/* ---- table lookup -------------------------------------------------------- */

int
op_toml_str(const op_toml_table_t *t, const char *k, const char **out)
{
    const kv_t *kv = table_find(t, k);
    if (!kv) return 0;
    if (kv->val.type != TV_STR) return -1;
    if (out) *out = kv->val.u.s;
    return 1;
}

int
op_toml_int(const op_toml_table_t *t, const char *k, long *out)
{
    const kv_t *kv = table_find(t, k);
    if (!kv) return 0;
    if (kv->val.type != TV_INT) return -1;
    if (out) *out = kv->val.u.n;
    return 1;
}

int
op_toml_bool(const op_toml_table_t *t, const char *k, int *out)
{
    const kv_t *kv = table_find(t, k);
    if (!kv) return 0;
    if (kv->val.type != TV_BOOL) return -1;
    if (out) *out = kv->val.u.b;
    return 1;
}

op_toml_table_t *
op_toml_table(const op_toml_table_t *t, const char *k)
{
    const kv_t *kv = table_find(t, k);
    if (!kv || kv->val.type != TV_TABLE) return NULL;
    return kv->val.u.tab;
}

op_toml_arr_t *
op_toml_arr(const op_toml_table_t *t, const char *k)
{
    const kv_t *kv = table_find(t, k);
    if (!kv || kv->val.type != TV_ARR) return NULL;
    return kv->val.u.arr;
}

/* ---- array access -------------------------------------------------------- */

int
op_toml_arr_len(const op_toml_arr_t *a)
{
    if (!a) return 0;
    return a->n;
}

int
op_toml_arr_str(const op_toml_arr_t *a, int i, const char **out)
{
    if (!a || i < 0 || i >= a->n) return 0;
    if (a->items[i].type != TV_STR) return -1;
    if (out) *out = a->items[i].u.s;
    return 1;
}

int
op_toml_arr_int(const op_toml_arr_t *a, int i, long *out)
{
    if (!a || i < 0 || i >= a->n) return 0;
    if (a->items[i].type != TV_INT) return -1;
    if (out) *out = a->items[i].u.n;
    return 1;
}

op_toml_table_t *
op_toml_arr_table(const op_toml_arr_t *a, int i)
{
    if (!a || i < 0 || i >= a->n) return NULL;
    if (a->items[i].type != TV_TABLE) return NULL;
    return a->items[i].u.tab;
}

/* ---- key iteration ------------------------------------------------------- */

void
op_toml_iter(const op_toml_table_t *t, op_toml_iter_fn fn, void *ud)
{
    if (!t || !fn) return;
    for (int i = 0; i < t->n; i++)
        fn(t->kv[i].key, ud);
}
