/*
 * libop: ophion support library.
 * trie.c: Ternary search trie (TST).
 *
 * Each TST node splits on one character c:
 *   lo   — keys where current char < c (left subtree)
 *   eq   — keys where current char == c (middle subtree, advance in key)
 *   hi   — keys where current char > c (right subtree)
 *
 * A terminal node (val_set=true) marks a complete key; the key string
 * is reconstructed during enumeration by accumulating characters along
 * the "eq" path.
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
#include <ctype.h>

/* ---- node ---------------------------------------------------------------- */

typedef struct tnode
{
    unsigned char   c;        /* split character                          */
    bool            val_set;  /* true → this node is a key terminal       */
    void           *val;      /* stored value (meaningful when val_set)   */
    struct tnode   *lo;       /* chars < c                                */
    struct tnode   *eq;       /* next char of key                         */
    struct tnode   *hi;       /* chars > c                                */
} tnode_t;

/* ---- tree ---------------------------------------------------------------- */

struct op_trie
{
    tnode_t    *root;
    size_t      count;
    bool        icase;
    const char *name;
};

/* ---- helpers ------------------------------------------------------------- */

static inline unsigned char
fold(bool icase, unsigned char c)
{
    return icase ? (unsigned char)tolower(c) : c;
}

/* ---- allocation ---------------------------------------------------------- */

static tnode_t *
node_new(unsigned char c)
{
    tnode_t *n = op_malloc(sizeof(*n));
    n->c       = c;
    n->val_set = false;
    n->val     = NULL;
    n->lo      = NULL;
    n->eq      = NULL;
    n->hi      = NULL;
    return n;
}

/* ---- insert -------------------------------------------------------------- */

static tnode_t *
insert(tnode_t *n, const unsigned char *key, bool icase,
       void *val, void **old_val, int *is_new)
{
    unsigned char c = fold(icase, *key);

    if (n == NULL)
        n = node_new(c);

    if (c < n->c)
        n->lo = insert(n->lo, key, icase, val, old_val, is_new);
    else if (c > n->c)
        n->hi = insert(n->hi, key, icase, val, old_val, is_new);
    else if (*(key + 1) == '\0')
    {
        /* Terminal: c == n->c and this is the last character. */
        if (n->val_set)
        {
            if (old_val) *old_val = n->val;
            *is_new = 0;
        }
        else
        {
            if (old_val) *old_val = NULL;
            *is_new = 1;
        }
        n->val_set = true;
        n->val     = val;
    }
    else
        n->eq = insert(n->eq, key + 1, icase, val, old_val, is_new);

    return n;
}

/* ---- lookup -------------------------------------------------------------- */

static tnode_t *
find_node(tnode_t *n, const unsigned char *key, bool icase)
{
    while (n != NULL)
    {
        unsigned char c = fold(icase, *key);
        if (c < n->c)
            n = n->lo;
        else if (c > n->c)
            n = n->hi;
        else
        {
            if (*(key + 1) == '\0')
                return n;   /* found the terminal node */
            key++;
            n = n->eq;
        }
    }
    return NULL;
}

/* ---- delete -------------------------------------------------------------- */

/*
 * Recursive delete.  Returns the (possibly NULL) new root of the subtree.
 * *removed is set to the old value when a key is found and removed.
 * *found is set to true when the key is found.
 */
static tnode_t *
do_del(tnode_t *n, const unsigned char *key, bool icase,
       void **removed, bool *found)
{
    if (n == NULL)
        return NULL;

    unsigned char c = fold(icase, *key);

    if (c < n->c)
        n->lo = do_del(n->lo, key, icase, removed, found);
    else if (c > n->c)
        n->hi = do_del(n->hi, key, icase, removed, found);
    else if (*(key + 1) == '\0')
    {
        /* Terminal */
        if (n->val_set)
        {
            *removed = n->val;
            *found   = true;
            n->val_set = false;
            n->val     = NULL;
        }
    }
    else
        n->eq = do_del(n->eq, key + 1, icase, removed, found);

    /* Prune completely empty leaf nodes to keep tree tidy. */
    if (!n->val_set && n->lo == NULL && n->eq == NULL && n->hi == NULL)
    {
        op_free(n);
        return NULL;
    }
    return n;
}

/* ---- enumeration --------------------------------------------------------- */

/*
 * Accumulate key chars along the eq spine; report terminals.
 * buf / buflen track the string built so far.
 */
typedef struct
{
    op_trie_each_t fn;
    void          *ud;
    char          *buf;
    size_t         bufcap;
    size_t         buflen;
    bool           stop;
} each_ctx_t;

static void ensure_buf(each_ctx_t *ctx, size_t needed)
{
    if (needed + 1 > ctx->bufcap)
    {
        ctx->bufcap = (needed + 1) * 2;
        ctx->buf    = op_realloc(ctx->buf, ctx->bufcap);
    }
}

static void
tst_each(tnode_t *n, each_ctx_t *ctx)
{
    if (n == NULL || ctx->stop)
        return;

    /* Traverse lo (chars < n->c) — same key prefix depth */
    tst_each(n->lo, ctx);
    if (ctx->stop) return;

    /* Append n->c, recurse into eq, then pop */
    ensure_buf(ctx, ctx->buflen + 1);
    ctx->buf[ctx->buflen] = (char)n->c;
    ctx->buflen++;

    if (n->val_set)
    {
        ctx->buf[ctx->buflen] = '\0';
        if (!ctx->fn(ctx->buf, n->val, ctx->ud))
        {
            ctx->stop = true;
            ctx->buflen--;
            return;
        }
    }

    tst_each(n->eq, ctx);

    ctx->buflen--;

    if (ctx->stop) return;

    /* Traverse hi (chars > n->c) — same key prefix depth */
    tst_each(n->hi, ctx);
}

/* ---- prefix query -------------------------------------------------------- */

/*
 * Walk the TST following prefix characters.  When the prefix is exhausted,
 * enumerate all keys in the subtree rooted at the eq child of the last
 * prefix node (plus the terminal of the last prefix node itself).
 */
static void
prefix_each(tnode_t *n, const unsigned char *prefix, bool icase, each_ctx_t *ctx)
{
    if (n == NULL || ctx->stop)
        return;

    unsigned char c = fold(icase, *prefix);

    if (c < n->c)
        prefix_each(n->lo, prefix, icase, ctx);
    else if (c > n->c)
        prefix_each(n->hi, prefix, icase, ctx);
    else
    {
        /* Match: append c to buf */
        ensure_buf(ctx, ctx->buflen + 1);
        ctx->buf[ctx->buflen] = (char)n->c;
        ctx->buflen++;

        if (*(prefix + 1) == '\0')
        {
            /* End of prefix — enumerate everything from here */
            if (n->val_set)
            {
                ctx->buf[ctx->buflen] = '\0';
                if (!ctx->fn(ctx->buf, n->val, ctx->ud))
                {
                    ctx->stop = true;
                    ctx->buflen--;
                    return;
                }
            }
            tst_each(n->eq, ctx);
        }
        else
            prefix_each(n->eq, prefix + 1, icase, ctx);

        ctx->buflen--;
    }
}

/* ---- wildcard (glob) ----------------------------------------------------- */

/*
 * Standard recursive glob match on NUL-terminated strings.
 * '*' matches any sequence (including empty); '?' matches exactly one char.
 * case folding applied when icase=true.
 */
static bool
glob_match(const unsigned char *pat, const unsigned char *str, bool icase)
{
    /* '*' — skip consecutive stars, then try anchoring remainder at every
     * position in str.  A trailing '*' (pat empty after skip) matches all. */
    if (*pat == '*')
    {
        while (*pat == '*')
            pat++;
        if (*pat == '\0')
            return true;
        for (; *str != '\0'; str++)
            if (glob_match(pat, str, icase))
                return true;
        return false;
    }

    /* Both exhausted → match; only pattern exhausted → str has extra chars. */
    if (*pat == '\0')
        return *str == '\0';

    if (*str == '\0')
        return false;

    /* '?' matches any single char; literal must equal (with optional fold). */
    if (*pat != '?' && fold(icase, *pat) != fold(icase, *str))
        return false;

    return glob_match(pat + 1, str + 1, icase);
}

/*
 * wildcard_each — DFS over all keys, filter by glob pattern.
 *
 * Simpler than a pattern-driven TST walk and avoids the edge cases in
 * '*' handling.  O(n * m) where n = number of keys, m = pattern length.
 */
static void
wildcard_each(tnode_t *n, const unsigned char *pat, bool icase,
              each_ctx_t *ctx)
{
    if (n == NULL || ctx->stop)
        return;

    wildcard_each(n->lo, pat, icase, ctx);
    if (ctx->stop) return;

    /* Append n->c, check if key is complete and matches pattern. */
    ensure_buf(ctx, ctx->buflen + 1);
    ctx->buf[ctx->buflen] = (char)n->c;
    ctx->buflen++;

    if (n->val_set)
    {
        ctx->buf[ctx->buflen] = '\0';
        if (glob_match(pat, (const unsigned char *)ctx->buf, icase))
        {
            if (!ctx->fn(ctx->buf, n->val, ctx->ud))
            {
                ctx->stop = true;
                ctx->buflen--;
                return;
            }
        }
    }

    wildcard_each(n->eq, pat, icase, ctx);

    ctx->buflen--;

    if (ctx->stop) return;

    wildcard_each(n->hi, pat, icase, ctx);
}

/* ---- destroy walker ------------------------------------------------------ */

static void
walk_free(tnode_t *n, op_trie_free_t fn, void *ud)
{
    if (n == NULL)
        return;
    walk_free(n->lo, fn, ud);
    walk_free(n->eq, fn, ud);
    walk_free(n->hi, fn, ud);
    if (n->val_set && fn)
        fn(n->val, ud);
    op_free(n);
}

/* ---- public API ---------------------------------------------------------- */

op_trie_t *
op_trie_create(const char *name, bool icase)
{
    op_trie_t *t = op_malloc(sizeof(*t));
    t->root  = NULL;
    t->count = 0;
    t->icase = icase;
    t->name  = name;
    return t;
}

void
op_trie_destroy(op_trie_t *t, op_trie_free_t free_fn, void *ud)
{
    walk_free(t->root, free_fn, ud);
    op_free(t);
}

int
op_trie_set(op_trie_t *t, const char *key, void *val, void **old_val)
{
    if (key == NULL || *key == '\0')
        return -1;   /* empty keys not supported */
    int is_new = 0;
    t->root = insert(t->root, (const unsigned char *)key,
                     t->icase, val, old_val, &is_new);
    if (is_new)
        t->count++;
    return is_new;
}

void *
op_trie_del(op_trie_t *t, const char *key)
{
    if (key == NULL || *key == '\0')
        return NULL;
    void *removed = NULL;
    bool  found   = false;
    t->root = do_del(t->root, (const unsigned char *)key,
                     t->icase, &removed, &found);
    if (found)
        t->count--;
    return removed;
}

void *
op_trie_get(const op_trie_t *t, const char *key)
{
    if (key == NULL || *key == '\0')
        return NULL;
    tnode_t *n = find_node(t->root, (const unsigned char *)key, t->icase);
    return (n && n->val_set) ? n->val : NULL;
}

bool
op_trie_has(const op_trie_t *t, const char *key)
{
    if (key == NULL || *key == '\0')
        return false;
    tnode_t *n = find_node(t->root, (const unsigned char *)key, t->icase);
    return n != NULL && n->val_set;
}

void
op_trie_foreach(const op_trie_t *t, op_trie_each_t fn, void *ud)
{
    each_ctx_t ctx = { .fn = fn, .ud = ud,
                       .buf = NULL, .bufcap = 0, .buflen = 0, .stop = false };
    tst_each(t->root, &ctx);
    op_free(ctx.buf);
}

void
op_trie_prefix(const op_trie_t *t, const char *prefix,
               op_trie_each_t fn, void *ud)
{
    if (prefix == NULL || *prefix == '\0')
    {
        op_trie_foreach(t, fn, ud);
        return;
    }
    each_ctx_t ctx = { .fn = fn, .ud = ud,
                       .buf = NULL, .bufcap = 0, .buflen = 0, .stop = false };
    prefix_each(t->root, (const unsigned char *)prefix, t->icase, &ctx);
    op_free(ctx.buf);
}

void
op_trie_wildcard(const op_trie_t *t, const char *pattern,
                 op_trie_each_t fn, void *ud)
{
    if (pattern == NULL)
        return;
    each_ctx_t ctx = { .fn = fn, .ud = ud,
                       .buf = NULL, .bufcap = 0, .buflen = 0, .stop = false };
    wildcard_each(t->root, (const unsigned char *)pattern, t->icase, &ctx);
    op_free(ctx.buf);
}

size_t
op_trie_count(const op_trie_t *t)
{
    return t->count;
}

const char *
op_trie_name(const op_trie_t *t)
{
    return t->name;
}
