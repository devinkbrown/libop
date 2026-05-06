/*
 * libop: ophion support library.
 * cidr_tbl.c: IPv4/IPv6 CIDR prefix lookup table (binary trie).
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

#ifndef _WIN32
# include <netinet/in.h>
# include <arpa/inet.h>
#endif

/* ---- trie node ----------------------------------------------------------- */

typedef struct cidr_node
{
    void             *data;   /* non-NULL → this node is a prefix endpoint */
    struct cidr_node *ch[2];  /* children for bit 0 and bit 1              */
} cidr_node_t;

/* ---- table --------------------------------------------------------------- */

struct op_cidr_tbl
{
    cidr_node_t  *root4;     /* IPv4 trie root (depth 32)  */
    cidr_node_t  *root6;     /* IPv6 trie root (depth 128) */
    op_bh        *node_heap; /* block heap for cidr_node_t allocation      */
    size_t        count4;
    size_t        count6;
    const char   *name;
};

/* ---- allocation helpers -------------------------------------------------- */

static cidr_node_t *
node_alloc(op_cidr_tbl_t *t)
{
    cidr_node_t *n = op_bh_alloc(t->node_heap);
    n->data  = NULL;
    n->ch[0] = NULL;
    n->ch[1] = NULL;
    return n;
}

/* ---- bit extraction ------------------------------------------------------ */

/*
 * IPv4: address is in network byte order (big-endian).
 * Bit 0 is the MSB of the first octet.
 */
static inline int
bit4(const struct in_addr *addr, int depth)
{
    uint32_t h = ntohl(addr->s_addr);
    return (h >> (31 - depth)) & 1;
}

/*
 * IPv6: address is a byte array, bit 0 is MSB of byte 0.
 */
static inline int
bit6(const struct in6_addr *addr, int depth)
{
#ifndef _WIN32
    const uint8_t *b = addr->s6_addr;
#else
    const uint8_t *b = (const uint8_t *)addr;
#endif
    return (b[depth / 8] >> (7 - (depth % 8))) & 1;
}

/* Unified bit extractor — dispatches on address family. */
static inline int
addr_bit(const uint8_t *addr, int af, int depth)
{
    return (af == AF_INET)
        ? bit4((const struct in_addr *)addr,  depth)
        : bit6((const struct in6_addr *)addr, depth);
}

/* ---- generic trie operations --------------------------------------------- */

/*
 * trie_set — insert a prefix of `depth` bits at the node rooted at *root.
 * Allocates nodes from the heap as needed.
 */
static int
trie_set(op_cidr_tbl_t *t, cidr_node_t **root,
         const uint8_t *addr, int af, int plen,
         void *val, void **old_val)
{
    if (*root == NULL)
        *root = node_alloc(t);

    cidr_node_t *cur = *root;

    for (int i = 0; i < plen; i++)
    {
        int bit = addr_bit(addr, af, i);
        if (cur->ch[bit] == NULL)
            cur->ch[bit] = node_alloc(t);
        cur = cur->ch[bit];
    }

    int is_new = (cur->data == NULL);
    if (old_val)
        *old_val = cur->data;
    cur->data = val;
    return is_new;
}

/*
 * trie_del — remove a prefix.  Returns the old data, or NULL if not found.
 * Does NOT prune empty nodes (acceptable for IRC ban-list usage where
 * inserts far outnumber deletes and memory overhead is negligible).
 */
static void *
trie_del(cidr_node_t *root,
         const uint8_t *addr, int af, int plen)
{
    if (root == NULL)
        return NULL;

    cidr_node_t *cur = root;

    for (int i = 0; i < plen; i++)
    {
        int bit = addr_bit(addr, af, i);
        if (cur->ch[bit] == NULL)
            return NULL;   /* prefix not in trie */
        cur = cur->ch[bit];
    }

    void *old = cur->data;
    cur->data = NULL;
    return old;
}

/*
 * trie_match_any — return data from the first node on the path that has
 * non-NULL data (shortest matching prefix / first match from the root).
 */
static void *
trie_match_any(cidr_node_t *root,
               const uint8_t *addr, int af, int maxdepth)
{
    cidr_node_t *cur = root;
    if (cur == NULL)
        return NULL;

    /* Check root (0.0.0.0/0 or ::/0). */
    if (cur->data)
        return cur->data;

    for (int i = 0; i < maxdepth; i++)
    {
        int bit = addr_bit(addr, af, i);
        cur = cur->ch[bit];
        if (cur == NULL)
            return NULL;
        if (cur->data)
            return cur->data;
    }
    return NULL;
}

/*
 * trie_lpm — longest-prefix match.  Walks the full address depth and
 * returns the data of the last prefix node encountered.
 */
static void *
trie_lpm(cidr_node_t *root,
         const uint8_t *addr, int af, int maxdepth)
{
    cidr_node_t *cur = root;
    void *best = NULL;

    if (cur == NULL)
        return NULL;

    if (cur->data)
        best = cur->data;

    for (int i = 0; i < maxdepth; i++)
    {
        int bit = addr_bit(addr, af, i);
        cur = cur->ch[bit];
        if (cur == NULL)
            break;
        if (cur->data)
            best = cur->data;
    }
    return best;
}

/* ---- enumeration helper -------------------------------------------------- */

typedef struct
{
    op_cidr_each_t         fn;
    void                  *ud;
    struct sockaddr_storage ss;
    int                    af;
    int                    depth;   /* current bit depth */
    bool                   stop;
} each_ctx_t;

/* Write bit value (0 or 1) at the given depth into ctx->ss. */
static inline void
set_addr_bit(each_ctx_t *ctx, int depth, int bit)
{
    if (ctx->af == AF_INET)
    {
        uint32_t *h = &((struct sockaddr_in *)&ctx->ss)->sin_addr.s_addr;
        uint32_t host = ntohl(*h);
        if (bit) host |=  (1u << (31 - depth));
        else     host &= ~(1u << (31 - depth));
        *h = htonl(host);
    }
    else
    {
#ifndef _WIN32
        uint8_t *b = ((struct sockaddr_in6 *)&ctx->ss)->sin6_addr.s6_addr;
#else
        uint8_t *b = (uint8_t *)&((struct sockaddr_in6 *)&ctx->ss)->sin6_addr;
#endif
        int byte = depth / 8, shift = 7 - (depth % 8);
        if (bit) b[byte] |=  (1u << shift);
        else     b[byte] &= ~(1u << shift);
    }
}

/* Clear the bit at depth (used to restore state after visiting a child). */
static inline void
clr_addr_bit(each_ctx_t *ctx, int depth)
{
    if (ctx->af == AF_INET)
    {
        uint32_t *h = &((struct sockaddr_in *)&ctx->ss)->sin_addr.s_addr;
        uint32_t host = ntohl(*h);
        host &= ~(1u << (31 - depth));
        *h = htonl(host);
    }
    else
    {
#ifndef _WIN32
        uint8_t *b = ((struct sockaddr_in6 *)&ctx->ss)->sin6_addr.s6_addr;
#else
        uint8_t *b = (uint8_t *)&((struct sockaddr_in6 *)&ctx->ss)->sin6_addr;
#endif
        int byte = depth / 8, shift = 7 - (depth % 8);
        b[byte] &= ~(1u << shift);
    }
}

static void
trie_foreach(cidr_node_t *node, each_ctx_t *ctx, int depth)
{
    if (node == NULL || ctx->stop)
        return;

    if (node->data != NULL)
    {
        if (!ctx->fn(&ctx->ss, depth, node->data, ctx->ud))
        {
            ctx->stop = true;
            return;
        }
    }

    for (int bit = 0; bit <= 1 && !ctx->stop; bit++)
    {
        if (node->ch[bit] == NULL)
            continue;
        set_addr_bit(ctx, depth, bit);
        trie_foreach(node->ch[bit], ctx, depth + 1);
        clr_addr_bit(ctx, depth);
    }
}

/* ---- node heap destruction helpers --------------------------------------- */

/* Call free_fn on every prefix node that carries data. */
static void
walk_vals(cidr_node_t *h, op_cidr_free_t fn, void *ud)
{
    if (h == NULL)
        return;
    if (h->data && fn)
        fn(h->data, ud);
    walk_vals(h->ch[0], fn, ud);
    walk_vals(h->ch[1], fn, ud);
}

/* ---- public API ---------------------------------------------------------- */

op_cidr_tbl_t *
op_cidr_create(const char *name)
{
    op_cidr_tbl_t *t = op_malloc(sizeof(*t));
    t->root4     = NULL;
    t->root6     = NULL;
    t->count4    = 0;
    t->count6    = 0;
    t->name      = name;
    t->node_heap = op_bh_create(sizeof(cidr_node_t), 256, "cidr_nodes");
    return t;
}

void
op_cidr_destroy(op_cidr_tbl_t *t, op_cidr_free_t free_fn, void *ud)
{
    /* Call free_fn for each stored value before releasing the node memory. */
    if (free_fn)
    {
        walk_vals(t->root4, free_fn, ud);
        walk_vals(t->root6, free_fn, ud);
    }

    /* All nodes were allocated from the block heap — destroy in one shot. */
    op_bh_destroy(t->node_heap);
    op_free(t);
}

/* ---- insert -------------------------------------------------------------- */

int
op_cidr_set4(op_cidr_tbl_t *t,
             const struct in_addr *addr, int plen,
             void *val, void **old_val)
{
    if (plen < 0 || plen > 32)
        return -1;
    int r = trie_set(t, &t->root4, (const uint8_t *)addr, AF_INET, plen,
                     val, old_val);
    if (r)
        t->count4++;
    return r;
}

int
op_cidr_set6(op_cidr_tbl_t *t,
             const struct in6_addr *addr, int plen,
             void *val, void **old_val)
{
    if (plen < 0 || plen > 128)
        return -1;
    int r = trie_set(t, &t->root6, (const uint8_t *)addr, AF_INET6, plen,
                     val, old_val);
    if (r)
        t->count6++;
    return r;
}

/* ---- delete -------------------------------------------------------------- */

void *
op_cidr_del4(op_cidr_tbl_t *t, const struct in_addr *addr, int plen)
{
    void *old = trie_del(t->root4, (const uint8_t *)addr, AF_INET, plen);
    if (old)
        t->count4--;
    return old;
}

void *
op_cidr_del6(op_cidr_tbl_t *t, const struct in6_addr *addr, int plen)
{
    void *old = trie_del(t->root6, (const uint8_t *)addr, AF_INET6, plen);
    if (old)
        t->count6--;
    return old;
}

/* ---- match-any ----------------------------------------------------------- */

void *
op_cidr_match_any4(const op_cidr_tbl_t *t, const struct in_addr *addr)
{
    return trie_match_any(t->root4, (const uint8_t *)addr, AF_INET, 32);
}

void *
op_cidr_match_any6(const op_cidr_tbl_t *t, const struct in6_addr *addr)
{
    return trie_match_any(t->root6, (const uint8_t *)addr, AF_INET6, 128);
}

void *
op_cidr_match_any_ss(const op_cidr_tbl_t *t, const struct sockaddr_storage *ss)
{
    if (GET_SS_FAMILY(ss) == AF_INET)
        return op_cidr_match_any4(t, &((const struct sockaddr_in *)ss)->sin_addr);
    if (GET_SS_FAMILY(ss) == AF_INET6)
        return op_cidr_match_any6(t, &((const struct sockaddr_in6 *)ss)->sin6_addr);
    return NULL;
}

/* ---- LPM ----------------------------------------------------------------- */

void *
op_cidr_lpm4(const op_cidr_tbl_t *t, const struct in_addr *addr)
{
    return trie_lpm(t->root4, (const uint8_t *)addr, AF_INET, 32);
}

void *
op_cidr_lpm6(const op_cidr_tbl_t *t, const struct in6_addr *addr)
{
    return trie_lpm(t->root6, (const uint8_t *)addr, AF_INET6, 128);
}

void *
op_cidr_lpm_ss(const op_cidr_tbl_t *t, const struct sockaddr_storage *ss)
{
    if (GET_SS_FAMILY(ss) == AF_INET)
        return op_cidr_lpm4(t, &((const struct sockaddr_in *)ss)->sin_addr);
    if (GET_SS_FAMILY(ss) == AF_INET6)
        return op_cidr_lpm6(t, &((const struct sockaddr_in6 *)ss)->sin6_addr);
    return NULL;
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_cidr_count4(const op_cidr_tbl_t *t)
{
    return t->count4;
}

size_t
op_cidr_count6(const op_cidr_tbl_t *t)
{
    return t->count6;
}

const char *
op_cidr_name(const op_cidr_tbl_t *t)
{
    return t->name;
}

/* ---- enumeration --------------------------------------------------------- */

void
op_cidr_foreach4(const op_cidr_tbl_t *t, op_cidr_each_t fn, void *ud)
{
    each_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fn = fn;
    ctx.ud = ud;
    ctx.af = AF_INET;
    ctx.stop  = false;
    ((struct sockaddr_in *)&ctx.ss)->sin_family = AF_INET;
    trie_foreach(t->root4, &ctx, 0);
}

void
op_cidr_foreach6(const op_cidr_tbl_t *t, op_cidr_each_t fn, void *ud)
{
    each_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fn = fn;
    ctx.ud = ud;
    ctx.af = AF_INET6;
    ctx.stop = false;
    ((struct sockaddr_in6 *)&ctx.ss)->sin6_family = AF_INET6;
    trie_foreach(t->root6, &ctx, 0);
}
