/*
 * libop: ophion support library.
 * itree.c: Augmented interval tree (LLRB with max_end augmentation).
 *
 * Each node stores one interval [lo, hi] plus a user value, and is keyed
 * by lo.  The max_end field in each node stores the maximum hi value in
 * its entire subtree — this is what enables O(log n) pruning during stab
 * and overlap queries.
 *
 * Multiple intervals with the same lo value are stored as a linked list
 * (segment_t chain) hanging off a single tree node.  This avoids the
 * complexity of a multi-key tree while keeping the tree balanced.
 *
 * Tree structure: Left-Leaning Red-Black (LLRB, Sedgewick 2008).
 * The augmentation invariant max_end = max(hi, left.max_end, right.max_end)
 * is maintained bottom-up via fixup_aug() after every structural change.
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

/* ---- node types ---------------------------------------------------------- */

/* One stored interval. */
typedef struct segment
{
    int64_t         hi;
    void           *val;
    struct segment *next;   /* chain for same-lo intervals */
} segment_t;

/* One LLRB node — represents all intervals sharing the same lo. */
typedef struct inode
{
    int64_t         lo;         /* sort key                          */
    int64_t         max_end;    /* max hi in this subtree            */
    segment_t      *segs;       /* non-empty linked list of segments */
    struct inode   *left;
    struct inode   *right;
    bool            red;
} inode_t;

/* ---- tree ---------------------------------------------------------------- */

struct op_itree
{
    inode_t    *root;
    size_t      count;      /* total number of stored intervals  */
    const char *name;
};

/* ---- helpers ------------------------------------------------------------- */

#define IS_RED(n)  ((n) != NULL && (n)->red)

static inline int64_t
max3(int64_t a, int64_t b, int64_t c)
{
    int64_t m = a > b ? a : b;
    return m > c ? m : c;
}

/* Recompute max_end from hi values of all segments plus children. */
static void
aug(inode_t *n)
{
    if (n == NULL)
        return;
    int64_t hi = INT64_MIN;
    for (segment_t *s = n->segs; s; s = s->next)
        if (s->hi > hi) hi = s->hi;
    int64_t left_max  = n->left  ? n->left->max_end  : INT64_MIN;
    int64_t right_max = n->right ? n->right->max_end : INT64_MIN;
    n->max_end = max3(hi, left_max, right_max);
}

/* ---- LLRB rotations ------------------------------------------------------ */

static inode_t *
rotate_left(inode_t *h)
{
    inode_t *x  = h->right;
    h->right    = x->left;
    x->left     = h;
    x->red      = h->red;
    h->red      = true;
    aug(h);
    aug(x);
    return x;
}

static inode_t *
rotate_right(inode_t *h)
{
    inode_t *x  = h->left;
    h->left     = x->right;
    x->right    = h;
    x->red      = h->red;
    h->red      = true;
    aug(h);
    aug(x);
    return x;
}

static void
flip_colours(inode_t *h)
{
    h->red        = !h->red;
    h->left->red  = !h->left->red;
    h->right->red = !h->right->red;
}

/* LLRB fixup — applied bottom-up on the way back from every insert/delete. */
static inode_t *
fixup(inode_t *h)
{
    if (IS_RED(h->right) && !IS_RED(h->left))   h = rotate_left(h);
    if (IS_RED(h->left)  && IS_RED(h->left->left)) h = rotate_right(h);
    if (IS_RED(h->left)  && IS_RED(h->right))   flip_colours(h);
    aug(h);
    return h;
}

/* ---- insertion ----------------------------------------------------------- */

static inode_t *
insert(inode_t *h, int64_t lo, int64_t hi, void *val)
{
    if (h == NULL)
    {
        inode_t *n   = op_malloc(sizeof(*n));
        n->lo        = lo;
        n->max_end   = hi;
        n->red       = true;
        n->left      = NULL;
        n->right     = NULL;
        segment_t *s = op_malloc(sizeof(*s));
        s->hi  = hi;
        s->val = val;
        s->next = NULL;
        n->segs = s;
        return n;
    }

    if (lo < h->lo)
        h->left  = insert(h->left,  lo, hi, val);
    else if (lo > h->lo)
        h->right = insert(h->right, lo, hi, val);
    else
    {
        /* Same lo — prepend a new segment to the chain. */
        segment_t *s = op_malloc(sizeof(*s));
        s->hi   = hi;
        s->val  = val;
        s->next = h->segs;
        h->segs = s;
    }

    return fixup(h);
}

/* ---- deletion ------------------------------------------------------------ */

static inode_t *
move_red_left(inode_t *h)
{
    flip_colours(h);
    if (IS_RED(h->right->left))
    {
        h->right = rotate_right(h->right);
        h        = rotate_left(h);
        flip_colours(h);
    }
    return h;
}

static inode_t *
move_red_right(inode_t *h)
{
    flip_colours(h);
    if (IS_RED(h->left->left))
    {
        h = rotate_right(h);
        flip_colours(h);
    }
    return h;
}

static inode_t *tree_min(inode_t *h)
{
    while (h->left) h = h->left;
    return h;
}

/* Remove the minimum node from the subtree rooted at h. */
static inode_t *
del_min(inode_t *h)
{
    if (h->left == NULL)
    {
        /* Free all segments on the minimum node. */
        segment_t *s = h->segs;
        while (s) { segment_t *nx = s->next; op_free(s); s = nx; }
        op_free(h);
        return NULL;
    }
    if (!IS_RED(h->left) && !IS_RED(h->left->left))
        h = move_red_left(h);
    h->left = del_min(h->left);
    return fixup(h);
}

/*
 * del — remove one segment (lo, hi, val) from the subtree.
 * *found is set to true if the segment was found and removed.
 */
static inode_t *
del(inode_t *h, int64_t lo, int64_t hi, void *val, bool *found)
{
    if (h == NULL)
        return NULL;

    if (lo < h->lo)
    {
        if (h->left == NULL) return h;
        if (!IS_RED(h->left) && !IS_RED(h->left->left))
            h = move_red_left(h);
        h->left = del(h->left, lo, hi, val, found);
    }
    else
    {
        if (IS_RED(h->left))
            h = rotate_right(h);

        if (lo == h->lo && h->right == NULL)
        {
            /* Leaf (or near-leaf after rotation). Try to remove segment. */
            segment_t **pp = &h->segs;
            while (*pp)
            {
                segment_t *s = *pp;
                if (s->hi == hi && s->val == val)
                {
                    *pp    = s->next;
                    op_free(s);
                    *found = true;
                    break;
                }
                pp = &s->next;
            }
            if (h->segs == NULL)
            {
                op_free(h);
                return NULL;
            }
            aug(h);
            return h;
        }

        if (h->right == NULL)
            return fixup(h);

        if (!IS_RED(h->right) && !IS_RED(h->right->left))
            h = move_red_right(h);

        if (lo == h->lo)
        {
            /* Remove from this node's segment chain, then steal successor
             * if the chain becomes empty. */
            segment_t **pp = &h->segs;
            while (*pp)
            {
                segment_t *s = *pp;
                if (s->hi == hi && s->val == val)
                {
                    *pp    = s->next;
                    op_free(s);
                    *found = true;
                    break;
                }
                pp = &s->next;
            }
            if (h->segs == NULL)
            {
                /* Steal the in-order successor to replace this node. */
                inode_t *succ = tree_min(h->right);
                h->lo   = succ->lo;
                /* Steal all segments from successor and free it. */
                for (segment_t *s = succ->segs; s; s = s->next)
                {
                    /* Prepend a copy to h. */
                    segment_t *ns = op_malloc(sizeof(*ns));
                    ns->hi   = s->hi;
                    ns->val  = s->val;
                    ns->next = h->segs;
                    h->segs  = ns;
                }
                /* Remove the (now-copied) successor node via del_min. */
                h->right = del_min(h->right);
            }
        }
        else
        {
            h->right = del(h->right, lo, hi, val, found);
        }
    }

    return fixup(h);
}

/* ---- queries ------------------------------------------------------------- */

typedef struct { int64_t a; int64_t b; op_itree_each_t fn; void *ud; bool stop; } qctx_t;

/* Visit all segments at node n that overlap [ctx->a, ctx->b]. */
static void
visit_segs(inode_t *n, qctx_t *ctx)
{
    for (segment_t *s = n->segs; s && !ctx->stop; s = s->next)
    {
        if (s->hi >= ctx->a && n->lo <= ctx->b)
        {
            if (!ctx->fn(n->lo, s->hi, s->val, ctx->ud))
                ctx->stop = true;
        }
    }
}

static void
query_overlap(inode_t *h, qctx_t *ctx)
{
    if (h == NULL || ctx->stop)
        return;
    /* Prune: if h->max_end < ctx->a, no interval in this subtree can overlap. */
    if (h->max_end < ctx->a)
        return;
    /* Prune: if h->lo > ctx->b, left subtree might still have matches but
     * right subtree's lo values are all > ctx->b, so skip right. */
    query_overlap(h->left, ctx);
    if (ctx->stop)
        return;
    if (h->lo <= ctx->b)
    {
        visit_segs(h, ctx);
        if (!ctx->stop)
            query_overlap(h->right, ctx);
    }
}

/* ---- destructor walker --------------------------------------------------- */

static void
walk_free(inode_t *h, op_itree_free_t fn, void *ud)
{
    if (h == NULL)
        return;
    walk_free(h->left,  fn, ud);
    walk_free(h->right, fn, ud);
    segment_t *s = h->segs;
    while (s)
    {
        segment_t *nx = s->next;
        if (fn) fn(s->val, ud);
        op_free(s);
        s = nx;
    }
    op_free(h);
}

/* ---- public API ---------------------------------------------------------- */

op_itree_t *
op_itree_create(const char *name)
{
    op_itree_t *t = op_malloc(sizeof(*t));
    t->root  = NULL;
    t->count = 0;
    t->name  = name;
    return t;
}

void
op_itree_destroy(op_itree_t *t, op_itree_free_t free_fn, void *ud)
{
    walk_free(t->root, free_fn, ud);
    op_free(t);
}

int
op_itree_insert(op_itree_t *t, int64_t lo, int64_t hi, void *val)
{
    if (hi < lo)
        return -1;
    t->root = insert(t->root, lo, hi, val);
    t->root->red = false;     /* root is always black */
    aug(t->root);
    t->count++;
    return 1;
}

int
op_itree_delete(op_itree_t *t, int64_t lo, int64_t hi, void *val)
{
    if (t->root == NULL)
        return 0;
    bool found = false;
    t->root = del(t->root, lo, hi, val, &found);
    if (t->root)
        t->root->red = false;
    if (found)
        t->count--;
    return found ? 1 : 0;
}

void
op_itree_stab(const op_itree_t *t, int64_t x,
              op_itree_each_t fn, void *ud)
{
    qctx_t ctx = { .a = x, .b = x, .fn = fn, .ud = ud, .stop = false };
    query_overlap(t->root, &ctx);
}

void
op_itree_overlap(const op_itree_t *t, int64_t a, int64_t b,
                 op_itree_each_t fn, void *ud)
{
    if (a > b) return;
    qctx_t ctx = { .a = a, .b = b, .fn = fn, .ud = ud, .stop = false };
    query_overlap(t->root, &ctx);
}

/* First-stab helper — returns on first match. */
typedef struct { int64_t x; void *result; } stab1_ctx_t;

static bool
stab1_cb(int64_t lo, int64_t hi, void *val, void *ud)
{
    (void)lo; (void)hi;
    stab1_ctx_t *c = ud;
    c->result = val;
    return false;  /* stop at first */
}

void *
op_itree_first_stab(const op_itree_t *t, int64_t x)
{
    stab1_ctx_t c = { .x = x, .result = NULL };
    op_itree_stab(t, x, stab1_cb, &c);
    return c.result;
}

size_t
op_itree_count(const op_itree_t *t)
{
    return t->count;
}

const char *
op_itree_name(const op_itree_t *t)
{
    return t->name;
}
