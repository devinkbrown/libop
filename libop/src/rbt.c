/*
 * libop: ophion support library.
 * rbt.c: Left-leaning red-black tree (LLRB).
 *
 * Implementation of Sedgewick's LLRB (2008 variant).  Maintains the
 * 2-3-4 tree invariant via three operations:
 *
 *   rotate_left  — fix a right-leaning red link
 *   rotate_right — fix two consecutive left-leaning red links
 *   flip_colours — split a 4-node into two 2-nodes
 *
 * Both insert and delete use these three operations in a recursive
 * top-down + fixup-on-the-way-up style.  Delete uses an additional
 * "move_red_left" / "move_red_right" to push red links toward the
 * deleted node so it can be removed as a red leaf.
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

/* ---- node ---------------------------------------------------------------- */

#define RED   true
#define BLACK false

typedef struct rbt_node
{
    void            *key;
    void            *val;
    struct rbt_node *left;
    struct rbt_node *right;
    bool             colour;   /* RED or BLACK */
} rbt_node_t;

/* ---- tree ---------------------------------------------------------------- */

struct op_rbt
{
    rbt_node_t *root;
    op_rbt_cmp_t cmp;
    size_t       size;
    const char  *name;
};

/* ---- helpers ------------------------------------------------------------- */

static inline bool
is_red(const rbt_node_t *h)
{
    return h != NULL && h->colour == RED;
}

static rbt_node_t *
node_alloc(void *key, void *val)
{
    rbt_node_t *n = op_malloc(sizeof(*n));
    n->key    = key;
    n->val    = val;
    n->left   = NULL;
    n->right  = NULL;
    n->colour = RED;   /* new nodes are red (they form 3-nodes or 4-nodes) */
    return n;
}

/* ---- structural transformations ------------------------------------------ */

static rbt_node_t *
rotate_left(rbt_node_t *h)
{
    rbt_node_t *x = h->right;
    h->right  = x->left;
    x->left   = h;
    x->colour = h->colour;
    h->colour = RED;
    return x;
}

static rbt_node_t *
rotate_right(rbt_node_t *h)
{
    rbt_node_t *x = h->left;
    h->left   = x->right;
    x->right  = h;
    x->colour = h->colour;
    h->colour = RED;
    return x;
}

static void
flip_colours(rbt_node_t *h)
{
    h->colour        = !h->colour;
    h->left->colour  = !h->left->colour;
    h->right->colour = !h->right->colour;
}

/* Standard LLRB fixup: called bottom-up on the way back from recursion. */
static rbt_node_t *
fixup(rbt_node_t *h)
{
    if (is_red(h->right) && !is_red(h->left))      h = rotate_left(h);
    if (is_red(h->left)  && is_red(h->left->left)) h = rotate_right(h);
    if (is_red(h->left)  && is_red(h->right))       flip_colours(h);
    return h;
}

/* ---- insert -------------------------------------------------------------- */

static rbt_node_t *
insert(rbt_node_t *h, void *key, void *val, op_rbt_cmp_t cmp,
       void **old_val, int *inserted)
{
    if (h == NULL)
    {
        *inserted = 1;
        return node_alloc(key, val);
    }

    int c = cmp(key, h->key);
    if (c < 0)
        h->left  = insert(h->left,  key, val, cmp, old_val, inserted);
    else if (c > 0)
        h->right = insert(h->right, key, val, cmp, old_val, inserted);
    else
    {
        /* Key exists — update value and key pointer. */
        if (old_val)
            *old_val = h->val;
        h->key = key;
        h->val = val;
        *inserted = 0;
    }

    return fixup(h);
}

/* ---- delete -------------------------------------------------------------- */

/*
 * move_red_left — called when h is a 2-node and h->left is a 2-node.
 * Temporarily merges h with its right sibling so we can descend left.
 */
static rbt_node_t *
move_red_left(rbt_node_t *h)
{
    flip_colours(h);
    if (is_red(h->right->left))
    {
        h->right = rotate_right(h->right);
        h        = rotate_left(h);
        flip_colours(h);
    }
    return h;
}

/*
 * move_red_right — called when h is a 2-node and h->right is a 2-node.
 */
static rbt_node_t *
move_red_right(rbt_node_t *h)
{
    flip_colours(h);
    if (is_red(h->left->left))
    {
        h = rotate_right(h);
        flip_colours(h);
    }
    return h;
}

/* Find the minimum node in the subtree rooted at h. */
static rbt_node_t *
tree_min(rbt_node_t *h)
{
    while (h->left != NULL)
        h = h->left;
    return h;
}

/* Delete the minimum node from the subtree; returns new root. */
static rbt_node_t *
del_min(rbt_node_t *h)
{
    if (h->left == NULL)
    {
        op_free(h);
        return NULL;
    }
    if (!is_red(h->left) && !is_red(h->left->left))
        h = move_red_left(h);
    h->left = del_min(h->left);
    return fixup(h);
}

/*
 * del — recursive delete.
 *
 * found_val: set to the deleted node's value.
 * found:     set to true if the key was found and deleted; false if not found.
 *
 * Using a separate bool avoids the NULL-as-sentinel problem where val=NULL
 * would be indistinguishable from "key not found".
 */
static rbt_node_t *
del(rbt_node_t *h, const void *key, op_rbt_cmp_t cmp,
    void **found_val, bool *found)
{
    if (h == NULL)
        return NULL;

    if (cmp(key, h->key) < 0)
    {
        if (h->left == NULL)
            return h;   /* not found — key < h but no left child */
        if (!is_red(h->left) && !is_red(h->left->left))
            h = move_red_left(h);
        h->left = del(h->left, key, cmp, found_val, found);
    }
    else
    {
        /* Lean right before going right or deleting. */
        if (is_red(h->left))
            h = rotate_right(h);

        /* Exact match at a leaf → delete this node. */
        if (cmp(key, h->key) == 0 && h->right == NULL)
        {
            *found_val = h->val;
            *found     = true;
            op_free(h);
            return NULL;
        }

        if (h->right == NULL)
            return fixup(h);   /* not found — key > h but no right child */

        if (!is_red(h->right) && !is_red(h->right->left))
            h = move_red_right(h);

        if (cmp(key, h->key) == 0)
        {
            /* Delete at an internal node: replace with in-order successor. */
            *found_val = h->val;
            *found     = true;
            rbt_node_t *s = tree_min(h->right);
            h->key   = s->key;
            h->val   = s->val;
            h->right = del_min(h->right);
        }
        else
        {
            h->right = del(h->right, key, cmp, found_val, found);
        }
    }

    return fixup(h);
}

/* ---- construction / destruction ------------------------------------------ */

op_rbt_t *
op_rbt_create(const char *name, op_rbt_cmp_t cmp)
{
    op_rbt_t *t = op_malloc(sizeof(*t));
    t->root = NULL;
    t->cmp  = cmp;
    t->size = 0;
    t->name = name;
    return t;
}

static void
destroy_r(rbt_node_t *h, op_rbt_free_t fn, void *ud)
{
    if (h == NULL)
        return;
    destroy_r(h->left,  fn, ud);
    destroy_r(h->right, fn, ud);
    if (fn)
        fn(h->key, h->val, ud);
    op_free(h);
}

void
op_rbt_destroy(op_rbt_t *t, op_rbt_free_t fn, void *ud)
{
    destroy_r(t->root, fn, ud);
    op_free(t);
}

/* ---- mutation ------------------------------------------------------------ */

int
op_rbt_set(op_rbt_t *t, void *key, void *val, void **old_val)
{
    int inserted = 0;
    if (old_val)
        *old_val = NULL;
    t->root = insert(t->root, key, val, t->cmp, old_val, &inserted);
    t->root->colour = BLACK;   /* root is always black */
    if (inserted)
        t->size++;
    return inserted;
}

void *
op_rbt_del(op_rbt_t *t, const void *key)
{
    void *found_val = NULL;
    bool  found     = false;
    t->root = del(t->root, key, t->cmp, &found_val, &found);
    if (t->root != NULL)
        t->root->colour = BLACK;
    if (found)
        t->size--;
    return found_val;
}

/* ---- lookup -------------------------------------------------------------- */

void *
op_rbt_get(const op_rbt_t *t, const void *key)
{
    rbt_node_t *h = t->root;
    while (h != NULL)
    {
        int c = t->cmp(key, h->key);
        if      (c < 0) h = h->left;
        else if (c > 0) h = h->right;
        else            return h->val;
    }
    return NULL;
}

bool
op_rbt_has(const op_rbt_t *t, const void *key)
{
    rbt_node_t *h = t->root;
    while (h != NULL)
    {
        int c = t->cmp(key, h->key);
        if      (c < 0) h = h->left;
        else if (c > 0) h = h->right;
        else            return true;
    }
    return false;
}

void *
op_rbt_min_key(const op_rbt_t *t)
{
    if (t->root == NULL)
        return NULL;
    rbt_node_t *h = t->root;
    while (h->left != NULL)
        h = h->left;
    return h->key;
}

void *
op_rbt_max_key(const op_rbt_t *t)
{
    if (t->root == NULL)
        return NULL;
    rbt_node_t *h = t->root;
    while (h->right != NULL)
        h = h->right;
    return h->key;
}

void *
op_rbt_lower_bound(const op_rbt_t *t, const void *key)
{
    rbt_node_t *h = t->root;
    void *best = NULL;
    while (h != NULL)
    {
        int c = t->cmp(key, h->key);
        if (c <= 0)
        {
            best = h->key;   /* h->key >= key, candidate */
            h = h->left;
        }
        else
        {
            h = h->right;
        }
    }
    return best;
}

void *
op_rbt_upper_bound(const op_rbt_t *t, const void *key)
{
    rbt_node_t *h = t->root;
    void *best = NULL;
    while (h != NULL)
    {
        int c = t->cmp(key, h->key);
        if (c < 0)
        {
            best = h->key;   /* h->key > key, candidate */
            h = h->left;
        }
        else
        {
            h = h->right;
        }
    }
    return best;
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_rbt_size(const op_rbt_t *t)
{
    return t->size;
}

const char *
op_rbt_name(const op_rbt_t *t)
{
    return t->name;
}

/* ---- in-order traversal -------------------------------------------------- */

static bool
foreach_r(rbt_node_t *h, op_rbt_each_t fn, void *ud)
{
    if (h == NULL)
        return true;
    if (!foreach_r(h->left, fn, ud))
        return false;
    if (!fn(h->key, h->val, ud))
        return false;
    return foreach_r(h->right, fn, ud);
}

void
op_rbt_foreach(const op_rbt_t *t, op_rbt_each_t fn, void *ud)
{
    foreach_r(t->root, fn, ud);
}

static bool
foreach_rev_r(rbt_node_t *h, op_rbt_each_t fn, void *ud)
{
    if (h == NULL)
        return true;
    if (!foreach_rev_r(h->right, fn, ud))
        return false;
    if (!fn(h->key, h->val, ud))
        return false;
    return foreach_rev_r(h->left, fn, ud);
}

void
op_rbt_foreach_rev(const op_rbt_t *t, op_rbt_each_t fn, void *ud)
{
    foreach_rev_r(t->root, fn, ud);
}

/* ---- stack-based iterators ----------------------------------------------- */

/*
 * Push all left-spine nodes from h onto the stack.
 * This positions the iterator at the leftmost (minimum) descendant.
 */
static void
push_left(op_rbt_iter_t *it, rbt_node_t *h)
{
    while (h != NULL && it->sp < OP_RBT_ITER_DEPTH - 1)
    {
        it->stack[++it->sp] = h;
        h = h->left;
    }
}

void
op_rbt_iter_init(op_rbt_iter_t *it, const op_rbt_t *t)
{
    it->sp = -1;
    push_left(it, t->root);
}

void
op_rbt_iter_lower(op_rbt_iter_t *it, const op_rbt_t *t, const void *lower)
{
    it->sp = -1;
    rbt_node_t *h = t->root;
    while (h != NULL && it->sp < OP_RBT_ITER_DEPTH - 1)
    {
        int c = t->cmp(lower, h->key);
        if (c <= 0)
        {
            it->stack[++it->sp] = h;   /* h is a candidate (h->key >= lower) */
            h = h->left;
        }
        else
        {
            h = h->right;
        }
    }
}

bool
op_rbt_iter_next(op_rbt_iter_t *it, void **key, void **val)
{
    if (it->sp < 0)
        return false;

    rbt_node_t *cur = it->stack[it->sp--];
    if (key) *key = cur->key;
    if (val) *val = cur->val;

    /* Push the right subtree's left spine for the next iteration. */
    push_left(it, cur->right);
    return true;
}

/* ---- convenience comparators --------------------------------------------- */

int
op_rbt_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int
op_rbt_cmp_istr(const void *a, const void *b)
{
    return op_strcasecmp((const char *)a, (const char *)b);
}

int
op_rbt_cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

int
op_rbt_cmp_ptr(const void *a, const void *b)
{
    return (a > b) - (a < b);
}
