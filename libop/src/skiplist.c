/*
 * libop: ophion support library.
 * skiplist.c: Probabilistic skip list (ordered map).
 *
 * A skip list is a randomised ordered structure.  Each node is promoted to
 * higher levels with probability p = 0.25; the sentinel head node spans all
 * SKIPLIST_MAX_LEVEL (32) levels.  Expected height is log_{1/p}(n) ≈ 5 for
 * n = 1 000, 10 for n = 1 000 000.
 *
 * Level 0 is doubly-linked (forward + prev) to support O(n) reverse traversal
 * without a separate array.
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

/* ---- constants ----------------------------------------------------------- */

#define SKIPLIST_MAX_LEVEL 32

/* ---- node ---------------------------------------------------------------- */

typedef struct slnode
{
    void          *key;
    void          *val;
    int            level;        /* number of forward[] slots            */
    struct slnode *prev;         /* level-0 backward pointer             */
    struct slnode *forward[];    /* forward[0..level-1]                  */
} slnode_t;

/* ---- list ---------------------------------------------------------------- */

struct op_skiplist
{
    slnode_t          *head;     /* sentinel; key/val = NULL             */
    slnode_t          *tail;     /* last real node, or NULL if empty     */
    op_skiplist_cmp_t  cmp;
    size_t             size;
    int                level;    /* highest level with any real nodes    */
    const char        *name;
};

/* ---- helpers ------------------------------------------------------------- */

static slnode_t *
node_new(int level, void *key, void *val)
{
    slnode_t *n = op_malloc(sizeof(*n) + (size_t)level * sizeof(slnode_t *));
    n->key   = key;
    n->val   = val;
    n->level = level;
    n->prev  = NULL;
    memset(n->forward, 0, (size_t)level * sizeof(slnode_t *));
    return n;
}

/*
 * random_level — geometric distribution with p=0.25.
 * On average produces level L with probability (3/4)^(L-1) * (1/4).
 */
static int
random_level(void)
{
    int lvl = 1;
    while (lvl < SKIPLIST_MAX_LEVEL && (arc4random() & 3u) == 0)
        lvl++;
    return lvl;
}

/* ---- lifecycle ----------------------------------------------------------- */

op_skiplist_t *
op_skiplist_create(const char *name, op_skiplist_cmp_t cmp)
{
    op_skiplist_t *sl = op_malloc(sizeof(*sl));
    sl->head  = node_new(SKIPLIST_MAX_LEVEL, NULL, NULL);
    sl->tail  = NULL;
    sl->cmp   = cmp;
    sl->size  = 0;
    sl->level = 1;
    sl->name  = name;
    return sl;
}

void
op_skiplist_destroy(op_skiplist_t *sl, op_skiplist_free_t free_fn, void *ud)
{
    slnode_t *n = sl->head->forward[0];
    while (n != NULL)
    {
        slnode_t *next = n->forward[0];
        if (free_fn)
            free_fn(n->key, n->val, ud);
        op_free(n);
        n = next;
    }
    op_free(sl->head);
    op_free(sl);
}

/* ---- mutation ------------------------------------------------------------ */

int
op_skiplist_set(op_skiplist_t *sl, void *key, void *val, void **old_val)
{
    slnode_t *update[SKIPLIST_MAX_LEVEL];
    slnode_t *x = sl->head;

    for (int i = sl->level - 1; i >= 0; i--)
    {
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) < 0)
            x = x->forward[i];
        update[i] = x;
    }

    x = x->forward[0];

    if (x != NULL && sl->cmp(x->key, key) == 0)
    {
        /* Update in place. */
        if (old_val) *old_val = x->val;
        x->key = key;
        x->val = val;
        return 0;
    }

    /* New node. */
    int lvl = random_level();
    if (lvl > sl->level)
    {
        for (int i = sl->level; i < lvl; i++)
            update[i] = sl->head;
        sl->level = lvl;
    }

    slnode_t *n = node_new(lvl, key, val);

    for (int i = 0; i < lvl; i++)
    {
        n->forward[i] = update[i]->forward[i];
        update[i]->forward[i] = n;
    }

    /* Level-0 backward link. */
    n->prev = update[0];
    if (n->forward[0] != NULL)
        n->forward[0]->prev = n;
    else
        sl->tail = n;   /* n is the new last node */

    sl->size++;
    if (old_val) *old_val = NULL;
    return 1;
}

void *
op_skiplist_del(op_skiplist_t *sl, const void *key)
{
    slnode_t *update[SKIPLIST_MAX_LEVEL];
    slnode_t *x = sl->head;

    for (int i = sl->level - 1; i >= 0; i--)
    {
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) < 0)
            x = x->forward[i];
        update[i] = x;
    }

    x = x->forward[0];

    if (x == NULL || sl->cmp(x->key, key) != 0)
        return NULL;

    /* Splice out of all levels. */
    for (int i = 0; i < sl->level; i++)
    {
        if (update[i]->forward[i] != x)
            break;
        update[i]->forward[i] = x->forward[i];
    }

    /* Fix level-0 backward link. */
    if (x->forward[0] != NULL)
        x->forward[0]->prev = x->prev;
    else
        sl->tail = (x->prev != sl->head) ? x->prev : NULL;

    /* Shrink active level count. */
    while (sl->level > 1 && sl->head->forward[sl->level - 1] == NULL)
        sl->level--;

    void *val = x->val;
    op_free(x);
    sl->size--;
    return val;
}

/* ---- lookup -------------------------------------------------------------- */

void *
op_skiplist_get(const op_skiplist_t *sl, const void *key)
{
    const slnode_t *x = sl->head;
    for (int i = sl->level - 1; i >= 0; i--)
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) < 0)
            x = x->forward[i];
    x = x->forward[0];
    return (x != NULL && sl->cmp(x->key, key) == 0) ? x->val : NULL;
}

bool
op_skiplist_has(const op_skiplist_t *sl, const void *key)
{
    const slnode_t *x = sl->head;
    for (int i = sl->level - 1; i >= 0; i--)
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) < 0)
            x = x->forward[i];
    x = x->forward[0];
    return x != NULL && sl->cmp(x->key, key) == 0;
}

void *
op_skiplist_min_key(const op_skiplist_t *sl)
{
    return sl->head->forward[0] ? sl->head->forward[0]->key : NULL;
}

void *
op_skiplist_max_key(const op_skiplist_t *sl)
{
    return sl->tail ? sl->tail->key : NULL;
}

void *
op_skiplist_lower_bound(const op_skiplist_t *sl, const void *key)
{
    const slnode_t *x = sl->head;
    for (int i = sl->level - 1; i >= 0; i--)
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) < 0)
            x = x->forward[i];
    x = x->forward[0];
    return x ? x->key : NULL;
}

void *
op_skiplist_upper_bound(const op_skiplist_t *sl, const void *key)
{
    const slnode_t *x = sl->head;
    for (int i = sl->level - 1; i >= 0; i--)
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, key) <= 0)
            x = x->forward[i];
    x = x->forward[0];
    return x ? x->key : NULL;
}

/* ---- traversal ----------------------------------------------------------- */

void
op_skiplist_foreach(const op_skiplist_t *sl, op_skiplist_each_t fn, void *ud)
{
    for (slnode_t *n = sl->head->forward[0]; n != NULL; n = n->forward[0])
        if (!fn(n->key, n->val, ud))
            return;
}

void
op_skiplist_foreach_rev(const op_skiplist_t *sl, op_skiplist_each_t fn, void *ud)
{
    if (sl->tail == NULL)
        return;
    for (slnode_t *n = sl->tail; n != sl->head; n = n->prev)
        if (!fn(n->key, n->val, ud))
            return;
}

/* ---- iterator ------------------------------------------------------------ */

void
op_skiplist_iter_init(op_skiplist_iter_t *it, const op_skiplist_t *sl)
{
    it->cur = sl->head->forward[0];
}

void
op_skiplist_iter_lower(op_skiplist_iter_t *it, const op_skiplist_t *sl,
                       const void *lower)
{
    const slnode_t *x = sl->head;
    for (int i = sl->level - 1; i >= 0; i--)
        while (x->forward[i] != NULL &&
               sl->cmp(x->forward[i]->key, lower) < 0)
            x = x->forward[i];
    it->cur = x->forward[0];
}

bool
op_skiplist_iter_next(op_skiplist_iter_t *it, void **key, void **val)
{
    const slnode_t *n = it->cur;
    if (n == NULL)
        return false;
    if (key) *key = n->key;
    if (val) *val = n->val;
    it->cur = n->forward[0];
    return true;
}

/* ---- introspection ------------------------------------------------------- */

size_t
op_skiplist_size(const op_skiplist_t *sl)
{
    return sl->size;
}

const char *
op_skiplist_name(const op_skiplist_t *sl)
{
    return sl->name;
}

/* ---- convenience comparators --------------------------------------------- */

int
op_skiplist_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int
op_skiplist_cmp_istr(const void *a, const void *b)
{
    return op_strcasecmp((const char *)a, (const char *)b);
}

int
op_skiplist_cmp_u64(const void *a, const void *b)
{
    uint64_t ua = (uint64_t)(uintptr_t)a;
    uint64_t ub = (uint64_t)(uintptr_t)b;
    return (ua > ub) - (ua < ub);
}

int
op_skiplist_cmp_ptr(const void *a, const void *b)
{
    return (a > b) - (a < b);
}
