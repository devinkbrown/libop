/*
 * libop: ophion support library.
 * graph.c: Directed weighted graph with BFS/DFS/topo-sort/Dijkstra.
 *
 * Internal layout
 * ---------------
 * Nodes are stored in a flat gnode_t array (slot table).  Each node carries
 * its outgoing edge list as a plain C array of gedge_t {to, weight}.  A
 * free-list of recycled IDs keeps allocation O(1) amortised.
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

/* ---- internal types ------------------------------------------------------ */

typedef struct
{
    op_graph_id_t  to;
    int64_t        weight;
} gedge_t;

typedef struct
{
    void          *val;
    bool           alive;
    uint32_t       in_deg;
    gedge_t       *edges;
    uint32_t       n_edges;
    uint32_t       edges_cap;
} gnode_t;

struct op_graph
{
    gnode_t       *nodes;
    uint32_t       n_slots;
    uint32_t       slots_cap;
    uint32_t      *free_list;
    uint32_t       n_free;
    uint32_t       n_alive;
    size_t         n_edges;
    const char    *name;
};

/* ---- helpers ------------------------------------------------------------- */

static inline bool
valid(const op_graph_t *g, op_graph_id_t id)
{
    return id < g->n_slots && g->nodes[id].alive;
}

static void
edge_push(gnode_t *n, op_graph_id_t to, int64_t w)
{
    if (n->n_edges == n->edges_cap)
    {
        n->edges_cap = n->edges_cap ? n->edges_cap * 2 : 4;
        n->edges = op_realloc(n->edges, n->edges_cap * sizeof(gedge_t));
    }
    n->edges[n->n_edges++] = (gedge_t){ to, w };
}

static gedge_t *
edge_find(const gnode_t *n, op_graph_id_t to)
{
    for (uint32_t i = 0; i < n->n_edges; i++)
        if (n->edges[i].to == to)
            return &n->edges[i];
    return NULL;
}

/* Remove edge to 'to' from n's list; does not update in_degree. */
static bool
edge_remove(gnode_t *n, op_graph_id_t to)
{
    for (uint32_t i = 0; i < n->n_edges; i++)
    {
        if (n->edges[i].to == to)
        {
            n->edges[i] = n->edges[--n->n_edges];
            return true;
        }
    }
    return false;
}

/* ---- lifecycle ----------------------------------------------------------- */

op_graph_t *
op_graph_create(const char *name)
{
    op_graph_t *g = op_malloc(sizeof(*g));
    g->nodes     = NULL;
    g->n_slots   = 0;
    g->slots_cap = 0;
    g->free_list = NULL;
    g->n_free    = 0;
    g->n_alive   = 0;
    g->n_edges   = 0;
    g->name      = name;
    return g;
}

void
op_graph_destroy(op_graph_t *g,
                 void (*free_fn)(void *val, void *ud), void *ud)
{
    for (uint32_t i = 0; i < g->n_slots; i++)
    {
        if (!g->nodes[i].alive)
            continue;
        if (free_fn)
            free_fn(g->nodes[i].val, ud);
        op_free(g->nodes[i].edges);
    }
    op_free(g->nodes);
    op_free(g->free_list);
    op_free(g);
}

/* ---- nodes --------------------------------------------------------------- */

op_graph_id_t
op_graph_add_node(op_graph_t *g, void *val)
{
    op_graph_id_t id;

    if (g->n_free > 0)
    {
        id = g->free_list[--g->n_free];
    }
    else
    {
        if (g->n_slots == g->slots_cap)
        {
            g->slots_cap = g->slots_cap ? g->slots_cap * 2 : 8;
            g->nodes = op_realloc(g->nodes, g->slots_cap * sizeof(gnode_t));
            /* Also grow free_list to same cap (worst case all slots freed). */
            g->free_list = op_realloc(g->free_list,
                                      g->slots_cap * sizeof(uint32_t));
        }
        id = g->n_slots++;
    }

    g->nodes[id] = (gnode_t){ .val = val, .alive = true,
                               .in_deg = 0, .edges = NULL,
                               .n_edges = 0, .edges_cap = 0 };
    g->n_alive++;
    return id;
}

void
op_graph_set_node(op_graph_t *g, op_graph_id_t id, void *val)
{
    if (valid(g, id))
        g->nodes[id].val = val;
}

void *
op_graph_get_node(const op_graph_t *g, op_graph_id_t id)
{
    return valid(g, id) ? g->nodes[id].val : NULL;
}

bool
op_graph_has_node(const op_graph_t *g, op_graph_id_t id)
{
    return valid(g, id);
}

void
op_graph_del_node(op_graph_t *g, op_graph_id_t id)
{
    if (!valid(g, id))
        return;

    gnode_t *n = &g->nodes[id];

    /* Remove all outgoing edges and decrement targets' in_degree. */
    for (uint32_t i = 0; i < n->n_edges; i++)
    {
        op_graph_id_t dst = n->edges[i].to;
        if (valid(g, dst))
            g->nodes[dst].in_deg--;
    }
    g->n_edges -= n->n_edges;

    /* Remove all incoming edges (scan all nodes — kept simple, del is rare). */
    for (uint32_t i = 0; i < g->n_slots; i++)
    {
        if (!g->nodes[i].alive || i == id)
            continue;
        if (edge_remove(&g->nodes[i], id))
            g->n_edges--;
    }

    op_free(n->edges);
    n->alive  = false;
    n->edges  = NULL;
    n->n_edges = 0;
    n->edges_cap = 0;
    g->n_alive--;
    g->free_list[g->n_free++] = id;
}

/* ---- edges --------------------------------------------------------------- */

int
op_graph_add_edge(op_graph_t *g, op_graph_id_t from, op_graph_id_t to,
                  int64_t weight)
{
    if (!valid(g, from) || !valid(g, to))
        return -1;

    gedge_t *e = edge_find(&g->nodes[from], to);
    if (e)
    {
        e->weight = weight;
        return 0;
    }

    edge_push(&g->nodes[from], to, weight);
    g->nodes[to].in_deg++;
    g->n_edges++;
    return 1;
}

int
op_graph_del_edge(op_graph_t *g, op_graph_id_t from, op_graph_id_t to)
{
    if (!valid(g, from) || !valid(g, to))
        return 0;
    if (!edge_remove(&g->nodes[from], to))
        return 0;
    g->nodes[to].in_deg--;
    g->n_edges--;
    return 1;
}

bool
op_graph_has_edge(const op_graph_t *g, op_graph_id_t from, op_graph_id_t to)
{
    return valid(g, from) && valid(g, to) &&
           edge_find(&g->nodes[from], to) != NULL;
}

int64_t
op_graph_edge_weight(const op_graph_t *g, op_graph_id_t from, op_graph_id_t to)
{
    if (!valid(g, from))
        return 0;
    gedge_t *e = edge_find(&g->nodes[from], to);
    return e ? e->weight : 0;
}

/* ---- BFS ----------------------------------------------------------------- */

void
op_graph_bfs(const op_graph_t *g, op_graph_id_t start,
             op_graph_visit_t fn, void *ud)
{
    if (!valid(g, start))
        return;

    /* visited array: stack-allocated for small graphs, heap otherwise. */
    bool *visited = op_calloc(g->n_slots, sizeof(bool));

    /* Simple FIFO queue using op_deque. */
    op_deque_t q;
    op_deque_init(&q, 64);

    visited[start] = true;
    op_deque_push_back(&q, (void *)(uintptr_t)start);

    while (!op_deque_empty(&q))
    {
        op_graph_id_t cur = (op_graph_id_t)(uintptr_t)op_deque_pop_front(&q);
        if (!fn(cur, g->nodes[cur].val, ud))
            break;

        gnode_t *n = &g->nodes[cur];
        for (uint32_t i = 0; i < n->n_edges; i++)
        {
            op_graph_id_t nb = n->edges[i].to;
            if (valid(g, nb) && !visited[nb])
            {
                visited[nb] = true;
                op_deque_push_back(&q, (void *)(uintptr_t)nb);
            }
        }
    }

    op_deque_fini(&q);
    op_free(visited);
}

/* ---- DFS ----------------------------------------------------------------- */

/* Iterative DFS using an explicit stack (op_deque as LIFO). */
void
op_graph_dfs(const op_graph_t *g, op_graph_id_t start,
             op_graph_visit_t fn, void *ud)
{
    if (!valid(g, start))
        return;

    bool *visited = op_calloc(g->n_slots, sizeof(bool));

    op_deque_t stack;
    op_deque_init(&stack, 64);

    op_deque_push_back(&stack, (void *)(uintptr_t)start);

    while (!op_deque_empty(&stack))
    {
        op_graph_id_t cur = (op_graph_id_t)(uintptr_t)op_deque_pop_back(&stack);
        if (visited[cur])
            continue;
        visited[cur] = true;

        if (!fn(cur, g->nodes[cur].val, ud))
            break;

        gnode_t *n = &g->nodes[cur];
        for (uint32_t i = 0; i < n->n_edges; i++)
        {
            op_graph_id_t nb = n->edges[i].to;
            if (valid(g, nb) && !visited[nb])
                op_deque_push_back(&stack, (void *)(uintptr_t)nb);
        }
    }

    op_deque_fini(&stack);
    op_free(visited);
}

/* ---- neighbors ----------------------------------------------------------- */

void
op_graph_neighbors(const op_graph_t *g, op_graph_id_t id,
                   op_graph_edge_visit_t fn, void *ud)
{
    if (!valid(g, id))
        return;
    gnode_t *n = &g->nodes[id];
    for (uint32_t i = 0; i < n->n_edges; i++)
        if (!fn(id, n->edges[i].to, n->edges[i].weight, ud))
            return;
}

/* ---- topological sort (Kahn's algorithm) --------------------------------- */

int
op_graph_topo_sort(const op_graph_t *g, op_graph_id_t *out, size_t cap)
{
    if (g->n_alive == 0)
        return 0;

    /* Copy in-degrees into a working array. */
    uint32_t *indeg = op_malloc(g->n_slots * sizeof(uint32_t));
    for (uint32_t i = 0; i < g->n_slots; i++)
        indeg[i] = g->nodes[i].alive ? g->nodes[i].in_deg : 0;

    /* Enqueue all zero-in-degree nodes. */
    op_deque_t q;
    op_deque_init(&q, g->n_alive);

    for (uint32_t i = 0; i < g->n_slots; i++)
        if (g->nodes[i].alive && indeg[i] == 0)
            op_deque_push_back(&q, (void *)(uintptr_t)i);

    int written = 0;

    while (!op_deque_empty(&q))
    {
        op_graph_id_t cur = (op_graph_id_t)(uintptr_t)op_deque_pop_front(&q);

        if ((size_t)written < cap)
            out[written] = cur;
        written++;

        gnode_t *n = &g->nodes[cur];
        for (uint32_t i = 0; i < n->n_edges; i++)
        {
            op_graph_id_t nb = n->edges[i].to;
            if (!valid(g, nb))
                continue;
            if (--indeg[nb] == 0)
                op_deque_push_back(&q, (void *)(uintptr_t)nb);
        }
    }

    op_deque_fini(&q);
    op_free(indeg);

    return ((uint32_t)written == g->n_alive) ? written : -1; /* -1 = cycle */
}

bool
op_graph_has_cycle(const op_graph_t *g)
{
    if (g->n_alive == 0)
        return false;
    op_graph_id_t *buf = op_malloc(g->n_alive * sizeof(op_graph_id_t));
    bool cycle = (op_graph_topo_sort(g, buf, g->n_alive) == -1);
    op_free(buf);
    return cycle;
}

/* ---- Dijkstra (single-source shortest path) ------------------------------ */

typedef struct
{
    int64_t       dist;
    op_graph_id_t id;
} dijkstra_entry_t;

static int
dijk_cmp(const void *a, const void *b)
{
    const dijkstra_entry_t *da = a;
    const dijkstra_entry_t *db = b;
    if (da->dist < db->dist) return -1;
    if (da->dist > db->dist) return  1;
    return 0;
}

int64_t
op_graph_shortest_path(const op_graph_t *g,
                       op_graph_id_t from, op_graph_id_t to,
                       op_graph_id_t *path, size_t cap)
{
    if (!valid(g, from) || !valid(g, to))
        return INT64_MAX;

    uint32_t n = g->n_slots;

    int64_t       *dist = op_malloc(n * sizeof(int64_t));
    op_graph_id_t *prev = op_malloc(n * sizeof(op_graph_id_t));
    bool          *done = op_calloc(n, sizeof(bool));

    for (uint32_t i = 0; i < n; i++)
    {
        dist[i] = INT64_MAX;
        prev[i] = OP_GRAPH_INVALID_ID;
    }
    dist[from] = 0;

    op_pqueue_t *pq = op_pqueue_create(dijk_cmp, g->n_alive);
    dijkstra_entry_t *start_e = op_malloc(sizeof(*start_e));
    start_e->dist = 0;
    start_e->id   = from;
    op_pqueue_push(pq, start_e);

    int64_t result = INT64_MAX;

    while (!op_pqueue_empty(pq))
    {
        dijkstra_entry_t *e = op_pqueue_pop(pq);
        op_graph_id_t cur   = e->id;
        int64_t       d     = e->dist;
        op_free(e);

        if (done[cur])
            continue;
        done[cur] = true;

        if (cur == to)
        {
            result = d;
            break;
        }

        gnode_t *node = &g->nodes[cur];
        for (uint32_t i = 0; i < node->n_edges; i++)
        {
            op_graph_id_t nb = node->edges[i].to;
            if (!valid(g, nb) || done[nb])
                continue;
            int64_t nd = d + node->edges[i].weight;
            if (nd < dist[nb])
            {
                dist[nb] = nd;
                prev[nb] = cur;
                dijkstra_entry_t *ne = op_malloc(sizeof(*ne));
                ne->dist = nd;
                ne->id   = nb;
                op_pqueue_push(pq, ne);
            }
        }
    }

    /* Free any remaining entries in the pqueue. */
    dijkstra_entry_t *leftover;
    while ((leftover = op_pqueue_pop(pq)) != NULL)
        op_free(leftover);
    op_pqueue_destroy(pq, NULL, NULL);

    /* Reconstruct path if requested and reachable. */
    if (path && cap > 0 && result != INT64_MAX)
    {
        /* Trace backwards from 'to'. */
        size_t plen = 0;
        op_graph_id_t cur = to;
        while (cur != OP_GRAPH_INVALID_ID)
        {
            plen++;
            cur = prev[cur];
        }
        /* Write in forward order. */
        size_t write = (plen < cap) ? plen : cap;
        cur = to;
        for (size_t i = write; i > 0; i--)
        {
            path[i - 1] = cur;
            cur = prev[cur];
        }
    }

    op_free(dist);
    op_free(prev);
    op_free(done);
    return result;
}

/* ---- iteration ----------------------------------------------------------- */

void
op_graph_foreach_node(const op_graph_t *g, op_graph_visit_t fn, void *ud)
{
    for (uint32_t i = 0; i < g->n_slots; i++)
        if (g->nodes[i].alive)
            if (!fn(i, g->nodes[i].val, ud))
                return;
}

void
op_graph_foreach_edge(const op_graph_t *g, op_graph_edge_visit_t fn, void *ud)
{
    for (uint32_t i = 0; i < g->n_slots; i++)
    {
        if (!g->nodes[i].alive)
            continue;
        gnode_t *n = &g->nodes[i];
        for (uint32_t j = 0; j < n->n_edges; j++)
            if (!fn(i, n->edges[j].to, n->edges[j].weight, ud))
                return;
    }
}

/* ---- introspection ------------------------------------------------------- */

size_t op_graph_node_count(const op_graph_t *g) { return g->n_alive; }
size_t op_graph_edge_count(const op_graph_t *g) { return g->n_edges; }
const char *op_graph_name(const op_graph_t *g)  { return g->name; }

size_t
op_graph_out_degree(const op_graph_t *g, op_graph_id_t id)
{
    return valid(g, id) ? g->nodes[id].n_edges : 0;
}

size_t
op_graph_in_degree(const op_graph_t *g, op_graph_id_t id)
{
    return valid(g, id) ? g->nodes[id].in_deg : 0;
}
