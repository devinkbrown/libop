/*
 * libop: ophion support library.
 * op_graph.h: Directed weighted graph.
 *
 * Overview
 * ========
 * op_graph is a directed, integer-node-ID graph backed by adjacency lists.
 * Nodes are identified by stable uint32_t IDs allocated by op_graph_add_node;
 * IDs are recycled via a free-list so the node table stays compact.
 *
 * Supported algorithms
 * ====================
 *   BFS  — breadth-first traversal from a start node
 *   DFS  — depth-first traversal from a start node
 *   Topo — Kahn's topological sort (returns −1 on cycle)
 *   Dijkstra — single-source shortest path (non-negative edge weights)
 *
 * Typical use (IRC server topology)
 * ==================================
 *   op_graph_t *net = op_graph_create("irc-net");
 *
 *   op_graph_id_t hub  = op_graph_add_node(net, hub_ptr);
 *   op_graph_id_t leaf = op_graph_add_node(net, leaf_ptr);
 *   op_graph_add_edge(net, hub, leaf, 1);
 *   op_graph_add_edge(net, leaf, hub, 1);   // bidirectional
 *
 *   op_graph_id_t path[64];
 *   int64_t dist = op_graph_shortest_path(net, src_id, dst_id, path, 64);
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_graph.h directly; include op_lib.h"
#endif

#ifndef LIBOP_GRAPH_H
#define LIBOP_GRAPH_H

/* ---- types --------------------------------------------------------------- */

typedef uint32_t op_graph_id_t;
#define OP_GRAPH_INVALID_ID  UINT32_MAX

/*
 * op_graph_visit_t — called for each node during BFS/DFS/foreach.
 * Return false to stop traversal early.
 */
typedef bool (*op_graph_visit_t)(op_graph_id_t id, void *val, void *ud);

/*
 * op_graph_edge_visit_t — called for each edge during foreach_edge /
 * op_graph_neighbors.  Return false to stop early.
 */
typedef bool (*op_graph_edge_visit_t)(op_graph_id_t from, op_graph_id_t to,
                                      int64_t weight, void *ud);

typedef struct op_graph op_graph_t;

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_graph_create — allocate an empty directed graph.
 * name is stored by pointer (use a string literal or permanent storage).
 */
op_graph_t *op_graph_create(const char *name);

/*
 * op_graph_destroy — free the graph and all nodes/edges.
 * If free_fn is non-NULL it is called for each live node's value.
 */
void op_graph_destroy(op_graph_t *g,
                      void (*free_fn)(void *val, void *ud), void *ud);

/* ---- nodes --------------------------------------------------------------- */

/*
 * op_graph_add_node — add a node with the given value.
 * Returns the new node's stable ID, or OP_GRAPH_INVALID_ID on OOM.
 */
op_graph_id_t op_graph_add_node(op_graph_t *g, void *val);

/* Replace the value of an existing node. No-op if id is invalid. */
void  op_graph_set_node(op_graph_t *g, op_graph_id_t id, void *val);

/* Returns the node's value, or NULL if not found. */
void *op_graph_get_node(const op_graph_t *g, op_graph_id_t id);

/* Returns true if id refers to a live node. */
bool  op_graph_has_node(const op_graph_t *g, op_graph_id_t id);

/*
 * op_graph_del_node — remove a node and all edges incident to it.
 * The ID is recycled for future add_node calls.
 */
void op_graph_del_node(op_graph_t *g, op_graph_id_t id);

/* ---- edges --------------------------------------------------------------- */

/*
 * op_graph_add_edge — add or update a directed edge from → to.
 * Returns  1 if a new edge was created.
 * Returns  0 if an existing edge's weight was updated.
 * Returns -1 if from or to is invalid.
 */
int op_graph_add_edge(op_graph_t *g, op_graph_id_t from, op_graph_id_t to,
                      int64_t weight);

/*
 * op_graph_del_edge — remove the directed edge from → to.
 * Returns 1 if found and removed, 0 if not found.
 */
int op_graph_del_edge(op_graph_t *g, op_graph_id_t from, op_graph_id_t to);

/* True if the directed edge from → to exists. */
bool    op_graph_has_edge(const op_graph_t *g,
                          op_graph_id_t from, op_graph_id_t to);

/* Returns the weight of edge from → to, or 0 if not found. */
int64_t op_graph_edge_weight(const op_graph_t *g,
                             op_graph_id_t from, op_graph_id_t to);

/* ---- traversal ----------------------------------------------------------- */

/*
 * op_graph_bfs — breadth-first search from start.
 * Visits each reachable node once; fn returns false to stop early.
 */
void op_graph_bfs(const op_graph_t *g, op_graph_id_t start,
                  op_graph_visit_t fn, void *ud);

/*
 * op_graph_dfs — depth-first search from start.
 * Visits each reachable node once; fn returns false to stop early.
 */
void op_graph_dfs(const op_graph_t *g, op_graph_id_t start,
                  op_graph_visit_t fn, void *ud);

/*
 * op_graph_neighbors — call fn for each outgoing edge of node id.
 */
void op_graph_neighbors(const op_graph_t *g, op_graph_id_t id,
                        op_graph_edge_visit_t fn, void *ud);

/* ---- topology ------------------------------------------------------------ */

/*
 * op_graph_topo_sort — Kahn's algorithm topological ordering.
 * Writes node IDs in topological order into out[0..cap-1].
 * Returns the number of nodes written (== node_count on success).
 * Returns -1 if the graph contains a directed cycle.
 */
int op_graph_topo_sort(const op_graph_t *g, op_graph_id_t *out, size_t cap);

/*
 * op_graph_has_cycle — returns true if the graph contains a directed cycle.
 */
bool op_graph_has_cycle(const op_graph_t *g);

/*
 * op_graph_shortest_path — Dijkstra single-source shortest path.
 * All edge weights must be non-negative.
 *
 * Writes the node IDs of the path (from inclusive, to inclusive) into
 * path[0..cap-1].  Returns total path weight, or INT64_MAX if unreachable.
 * Pass path=NULL / cap=0 to query only the distance.
 */
int64_t op_graph_shortest_path(const op_graph_t *g,
                               op_graph_id_t from, op_graph_id_t to,
                               op_graph_id_t *path, size_t cap);

/* ---- iteration ----------------------------------------------------------- */

/* Calls fn for every live node in ID order. */
void op_graph_foreach_node(const op_graph_t *g, op_graph_visit_t fn, void *ud);

/* Calls fn for every directed edge in the graph. */
void op_graph_foreach_edge(const op_graph_t *g,
                           op_graph_edge_visit_t fn, void *ud);

/* ---- introspection ------------------------------------------------------- */

size_t      op_graph_node_count(const op_graph_t *g);
size_t      op_graph_edge_count(const op_graph_t *g);
size_t      op_graph_out_degree(const op_graph_t *g, op_graph_id_t id);
size_t      op_graph_in_degree (const op_graph_t *g, op_graph_id_t id);
const char *op_graph_name(const op_graph_t *g);

#endif /* LIBOP_GRAPH_H */
