/*
 * test_graph.c — unit tests for op_graph_t (directed weighted graph).
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

/* ---- helpers ------------------------------------------------------------- */

static size_t g_visit_count;
static size_t g_edge_count;

static bool count_visit(op_graph_id_t id, void *val, void *ud)
{
    (void)id; (void)val; (void)ud;
    g_visit_count++;
    return true;
}

static bool count_edge(op_graph_id_t from, op_graph_id_t to,
                        int64_t w, void *ud)
{
    (void)from; (void)to; (void)w; (void)ud;
    g_edge_count++;
    return true;
}

static bool stop_after_one(op_graph_id_t id, void *val, void *ud)
{
    (void)id; (void)val;
    (*(size_t *)ud)++;
    return false;
}

/* ======================================================================== */

int
main(void)
{
    printf("test_graph\n");

    /* [1] create / destroy empty */
    SECTION("create-destroy");
    {
        op_graph_t *g = op_graph_create("test");
        CHECK(g != NULL);
        CHECK(op_graph_node_count(g) == 0);
        CHECK(op_graph_edge_count(g) == 0);
        CHECK(strcmp(op_graph_name(g), "test") == 0);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [2] add / get / has node */
    SECTION("add-get-node");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, (void *)1);
        op_graph_id_t b = op_graph_add_node(g, (void *)2);
        CHECK(a != OP_GRAPH_INVALID_ID);
        CHECK(b != OP_GRAPH_INVALID_ID);
        CHECK(op_graph_node_count(g) == 2);
        CHECK(op_graph_has_node(g, a));
        CHECK(op_graph_has_node(g, b));
        CHECK(!op_graph_has_node(g, 99));
        CHECK(op_graph_get_node(g, a) == (void *)1);
        CHECK(op_graph_get_node(g, b) == (void *)2);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [3] set node value */
    SECTION("set-node");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, (void *)10);
        op_graph_set_node(g, a, (void *)99);
        CHECK(op_graph_get_node(g, a) == (void *)99);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [4] del node — removes incident edges */
    SECTION("del-node");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        op_graph_id_t c = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, a, b, 1);
        op_graph_add_edge(g, b, c, 1);
        op_graph_add_edge(g, c, a, 1);

        op_graph_del_node(g, b);
        CHECK(!op_graph_has_node(g, b));
        CHECK(op_graph_node_count(g) == 2);
        CHECK(op_graph_edge_count(g) == 1);   /* only c→a remains */
        CHECK(!op_graph_has_edge(g, a, b));
        CHECK(!op_graph_has_edge(g, b, c));
        CHECK(op_graph_has_edge(g, c, a));
        op_graph_destroy(g, NULL, NULL);
    }

    /* [5] node ID recycled after del */
    SECTION("node-id-recycle");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, (void *)1);
        (void)op_graph_add_node(g, (void *)2);
        op_graph_del_node(g, a);
        op_graph_id_t c = op_graph_add_node(g, (void *)3); /* reuses a's slot */
        CHECK(c == a);
        CHECK(op_graph_get_node(g, c) == (void *)3);
        CHECK(op_graph_node_count(g) == 2);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [6] add / has / del / weight edge */
    SECTION("edges");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);

        CHECK(op_graph_add_edge(g, a, b, 42) == 1);  /* new */
        CHECK(op_graph_has_edge(g, a, b));
        CHECK(!op_graph_has_edge(g, b, a));           /* directed */
        CHECK(op_graph_edge_weight(g, a, b) == 42);
        CHECK(op_graph_out_degree(g, a) == 1);
        CHECK(op_graph_in_degree(g, b) == 1);

        CHECK(op_graph_add_edge(g, a, b, 99) == 0);  /* update */
        CHECK(op_graph_edge_weight(g, a, b) == 99);
        CHECK(op_graph_edge_count(g) == 1);           /* still one edge */

        CHECK(op_graph_del_edge(g, a, b) == 1);
        CHECK(!op_graph_has_edge(g, a, b));
        CHECK(op_graph_edge_count(g) == 0);
        CHECK(op_graph_del_edge(g, a, b) == 0);      /* already gone */
        op_graph_destroy(g, NULL, NULL);
    }

    /* [7] BFS — visits all reachable nodes */
    SECTION("bfs");
    {
        op_graph_t *g = op_graph_create("g");
        /*  0 → 1 → 3
         *  0 → 2 → 3
         * (diamond)
         */
        op_graph_id_t n0 = op_graph_add_node(g, NULL);
        op_graph_id_t n1 = op_graph_add_node(g, NULL);
        op_graph_id_t n2 = op_graph_add_node(g, NULL);
        op_graph_id_t n3 = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, n0, n1, 1);
        op_graph_add_edge(g, n0, n2, 1);
        op_graph_add_edge(g, n1, n3, 1);
        op_graph_add_edge(g, n2, n3, 1);

        g_visit_count = 0;
        op_graph_bfs(g, n0, count_visit, NULL);
        CHECK(g_visit_count == 4);

        /* BFS from isolated node visits only that node. */
        op_graph_id_t iso = op_graph_add_node(g, NULL);
        g_visit_count = 0;
        op_graph_bfs(g, iso, count_visit, NULL);
        CHECK(g_visit_count == 1);

        op_graph_destroy(g, NULL, NULL);
    }

    /* [8] DFS — visits all reachable nodes */
    SECTION("dfs");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t n[5];
        for (int i = 0; i < 5; i++) n[i] = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, n[0], n[1], 1);
        op_graph_add_edge(g, n[1], n[2], 1);
        op_graph_add_edge(g, n[2], n[3], 1);
        op_graph_add_edge(g, n[0], n[4], 1);

        g_visit_count = 0;
        op_graph_dfs(g, n[0], count_visit, NULL);
        CHECK(g_visit_count == 5);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [9] early stop from BFS */
    SECTION("bfs-early-stop");
    {
        op_graph_t *g = op_graph_create("g");
        for (int i = 0; i < 5; i++) {
            op_graph_id_t id = op_graph_add_node(g, NULL);
            if (i > 0) op_graph_add_edge(g, i - 1, id, 1);
        }
        size_t cnt = 0;
        op_graph_bfs(g, 0, stop_after_one, &cnt);
        CHECK(cnt == 1);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [10] neighbors callback */
    SECTION("neighbors");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        op_graph_id_t c = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, a, b, 10);
        op_graph_add_edge(g, a, c, 20);

        g_edge_count = 0;
        op_graph_neighbors(g, a, count_edge, NULL);
        CHECK(g_edge_count == 2);

        g_edge_count = 0;
        op_graph_neighbors(g, b, count_edge, NULL);
        CHECK(g_edge_count == 0);   /* b has no outgoing edges */
        op_graph_destroy(g, NULL, NULL);
    }

    /* [11] topological sort — DAG */
    SECTION("topo-sort-dag");
    {
        /* 0 → 1 → 3
         * 0 → 2 → 3
         * valid topo orders: [0,1,2,3] or [0,2,1,3]
         */
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t n[4];
        for (int i = 0; i < 4; i++) n[i] = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, n[0], n[1], 1);
        op_graph_add_edge(g, n[0], n[2], 1);
        op_graph_add_edge(g, n[1], n[3], 1);
        op_graph_add_edge(g, n[2], n[3], 1);

        op_graph_id_t order[4];
        int r = op_graph_topo_sort(g, order, 4);
        CHECK(r == 4);
        CHECK(order[0] == n[0]);    /* 0 must come first */
        CHECK(order[3] == n[3]);    /* 3 must come last  */
        op_graph_destroy(g, NULL, NULL);
    }

    /* [12] topological sort — cycle → returns -1 */
    SECTION("topo-sort-cycle");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, a, b, 1);
        op_graph_add_edge(g, b, a, 1);
        op_graph_id_t out[2];
        CHECK(op_graph_topo_sort(g, out, 2) == -1);
        CHECK(op_graph_has_cycle(g));
        op_graph_destroy(g, NULL, NULL);
    }

    /* [13] has_cycle — no cycle */
    SECTION("no-cycle");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, a, b, 1);
        CHECK(!op_graph_has_cycle(g));
        op_graph_destroy(g, NULL, NULL);
    }

    /* [14] shortest path — simple chain */
    SECTION("shortest-path-chain");
    {
        /* 0 -1- 1 -2- 2 -3- 3   path cost = 6 */
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t n[4];
        for (int i = 0; i < 4; i++) n[i] = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, n[0], n[1], 1);
        op_graph_add_edge(g, n[1], n[2], 2);
        op_graph_add_edge(g, n[2], n[3], 3);

        op_graph_id_t path[4];
        int64_t dist = op_graph_shortest_path(g, n[0], n[3], path, 4);
        CHECK(dist == 6);
        CHECK(path[0] == n[0]);
        CHECK(path[1] == n[1]);
        CHECK(path[2] == n[2]);
        CHECK(path[3] == n[3]);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [15] shortest path — chooses optimal route */
    SECTION("shortest-path-optimal");
    {
        /* Direct: 0 -100- 1
         * Via:    0 -1- 2 -1- 1
         * Optimal via 2, cost = 2
         */
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t n0 = op_graph_add_node(g, NULL);
        op_graph_id_t n1 = op_graph_add_node(g, NULL);
        op_graph_id_t n2 = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, n0, n1, 100);
        op_graph_add_edge(g, n0, n2, 1);
        op_graph_add_edge(g, n2, n1, 1);

        int64_t dist = op_graph_shortest_path(g, n0, n1, NULL, 0);
        CHECK(dist == 2);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [16] shortest path — unreachable → INT64_MAX */
    SECTION("shortest-path-unreachable");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        /* No edge from a to b. */
        int64_t dist = op_graph_shortest_path(g, a, b, NULL, 0);
        CHECK(dist == INT64_MAX);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [17] foreach_node / foreach_edge */
    SECTION("foreach");
    {
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t a = op_graph_add_node(g, NULL);
        op_graph_id_t b = op_graph_add_node(g, NULL);
        op_graph_id_t c = op_graph_add_node(g, NULL);
        op_graph_add_edge(g, a, b, 1);
        op_graph_add_edge(g, b, c, 2);
        op_graph_add_edge(g, c, a, 3);

        g_visit_count = 0;
        op_graph_foreach_node(g, count_visit, NULL);
        CHECK(g_visit_count == 3);

        g_edge_count = 0;
        op_graph_foreach_edge(g, count_edge, NULL);
        CHECK(g_edge_count == 3);
        op_graph_destroy(g, NULL, NULL);
    }

    /* [18] IRC network topology — shortest path routing */
    SECTION("irc-topology");
    {
        /*
         *  Hub1 ─1─ Hub2
         *  │         │
         *  1         1
         *  │         │
         * Leaf1    Leaf2
         *
         * Shortest path Leaf1→Leaf2: Leaf1→Hub1→Hub2→Leaf2 (cost 3)
         */
        op_graph_t *g = op_graph_create("irc-net");

        op_graph_id_t hub1  = op_graph_add_node(g, "hub1.example.net");
        op_graph_id_t hub2  = op_graph_add_node(g, "hub2.example.net");
        op_graph_id_t leaf1 = op_graph_add_node(g, "leaf1.example.net");
        op_graph_id_t leaf2 = op_graph_add_node(g, "leaf2.example.net");

        /* Bidirectional links. */
        op_graph_add_edge(g, hub1,  hub2,  1);
        op_graph_add_edge(g, hub2,  hub1,  1);
        op_graph_add_edge(g, hub1,  leaf1, 1);
        op_graph_add_edge(g, leaf1, hub1,  1);
        op_graph_add_edge(g, hub2,  leaf2, 1);
        op_graph_add_edge(g, leaf2, hub2,  1);

        int64_t dist = op_graph_shortest_path(g, leaf1, leaf2, NULL, 0);
        CHECK(dist == 3);

        /* Simulate hub2 splitting — leaf2 becomes unreachable from leaf1. */
        op_graph_del_node(g, hub2);
        dist = op_graph_shortest_path(g, leaf1, leaf2, NULL, 0);
        CHECK(dist == INT64_MAX);

        op_graph_destroy(g, NULL, NULL);
    }

    /* [19] stress — 500 nodes, 1000 edges */
    SECTION("stress");
    {
#define GN 500
#define GE 1000
        op_graph_t *g = op_graph_create("g");
        op_graph_id_t ids[GN];
        for (int i = 0; i < GN; i++)
            ids[i] = op_graph_add_node(g, (void *)(intptr_t)i);
        CHECK(op_graph_node_count(g) == GN);

        srand(42);
        for (int i = 0; i < GE; i++)
            op_graph_add_edge(g,
                ids[rand() % GN], ids[rand() % GN],
                rand() % 100 + 1);

        CHECK(op_graph_edge_count(g) <= GE);

        /* BFS visits all reachable from node 0 without crash. */
        g_visit_count = 0;
        op_graph_bfs(g, ids[0], count_visit, NULL);
#undef GN
#undef GE
        op_graph_destroy(g, NULL, NULL);
    }

    printf("ALL PASS\n");
    return 0;
}
