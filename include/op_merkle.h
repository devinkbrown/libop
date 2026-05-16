/*
 * libop/include/op_merkle.h — XOR-accumulator Merkle tree for set reconciliation.
 *
 * Binary Merkle tree where each node stores a 16-byte XOR fingerprint
 * of all event IDs in its subtree.  Leaves are timestamp-range buckets.
 *
 * Tree layout (implicit array, 1-indexed):
 *   node[1]       = root
 *   node[2i]      = left child of node[i]
 *   node[2i+1]    = right child of node[i]
 *   Leaves:       node[2^depth .. 2^(depth+1)-1]
 *
 * Configurable depth.  Default OP_MERKLE_DEPTH=10 gives 1024 leaf buckets.
 *
 * Copyright (c) 2026 Ophion Development Team.  GPL v2.
 */

#ifndef OP_MERKLE_H
#define OP_MERKLE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef OP_MERKLE_DEPTH
#define OP_MERKLE_DEPTH     10
#endif

#define OP_MERKLE_ID_LEN    16
#define OP_MERKLE_LEAVES    (1u << OP_MERKLE_DEPTH)
#define OP_MERKLE_NODES     (2u * OP_MERKLE_LEAVES)

typedef struct {
	uint8_t fingerprint[OP_MERKLE_ID_LEN];
} op_merkle_node_t;

typedef struct {
	op_merkle_node_t nodes[OP_MERKLE_NODES];
	uint64_t         ts_min;
	uint64_t         ts_max;
	uint32_t         depth;
	uint32_t         count;
} op_merkle_t;

static inline void
op_merkle_init(op_merkle_t *m, uint64_t ts_min, uint64_t ts_max)
{
	memset(m, 0, sizeof(*m));
	m->ts_min = ts_min;
	m->ts_max = ts_max;
	m->depth = OP_MERKLE_DEPTH;
}

static inline uint32_t
op_merkle_leaf_index(const op_merkle_t *m, uint64_t ts)
{
	if (ts <= m->ts_min)
		return 0;
	if (ts >= m->ts_max)
		return OP_MERKLE_LEAVES - 1;

	uint64_t range = m->ts_max - m->ts_min;
	uint64_t offset = ts - m->ts_min;
	uint32_t bucket = (uint32_t)((offset * OP_MERKLE_LEAVES) / range);
	if (bucket >= OP_MERKLE_LEAVES)
		bucket = OP_MERKLE_LEAVES - 1;
	return bucket;
}

static inline void
op_merkle_xor(uint8_t dst[OP_MERKLE_ID_LEN],
              const uint8_t a[OP_MERKLE_ID_LEN],
              const uint8_t b[OP_MERKLE_ID_LEN])
{
	for (int i = 0; i < OP_MERKLE_ID_LEN; i++)
		dst[i] = a[i] ^ b[i];
}

static inline void
op_merkle_insert(op_merkle_t *m, uint64_t ts,
                 const uint8_t id[OP_MERKLE_ID_LEN])
{
	uint32_t leaf = op_merkle_leaf_index(m, ts);
	uint32_t idx = OP_MERKLE_LEAVES + leaf;

	op_merkle_xor(m->nodes[idx].fingerprint,
	              m->nodes[idx].fingerprint, id);
	m->count++;

	/* Propagate up to root */
	idx >>= 1;
	while (idx >= 1) {
		op_merkle_xor(m->nodes[idx].fingerprint,
		              m->nodes[idx * 2].fingerprint,
		              m->nodes[idx * 2 + 1].fingerprint);
		idx >>= 1;
	}
}

static inline bool
op_merkle_node_equal(const op_merkle_t *a, const op_merkle_t *b,
                     uint32_t idx)
{
	return memcmp(a->nodes[idx].fingerprint,
	              b->nodes[idx].fingerprint, OP_MERKLE_ID_LEN) == 0;
}

/*
 * op_merkle_diff — find differing leaf indices between two trees.
 *
 * Walks the tree top-down, only descending into subtrees with differing
 * fingerprints.  Returns the number of differing leaves written to
 * diff_leaves[], up to max_diff.
 */
static inline uint32_t
op_merkle_diff(const op_merkle_t *mk_local, const op_merkle_t *mk_remote,
               uint32_t *diff_leaves, uint32_t max_diff)
{
	uint32_t found = 0;

	/* BFS stack — worst case all internal nodes at one level */
	uint32_t stack[OP_MERKLE_LEAVES];
	uint32_t sp = 0;

	if (op_merkle_node_equal(mk_local, mk_remote, 1))
		return 0;

	stack[sp++] = 1;

	while (sp > 0 && found < max_diff) {
		uint32_t node = stack[--sp];

		if (node >= OP_MERKLE_LEAVES) {
			/* Leaf node */
			uint32_t leaf_idx = node - OP_MERKLE_LEAVES;
			if (!op_merkle_node_equal(mk_local, mk_remote, node))
				diff_leaves[found++] = leaf_idx;
			continue;
		}

		uint32_t left = node * 2;
		uint32_t right = node * 2 + 1;

		if (!op_merkle_node_equal(mk_local, mk_remote, right))
			stack[sp++] = right;
		if (!op_merkle_node_equal(mk_local, mk_remote, left))
			stack[sp++] = left;
	}

	return found;
}

/*
 * op_merkle_leaf_range — get the timestamp range for a leaf bucket.
 */
static inline void
op_merkle_leaf_range(const op_merkle_t *m, uint32_t leaf,
                     uint64_t *lo, uint64_t *hi)
{
	uint64_t range = m->ts_max - m->ts_min;
	*lo = m->ts_min + (range * leaf) / OP_MERKLE_LEAVES;
	*hi = m->ts_min + (range * (leaf + 1)) / OP_MERKLE_LEAVES;
}

static inline bool
op_merkle_root_equal(const op_merkle_t *a, const op_merkle_t *b)
{
	return op_merkle_node_equal(a, b, 1);
}

/*
 * Serialization: pack the fingerprints at a given tree level for wire.
 *
 * Level 0 = root (1 node), level 1 = 2 nodes, ..., level D = 2^D leaves.
 * Returns bytes written, or -1 on overflow.
 */
static inline int
op_merkle_serialize_level(const op_merkle_t *m, uint32_t level,
                          uint8_t *buf, size_t buf_len)
{
	if (level > m->depth)
		return -1;

	uint32_t first = 1u << level;
	uint32_t count = first;
	size_t need = (size_t)count * OP_MERKLE_ID_LEN;
	if (need > buf_len)
		return -1;

	for (uint32_t i = 0; i < count; i++)
		memcpy(buf + i * OP_MERKLE_ID_LEN,
		       m->nodes[first + i].fingerprint, OP_MERKLE_ID_LEN);

	return (int)need;
}

/*
 * Deserialization: unpack fingerprints at a level into a remote tree.
 */
static inline int
op_merkle_deserialize_level(op_merkle_t *m, uint32_t level,
                            const uint8_t *buf, size_t buf_len)
{
	if (level > m->depth)
		return -1;

	uint32_t first = 1u << level;
	uint32_t count = first;
	size_t need = (size_t)count * OP_MERKLE_ID_LEN;
	if (buf_len < need)
		return -1;

	for (uint32_t i = 0; i < count; i++)
		memcpy(m->nodes[first + i].fingerprint,
		       buf + i * OP_MERKLE_ID_LEN, OP_MERKLE_ID_LEN);

	return (int)need;
}

#endif /* OP_MERKLE_H */
