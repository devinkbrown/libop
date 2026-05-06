/*
 * libop: ophion support library.
 * op_cidr_tbl.h: IPv4/IPv6 CIDR prefix lookup table (binary trie).
 *
 * Overview
 * ========
 * op_cidr_tbl is a binary trie for associating user data with IPv4 or IPv6
 * CIDR prefixes.  Two lookup modes are supported:
 *
 *   Match-any  — returns data from the FIRST prefix in the trie that covers
 *                the query address (any-hit).  Ideal for ban lists: stop as
 *                soon as any matching ban prefix is found.
 *
 *   LPM        — Longest-Prefix Match.  Returns data from the MOST SPECIFIC
 *                prefix that covers the query address.  Ideal for GeoIP
 *                databases and routing tables.
 *
 * Design
 * ======
 * One binary trie per address family (IPv4: depth 32, IPv6: depth 128).
 * Each trie node has two children (bit 0 and bit 1) and an optional data
 * pointer.  Nodes are allocated from a block heap (op_bh) for cache locality
 * and to avoid per-node malloc overhead under high churn (e.g. repeated
 * REHASH with hundreds of D-lines).
 *
 * Complexity:
 *   Insert / delete:  O(prefix_len)   — at most 32 or 128 node visits.
 *   Match-any:        O(prefix_len) worst case; O(1) best case (root hit).
 *   LPM:              O(32) or O(128) — always walks the full depth.
 *
 * Usage (IRC D-line / ban matching)
 * ==================================
 *   op_cidr_tbl_t *bans = op_cidr_create("dlines");
 *
 *   // Add bans
 *   struct in_addr net4;
 *   inet_pton(AF_INET, "10.0.0.0", &net4);
 *   op_cidr_set4(bans, &net4, 8, dline_record);
 *
 *   // Check a client IP
 *   void *hit = op_cidr_match_any_ss(bans, &client->sockaddr);
 *   if (hit) { ... }
 *
 *   op_cidr_destroy(bans, NULL, NULL);
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_cidr_tbl.h directly; include op_lib.h"
#endif

#ifndef LIBOP_CIDR_TBL_H
#define LIBOP_CIDR_TBL_H

#ifndef _WIN32
# include <netinet/in.h>
# include <arpa/inet.h>
#endif

/* ---- opaque handle ------------------------------------------------------- */

typedef struct op_cidr_tbl op_cidr_tbl_t;

typedef void (*op_cidr_free_t)(void *val, void *ud);
typedef bool (*op_cidr_each_t)(const struct sockaddr_storage *prefix,
                                int prefixlen, void *val, void *ud);

/* ---- lifecycle ----------------------------------------------------------- */

/*
 * op_cidr_create — allocate a new empty CIDR table.
 *
 * name: diagnostic label.
 * Never returns NULL; aborts on OOM.
 */
op_cidr_tbl_t *op_cidr_create(const char *name);

/*
 * op_cidr_destroy — free all nodes and the table.
 *
 * If free_fn is non-NULL, called for each stored val before freeing.
 * After this call the pointer is invalid.
 */
void op_cidr_destroy(op_cidr_tbl_t *t, op_cidr_free_t free_fn, void *ud);

/* ---- insert -------------------------------------------------------------- */

/*
 * op_cidr_set4 — associate val with the IPv4 CIDR prefix addr/plen.
 *
 * plen: prefix length [0, 32].  addr is in network byte order.
 *
 * If the prefix already exists, old_val (if non-NULL) receives the previous
 * value and it is replaced.  Returns 1 on insert, 0 on update.
 */
int op_cidr_set4(op_cidr_tbl_t *t,
                 const struct in_addr *addr, int plen,
                 void *val, void **old_val);

/*
 * op_cidr_set6 — associate val with the IPv6 CIDR prefix addr/plen.
 * plen: prefix length [0, 128].
 */
int op_cidr_set6(op_cidr_tbl_t *t,
                 const struct in6_addr *addr, int plen,
                 void *val, void **old_val);

/* ---- delete -------------------------------------------------------------- */

/* Returns the removed value, or NULL if the prefix was not present. */
void *op_cidr_del4(op_cidr_tbl_t *t,
                   const struct in_addr *addr, int plen);

void *op_cidr_del6(op_cidr_tbl_t *t,
                   const struct in6_addr *addr, int plen);

/* ---- lookup (match-any) -------------------------------------------------- */

/*
 * op_cidr_match_any4 — return the data associated with the FIRST (shortest)
 * prefix that covers addr.  Returns NULL if no prefix matches.
 *
 * "First" is the root-to-leaf direction: a /8 match is found before a /24
 * match.  For ban lists this is the expected semantics: the broadest ban wins.
 *
 * For strict "most specific first" behaviour, use op_cidr_lpm4 instead.
 */
void *op_cidr_match_any4(const op_cidr_tbl_t *t, const struct in_addr *addr);
void *op_cidr_match_any6(const op_cidr_tbl_t *t, const struct in6_addr *addr);

/*
 * op_cidr_match_any_ss — address-family-agnostic variant.
 * ss may be AF_INET or AF_INET6.  Returns NULL for other families.
 */
void *op_cidr_match_any_ss(const op_cidr_tbl_t *t,
                            const struct sockaddr_storage *ss);

/* ---- lookup (longest-prefix match) --------------------------------------- */

/*
 * op_cidr_lpm4 — return the data associated with the LONGEST (most specific)
 * prefix that covers addr.  Walks the full 32-bit depth.
 * Returns NULL if no prefix matches.
 */
void *op_cidr_lpm4(const op_cidr_tbl_t *t, const struct in_addr *addr);
void *op_cidr_lpm6(const op_cidr_tbl_t *t, const struct in6_addr *addr);

/* Address-family-agnostic LPM. */
void *op_cidr_lpm_ss(const op_cidr_tbl_t *t,
                     const struct sockaddr_storage *ss);

/* ---- introspection ------------------------------------------------------- */

size_t      op_cidr_count4(const op_cidr_tbl_t *t); /* IPv4 prefix count  */
size_t      op_cidr_count6(const op_cidr_tbl_t *t); /* IPv6 prefix count  */
const char *op_cidr_name  (const op_cidr_tbl_t *t);

/* ---- enumeration --------------------------------------------------------- */

/*
 * op_cidr_foreach4 — call fn for every stored IPv4 prefix in no particular
 * order.  fn receives a sockaddr_storage (AF_INET), the prefix length, the
 * associated val, and ud.  Stops early if fn returns false.
 */
void op_cidr_foreach4(const op_cidr_tbl_t *t, op_cidr_each_t fn, void *ud);
void op_cidr_foreach6(const op_cidr_tbl_t *t, op_cidr_each_t fn, void *ud);

#endif /* LIBOP_CIDR_TBL_H */
