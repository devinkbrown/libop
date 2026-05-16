/*
 * libop — op_hlc.h
 * Hybrid Logical Clock (Kulkarni et al., 2014).
 *
 * Combines a physical wall-clock component with a bounded logical counter
 * to produce timestamps that are:
 *   - Monotonically non-decreasing within a single node
 *   - Causally ordered across communicating nodes
 *   - Close to wall-clock time (bounded drift)
 *
 * Encoding: 8 bytes total.
 *   Bits [63:16]  48-bit wall-clock milliseconds since Unix epoch
 *   Bits [15:0]   16-bit logical counter
 *
 * This gives ~8925 years of range and 65536 events per millisecond per node.
 *
 * Copyright (c) 2026 Ophion Development Team.  MIT License.
 */

#ifndef OP_HLC_H
#define OP_HLC_H

#ifndef LIBOP_LIB_H
# error "Do not include op_hlc.h directly; include op_lib.h"
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct op_hlc {
	uint64_t ts;  /* packed: (wall_ms << 16) | logical */
} op_hlc_t;

#define OP_HLC_ZERO  ((op_hlc_t){ .ts = 0 })

/* Extract components. */
static inline uint64_t op_hlc_wall_ms(op_hlc_t h)   { return h.ts >> 16; }
static inline uint16_t op_hlc_logical(op_hlc_t h)    { return (uint16_t)(h.ts & 0xFFFF); }

/* Pack components into an HLC timestamp. */
static inline op_hlc_t op_hlc_pack(uint64_t wall_ms, uint16_t logical)
{
	return (op_hlc_t){ .ts = (wall_ms << 16) | logical };
}

/* Compare two HLC timestamps.  Returns <0, 0, or >0. */
static inline int op_hlc_cmp(op_hlc_t a, op_hlc_t b)
{
	if (a.ts < b.ts) return -1;
	if (a.ts > b.ts) return  1;
	return 0;
}

/* Return the maximum of two HLC timestamps. */
static inline op_hlc_t op_hlc_max(op_hlc_t a, op_hlc_t b)
{
	return a.ts >= b.ts ? a : b;
}

/*
 * Advance the local HLC for a local event.
 *
 *   now_ms: current wall-clock time in milliseconds
 *   local:  current local HLC state (updated in place)
 *
 * Returns the new timestamp assigned to this event.
 */
static inline op_hlc_t op_hlc_tick(op_hlc_t *hlc, uint64_t now_ms)
{
	uint64_t l_wall = op_hlc_wall_ms(*hlc);

	if (now_ms > l_wall) {
		*hlc = op_hlc_pack(now_ms, 0);
	} else {
		uint16_t l_log = op_hlc_logical(*hlc);
		*hlc = op_hlc_pack(l_wall, (uint16_t)(l_log + 1));
	}
	return *hlc;
}

/*
 * Advance the local HLC upon receiving a remote message.
 *
 *   now_ms: current wall-clock time in milliseconds
 *   local:  current local HLC state (updated in place)
 *   remote: HLC timestamp from the received message
 *
 * Returns the new local timestamp.
 */
static inline op_hlc_t op_hlc_recv(op_hlc_t *hlc, uint64_t now_ms,
                                    op_hlc_t hlc_remote)
{
	uint64_t l_wall = op_hlc_wall_ms(*hlc);
	uint64_t r_wall = op_hlc_wall_ms(hlc_remote);
	uint16_t l_log  = op_hlc_logical(*hlc);
	uint16_t r_log  = op_hlc_logical(hlc_remote);

	uint64_t max_wall = now_ms;
	if (l_wall > max_wall) max_wall = l_wall;
	if (r_wall > max_wall) max_wall = r_wall;

	uint16_t new_log;
	if (max_wall == l_wall && max_wall == r_wall)
		new_log = (l_log > r_log ? l_log : r_log) + 1;
	else if (max_wall == l_wall)
		new_log = l_log + 1;
	else if (max_wall == r_wall)
		new_log = r_log + 1;
	else
		new_log = 0;

	*hlc = op_hlc_pack(max_wall, new_log);
	return *hlc;
}

#endif /* OP_HLC_H */
