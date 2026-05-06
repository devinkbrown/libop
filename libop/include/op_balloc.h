/*
 *  libop: ophion support library.
 *  op_balloc.h: Block allocator.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025-2026 ophion development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_balloc.h directly; include op_lib.h"
#endif

#ifndef LIBOP_BALLOC_H
#define LIBOP_BALLOC_H


struct op_bh;
typedef struct op_bh op_bh;
typedef void op_bh_usage_cb (size_t bused, size_t bfree, size_t bmemusage, size_t heapalloc,
			     const char *desc, void *data);


void op_bh_free(op_bh *, void *);
void *op_bh_alloc(op_bh *);

/* Runtime toggle for memory poisoning.  In debug builds, set to 0 to
 * disable the 0xDE fill/check without recompiling.  Defined in balloc.c. */
extern int op_balloc_poison;

op_bh *op_bh_create(size_t elemsize, size_t elemsperblock, const char *desc);
int op_bh_destroy(op_bh *bh);
void op_init_bh(void);
void op_bh_usage(op_bh *bh, size_t *bused, size_t *bfree, size_t *bmemusage, const char **desc);
void op_bh_usage_all(op_bh_usage_cb *cb, void *data);
void op_bh_total_usage(size_t *total_alloc, size_t *total_used);

/*
 * op_bh_create_shared — shared-memory slab allocator for hot-reload pools.
 *
 * Identical to op_bh_create() except that each slab is backed by a memfd
 * (Linux 3.17+) or a POSIX shm_open() anonymous file.  The backing file
 * descriptor is retrievable via op_bh_shmem_fd() and can be passed to a
 * new process or a new dlopen() instance via SCM_RIGHTS.  The new instance
 * calls op_bh_attach_shmem() to map the same physical pages, giving it
 * pointer-stable access to all existing allocations across a hot-reload.
 *
 * Ownership model:
 *   - The shim creates the heaps before exec'ing the ircd, then passes the
 *     FDs via SCM_RIGHTS (OPHION_SHIM_SHMEM environment variable).
 *   - The ircd core calls op_bh_attach_shmem(fd, size) to map each region.
 *   - On hot-reload: dlclose() unmaps the library but the memfd pages stay
 *     alive (the shim still has the FD open).  The new core re-attaches.
 *
 * Returns NULL on platforms where shared-memory slabs are unavailable;
 * callers must fall back to op_bh_create().
 */
op_bh  *op_bh_create_shared(size_t elemsize, size_t elemsperblock,
                             const char *desc);
int     op_bh_shmem_fd(const op_bh *bh);   /* -1 if not a shared heap    */
size_t  op_bh_shmem_size(const op_bh *bh); /* total bytes in the memfd   */

/*
 * op_bh_attach_shmem — attach to an existing shared-memory heap by FD.
 *
 * Called by the new core instance during hot-reload to map the same physical
 * pages that the previous instance was using.  The slab layout (elemsize,
 * elemsperblock, data_off, etc.) is read from the header written at the start
 * of the memfd region.  Returns the reconstituted op_bh on success, NULL on
 * error.
 */
op_bh  *op_bh_attach_shmem(int fd, size_t size, const char *desc);

#endif /* LIBOP_BALLOC_H */
