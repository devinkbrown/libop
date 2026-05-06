/*
 *  libop — Ophion IRC daemon support library
 *  libop/src/version.c: Build identity and copyright metadata.
 *
 *  Copyright (c) 2002-2008 ircd-ratbox Development Team
 *  Copyright (c) 2024-2026 Ophion Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Design note
 * -----------
 * The old approach exported a raw uint64_t and a sentinel-terminated string
 * array (libop_infotext[]).  Callers had to know the array layout and iterate
 * a NULL sentinel — no type safety, no structured access, hard to extend.
 *
 * The new approach:
 *   • op_build_info_t (declared in op_lib.h) carries all metadata as named
 *     fields that can be queried by name, not by array index.
 *   • All fields are baked in at link time from meson-injected macros
 *     (DATECODE, BRANDING_NAME, BRANDING_VERSION) — zero runtime overhead.
 *   • op_build_info() returns a const pointer to the singleton; callers may
 *     cache it freely (it never changes after link).
 *   • libop_datecode is kept as an exported symbol for ABI compatibility with
 *     any out-of-tree code that links against it directly.
 */

#include <libop_config.h>
#include <op_lib.h>

/* -------------------------------------------------------------------------
 * ABI compatibility shim — retained for out-of-tree modules that reference
 * libop_datecode via a direct extern declaration rather than op_build_info().
 * New code should use op_build_info()->build_date instead.
 * ---------------------------------------------------------------------- */
const uint64_t libop_datecode = DATECODE;

/* -------------------------------------------------------------------------
 * Compile-time-initialised build identity.
 *
 * BRANDING_NAME and BRANDING_VERSION are -D defines injected by meson from
 * meson.project_name() / meson.project_version().  DATECODE is the Unix
 * timestamp of the most-recent git commit (0 on unversioned trees).
 * ---------------------------------------------------------------------- */
static const op_build_info_t _build_info = {
	.product         = BRANDING_NAME,
	.version         = BRANDING_VERSION,
	.build_date      = DATECODE,
	.copyright =
		"Copyright (c) 1988-1991 University of Oulu, Computing Center\n"
		"Copyright (c) 1996-2001 Hybrid Development Team\n"
		"Copyright (c) 2002-2008 ircd-ratbox Development Team\n"
		"Copyright (c) 2024-2026 Ophion Development Team",
	.license =
		"This program is free software; you can redistribute it and/or\n"
		"modify it under the terms of the GNU General Public License as\n"
		"published by the Free Software Foundation; either version 2, or\n"
		"(at your option) any later version.",
	.credits =
		"Ophion is a fork of charybdis, which itself was based on\n"
		"ircd-ratbox.  For a full list of contributors to predecessor\n"
		"projects see doc/credits-past.txt in the source distribution.",
};

/* -------------------------------------------------------------------------
 * op_build_info — return a pointer to the singleton build identity record.
 *
 * The returned pointer is valid for the lifetime of the process.  The struct
 * is const; callers must not attempt to modify it.
 * ---------------------------------------------------------------------- */
const op_build_info_t *
op_build_info(void)
{
	return &_build_info;
}
