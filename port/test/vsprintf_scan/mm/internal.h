/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_MM_INTERNAL_H
#define _SHIM_VSPRINTF_MM_INTERNAL_H
/*
 * format_page_flags() (the %pGp seam, deferred, unexercised by this
 * harness's corpus) is the only user of pageflag_names/pff[]'s
 * SECTIONS_WIDTH-family constants. Zero-width fields make format_page_flags's
 * own loop skip every one (`if (!pff[i].width) continue;`), so all of these
 * are 0 here -- deliberately not modeling the real page-flags layout, since
 * nothing in this harness's corpus reaches this function.
 */
extern const struct trace_print_flags pageflag_names[];
/* gfpflag_names/vmaflag_names ARE exercised by this harness (flags_string's
 * 'g'/'v' cases, in scope) -- real, small, deterministic tables defined
 * once in stubs.c and shared by both the REF and RS arms. */
extern const struct trace_print_flags vmaflag_names[];
extern const struct trace_print_flags gfpflag_names[];

#define SECTIONS_WIDTH 0
#define SECTIONS_PGSHIFT 0
#define SECTIONS_MASK 0
#define NODES_WIDTH 0
#define NODES_PGSHIFT 0
#define NODES_MASK 0
#define ZONES_WIDTH 0
#define ZONES_PGSHIFT 0
#define ZONES_MASK 0
#define LAST_CPUPID_WIDTH 0
#define LAST_CPUPID_PGSHIFT 0
#define LAST_CPUPID_MASK 0
#define KASAN_TAG_WIDTH 0
#define KASAN_TAG_PGSHIFT 0
#define KASAN_TAG_MASK 0
#define PAGEFLAGS_MASK 0

#endif
