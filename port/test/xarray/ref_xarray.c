/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The xarray oracle: the PRISTINE lib/xarray.c, with every symbol it
 * exports renamed ref_* so both arms live in one binary. XA_CHUNK_SHIFT
 * is overridden (see shim/linux/kernel.h) to 4 for corpus depth -- both
 * arms see the same override, since both compile the same header.
 */
#define xas_load		ref_xas_load
#define xas_destroy		ref_xas_destroy
#define xas_nomem		ref_xas_nomem
#define xas_create_range	ref_xas_create_range
#define xas_store		ref_xas_store
#define xas_get_mark		ref_xas_get_mark
#define xas_set_mark		ref_xas_set_mark
#define xas_clear_mark		ref_xas_clear_mark
#define xas_init_marks		ref_xas_init_marks
#define xas_split_alloc		ref_xas_split_alloc
#define xas_split		ref_xas_split
#define xas_try_split_min_order	ref_xas_try_split_min_order
#define xas_try_split		ref_xas_try_split
#define xas_pause		ref_xas_pause
#define __xas_prev		ref___xas_prev
#define __xas_next		ref___xas_next
#define xas_find		ref_xas_find
#define xas_find_marked		ref_xas_find_marked
#define xas_find_conflict	ref_xas_find_conflict
#define xas_get_order		ref_xas_get_order

#define xa_load			ref_xa_load
#define __xa_erase		ref___xa_erase
#define xa_erase		ref_xa_erase
#define __xa_store		ref___xa_store
#define xa_store		ref_xa_store
#define __xa_cmpxchg		ref___xa_cmpxchg
#define __xa_insert		ref___xa_insert
#define xa_store_range		ref_xa_store_range
#define xa_get_order		ref_xa_get_order
#define __xa_alloc		ref___xa_alloc
#define __xa_alloc_cyclic	ref___xa_alloc_cyclic
#define __xa_set_mark		ref___xa_set_mark
#define __xa_clear_mark		ref___xa_clear_mark
#define xa_get_mark		ref_xa_get_mark
#define xa_set_mark		ref_xa_set_mark
#define xa_clear_mark		ref_xa_clear_mark
#define xa_find			ref_xa_find
#define xa_find_after		ref_xa_find_after
#define xa_extract		ref_xa_extract
#define xa_delete_node		ref_xa_delete_node
#define xa_destroy		ref_xa_destroy

#include "../../pristine/lib/xarray.c"
