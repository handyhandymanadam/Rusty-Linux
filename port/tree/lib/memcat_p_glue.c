// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (lib/memcat_p.c, 6.18.49): __memcat_p() is in memcat_p_rs.rs. This file keeps the export as a thunk (the MODVERSIONS fingerprint comes from the DWARF of the
 * definition) and the kmalloc_array() wrapper. Upstream's whole file is installed as memcat_p_norust.c for CONFIG_RUST=n.
 */

#include <linux/slab.h>

void **rust___memcat_p(void **a, void **b);
void **rust_mc_kmalloc_array(size_t n);

void **rust_mc_kmalloc_array(size_t n) { return kmalloc_array(n, sizeof(void *), GFP_KERNEL); }

/*
 * Merge two NULL-terminated pointer arrays into a newly allocated
 * array, which is also NULL-terminated. Nomenclature is inspired by
 * memset_p() and memcat() found elsewhere in the kernel source tree.
 */
void **__memcat_p(void **a, void **b)
{
	return rust___memcat_p(a, b);
}
EXPORT_SYMBOL_GPL(__memcat_p);
