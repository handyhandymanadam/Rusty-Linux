// SPDX-License-Identifier: GPL-2.0-only
/*
 * The Rust string_helpers wrapper's allocation thunks.
 *
 * kmalloc/kcalloc are alloc_hooks(..._noprof(...)) macros since 6.10's
 * allocation profiling -- no linkable symbol. kfree/kstrdup/kasprintf/
 * __devres_alloc_node/devres_add/devres_free are real EXPORT_SYMBOLs and
 * are called directly from string_helpers_rs.rs; only the two macros need
 * a C body here. GFP_KERNEL/PAGE_SIZE need no thunk at all -- every file
 * using kernel::kabi_export!() already links --extern kernel, and both are
 * plain pub consts in kernel::bindings. See string_helpers_rs.rs's module
 * doc for the rest of the port.
 */
#include <linux/slab.h>

/* -Wmissing-prototypes requires these visible before the definitions
 * below, since nothing else in the C tree calls them -- their only
 * callers are Rust, via FFI. */
void *string_helpers_kmalloc(size_t size, gfp_t gfp);
void *string_helpers_kcalloc(size_t n, size_t size, gfp_t gfp);

void *string_helpers_kmalloc(size_t size, gfp_t gfp)
{
	return kmalloc(size, gfp);
}

void *string_helpers_kcalloc(size_t n, size_t size, gfp_t gfp)
{
	return kcalloc(n, size, gfp);
}
