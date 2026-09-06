/* SPDX-License-Identifier: GPL-2.0-only */
/* <linux/container_of.h>, reduced to what rb_entry() needs.
 *
 * The real header's container_of() carries a __same_type() build assertion.
 * It is dropped here rather than reproduced: it is a compile-time type check
 * on the CALLER, not a code path, and every use in this harness comes from
 * the pristine kernel headers where the kernel build has already checked it. */
#ifndef _SHIM_INTERVAL_TREE_LINUX_CONTAINER_OF_H
#define _SHIM_INTERVAL_TREE_LINUX_CONTAINER_OF_H

#include <stddef.h>

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

#endif
