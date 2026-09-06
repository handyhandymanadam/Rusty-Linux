/* SPDX-License-Identifier: GPL-2.0-only */
/* port/test/interval_tree/shim/linux/kernel.h
 *
 * This module needs nothing beyond the shared base, so this file is the
 * delta and the delta is empty. It exists only to satisfy the
 * `#include_next` convention documented in port/test/common/shim/linux/
 * kernel.h -- a module with no delta is supposed to delete its copy and get
 * the base directly, and that is what the -I ordering in run.sh does.
 *
 * Kept as a one-line forward rather than deleted so that a future delta has
 * an obvious home and cannot be smuggled into the shared base.
 */
#ifndef _SHIM_INTERVAL_TREE_LINUX_KERNEL_H
#define _SHIM_INTERVAL_TREE_LINUX_KERNEL_H
#include_next <linux/kernel.h>
#endif
