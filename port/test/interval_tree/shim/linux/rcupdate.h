/* SPDX-License-Identifier: GPL-2.0-only */
/* <linux/rcupdate.h>, reduced to the two macros <linux/rbtree.h> and
 * <linux/rbtree_augmented.h> use: rcu_assign_pointer() and
 * rcu_dereference_raw().
 *
 * Both headers include this one, so it has to exist. Neither macro is on any
 * path lib/interval_tree.c reaches -- they appear only in rb_link_node_rcu(),
 * __rb_change_child_rcu(), rb_replace_node_rcu() and the rb_*_rcu() lookup
 * helpers. They are given real acquire/release semantics rather than stubbed
 * to plain accesses so that a future harness which DOES reach one of them
 * does not silently get weaker ordering than the kernel builds. */
#ifndef _SHIM_INTERVAL_TREE_LINUX_RCUPDATE_H
#define _SHIM_INTERVAL_TREE_LINUX_RCUPDATE_H

#define rcu_assign_pointer(p, v) \
	__atomic_store_n(&(p), (v), __ATOMIC_RELEASE)

#define rcu_dereference_raw(p) \
	__atomic_load_n(&(p), __ATOMIC_RELAXED)

#endif
