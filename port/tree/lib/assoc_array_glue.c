// SPDX-License-Identifier: GPL-2.0-or-later
/* Generic associative array implementation.
 *
 * See Documentation/core-api/assoc_array.rst for information.
 *
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
//#define DEBUG
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/assoc_array_priv.h>

/*
 * RUST PORT (lib/assoc_array.c, 6.18.49): the whole algorithm -- assoc_array_iterate/find/destroy/insert/insert_set_object/delete/
 * clear/apply_edit/cancel_edit/gc -- is in assoc_array_rs.rs, which defines those symbols itself (none is EXPORT_SYMBOL'd). This file
 * keeps only what must stay C: kzalloc/kmalloc/kfree, call_rcu with its callback, and BUG() (every BUG_ON of the original is a call
 * to the one helper, so the bug-table entry now names this file, once). Upstream's file is installed as assoc_array_norust.c for
 * CONFIG_RUST=n.
 */

/*
 * The layouts and constants assoc_array_rs.rs mirrors, checked here against the real headers at every build.
 */
static_assert(sizeof(struct assoc_array) == 16 && offsetof(struct assoc_array, root) == 0 &&
	      offsetof(struct assoc_array, nr_leaves_on_tree) == 8);
static_assert(sizeof(struct assoc_array_ops) == 40 && offsetof(struct assoc_array_ops, get_key_chunk) == 0 &&
	      offsetof(struct assoc_array_ops, get_object_key_chunk) == 8 && offsetof(struct assoc_array_ops, compare_object) == 16 &&
	      offsetof(struct assoc_array_ops, diff_objects) == 24 && offsetof(struct assoc_array_ops, free_object) == 32);
static_assert(sizeof(struct assoc_array_node) == 152 && offsetof(struct assoc_array_node, back_pointer) == 0 &&
	      offsetof(struct assoc_array_node, parent_slot) == 8 && offsetof(struct assoc_array_node, slots) == 16 &&
	      offsetof(struct assoc_array_node, nr_leaves_on_branch) == 144);
static_assert(sizeof(struct assoc_array_shortcut) == 24 && offsetof(struct assoc_array_shortcut, back_pointer) == 0 &&
	      offsetof(struct assoc_array_shortcut, parent_slot) == 8 && offsetof(struct assoc_array_shortcut, skip_to_level) == 12 &&
	      offsetof(struct assoc_array_shortcut, next_node) == 16 && offsetof(struct assoc_array_shortcut, index_key) == 24);
static_assert(sizeof(struct assoc_array_edit) == 328 && offsetof(struct assoc_array_edit, array) == 16 &&
	      offsetof(struct assoc_array_edit, ops) == 24 && offsetof(struct assoc_array_edit, ops_for_excised_subtree) == 32 &&
	      offsetof(struct assoc_array_edit, leaf) == 40 && offsetof(struct assoc_array_edit, leaf_p) == 48 &&
	      offsetof(struct assoc_array_edit, dead_leaf) == 56 && offsetof(struct assoc_array_edit, new_meta) == 64 &&
	      offsetof(struct assoc_array_edit, excised_meta) == 88 && offsetof(struct assoc_array_edit, excised_subtree) == 96 &&
	      offsetof(struct assoc_array_edit, set_backpointers) == 104 && offsetof(struct assoc_array_edit, set_backpointers_to) == 232 &&
	      offsetof(struct assoc_array_edit, adjust_count_on) == 240 && offsetof(struct assoc_array_edit, adjust_count_by) == 248 &&
	      offsetof(struct assoc_array_edit, set) == 256 && offsetof(struct assoc_array_edit, set_parent_slot) == 288 &&
	      offsetof(struct assoc_array_edit, segment_cache) == 304);
static_assert(sizeof(struct rcu_head) == 16);
static_assert(ASSOC_ARRAY_FAN_OUT == 16 && ASSOC_ARRAY_KEY_CHUNK_SIZE == 64 && ASSOC_ARRAY_LEVEL_STEP == 4 &&
	      ASSOC_ARRAY_PTR_TYPE_MASK == 1 && ASSOC_ARRAY_PTR_SUBTYPE_MASK == 2 && ASSOC_ARRAY_PTR_META_TYPE == 1 &&
	      ASSOC_ARRAY_PTR_SHORTCUT_SUBTYPE == 2 && ASSOC_ARRAY_KEY_CHUNK_SHIFT == 6);

/* lib/assoc_array_rs.rs */
void rust_assoc_array_rcu_cleanup(struct assoc_array_edit *edit);

/* helpers the Rust calls */
void *rust_assoc_array_kzalloc(size_t size);
void *rust_assoc_array_kmalloc(size_t size);
void rust_assoc_array_kfree(void *p);
void rust_assoc_array_call_rcu(struct assoc_array_edit *edit);
void rust_assoc_array_bug(void);

void *rust_assoc_array_kzalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void *rust_assoc_array_kmalloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

void rust_assoc_array_kfree(void *p)
{
	kfree(p);
}

void rust_assoc_array_bug(void)
{
	BUG();
}

/*
 * Handle the deferred destruction after an applied edit.
 */
static void assoc_array_rcu_cleanup(struct rcu_head *head)
{
	struct assoc_array_edit *edit =
		container_of(head, struct assoc_array_edit, rcu);

	rust_assoc_array_rcu_cleanup(edit);
}

void rust_assoc_array_call_rcu(struct assoc_array_edit *edit)
{
	call_rcu(&edit->rcu, assoc_array_rcu_cleanup);
}
