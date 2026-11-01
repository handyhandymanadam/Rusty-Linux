/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME pristine
 * C, so `run.sh --selfcheck` exercises every line of main.c with an arm
 * that cannot disagree. Proves the plumbing, not the port.
 */
#include <stddef.h>

typedef void (*augment_rotate_fn)(void *old, void *new);

void ref_rb_insert_color(void *node, void *root);
void rs_rb_insert_color(void *node, void *root) { ref_rb_insert_color(node, root); }

void ref_rb_erase(void *node, void *root);
void rs_rb_erase(void *node, void *root) { ref_rb_erase(node, root); }

void ref___rb_insert_augmented(void *node, void *root, augment_rotate_fn rotate);
void rs___rb_insert_augmented(void *node, void *root, augment_rotate_fn rotate)
{ ref___rb_insert_augmented(node, root, rotate); }

void ref___rb_erase_color(void *parent, void *root, augment_rotate_fn rotate);
void rs___rb_erase_color(void *parent, void *root, augment_rotate_fn rotate)
{ ref___rb_erase_color(parent, root, rotate); }

void *ref_rb_first(const void *root);
void *rs_rb_first(const void *root) { return ref_rb_first(root); }

void *ref_rb_last(const void *root);
void *rs_rb_last(const void *root) { return ref_rb_last(root); }

void *ref_rb_next(const void *node);
void *rs_rb_next(const void *node) { return ref_rb_next(node); }

void *ref_rb_prev(const void *node);
void *rs_rb_prev(const void *node) { return ref_rb_prev(node); }

void ref_rb_replace_node(void *victim, void *new, void *root);
void rs_rb_replace_node(void *victim, void *new, void *root) { ref_rb_replace_node(victim, new, root); }

void ref_rb_replace_node_rcu(void *victim, void *new, void *root);
void rs_rb_replace_node_rcu(void *victim, void *new, void *root) { ref_rb_replace_node_rcu(victim, new, root); }

void *ref_rb_next_postorder(const void *node);
void *rs_rb_next_postorder(const void *node) { return ref_rb_next_postorder(node); }

void *ref_rb_first_postorder(const void *root);
void *rs_rb_first_postorder(const void *root) { return ref_rb_first_postorder(root); }
