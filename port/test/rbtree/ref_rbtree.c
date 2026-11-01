/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The rbtree oracle: the PRISTINE lib/rbtree.c, with every symbol it
 * exports renamed ref_* so both arms live in one binary.
 */
#define __rb_erase_color	ref___rb_erase_color
#define rb_insert_color		ref_rb_insert_color
#define rb_erase		ref_rb_erase
#define __rb_insert_augmented	ref___rb_insert_augmented
#define rb_first		ref_rb_first
#define rb_last			ref_rb_last
#define rb_next			ref_rb_next
#define rb_prev			ref_rb_prev
#define rb_replace_node		ref_rb_replace_node
#define rb_replace_node_rcu	ref_rb_replace_node_rcu
#define rb_next_postorder	ref_rb_next_postorder
#define rb_first_postorder	ref_rb_first_postorder

#include "../../pristine/lib/rbtree.c"
