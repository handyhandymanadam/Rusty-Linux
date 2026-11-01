// SPDX-License-Identifier: GPL-2.0-or-later

//! Red-black trees: the twelve `EXPORT_SYMBOL`'d functions in
//! `lib/rbtree.c` -- insertion/erase rebalancing (plain and augmented),
//! and the four traversal families (`rb_first`/`rb_last`/`rb_next`/
//! `rb_prev`, `rb_replace_node[_rcu]`, and postorder).
//!
//! Ported from `lib/rbtree.c` (6.18.49), `(C) 1999 Andrea Arcangeli,
//! (C) 2002 David Woodhouse, (C) 2012 Michel Lespinasse`.
//!
//! # `struct rb_node`'s layout is not this file's to get wrong alone
//!
//! `__rb_parent_color` at offset 0, `rb_right` at 8, `rb_left` at 16 --
//! confirmed against `pahole -C rb_node` on the real `build-full/vmlinux`
//! (size 24), and against `lib/interval_tree_rs.rs`'s `IntervalTreeRbNode`
//! and `lib/timerqueue_rs.rs`'s `RbNode`, both already `#[repr(C)]` mirrors
//! of this exact layout, both already checked by `rig/layout-check.sh`.
//! Those two files' mirrors and this one's are three independent
//! transcriptions of the same live struct -- real kernel objects
//! (`struct vm_area_struct`, `struct sched_entity`, `struct
//! interval_tree_node`, `struct timerqueue_node`, ...) embed one
//! `struct rb_node` that all of them read and write, through whichever of
//! the three crates happens to be walking that tree at the time. A
//! one-field disagreement here would not just misport this file, it would
//! corrupt data two already-shipped ports believe they own alone. Kept in
//! the same field order as those two mirrors for exactly that reason.
//!
//! # `lib/union_find` shape
//!
//! All twelve exports are plain `EXPORT_SYMBOL` (not `_GPL`), and none
//! holds a guard, static-key dispatch or `__weak` marker (checked against
//! `logs/c-entry-rule.md`'s criteria directly, not assumed) -- pure
//! algorithm throughout. Each carries its own `kernel::kabi_export!` pin;
//! no C thunk, no C file at all in the `CONFIG_RUST=y` arm.
//!
//! # What this file reproduces, and what it calls
//!
//! Nothing in this file calls anything -- there is nothing left to call
//! into. `include/linux/rbtree.h` and `rbtree_augmented.h` stay completely
//! untouched, for the ~200 files that still `#include` them and use their
//! `static inline` surface directly; this file reproduces its OWN copies
//! of the handful it needs internally: the parent/colour bit-packing
//! (`rb_parent`, `rb_color`, `rb_is_red`/`_black`, `rb_set_parent[_color]`,
//! `rb_red_parent`, `rb_set_black`), `__rb_change_child`, and
//! `__rb_rotate_set_parents`.
//!
//! `rb_erase()` is the one exported function whose C body calls the
//! header's `static __always_inline __rb_erase_augmented()` -- not a
//! linkable symbol, so it cannot be called across this boundary either.
//! [`rb_erase_splice`] reproduces that function's splice logic specifically
//! for `rb_erase()`'s own case: the C instantiates `__rb_erase_augmented`
//! with `dummy_callbacks` (`propagate`/`copy`/`rotate` all no-ops) and the
//! compiler optimises the two dead calls away, leaving exactly the splice.
//! [`rb_erase_splice`] is that already-optimised shape, written directly
//! rather than carrying two calls that would compile to nothing -- not a
//! new divergence, the same one the C's own build already makes.
//!
//! # `augment_rotate` is a real function pointer, not `Option`
//!
//! `__rb_insert`/`____rb_erase_color`'s `augment_rotate` parameter is
//! called unconditionally in the C (`void (*)(...)`, never null-checked),
//! and the non-augmented entry points pass a real no-op ([`dummy_rotate`])
//! rather than a null pointer -- so the Rust signature is a plain
//! `unsafe extern "C" fn`, matching `interval_tree_rs.rs`'s own `extern
//! "C"` declaration for the same three imported symbols exactly.
//!
//! # `WRITE_ONCE` is reproduced as a volatile store
//!
//! Every child/root pointer publish the C makes with `WRITE_ONCE()` is a
//! `write_volatile` below, same reasoning `interval_tree_rs.rs`'s own
//! module doc gives: the tree is walked by lockless RCU readers, and
//! GOALS.md §5 names the order writes become visible as one of the three
//! things a port may not change. `rb_replace_node_rcu()`'s `rcu_assign_
//! pointer()` needs a release fence in addition to the plain volatile
//! store (`smp_store_release`, which `rcu_assign_pointer` expands to on
//! this architecture) -- ordinary `WRITE_ONCE` stores elsewhere do not.
//!
//! Replaces: lib/rbtree.c

#![allow(non_snake_case)]

use core::sync::atomic::{fence, Ordering};

/// Mirrors `struct rb_node` (`include/linux/rbtree_types.h`). See the
/// module doc's layout note.
#[repr(C)]
pub struct RbNode {
    __rb_parent_color: usize,
    rb_right: *mut RbNode,
    rb_left: *mut RbNode,
}

/// Mirrors `struct rb_root`.
#[repr(C)]
pub struct RbRoot {
    rb_node: *mut RbNode,
}

/// `RB_RED`.
const RB_RED: usize = 0;
/// `RB_BLACK`.
const RB_BLACK: usize = 1;

/// The `void (*)(struct rb_node *old, struct rb_node *new)` callback type,
/// called unconditionally -- see the module doc.
type AugmentRotate = unsafe extern "C" fn(*mut RbNode, *mut RbNode);

/// `dummy_rotate()`: the no-op `augment_rotate` the non-augmented entry
/// points pass.
unsafe extern "C" fn dummy_rotate(_old: *mut RbNode, _new: *mut RbNode) {}

// ---------------------------------------------------------------------------
// rbtree.h / rbtree_augmented.h -- the header-only parts this file needs.
// Own copies; see the module doc on why they cannot be shared or called.
// ---------------------------------------------------------------------------

/// `rb_parent()`. The low two bits of `__rb_parent_color` carry the colour.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_parent(rb: *const RbNode) -> *mut RbNode {
    // SAFETY: caller guarantees `rb` is valid.
    unsafe { ((*rb).__rb_parent_color & !3) as *mut RbNode }
}

/// `__rb_parent()`, over a saved `__rb_parent_color` word rather than a
/// live node -- used where the C reads the word once before the node's
/// own colour/parent are overwritten.
#[inline(always)]
fn raw_rb_parent(pc: usize) -> *mut RbNode {
    (pc & !3) as *mut RbNode
}

/// `rb_color()` -- `RB_RED` is 0, `RB_BLACK` is 1.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_color(rb: *const RbNode) -> usize {
    // SAFETY: caller guarantees `rb` is valid.
    unsafe { (*rb).__rb_parent_color & 1 }
}

/// `rb_is_red()`.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_is_red(rb: *const RbNode) -> bool {
    // SAFETY: as above.
    unsafe { rb_color(rb) == RB_RED }
}

/// `rb_is_black()`.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_is_black(rb: *const RbNode) -> bool {
    // SAFETY: as above.
    unsafe { rb_color(rb) == RB_BLACK }
}

/// `__rb_is_black()`, over a saved `__rb_parent_color` word.
#[inline(always)]
fn raw_rb_is_black(pc: usize) -> bool {
    (pc & 1) == RB_BLACK
}

/// `rb_set_parent()`.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_set_parent(rb: *mut RbNode, p: *mut RbNode) {
    // SAFETY: caller guarantees `rb` is valid. `rb_color(rb) + (p as
    // usize)` matches interval_tree_rs.rs's own rb_set_parent(): a real
    // pointer value is never within 1 of usize::MAX, but the C's `+` on
    // `unsigned long` is defined wraparound regardless, so wrapping_add is
    // faithful either way. Found by the CONFIG_RUST_OVERFLOW_CHECKS
    // panic-symbol sweep, 2026-09-06.
    unsafe {
        (*rb).__rb_parent_color = rb_color(rb).wrapping_add(p as usize);
    }
}

/// `rb_set_parent_color()`.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_set_parent_color(rb: *mut RbNode, p: *mut RbNode, color: usize) {
    // SAFETY: caller guarantees `rb` is valid. Same reasoning as
    // rb_set_parent() above -- matches interval_tree_rs.rs's own copy.
    unsafe {
        (*rb).__rb_parent_color = (p as usize).wrapping_add(color);
    }
}

/// `rb_set_black()`.
///
/// # Safety
/// `rb` must be valid.
#[inline(always)]
unsafe fn rb_set_black(rb: *mut RbNode) {
    // SAFETY: caller guarantees `rb` is valid.
    unsafe {
        (*rb).__rb_parent_color += RB_BLACK;
    }
}

/// `rb_red_parent()`: the parent of a node already known to be red, so its
/// `__rb_parent_color` word IS the parent pointer (colour bits are 0).
///
/// # Safety
/// `red` must be valid and actually red.
#[inline(always)]
unsafe fn rb_red_parent(red: *const RbNode) -> *mut RbNode {
    // SAFETY: caller guarantees `red` is valid; being red, its
    // `__rb_parent_color` has no colour bits set, so it IS the pointer.
    unsafe { (*red).__rb_parent_color as *mut RbNode }
}

/// `__rb_change_child()`.
///
/// # Safety
/// `parent` (if non-null) and `root` must be valid; `old` must currently be
/// one of `parent`'s children, or `root`'s node if `parent` is null.
#[inline(always)]
unsafe fn __rb_change_child(old: *mut RbNode, new: *mut RbNode, parent: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        if !parent.is_null() {
            if (*parent).rb_left == old {
                core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(new);
            } else {
                core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(new);
            }
        } else {
            core::ptr::addr_of_mut!((*root).rb_node).write_volatile(new);
        }
    }
}

/// `__rb_change_child_rcu()`: the same publish, but with the release
/// ordering `rcu_assign_pointer()` adds on top of the plain volatile
/// store -- see the module doc.
///
/// # Safety
/// Same as [`__rb_change_child`].
#[inline(always)]
unsafe fn __rb_change_child_rcu(old: *mut RbNode, new: *mut RbNode, parent: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        fence(Ordering::Release);
        if !parent.is_null() {
            if (*parent).rb_left == old {
                core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(new);
            } else {
                core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(new);
            }
        } else {
            core::ptr::addr_of_mut!((*root).rb_node).write_volatile(new);
        }
    }
}

/// `__rb_rotate_set_parents()`.
///
/// # Safety
/// `old`, `new` and `root` must be valid.
#[inline(always)]
unsafe fn __rb_rotate_set_parents(old: *mut RbNode, new: *mut RbNode, root: *mut RbRoot, color: usize) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let parent = rb_parent(old);
        (*new).__rb_parent_color = (*old).__rb_parent_color;
        rb_set_parent_color(old, new, color);
        __rb_change_child(old, new, parent, root);
    }
}

// ---------------------------------------------------------------------------
// __rb_insert(): shared insert-side rebalance, plain and augmented alike.
// ---------------------------------------------------------------------------

/// `__rb_insert()`.
///
/// # Safety
/// `node` must already be linked into `*root` (via the header's
/// `rb_link_node()`) and coloured red, with `rb_red_parent(node)` valid.
/// `augment_rotate` must be safe to call with any two nodes this rebalance
/// rotates.
unsafe fn __rb_insert(node: *mut RbNode, root: *mut RbRoot, augment_rotate: AugmentRotate) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let mut node = node;
        let mut parent = rb_red_parent(node);
        let mut gparent;
        let mut tmp;

        loop {
            if parent.is_null() {
                rb_set_parent_color(node, core::ptr::null_mut(), RB_BLACK);
                break;
            }

            if rb_is_black(parent) {
                break;
            }

            gparent = rb_red_parent(parent);

            tmp = (*gparent).rb_right;
            if parent != tmp {
                // parent == gparent->rb_left
                if !tmp.is_null() && rb_is_red(tmp) {
                    // Case 1 - uncle is red (colour flip); recurse at gparent.
                    rb_set_parent_color(tmp, gparent, RB_BLACK);
                    rb_set_parent_color(parent, gparent, RB_BLACK);
                    node = gparent;
                    parent = rb_parent(node);
                    rb_set_parent_color(node, parent, RB_RED);
                    continue;
                }

                tmp = (*parent).rb_right;
                if node == tmp {
                    // Case 2 - uncle black, node is parent's right child.
                    tmp = (*node).rb_left;
                    core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(tmp);
                    core::ptr::addr_of_mut!((*node).rb_left).write_volatile(parent);
                    if !tmp.is_null() {
                        rb_set_parent_color(tmp, parent, RB_BLACK);
                    }
                    rb_set_parent_color(parent, node, RB_RED);
                    augment_rotate(parent, node);
                    parent = node;
                    tmp = (*node).rb_right;
                }

                // Case 3 - uncle black, node is parent's left child.
                core::ptr::addr_of_mut!((*gparent).rb_left).write_volatile(tmp);
                core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(gparent);
                if !tmp.is_null() {
                    rb_set_parent_color(tmp, gparent, RB_BLACK);
                }
                __rb_rotate_set_parents(gparent, parent, root, RB_RED);
                augment_rotate(gparent, parent);
                break;
            } else {
                tmp = (*gparent).rb_left;
                if !tmp.is_null() && rb_is_red(tmp) {
                    // Case 1 - colour flip.
                    rb_set_parent_color(tmp, gparent, RB_BLACK);
                    rb_set_parent_color(parent, gparent, RB_BLACK);
                    node = gparent;
                    parent = rb_parent(node);
                    rb_set_parent_color(node, parent, RB_RED);
                    continue;
                }

                tmp = (*parent).rb_left;
                if node == tmp {
                    // Case 2 - right rotate at parent.
                    tmp = (*node).rb_right;
                    core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(tmp);
                    core::ptr::addr_of_mut!((*node).rb_right).write_volatile(parent);
                    if !tmp.is_null() {
                        rb_set_parent_color(tmp, parent, RB_BLACK);
                    }
                    rb_set_parent_color(parent, node, RB_RED);
                    augment_rotate(parent, node);
                    parent = node;
                    tmp = (*node).rb_left;
                }

                // Case 3 - left rotate at gparent.
                core::ptr::addr_of_mut!((*gparent).rb_right).write_volatile(tmp);
                core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(gparent);
                if !tmp.is_null() {
                    rb_set_parent_color(tmp, gparent, RB_BLACK);
                }
                __rb_rotate_set_parents(gparent, parent, root, RB_RED);
                augment_rotate(gparent, parent);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ____rb_erase_color(): shared erase-side rebalance, plain and augmented.
// ---------------------------------------------------------------------------

/// `____rb_erase_color()`.
///
/// # Safety
/// `parent` must be a valid, non-null, non-root node whose (missing) child
/// on the erased side is one black shorter than its sibling's paths, per
/// the C's own loop-invariant comment. `augment_rotate` must be safe to
/// call with any two nodes this rebalance rotates.
unsafe fn rb_erase_color(mut parent: *mut RbNode, root: *mut RbRoot, augment_rotate: AugmentRotate) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let mut node: *mut RbNode = core::ptr::null_mut();
        let mut sibling;
        let mut tmp1;
        let mut tmp2;

        loop {
            sibling = (*parent).rb_right;
            if node != sibling {
                // node == parent->rb_left
                if rb_is_red(sibling) {
                    // Case 1 - left rotate at parent.
                    tmp1 = (*sibling).rb_left;
                    core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(tmp1);
                    core::ptr::addr_of_mut!((*sibling).rb_left).write_volatile(parent);
                    rb_set_parent_color(tmp1, parent, RB_BLACK);
                    __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                    augment_rotate(parent, sibling);
                    sibling = tmp1;
                }
                tmp1 = (*sibling).rb_right;
                if tmp1.is_null() || rb_is_black(tmp1) {
                    tmp2 = (*sibling).rb_left;
                    if tmp2.is_null() || rb_is_black(tmp2) {
                        // Case 2 - sibling colour flip.
                        rb_set_parent_color(sibling, parent, RB_RED);
                        if rb_is_red(parent) {
                            rb_set_black(parent);
                        } else {
                            node = parent;
                            parent = rb_parent(node);
                            if !parent.is_null() {
                                continue;
                            }
                        }
                        break;
                    }
                    // Case 3 - right rotate at sibling.
                    tmp1 = (*tmp2).rb_right;
                    core::ptr::addr_of_mut!((*sibling).rb_left).write_volatile(tmp1);
                    core::ptr::addr_of_mut!((*tmp2).rb_right).write_volatile(sibling);
                    core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(tmp2);
                    if !tmp1.is_null() {
                        rb_set_parent_color(tmp1, sibling, RB_BLACK);
                    }
                    augment_rotate(sibling, tmp2);
                    tmp1 = sibling;
                    sibling = tmp2;
                }
                // Case 4 - left rotate at parent + colour flips.
                tmp2 = (*sibling).rb_left;
                core::ptr::addr_of_mut!((*parent).rb_right).write_volatile(tmp2);
                core::ptr::addr_of_mut!((*sibling).rb_left).write_volatile(parent);
                rb_set_parent_color(tmp1, sibling, RB_BLACK);
                if !tmp2.is_null() {
                    rb_set_parent(tmp2, parent);
                }
                __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
                augment_rotate(parent, sibling);
                break;
            } else {
                sibling = (*parent).rb_left;
                if rb_is_red(sibling) {
                    // Case 1 - right rotate at parent.
                    tmp1 = (*sibling).rb_right;
                    core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(tmp1);
                    core::ptr::addr_of_mut!((*sibling).rb_right).write_volatile(parent);
                    rb_set_parent_color(tmp1, parent, RB_BLACK);
                    __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                    augment_rotate(parent, sibling);
                    sibling = tmp1;
                }
                tmp1 = (*sibling).rb_left;
                if tmp1.is_null() || rb_is_black(tmp1) {
                    tmp2 = (*sibling).rb_right;
                    if tmp2.is_null() || rb_is_black(tmp2) {
                        // Case 2 - sibling colour flip.
                        rb_set_parent_color(sibling, parent, RB_RED);
                        if rb_is_red(parent) {
                            rb_set_black(parent);
                        } else {
                            node = parent;
                            parent = rb_parent(node);
                            if !parent.is_null() {
                                continue;
                            }
                        }
                        break;
                    }
                    // Case 3 - left rotate at sibling.
                    tmp1 = (*tmp2).rb_left;
                    core::ptr::addr_of_mut!((*sibling).rb_right).write_volatile(tmp1);
                    core::ptr::addr_of_mut!((*tmp2).rb_left).write_volatile(sibling);
                    core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(tmp2);
                    if !tmp1.is_null() {
                        rb_set_parent_color(tmp1, sibling, RB_BLACK);
                    }
                    augment_rotate(sibling, tmp2);
                    tmp1 = sibling;
                    sibling = tmp2;
                }
                // Case 4 - right rotate at parent + colour flips.
                tmp2 = (*sibling).rb_right;
                core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(tmp2);
                core::ptr::addr_of_mut!((*sibling).rb_right).write_volatile(parent);
                rb_set_parent_color(tmp1, sibling, RB_BLACK);
                if !tmp2.is_null() {
                    rb_set_parent(tmp2, parent);
                }
                __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
                augment_rotate(parent, sibling);
                break;
            }
        }
    }
}

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
kernel::kabi_rule!("type_string", "s#rb_node",
    "structure_type rb_node { member base_type unsigned long byte_size(8) encoding(7) __rb_parent_color data_member_location(0) , member pointer_type { s#rb_node } rb_right data_member_location(8) , member pointer_type { s#rb_node } rb_left data_member_location(16) } byte_size(24) alignment(8)");
kernel::kabi_rule!("type_string", "s#rb_root",
    "structure_type rb_root { member pointer_type { s#rb_node } rb_node data_member_location(0) } byte_size(8)");

kernel::kabi_export! {
    __rb_erase_color,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } parent , formal_parameter pointer_type { s#rb_root } root , formal_parameter pointer_type { subroutine_type ( formal_parameter pointer_type { s#rb_node } , formal_parameter pointer_type { s#rb_node } ) -> base_type void } augment_rotate ) -> base_type void",
}

/// `__rb_erase_color()`: the exported non-inline wrapper `rb_erase_
/// augmented()` (header, reproduced per-caller) calls after its own splice.
///
/// # Safety
/// Same as [`rb_erase_color`].
#[no_mangle]
pub unsafe extern "C" fn __rb_erase_color(parent: *mut RbNode, root: *mut RbRoot, augment_rotate: AugmentRotate) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe { rb_erase_color(parent, root, augment_rotate) }
}

// ---------------------------------------------------------------------------
// Non-augmented entry points.
// ---------------------------------------------------------------------------

kernel::kabi_export! {
    rb_insert_color,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } node , formal_parameter pointer_type { s#rb_root } root ) -> base_type void",
}

/// `rb_insert_color()`.
///
/// # Safety
/// `node` must already be linked into `*root` and coloured red, as
/// [`__rb_insert`] requires.
#[no_mangle]
pub unsafe extern "C" fn rb_insert_color(node: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe { __rb_insert(node, root, dummy_rotate) }
}

/// `__rb_erase_augmented()`'s splice, specialised to `rb_erase()`'s own
/// dummy (no-op) callbacks -- see the module doc. Returns the node
/// `rb_erase_color` must be called on, if rebalancing is needed.
///
/// # Safety
/// `node` must be a live node currently linked into `*root`.
unsafe fn rb_erase_splice(node: *mut RbNode, root: *mut RbRoot) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let child = (*node).rb_right;
        let mut tmp = (*node).rb_left;
        let mut parent;
        let rebalance;
        let pc;

        if tmp.is_null() {
            // Case 1: no more than one child.
            pc = (*node).__rb_parent_color;
            parent = raw_rb_parent(pc);
            __rb_change_child(node, child, parent, root);
            if !child.is_null() {
                (*child).__rb_parent_color = pc;
                rebalance = core::ptr::null_mut();
            } else {
                rebalance = if raw_rb_is_black(pc) { parent } else { core::ptr::null_mut() };
            }
            tmp = parent;
        } else if child.is_null() {
            // Still case 1, this time the child is node->rb_left.
            (*tmp).__rb_parent_color = (*node).__rb_parent_color;
            pc = (*tmp).__rb_parent_color;
            parent = raw_rb_parent(pc);
            __rb_change_child(node, tmp, parent, root);
            rebalance = core::ptr::null_mut();
            tmp = parent;
        } else {
            let mut successor = child;
            let child2;

            tmp = (*child).rb_left;
            if tmp.is_null() {
                // Case 2: successor is node's right child.
                parent = successor;
                child2 = (*successor).rb_right;
            } else {
                // Case 3: successor is leftmost under node's right subtree.
                loop {
                    parent = successor;
                    successor = tmp;
                    tmp = (*tmp).rb_left;
                    if tmp.is_null() {
                        break;
                    }
                }
                child2 = (*successor).rb_right;
                core::ptr::addr_of_mut!((*parent).rb_left).write_volatile(child2);
                core::ptr::addr_of_mut!((*successor).rb_right).write_volatile(child);
                rb_set_parent(child, successor);
            }

            tmp = (*node).rb_left;
            core::ptr::addr_of_mut!((*successor).rb_left).write_volatile(tmp);
            rb_set_parent(tmp, successor);

            pc = (*node).__rb_parent_color;
            let gp = raw_rb_parent(pc);
            __rb_change_child(node, successor, gp, root);

            if !child2.is_null() {
                rb_set_parent_color(child2, parent, RB_BLACK);
                rebalance = core::ptr::null_mut();
            } else {
                rebalance = if rb_is_black(successor) { parent } else { core::ptr::null_mut() };
            }
            (*successor).__rb_parent_color = pc;
            tmp = successor;
        }

        let _ = tmp;
        rebalance
    }
}

kernel::kabi_export! {
    rb_erase,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } node , formal_parameter pointer_type { s#rb_root } root ) -> base_type void",
}

/// `rb_erase()`.
///
/// # Safety
/// `node` must be a live node currently linked into `*root`.
#[no_mangle]
pub unsafe extern "C" fn rb_erase(node: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let rebalance = rb_erase_splice(node, root);
        if !rebalance.is_null() {
            rb_erase_color(rebalance, root, dummy_rotate);
        }
    }
}

// ---------------------------------------------------------------------------
// Augmented entry point.
// ---------------------------------------------------------------------------

kernel::kabi_export! {
    __rb_insert_augmented,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } node , formal_parameter pointer_type { s#rb_root } root , formal_parameter pointer_type { subroutine_type ( formal_parameter pointer_type { s#rb_node } , formal_parameter pointer_type { s#rb_node } ) -> base_type void } augment_rotate ) -> base_type void",
}

/// `__rb_insert_augmented()`.
///
/// # Safety
/// Same as [`__rb_insert`].
#[no_mangle]
pub unsafe extern "C" fn __rb_insert_augmented(node: *mut RbNode, root: *mut RbRoot, augment_rotate: AugmentRotate) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe { __rb_insert(node, root, augment_rotate) }
}

// ---------------------------------------------------------------------------
// Traversal.
// ---------------------------------------------------------------------------

kernel::kabi_export! {
    rb_first,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_root } } root ) -> pointer_type { s#rb_node }",
}

/// `rb_first()`.
///
/// # Safety
/// `root` must be valid.
#[no_mangle]
pub unsafe extern "C" fn rb_first(root: *const RbRoot) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let mut n = (*root).rb_node;
        if n.is_null() {
            return core::ptr::null_mut();
        }
        while !(*n).rb_left.is_null() {
            n = (*n).rb_left;
        }
        n
    }
}

kernel::kabi_export! {
    rb_last,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_root } } root ) -> pointer_type { s#rb_node }",
}

/// `rb_last()`.
///
/// # Safety
/// `root` must be valid.
#[no_mangle]
pub unsafe extern "C" fn rb_last(root: *const RbRoot) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let mut n = (*root).rb_node;
        if n.is_null() {
            return core::ptr::null_mut();
        }
        while !(*n).rb_right.is_null() {
            n = (*n).rb_right;
        }
        n
    }
}

/// `RB_EMPTY_NODE()`.
///
/// # Safety
/// `node` must be valid.
#[inline(always)]
unsafe fn rb_empty_node(node: *const RbNode) -> bool {
    // SAFETY: caller guarantees `node` is valid.
    unsafe { (*node).__rb_parent_color == node as usize }
}

kernel::kabi_export! {
    rb_next,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_node } } node ) -> pointer_type { s#rb_node }",
}

/// `rb_next()`.
///
/// # Safety
/// `node` must be valid.
#[no_mangle]
pub unsafe extern "C" fn rb_next(node: *const RbNode) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        if rb_empty_node(node) {
            return core::ptr::null_mut();
        }

        if !(*node).rb_right.is_null() {
            let mut n = (*node).rb_right;
            while !(*n).rb_left.is_null() {
                n = (*n).rb_left;
            }
            return n;
        }

        let mut node = node;
        let mut parent;
        loop {
            parent = rb_parent(node);
            if parent.is_null() || node != (*parent).rb_right {
                break;
            }
            node = parent;
        }
        parent
    }
}

kernel::kabi_export! {
    rb_prev,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_node } } node ) -> pointer_type { s#rb_node }",
}

/// `rb_prev()`.
///
/// # Safety
/// `node` must be valid.
#[no_mangle]
pub unsafe extern "C" fn rb_prev(node: *const RbNode) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        if rb_empty_node(node) {
            return core::ptr::null_mut();
        }

        if !(*node).rb_left.is_null() {
            let mut n = (*node).rb_left;
            while !(*n).rb_right.is_null() {
                n = (*n).rb_right;
            }
            return n;
        }

        let mut node = node;
        let mut parent;
        loop {
            parent = rb_parent(node);
            if parent.is_null() || node != (*parent).rb_left {
                break;
            }
            node = parent;
        }
        parent
    }
}

kernel::kabi_export! {
    rb_replace_node,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } victim , formal_parameter pointer_type { s#rb_node } new , formal_parameter pointer_type { s#rb_root } root ) -> base_type void",
}

/// `rb_replace_node()`.
///
/// # Safety
/// `victim` must be valid and linked into `*root`; `new` must be valid and
/// not linked into any tree.
#[no_mangle]
pub unsafe extern "C" fn rb_replace_node(victim: *mut RbNode, new: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let parent = rb_parent(victim);

        *new = RbNode {
            __rb_parent_color: (*victim).__rb_parent_color,
            rb_right: (*victim).rb_right,
            rb_left: (*victim).rb_left,
        };

        if !(*victim).rb_left.is_null() {
            rb_set_parent((*victim).rb_left, new);
        }
        if !(*victim).rb_right.is_null() {
            rb_set_parent((*victim).rb_right, new);
        }
        __rb_change_child(victim, new, parent, root);
    }
}

kernel::kabi_export! {
    rb_replace_node_rcu,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#rb_node } victim , formal_parameter pointer_type { s#rb_node } new , formal_parameter pointer_type { s#rb_root } root ) -> base_type void",
}

/// `rb_replace_node_rcu()`.
///
/// # Safety
/// Same as [`rb_replace_node`].
#[no_mangle]
pub unsafe extern "C" fn rb_replace_node_rcu(victim: *mut RbNode, new: *mut RbNode, root: *mut RbRoot) {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let parent = rb_parent(victim);

        *new = RbNode {
            __rb_parent_color: (*victim).__rb_parent_color,
            rb_right: (*victim).rb_right,
            rb_left: (*victim).rb_left,
        };

        if !(*victim).rb_left.is_null() {
            rb_set_parent((*victim).rb_left, new);
        }
        if !(*victim).rb_right.is_null() {
            rb_set_parent((*victim).rb_right, new);
        }

        // The parent's pointer is set last, after the release fence
        // __rb_change_child_rcu() applies, so an RCU walk over the tree
        // sees the pointers onward already correct -- the C's own comment.
        __rb_change_child_rcu(victim, new, parent, root);
    }
}

/// `rb_left_deepest_node()`.
///
/// # Safety
/// `node` must be valid.
unsafe fn rb_left_deepest_node(node: *const RbNode) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        let mut node = node;
        loop {
            if !(*node).rb_left.is_null() {
                node = (*node).rb_left;
            } else if !(*node).rb_right.is_null() {
                node = (*node).rb_right;
            } else {
                return node as *mut RbNode;
            }
        }
    }
}

kernel::kabi_export! {
    rb_next_postorder,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_node } } node ) -> pointer_type { s#rb_node }",
}

/// `rb_next_postorder()`.
///
/// # Safety
/// `node` must be valid, or null.
#[no_mangle]
pub unsafe extern "C" fn rb_next_postorder(node: *const RbNode) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        if node.is_null() {
            return core::ptr::null_mut();
        }
        let parent = rb_parent(node);

        if !parent.is_null() && node == (*parent).rb_left && !(*parent).rb_right.is_null() {
            rb_left_deepest_node((*parent).rb_right)
        } else {
            parent
        }
    }
}

kernel::kabi_export! {
    rb_first_postorder,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#rb_root } } root ) -> pointer_type { s#rb_node }",
}

/// `rb_first_postorder()`.
///
/// # Safety
/// `root` must be valid.
#[no_mangle]
pub unsafe extern "C" fn rb_first_postorder(root: *const RbRoot) -> *mut RbNode {
    // SAFETY: class B (boundary). The caller's contract above.
    unsafe {
        if (*root).rb_node.is_null() {
            return core::ptr::null_mut();
        }
        rb_left_deepest_node((*root).rb_node)
    }
}
