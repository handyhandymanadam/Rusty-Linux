// SPDX-License-Identifier: GPL-2.0-or-later

//! Generic timer-queue -- the Rust behind `lib/timerqueue.c`.
//!
//! Replaces: lib/timerqueue.c
//!
//! A `timerqueue_node` is an rbtree node (`struct rb_node`) plus an
//! expiration time, ordered by expiration, with the leftmost (soonest)
//! node cached for O(1) access -- exactly `struct rb_root_cached`.
//!
//! # Calling into `lib/rbtree.c`, not reproducing it
//!
//! `rb_insert_color()`, `rb_erase()` and `rb_next()` are real, exported,
//! `lib/rbtree.c` functions -- the rebalancing logic, unported and far
//! larger than this file. `rb_add_cached()`, `rb_insert_color_cached()`,
//! `rb_erase_cached()` and `rb_link_node()`, by contrast, are `static
//! inline` in `include/linux/rbtree.h`: header text with no linkable
//! symbol, so this file reproduces their (short) bodies directly and calls
//! through to the three real functions for the actual tree surgery --
//! exactly what the C compiled to at this call site, just written out
//! instead of textually included.
//!
//! # The comparator is specialized, not passed as a function pointer
//!
//! `rb_add_cached()`'s C signature takes a generic `less` callback; this
//! file has exactly one caller with exactly one comparator
//! (`__timerqueue_less`, comparing `expires`), so the reproduced loop calls
//! it directly rather than carrying a function-pointer parameter that
//! would only ever be given one argument.
//!
//! # No locking here, same as the C
//!
//! The original's own top comment: *"All of the following functions need
//! to be serialized to avoid races. No locking is done by this library
//! code."* Every field access below is a plain read/write for the same
//! reason the C's is -- the caller's serialization is what makes it safe,
//! not anything this file could add.

use core::ptr;

/// Mirrors `struct rb_node` (`include/linux/rbtree.h`). Field order and
/// offsets from the compiled C's own DWARF (`rig/kabi-pin.sh --capture`),
/// not transcribed from the header, and checked by `rig/layout-check.sh`.
#[repr(C)]
pub struct RbNode {
    rb_parent_color: usize,
    rb_right: *mut RbNode,
    rb_left: *mut RbNode,
}

/// Mirrors `struct rb_root`.
#[repr(C)]
pub struct RbRoot {
    rb_node: *mut RbNode,
}

/// Mirrors `struct rb_root_cached`.
#[repr(C)]
pub struct RbRootCached {
    rb_root: RbRoot,
    rb_leftmost: *mut RbNode,
}

/// Mirrors `struct timerqueue_head` -- the type this file's exports are
/// declared against.
#[repr(C)]
pub struct TimerqueueHead {
    rb_root: RbRootCached,
}

/// Mirrors `struct timerqueue_node`. `node` at offset 0 is what makes
/// `container_of(rb_node_ptr, timerqueue_node, node)` in
/// [`timerqueue_iterate_next`] a plain pointer cast, exactly as it is here.
#[repr(C)]
pub struct TimerqueueNode {
    node: RbNode,
    expires: i64, // ktime_t
}

extern "C" {
    fn rb_insert_color(node: *mut RbNode, root: *mut RbRoot);
    fn rb_erase(node: *mut RbNode, root: *mut RbRoot);
    fn rb_next(node: *const RbNode) -> *mut RbNode;
}

/// `RB_EMPTY_NODE()`.
#[inline]
unsafe fn rb_empty_node(node: *const RbNode) -> bool {
    // SAFETY: caller guarantees `node` is valid.
    unsafe { (*node).rb_parent_color == node as usize }
}

/// `RB_CLEAR_NODE()`.
#[inline]
unsafe fn rb_clear_node(node: *mut RbNode) {
    // SAFETY: caller guarantees `node` is valid.
    unsafe { (*node).rb_parent_color = node as usize };
}

/// `RB_EMPTY_ROOT()`.
///
/// Deliberate divergence, recorded rather than silent: the C macro reads
/// through `READ_ONCE()`, a volatile single-word read; this is a plain
/// read. Inert under this file's own contract -- no locking, caller
/// serializes -- but noted because it does not literally match the macro.
#[inline]
unsafe fn rb_empty_root(root: *const RbRoot) -> bool {
    // SAFETY: caller guarantees `root` is valid.
    unsafe { (*root).rb_node.is_null() }
}

/// `rb_link_node()`.
#[inline]
unsafe fn rb_link_node(node: *mut RbNode, parent: *mut RbNode, rb_link: *mut *mut RbNode) {
    // SAFETY: caller guarantees `node` and `rb_link` are valid; `parent`
    // may be null (the tree-was-empty case), which is a valid parent value.
    unsafe {
        (*node).rb_parent_color = parent as usize;
        (*node).rb_left = ptr::null_mut();
        (*node).rb_right = ptr::null_mut();
        *rb_link = node;
    }
}

/// `rb_insert_color_cached()`.
#[inline]
unsafe fn rb_insert_color_cached(node: *mut RbNode, root: *mut RbRootCached, leftmost: bool) {
    // SAFETY: caller guarantees `node` and `root` are valid.
    unsafe {
        if leftmost {
            (*root).rb_leftmost = node;
        }
        rb_insert_color(node, ptr::addr_of_mut!((*root).rb_root));
    }
}

/// `rb_erase_cached()`.
#[inline]
unsafe fn rb_erase_cached(node: *mut RbNode, root: *mut RbRootCached) -> *mut RbNode {
    // SAFETY: caller guarantees `node` and `root` are valid.
    unsafe {
        let mut leftmost = ptr::null_mut();
        if (*root).rb_leftmost == node {
            leftmost = rb_next(node);
            (*root).rb_leftmost = leftmost;
        }
        rb_erase(node, ptr::addr_of_mut!((*root).rb_root));
        leftmost
    }
}

/// `__timerqueue_less()`.
#[inline]
unsafe fn timerqueue_less(a: *const RbNode, b: *const RbNode) -> bool {
    // SAFETY: both are `node` fields of a `TimerqueueNode`, offset 0, so
    // this is the same pointer the enclosing `TimerqueueNode` starts at.
    unsafe {
        (*a.cast::<TimerqueueNode>()).expires < (*b.cast::<TimerqueueNode>()).expires
    }
}

/// `rb_add_cached()`, specialized to [`timerqueue_less`]. Returns `node`
/// when it became the new leftmost, `NULL` otherwise.
#[inline]
unsafe fn rb_add_cached_tq(node: *mut RbNode, tree: *mut RbRootCached) -> *mut RbNode {
    // SAFETY: caller guarantees `node` and `tree` are valid.
    unsafe {
        let mut link = ptr::addr_of_mut!((*tree).rb_root.rb_node);
        let mut parent: *mut RbNode = ptr::null_mut();
        let mut leftmost = true;

        while !(*link).is_null() {
            parent = *link;
            if timerqueue_less(node, parent) {
                link = ptr::addr_of_mut!((*parent).rb_left);
            } else {
                link = ptr::addr_of_mut!((*parent).rb_right);
                leftmost = false;
            }
        }

        rb_link_node(node, parent, link);
        rb_insert_color_cached(node, tree, leftmost);

        if leftmost { node } else { ptr::null_mut() }
    }
}

// The C types these contracts name. Generated by `rig/kabi-pin.sh
// --capture`; do not hand-edit -- see logs/pins/timerqueue.pins.
kernel::kabi_rule!("type_string", "t#__s64",
    "typedef_type __s64 { base_type long long byte_size(8) encoding(5) }");
kernel::kabi_rule!("type_string", "t#s64",
    "typedef_type s64 { t#__s64 }");
kernel::kabi_rule!("type_string", "t#ktime_t",
    "typedef_type ktime_t { t#s64 }");
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "s#rb_node",
    "structure_type rb_node { member base_type unsigned long byte_size(8) \
     encoding(7) __rb_parent_color data_member_location(0) , member \
     pointer_type { s#rb_node } rb_right data_member_location(8) , member \
     pointer_type { s#rb_node } rb_left data_member_location(16) } \
     byte_size(24) alignment(8)");
kernel::kabi_rule!("type_string", "s#rb_root",
    "structure_type rb_root { member pointer_type { s#rb_node } rb_node \
     data_member_location(0) } byte_size(8)");
kernel::kabi_rule!("type_string", "s#rb_root_cached",
    "structure_type rb_root_cached { member s#rb_root rb_root \
     data_member_location(0) , member pointer_type { s#rb_node } \
     rb_leftmost data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#timerqueue_head",
    "structure_type timerqueue_head { member s#rb_root_cached rb_root \
     data_member_location(0) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#timerqueue_node",
    "structure_type timerqueue_node { member s#rb_node node \
     data_member_location(0) , member t#ktime_t expires \
     data_member_location(24) } byte_size(32)");

kernel::kabi_export! {
    timerqueue_add,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timerqueue_head } head , formal_parameter pointer_type { s#timerqueue_node } node ) -> t#bool",
}

/// `timerqueue_add()`: add `node` to `head`, sorted by `expires`. Returns
/// `true` if `node` is now the soonest-expiring timer in the queue.
///
/// # Safety
/// `head` and `node` must be valid, and `node` must not already be linked
/// into any timerqueue.
#[no_mangle]
pub unsafe extern "C" fn timerqueue_add(head: *mut TimerqueueHead, node: *mut TimerqueueNode) -> bool {
    // SAFETY: caller guarantees `node` is valid.
    let n = unsafe { ptr::addr_of_mut!((*node).node) };
    // SAFETY: `n` is valid, from the line above.
    kernel::kabi_warn_on_once!(!unsafe { rb_empty_node(n) });
    // SAFETY: caller guarantees `head` and `node` are valid, and that
    // `node` is not already linked, which is what the warning above checks.
    let added = unsafe { rb_add_cached_tq(n, ptr::addr_of_mut!((*head).rb_root)) };
    !added.is_null()
}

kernel::kabi_export! {
    timerqueue_del,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timerqueue_head } head , formal_parameter pointer_type { s#timerqueue_node } node ) -> t#bool",
}

/// `timerqueue_del()`: remove `node` from `head`. Returns `true` if the
/// queue is non-empty afterward.
///
/// # Safety
/// `head` and `node` must be valid, and `node` must currently be linked
/// into `head`.
#[no_mangle]
pub unsafe extern "C" fn timerqueue_del(head: *mut TimerqueueHead, node: *mut TimerqueueNode) -> bool {
    // SAFETY: caller guarantees `node` is valid.
    let n = unsafe { ptr::addr_of_mut!((*node).node) };
    // SAFETY: `n` is valid, from the line above.
    kernel::kabi_warn_on_once!(unsafe { rb_empty_node(n) });
    // SAFETY: caller guarantees `head` and `node` are valid and linked.
    unsafe {
        let root = ptr::addr_of_mut!((*head).rb_root);
        rb_erase_cached(n, root);
        rb_clear_node(n);
        !rb_empty_root(ptr::addr_of!((*root).rb_root))
    }
}

kernel::kabi_export! {
    timerqueue_iterate_next,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timerqueue_node } node ) -> pointer_type { s#timerqueue_node }",
}

/// `timerqueue_iterate_next()`: the timer after `node`, in expiration
/// order, or `NULL` at the end.
///
/// # Safety
/// `node`, if non-null, must be valid and linked into a timerqueue.
#[no_mangle]
pub unsafe extern "C" fn timerqueue_iterate_next(node: *mut TimerqueueNode) -> *mut TimerqueueNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `node` is valid and linked.
    let next = unsafe { rb_next(ptr::addr_of!((*node).node)) };
    if next.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `next` is a `node` field of some `TimerqueueNode`, offset 0.
    next.cast::<TimerqueueNode>()
}
