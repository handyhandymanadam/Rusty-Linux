// SPDX-License-Identifier: GPL-2.0-or-later

//! Generic associative array -- the Rust behind `lib/assoc_array.c`.
//!
//! Ported from `lib/assoc_array.c` (6.18.49), "Generic associative array implementation" by David Howells: a radix tree keyed on chunks
//! of an index key (16-way nodes, shortcuts that skip runs of identical key bits), edited copy-on-write so readers under RCU never see
//! a half-made change. Everything in the file is here: the walk (`assoc_array_walk`), `find`, `iterate`, `destroy`, the three insertion
//! shapes (empty tree, terminal node, mid-shortcut), `delete` with collapse, `clear`, `gc`, and the edit machinery (`apply_edit`,
//! `cancel_edit`, the RCU cleanup).
//!
//! # What stays C (`assoc_array_glue.c`)
//! * Nothing of the algorithm. None of the ten public functions is `EXPORT_SYMBOL`'d (only built-in code such as the keyrings uses
//!   them), so there are no MODVERSIONS fingerprints to protect and this file defines them directly under their C names.
//! * `kzalloc`/`kmalloc`/`kfree` (one-line helpers), `call_rcu` and the RCU callback that calls [`rust_assoc_array_rcu_cleanup`],
//!   and `BUG()`. Every `BUG_ON` of the C is a call to the one `rust_assoc_array_bug()` helper here: the recorded divergence is that
//!   the bug-table entry names the glue, one line for all of them, not the original sites.
//!
//! # The ordering contract (concurrency bar, item 1)
//! Readers (`iterate`, `walk`, `find`) hold the RCU read lock and follow pointers with `READ_ONCE` (here `read_volatile`: the C relies
//! on the address dependency, which x86 and every other mainstream CPU honour, and on the compiler not caching the load). Writers
//! are serialised by the caller and never edit a published node in place: `apply_edit` first builds everything off to the side,
//! then publishes with four `smp_wmb()`-separated groups of plain stores -- the new leaf, the parent-slot fix-ups, the back-pointer
//! fix-ups, and last the pointer(s) that make the new subtree reachable -- exactly as the C. `smp_wmb()` is `fence(Release)` (a
//! compiler barrier on x86). The old pieces are freed by `call_rcu` after a grace period.
//!
//! # Mechanical translation
//! The C is goto-heavy; each label becomes a state of a `loop { match state }`. Variable names, the order of every assignment and
//! every `BUG_ON` follow the C. Pointers keep their tag bits (`ASSOC_ARRAY_PTR_*`).
//!
//! Replaces: lib/assoc_array.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::too_many_lines)]

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr::{null, null_mut, read_volatile};
use core::sync::atomic::{fence, Ordering};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("assoc_array_rs.rs: x86-64 little-endian only (BITS_PER_LONG == 64 chunks, struct layouts)");

const ENOMEM: c_int = 12;

const FAN_OUT: usize = 16;
const FAN_MASK: c_ulong = 15;
const LEVEL_STEP: c_int = 4;
const LEVEL_STEP_MASK: c_int = 3;
const KEY_CHUNK_SIZE: c_int = 64;
const KEY_CHUNK_MASK: c_int = 63;
const KEY_CHUNK_SHIFT: c_int = 6;

const PTR_TYPE_MASK: usize = 0x1;
const PTR_META_TYPE: usize = 0x1;
const PTR_SUBTYPE_MASK: usize = 0x2;
const PTR_SHORTCUT_SUBTYPE: usize = 0x2;

/// `struct assoc_array_ptr *`: a tagged pointer.
type Ptr = *mut c_void;

/// `struct assoc_array_node`.
#[repr(C)]
pub struct Node {
    back_pointer: Ptr,
    parent_slot: u8,
    slots: [Ptr; FAN_OUT],
    nr_leaves_on_branch: c_ulong,
}

/// `struct assoc_array_shortcut` (the flexible `index_key[]` follows the header).
#[repr(C)]
pub struct Shortcut {
    back_pointer: Ptr,
    parent_slot: c_int,
    skip_to_level: c_int,
    next_node: Ptr,
    index_key: [c_ulong; 0],
}

/// `struct assoc_array`.
#[repr(C)]
pub struct AssocArray {
    root: Ptr,
    nr_leaves_on_tree: c_ulong,
}

/// `struct assoc_array_ops`.
#[repr(C)]
pub struct Ops {
    get_key_chunk: unsafe extern "C" fn(*const c_void, c_int) -> c_ulong,
    get_object_key_chunk: unsafe extern "C" fn(*const c_void, c_int) -> c_ulong,
    compare_object: unsafe extern "C" fn(*const c_void, *const c_void) -> bool,
    diff_objects: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    free_object: unsafe extern "C" fn(*mut c_void),
}

#[repr(C)]
struct SetPtr {
    ptr: *mut Ptr,
    to: Ptr,
}

#[repr(C)]
struct SetSlot {
    p: *mut u8,
    to: u8,
}

/// `struct assoc_array_edit`.
#[repr(C)]
pub struct Edit {
    rcu: [usize; 2],
    array: *mut AssocArray,
    ops: *const Ops,
    ops_for_excised_subtree: *const Ops,
    leaf: Ptr,
    leaf_p: *mut Ptr,
    dead_leaf: Ptr,
    new_meta: [Ptr; 3],
    excised_meta: [Ptr; 1],
    excised_subtree: Ptr,
    set_backpointers: [*mut Ptr; FAN_OUT],
    set_backpointers_to: Ptr,
    adjust_count_on: *mut Node,
    adjust_count_by: c_long,
    set: [SetPtr; 2],
    set_parent_slot: [SetSlot; 1],
    segment_cache: [u8; FAN_OUT + 1],
}

extern "C" {
    fn rust_assoc_array_kzalloc(size: usize) -> *mut c_void;
    fn rust_assoc_array_kmalloc(size: usize) -> *mut c_void;
    fn rust_assoc_array_kfree(p: *mut c_void);
    fn rust_assoc_array_call_rcu(edit: *mut Edit);
    fn rust_assoc_array_bug() -> !;
}

// ---------------------------------------------------------------------------
// assoc_array_priv.h
// ---------------------------------------------------------------------------

#[inline(always)]
fn is_meta(x: Ptr) -> bool {
    x as usize & PTR_TYPE_MASK != 0
}
#[inline(always)]
fn is_leaf(x: Ptr) -> bool {
    !is_meta(x)
}
#[inline(always)]
fn is_shortcut(x: Ptr) -> bool {
    x as usize & PTR_SUBTYPE_MASK != 0
}
#[inline(always)]
fn is_node(x: Ptr) -> bool {
    !is_shortcut(x)
}
#[inline(always)]
fn to_leaf(x: Ptr) -> *mut c_void {
    (x as usize & !PTR_TYPE_MASK) as *mut c_void
}
#[inline(always)]
fn to_node(x: Ptr) -> *mut Node {
    (x as usize & !(PTR_SUBTYPE_MASK | PTR_TYPE_MASK)) as *mut Node
}
#[inline(always)]
fn to_shortcut(x: Ptr) -> *mut Shortcut {
    (x as usize & !(PTR_SUBTYPE_MASK | PTR_TYPE_MASK)) as *mut Shortcut
}
#[inline(always)]
fn leaf_to_ptr(p: *const c_void) -> Ptr {
    p as usize as Ptr
}
#[inline(always)]
fn node_to_ptr(p: *const Node) -> Ptr {
    (p as usize | PTR_META_TYPE) as Ptr
}
#[inline(always)]
fn shortcut_to_ptr(p: *const Shortcut) -> Ptr {
    (p as usize | PTR_META_TYPE | PTR_SHORTCUT_SUBTYPE) as Ptr
}

/// `BUG_ON(cond)`.
#[inline(always)]
fn bug_on(cond: bool) {
    if cond {
        // SAFETY: never returns.
        unsafe { rust_assoc_array_bug() }
    }
}

/// `READ_ONCE()`.
#[inline(always)]
unsafe fn rd<T: Copy>(p: *const T) -> T {
    // SAFETY: caller contract (valid, aligned).
    unsafe { read_volatile(p) }
}

/// `round_up(x, 64)` / `round_down(x, 64)` on a (non-negative) int.
#[inline(always)]
fn round_up_chunk(x: c_int) -> c_int {
    (x + KEY_CHUNK_MASK) & !KEY_CHUNK_MASK
}
#[inline(always)]
fn round_down_chunk(x: c_int) -> c_int {
    x & !KEY_CHUNK_MASK
}

/// `sizeof(struct assoc_array_shortcut) + keylen * sizeof(unsigned long)` (`struct_size(s, index_key, keylen)`).
#[inline(always)]
fn shortcut_size(keylen: usize) -> usize {
    core::mem::size_of::<Shortcut>() + keylen * core::mem::size_of::<c_ulong>()
}

/// `s->index_key` as a pointer.
#[inline(always)]
unsafe fn index_key(s: *mut Shortcut) -> *mut c_ulong {
    // SAFETY: the flexible array starts right after the header.
    unsafe { (&raw mut (*s).index_key).cast::<c_ulong>() }
}

// ---------------------------------------------------------------------------
// iteration
// ---------------------------------------------------------------------------

type Iterator_ = unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int;

/// `assoc_array_subtree_iterate()`: iterate over a subtree; the caller holds the RCU read lock or better.
unsafe fn subtree_iterate(root: Ptr, stop: Ptr, iterator: Iterator_, iterator_data: *mut c_void) -> c_int {
    #[derive(Clone, Copy)]
    enum S {
        BeginNode,
        ContinueNode,
        FinishedNode,
    }
    // SAFETY: caller contract.
    unsafe {
        let mut cursor = root;
        let mut node: *mut Node = null_mut();
        let mut slot: c_int = 0;
        let mut s = S::BeginNode;

        loop {
            match s {
                S::BeginNode => {
                    if is_shortcut(cursor) {
                        /* Descend through a shortcut */
                        let shortcut = to_shortcut(cursor);
                        cursor = rd(&raw const (*shortcut).next_node); /* Address dependency. */
                    }

                    node = to_node(cursor);
                    slot = 0;

                    /* We perform two passes of each node. The first pass does all the leaves in this node. */
                    let mut has_meta: usize = 0;
                    while (slot as usize) < FAN_OUT {
                        let ptr = rd(&raw const (*node).slots[slot as usize]); /* Address dependency. */
                        has_meta |= ptr as usize;
                        if !ptr.is_null() && is_leaf(ptr) {
                            let ret = iterator(to_leaf(ptr), iterator_data);
                            if ret != 0 {
                                return ret;
                            }
                        }
                        slot += 1;
                    }

                    /* The second pass attends to all the metadata pointers. */
                    if has_meta & PTR_META_TYPE == 0 {
                        s = S::FinishedNode;
                    } else {
                        slot = 0;
                        s = S::ContinueNode;
                    }
                }
                S::ContinueNode => {
                    node = to_node(cursor);
                    let mut descended = false;
                    while (slot as usize) < FAN_OUT {
                        let ptr = rd(&raw const (*node).slots[slot as usize]); /* Address dependency. */
                        if is_meta(ptr) {
                            cursor = ptr;
                            descended = true;
                            break;
                        }
                        slot += 1;
                    }
                    s = if descended { S::BeginNode } else { S::FinishedNode };
                }
                S::FinishedNode => {
                    /* Move up to the parent (may need to skip back over a shortcut) */
                    let mut parent = rd(&raw const (*node).back_pointer); /* Address dependency. */
                    slot = (*node).parent_slot as c_int;
                    if parent == stop {
                        return 0;
                    }

                    if is_shortcut(parent) {
                        let shortcut = to_shortcut(parent);
                        /* (the C also does `cursor = parent` here; it is overwritten below before any read) */
                        parent = rd(&raw const (*shortcut).back_pointer); /* Address dependency. */
                        slot = (*shortcut).parent_slot;
                        if parent == stop {
                            return 0;
                        }
                    }

                    /* Ascend to next slot in parent node */
                    cursor = parent;
                    slot += 1;
                    s = S::ContinueNode;
                }
            }
        }
    }
}

/// `assoc_array_iterate()`.
///
/// # Safety
/// `array` valid; the caller holds the RCU read lock or better.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_iterate(array: *const AssocArray, iterator: Iterator_, iterator_data: *mut c_void) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let root = rd(&raw const (*array).root); /* Address dependency. */

        if root.is_null() {
            return 0;
        }
        subtree_iterate(root, null_mut(), iterator, iterator_data)
    }
}

// ---------------------------------------------------------------------------
// walk
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    TreeEmpty,
    FoundTerminalNode,
    FoundWrongShortcut,
}

struct TerminalNode {
    node: *mut Node,
    level: c_int,
    slot: c_int,
}

struct WrongShortcut {
    shortcut: *mut Shortcut,
    level: c_int,
    sc_level: c_int,
    sc_segments: c_ulong,
    dissimilarity: c_ulong,
}

struct WalkResult {
    terminal_node: TerminalNode,
    wrong_shortcut: WrongShortcut,
}

/// `assoc_array_walk()`: navigate through the internal tree looking for the closest node to the key.
unsafe fn walk(array: *const AssocArray, ops: *const Ops, index_key_: *const c_void, result: &mut WalkResult) -> Walk {
    #[derive(Clone, Copy)]
    enum S {
        Jumped,
        ConsiderNode,
        FollowShortcut,
    }
    // SAFETY: caller contract.
    unsafe {
        let mut cursor = rd(&raw const (*array).root); /* Address dependency. */
        if cursor.is_null() {
            return Walk::TreeEmpty;
        }

        let mut level: c_int = 0;
        let mut segments: c_ulong = 0;
        let mut s = S::Jumped;

        loop {
            match s {
                S::Jumped => {
                    segments = ((*ops).get_key_chunk)(index_key_, level);

                    if is_shortcut(cursor) {
                        s = S::FollowShortcut;
                    } else {
                        s = S::ConsiderNode;
                    }
                }
                S::ConsiderNode => {
                    let node = to_node(cursor);
                    let slot = (segments >> (level & KEY_CHUNK_MASK)) & FAN_MASK;
                    let ptr = rd(&raw const (*node).slots[slot as usize]); /* Address dependency. */

                    if !is_meta(ptr) {
                        /* The node doesn't have a node/shortcut pointer in the slot corresponding to the index key that we
                         * have to follow. */
                        result.terminal_node.node = node;
                        result.terminal_node.level = level;
                        result.terminal_node.slot = slot as c_int;
                        return Walk::FoundTerminalNode;
                    }

                    if is_node(ptr) {
                        /* There is a pointer to a node in the slot corresponding to this index key segment, so we need to
                         * follow it. */
                        cursor = ptr;
                        level += LEVEL_STEP;
                        if level & KEY_CHUNK_MASK != 0 {
                            s = S::ConsiderNode;
                        } else {
                            s = S::Jumped;
                        }
                        continue;
                    }

                    /* There is a shortcut in the slot corresponding to the index key segment. */
                    cursor = ptr;
                    s = S::FollowShortcut;
                }
                S::FollowShortcut => {
                    let shortcut = to_shortcut(cursor);
                    let mut sc_level = level + LEVEL_STEP;
                    bug_on(sc_level > (*shortcut).skip_to_level);

                    loop {
                        /* Check the leaf against the shortcut's index key a word at a time, trimming the final word. */
                        if sc_level & KEY_CHUNK_MASK == 0 {
                            segments = ((*ops).get_key_chunk)(index_key_, sc_level);
                        }

                        let sc_segments = *index_key(shortcut).add((sc_level >> KEY_CHUNK_SHIFT) as usize);
                        let mut dissimilarity = segments ^ sc_segments;
                        let next_sc_level: c_int;

                        if (*shortcut).skip_to_level < round_down_chunk(sc_level) + KEY_CHUNK_SIZE {
                            /* Trim segments that are beyond the shortcut */
                            let shift = (*shortcut).skip_to_level & KEY_CHUNK_MASK;
                            dissimilarity &= !(c_ulong::MAX << shift);
                            next_sc_level = (*shortcut).skip_to_level;
                        } else {
                            next_sc_level = round_down_chunk(sc_level + KEY_CHUNK_SIZE);
                        }

                        if dissimilarity != 0 {
                            /* This shortcut points elsewhere */
                            result.wrong_shortcut.shortcut = shortcut;
                            result.wrong_shortcut.level = level;
                            result.wrong_shortcut.sc_level = sc_level;
                            result.wrong_shortcut.sc_segments = sc_segments;
                            result.wrong_shortcut.dissimilarity = dissimilarity;
                            return Walk::FoundWrongShortcut;
                        }

                        sc_level = next_sc_level;
                        if sc_level >= (*shortcut).skip_to_level {
                            break;
                        }
                    }

                    /* The shortcut matches the leaf's index to this point. */
                    cursor = rd(&raw const (*shortcut).next_node); /* Address dependency. */
                    if ((level ^ sc_level) & !KEY_CHUNK_MASK) != 0 {
                        level = sc_level;
                        s = S::Jumped;
                    } else {
                        level = sc_level;
                        s = S::ConsiderNode;
                    }
                }
            }
        }
    }
}

/// `assoc_array_find()`.
///
/// # Safety
/// `array` and `ops` valid; the caller holds the RCU read lock or better.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_find(array: *const AssocArray, ops: *const Ops, index_key_: *const c_void) -> *mut c_void {
    // SAFETY: caller contract.
    unsafe {
        let mut result = WalkResult {
            terminal_node: TerminalNode { node: null_mut(), level: 0, slot: 0 },
            wrong_shortcut: WrongShortcut { shortcut: null_mut(), level: 0, sc_level: 0, sc_segments: 0, dissimilarity: 0 },
        };

        if walk(array, ops, index_key_, &mut result) != Walk::FoundTerminalNode {
            return null_mut();
        }

        let node = result.terminal_node.node;

        /* If the target key is available to us, it's has to be pointed to by the terminal node. */
        let mut slot = 0;
        while slot < FAN_OUT {
            let ptr = rd(&raw const (*node).slots[slot]); /* Address dependency. */
            if !ptr.is_null() && is_leaf(ptr) {
                let leaf = to_leaf(ptr);
                if ((*ops).compare_object)(leaf, index_key_) {
                    return leaf;
                }
            }
            slot += 1;
        }

        null_mut()
    }
}

// ---------------------------------------------------------------------------
// destroy
// ---------------------------------------------------------------------------

/// `assoc_array_destroy_subtree()`: destructively iterate over an associative array; the caller prevents other accesses.
unsafe fn destroy_subtree(root: Ptr, ops: *const Ops) {
    #[derive(Clone, Copy)]
    enum S {
        MoveToMeta,
        ContinueNode,
    }
    // SAFETY: caller contract.
    unsafe {
        let mut cursor = root;
        let mut parent: Ptr = null_mut();
        let mut slot: c_int = -1;
        let mut node: *mut Node = null_mut();

        if cursor.is_null() {
            return;
        }
        let mut s = S::MoveToMeta;

        loop {
            match s {
                S::MoveToMeta => {
                    if is_shortcut(cursor) {
                        /* Descend through a shortcut */
                        bug_on(!is_shortcut(cursor));
                        let shortcut = to_shortcut(cursor);
                        bug_on((*shortcut).back_pointer != parent);
                        bug_on(slot != -1 && (*shortcut).parent_slot != slot);
                        parent = cursor;
                        cursor = (*shortcut).next_node;
                        slot = -1;
                        bug_on(!is_node(cursor));
                    }

                    node = to_node(cursor);
                    bug_on((*node).back_pointer != parent);
                    bug_on(slot != -1 && (*node).parent_slot as c_int != slot);
                    slot = 0;
                    s = S::ContinueNode;
                }
                S::ContinueNode => {
                    let mut moved = false;
                    while (slot as usize) < FAN_OUT {
                        let ptr = (*node).slots[slot as usize];
                        if ptr.is_null() {
                            slot += 1;
                            continue;
                        }
                        if is_meta(ptr) {
                            parent = cursor;
                            cursor = ptr;
                            moved = true;
                            break;
                        }

                        if !ops.is_null() {
                            ((*ops).free_object)(to_leaf(ptr));
                        }
                        slot += 1;
                    }
                    if moved {
                        s = S::MoveToMeta;
                        continue;
                    }

                    parent = (*node).back_pointer;
                    slot = (*node).parent_slot as c_int;
                    rust_assoc_array_kfree(node.cast());
                    if parent.is_null() {
                        return; /* Done */
                    }

                    /* Move back up to the parent (may need to free a shortcut on the way up) */
                    if is_shortcut(parent) {
                        let shortcut = to_shortcut(parent);
                        bug_on((*shortcut).next_node != cursor);
                        /* (the C also does `cursor = parent` here; it is overwritten below before any read) */
                        parent = (*shortcut).back_pointer;
                        slot = (*shortcut).parent_slot;
                        rust_assoc_array_kfree(shortcut.cast());
                        if parent.is_null() {
                            return;
                        }

                        bug_on(!is_node(parent));
                    }

                    /* Ascend to next slot in parent node */
                    cursor = parent;
                    node = to_node(cursor);
                    slot += 1;
                }
            }
        }
    }
}

/// `assoc_array_destroy()`.
///
/// # Safety
/// The caller prevents all other accesses.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_destroy(array: *mut AssocArray, ops: *const Ops) {
    // SAFETY: caller contract.
    unsafe {
        destroy_subtree((*array).root, ops);
        (*array).root = null_mut();
    }
}

// ---------------------------------------------------------------------------
// insertion
// ---------------------------------------------------------------------------

/// `assoc_array_insert_in_empty_tree()`.
unsafe fn insert_in_empty_tree(edit: *mut Edit) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let new_n0 = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
        if new_n0.is_null() {
            return false;
        }

        (*edit).new_meta[0] = node_to_ptr(new_n0);
        (*edit).leaf_p = &raw mut (*new_n0).slots[0];
        (*edit).adjust_count_on = new_n0;
        (*edit).set[0].ptr = &raw mut (*(*edit).array).root;
        (*edit).set[0].to = node_to_ptr(new_n0);

        true
    }
}

/// `assoc_array_insert_into_terminal_node()`.
unsafe fn insert_into_terminal_node(edit: *mut Edit, ops: *const Ops, index_key_: *const c_void, result: &WalkResult) -> bool {
    #[derive(Clone, Copy)]
    enum S {
        SplitNode,
        DoSplitNode,
        AllLeavesClusterTogether,
    }
    // SAFETY: caller contract.
    unsafe {
        let node = result.terminal_node.node;
        let mut level = result.terminal_node.level;
        (*edit).segment_cache[FAN_OUT] = result.terminal_node.slot as u8;

        let mut free_slot: c_int = -1;
        let mut i: usize;

        /* Firstly, we have to check the leaves in this node to see if there's a matching one we should replace in place. */
        i = 0;
        while i < FAN_OUT {
            let ptr = (*node).slots[i];
            if ptr.is_null() {
                free_slot = i as c_int;
                i += 1;
                continue;
            }
            if is_leaf(ptr) && ((*ops).compare_object)(to_leaf(ptr), index_key_) {
                (*edit).leaf_p = &raw mut (*node).slots[i];
                (*edit).dead_leaf = (*node).slots[i];
                return true;
            }
            i += 1;
        }

        /* If there is a free slot in this node then we can just insert the leaf here. */
        if free_slot >= 0 {
            (*edit).leaf_p = &raw mut (*node).slots[free_slot as usize];
            (*edit).adjust_count_on = node;
            return true;
        }

        /* The node has no spare slots - so we're either going to have to split it or insert another node before it. */
        let new_n0 = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
        if new_n0.is_null() {
            return false;
        }
        (*edit).new_meta[0] = node_to_ptr(new_n0);
        let new_n1 = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
        if new_n1.is_null() {
            return false;
        }
        (*edit).new_meta[1] = node_to_ptr(new_n1);

        /* We need to find out how similar the leaves are. */
        let mut have_meta = false;
        i = 0;
        while i < FAN_OUT {
            let ptr = (*node).slots[i];
            if is_meta(ptr) {
                (*edit).segment_cache[i] = 0xff;
                have_meta = true;
                i += 1;
                continue;
            }
            let mut base_seg = ((*ops).get_object_key_chunk)(to_leaf(ptr), level);
            base_seg >>= level & KEY_CHUNK_MASK;
            (*edit).segment_cache[i] = (base_seg & FAN_MASK) as u8;
            i += 1;
        }

        let mut s: S;
        if have_meta {
            s = S::SplitNode;
        } else {
            /* The node contains only leaves */
            let mut dissimilarity: c_ulong = 0;
            let base_seg = (*edit).segment_cache[0] as c_ulong;
            i = 1;
            while i < FAN_OUT {
                dissimilarity |= (*edit).segment_cache[i] as c_ulong ^ base_seg;
                i += 1;
            }

            s = S::SplitNode;
            if dissimilarity & FAN_MASK == 0 {
                /* The old leaves all cluster in the same slot. We will need to insert a shortcut if the new node wants to
                 * cluster with them. */
                if ((*edit).segment_cache[FAN_OUT] as c_ulong ^ base_seg) == 0 {
                    s = S::AllLeavesClusterTogether;
                }
                /* Otherwise fall through to the node splitting path. */
            }
        }

        let mut slot: c_int = 0;
        let mut j: usize = 0;
        let mut next_slot: c_int;
        let mut ptr: Ptr;

        loop {
            match s {
                S::SplitNode => {
                    /* We need to split the current node. */
                    (*edit).set[0].to = node_to_ptr(new_n0);
                    (*new_n0).back_pointer = (*node).back_pointer;
                    (*new_n0).parent_slot = (*node).parent_slot;
                    (*new_n1).back_pointer = node_to_ptr(new_n0);
                    (*new_n1).parent_slot = 0xff; /* Need to calculate this: the C stores -1 in a u8 */
                    s = S::DoSplitNode;
                }
                S::DoSplitNode => {
                    (*new_n0).nr_leaves_on_branch = (*node).nr_leaves_on_branch;
                    (*new_n1).nr_leaves_on_branch = 0;

                    /* Begin by finding two matching leaves. */
                    i = 0;
                    let mut found = false;
                    'find: while i < FAN_OUT {
                        slot = (*edit).segment_cache[i] as c_int;
                        if slot != 0xff {
                            j = i + 1;
                            while j < FAN_OUT + 1 {
                                if (*edit).segment_cache[j] as c_int == slot {
                                    found = true;
                                    break 'find;
                                }
                                j += 1;
                            }
                        }
                        i += 1;
                    }
                    if !found {
                        /* the C falls out of the loop with i == FAN_OUT; the first BUG_ON below fires */
                        i = FAN_OUT;
                    }
                    bug_on(i >= FAN_OUT);
                    bug_on(j >= FAN_OUT + 1);
                    bug_on(slot >= FAN_OUT as c_int);

                    (*new_n1).parent_slot = slot as u8;

                    /* Metadata pointers cannot change slot */
                    i = 0;
                    while i < FAN_OUT {
                        if is_meta((*node).slots[i]) {
                            (*new_n0).slots[i] = (*node).slots[i];
                        } else {
                            (*new_n0).slots[i] = null_mut();
                        }
                        i += 1;
                    }
                    bug_on(!(*new_n0).slots[slot as usize].is_null());
                    (*new_n0).slots[slot as usize] = node_to_ptr(new_n1);

                    /* Filter the leaf pointers between the new nodes */
                    free_slot = -1;
                    next_slot = 0;
                    i = 0;
                    while i < FAN_OUT {
                        if is_meta((*node).slots[i]) {
                            i += 1;
                            continue;
                        }
                        if (*edit).segment_cache[i] as c_int == slot {
                            (*new_n1).slots[next_slot as usize] = (*node).slots[i];
                            next_slot += 1;
                            (*new_n1).nr_leaves_on_branch += 1;
                        } else {
                            loop {
                                free_slot += 1;
                                if (*new_n0).slots[free_slot as usize].is_null() {
                                    break;
                                }
                            }
                            (*new_n0).slots[free_slot as usize] = (*node).slots[i];
                        }
                        i += 1;
                    }

                    if (*edit).segment_cache[FAN_OUT] as c_int != slot {
                        loop {
                            free_slot += 1;
                            if (*new_n0).slots[free_slot as usize].is_null() {
                                break;
                            }
                        }
                        (*edit).leaf_p = &raw mut (*new_n0).slots[free_slot as usize];
                        (*edit).adjust_count_on = new_n0;
                    } else {
                        (*edit).leaf_p = &raw mut (*new_n1).slots[next_slot as usize];
                        next_slot += 1;
                        (*edit).adjust_count_on = new_n1;
                    }

                    bug_on(next_slot <= 1);

                    (*edit).set_backpointers_to = node_to_ptr(new_n0);
                    i = 0;
                    while i < FAN_OUT {
                        if (*edit).segment_cache[i] == 0xff {
                            ptr = (*node).slots[i];
                            bug_on(is_leaf(ptr));
                            if is_node(ptr) {
                                let side = to_node(ptr);
                                (*edit).set_backpointers[i] = &raw mut (*side).back_pointer;
                            } else {
                                let shortcut = to_shortcut(ptr);
                                (*edit).set_backpointers[i] = &raw mut (*shortcut).back_pointer;
                            }
                        }
                        i += 1;
                    }

                    ptr = (*node).back_pointer;
                    if ptr.is_null() {
                        (*edit).set[0].ptr = &raw mut (*(*edit).array).root;
                    } else if is_node(ptr) {
                        (*edit).set[0].ptr = &raw mut (*to_node(ptr)).slots[(*node).parent_slot as usize];
                    } else {
                        (*edit).set[0].ptr = &raw mut (*to_shortcut(ptr)).next_node;
                    }
                    (*edit).excised_meta[0] = node_to_ptr(node);
                    return true;
                }
                S::AllLeavesClusterTogether => {
                    /* All the leaves, new and old, want to cluster together in this node in the same slot, so we have to
                     * replace this node with a shortcut to skip over the identical parts of the key. */
                    let mut diff: c_int = c_int::MAX;
                    i = 0;
                    while i < FAN_OUT {
                        let x = ((*ops).diff_objects)(to_leaf((*node).slots[i]), index_key_);
                        if x < diff {
                            bug_on(x < 0);
                            diff = x;
                        }
                        i += 1;
                    }
                    bug_on(diff == c_int::MAX);
                    bug_on(diff < level + LEVEL_STEP);

                    let mut keylen = round_up_chunk(diff) as usize;
                    keylen >>= KEY_CHUNK_SHIFT;

                    let new_s0 = rust_assoc_array_kzalloc(shortcut_size(keylen)).cast::<Shortcut>();
                    if new_s0.is_null() {
                        return false;
                    }
                    (*edit).new_meta[2] = shortcut_to_ptr(new_s0);

                    (*edit).set[0].to = shortcut_to_ptr(new_s0);
                    (*new_s0).back_pointer = (*node).back_pointer;
                    (*new_s0).parent_slot = (*node).parent_slot as c_int;
                    (*new_s0).next_node = node_to_ptr(new_n0);
                    (*new_n0).back_pointer = shortcut_to_ptr(new_s0);
                    (*new_n0).parent_slot = 0;
                    (*new_n1).back_pointer = node_to_ptr(new_n0);
                    (*new_n1).parent_slot = 0xff; /* Need to calculate this */

                    level = diff & !LEVEL_STEP_MASK;
                    (*new_s0).skip_to_level = level;
                    bug_on(level <= 0);

                    i = 0;
                    while i < keylen {
                        *index_key(new_s0).add(i) = ((*ops).get_key_chunk)(index_key_, (i as c_int) * KEY_CHUNK_SIZE);
                        i += 1;
                    }

                    if level & KEY_CHUNK_MASK != 0 {
                        let blank = c_ulong::MAX << (level & KEY_CHUNK_MASK);
                        *index_key(new_s0).add(keylen - 1) &= !blank;
                    }

                    /* This now reduces to a node splitting exercise for which we'll need to regenerate the disparity table. */
                    i = 0;
                    while i < FAN_OUT {
                        let p = (*node).slots[i];
                        let mut base_seg = ((*ops).get_object_key_chunk)(to_leaf(p), level);
                        base_seg >>= level & KEY_CHUNK_MASK;
                        (*edit).segment_cache[i] = (base_seg & FAN_MASK) as u8;
                        i += 1;
                    }

                    let mut base_seg = ((*ops).get_key_chunk)(index_key_, level);
                    base_seg >>= level & KEY_CHUNK_MASK;
                    (*edit).segment_cache[FAN_OUT] = (base_seg & FAN_MASK) as u8;
                    s = S::DoSplitNode;
                }
            }
        }
    }
}

/// `assoc_array_insert_mid_shortcut()`.
unsafe fn insert_mid_shortcut(edit: *mut Edit, _ops: *const Ops, result: &WalkResult) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let shortcut = result.wrong_shortcut.shortcut;
        let mut level = result.wrong_shortcut.level;
        let sc_level = result.wrong_shortcut.sc_level;
        let sc_segments = result.wrong_shortcut.sc_segments;
        let dissimilarity = result.wrong_shortcut.dissimilarity;

        /* We need to split a shortcut and insert a node between the two pieces. Zero-length pieces will be dispensed with entirely.
         * First of all, we need to find out in which level the first difference was. */
        let mut diff: c_int = dissimilarity.trailing_zeros() as c_int; /* __ffs() */
        diff &= !LEVEL_STEP_MASK;
        diff += sc_level & !KEY_CHUNK_MASK;

        if (*shortcut).back_pointer.is_null() {
            (*edit).set[0].ptr = &raw mut (*(*edit).array).root;
        } else if is_node((*shortcut).back_pointer) {
            let node = to_node((*shortcut).back_pointer);
            (*edit).set[0].ptr = &raw mut (*node).slots[(*shortcut).parent_slot as usize];
        } else {
            rust_assoc_array_bug();
        }

        (*edit).excised_meta[0] = shortcut_to_ptr(shortcut);

        /* Create a new node now since we're going to need it anyway */
        let new_n0 = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
        if new_n0.is_null() {
            return false;
        }
        (*edit).new_meta[0] = node_to_ptr(new_n0);
        (*edit).adjust_count_on = new_n0;

        /* Insert a new shortcut before the new node if this segment isn't of zero length - otherwise we just connect the new node
         * directly to the parent. */
        level += LEVEL_STEP;
        if diff > level {
            let mut keylen = round_up_chunk(diff) as usize;
            keylen >>= KEY_CHUNK_SHIFT;

            let new_s0 = rust_assoc_array_kzalloc(shortcut_size(keylen)).cast::<Shortcut>();
            if new_s0.is_null() {
                return false;
            }
            (*edit).new_meta[1] = shortcut_to_ptr(new_s0);
            (*edit).set[0].to = shortcut_to_ptr(new_s0);
            (*new_s0).back_pointer = (*shortcut).back_pointer;
            (*new_s0).parent_slot = (*shortcut).parent_slot;
            (*new_s0).next_node = node_to_ptr(new_n0);
            (*new_s0).skip_to_level = diff;

            (*new_n0).back_pointer = shortcut_to_ptr(new_s0);
            (*new_n0).parent_slot = 0;

            core::ptr::copy_nonoverlapping(index_key(shortcut), index_key(new_s0), keylen);

            let blank = c_ulong::MAX << (diff & KEY_CHUNK_MASK);
            *index_key(new_s0).add(keylen - 1) &= !blank;
        } else {
            (*edit).set[0].to = node_to_ptr(new_n0);
            (*new_n0).back_pointer = (*shortcut).back_pointer;
            (*new_n0).parent_slot = (*shortcut).parent_slot as u8;
        }

        let side = to_node((*shortcut).next_node);
        (*new_n0).nr_leaves_on_branch = (*side).nr_leaves_on_branch;

        /* We need to know which slot in the new node is going to take a metadata pointer. */
        let sc_slot = ((sc_segments >> (diff & KEY_CHUNK_MASK)) & FAN_MASK) as usize;

        /* Determine whether we need to follow the new node with a replacement for the current shortcut. */
        level = diff + LEVEL_STEP;
        if level < (*shortcut).skip_to_level {
            let mut keylen = round_up_chunk((*shortcut).skip_to_level) as usize;
            keylen >>= KEY_CHUNK_SHIFT;

            let new_s1 = rust_assoc_array_kzalloc(shortcut_size(keylen)).cast::<Shortcut>();
            if new_s1.is_null() {
                return false;
            }
            (*edit).new_meta[2] = shortcut_to_ptr(new_s1);

            (*new_s1).back_pointer = node_to_ptr(new_n0);
            (*new_s1).parent_slot = sc_slot as c_int;
            (*new_s1).next_node = (*shortcut).next_node;
            (*new_s1).skip_to_level = (*shortcut).skip_to_level;

            (*new_n0).slots[sc_slot] = shortcut_to_ptr(new_s1);

            core::ptr::copy_nonoverlapping(index_key(shortcut), index_key(new_s1), keylen);

            (*edit).set[1].ptr = &raw mut (*side).back_pointer;
            (*edit).set[1].to = shortcut_to_ptr(new_s1);
        } else {
            (*new_n0).slots[sc_slot] = (*shortcut).next_node;
            (*edit).set_parent_slot[0].p = &raw mut (*side).parent_slot;
            (*edit).set_parent_slot[0].to = sc_slot as u8;
            (*edit).set[1].ptr = &raw mut (*side).back_pointer;
            (*edit).set[1].to = node_to_ptr(new_n0);
        }

        if sc_slot == 0 {
            (*edit).leaf_p = &raw mut (*new_n0).slots[1];
        } else {
            (*edit).leaf_p = &raw mut (*new_n0).slots[0];
        }

        true
    }
}

/// `assoc_array_insert()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_insert(
    array: *mut AssocArray,
    ops: *const Ops,
    index_key_: *const c_void,
    object: *mut c_void,
) -> *mut Edit {
    // SAFETY: caller contract.
    unsafe {
        bug_on(is_meta(object));

        let edit = rust_assoc_array_kzalloc(core::mem::size_of::<Edit>()).cast::<Edit>();
        if edit.is_null() {
            return (-(ENOMEM as isize)) as usize as *mut Edit; /* ERR_PTR(-ENOMEM) */
        }
        (*edit).array = array;
        (*edit).ops = ops;
        (*edit).leaf = leaf_to_ptr(object);
        (*edit).adjust_count_by = 1;

        let mut result = WalkResult {
            terminal_node: TerminalNode { node: null_mut(), level: 0, slot: 0 },
            wrong_shortcut: WrongShortcut { shortcut: null_mut(), level: 0, sc_level: 0, sc_segments: 0, dissimilarity: 0 },
        };

        let ok = match walk(array, ops, index_key_, &mut result) {
            Walk::TreeEmpty => insert_in_empty_tree(edit),
            Walk::FoundTerminalNode => insert_into_terminal_node(edit, ops, index_key_, &result),
            Walk::FoundWrongShortcut => insert_mid_shortcut(edit, ops, &result),
        };
        if ok {
            return edit;
        }

        /* enomem: */
        assoc_array_cancel_edit(edit);
        (-(ENOMEM as isize)) as usize as *mut Edit
    }
}

/// `assoc_array_insert_set_object()`.
///
/// # Safety
/// `edit` valid.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_insert_set_object(edit: *mut Edit, object: *mut c_void) {
    bug_on(object.is_null());
    // SAFETY: caller contract.
    unsafe { (*edit).leaf = leaf_to_ptr(object) };
}

// ---------------------------------------------------------------------------
// delete / clear
// ---------------------------------------------------------------------------

struct CollapseContext {
    node: *mut Node,
    skip_leaf: *const c_void,
    slot: c_int,
}

/// `assoc_array_delete_collapse_iterator()`.
unsafe extern "C" fn delete_collapse_iterator(leaf: *const c_void, iterator_data: *mut c_void) -> c_int {
    // SAFETY: `iterator_data` is the `CollapseContext` `delete()` passed.
    unsafe {
        let collapse = iterator_data.cast::<CollapseContext>();

        if leaf == (*collapse).skip_leaf {
            return 0;
        }

        bug_on((*collapse).slot >= FAN_OUT as c_int);

        (*(*collapse).node).slots[(*collapse).slot as usize] = leaf_to_ptr(leaf);
        (*collapse).slot += 1;
        0
    }
}

/// `assoc_array_delete()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_delete(array: *mut AssocArray, ops: *const Ops, index_key_: *const c_void) -> *mut Edit {
    // SAFETY: caller contract.
    unsafe {
        let edit = rust_assoc_array_kzalloc(core::mem::size_of::<Edit>()).cast::<Edit>();
        if edit.is_null() {
            return (-(ENOMEM as isize)) as usize as *mut Edit;
        }
        (*edit).array = array;
        (*edit).ops = ops;
        (*edit).adjust_count_by = -1;

        let mut result = WalkResult {
            terminal_node: TerminalNode { node: null_mut(), level: 0, slot: 0 },
            wrong_shortcut: WrongShortcut { shortcut: null_mut(), level: 0, sc_level: 0, sc_segments: 0, dissimilarity: 0 },
        };

        let mut node: *mut Node = null_mut();
        let mut found_slot: Option<usize> = None;

        if walk(array, ops, index_key_, &mut result) == Walk::FoundTerminalNode {
            /* We found a node that should contain the leaf we've been asked to remove - *if* it's in the tree. */
            node = result.terminal_node.node;

            let mut slot = 0;
            while slot < FAN_OUT {
                let ptr = (*node).slots[slot];
                if !ptr.is_null() && is_leaf(ptr) && ((*ops).compare_object)(to_leaf(ptr), index_key_) {
                    found_slot = Some(slot);
                    break;
                }
                slot += 1;
            }
        }
        let slot = match found_slot {
            Some(s) => s,
            None => {
                assoc_array_cancel_edit(edit);
                return null_mut();
            }
        };

        // found_leaf:
        bug_on((*array).nr_leaves_on_tree == 0);

        /* In the simplest form of deletion we just clear the slot and release the leaf after a suitable interval. */
        (*edit).dead_leaf = (*node).slots[slot];
        (*edit).set[0].ptr = &raw mut (*node).slots[slot];
        (*edit).set[0].to = null_mut();
        (*edit).adjust_count_on = node;

        /* If that concludes erasure of the last leaf, then delete the entire internal array. */
        if (*array).nr_leaves_on_tree == 1 {
            (*edit).set[1].ptr = &raw mut (*array).root;
            (*edit).set[1].to = null_mut();
            (*edit).adjust_count_on = null_mut();
            (*edit).excised_subtree = (*array).root;
            return edit;
        }

        /* However, we'd also like to clear up some metadata blocks if we possibly can. */
        if (*node).nr_leaves_on_branch <= FAN_OUT as c_ulong + 1 {
            /* First of all, we need to know if this node has metadata so that we don't try collapsing if all the leaves are
             * already here. */
            let mut has_meta = false;
            let mut i = 0;
            while i < FAN_OUT {
                let ptr = (*node).slots[i];
                if is_meta(ptr) {
                    has_meta = true;
                    break;
                }
                i += 1;
            }

            /* Look further up the tree to see if we can collapse this node into a more proximal node too. */
            let mut parent = node;
            loop {
                // collapse_up:
                let mut ptr = (*parent).back_pointer;
                if ptr.is_null() {
                    break; // goto do_collapse
                }
                if is_shortcut(ptr) {
                    let s = to_shortcut(ptr);
                    ptr = (*s).back_pointer;
                    if ptr.is_null() {
                        break; // goto do_collapse
                    }
                }

                let grandparent = to_node(ptr);
                if (*grandparent).nr_leaves_on_branch <= FAN_OUT as c_ulong + 1 {
                    parent = grandparent;
                    continue; // goto collapse_up
                }
                break;
            }

            // do_collapse:
            /* There's no point collapsing if the original node has no meta pointers to discard and if we didn't merge into one
             * of that node's ancestry. */
            if has_meta || parent != node {
                node = parent;

                /* Create a new node to collapse into */
                let new_n0 = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
                if new_n0.is_null() {
                    /* enomem: */
                    assoc_array_cancel_edit(edit);
                    return (-(ENOMEM as isize)) as usize as *mut Edit;
                }
                (*edit).new_meta[0] = node_to_ptr(new_n0);

                (*new_n0).back_pointer = (*node).back_pointer;
                (*new_n0).parent_slot = (*node).parent_slot;
                (*new_n0).nr_leaves_on_branch = (*node).nr_leaves_on_branch;
                (*edit).adjust_count_on = new_n0;

                let mut collapse =
                    CollapseContext { node: new_n0, skip_leaf: to_leaf((*edit).dead_leaf), slot: 0 };
                subtree_iterate(
                    node_to_ptr(node),
                    (*node).back_pointer,
                    delete_collapse_iterator,
                    (&raw mut collapse).cast(),
                );
                bug_on(collapse.slot as c_ulong != (*new_n0).nr_leaves_on_branch.wrapping_sub(1));

                if (*node).back_pointer.is_null() {
                    (*edit).set[1].ptr = &raw mut (*array).root;
                } else if is_leaf((*node).back_pointer) {
                    rust_assoc_array_bug();
                } else if is_node((*node).back_pointer) {
                    let p = to_node((*node).back_pointer);
                    (*edit).set[1].ptr = &raw mut (*p).slots[(*node).parent_slot as usize];
                } else if is_shortcut((*node).back_pointer) {
                    let s = to_shortcut((*node).back_pointer);
                    (*edit).set[1].ptr = &raw mut (*s).next_node;
                }
                (*edit).set[1].to = node_to_ptr(new_n0);
                (*edit).excised_subtree = node_to_ptr(node);
            }
        }

        edit
    }
}

/// `assoc_array_clear()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_clear(array: *mut AssocArray, ops: *const Ops) -> *mut Edit {
    // SAFETY: caller contract.
    unsafe {
        if (*array).root.is_null() {
            return null_mut();
        }

        let edit = rust_assoc_array_kzalloc(core::mem::size_of::<Edit>()).cast::<Edit>();
        if edit.is_null() {
            return (-(ENOMEM as isize)) as usize as *mut Edit;
        }
        (*edit).array = array;
        (*edit).ops = ops;
        (*edit).set[1].ptr = &raw mut (*array).root;
        (*edit).set[1].to = null_mut();
        (*edit).excised_subtree = (*array).root;
        (*edit).ops_for_excised_subtree = ops;
        edit
    }
}

// ---------------------------------------------------------------------------
// applying and cancelling edits
// ---------------------------------------------------------------------------

/// `assoc_array_rcu_cleanup()`'s body: the deferred destruction after an applied edit.
///
/// # Safety
/// `edit` is an applied edit whose grace period has elapsed.
#[no_mangle]
pub unsafe extern "C" fn rust_assoc_array_rcu_cleanup(edit: *mut Edit) {
    // SAFETY: caller contract.
    unsafe {
        if !(*edit).dead_leaf.is_null() {
            ((*(*edit).ops).free_object)(to_leaf((*edit).dead_leaf));
        }
        let mut i = 0;
        while i < (*edit).excised_meta.len() {
            if !(*edit).excised_meta[i].is_null() {
                rust_assoc_array_kfree(to_node((*edit).excised_meta[i]).cast());
            }
            i += 1;
        }

        if !(*edit).excised_subtree.is_null() {
            bug_on(is_leaf((*edit).excised_subtree));
            if is_node((*edit).excised_subtree) {
                let n = to_node((*edit).excised_subtree);
                (*n).back_pointer = null_mut();
            } else {
                let s = to_shortcut((*edit).excised_subtree);
                (*s).back_pointer = null_mut();
            }
            destroy_subtree((*edit).excised_subtree, (*edit).ops_for_excised_subtree);
        }

        rust_assoc_array_kfree(edit.cast());
    }
}

/// `smp_wmb()`.
#[inline(always)]
fn smp_wmb() {
    fence(Ordering::Release);
}

/// `assoc_array_apply_edit()`.
///
/// # Safety
/// As the C.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_apply_edit(edit: *mut Edit) {
    // SAFETY: caller contract.
    unsafe {
        smp_wmb();
        if !(*edit).leaf_p.is_null() {
            *(*edit).leaf_p = (*edit).leaf;
        }

        smp_wmb();
        let mut i = 0;
        while i < (*edit).set_parent_slot.len() {
            if !(*edit).set_parent_slot[i].p.is_null() {
                *(*edit).set_parent_slot[i].p = (*edit).set_parent_slot[i].to;
            }
            i += 1;
        }

        smp_wmb();
        i = 0;
        while i < (*edit).set_backpointers.len() {
            if !(*edit).set_backpointers[i].is_null() {
                *(*edit).set_backpointers[i] = (*edit).set_backpointers_to;
            }
            i += 1;
        }

        smp_wmb();
        i = 0;
        while i < (*edit).set.len() {
            if !(*edit).set[i].ptr.is_null() {
                *(*edit).set[i].ptr = (*edit).set[i].to;
            }
            i += 1;
        }

        if (*(*edit).array).root.is_null() {
            (*(*edit).array).nr_leaves_on_tree = 0;
        } else if !(*edit).adjust_count_on.is_null() {
            let mut node = (*edit).adjust_count_on;
            loop {
                (*node).nr_leaves_on_branch = (*node).nr_leaves_on_branch.wrapping_add((*edit).adjust_count_by as c_ulong);

                let mut ptr = (*node).back_pointer;
                if ptr.is_null() {
                    break;
                }
                if is_shortcut(ptr) {
                    let shortcut = to_shortcut(ptr);
                    ptr = (*shortcut).back_pointer;
                    if ptr.is_null() {
                        break;
                    }
                }
                bug_on(!is_node(ptr));
                node = to_node(ptr);
            }

            (*(*edit).array).nr_leaves_on_tree =
                (*(*edit).array).nr_leaves_on_tree.wrapping_add((*edit).adjust_count_by as c_ulong);
        }

        rust_assoc_array_call_rcu(edit);
    }
}

/// `assoc_array_cancel_edit()`.
///
/// # Safety
/// `edit` valid and unapplied.
#[no_mangle]
pub unsafe extern "C" fn assoc_array_cancel_edit(edit: *mut Edit) {
    // SAFETY: caller contract.
    unsafe {
        let mut i = 0;
        while i < (*edit).new_meta.len() {
            let ptr = (*edit).new_meta[i];
            if !ptr.is_null() {
                if is_node(ptr) {
                    rust_assoc_array_kfree(to_node(ptr).cast());
                } else {
                    rust_assoc_array_kfree(to_shortcut(ptr).cast());
                }
            }
            i += 1;
        }
        rust_assoc_array_kfree(edit.cast());
    }
}

// ---------------------------------------------------------------------------
// garbage collection
// ---------------------------------------------------------------------------

type GcIterator = unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;

/// `assoc_array_gc()`.
///
/// # Safety
/// As the C.
#[allow(unused_assignments)]
#[no_mangle]
pub unsafe extern "C" fn assoc_array_gc(
    array: *mut AssocArray,
    ops: *const Ops,
    iterator: GcIterator,
    iterator_data: *mut c_void,
) -> c_int {
    #[derive(Clone, Copy)]
    enum S {
        Descend,
        ContinueNode,
        RetryCompress,
        AscendOldTree,
        GcComplete,
        Enomem,
    }
    // SAFETY: caller contract.
    unsafe {
        if (*array).root.is_null() {
            return 0;
        }

        let edit = rust_assoc_array_kzalloc(core::mem::size_of::<Edit>()).cast::<Edit>();
        if edit.is_null() {
            return -ENOMEM;
        }
        (*edit).array = array;
        (*edit).ops = ops;
        (*edit).ops_for_excised_subtree = ops;
        (*edit).set[0].ptr = &raw mut (*array).root;
        (*edit).excised_subtree = (*array).root;

        let mut new_root: Ptr = null_mut();
        let mut new_parent: Ptr = null_mut();
        let mut new_ptr_pp: *mut Ptr = &raw mut new_root;
        let mut cursor: Ptr = (*array).root;

        let mut shortcut: *mut Shortcut;
        let mut new_s: *mut Shortcut = null_mut();
        let mut node: *mut Node = null_mut();
        let mut new_n: *mut Node = null_mut();
        let mut ptr: Ptr;
        let mut nr_leaves_on_tree: c_ulong = 0;
        let mut slot: c_int = 0;
        let mut nr_free: c_int;
        let mut next_slot: c_int;
        let mut i: usize;

        let mut s = S::Descend;

        loop {
            match s {
                S::Descend => {
                    /* If this point is a shortcut, then we need to duplicate it and advance the target cursor. */
                    if is_shortcut(cursor) {
                        shortcut = to_shortcut(cursor);
                        let mut keylen = round_up_chunk((*shortcut).skip_to_level) as usize;
                        keylen >>= KEY_CHUNK_SHIFT;
                        new_s = rust_assoc_array_kmalloc(shortcut_size(keylen)).cast::<Shortcut>();
                        if new_s.is_null() {
                            s = S::Enomem;
                            continue;
                        }
                        core::ptr::copy_nonoverlapping(shortcut.cast::<u8>(), new_s.cast::<u8>(), shortcut_size(keylen));
                        (*new_s).back_pointer = new_parent;
                        (*new_s).parent_slot = (*shortcut).parent_slot;
                        new_parent = shortcut_to_ptr(new_s);
                        *new_ptr_pp = new_parent;
                        new_ptr_pp = &raw mut (*new_s).next_node;
                        cursor = (*shortcut).next_node;
                    }

                    /* Duplicate the node at this position */
                    node = to_node(cursor);
                    new_n = rust_assoc_array_kzalloc(core::mem::size_of::<Node>()).cast::<Node>();
                    if new_n.is_null() {
                        s = S::Enomem;
                        continue;
                    }
                    (*new_n).back_pointer = new_parent;
                    (*new_n).parent_slot = (*node).parent_slot;
                    new_parent = node_to_ptr(new_n);
                    *new_ptr_pp = new_parent;
                    new_ptr_pp = null_mut();
                    slot = 0;
                    s = S::ContinueNode;
                }
                S::ContinueNode => {
                    /* Filter across any leaves and gc any subtrees */
                    let mut descend = false;
                    while (slot as usize) < FAN_OUT {
                        ptr = (*node).slots[slot as usize];
                        if ptr.is_null() {
                            slot += 1;
                            continue;
                        }

                        if is_leaf(ptr) {
                            if iterator(to_leaf(ptr), iterator_data) {
                                /* The iterator will have done any reference counting on the object for us. */
                                (*new_n).slots[slot as usize] = ptr;
                            }
                            slot += 1;
                            continue;
                        }

                        new_ptr_pp = &raw mut (*new_n).slots[slot as usize];
                        cursor = ptr;
                        descend = true;
                        break;
                    }
                    s = if descend { S::Descend } else { S::RetryCompress };
                }
                S::RetryCompress => {
                    (*new_n).nr_leaves_on_branch = 0;
                    nr_free = 0;
                    slot = 0;
                    while (slot as usize) < FAN_OUT {
                        ptr = (*new_n).slots[slot as usize];
                        if ptr.is_null() {
                            nr_free += 1;
                        } else if is_leaf(ptr) {
                            (*new_n).nr_leaves_on_branch += 1;
                        }
                        slot += 1;
                    }

                    let mut retained = false;
                    next_slot = 0;
                    slot = 0;
                    while (slot as usize) < FAN_OUT {
                        ptr = (*new_n).slots[slot as usize];
                        if ptr.is_null() || is_leaf(ptr) {
                            slot += 1;
                            continue;
                        }

                        let mut sc: *mut Shortcut = null_mut();
                        if is_shortcut(ptr) {
                            sc = to_shortcut(ptr);
                            ptr = (*sc).next_node;
                        }

                        let child = to_node(ptr);
                        (*new_n).nr_leaves_on_branch += (*child).nr_leaves_on_branch;

                        if (*child).nr_leaves_on_branch <= (nr_free + 1) as c_ulong {
                            bug_on(!sc.is_null());

                            (*new_n).slots[slot as usize] = null_mut();
                            nr_free += 1;
                            if slot < next_slot {
                                next_slot = slot;
                            }
                            i = 0;
                            while i < FAN_OUT {
                                let p = (*child).slots[i];
                                if p.is_null() {
                                    i += 1;
                                    continue;
                                }
                                bug_on(is_meta(p));
                                while !(*new_n).slots[next_slot as usize].is_null() {
                                    next_slot += 1;
                                }
                                bug_on(next_slot >= FAN_OUT as c_int);
                                (*new_n).slots[next_slot as usize] = p;
                                next_slot += 1;
                                nr_free -= 1;
                                i += 1;
                            }
                            rust_assoc_array_kfree(child.cast());
                        } else {
                            retained = true;
                        }
                        slot += 1;
                    }

                    if retained && (*new_n).nr_leaves_on_branch <= FAN_OUT as c_ulong {
                        s = S::RetryCompress;
                        continue;
                    }

                    nr_leaves_on_tree = (*new_n).nr_leaves_on_branch;

                    /* Excise this node if it is singly occupied by a shortcut */
                    if nr_free == FAN_OUT as c_int - 1 {
                        slot = 0;
                        ptr = null_mut();
                        while (slot as usize) < FAN_OUT {
                            ptr = (*new_n).slots[slot as usize];
                            if !ptr.is_null() {
                                break;
                            }
                            slot += 1;
                        }

                        if is_meta(ptr) && is_shortcut(ptr) {
                            new_s = to_shortcut(ptr);
                            new_parent = (*new_n).back_pointer;
                            slot = (*new_n).parent_slot as c_int;
                            rust_assoc_array_kfree(new_n.cast());
                            if new_parent.is_null() {
                                (*new_s).back_pointer = null_mut();
                                (*new_s).parent_slot = 0;
                                new_root = ptr;
                                s = S::GcComplete;
                                continue;
                            }

                            if is_shortcut(new_parent) {
                                let sp = to_shortcut(new_parent);

                                (*new_s).back_pointer = (*sp).back_pointer;
                                new_parent = (*new_s).back_pointer;
                                (*new_s).parent_slot = (*sp).parent_slot;
                                slot = (*new_s).parent_slot;
                                rust_assoc_array_kfree(sp.cast());
                                if new_parent.is_null() {
                                    (*new_s).back_pointer = null_mut();
                                    (*new_s).parent_slot = 0;
                                    new_root = ptr;
                                    s = S::GcComplete;
                                    continue;
                                }
                            }

                            (*new_s).back_pointer = new_parent;
                            (*new_s).parent_slot = slot;
                            new_n = to_node(new_parent);
                            (*new_n).slots[slot as usize] = ptr;
                            s = S::AscendOldTree;
                            continue;
                        }
                    }

                    /* Excise any shortcuts we might encounter that point to nodes that only contain leaves. */
                    ptr = (*new_n).back_pointer;
                    if ptr.is_null() {
                        s = S::GcComplete;
                        continue;
                    }

                    if is_shortcut(ptr) {
                        new_s = to_shortcut(ptr);
                        new_parent = (*new_s).back_pointer;
                        slot = (*new_s).parent_slot;

                        if (*new_n).nr_leaves_on_branch <= FAN_OUT as c_ulong {
                            (*new_n).back_pointer = new_parent;
                            (*new_n).parent_slot = slot as u8;
                            rust_assoc_array_kfree(new_s.cast());
                            if new_parent.is_null() {
                                new_root = node_to_ptr(new_n);
                                s = S::GcComplete;
                                continue;
                            }

                            let n = to_node(new_parent);
                            (*n).slots[slot as usize] = node_to_ptr(new_n);
                        }
                    } else {
                        new_parent = ptr;
                    }
                    new_n = to_node(new_parent);
                    s = S::AscendOldTree;
                }
                S::AscendOldTree => {
                    ptr = (*node).back_pointer;
                    if is_shortcut(ptr) {
                        shortcut = to_shortcut(ptr);
                        slot = (*shortcut).parent_slot;
                        cursor = (*shortcut).back_pointer;
                        if cursor.is_null() {
                            s = S::GcComplete;
                            continue;
                        }
                    } else {
                        slot = (*node).parent_slot as c_int;
                        cursor = ptr;
                    }
                    bug_on(cursor.is_null());
                    node = to_node(cursor);
                    slot += 1;
                    s = S::ContinueNode;
                }
                S::GcComplete => {
                    (*edit).set[0].to = new_root;
                    assoc_array_apply_edit(edit);
                    (*array).nr_leaves_on_tree = nr_leaves_on_tree;
                    return 0;
                }
                S::Enomem => {
                    destroy_subtree(new_root, (*edit).ops);
                    rust_assoc_array_kfree(edit.cast());
                    return -ENOMEM;
                }
            }
        }
    }
}

#[allow(dead_code)]
const _: *const c_void = null();
