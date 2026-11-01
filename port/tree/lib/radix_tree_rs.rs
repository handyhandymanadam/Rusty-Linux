// SPDX-License-Identifier: GPL-2.0-or-later

//! The radix tree and the IDR's free-slot search -- the Rust behind `lib/radix-tree.c`.
//!
//! Ported from `lib/radix-tree.c` (6.18.49). A radix tree maps an `unsigned long` index to a pointer through a tree of `struct xa_node` (the XArray's node: 64 slots, 3
//! tag bitmaps), with a single entry kept directly in `root->xa_head`, tags aggregated up to the root's `xa_flags`, and (for the IDR) an `IDR_FREE` tag meaning "this slot
//! still has room". In Rust: extend, shrink, delete_node, create, insert, lookup, replace, the tag operations, `next_chunk` and the iterator step, the gang lookups, delete,
//! `idr_get_free` and `idr_destroy`. In C (`radix-tree_glue.c`): the exports as thunks (MODVERSIONS fingerprints come from the DWARF of the definition), the node cache and
//! per-CPU preload (`radix_tree_node_alloc`, `__radix_tree_preload`, `radix_tree_preload`, `radix_tree_maybe_preload`, `idr_preload`, the constructor, the CPU-dead hook,
//! `radix_tree_init`), `radix_tree_node_free` (`call_rcu`), and wrappers for the `BUG_ON`/`WARN_ON_ONCE` sites (they now name the glue file -- recorded divergence).
//!
//! The root is reached through offsets (`xa_flags`, `xa_head` follow a `spinlock_t` whose size depends on the configuration), and the tag shift in `xa_flags` is
//! `__GFP_BITS_SHIFT`, which also depends on it; `radix-tree_glue.c` exports both and checks the node layout.
//!
//! Replaces: lib/radix-tree.c (all but the node cache / preload / init, which stay C)

use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicPtr, Ordering};

/// `unsigned long` (`usize` on every target this runs on, and the same type as the indices and slot arithmetic here).
#[allow(non_camel_case_types)]
type c_ulong = usize;

const EEXIST: c_int = 17;
const ENOMEM: c_int = 12;
const ENOSPC: c_int = 28;

#[cfg(not(radix_harness_small_chunk))]
const MAP_SHIFT: usize = 6;
#[cfg(radix_harness_small_chunk)]
const MAP_SHIFT: usize = 4;
const MAP_SIZE: usize = 1 << MAP_SHIFT;
const MAP_MASK: usize = MAP_SIZE - 1;
const MAX_TAGS: usize = 3;
const TAG_LONGS: usize = MAP_SIZE.div_ceil(usize::BITS as usize);
const BITS_PER_LONG: usize = usize::BITS as usize;

const IDR_FREE: c_uint = 0;
const ROOT_IS_IDR: u32 = 4;
const ITER_TAG_MASK: c_uint = 0x0f;
const ITER_TAGGED: c_uint = 0x10;
const ITER_CONTIG: c_uint = 0x20;
/// `XA_RETRY_ENTRY` = `xa_mk_internal(256)`.
const RETRY: *mut c_void = ((256usize << 2) | 2) as *mut c_void;

/// `struct xa_node` (= `struct radix_tree_node`).
#[repr(C)]
pub struct Node {
    shift: u8,
    offset: u8,
    count: u8,
    nr_values: u8,
    parent: *mut Node,
    array: *mut c_void,
    private: [usize; 2],
    slots: [*mut c_void; MAP_SIZE],
    tags: [[usize; TAG_LONGS]; MAX_TAGS],
}

/// `struct radix_tree_iter`.
#[repr(C)]
pub struct Iter {
    index: c_ulong,
    next_index: c_ulong,
    tags: c_ulong,
    node: *mut Node,
}

type Slot = *mut *mut c_void;

extern "C" {
    static rust_rt_off_flags: usize; // offsetof(struct radix_tree_root, xa_flags)
    static rust_rt_off_head: usize; // offsetof(struct radix_tree_root, xa_head)
    static rust_rt_root_tag_shift: u32; // ROOT_TAG_SHIFT = __GFP_BITS_SHIFT
    static rust_rt_root_gfp_bits: u32; // __GFP_BITS_MASK & ~GFP_ZONEMASK

    fn rust_rt_node_alloc(gfp: u32, parent: *mut Node, root: *mut c_void, shift: c_uint, offset: c_uint, count: c_uint, nr_values: c_uint) -> *mut Node;
    fn rust_rt_node_free(node: *mut Node);
    fn rust_rt_bug(cond: bool);
    fn rust_rt_warn_replace(cond: bool);
    fn rust_rt_warn_private_list_shrink(node: *mut Node);
    fn rust_rt_warn_private_list_delete(node: *mut Node);
    fn rust_rt_warn_private_list_free(node: *mut Node);
}

// ---- entries -------------------------------------------------------------------------------------------------------------------------------------------------

/// `radix_tree_is_internal_node()`.
#[inline(always)]
fn is_internal(p: *mut c_void) -> bool {
    (p as usize) & 3 == 2
}

/// `xa_is_value()`.
#[inline(always)]
fn is_value(p: *mut c_void) -> bool {
    (p as usize) & 1 != 0
}

/// `xa_is_node()`.
#[inline(always)]
fn is_node(p: *mut c_void) -> bool {
    is_internal(p) && (p as usize) > 4096
}

/// `entry_to_node()`.
#[inline(always)]
fn entry_to_node(p: *mut c_void) -> *mut Node {
    ((p as usize) & !2usize) as *mut Node
}

/// `node_to_entry()`.
#[inline(always)]
fn node_to_entry(n: *mut Node) -> *mut c_void {
    ((n as usize) | 2) as *mut c_void
}

/// `rcu_dereference_raw()` of a slot.
#[inline(always)]
unsafe fn load(slot: Slot) -> *mut c_void {
    unsafe { read_volatile(slot) }
}

/// `rcu_assign_pointer()`.
#[inline(always)]
unsafe fn store_release(slot: Slot, v: *mut c_void) {
    unsafe { AtomicPtr::from_ptr(slot).store(v, Ordering::Release) }
}

// ---- root ----------------------------------------------------------------------------------------------------------------------------------------------------

#[inline(always)]
unsafe fn flags_of(root: *const c_void) -> *mut u32 {
    unsafe { (root as *mut u8).add(rust_rt_off_flags) as *mut u32 }
}

#[inline(always)]
unsafe fn head_of(root: *const c_void) -> Slot {
    unsafe { (root as *mut u8).add(rust_rt_off_head) as Slot }
}

/// `root_gfp_mask()`.
#[inline(always)]
unsafe fn root_gfp_mask(root: *const c_void) -> u32 {
    unsafe { *flags_of(root) & rust_rt_root_gfp_bits }
}

#[inline(always)]
unsafe fn root_tag_set(root: *mut c_void, tag: c_uint) {
    unsafe { *flags_of(root) |= 1u32 << (tag + rust_rt_root_tag_shift) }
}

#[inline(always)]
unsafe fn root_tag_clear(root: *mut c_void, tag: c_uint) {
    unsafe { *flags_of(root) &= !(1u32 << (tag + rust_rt_root_tag_shift)) }
}

#[inline(always)]
unsafe fn root_tag_clear_all(root: *mut c_void) {
    unsafe { *flags_of(root) &= (1u32 << rust_rt_root_tag_shift) - 1 }
}

#[inline(always)]
unsafe fn root_tag_get(root: *const c_void, tag: c_uint) -> bool {
    unsafe { *flags_of(root) & (1u32 << (tag + rust_rt_root_tag_shift)) != 0 }
}

#[inline(always)]
unsafe fn root_tags_get(root: *const c_void) -> u32 {
    unsafe { *flags_of(root) >> rust_rt_root_tag_shift }
}

#[inline(always)]
unsafe fn is_idr(root: *const c_void) -> bool {
    unsafe { *flags_of(root) & ROOT_IS_IDR != 0 }
}

// ---- node tags -----------------------------------------------------------------------------------------------------------------------------------------------

#[inline(always)]
unsafe fn tag_set(node: *mut Node, tag: c_uint, offset: usize) {
    unsafe { (*node).tags[tag as usize][offset / BITS_PER_LONG] |= 1usize << (offset % BITS_PER_LONG) }
}

#[inline(always)]
unsafe fn tag_clear(node: *mut Node, tag: c_uint, offset: usize) {
    unsafe { (*node).tags[tag as usize][offset / BITS_PER_LONG] &= !(1usize << (offset % BITS_PER_LONG)) }
}

#[inline(always)]
unsafe fn tag_get(node: *const Node, tag: c_uint, offset: usize) -> bool {
    unsafe { (*node).tags[tag as usize][offset / BITS_PER_LONG] >> (offset % BITS_PER_LONG) & 1 != 0 }
}

/// `any_tag_set()`.
unsafe fn any_tag_set(node: *const Node, tag: c_uint) -> bool {
    unsafe { (*node).tags[tag as usize].iter().any(|w| *w != 0) }
}

/// `all_tag_set()` (`bitmap_fill()` of `RADIX_TREE_MAP_SIZE` bits: whole words).
unsafe fn all_tag_set(node: *mut Node, tag: c_uint) {
    unsafe {
        for w in (*node).tags[tag as usize].iter_mut() {
            *w = !0;
        }
    }
}

/// `radix_tree_find_next_bit()`: next set bit of the tag at or after `offset`, or `MAP_SIZE`.
unsafe fn find_next_bit(node: *const Node, tag: c_uint, offset: usize) -> usize {
    unsafe {
        let addr = &(*node).tags[tag as usize];
        let mut offset = offset;
        if offset < MAP_SIZE {
            let mut i = offset / BITS_PER_LONG;
            let tmp = addr[i] >> (offset % BITS_PER_LONG);
            if tmp != 0 {
                return tmp.trailing_zeros() as usize + offset;
            }
            offset = (offset + BITS_PER_LONG) & !(BITS_PER_LONG - 1);
            while offset < MAP_SIZE {
                i += 1;
                let tmp = addr[i];
                if tmp != 0 {
                    return tmp.trailing_zeros() as usize + offset;
                }
                offset += BITS_PER_LONG;
            }
        }
        MAP_SIZE
    }
}

// ---- geometry ------------------------------------------------------------------------------------------------------------------------------------------------

/// `get_slot_offset()`.
#[inline(always)]
unsafe fn get_slot_offset(parent: *const Node, slot: Slot) -> usize {
    unsafe {
        if parent.is_null() {
            0
        } else {
            slot.offset_from((*parent).slots.as_ptr() as Slot) as usize
        }
    }
}

/// `radix_tree_descend()`: the offset of `index` in `parent`, and the entry there in `*nodep`.
#[inline(always)]
unsafe fn descend(parent: *const Node, nodep: &mut *mut c_void, index: c_ulong) -> usize {
    unsafe {
        let offset = (index >> (*parent).shift) as usize & MAP_MASK;
        *nodep = load((*parent).slots.as_ptr().add(offset) as Slot);
        offset
    }
}

/// `shift_maxindex()`.
#[inline(always)]
fn shift_maxindex(shift: u32) -> c_ulong {
    ((MAP_SIZE as c_ulong) << shift).wrapping_sub(1)
}

/// `node_maxindex()`.
#[inline(always)]
unsafe fn node_maxindex(node: *const Node) -> c_ulong {
    unsafe { shift_maxindex((*node).shift as u32) }
}

/// `next_index()`.
unsafe fn next_index(index: c_ulong, node: *const Node, offset: usize) -> c_ulong {
    unsafe { (index & !node_maxindex(node)).wrapping_add((offset as c_ulong) << (*node).shift) }
}

/// `iter_offset()`.
#[inline(always)]
fn iter_offset(iter: &Iter) -> usize {
    iter.index as usize & MAP_MASK
}

/// `radix_tree_load_root()`: the root entry in `*nodep`, `*maxindex` the largest index it covers; returns the shift above the root node.
unsafe fn load_root(root: *const c_void, nodep: &mut *mut c_void, maxindex: &mut c_ulong) -> u32 {
    unsafe {
        let node = load(head_of(root));
        *nodep = node;
        if is_internal(node) {
            let n = entry_to_node(node);
            *maxindex = node_maxindex(n);
            return (*n).shift as u32 + MAP_SHIFT as u32;
        }
        *maxindex = 0;
        0
    }
}

// ---- growing and shrinking -----------------------------------------------------------------------------------------------------------------------------------

/// `radix_tree_extend()`: make the tree tall enough for `index`; returns the new shift above the root, or a negative errno.
unsafe fn extend(root: *mut c_void, gfp: u32, index: c_ulong, shift: u32) -> c_int {
    unsafe {
        let mut shift = shift;
        let mut maxshift = shift;
        while index > shift_maxindex(maxshift) {
            maxshift += MAP_SHIFT as u32;
        }

        let mut entry = load(head_of(root));
        if entry.is_null() && (!is_idr(root) || root_tag_get(root, IDR_FREE)) {
            return (maxshift + MAP_SHIFT as u32) as c_int;
        }

        loop {
            let node = rust_rt_node_alloc(gfp, null_mut(), root, shift, 0, 1, 0);
            if node.is_null() {
                return -ENOMEM;
            }

            if is_idr(root) {
                all_tag_set(node, IDR_FREE);
                if !root_tag_get(root, IDR_FREE) {
                    tag_clear(node, IDR_FREE, 0);
                    root_tag_set(root, IDR_FREE);
                }
            } else {
                // Propagate the aggregated tag info to the new child
                for tag in 0..MAX_TAGS as c_uint {
                    if root_tag_get(root, tag) {
                        tag_set(node, tag, 0);
                    }
                }
            }

            rust_rt_bug(shift as usize > BITS_PER_LONG);
            if is_internal(entry) {
                (*entry_to_node(entry)).parent = node;
            } else if is_value(entry) {
                // Moving a value entry root->xa_head to a node
                (*node).nr_values = 1;
            }
            // entry was already in the radix tree, so we do not need rcu_assign_pointer here
            (*node).slots[0] = entry;
            entry = node_to_entry(node);
            store_release(head_of(root), entry);
            shift += MAP_SHIFT as u32;
            if shift > maxshift {
                break;
            }
        }
        (maxshift + MAP_SHIFT as u32) as c_int
    }
}

/// `radix_tree_shrink()`.
unsafe fn shrink(root: *mut c_void) -> bool {
    unsafe {
        let mut shrunk = false;

        loop {
            let entry = load(head_of(root));
            if !is_internal(entry) {
                break;
            }
            let node = entry_to_node(entry);

            // The candidate node has more than one child, or its child is not at the leftmost slot, we cannot shrink.
            if (*node).count != 1 {
                break;
            }
            let child = load((*node).slots.as_mut_ptr());
            if child.is_null() {
                break;
            }

            // For an IDR, we must not shrink entry 0 into the root in case somebody calls idr_replace() with a pointer that appears to be an internal entry
            if (*node).shift == 0 && is_idr(root) {
                break;
            }

            if is_internal(child) {
                (*entry_to_node(child)).parent = null_mut();
            }

            // We don't need rcu_assign_pointer(), since we are simply moving the node from one part of the tree to another.
            write_volatile(head_of(root), child);
            if is_idr(root) && !tag_get(node, IDR_FREE, 0) {
                root_tag_clear(root, IDR_FREE);
            }

            // The node's slot[0] must not be NULLed in case there are concurrent lookups expecting to find the item; tag the slot as retry so callers look again.
            (*node).count = 0;
            if !is_internal(child) {
                (*node).slots[0] = RETRY;
            }

            rust_rt_warn_private_list_shrink(node);
            rust_rt_node_free(node);
            shrunk = true;
        }

        shrunk
    }
}

/// `delete_node()`: free `node` if it is empty, and its now-empty parents; shrink the tree if the root can go.
unsafe fn delete_node(root: *mut c_void, node: *mut Node) -> bool {
    unsafe {
        let mut node = node;
        let mut deleted = false;

        loop {
            if (*node).count != 0 {
                if node_to_entry(node) == load(head_of(root)) {
                    deleted |= shrink(root);
                }
                return deleted;
            }

            let parent = (*node).parent;
            if !parent.is_null() {
                (*parent).slots[(*node).offset as usize] = null_mut();
                (*parent).count = (*parent).count.wrapping_sub(1);
            } else {
                // Shouldn't the tags already have all been cleared by the caller?
                if !is_idr(root) {
                    root_tag_clear_all(root);
                }
                write_volatile(head_of(root), null_mut());
            }

            rust_rt_warn_private_list_delete(node);
            rust_rt_node_free(node);
            deleted = true;

            node = parent;
            if node.is_null() {
                break;
            }
        }
        deleted
    }
}

/// `__radix_tree_create()`: find (making it if need be) the node and slot for `index`.
unsafe fn create(root: *mut c_void, index: c_ulong, nodep: *mut *mut Node, slotp: *mut Slot) -> c_int {
    unsafe {
        let mut node: *mut Node = null_mut();
        let mut child: *mut c_void = null_mut();
        let mut slot: Slot = head_of(root);
        let mut maxindex: c_ulong = 0;
        let mut offset: usize = 0;
        let max = index;
        let gfp = root_gfp_mask(root);

        let mut shift = load_root(root, &mut child, &mut maxindex);

        // Make sure the tree is high enough.
        if max > maxindex {
            let error = extend(root, gfp, max, shift);
            if error < 0 {
                return error;
            }
            shift = error as u32;
            child = load(head_of(root));
        }

        while shift > 0 {
            shift -= MAP_SHIFT as u32;
            if child.is_null() {
                // Have to add a child node.
                let c = rust_rt_node_alloc(gfp, node, root, shift, offset as c_uint, 0, 0);
                if c.is_null() {
                    return -ENOMEM;
                }
                child = node_to_entry(c);
                store_release(slot, child);
                if !node.is_null() {
                    (*node).count = (*node).count.wrapping_add(1);
                }
            } else if !is_internal(child) {
                break;
            }

            // Go a level down
            node = entry_to_node(child);
            offset = descend(node, &mut child, index);
            slot = (*node).slots.as_mut_ptr().add(offset);
        }

        if !nodep.is_null() {
            *nodep = node;
        }
        if !slotp.is_null() {
            *slotp = slot;
        }
        0
    }
}

/// `radix_tree_free_nodes()`: free the nodes below `node` (and `node` itself); the tree is presumed not to need shrinking.
unsafe fn free_nodes(node: *mut c_void) {
    unsafe {
        let top = entry_to_node(node);
        let mut offset: usize = 0;
        let mut child = top;

        loop {
            let entry = load((*child).slots.as_mut_ptr().add(offset));
            if is_node(entry) && (*child).shift != 0 {
                child = entry_to_node(entry);
                offset = 0;
                continue;
            }
            offset += 1;
            while offset == MAP_SIZE {
                let old = child;
                offset = (*child).offset as usize + 1;
                child = (*child).parent;
                rust_rt_warn_private_list_free(old);
                rust_rt_node_free(old);
                if old == top {
                    return;
                }
            }
        }
    }
}

/// `insert_entries()`.
unsafe fn insert_entries(node: *mut Node, slot: Slot, item: *mut c_void) -> c_int {
    unsafe {
        if !load(slot).is_null() {
            return -EEXIST;
        }
        store_release(slot, item);
        if !node.is_null() {
            (*node).count = (*node).count.wrapping_add(1);
            if is_value(item) {
                (*node).nr_values = (*node).nr_values.wrapping_add(1);
            }
        }
        1
    }
}

/// `radix_tree_insert()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_insert(root: *mut c_void, index: c_ulong, item: *mut c_void) -> c_int {
    unsafe {
        let mut node: *mut Node = null_mut();
        let mut slot: Slot = null_mut();

        rust_rt_bug(is_internal(item));

        let mut error = create(root, index, &mut node, &mut slot);
        if error != 0 {
            return error;
        }

        error = insert_entries(node, slot, item);
        if error < 0 {
            return error;
        }

        if !node.is_null() {
            let offset = get_slot_offset(node, slot);
            rust_rt_bug(tag_get(node, 0, offset));
            rust_rt_bug(tag_get(node, 1, offset));
            rust_rt_bug(tag_get(node, 2, offset));
        } else {
            rust_rt_bug(root_tags_get(root) != 0);
        }

        0
    }
}

/// `__radix_tree_lookup()`.
#[no_mangle]
pub unsafe extern "C" fn rust___radix_tree_lookup(root: *const c_void, index: c_ulong, nodep: *mut *mut Node, slotp: *mut Slot) -> *mut c_void {
    unsafe {
        'restart: loop {
            let mut parent: *mut Node = null_mut();
            let mut slot: Slot = head_of(root);
            let mut node: *mut c_void = null_mut();
            let mut maxindex: c_ulong = 0;

            load_root(root, &mut node, &mut maxindex);
            if index > maxindex {
                return null_mut();
            }

            while is_internal(node) {
                parent = entry_to_node(node);
                let offset = descend(parent, &mut node, index);
                slot = (*parent).slots.as_mut_ptr().add(offset);
                if node == RETRY {
                    continue 'restart;
                }
                if (*parent).shift == 0 {
                    break;
                }
            }

            if !nodep.is_null() {
                *nodep = parent;
            }
            if !slotp.is_null() {
                *slotp = slot;
            }
            return node;
        }
    }
}

/// `radix_tree_lookup_slot()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_lookup_slot(root: *const c_void, index: c_ulong) -> Slot {
    unsafe {
        let mut slot: Slot = null_mut();
        if rust___radix_tree_lookup(root, index, null_mut(), &mut slot).is_null() {
            return null_mut();
        }
        slot
    }
}

/// `radix_tree_lookup()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_lookup(root: *const c_void, index: c_ulong) -> *mut c_void {
    unsafe { rust___radix_tree_lookup(root, index, null_mut(), null_mut()) }
}

/// `replace_slot()`.
unsafe fn replace_slot(slot: Slot, item: *mut c_void, node: *mut Node, count: c_int, values: c_int) {
    unsafe {
        if !node.is_null() && (count != 0 || values != 0) {
            (*node).count = (*node).count.wrapping_add(count as u8);
            (*node).nr_values = (*node).nr_values.wrapping_add(values as u8);
        }
        store_release(slot, item);
    }
}

/// `node_tag_get()`.
unsafe fn node_tag_get(root: *const c_void, node: *const Node, tag: c_uint, offset: usize) -> bool {
    unsafe {
        if !node.is_null() {
            return tag_get(node, tag, offset);
        }
        root_tag_get(root, tag)
    }
}

/// `calculate_count()`.
unsafe fn calculate_count(root: *mut c_void, node: *mut Node, slot: Slot, item: *mut c_void, old: *mut c_void) -> c_int {
    unsafe {
        if is_idr(root) {
            let offset = get_slot_offset(node, slot);
            let free = node_tag_get(root, node, IDR_FREE, offset);
            if !free {
                return 0;
            }
            if old.is_null() {
                return 1;
            }
        }
        (!item.is_null()) as c_int - (!old.is_null()) as c_int
    }
}

/// `__radix_tree_replace()`.
#[no_mangle]
pub unsafe extern "C" fn rust___radix_tree_replace(root: *mut c_void, node: *mut Node, slot: Slot, item: *mut c_void) {
    unsafe {
        let old = load(slot);
        let values = is_value(item) as c_int - is_value(old) as c_int;
        let count = calculate_count(root, node, slot, item, old);

        // This function supports replacing value entries and deleting entries, but that needs accounting against the node unless the slot is root->xa_head.
        rust_rt_warn_replace(node.is_null() && slot != head_of(root) && (count != 0 || values != 0));
        replace_slot(slot, item, node, count, values);

        if node.is_null() {
            return;
        }

        delete_node(root, node);
    }
}

/// `radix_tree_replace_slot()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_replace_slot(root: *mut c_void, slot: Slot, item: *mut c_void) {
    unsafe { rust___radix_tree_replace(root, null_mut(), slot, item) }
}

/// `radix_tree_iter_replace()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_iter_replace(root: *mut c_void, iter: *const Iter, slot: Slot, item: *mut c_void) {
    unsafe { rust___radix_tree_replace(root, (*iter).node, slot, item) }
}

// ---- tags ----------------------------------------------------------------------------------------------------------------------------------------------------

/// `node_tag_set()`.
unsafe fn node_tag_set(root: *mut c_void, node: *mut Node, tag: c_uint, offset: usize) {
    unsafe {
        let mut node = node;
        let mut offset = offset;
        while !node.is_null() {
            if tag_get(node, tag, offset) {
                return;
            }
            tag_set(node, tag, offset);
            offset = (*node).offset as usize;
            node = (*node).parent;
        }

        if !root_tag_get(root, tag) {
            root_tag_set(root, tag);
        }
    }
}

/// `radix_tree_tag_set()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_tag_set(root: *mut c_void, index: c_ulong, tag: c_uint) -> *mut c_void {
    unsafe {
        let mut node: *mut c_void = null_mut();
        let mut maxindex: c_ulong = 0;

        load_root(root, &mut node, &mut maxindex);
        rust_rt_bug(index > maxindex);

        while is_internal(node) {
            let parent = entry_to_node(node);
            let offset = descend(parent, &mut node, index);
            rust_rt_bug(node.is_null());

            if !tag_get(parent, tag, offset) {
                tag_set(parent, tag, offset);
            }
        }

        // set the root's tag bit
        if !root_tag_get(root, tag) {
            root_tag_set(root, tag);
        }

        node
    }
}

/// `node_tag_clear()`.
unsafe fn node_tag_clear(root: *mut c_void, node: *mut Node, tag: c_uint, offset: usize) {
    unsafe {
        let mut node = node;
        let mut offset = offset;
        while !node.is_null() {
            if !tag_get(node, tag, offset) {
                return;
            }
            tag_clear(node, tag, offset);
            if any_tag_set(node, tag) {
                return;
            }

            offset = (*node).offset as usize;
            node = (*node).parent;
        }

        // clear the root's tag bit
        if root_tag_get(root, tag) {
            root_tag_clear(root, tag);
        }
    }
}

/// `radix_tree_tag_clear()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_tag_clear(root: *mut c_void, index: c_ulong, tag: c_uint) -> *mut c_void {
    unsafe {
        let mut node: *mut c_void = null_mut();
        let mut maxindex: c_ulong = 0;
        let mut offset: usize = 0;

        load_root(root, &mut node, &mut maxindex);
        if index > maxindex {
            return null_mut();
        }

        let mut parent: *mut Node = null_mut();

        while is_internal(node) {
            parent = entry_to_node(node);
            offset = descend(parent, &mut node, index);
        }

        if !node.is_null() {
            node_tag_clear(root, parent, tag, offset);
        }

        node
    }
}

/// `radix_tree_iter_tag_clear()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_iter_tag_clear(root: *mut c_void, iter: *const Iter, tag: c_uint) {
    unsafe { node_tag_clear(root, (*iter).node, tag, iter_offset(&*iter)) }
}

/// `radix_tree_tag_get()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_tag_get(root: *const c_void, index: c_ulong, tag: c_uint) -> c_int {
    unsafe {
        let mut node: *mut c_void = null_mut();
        let mut maxindex: c_ulong = 0;

        if !root_tag_get(root, tag) {
            return 0;
        }

        load_root(root, &mut node, &mut maxindex);
        if index > maxindex {
            return 0;
        }

        while is_internal(node) {
            let parent = entry_to_node(node);
            let offset = descend(parent, &mut node, index);

            if !tag_get(parent, tag, offset) {
                return 0;
            }
            if node == RETRY {
                break;
            }
        }

        1
    }
}

/// `radix_tree_tagged()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_tagged(root: *const c_void, tag: c_uint) -> c_int {
    // `root_tag_get()` returns the masked bit itself (not 0 or 1), and callers of the export see that value
    unsafe { (*flags_of(root) & (1u32 << (tag + rust_rt_root_tag_shift))) as c_int }
}

// ---- iteration -----------------------------------------------------------------------------------------------------------------------------------------------

/// `set_iter_tags()`: construct `iter->tags` from `node->tags[tag]`.
unsafe fn set_iter_tags(iter: &mut Iter, node: *mut Node, offset: usize, tag: c_uint) {
    unsafe {
        let tag_long = offset / BITS_PER_LONG;
        let tag_bit = offset % BITS_PER_LONG;

        if node.is_null() {
            iter.tags = 1;
            return;
        }

        iter.tags = (*node).tags[tag as usize][tag_long] >> tag_bit;

        // This never happens if RADIX_TREE_TAG_LONGS == 1
        if tag_long < TAG_LONGS - 1 {
            // Pick tags from next element
            if tag_bit != 0 {
                iter.tags |= (*node).tags[tag as usize][tag_long + 1] << (BITS_PER_LONG - tag_bit);
            }
            // Clip chunk size, here only BITS_PER_LONG tags
            iter.next_index = iter.index.wrapping_add(BITS_PER_LONG as c_ulong);
        }
    }
}

/// `radix_tree_iter_resume()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_iter_resume(_slot: Slot, iter: *mut Iter) -> Slot {
    unsafe {
        (*iter).index = (*iter).index.wrapping_add(1);
        (*iter).next_index = (*iter).index;
        (*iter).tags = 0;
        null_mut()
    }
}

/// `radix_tree_next_chunk()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_next_chunk(root: *const c_void, iter: *mut Iter, flags: c_uint) -> Slot {
    unsafe {
        let iter = &mut *iter;
        let tag = flags & ITER_TAG_MASK;

        if flags & ITER_TAGGED != 0 && !root_tag_get(root, tag) {
            return null_mut();
        }

        // Catch next_index overflow after ~0UL. iter->index never overflows during iterating; it can be zero only at the beginning.
        let mut index = iter.next_index;
        if index == 0 && iter.index != 0 {
            return null_mut();
        }

        'restart: loop {
            let mut child: *mut c_void = null_mut();
            let mut maxindex: c_ulong = 0;
            let mut node: *mut Node;
            let mut offset: usize;

            load_root(root, &mut child, &mut maxindex);
            if index > maxindex {
                return null_mut();
            }
            if child.is_null() {
                return null_mut();
            }

            if !is_internal(child) {
                // Single-slot tree
                iter.index = index;
                iter.next_index = maxindex.wrapping_add(1);
                iter.tags = 1;
                iter.node = null_mut();
                return head_of(root);
            }

            loop {
                node = entry_to_node(child);
                offset = descend(node, &mut child, index);

                let hole = if flags & ITER_TAGGED != 0 { !tag_get(node, tag, offset) } else { child.is_null() };
                if hole {
                    // Hole detected
                    if flags & ITER_CONTIG != 0 {
                        return null_mut();
                    }

                    if flags & ITER_TAGGED != 0 {
                        offset = find_next_bit(node, tag, offset + 1);
                    } else {
                        loop {
                            offset += 1;
                            if offset >= MAP_SIZE {
                                break;
                            }
                            let slot = load((*node).slots.as_mut_ptr().add(offset));
                            if !slot.is_null() {
                                break;
                            }
                        }
                    }
                    index &= !node_maxindex(node);
                    index = index.wrapping_add((offset as c_ulong) << (*node).shift);
                    // Overflow after ~0UL
                    if index == 0 {
                        return null_mut();
                    }
                    if offset == MAP_SIZE {
                        continue 'restart;
                    }
                    child = load((*node).slots.as_mut_ptr().add(offset));
                }

                if child.is_null() {
                    continue 'restart;
                }
                if child == RETRY {
                    break;
                }
                if !((*node).shift != 0 && is_internal(child)) {
                    break;
                }
            }

            // Update the iterator state
            iter.index = (index & !node_maxindex(node)) | offset as c_ulong;
            iter.next_index = (index | node_maxindex(node)).wrapping_add(1);
            iter.node = node;

            if flags & ITER_TAGGED != 0 {
                set_iter_tags(iter, node, offset, tag);
            }

            return (*node).slots.as_mut_ptr().add(offset);
        }
    }
}

/// `radix_tree_iter_init()`.
#[inline(always)]
fn iter_init(iter: &mut Iter, start: c_ulong) -> Slot {
    // Set index to zero to bypass next_index overflow protection.
    iter.index = 0;
    iter.next_index = start;
    null_mut()
}

/// `radix_tree_iter_retry()`.
#[inline(always)]
fn iter_retry(iter: &mut Iter) -> Slot {
    iter.next_index = iter.index;
    iter.tags = 0;
    null_mut()
}

/// `radix_tree_next_slot()`.
unsafe fn next_slot(slot: Slot, iter: &mut Iter, flags: c_uint) -> Slot {
    unsafe {
        let mut slot = slot;
        if flags & ITER_TAGGED != 0 {
            iter.tags >>= 1;
            if iter.tags == 0 {
                return null_mut();
            }
            if iter.tags & 1 != 0 {
                iter.index = iter.index.wrapping_add(1);
                return slot.add(1);
            }
            if flags & ITER_CONTIG == 0 {
                let mut offset = iter.tags.trailing_zeros() as c_ulong;

                // the C is `iter->tags >>= offset++`: shift by the old value, then step one further
                iter.tags >>= offset;
                offset += 1;
                iter.index = iter.index.wrapping_add(offset);
                slot = slot.add(offset as usize);
                return slot;
            }
        } else {
            let mut count = iter.next_index.wrapping_sub(iter.index) as i64;

            loop {
                count -= 1;
                if count <= 0 {
                    break;
                }
                slot = slot.add(1);
                iter.index = iter.index.wrapping_add(1);

                if !load(slot).is_null() {
                    return slot;
                }
                if flags & ITER_CONTIG != 0 {
                    // forbid switching to the next chunk
                    iter.next_index = 0;
                    break;
                }
            }
        }
        null_mut()
    }
}

/// `radix_tree_gang_lookup()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_gang_lookup(root: *const c_void, results: *mut *mut c_void, first_index: c_ulong, max_items: c_uint) -> c_uint {
    unsafe {
        let mut iter = Iter { index: 0, next_index: 0, tags: 0, node: null_mut() };
        let mut ret: c_uint = 0;

        if max_items == 0 {
            return 0;
        }

        let mut slot = iter_init(&mut iter, first_index);
        while !slot.is_null() || {
            slot = rust_radix_tree_next_chunk(root, &mut iter, 0);
            !slot.is_null()
        } {
            let r = load(slot);
            *results.add(ret as usize) = r;
            if !r.is_null() {
                if is_internal(r) {
                    slot = iter_retry(&mut iter);
                    continue;
                }
                ret += 1;
                if ret == max_items {
                    break;
                }
            }
            slot = next_slot(slot, &mut iter, 0);
        }

        ret
    }
}

/// `radix_tree_gang_lookup_tag()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_gang_lookup_tag(root: *const c_void, results: *mut *mut c_void, first_index: c_ulong, max_items: c_uint, tag: c_uint) -> c_uint {
    unsafe {
        let mut iter = Iter { index: 0, next_index: 0, tags: 0, node: null_mut() };
        let mut ret: c_uint = 0;

        if max_items == 0 {
            return 0;
        }

        let mut slot = iter_init(&mut iter, first_index);
        while !slot.is_null() || {
            slot = rust_radix_tree_next_chunk(root, &mut iter, ITER_TAGGED | tag);
            !slot.is_null()
        } {
            let r = load(slot);
            *results.add(ret as usize) = r;
            if !r.is_null() {
                if is_internal(r) {
                    slot = iter_retry(&mut iter);
                    continue;
                }
                ret += 1;
                if ret == max_items {
                    break;
                }
            }
            slot = next_slot(slot, &mut iter, ITER_TAGGED | tag);
        }

        ret
    }
}

/// `radix_tree_gang_lookup_tag_slot()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_gang_lookup_tag_slot(root: *const c_void, results: *mut Slot, first_index: c_ulong, max_items: c_uint, tag: c_uint) -> c_uint {
    unsafe {
        let mut iter = Iter { index: 0, next_index: 0, tags: 0, node: null_mut() };
        let mut ret: c_uint = 0;

        if max_items == 0 {
            return 0;
        }

        let mut slot = iter_init(&mut iter, first_index);
        while !slot.is_null() || {
            slot = rust_radix_tree_next_chunk(root, &mut iter, ITER_TAGGED | tag);
            !slot.is_null()
        } {
            *results.add(ret as usize) = slot;
            ret += 1;
            if ret == max_items {
                break;
            }
            slot = next_slot(slot, &mut iter, ITER_TAGGED | tag);
        }

        ret
    }
}

// ---- deletion ------------------------------------------------------------------------------------------------------------------------------------------------

/// `__radix_tree_delete()`.
unsafe fn radix_tree_delete_slot(root: *mut c_void, node: *mut Node, slot: Slot) -> bool {
    unsafe {
        let old = load(slot);
        let values = if is_value(old) { -1 } else { 0 };
        let offset = get_slot_offset(node, slot);

        if is_idr(root) {
            node_tag_set(root, node, IDR_FREE, offset);
        } else {
            for tag in 0..MAX_TAGS as c_uint {
                node_tag_clear(root, node, tag, offset);
            }
        }

        replace_slot(slot, null_mut(), node, -1, values);
        !node.is_null() && delete_node(root, node)
    }
}

/// `radix_tree_iter_delete()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_iter_delete(root: *mut c_void, iter: *mut Iter, slot: Slot) {
    unsafe {
        if radix_tree_delete_slot(root, (*iter).node, slot) {
            (*iter).index = (*iter).next_index;
        }
    }
}

/// `radix_tree_delete_item()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_delete_item(root: *mut c_void, index: c_ulong, item: *mut c_void) -> *mut c_void {
    unsafe {
        let mut node: *mut Node = null_mut();
        let mut slot: Slot = null_mut();

        let entry = rust___radix_tree_lookup(root, index, &mut node, &mut slot);
        if slot.is_null() {
            return null_mut();
        }
        if entry.is_null() && (!is_idr(root) || node_tag_get(root, node, IDR_FREE, get_slot_offset(node, slot))) {
            return null_mut();
        }

        if !item.is_null() && entry != item {
            return null_mut();
        }

        radix_tree_delete_slot(root, node, slot);

        entry
    }
}

/// `radix_tree_delete()`.
#[no_mangle]
pub unsafe extern "C" fn rust_radix_tree_delete(root: *mut c_void, index: c_ulong) -> *mut c_void {
    unsafe { rust_radix_tree_delete_item(root, index, null_mut()) }
}

// ---- IDR -----------------------------------------------------------------------------------------------------------------------------------------------------

/// `idr_get_free()`: find a free slot at or after `iter->next_index` and not above `max`; an `ERR_PTR` on failure.
#[no_mangle]
pub unsafe extern "C" fn rust_idr_get_free(root: *mut c_void, iter: *mut Iter, gfp: u32, max: c_ulong) -> Slot {
    unsafe {
        let iter = &mut *iter;
        let mut node: *mut Node = null_mut();
        let mut child: *mut c_void = null_mut();
        let mut slot: Slot = head_of(root);
        let mut maxindex: c_ulong = 0;
        let mut start = iter.next_index;
        let mut offset: usize = 0;
        let mut shift: u32;

        'grow: loop {
            shift = load_root(root, &mut child, &mut maxindex);
            if rust_radix_tree_tagged(root, IDR_FREE) == 0 {
                start = start.max(maxindex.wrapping_add(1));
            }
            if start > max {
                return -(ENOSPC as isize) as Slot;
            }

            if start > maxindex {
                let error = extend(root, gfp, start, shift);
                if error < 0 {
                    return error as isize as Slot;
                }
                shift = error as u32;
                child = load(head_of(root));
            }
            if start == 0 && shift == 0 {
                shift = MAP_SHIFT as u32;
            }

            while shift != 0 {
                shift -= MAP_SHIFT as u32;
                if child.is_null() {
                    // Have to add a child node.
                    let c = rust_rt_node_alloc(gfp, node, root, shift, offset as c_uint, 0, 0);
                    if c.is_null() {
                        return -(ENOMEM as isize) as Slot;
                    }
                    all_tag_set(c, IDR_FREE);
                    child = node_to_entry(c);
                    store_release(slot, child);
                    if !node.is_null() {
                        (*node).count = (*node).count.wrapping_add(1);
                    }
                } else if !is_internal(child) {
                    break;
                }

                node = entry_to_node(child);
                offset = descend(node, &mut child, start);
                if !tag_get(node, IDR_FREE, offset) {
                    offset = find_next_bit(node, IDR_FREE, offset + 1);
                    start = next_index(start, node, offset);
                    if start > max || start == 0 {
                        return -(ENOSPC as isize) as Slot;
                    }
                    while offset == MAP_SIZE {
                        offset = (*node).offset as usize + 1;
                        node = (*node).parent;
                        if node.is_null() {
                            continue 'grow;
                        }
                        shift = (*node).shift as u32;
                    }
                    child = load((*node).slots.as_mut_ptr().add(offset));
                }
                slot = (*node).slots.as_mut_ptr().add(offset);
            }
            break;
        }

        iter.index = start;
        if !node.is_null() {
            iter.next_index = 1 + max.min(start | node_maxindex(node));
        } else {
            iter.next_index = 1;
        }
        iter.node = node;
        set_iter_tags(iter, node, offset, IDR_FREE);

        slot
    }
}

/// `idr_destroy()` (the tree part: everything but the `idr` wrapper).
#[no_mangle]
pub unsafe extern "C" fn rust_idr_destroy(root: *mut c_void) {
    unsafe {
        let node = load(head_of(root));
        if is_internal(node) {
            free_nodes(node);
        }
        write_volatile(head_of(root), null_mut());
        root_tag_set(root, IDR_FREE);
    }
}
