// SPDX-License-Identifier: GPL-2.0-or-later

//! Descending-priority sorted double-linked list -- the Rust bodies behind
//! `lib/plist.c`.
//!
//! Ported from `lib/plist.c` (6.18.49), Copyright (C) 2004 MontaVista
//! Software / Inaky Perez-Gonzalez, simplified by Oleg Nesterov.
//!
//! # The data structure, because the code is unreadable without it
//!
//! Every node is on `node_list`, in descending priority order. Only the
//! **first** node of each distinct priority is additionally on `prio_list`,
//! which is therefore a list of priority "buckets" and is what makes
//! insertion O(number of distinct priorities) rather than O(nodes).
//!
//! `plist_add()` walks `prio_list` from both ends at once, which is why it
//! carries `iter` and `reverse_iter` and why the loop condition is
//! `iter != first`.
//!
//! # Layout is the caller's
//!
//! `struct plist_head` and `struct plist_node` are embedded in `task_struct`,
//! `rt_mutex`, `pm_qos_constraints` and more, and are read through the
//! `static inline`s and macros in `include/linux/plist.h`. GOALS.md §5 puts
//! them out of bounds; the `#[repr(C)]` mirrors below match
//! `include/linux/plist_types.h` field for field.
//!
//! # What stays in C
//!
//! The `WARN_ON`s in `plist_add()` and the `BUG_ON`s in `plist_requeue()`.
//! Both plant bug-table entries naming their own file and line, and the
//! splat should say `plist_add`, not a Rust shim.
//!
//! Replaces: lib/plist.c

include!("list_helpers.rs");

use core::ffi::c_int;

/// Mirrors `struct plist_head` in `include/linux/plist_types.h`.
#[repr(C)]
pub struct PlistHead {
    /// Every node, in descending priority order.
    pub node_list: ListHead,
}

/// Mirrors `struct plist_node` in `include/linux/plist_types.h`.
#[repr(C)]
pub struct PlistNode {
    /// Priority; higher sorts earlier.
    pub prio: c_int,
    /// Linked only for the first node of each distinct priority.
    pub prio_list: ListHead,
    /// Linked for every node.
    pub node_list: ListHead,
}

/// `container_of(l, struct plist_node, node_list)`.
///
/// # Safety
/// `l` must point at the `node_list` member of a live [`PlistNode`].
#[inline]
unsafe fn node_of_node_list(l: *mut ListHead) -> *mut PlistNode {
    // SAFETY: the caller guarantees `l` is that member, so subtracting its
    // offset lands on the containing struct -- the C's container_of().
    unsafe { (l as *mut u8).sub(core::mem::offset_of!(PlistNode, node_list)) as *mut PlistNode }
}

/// `container_of(l, struct plist_node, prio_list)`.
///
/// # Safety
/// `l` must point at the `prio_list` member of a live [`PlistNode`].
#[inline]
unsafe fn node_of_prio_list(l: *mut ListHead) -> *mut PlistNode {
    // SAFETY: as above, for the other member.
    unsafe { (l as *mut u8).sub(core::mem::offset_of!(PlistNode, prio_list)) as *mut PlistNode }
}

/// `plist_first()`. The list must not be empty.
///
/// # Safety
/// `head` must be a non-empty, well-formed plist.
#[inline]
unsafe fn first(head: *mut PlistHead) -> *mut PlistNode {
    // SAFETY: the caller guarantees the list is non-empty and well-formed.
    unsafe { node_of_node_list((*head).node_list.next) }
}

/// Body of `plist_add()`.
///
/// The `WARN_ON`s the C does first are in `lib/plist.c`; by the time this
/// runs they have already fired if they were going to.
///
/// # Safety
/// `node` must be an initialised, unlinked [`PlistNode`] and `head` a
/// well-formed plist. Same contract as the C, including that the caller
/// holds whatever lock protects the list.
#[no_mangle]
pub unsafe extern "C" fn rust_plist_add(node: *mut PlistNode, head: *mut PlistHead) {
    // SAFETY: the caller's contract. Every dereference below is of a node
    // reached through the list's own links, which the caller guarantees are
    // well-formed.
    unsafe {
        let mut node_next: *mut ListHead = &mut (*head).node_list;

        if is_empty(&(*head).node_list) {
            add_tail(&mut (*node).node_list, node_next);
            return;
        }

        let first_node = first(head);
        let mut iter = first_node;
        let last = node_of_prio_list((*first_node).prio_list.prev);
        let mut reverse_iter = last;
        let mut prev: *mut PlistNode = core::ptr::null_mut();

        // Walk the priority buckets from both ends at once.
        loop {
            if (*node).prio < (*iter).prio {
                node_next = &mut (*iter).node_list;
                break;
            } else if (*node).prio >= (*reverse_iter).prio {
                prev = reverse_iter;
                iter = node_of_prio_list((*reverse_iter).prio_list.next);
                if reverse_iter != last {
                    node_next = &mut (*iter).node_list;
                }
                break;
            }

            prev = iter;
            iter = node_of_prio_list((*iter).prio_list.next);
            reverse_iter = node_of_prio_list((*reverse_iter).prio_list.prev);

            if iter == first_node {
                break;
            }
        }

        // A new distinct priority starts a new bucket.
        if prev.is_null() || (*prev).prio != (*node).prio {
            add_tail(&mut (*node).prio_list, &mut (*iter).prio_list);
        }

        add_tail(&mut (*node).node_list, node_next);
    }
}

/// Body of `plist_del()`.
///
/// # Safety
/// `node` must be linked into `head`, which must be well-formed. Same
/// contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rust_plist_del(node: *mut PlistNode, head: *mut PlistHead) {
    // SAFETY: the caller's contract.
    unsafe {
        if !is_empty(&(*node).prio_list) {
            // This node heads a priority bucket. If the next node shares its
            // priority it has to inherit the bucket, or the bucket vanishes
            // and every node behind it becomes invisible to plist_add().
            if (*node).node_list.next != &mut (*head).node_list {
                let next = node_of_node_list((*node).node_list.next);

                if is_empty(&(*next).prio_list) {
                    add(&mut (*next).prio_list, &mut (*node).prio_list);
                }
            }
            del_init(&mut (*node).prio_list);
        }

        del_init(&mut (*node).node_list);
    }
}

/// Body of `plist_requeue()`: move `node` to the end of its own priority
/// bucket, which is what a caller does after lowering its effective
/// priority without changing `prio`.
///
/// The `BUG_ON`s the C does first are in `lib/plist.c`.
///
/// # Safety
/// As [`rust_plist_del`].
#[no_mangle]
pub unsafe extern "C" fn rust_plist_requeue(node: *mut PlistNode, head: *mut PlistHead) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut node_next: *mut ListHead = &mut (*head).node_list;

        // Already last, or the only one at its priority: nothing to do.
        if (*node).node_list.next == &mut (*head).node_list {
            return;
        }
        let mut iter = node_of_node_list((*node).node_list.next);

        if (*node).prio != (*iter).prio {
            return;
        }

        rust_plist_del(node, head);

        if !is_empty(&(*iter).prio_list) {
            iter = node_of_prio_list((*iter).prio_list.next);
            node_next = &mut (*iter).node_list;
        } else {
            // plist_for_each_continue(iter, head)
            loop {
                let n = (*iter).node_list.next;

                if n == &mut (*head).node_list {
                    break;
                }
                iter = node_of_node_list(n);
                if (*node).prio != (*iter).prio {
                    node_next = &mut (*iter).node_list;
                    break;
                }
            }
        }

        add_tail(&mut (*node).node_list, node_next);
    }
}
