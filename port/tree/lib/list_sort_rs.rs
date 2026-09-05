// SPDX-License-Identifier: GPL-2.0

//! Stable list merge sort -- the Rust body behind `lib/list_sort.c`.
//!
//! Ported from `lib/list_sort.c` (6.18.49). A bottom-up merge sort over a
//! circular doubly-linked `struct list_head`, doing at most `2n` comparisons
//! more than the theoretical minimum and touching no memory it did not
//! already own.
//!
//! # Layout is the caller's, and this one is not negotiable
//!
//! `struct list_head` is embedded in every structure the kernel sorts, and
//! `list_sort()` is handed the head of a live circular list. GOALS.md §5
//! names exactly this case: change the layout and call sites break without a
//! single signature changing. So the `#[repr(C)]` mirror below is
//! `include/linux/types.h`'s, field for field, and nothing here may reorder
//! or resize it.
//!
//! # Why it is raw pointers throughout, not references
//!
//! During the sort the list is deliberately **not** a well-formed doubly
//! linked list. The C says so in its own invariants: the sublists are
//! singly linked and NUL-terminated, and `prev` is reused as the link
//! between *pending sublists* rather than pointing backwards at all. A
//! `&mut` would be claiming an exclusivity that is not true of a structure
//! being rewired in place, so this uses `*mut` and does what the C does.
//!
//! # What is NOT changed, and would be tempting
//!
//! `merge_final()` duplicates `merge()`'s loop rather than calling it and
//! fixing the `prev` links afterwards. That looks like something to tidy.
//! The C's own comment says it is deliberate: the tidier alternatives — a
//! separate prev-restoration pass, or maintaining `prev` throughout — are
//! both slower. Left alone, and recorded here so the next reader does not
//! "fix" it (GOALS.md §5).
//!
//! Replaces: lib/list_sort.c

use core::ffi::c_void;

/// Mirrors `struct list_head` in `include/linux/types.h`.
#[repr(C)]
pub struct ListHead {
    /// Next entry, or null inside a sublist being merged.
    pub next: *mut ListHead,
    /// Previous entry, or the link between pending sublists mid-sort.
    pub prev: *mut ListHead,
}

/// `list_cmp_func_t` from `include/linux/list_sort.h`.
type ListCmpFunc =
    unsafe extern "C" fn(*mut c_void, *const ListHead, *const ListHead) -> core::ffi::c_int;

/// Merge two null-terminated sorted sublists into one.
///
/// The result is in the intermediate format `merge()` calls chain in:
/// null-terminated, no sentinel head, `prev` not maintained.
///
/// # Safety
/// `a` and `b` must be non-null heads of null-terminated sublists, and `cmp`
/// must be callable with `priv_`.
unsafe fn merge(
    priv_: *mut c_void,
    cmp: ListCmpFunc,
    a: *mut ListHead,
    b: *mut ListHead,
) -> *mut ListHead {
    let mut a = a;
    let mut b = b;
    let mut head: *mut ListHead = core::ptr::null_mut();
    // The C threads a `struct list_head **tail` through the `next` fields.
    // Here `tail` is that same pointer-to-pointer.
    let mut tail: *mut *mut ListHead = &mut head;

    // SAFETY: both sublists are non-empty and null-terminated on entry, and
    // each branch re-establishes that before looping. Every write is to a
    // `next` field of a node the caller owns.
    unsafe {
        loop {
            // On a tie take 'a' -- this is what makes the sort stable.
            if cmp(priv_, a, b) <= 0 {
                *tail = a;
                tail = &mut (*a).next;
                a = (*a).next;
                if a.is_null() {
                    *tail = b;
                    break;
                }
            } else {
                *tail = b;
                tail = &mut (*b).next;
                b = (*b).next;
                if b.is_null() {
                    *tail = a;
                    break;
                }
            }
        }
    }
    head
}

/// The final merge, which also restores the `prev` links and closes the
/// list back into a circle.
///
/// # Safety
/// As [`merge`], plus `head` must be the caller's list head.
unsafe fn merge_final(
    priv_: *mut c_void,
    cmp: ListCmpFunc,
    head: *mut ListHead,
    a: *mut ListHead,
    b: *mut ListHead,
) {
    let mut a = a;
    let mut b = b;
    let mut tail = head;
    let mut count: u8 = 0;

    // SAFETY: as merge(), and `head` is the live list head the caller passed
    // to list_sort().
    unsafe {
        loop {
            // On a tie take 'a' -- stability again.
            if cmp(priv_, a, b) <= 0 {
                (*tail).next = a;
                (*a).prev = tail;
                tail = a;
                a = (*a).next;
                if a.is_null() {
                    break;
                }
            } else {
                (*tail).next = b;
                (*b).prev = tail;
                tail = b;
                b = (*b).next;
                if b.is_null() {
                    b = a;
                    break;
                }
            }
        }

        // Link the remainder of b onto the tail.
        (*tail).next = b;
        loop {
            // If the merge is very unbalanced -- an already-sorted input,
            // say -- this runs many iterations with nothing to compare.
            // Call cmp() anyway, once every 256, so a client that uses it to
            // cond_resched() still gets the chance. That is the C's reason
            // and it is the only thing this call is for.
            count = count.wrapping_add(1);
            if count == 0 {
                cmp(priv_, b, b);
            }
            (*b).prev = tail;
            tail = b;
            b = (*b).next;
            if b.is_null() {
                break;
            }
        }

        // And the final links, back into a circular doubly-linked list.
        (*tail).next = head;
        (*head).prev = tail;
    }
}

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
kernel::kabi_rule!("type_string", "s#list_head",
    "structure_type list_head { member pointer_type { s#list_head } next data_member_location(0) , member pointer_type { s#list_head } prev data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#list_cmp_func_t",
    "typedef_type list_cmp_func_t { pointer_type { subroutine_type ( formal_parameter pointer_type { base_type void } , formal_parameter pointer_type { const_type { s#list_head } } , formal_parameter pointer_type { const_type { s#list_head } } ) -> base_type int byte_size(4) encoding(5) } }");

kernel::kabi_export! {
    list_sort,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } priv , formal_parameter pointer_type { s#list_head } head , formal_parameter t#list_cmp_func_t cmp ) -> base_type void",
}

/// Body of `list_sort()`.
///
/// # Safety
/// `head` must be a live circular doubly-linked list head and `cmp` a valid
/// comparison callback. Same contract as the C, including that `cmp` must be
/// antisymmetric and transitive; a comparison that is not will not corrupt
/// memory here, but the ordering is then meaningless in both languages.
#[no_mangle]
pub unsafe extern "C" fn list_sort(
    priv_: *mut c_void,
    head: *mut ListHead,
    cmp: ListCmpFunc,
) {
    // SAFETY: the caller guarantees `head` heads a well-formed circular list.
    unsafe {
        let mut list = (*head).next;
        let mut pending: *mut ListHead = core::ptr::null_mut();
        let mut count: usize = 0;

        if list == (*head).prev {
            // Zero or one elements.
            return;
        }

        // Convert to a null-terminated singly-linked list.
        (*(*head).prev).next = core::ptr::null_mut();

        // Invariants, as the C states them:
        //  - all lists are singly linked and null-terminated; prev is not
        //    maintained
        //  - `pending` is a prev-linked list of sorted sublists awaiting
        //    further merging
        //  - each sublist is a power of two in size
        //  - sublists are sorted by size and age, smallest and newest first
        //  - there are zero to two sublists of each size
        //  - a pair is merged as soon as the number of following pending
        //    elements equals their size, which keeps every later final
        //    merge at worst 2:1
        loop {
            let mut tail: *mut *mut ListHead = &mut pending;
            let mut bits = count;

            // The least-significant clear bit in count.
            while bits & 1 != 0 {
                tail = &mut (**tail).prev;
                bits >>= 1;
            }

            if bits != 0 {
                let a = *tail;
                let b = (*a).prev;
                let merged = merge(priv_, cmp, b, a);

                // Install the merged result in place of the inputs.
                (*merged).prev = (*b).prev;
                *tail = merged;
            }

            // Move one element from the input list to pending.
            (*list).prev = pending;
            pending = list;
            list = (*list).next;
            (*pending).next = core::ptr::null_mut();
            count += 1;

            if list.is_null() {
                break;
            }
        }

        // End of input; merge all the pending lists together.
        let mut list = pending;

        pending = (*pending).prev;
        loop {
            let next = (*pending).prev;

            if next.is_null() {
                break;
            }
            list = merge(priv_, cmp, pending, list);
            pending = next;
        }

        // The final merge, which rebuilds the prev links.
        merge_final(priv_, cmp, head, pending, list);
    }
}
