// SPDX-License-Identifier: GPL-2.0
//
// NOT A CRATE. This file is `include!`d by lib/plist_rs.rs and has no entry
// in any Makefile. kbuild compiles every non-rust/ .rs file as its own
// crate, so there is no module system to share code through; `include!` is
// the same arrangement the kernel's own rust/ directory uses for generated
// code. Its comments are therefore `//` and not `//!`, because an inner doc
// comment cannot appear part-way through a file.
// The `list_head` primitives from `include/linux/list.h`, in Rust.
//
// # Why this exists, and why it is not premature
//
// `include/linux/list.h` is entirely `static inline`: it has no symbols, so
// there is nothing to port and nothing to link against. Any Rust body that
// manipulates a `list_head` therefore has to write these out. The first
// such port, `lib/list_sort_rs.rs`, only relinks `next`/`prev` by hand
// and needed none of them. `lib/plist_rs.rs` is the first that does, and it
// needs six.
//
// So this file was written when a port demanded it, not in advance —
// PRIOR-ART.md's whole argument — and it holds exactly the six operations
// `plist` uses. It grows when the next port needs the seventh.
//
// # These are `pub(crate)`-shaped, but the kernel builds each `.rs` as its
// own crate
//
// kbuild compiles every non-`rust/` file as a separate crate, so there is no
// module to share this through. `lib/plist_rs.rs` includes it with
// `include!`, which is the same arrangement the kernel's own `rust/`
// directory uses for generated code. Nothing here is exported.

/// Mirrors `struct list_head` in `include/linux/types.h`.
#[repr(C)]
pub struct ListHead {
    /// Next entry.
    pub next: *mut ListHead,
    /// Previous entry.
    pub prev: *mut ListHead,
}

/// `INIT_LIST_HEAD()`: point the node at itself.
///
/// # Safety
/// `h` must be valid and writable.
#[inline]
pub unsafe fn init(h: *mut ListHead) {
    // SAFETY: the caller guarantees `h` is valid and writable.
    unsafe {
        (*h).next = h;
        (*h).prev = h;
    }
}

/// `list_empty()`.
///
/// # Safety
/// `h` must be valid and readable and its links well-formed.
#[inline]
pub unsafe fn is_empty(h: *const ListHead) -> bool {
    // SAFETY: the caller's contract.
    unsafe { (*h).next == h as *mut ListHead }
}

/// `__list_add()`: insert `node` between `prev` and `next`.
///
/// # Safety
/// All three must be valid, and `prev`/`next` adjacent in a well-formed list.
#[inline]
unsafe fn add_between(node: *mut ListHead, prev: *mut ListHead, next: *mut ListHead) {
    // SAFETY: the caller's contract. The write order is the C's:
    // next->prev, node->next, node->prev, prev->next. `list.h` does not
    // document that order as load-bearing for lockless readers, but it is
    // reproduced exactly rather than tidied -- GOALS.md §5 names write
    // ordering as the boundary that bites.
    unsafe {
        (*next).prev = node;
        (*node).next = next;
        (*node).prev = prev;
        (*prev).next = node;
    }
}

/// `list_add()`: insert `node` just after `head`.
///
/// # Safety
/// Both must be valid and `head` part of a well-formed list.
#[inline]
pub unsafe fn add(node: *mut ListHead, head: *mut ListHead) {
    // SAFETY: the caller's contract.
    unsafe { add_between(node, head, (*head).next) };
}

/// `list_add_tail()`: insert `node` just before `head`.
///
/// # Safety
/// Both must be valid and `head` part of a well-formed list.
#[inline]
pub unsafe fn add_tail(node: *mut ListHead, head: *mut ListHead) {
    // SAFETY: the caller's contract.
    unsafe { add_between(node, (*head).prev, head) };
}

/// `list_del_init()`: unlink `node` and reinitialise it.
///
/// # Safety
/// `node` must be valid and part of a well-formed list, or already
/// self-linked.
#[inline]
pub unsafe fn del_init(node: *mut ListHead) {
    // SAFETY: the caller's contract.
    unsafe {
        let prev = (*node).prev;
        let next = (*node).next;

        (*next).prev = prev;
        (*prev).next = next;
        init(node);
    }
}
