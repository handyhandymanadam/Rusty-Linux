// SPDX-License-Identifier: GPL-2.0-or-later

//! Differential-harness wrapper around the real `rbtree_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than
//! copying it. Presents the port's twelve entry points under `rs_*` so
//! both arms can live in one binary; in the kernel each keeps its own C
//! name, `EXPORT_SYMBOL`'d directly out of the Rust (`lib/union_find`
//! shape, no C thunk).

#![allow(non_snake_case)]

use std::os::raw::c_void;

/// `kernel` is a real, separately compiled crate here (`kernel_stub.rs`,
/// linked via `--extern`) -- a same-file `mod kernel {}` would not resolve
/// from inside `#[path]`-included `rbtree_rs` below, which is its own
/// module, not code pasted into this one. See `kernel_stub.rs`'s own
/// comment and port/test/lzo_compress/probe.rs's identical arrangement.
#[allow(unused_extern_crates)]
extern crate kernel;

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/rbtree_rs.rs"]
mod rbtree_rs;

use rbtree_rs as p;

/// The `void (*)(struct rb_node *, struct rb_node *)` callback type, as the
/// C ABI sees it -- opaque here, since main.c supplies real callbacks for
/// the augmented-path tests.
type AugmentRotate = unsafe extern "C" fn(*mut c_void, *mut c_void);

/// # Safety
/// Same contract as the C `rb_insert_color`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_insert_color(node: *mut c_void, root: *mut c_void) {
    unsafe { p::rb_insert_color(node as *mut p::RbNode, root as *mut p::RbRoot) }
}

/// # Safety
/// Same contract as the C `rb_erase`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_erase(node: *mut c_void, root: *mut c_void) {
    unsafe { p::rb_erase(node as *mut p::RbNode, root as *mut p::RbRoot) }
}

/// # Safety
/// Same contract as the C `__rb_insert_augmented`.
#[no_mangle]
pub unsafe extern "C" fn rs___rb_insert_augmented(node: *mut c_void, root: *mut c_void, augment_rotate: AugmentRotate) {
    unsafe {
        p::__rb_insert_augmented(
            node as *mut p::RbNode,
            root as *mut p::RbRoot,
            core::mem::transmute::<AugmentRotate, unsafe extern "C" fn(*mut p::RbNode, *mut p::RbNode)>(
                augment_rotate,
            ),
        )
    }
}

/// # Safety
/// Same contract as the C `__rb_erase_color`.
#[no_mangle]
pub unsafe extern "C" fn rs___rb_erase_color(parent: *mut c_void, root: *mut c_void, augment_rotate: AugmentRotate) {
    unsafe {
        p::__rb_erase_color(
            parent as *mut p::RbNode,
            root as *mut p::RbRoot,
            core::mem::transmute::<AugmentRotate, unsafe extern "C" fn(*mut p::RbNode, *mut p::RbNode)>(
                augment_rotate,
            ),
        )
    }
}

/// # Safety
/// Same contract as the C `rb_first`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_first(root: *const c_void) -> *mut c_void {
    unsafe { p::rb_first(root as *const p::RbRoot) as *mut c_void }
}

/// # Safety
/// Same contract as the C `rb_last`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_last(root: *const c_void) -> *mut c_void {
    unsafe { p::rb_last(root as *const p::RbRoot) as *mut c_void }
}

/// # Safety
/// Same contract as the C `rb_next`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_next(node: *const c_void) -> *mut c_void {
    unsafe { p::rb_next(node as *const p::RbNode) as *mut c_void }
}

/// # Safety
/// Same contract as the C `rb_prev`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_prev(node: *const c_void) -> *mut c_void {
    unsafe { p::rb_prev(node as *const p::RbNode) as *mut c_void }
}

/// # Safety
/// Same contract as the C `rb_replace_node`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_replace_node(victim: *mut c_void, new: *mut c_void, root: *mut c_void) {
    unsafe { p::rb_replace_node(victim as *mut p::RbNode, new as *mut p::RbNode, root as *mut p::RbRoot) }
}

/// # Safety
/// Same contract as the C `rb_replace_node_rcu`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_replace_node_rcu(victim: *mut c_void, new: *mut c_void, root: *mut c_void) {
    unsafe { p::rb_replace_node_rcu(victim as *mut p::RbNode, new as *mut p::RbNode, root as *mut p::RbRoot) }
}

/// # Safety
/// Same contract as the C `rb_next_postorder`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_next_postorder(node: *const c_void) -> *mut c_void {
    unsafe { p::rb_next_postorder(node as *const p::RbNode) as *mut c_void }
}

/// # Safety
/// Same contract as the C `rb_first_postorder`.
#[no_mangle]
pub unsafe extern "C" fn rs_rb_first_postorder(root: *const c_void) -> *mut c_void {
    unsafe { p::rb_first_postorder(root as *const p::RbRoot) as *mut c_void }
}
