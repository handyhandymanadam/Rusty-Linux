// SPDX-License-Identifier: GPL-2.0-or-later

//! Differential-harness wrapper around the real `xarray_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than
//! copying it. Presents the port's 41 entry points under `rs_*` so both
//! arms can live in one binary; in the kernel each keeps its own C
//! name, `EXPORT_SYMBOL[_GPL]`'d directly out of the Rust.
//!
//! Every wrapper below casts its opaque `*mut c_void` parameters to the
//! real internal type (`p::XaState`/`p::Xarray`/`p::XaNode`) before
//! calling through -- `main.c` never constructs those types itself, it
//! only ever passes back pointers this side handed it, or a `struct
//! xa_state`/`struct xarray` it built via the REAL C headers (which are
//! layout-identical to these by construction: same pahole-verified
//! sizes, same field order).

#![allow(non_snake_case)]

use std::os::raw::{c_int, c_uint, c_void};

/// `kernel` is a real, separately compiled crate here (`kernel_stub.rs`,
/// linked via `--extern`) -- a same-file `mod kernel {}` would not
/// resolve from inside `#[path]`-included `xarray_rs` below. See
/// `kernel_stub.rs`'s own comment and port/test/rbtree/probe.rs's
/// identical arrangement.
#[allow(unused_extern_crates)]
extern crate kernel;

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/xarray_rs.rs"]
mod xarray_rs;

use xarray_rs as p;

/// The C ABI's `struct xa_limit { u32 max; u32 min; }`.
#[repr(C)]
pub struct XaLimit {
    /// `xa_limit.max`.
    pub max: u32,
    /// `xa_limit.min`.
    pub min: u32,
}

/// # Safety: same contract as the C `xas_load`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_load(xas: *mut c_void) -> *mut c_void {
    unsafe { p::xas_load(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `xas_destroy`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_destroy(xas: *mut c_void) {
    unsafe { p::xas_destroy(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `xas_nomem`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_nomem(xas: *mut c_void, gfp: c_uint) -> bool {
    unsafe { p::xas_nomem(xas as *mut p::XaState, gfp) }
}
/// # Safety: same contract as the C `xas_create_range`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_create_range(xas: *mut c_void) {
    unsafe { p::xas_create_range(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `xas_store`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_store(xas: *mut c_void, entry: *mut c_void) -> *mut c_void {
    unsafe { p::xas_store(xas as *mut p::XaState, entry) }
}
/// # Safety: same contract as the C `xas_get_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_get_mark(xas: *const c_void, mark: c_uint) -> bool {
    unsafe { p::xas_get_mark(xas as *const p::XaState, mark) }
}
/// # Safety: same contract as the C `xas_set_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_set_mark(xas: *const c_void, mark: c_uint) {
    unsafe { p::xas_set_mark(xas as *const p::XaState, mark) }
}
/// # Safety: same contract as the C `xas_clear_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_clear_mark(xas: *const c_void, mark: c_uint) {
    unsafe { p::xas_clear_mark(xas as *const p::XaState, mark) }
}
/// # Safety: same contract as the C `xas_init_marks`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_init_marks(xas: *const c_void) {
    unsafe { p::xas_init_marks(xas as *const p::XaState) }
}
/// # Safety: same contract as the C `xas_split_alloc`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_split_alloc(
    xas: *mut c_void,
    entry: *mut c_void,
    order: c_uint,
    gfp: c_uint,
) {
    unsafe { p::xas_split_alloc(xas as *mut p::XaState, entry, order, gfp) }
}
/// # Safety: same contract as the C `xas_split`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_split(xas: *mut c_void, entry: *mut c_void, order: c_uint) {
    unsafe { p::xas_split(xas as *mut p::XaState, entry, order) }
}
/// # Safety: same contract as the C `xas_try_split_min_order`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_try_split_min_order(order: c_uint) -> c_uint {
    unsafe { p::xas_try_split_min_order(order) }
}
/// # Safety: same contract as the C `xas_try_split`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_try_split(xas: *mut c_void, entry: *mut c_void, order: c_uint) {
    unsafe { p::xas_try_split(xas as *mut p::XaState, entry, order) }
}
/// # Safety: same contract as the C `xas_pause`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_pause(xas: *mut c_void) {
    unsafe { p::xas_pause(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `__xas_prev`.
#[no_mangle]
pub unsafe extern "C" fn rs___xas_prev(xas: *mut c_void) -> *mut c_void {
    unsafe { p::__xas_prev(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `__xas_next`.
#[no_mangle]
pub unsafe extern "C" fn rs___xas_next(xas: *mut c_void) -> *mut c_void {
    unsafe { p::__xas_next(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `xas_find`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_find(xas: *mut c_void, max: usize) -> *mut c_void {
    unsafe { p::xas_find(xas as *mut p::XaState, max) }
}
/// # Safety: same contract as the C `xas_find_marked`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_find_marked(
    xas: *mut c_void,
    max: usize,
    mark: c_uint,
) -> *mut c_void {
    unsafe { p::xas_find_marked(xas as *mut p::XaState, max, mark) }
}
/// # Safety: same contract as the C `xas_find_conflict`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_find_conflict(xas: *mut c_void) -> *mut c_void {
    unsafe { p::xas_find_conflict(xas as *mut p::XaState) }
}
/// # Safety: same contract as the C `xas_get_order`.
#[no_mangle]
pub unsafe extern "C" fn rs_xas_get_order(xas: *mut c_void) -> c_int {
    unsafe { p::xas_get_order(xas as *mut p::XaState) }
}

/// # Safety: same contract as the C `xa_load`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_load(xa: *mut c_void, index: usize) -> *mut c_void {
    unsafe { p::xa_load(xa as *mut p::Xarray, index) }
}
/// # Safety: same contract as the C `__xa_erase`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_erase(xa: *mut c_void, index: usize) -> *mut c_void {
    unsafe { p::__xa_erase(xa as *mut p::Xarray, index) }
}
/// # Safety: same contract as the C `xa_erase`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_erase(xa: *mut c_void, index: usize) -> *mut c_void {
    unsafe { p::xa_erase(xa as *mut p::Xarray, index) }
}
/// # Safety: same contract as the C `__xa_store`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_store(
    xa: *mut c_void,
    index: usize,
    entry: *mut c_void,
    gfp: c_uint,
) -> *mut c_void {
    unsafe { p::__xa_store(xa as *mut p::Xarray, index, entry, gfp) }
}
/// # Safety: same contract as the C `xa_store`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_store(
    xa: *mut c_void,
    index: usize,
    entry: *mut c_void,
    gfp: c_uint,
) -> *mut c_void {
    unsafe { p::xa_store(xa as *mut p::Xarray, index, entry, gfp) }
}
/// # Safety: same contract as the C `__xa_cmpxchg`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_cmpxchg(
    xa: *mut c_void,
    index: usize,
    old: *mut c_void,
    entry: *mut c_void,
    gfp: c_uint,
) -> *mut c_void {
    unsafe { p::__xa_cmpxchg(xa as *mut p::Xarray, index, old, entry, gfp) }
}
/// # Safety: same contract as the C `__xa_insert`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_insert(
    xa: *mut c_void,
    index: usize,
    entry: *mut c_void,
    gfp: c_uint,
) -> c_int {
    unsafe { p::__xa_insert(xa as *mut p::Xarray, index, entry, gfp) }
}
/// # Safety: same contract as the C `xa_store_range`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_store_range(
    xa: *mut c_void,
    first: usize,
    last: usize,
    entry: *mut c_void,
    gfp: c_uint,
) -> *mut c_void {
    unsafe { p::xa_store_range(xa as *mut p::Xarray, first, last, entry, gfp) }
}
/// # Safety: same contract as the C `xa_get_order`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_get_order(xa: *mut c_void, index: usize) -> c_int {
    unsafe { p::xa_get_order(xa as *mut p::Xarray, index) }
}
/// # Safety: same contract as the C `__xa_set_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_set_mark(xa: *mut c_void, index: usize, mark: c_uint) {
    unsafe { p::__xa_set_mark(xa as *mut p::Xarray, index, mark) }
}
/// # Safety: same contract as the C `__xa_clear_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_clear_mark(xa: *mut c_void, index: usize, mark: c_uint) {
    unsafe { p::__xa_clear_mark(xa as *mut p::Xarray, index, mark) }
}
/// # Safety: same contract as the C `xa_get_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_get_mark(xa: *mut c_void, index: usize, mark: c_uint) -> bool {
    unsafe { p::xa_get_mark(xa as *mut p::Xarray, index, mark) }
}
/// # Safety: same contract as the C `xa_set_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_set_mark(xa: *mut c_void, index: usize, mark: c_uint) {
    unsafe { p::xa_set_mark(xa as *mut p::Xarray, index, mark) }
}
/// # Safety: same contract as the C `xa_clear_mark`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_clear_mark(xa: *mut c_void, index: usize, mark: c_uint) {
    unsafe { p::xa_clear_mark(xa as *mut p::Xarray, index, mark) }
}
/// # Safety: same contract as the C `xa_find`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_find(
    xa: *mut c_void,
    indexp: *mut usize,
    max: usize,
    filter: c_uint,
) -> *mut c_void {
    unsafe { p::xa_find(xa as *mut p::Xarray, indexp, max, filter) }
}
/// # Safety: same contract as the C `xa_find_after`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_find_after(
    xa: *mut c_void,
    indexp: *mut usize,
    max: usize,
    filter: c_uint,
) -> *mut c_void {
    unsafe { p::xa_find_after(xa as *mut p::Xarray, indexp, max, filter) }
}
/// # Safety: same contract as the C `xa_extract`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_extract(
    xa: *mut c_void,
    dst: *mut *mut c_void,
    start: usize,
    max: usize,
    n: c_uint,
    filter: c_uint,
) -> c_uint {
    unsafe { p::xa_extract(xa as *mut p::Xarray, dst, start, max, n, filter) }
}
/// # Safety: same contract as the C `xa_destroy`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_destroy(xa: *mut c_void) {
    unsafe { p::xa_destroy(xa as *mut p::Xarray) }
}
/// # Safety: same contract as the C `xa_delete_node`.
#[no_mangle]
pub unsafe extern "C" fn rs_xa_delete_node(
    node: *mut c_void,
    update: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    unsafe {
        p::xa_delete_node(
            node as *mut p::XaNode,
            core::mem::transmute::<
                Option<unsafe extern "C" fn(*mut c_void)>,
                Option<unsafe extern "C" fn(*mut p::XaNode)>,
            >(update),
        )
    }
}
/// # Safety: same contract as the C `__xa_alloc`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_alloc(
    xa: *mut c_void,
    id: *mut u32,
    entry: *mut c_void,
    limit: XaLimit,
    gfp: c_uint,
) -> c_int {
    unsafe {
        p::__xa_alloc(
            xa as *mut p::Xarray,
            id,
            entry,
            p::XaLimit { max: limit.max, min: limit.min },
            gfp,
        )
    }
}
/// # Safety: same contract as the C `__xa_alloc_cyclic`.
#[no_mangle]
pub unsafe extern "C" fn rs___xa_alloc_cyclic(
    xa: *mut c_void,
    id: *mut u32,
    entry: *mut c_void,
    limit: XaLimit,
    next: *mut u32,
    gfp: c_uint,
) -> c_int {
    unsafe {
        p::__xa_alloc_cyclic(
            xa as *mut p::Xarray,
            id,
            entry,
            p::XaLimit { max: limit.max, min: limit.min },
            next,
            gfp,
        )
    }
}
