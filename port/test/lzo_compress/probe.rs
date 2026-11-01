// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `lzo1x_compress_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than
//! copying it. Presents the port's four entry points under `rs_*` so both
//! arms can live in one binary; in the kernel each keeps its own C name,
//! `EXPORT_SYMBOL_GPL`'d directly out of the Rust (`lib/union_find` shape,
//! no C thunk).

#![allow(non_snake_case)]

use std::os::raw::{c_int, c_uchar, c_void};

/// `kernel` is a real, separately compiled crate here too (`kernel_stub.rs`,
/// linked via `--extern`) -- a same-file `mod kernel {}` would not resolve
/// from inside `#[path]`-included `lzo1x_compress_rs` below, which is its
/// own module, not code pasted into this one. See `kernel_stub.rs`'s own
/// comment. Only `lzo1x_compress_rs` itself names `kernel::` directly, so
/// this crate's own top level never mentions it -- hence the `allow`.
#[allow(unused_extern_crates)]
extern crate kernel;

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/lzo/lzo1x_compress_rs.rs"]
mod lzo1x_compress_rs;

use lzo1x_compress_rs as p;

/// # Safety
/// Same contract as the C `lzo1x_1_compress`.
#[no_mangle]
pub unsafe extern "C" fn rs_lzo1x_1_compress(
    src: *const c_uchar,
    src_len: usize,
    dst: *mut c_uchar,
    dst_len: *mut usize,
    wrkmem: *mut c_void,
) -> c_int {
    unsafe { p::lzo1x_1_compress(src, src_len, dst, dst_len, wrkmem) }
}

/// # Safety
/// Same contract as the C `lzorle1x_1_compress`.
#[no_mangle]
pub unsafe extern "C" fn rs_lzorle1x_1_compress(
    src: *const c_uchar,
    src_len: usize,
    dst: *mut c_uchar,
    dst_len: *mut usize,
    wrkmem: *mut c_void,
) -> c_int {
    unsafe { p::lzorle1x_1_compress(src, src_len, dst, dst_len, wrkmem) }
}

/// # Safety
/// Same contract as the C `lzo1x_1_compress_safe`.
#[no_mangle]
pub unsafe extern "C" fn rs_lzo1x_1_compress_safe(
    src: *const c_uchar,
    src_len: usize,
    dst: *mut c_uchar,
    dst_len: *mut usize,
    wrkmem: *mut c_void,
) -> c_int {
    unsafe { p::lzo1x_1_compress_safe(src, src_len, dst, dst_len, wrkmem) }
}

/// # Safety
/// Same contract as the C `lzorle1x_1_compress_safe`.
#[no_mangle]
pub unsafe extern "C" fn rs_lzorle1x_1_compress_safe(
    src: *const c_uchar,
    src_len: usize,
    dst: *mut c_uchar,
    dst_len: *mut usize,
    wrkmem: *mut c_void,
) -> c_int {
    unsafe { p::lzorle1x_1_compress_safe(src, src_len, dst, dst_len, wrkmem) }
}
