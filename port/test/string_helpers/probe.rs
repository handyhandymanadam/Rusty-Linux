// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `string_helpers_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than
//! copying it. Each of the 16 functions under test keeps its own C name in
//! the kernel (`lib/union_find` shape, no thunk); this wraps each under an
//! `rs_`-prefixed name so both arms can live in one binary, same pattern
//! `port/test/lzo_compress/probe.rs` established.

#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

/// `kernel` is a real, separately compiled crate here too (`kernel_stub.rs`,
/// linked via `--extern`) -- see that file's own comment.
#[allow(unused_extern_crates)]
extern crate kernel;

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/string_helpers_rs.rs"]
mod string_helpers_rs;

use string_helpers_rs as p;

/// # Safety
/// Same contract as the C `string_get_size`.
#[no_mangle]
pub unsafe extern "C" fn rs_string_get_size(
    size: u64,
    blk_size: u64,
    units: c_uint,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    unsafe { p::string_get_size(size, blk_size, units, buf, len) }
}

/// # Safety
/// Same contract as the C `parse_int_array`.
#[no_mangle]
pub unsafe extern "C" fn rs_parse_int_array(
    buf: *const c_char,
    count: usize,
    array: *mut *mut c_int,
) -> c_int {
    unsafe { p::parse_int_array(buf, count, array) }
}

/// # Safety
/// Same contract as the C `parse_int_array_user`.
#[no_mangle]
pub unsafe extern "C" fn rs_parse_int_array_user(
    from: *const c_char,
    count: usize,
    array: *mut *mut c_int,
) -> c_int {
    unsafe { p::parse_int_array_user(from, count, array) }
}

/// # Safety
/// Same contract as the C `string_unescape`.
#[no_mangle]
pub unsafe extern "C" fn rs_string_unescape(
    src: *mut c_char,
    dst: *mut c_char,
    size: usize,
    flags: c_uint,
) -> c_int {
    unsafe { p::string_unescape(src, dst, size, flags) }
}

/// # Safety
/// Same contract as the C `string_escape_mem`.
#[no_mangle]
pub unsafe extern "C" fn rs_string_escape_mem(
    src: *const c_char,
    isz: usize,
    dst: *mut c_char,
    osz: usize,
    flags: c_uint,
    only: *const c_char,
) -> c_int {
    unsafe { p::string_escape_mem(src, isz, dst, osz, flags, only) }
}

/// # Safety
/// Same contract as the C `kstrdup_quotable`.
#[no_mangle]
pub unsafe extern "C" fn rs_kstrdup_quotable(src: *const c_char, gfp: c_uint) -> *mut c_char {
    unsafe { p::kstrdup_quotable(src, gfp) }
}

/// # Safety
/// Same contract as the C `kstrdup_and_replace`.
#[no_mangle]
pub unsafe extern "C" fn rs_kstrdup_and_replace(
    src: *const c_char,
    old: c_char,
    new: c_char,
    gfp: c_uint,
) -> *mut c_char {
    unsafe { p::kstrdup_and_replace(src, old, new, gfp) }
}

/// # Safety
/// Same contract as the C `kasprintf_strarray`.
#[no_mangle]
pub unsafe extern "C" fn rs_kasprintf_strarray(
    gfp: c_uint,
    prefix: *const c_char,
    n: usize,
) -> *mut *mut c_char {
    unsafe { p::kasprintf_strarray(gfp, prefix, n) }
}

/// # Safety
/// Same contract as the C `kfree_strarray`.
#[no_mangle]
pub unsafe extern "C" fn rs_kfree_strarray(array: *mut *mut c_char, n: usize) {
    unsafe { p::kfree_strarray(array, n) }
}

/// # Safety
/// Same contract as the C `skip_spaces`.
#[no_mangle]
pub unsafe extern "C" fn rs_skip_spaces(str_: *const c_char) -> *mut c_char {
    unsafe { p::skip_spaces(str_) }
}

/// # Safety
/// Same contract as the C `strim`.
#[no_mangle]
pub unsafe extern "C" fn rs_strim(s: *mut c_char) -> *mut c_char {
    unsafe { p::strim(s) }
}

/// # Safety
/// Same contract as the C `sysfs_streq`. Widened to `c_int` here so the
/// harness's C caller (which declares it `int`, matching the C `bool`'s
/// ABI as a C source but not necessarily Rust's `bool`, which is 1 byte)
/// reads a clean 0/1 rather than an uninitialized upper 3 bytes of `eax`.
#[no_mangle]
pub unsafe extern "C" fn rs_sysfs_streq(s1: *const c_char, s2: *const c_char) -> c_int {
    unsafe { p::sysfs_streq(s1, s2) as c_int }
}

/// # Safety
/// Same contract as the C `match_string`.
#[no_mangle]
pub unsafe extern "C" fn rs_match_string(
    array: *const *const c_char,
    n: usize,
    string: *const c_char,
) -> c_int {
    unsafe { p::match_string(array, n, string) }
}

/// # Safety
/// Same contract as the C `__sysfs_match_string`.
#[no_mangle]
pub unsafe extern "C" fn rs___sysfs_match_string(
    array: *const *const c_char,
    n: usize,
    str_: *const c_char,
) -> c_int {
    unsafe { p::__sysfs_match_string(array, n, str_) }
}

/// # Safety
/// Same contract as the C `strreplace`.
#[no_mangle]
pub unsafe extern "C" fn rs_strreplace(str_: *mut c_char, old: c_char, new: c_char) -> *mut c_char {
    unsafe { p::strreplace(str_, old, new) }
}

/// # Safety
/// Same contract as the C `memcpy_and_pad`.
#[no_mangle]
pub unsafe extern "C" fn rs_memcpy_and_pad(
    dest: *mut c_void,
    dest_len: usize,
    src: *const c_void,
    count: usize,
    pad: c_int,
) {
    unsafe { p::memcpy_and_pad(dest, dest_len, src, count, pad) }
}
