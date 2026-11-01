// SPDX-License-Identifier: 0BSD

//! Differential-harness wrapper around the real `xz_dec_lzma2_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it — a stale copy tested here while the kernel builds something else is the
//! failure notes/PRIOR-ART.md §2 records four times.
//!
//! It presents the port under `rs_xz_dec_lzma2_*`, standing in for the C
//! `xz_dec_lzma2_create()`/`_end()` that own `kmalloc`/`vmalloc` and therefore
//! stay C in the kernel.

use std::os::raw::{c_int, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/xz/xz_dec_lzma2_rs.rs"]
mod xz_dec_lzma2_rs;

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn xz_dec_lzma2_dict_alloc(size: u32) -> *mut u8;
}

/// Stand-in for the C `xz_dec_lzma2_create()`.
///
/// # Safety
/// The result must be passed to [`rs_xz_dec_lzma2_end`].
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_lzma2_create(mode: c_int, dict_max: u32) -> *mut c_void {
    let size = xz_dec_lzma2_rs::rust_xz_dec_lzma2_size();
    // SAFETY: malloc of exactly the size the port reports for its state.
    let s = unsafe { malloc(size) };
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `s` covers `size` bytes.
    unsafe { core::ptr::write_bytes(s as *mut u8, 0, size) };

    // XZ_PREALLOC is 1: the C allocates the dictionary up front in that mode
    // only, and leaves dict.buf null in the other two.
    let mut dict_buf: *mut u8 = core::ptr::null_mut();
    if mode == 1 {
        // SAFETY: plain call into the allocator shim.
        dict_buf = unsafe { xz_dec_lzma2_dict_alloc(dict_max) };
        if dict_buf.is_null() {
            // SAFETY: `s` came from malloc above and is dropped here.
            unsafe { free(s) };
            return core::ptr::null_mut();
        }
    }
    // SAFETY: `s` is correctly sized and zeroed; `dict_buf` is a live
    // allocation of `dict_max` bytes in XZ_PREALLOC and null otherwise, which
    // is exactly what this function's contract requires.
    unsafe { xz_dec_lzma2_rs::rust_xz_dec_lzma2_init(s as *mut _, mode, dict_max, dict_buf) };
    s
}

/// # Safety
/// `s` must come from [`rs_xz_dec_lzma2_create`].
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_lzma2_reset(s: *mut c_void, props: u8) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { xz_dec_lzma2_rs::xz_dec_lzma2_reset(s as *mut _, props) }
}

/// # Safety
/// `s` must come from [`rs_xz_dec_lzma2_create`]; `b` a live `struct xz_buf`.
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_lzma2_run(s: *mut c_void, b: *mut c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { xz_dec_lzma2_rs::xz_dec_lzma2_run(s as *mut _, b as *mut _) }
}

/// # Safety
/// `s` must come from [`rs_xz_dec_lzma2_create`] and is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_lzma2_end(s: *mut c_void) {
    if s.is_null() {
        return;
    }
    // SAFETY: the port hands back whichever dictionary buffer it owns, or
    // null; free() accepts null.
    unsafe {
        let d = xz_dec_lzma2_rs::rust_xz_dec_lzma2_dict_to_free(s as *mut _);
        free(d);
        free(s);
    }
}
