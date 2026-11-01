// SPDX-License-Identifier: 0BSD

//! Differential-harness wrapper around the real `xz_dec_stream_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it — a stale copy tested here while the kernel builds something else is the
//! failure notes/PRIOR-ART.md §2 records four times.
//!
//! It exists to present the port under the `rs_xz_dec_*` names the harness
//! calls, allocating the state with `malloc` because the kernel's own
//! `xz_dec_init()` is the C half that owns `kmalloc`.

use std::os::raw::{c_int, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/xz/xz_dec_stream_rs.rs"]
mod xz_dec_stream_rs;

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    /* Only the stream layer is ported, so lzma2, bcj and crc32 are the
     * kernel's own pristine C, shared by both arms. xz_private.h:118,139. */
    fn xz_dec_lzma2_create(mode: c_int, dict_max: u32) -> *mut c_void;
    fn xz_dec_lzma2_end(s: *mut c_void);
    fn xz_dec_bcj_create(single_call: bool) -> *mut c_void;
}

/// Allocate and initialise a decoder, the way the C `xz_dec_init()` does.
///
/// The kernel's `xz_dec_init()` is the C half that owns `kmalloc`; this is the
/// userspace stand-in for it, so the harness exercises the same Rust the
/// kernel does without the port having to allocate.
///
/// # Safety
/// Returns a pointer the caller must pass to [`rs_xz_dec_end`].
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_init(mode: c_int, dict_max: u32) -> *mut c_void {
    let size = xz_dec_stream_rs::rust_xz_dec_size();
    // SAFETY: malloc of exactly the size the port reports for its own state.
    let p = unsafe { malloc(size) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `p` covers `size` bytes, which is what the port asked for.
    unsafe { core::ptr::write_bytes(p as *mut u8, 0, size) };

    // XZ_SINGLE is 0; anything else is multi-call. xz_private.h:139.
    let single = mode == 0;
    // SAFETY: plain calls into the pristine C allocators.
    let lz = unsafe { xz_dec_lzma2_create(mode, dict_max) };
    // SAFETY: as above.
    let bcj = unsafe { xz_dec_bcj_create(single) };
    if lz.is_null() || bcj.is_null() {
        // SAFETY: everything here came from malloc/create above and is dropped.
        unsafe {
            if !lz.is_null() { xz_dec_lzma2_end(lz); }
            if !bcj.is_null() { free(bcj); }
            free(p);
        }
        return core::ptr::null_mut();
    }
    // SAFETY: `p` is correctly sized and aligned; `bcj` and `lzma2` are live
    // pointers from the creators above, and the port owns them from here.
    unsafe {
        xz_dec_stream_rs::rust_xz_dec_init(p as *mut _, mode, bcj as *mut _, lz as *mut _)
    };
    p
}

/// # Safety
/// `s` must come from [`rs_xz_dec_init`] and `b` must be a live `struct xz_buf`.
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_run(s: *mut c_void, b: *mut c_void) -> c_int {
    // SAFETY: the caller's contract, above.
    unsafe { xz_dec_stream_rs::rust_xz_dec_run(s as *mut _, b as *mut _) }
}

/// # Safety
/// `s` must come from [`rs_xz_dec_init`] and is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn rs_xz_dec_end(s: *mut c_void) {
    if s.is_null() {
        return;
    }
    // SAFETY: the port hands back the pointers it was given at init.
    unsafe {
        let lz = xz_dec_stream_rs::rust_xz_dec_lzma2(s as *mut _);
        let bcj = xz_dec_stream_rs::rust_xz_dec_bcj(s as *mut _);
        xz_dec_lzma2_end(lz as *mut c_void);
        // xz_private.h:158 defines xz_dec_bcj_end(s) as kfree(s).
        free(bcj as *mut c_void);
        free(s);
    }
}
