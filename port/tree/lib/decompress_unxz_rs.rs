// SPDX-License-Identifier: 0BSD

//! The XZ stream driver -- Rust behind `lib/decompress_unxz.c`.
//!
//! Replaces: lib/decompress_unxz.c (the non-`XZ_PREBOOT` arm only -- see
//! `decompress_bunzip2_rs.rs`'s module doc for why the pre-boot arm is out
//! of scope for every file in this family: here it's `#ifdef XZ_PREBOOT`
//! rather than `#ifdef STATIC` / `#define PREBOOT`, but the same freestanding
//! translation unit neither of this project's builds compiles, textually
//! `#include`-ing `xz_crc32.c`/`xz_dec_stream.c`/`xz_dec_lzma2.c`/
//! `xz_dec_bcj.c` bodies that in the normal build are already Rust).
//!
//! `unxz()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` table and is not `EXPORT_SYMBOL`'d, so this is a
//! full replacement, same shape as the rest of this file family.
//!
//! # Simpler than its siblings: no archive framing of its own
//!
//! Unlike `decompress_unlz4_rs.rs` (chunk length prefixes) and
//! `decompress_unlzo_rs.rs` (LZOP header + block prefixes), the `.xz`
//! container format is entirely `xz_dec_run()`'s problem, not this
//! wrapper's -- `xz/xz_dec_stream.c` is `lib/bcd` shaped (real C entry
//! symbols `xz_dec_init()`/`xz_dec_run()`/`xz_dec_end()`, Rust bodies behind
//! them per that file's own module doc; `xz_dec_run()` itself has no
//! `EXPORT_SYMBOL` but the shape is otherwise identical) and does all of the
//! stream/block/index parsing. This file only drives the state machine:
//! pick single-call or multi-call mode, own the buffers if the caller
//! didn't supply them, and shuttle bytes through `fill()`/`flush()` in the
//! multi-call case. All three calls here are declared `extern "C"` and
//! called exactly as the C wrapper being replaced already called them.
//!
//! # `kmalloc` stays in C, `kfree` doesn't
//!
//! `<linux/decompress/mm.h>` is included unconditionally here (guarded by
//! `__KERNEL__`, not `STATIC`), and its non-`STATIC` arm is what maps this
//! file's `malloc`/`free` calls to `kmalloc(a, GFP_KERNEL)`/`kfree(a)` --
//! same mechanism `decompress_bunzip2_rs.rs` uses. `kmalloc` is a macro with
//! no linkable symbol, so `decompress_unxz.c` (this port's C half) keeps a
//! three-line wrapper, `decompress_unxz_alloc`. `kfree` is a real
//! `EXPORT_SYMBOL` and is called directly from here.
//!
//! # The alloc-failure goto cascade, and the ONE PLACE IT DOESN'T RUN
//!
//! `xz_dec_init()` failing, then `malloc()`ing `out` failing, then
//! `malloc()`ing `in` failing are three plain forward gotos into a shared
//! cleanup tail (`error_alloc_in` falls into `error_alloc_out` falls into
//! `error_alloc_state`) -- structurally the same shape
//! `decompress_unlz4_rs.rs`'s module doc describes, translated the same way
//! with early returns instead, since nothing here is inside a loop.
//!
//! **Recorded, not fixed:** in single-call mode (`fill == NULL && flush ==
//! NULL`), the C's `if (must_free_in) free(in); if (flush != NULL)
//! free(b.out);` cleanup sits ONLY in the multi-call `else` branch -- it
//! never runs for single-call mode at all. `b.out` is never a problem there
//! (`flush == NULL` forces `b.out = out`, the caller's own pointer, never
//! allocated). `in` only leaks if a caller passes `in == NULL` together with
//! `fill == NULL`, which has no sensible single-call meaning in the first
//! place (nothing could ever fill the freshly `malloc`'d buffer) and is not
//! a combination any in-tree caller uses. Kept exactly as upstream has it
//! rather than adding a free upstream doesn't have, since "fixing" an
//! unreachable-in-practice leak is exactly the kind of silent behavior
//! change GOALS.md's C-is-a-reference boundary warns against doing quietly.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

const XZ_IOBUF_SIZE: usize = 4096;

const XZ_SINGLE: c_int = 0;
const XZ_DYNALLOC: c_int = 2;

const XZ_OK: c_int = 0;
const XZ_STREAM_END: c_int = 1;
const XZ_MEM_ERROR: c_int = 3;
const XZ_FORMAT_ERROR: c_int = 5;
const XZ_OPTIONS_ERROR: c_int = 6;
const XZ_DATA_ERROR: c_int = 7;
const XZ_BUF_ERROR: c_int = 8;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

/// `struct xz_dec`, `include/linux/xz.h` -- opaque; only ever passed
/// through to the real `xz_dec_*` entry points.
#[repr(C)]
struct XzDec {
    _private: [u8; 0],
}

/// `struct xz_buf`, `include/linux/xz.h`.
#[repr(C)]
struct XzBuf {
    in_: *const u8,
    in_pos: usize,
    in_size: usize,
    out: *mut u8,
    out_pos: usize,
    out_size: usize,
}

extern "C" {
    /// `lib/decompress_unxz.c`. Three lines: `return kmalloc(size,
    /// GFP_KERNEL);` -- `kmalloc` itself has no linkable symbol.
    fn decompress_unxz_alloc(size: c_uint) -> *mut c_void;
    /// `mm/slub.c`, `EXPORT_SYMBOL(kfree)`. Real out-of-line function.
    fn kfree(objp: *const c_void);
    /// `lib/xz/xz_dec_stream.c`. Real C entry symbol, `kmalloc`s the state
    /// and calls into Rust (`rust_xz_dec_init`) to fill it in.
    fn xz_dec_init(mode: c_int, dict_max: c_uint) -> *mut XzDec;
    /// `lib/xz/xz_dec_stream_rs.rs`. Already Rust, no `EXPORT_SYMBOL` (same
    /// as `unxz` itself -- reached only through this file).
    fn xz_dec_run(s: *mut XzDec, b: *mut XzBuf) -> c_int;
    /// `lib/decompress_unxz.c`. Real C entry symbol, `kfree`s the state.
    fn xz_dec_end(s: *mut XzDec);
}

/// `unxz()`, `lib/decompress_unxz.c`. The dispatcher's `.decompressor`
/// entry for the `"xz"` magic (`\xfd7zXZ`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn unxz(
    in_: *mut u8,
    in_size_param: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out: *mut u8,
    in_used: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    // *in_used += b.in_pos accumulates across every fill/flush loop
    // iteration; the C's `long` is signed, so an overflow here is UB in C
    // too, not a defined wraparound to preserve -- but reaching it needs
    // exabyte-scale total input in one call, via a caller-configured
    // per-chunk buffer size, not a stream-embedded length field. wrapping_add
    // matches what the C actually compiles to on this target (a plain add)
    // rather than panicking on an overflow neither arm can realistically hit.
    // Found by the CONFIG_RUST_OVERFLOW_CHECKS panic-symbol sweep, 2026-09-06.
    if !in_used.is_null() {
        unsafe { *in_used = 0 };
    }

    // Found by adversarial review: an earlier version passed u32::MAX for
    // dict_max unconditionally. C passes 0 for XZ_SINGLE and (uint32_t)-1
    // only for XZ_DYNALLOC -- `xz_dec_init(XZ_SINGLE, 0)` /
    // `xz_dec_init(XZ_DYNALLOC, (uint32_t)-1)`. Currently harmless (dict_max
    // is read only under DEC_IS_MULTI, which XZ_SINGLE never satisfies) but
    // a real, avoidable divergence from what the C wrapper being replaced
    // actually passed -- matched exactly rather than recorded as
    // deliberate, since there's no reason to differ here at all.
    let (mode, dict_max) = if fill.is_none() && flush.is_none() {
        (XZ_SINGLE, 0)
    } else {
        (XZ_DYNALLOC, u32::MAX)
    };
    let s = unsafe { xz_dec_init(mode, dict_max) };
    if s.is_null() {
        call_error(b"XZ decompressor ran out of memory\0");
        return -1;
    }

    let mut b = XzBuf {
        in_: core::ptr::null(),
        in_pos: 0,
        in_size: 0,
        out: core::ptr::null_mut(),
        out_pos: 0,
        out_size: 0,
    };

    if flush.is_none() {
        b.out = out;
        b.out_size = usize::MAX;
    } else {
        b.out_size = XZ_IOBUF_SIZE;
        b.out = unsafe { decompress_unxz_alloc(XZ_IOBUF_SIZE as c_uint) } as *mut u8;
        if b.out.is_null() {
            unsafe { xz_dec_end(s) };
            call_error(b"XZ decompressor ran out of memory\0");
            return -1;
        }
    }

    let mut in_ = in_;
    let must_free_in = in_.is_null();
    if must_free_in {
        in_ = unsafe { decompress_unxz_alloc(XZ_IOBUF_SIZE as c_uint) } as *mut u8;
        if in_.is_null() {
            if flush.is_some() {
                unsafe { kfree(b.out as *const c_void) };
            }
            unsafe { xz_dec_end(s) };
            call_error(b"XZ decompressor ran out of memory\0");
            return -1;
        }
    }

    b.in_ = in_;
    b.in_pos = 0;
    b.in_size = in_size_param as usize;
    b.out_pos = 0;

    let mut ret: c_int;
    if fill.is_none() && flush.is_none() {
        ret = unsafe { xz_dec_run(s, &mut b) };
    } else {
        loop {
            if b.in_pos == b.in_size {
                if let Some(f) = fill {
                    if !in_used.is_null() {
                        unsafe { *in_used = (*in_used).wrapping_add(b.in_pos as c_long) };
                    }
                    b.in_pos = 0;

                    let got = unsafe { f(in_ as *mut c_void, XZ_IOBUF_SIZE as c_ulong) };
                    if got < 0 {
                        ret = XZ_BUF_ERROR;
                        break;
                    }
                    b.in_size = got as usize;
                }
            }

            ret = unsafe { xz_dec_run(s, &mut b) };

            if let Some(f) = flush {
                if b.out_pos == b.out_size || (ret != XZ_OK && b.out_pos > 0) {
                    if unsafe { f(b.out as *mut c_void, b.out_pos as c_ulong) }
                        != b.out_pos as c_long
                    {
                        ret = XZ_BUF_ERROR;
                    }
                    b.out_pos = 0;
                }
            }

            if ret != XZ_OK {
                break;
            }
        }

        if must_free_in {
            unsafe { kfree(in_ as *const c_void) };
        }
        if flush.is_some() {
            unsafe { kfree(b.out as *const c_void) };
        }
    }

    if !in_used.is_null() {
        unsafe { *in_used = (*in_used).wrapping_add(b.in_pos as c_long) };
    }

    unsafe { xz_dec_end(s) };

    if ret == XZ_STREAM_END {
        return 0;
    }
    match ret {
        XZ_MEM_ERROR => call_error(b"XZ decompressor ran out of memory\0"),
        XZ_FORMAT_ERROR => {
            call_error(b"Input is not in the XZ format (wrong magic bytes)\0")
        }
        XZ_OPTIONS_ERROR => call_error(
            b"Input was encoded with settings that are not supported by this XZ decoder\0",
        ),
        XZ_DATA_ERROR | XZ_BUF_ERROR => call_error(b"XZ-compressed data is corrupt\0"),
        _ => call_error(b"Bug in the XZ decompressor\0"),
    }
    -1
}
