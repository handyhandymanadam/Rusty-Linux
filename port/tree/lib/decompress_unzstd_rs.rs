// SPDX-License-Identifier: GPL-2.0

//! The ZSTD stream driver -- Rust behind `lib/decompress_unzstd.c`.
//!
//! Replaces: lib/decompress_unzstd.c (the non-`UNZSTD_PREBOOT` arm only --
//! see `decompress_bunzip2_rs.rs`'s module doc for why the pre-boot arm is
//! out of scope for every file in this family).
//!
//! `unzstd()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` table and is not `EXPORT_SYMBOL`'d, so this is a
//! full replacement, same shape as the rest of this file family.
//!
//! # Calls a real EXPORT_SYMBOL API that is still entirely C behind it
//!
//! Unlike `decompress_unxz_rs.rs` (whose `xz_dec_*` calls are already
//! `bcd`-shaped, C entry symbols with Rust bodies), the ten `zstd_*`
//! functions this file calls are real `EXPORT_SYMBOL`s from
//! `lib/zstd/zstd_decompress_module.c` -- itself a thin (141-line) thunk
//! layer, but over `lib/zstd/decompress/{zstd_decompress,
//! zstd_decompress_block,zstd_ddict}.c`, which are NOT ported yet (~4500
//! lines together, still queued). That does not change anything about
//! porting THIS file: `zstd_decompress_dctx()` etc. are stable, exported C
//! ABI regardless of what is or isn't Rust behind them, called here exactly
//! as the C wrapper being replaced already called them -- the same
//! reasoning as calling any other kernel C function. When that backend is
//! ported later, this file does not change at all.
//!
//! # `vmalloc`/`vfree` stay split, same pattern as `decompress_unlz4_rs.rs`
//!
//! `large_malloc`/`large_free` are `vmalloc`/`vfree` under `mm.h`'s non-
//! `STATIC` arm (this file, like `decompress_unxz.c`, includes
//! `<linux/decompress/mm.h>` unconditionally rather than gating it on
//! `STATIC` directly). `vmalloc` is a macro with no linkable symbol, so
//! `decompress_unzstd.c` (this port's C half) keeps a three-line wrapper,
//! `decompress_unzstd_alloc`. `vfree` is a real `EXPORT_SYMBOL` and is
//! called directly from here.
//!
//! # Three functions, three different shapes
//!
//! `handle_zstd_error()` is a plain leaf, no cleanup, translated directly.
//! `decompress_single()` has one `goto out` cleanup point (free the
//! workspace if allocated) -- a single early-return-with-cleanup, not
//! worth a labelled block. `__unzstd()` has TEN `goto out` sites (pristine
//! `lib/decompress_unzstd.c` lines 209/220/232/252/256/261/274/297/306/312,
//! confirmed with `grep -n 'goto out' port/pristine/lib/decompress_unzstd.c`
//! -- corrected by adversarial review, which counted from the code rather
//! than trusting this paragraph's first draft of "six") converging on ONE
//! cleanup
//! that independently frees three buffers (`in_allocated`/`out_allocated`/
//! `wksp`) each only if it was actually allocated -- unlike this file
//! family's other multi-exit functions, the three frees here are not
//! staged/cascading (nothing here depends on ownership of something else),
//! so a single labelled block whose `break` value is `err`, followed by
//! three independent null checks, is the direct translation -- no state
//! machine, no early-return duplication. Re-verified against every one of
//! the ten sites: no double-free, no leak, no path escapes the block.
//!
//! # A recorded divergence: `decompress_unzstd.c`'s own sign-extension bug
//!
//! `lib/decompress_unzstd.c:81`'s own `#define ZSTD_WINDOWSIZE_MAX (1 <<
//! ZSTD_WINDOWLOG_MAX)` -- **this file's bug, not `lib/zstd/`'s**: the real
//! zstd library computes the identical value correctly at
//! `zstd_decompress.c:1926` with `1U << ...`. `ZSTD_WINDOWLOG_MAX == 31` on
//! every 64-bit target this project builds, and the bare (signed) `1 << 31`
//! sets the sign bit; `header.windowSize > ZSTD_WINDOWSIZE_MAX` then
//! promotes that negative `int` to `unsigned long long` by sign-extending
//! first, landing on `0xffffffff80000000` (measured with a standalone C
//! program, not assumed).
//!
//! Independently adversarially reviewed (rusty-remote) with a correction to
//! this port's first read of it: it is not fully dead, and not exploitable.
//! Multi-segment frames never reach the comparison in a way that matters --
//! zstd's own internal cap already limits window size to 3.75 GiB there
//! regardless. Single-segment frames DO still get a check, just at this
//! wrong (far higher) threshold instead of the intended 2 GiB. The pre-boot
//! path (`decompress_single`, used by `arch/x86/boot/compressed/misc.c`)
//! never reaches this code at all -- it does no frame-header parsing.
//! Worst case on the streaming path (`init/initramfs.c`): a `vmalloc`
//! over-allocation (~1.75x, DoS-flavored) or a misleading "Out of memory"
//! message instead of "window too large" -- `zstd_decompress_module.c:107`
//! guards the null-workspace case, so no null-deref, and nothing here
//! corrupts data.
//!
//! Reproduced exactly (`1 << 31`'s actual sign-extended value, as a `u64`
//! constant, not `1u64 << 31`) rather than fixed: `logs/floor.md`'s
//! 2026-09-04 ruling is that a port may not be safer than the C it replaces
//! yet, and correcting this check would be a real behavioral divergence on
//! real initramfs input (GOALS.md §5) -- rejecting a window size the
//! original silently accepted. Flagged for Adam, not packaged: this is a
//! Linux-kernel-wrapper-local defect (upstream zstd itself is fine), so any
//! eventual report is scoped to this one file, not to zstd generally.
//!
//! One more thing nobody has reconciled, noted rather than fixed: this
//! file's own comments disagree with each other about this constant --
//! line 80 says "128MB," line 245 says "8MB," and the value the macro
//! actually computes (ignoring the bug above) is 2 GiB.
//!
//! Two more things adversarial review added on a second pass, neither a
//! live defect for this project (x86_64 only, one LTS pinned) but worth
//! recording since the frozen literal hides both: on a 32-bit kernel
//! `ZSTD_WINDOWLOG_MAX` is 30, so the C's `1 << 30` is `+0x40000000` --
//! POSITIVE, no sign extension, and the check works correctly there (fires
//! at 1 GiB); this port's constant, being 64-bit-only, would silently
//! accept everything on that arch instead. And the literal no longer
//! tracks `ZSTD_WINDOWLOG_MAX` symbolically -- if a future LTS changes
//! `ZSTD_WINDOWLOG_MAX_64`, the C's bug moves with it and this constant
//! does not, silently (same shape as the frozen-layout pins
//! `logs/c-entry-rule.md` describes).

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

/// `ZSTD_IOBUF_SIZE`, `lib/decompress_unzstd.c` -- `1 << 17`.
const ZSTD_IOBUF_SIZE: usize = 1 << 17;

/// See this file's module doc: the C's actual computed
/// `ZSTD_WINDOWSIZE_MAX`, integer-promotion defect included, not `1u64 <<
/// 31`.
const ZSTD_WINDOWSIZE_MAX: u64 = 0xffff_ffff_8000_0000;

const ZSTD_ERROR_MEMORY_ALLOCATION: c_uint = 64;
const ZSTD_ERROR_PREFIX_UNKNOWN: c_uint = 10;
const ZSTD_ERROR_DSTSIZE_TOOSMALL: c_uint = 70;
const ZSTD_ERROR_CORRUPTION_DETECTED: c_uint = 20;
const ZSTD_ERROR_CHECKSUM_WRONG: c_uint = 22;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

/// `zstd_dctx`/`zstd_dstream`, `include/linux/zstd.h` -- both alias
/// `ZSTD_DCtx` (`zstd_lib.h`: "DCtx and DStream are now effectively same
/// object"). Opaque; only ever passed through to the real `zstd_*` entry
/// points.
#[repr(C)]
struct ZstdDCtx {
    _private: [u8; 0],
}

/// `zstd_in_buffer` / `ZSTD_inBuffer_s`, `zstd_lib.h`.
#[repr(C)]
struct ZstdInBuffer {
    src: *const u8,
    size: usize,
    pos: usize,
}

/// `zstd_out_buffer` / `ZSTD_outBuffer_s`, `zstd_lib.h`.
#[repr(C)]
struct ZstdOutBuffer {
    dst: *mut u8,
    size: usize,
    pos: usize,
}

/// `zstd_frame_header` / `ZSTD_FrameHeader`, `zstd_lib.h`. Only
/// `window_size` is ever read here, but the whole layout has to match for
/// that field to land in the right place.
#[repr(C)]
struct ZstdFrameHeader {
    frame_content_size: u64,
    window_size: u64,
    block_size_max: c_uint,
    frame_type: c_int,
    header_size: c_uint,
    dict_id: c_uint,
    checksum_flag: c_uint,
    _reserved1: c_uint,
    _reserved2: c_uint,
}

extern "C" {
    /// `lib/decompress_unzstd.c`. Three lines: `return vmalloc(size);` --
    /// `vmalloc` itself has no linkable symbol.
    fn decompress_unzstd_alloc(size: c_ulong) -> *mut c_void;
    /// `mm/vmalloc.c`, `EXPORT_SYMBOL(vfree)`. Real out-of-line function.
    fn vfree(addr: *const c_void);

    /// `lib/zstd/zstd_decompress_module.c`. Real EXPORT_SYMBOLs; the
    /// decoder behind them is still C (see module doc).
    fn zstd_is_error(code: usize) -> c_uint;
    fn zstd_get_error_code(code: usize) -> c_uint;
    fn zstd_dctx_workspace_bound() -> usize;
    fn zstd_init_dctx(workspace: *mut c_void, workspace_size: usize) -> *mut ZstdDCtx;
    fn zstd_find_frame_compressed_size(src: *const c_void, src_size: usize) -> usize;
    fn zstd_decompress_dctx(
        dctx: *mut ZstdDCtx,
        dst: *mut c_void,
        dst_capacity: usize,
        src: *const c_void,
        src_size: usize,
    ) -> usize;
    fn zstd_dstream_workspace_bound(max_window_size: usize) -> usize;
    fn zstd_init_dstream(
        max_window_size: usize,
        workspace: *mut c_void,
        workspace_size: usize,
    ) -> *mut ZstdDCtx;
    fn zstd_get_frame_header(params: *mut ZstdFrameHeader, src: *const c_void, src_size: usize) -> usize;
    fn zstd_decompress_stream(
        dstream: *mut ZstdDCtx,
        output: *mut ZstdOutBuffer,
        input: *mut ZstdInBuffer,
    ) -> usize;
}

/// `handle_zstd_error()`, `lib/decompress_unzstd.c`.
unsafe fn handle_zstd_error(ret: usize, call_error: &dyn Fn(&[u8])) -> i32 {
    if unsafe { zstd_is_error(ret) } == 0 {
        return 0;
    }
    let err = unsafe { zstd_get_error_code(ret) };
    match err {
        ZSTD_ERROR_MEMORY_ALLOCATION => call_error(b"ZSTD decompressor ran out of memory\0"),
        ZSTD_ERROR_PREFIX_UNKNOWN => {
            call_error(b"Input is not in the ZSTD format (wrong magic bytes)\0")
        }
        ZSTD_ERROR_DSTSIZE_TOOSMALL | ZSTD_ERROR_CORRUPTION_DETECTED | ZSTD_ERROR_CHECKSUM_WRONG => {
            call_error(b"ZSTD-compressed data is corrupt\0")
        }
        _ => call_error(b"ZSTD-compressed data is probably corrupt\0"),
    }
    -1
}

/// `decompress_single()`, `lib/decompress_unzstd.c`.
unsafe fn decompress_single(
    in_buf: *const u8,
    in_len: c_long,
    out_buf: *mut u8,
    out_len: c_long,
    in_pos: *mut c_long,
    call_error: &dyn Fn(&[u8]),
) -> i32 {
    let wksp_size = unsafe { zstd_dctx_workspace_bound() };
    let wksp = unsafe { decompress_unzstd_alloc(wksp_size as c_ulong) };
    let err: i32 = 'body: {
        if wksp.is_null() {
            call_error(b"Out of memory while allocating zstd_dctx\0");
            break 'body -1;
        }
        let dctx = unsafe { zstd_init_dctx(wksp, wksp_size) };
        if dctx.is_null() {
            call_error(b"Out of memory while allocating zstd_dctx\0");
            break 'body -1;
        }

        let ret = unsafe {
            zstd_find_frame_compressed_size(in_buf as *const c_void, in_len as usize)
        };
        let err = unsafe { handle_zstd_error(ret, call_error) };
        if err != 0 {
            break 'body err;
        }
        let in_len = ret as c_long;

        let ret = unsafe {
            zstd_decompress_dctx(
                dctx,
                out_buf as *mut c_void,
                out_len as usize,
                in_buf as *const c_void,
                in_len as usize,
            )
        };
        let err = unsafe { handle_zstd_error(ret, call_error) };
        if err != 0 {
            break 'body err;
        }

        if !in_pos.is_null() {
            unsafe { *in_pos = in_len };
        }
        0
    };
    if !wksp.is_null() {
        unsafe { vfree(wksp as *const c_void) };
    }
    err
}

/// `__unzstd()`, `lib/decompress_unzstd.c`.
unsafe fn __unzstd(
    in_buf_param: *mut u8,
    in_len_param: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out_buf_param: *mut u8,
    out_len_param: c_long,
    in_pos: *mut c_long,
    error: Option<ErrorFn>,
) -> i32 {
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    let out_len = if out_len_param == 0 {
        (u64::MAX - out_buf_param as u64) as c_long
    } else {
        out_len_param
    };

    if fill.is_none() && flush.is_none() {
        return unsafe {
            decompress_single(in_buf_param, in_len_param, out_buf_param, out_len, in_pos, &call_error)
        };
    }

    let mut in_allocated: *mut c_void = core::ptr::null_mut();
    let mut out_allocated: *mut c_void = core::ptr::null_mut();
    let mut wksp: *mut c_void = core::ptr::null_mut();

    let err: i32 = 'body: {
        let mut in_buf = in_buf_param;
        let mut in_len = in_len_param;
        let mut out_buf = out_buf_param;
        let mut out_len = out_len;

        if in_buf.is_null() {
            in_allocated = unsafe { decompress_unzstd_alloc(ZSTD_IOBUF_SIZE as c_ulong) };
            if in_allocated.is_null() {
                call_error(b"Out of memory while allocating input buffer\0");
                break 'body -1;
            }
            in_buf = in_allocated as *mut u8;
            in_len = 0;
        }
        if let Some(f) = fill {
            in_len = unsafe { f(in_buf as *mut c_void, ZSTD_IOBUF_SIZE as c_ulong) };
        }
        if in_len < 0 {
            call_error(b"ZSTD-compressed data is truncated\0");
            break 'body -1;
        }

        let mut input = ZstdInBuffer {
            src: in_buf,
            size: in_len as usize,
            pos: 0,
        };

        if flush.is_some() {
            out_allocated = unsafe { decompress_unzstd_alloc(ZSTD_IOBUF_SIZE as c_ulong) };
            if out_allocated.is_null() {
                call_error(b"Out of memory while allocating output buffer\0");
                break 'body -1;
            }
            out_buf = out_allocated as *mut u8;
            out_len = ZSTD_IOBUF_SIZE as c_long;
        }
        let mut output = ZstdOutBuffer {
            dst: out_buf,
            size: out_len as usize,
            pos: 0,
        };

        let mut header = ZstdFrameHeader {
            frame_content_size: 0,
            window_size: 0,
            block_size_max: 0,
            frame_type: 0,
            header_size: 0,
            dict_id: 0,
            checksum_flag: 0,
            _reserved1: 0,
            _reserved2: 0,
        };
        let ret = unsafe {
            zstd_get_frame_header(&mut header, input.src as *const c_void, input.size)
        };
        let err = unsafe { handle_zstd_error(ret, &call_error) };
        if err != 0 {
            break 'body err;
        }
        if ret != 0 {
            call_error(b"ZSTD-compressed data has an incomplete frame header\0");
            break 'body -1;
        }
        if header.window_size > ZSTD_WINDOWSIZE_MAX {
            call_error(b"ZSTD-compressed data has too large a window size\0");
            break 'body -1;
        }

        let wksp_size = unsafe { zstd_dstream_workspace_bound(header.window_size as usize) };
        wksp = unsafe { decompress_unzstd_alloc(wksp_size as c_ulong) };
        let dstream = if wksp.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { zstd_init_dstream(header.window_size as usize, wksp, wksp_size) }
        };
        if dstream.is_null() {
            call_error(b"Out of memory while allocating ZSTD_DStream\0");
            break 'body -1;
        }

        if !in_pos.is_null() {
            unsafe { *in_pos = 0 };
        }
        let mut ret: usize;
        loop {
            if input.pos == input.size {
                // *in_pos += input.pos accumulates across every fill/flush
                // loop iteration; the C's `long` is signed, so an overflow
                // here is UB in C too, not a defined wraparound to preserve
                // -- but reaching it needs exabyte-scale total input in one
                // call, via a caller-configured per-chunk buffer size, not a
                // stream-embedded length field. wrapping_add matches what
                // the C actually compiles to on this target (a plain add)
                // rather than panicking on an overflow neither arm can
                // realistically hit. Found by the CONFIG_RUST_OVERFLOW_CHECKS
                // panic-symbol sweep, 2026-09-06 -- same shape as
                // decompress_unxz_rs.rs's identical *in_used pattern.
                if !in_pos.is_null() {
                    unsafe { *in_pos = (*in_pos).wrapping_add(input.pos as c_long) };
                }
                let got = match fill {
                    Some(f) => unsafe { f(in_buf as *mut c_void, ZSTD_IOBUF_SIZE as c_ulong) },
                    None => -1,
                };
                if got < 0 {
                    call_error(b"ZSTD-compressed data is truncated\0");
                    break 'body -1;
                }
                input.pos = 0;
                input.size = got as usize;
            }

            ret = unsafe { zstd_decompress_stream(dstream, &mut output, &mut input) };
            let err = unsafe { handle_zstd_error(ret, &call_error) };
            if err != 0 {
                break 'body err;
            }
            if let Some(f) = flush {
                if output.pos > 0 {
                    if unsafe { f(output.dst as *mut c_void, output.pos as c_ulong) }
                        != output.pos as c_long
                    {
                        call_error(b"Failed to flush()\0");
                        break 'body -1;
                    }
                    output.pos = 0;
                }
            }
            if ret == 0 {
                break;
            }
        }

        if !in_pos.is_null() {
            unsafe { *in_pos = (*in_pos).wrapping_add(input.pos as c_long) };
        }
        0
    };

    if !in_allocated.is_null() {
        unsafe { vfree(in_allocated as *const c_void) };
    }
    if !out_allocated.is_null() {
        unsafe { vfree(out_allocated as *const c_void) };
    }
    if !wksp.is_null() {
        unsafe { vfree(wksp as *const c_void) };
    }
    err
}

/// `unzstd()`, `lib/decompress_unzstd.c`. The dispatcher's `.decompressor`
/// entry for the `"zstd"` magic (`\x28\xb5`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn unzstd(
    buf: *mut u8,
    len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out_buf: *mut u8,
    pos: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    unsafe { __unzstd(buf, len, fill, flush, out_buf, 0, pos, error) }
}

/// The pre-boot entry, `__decompress()`'s call into the driver
/// (`lib/decompress_unzstd.c`, `UNZSTD_PREBOOT` arm): the same `__unzstd()`
/// but with the caller's real `out_len` (`unzstd()` always passes 0). Built
/// only for the x86 boot stub (`--cfg=boot_driver`, arch/x86/boot/compressed/
/// Makefile), so the running kernel's object is unchanged.
#[cfg(boot_driver)]
#[no_mangle]
pub unsafe extern "C" fn unzstd_boot(
    buf: *mut u8,
    len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out_buf: *mut u8,
    out_len: c_long,
    pos: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    unsafe { __unzstd(buf, len, fill, flush, out_buf, out_len, pos, error) }
}
