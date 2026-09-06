// SPDX-License-Identifier: GPL-2.0

//! The gzip stream driver -- Rust behind `lib/decompress_inflate.c`'s
//! `gunzip()` (the non-`PREBOOT` arm only).
//!
//! # UNLIKE EVERY OTHER FILE IN THIS FAMILY: `lib/decompress_inflate.c`
//! # ITSELF IS LEFT COMPLETELY UNTOUCHED, BYTE-IDENTICAL TO UPSTREAM
//!
//! Every other port in this family (bunzip2/unlz4/unlzo/unxz/unzstd)
//! replaces its `lib/decompress_*.c` file outright, because each one's
//! `#ifdef STATIC` / preboot arm is dead code in this project: `arch/x86/
//! boot/compressed/misc.c` textually `#include`s each one under its own
//! `#ifdef CONFIG_KERNEL_<FORMAT>`, and this project's configs only ever
//! set `CONFIG_KERNEL_GZIP=y` -- so `CONFIG_KERNEL_BZIP2`/`_XZ`/`_LZO`/
//! `_LZ4`/`_ZSTD` never fire and those five files' STATIC arms are never
//! compiled by anything. **`CONFIG_KERNEL_GZIP` is the one that DOES
//! fire.** `misc.c` really does `#include "../../../../lib/
//! decompress_inflate.c"` with `STATIC` defined, and that inclusion
//! becomes the kernel image's own pre-boot self-decompression stub
//! (`__decompress()`, at the bottom of that file) -- genuinely live,
//! genuinely load-bearing, on every boot this project does, before Rust
//! (or anything else) has even started. An earlier version of this port
//! got this backwards: it overwrote `decompress_inflate.c` the same way
//! the other five overwrite theirs, which silently deleted the pre-boot
//! decompressor and broke `arch/x86/boot/compressed/misc.o` with
//! `error: call to undeclared function '__decompress'` -- caught by the
//! build, not by reasoning about it in advance, which is exactly why this
//! paragraph exists now.
//!
//! So `lib/decompress_inflate.c` stays pristine (verified byte-identical
//! against `port/pristine/lib/decompress_inflate.c`), preserving
//! `__decompress()` for the preboot textual include AND its own
//! `gunzip()` for the (unused in the Rust-enabled build, but still
//! correct) `CONFIG_RUST=n` fallback arm. This is the SAME convention
//! `lib/zstd/`'s Makefile already documents for exactly this reason
//! ("NEITHER ARM DELETES A FILE FROM THE TREE... lib/decompress_inflate.c
//! textually #includes inftrees.c, inffast.c and inflate.c under #ifdef
//! STATIC, and both of this project's configs set CONFIG_KERNEL_GZIP, so
//! those copies ARE compiled... in BOTH arms") -- `zlib_inflate/{inftrees,
//! inffast,inflate}.c` are the OTHER files that textual include reaches,
//! and they already follow it: `inflate.c` keeps the upstream body (plus
//! one deliberate security hunk, per its own header) with a separate
//! `inflate_thunk.c` carrying the Rust-calling entry points beside it,
//! never inside it.
//!
//! `gunzip()` has no `EXPORT_SYMBOL`, unlike `inflate_thunk.c`'s six entry
//! points, so there is no MODVERSIONS CRC forcing a C-entry/Rust-body
//! thunk shape here -- this file defines `gunzip()` directly, under its
//! own name, the `lib/union_find` shape (same reasoning
//! `decompress/huf_decompress_rs.rs` uses for the nine HUF symbols
//! nothing exports). The Makefile's `CONFIG_RUST` arm simply does not
//! compile `decompress_inflate.o` at all -- this file's `gunzip()` is the
//! only definition of that symbol when `CONFIG_RUST=y` -- and does compile
//! it, unmodified, when `CONFIG_RUST=n`.
//!
//! # THE ONE FILE IN THIS FAMILY THAT IS CLASS B, NOT CLASS A
//!
//! `gunzip()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` table (magic `\x1f\x8b`/`\x1f\x9e`), same as every
//! other file in this family -- but unlike bunzip2/unlz4/unlzo/unxz/unzstd,
//! this project's OWN initramfs really is gzip (`rig/boot.sh` pipes the
//! cpio archive through `gzip -9`), and `init/initramfs.c`'s only call to
//! `decompress()` is the sole caller of anything in `lib/decompress.c`
//! anywhere in this tree (checked: `grep -rn '\bdecompress(' --include=*.c`
//! finds nothing else calling the dispatcher this family belongs to). So
//! this port's correctness is proven primarily by every boot this project
//! already does, not by a bespoke libtest self-test the way the other five
//! are -- `test_gunzip()` in libtest.c is added anyway, for the same
//! "verify, don't rely solely on incidental coverage" reason PRIOR-ART.md
//! warns about, but it is not the reachability proof here; the boot log's
//! own successful gzip'd-initramfs unpack is.
//!
//! `init/initramfs.c:551` calls `decompress(buf, len, NULL, flush_buffer,
//! NULL, &pos, error)` -- `fill == NULL`, `flush` set. That means the ONLY
//! shape actually exercised in this tree is the streaming/flush branch
//! below; the buffer-mode (`flush == NULL`) branch and the `fill == NULL`
//! `nofill()` fallback are real, faithfully-ported code paths with no live
//! caller in this tree at all (same as this whole family's PREBOOT arm,
//! though for a different reason -- there it's a separate compiled-out
//! translation unit, here it's simply an argument combination nothing
//! passes). Ported in full regardless: GOALS.md's C-is-a-reference boundary
//! doesn't shrink to "whatever today's one caller happens to use."
//!
//! # `kmalloc` stays in C, `kfree` doesn't -- in a THIRD file
//!
//! Same mechanism as `decompress_bunzip2_rs.rs`/`decompress_unxz_rs.rs`:
//! `kmalloc` is a macro with no linkable symbol, so a tiny C wrapper,
//! `decompress_inflate_alloc`, is needed. It lives in
//! `decompress_inflate_alloc.c`, a NEW file -- not in
//! `decompress_inflate.c`, which (see above) must stay byte-identical to
//! upstream. `kfree` is a real `EXPORT_SYMBOL` and is called directly from
//! here. Its `size` parameter is `c_ulong`, matching kmalloc's own
//! parameter type -- found by adversarial review reproducing the exact
//! same 32-bit-narrowing shape `decompress_unzstd_alloc()` had before its
//! own fix; not live here (every caller passes a small, fixed-shape
//! value), but the same unsound interface. A second tiny C helper in that
//! same new file, `decompress_inflate_state_size()`, exists for one
//! reason: the single-call workspace-size branch below needs `sizeof(
//! struct inflate_state)`, and that struct's tail (`lens`/`work`/
//! `codes[ENOUGH]`, `ENOUGH` computed from `inftrees.h`) is internal to
//! `zlib_inflate/` on purpose -- hand-duplicating its layout in Rust just to
//! compute one number would be a second, driftable copy of a struct this
//! file has no other reason to know the shape of. See that helper's own
//! comment.
//!
//! # The alloc-failure cascade, translated as independent ownership checks
//!
//! The C is FOUR chained `goto`s into a shared cleanup tail that falls
//! through label by label (`gunzip_5` falls into `gunzip_nomem4` falls into
//! `gunzip_nomem3` falls into `gunzip_nomem2` falls into `gunzip_nomem1`),
//! so which frees actually run depends on which label was jumped to --
//! structurally the "staged/cascading" shape `decompress_unlz4_rs.rs`'s
//! module doc describes. It is translated here the way
//! `decompress_unzstd_rs.rs`'s `__unzstd()` translates its own (differently
//! caused) multi-buffer cleanup: one labelled block whose `break` values are
//! plain `-1` literals (matching `rc`'s value at every point C can `goto`
//! from, since C never changes `rc` away from its initial `-1` before the
//! first point past all four allocations), followed by four independent
//! null/ownership checks that -- because each one matches exactly the
//! condition under which the C actually OWNS that resource (see each
//! variable's own comment below) -- reproduce every `goto` target's exact
//! effective behavior without needing to track "which label" at all.
//!
//! # A detail preserved exactly, not normalized: which error path sets `*pos`
//!
//! Of the two `goto`s that fire before the main loop, only the first ("Not a
//! gzip file") sets `*pos = 0`. The second (the asciz-filename-skip running
//! past `avail_in`, "header error") does not touch `*pos` at all, leaving it
//! whatever the caller initialized it to. This looks like an oversight, and
//! it is kept exactly as upstream has it rather than "fixed" to match the
//! first -- GOALS.md's C-is-a-reference boundary is about behavior on real
//! input, and unifying the two would be exactly that kind of silent
//! divergence, however small.
//!
//! # `CONFIG_ZLIB_DFLTCC`: ported, not dropped -- added after adversarial
//! # review found an earlier version silently took the wrong arm
//!
//! The C forks on this symbol (`depends on S390`, `lib/Kconfig:195`) in two
//! places: the single-call (`flush == NULL`) workspace-size expression
//! (full `zlib_inflate_workspacesize()` under DFLTCC, vs. the smaller
//! `sizeof(struct inflate_state)` otherwise -- DFLTCC has no smaller
//! single-call layout to allocate instead), and the post-`zlib_inflateInit2`
//! wsize/window reset (skipped entirely under DFLTCC, which always keeps
//! the window). Both are `#[cfg(CONFIG_ZLIB_DFLTCC)]`/`#[cfg(not(...))]`
//! branches here now, matching `lib/zlib_inflate/inflate_rs.rs`'s own
//! DFLTCC hooks -- see `logs/build-limits.md`'s entry on that symbol for
//! why they're ported despite s390 not selecting `HAVE_RUST` (so neither
//! arm here can actually be *exercised*, only compiled): "it was ported
//! anyway because leaving it out would break s390 silently," the same
//! reasoning applies to this file. `port/test/decompress_inflate/run.sh`
//! carries the matching compiles-with-and-without-the-cfg sweep
//! `port/test/zlib_inflate/run.sh` already does for `inflate_rs.rs`.
//!
//! # `Z_OK`/`Z_STREAM_END`/`Z_NO_FLUSH` only
//!
//! No other `Z_*` return code is ever compared against by name in this file
//! -- everything else collapses to the generic "uncompression error" -> -1
//! path, so only these three are defined here rather than the full zlib
//! error enum.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

/// `GZIP_IOBUF_SIZE`, `lib/decompress_inflate.c` -- `16 * 1024`.
const GZIP_IOBUF_SIZE: usize = 16 * 1024;

/// `MAX_WBITS`, `include/linux/zconf.h` -- `15` (32K window). Passed
/// negated to `zlib_inflateInit2()` for raw-deflate mode, since the gzip
/// header/trailer are handled by this file, not zlib's own gzip support.
const MAX_WBITS: c_int = 15;

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NO_FLUSH: c_int = 0;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

/// `struct z_stream_s` / `z_stream`, `include/linux/zlib.h`. `Byte = u8`,
/// `uLong = c_ulong` (both from `include/linux/zconf.h`).
#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: c_ulong,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: c_ulong,
    total_out: c_ulong,
    msg: *mut c_char,
    state: *mut c_void,
    workspace: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

/// The head of `struct inflate_workspace` (`lib/zlib_inflate/infutil.h`) up
/// through the two fields this file ever touches -- `wsize`/`window`, at the
/// same offsets `WS(strm)->inflate_state.wsize`/`.window` resolve to, since
/// `inflate_state` is `inflate_workspace`'s first member (offset 0). Every
/// field before them must match `struct inflate_state`
/// (`lib/zlib_inflate/inflate.h`) exactly in type and order; nothing after
/// `window` is ever read or written through this view, so nothing after it
/// is declared.
#[repr(C)]
#[cfg(not(CONFIG_ZLIB_DFLTCC))]
struct InflateStateHead {
    mode: c_int,
    last: c_int,
    wrap: c_int,
    havedict: c_int,
    flags: c_int,
    dmax: core::ffi::c_uint,
    check: c_ulong,
    total: c_ulong,
    wbits: core::ffi::c_uint,
    wsize: core::ffi::c_uint,
    whave: core::ffi::c_uint,
    write: core::ffi::c_uint,
    window: *mut u8,
}

extern "C" {
    /// `lib/decompress_inflate_alloc.c`. Three lines: `return
    /// kmalloc(size, GFP_KERNEL);` -- `kmalloc` itself has no linkable
    /// symbol.
    fn decompress_inflate_alloc(size: c_ulong) -> *mut c_void;
    /// `lib/decompress_inflate_alloc.c`. `return sizeof(struct
    /// inflate_state);` -- see this file's module doc. Only used in the
    /// non-DFLTCC arm, which has a smaller single-call workspace size;
    /// DFLTCC always allocates the full `zlib_inflate_workspacesize()`.
    #[cfg(not(CONFIG_ZLIB_DFLTCC))]
    fn decompress_inflate_state_size() -> c_ulong;
    /// `mm/slub.c`, `EXPORT_SYMBOL(kfree)`. Real out-of-line function.
    fn kfree(objp: *const c_void);
    /// `lib/zlib_inflate/inflate_thunk.c`. Real C entry symbol, Rust body
    /// in `lib/zlib_inflate/inflate_rs.rs`.
    fn zlib_inflate_workspacesize() -> c_int;
    fn zlib_inflateInit2(strm: *mut ZStream, window_bits: c_int) -> c_int;
    fn zlib_inflate(strm: *mut ZStream, flush: c_int) -> c_int;
    fn zlib_inflateEnd(strm: *mut ZStream) -> c_int;
}

/// `nofill()`, `lib/decompress_inflate.c`. Used only when the caller
/// supplies neither `buf` (a ready input buffer) nor `fill` -- has no live
/// caller in this tree (see module doc) but is a real fallback value stored
/// through the same function-pointer type `fill` itself uses, so it must
/// share `FillFn`'s exact signature.
unsafe extern "C" fn nofill(_buffer: *mut c_void, _len: c_ulong) -> c_long {
    -1
}

/// `__gunzip()`, `lib/decompress_inflate.c`.
unsafe fn __gunzip(
    buf: *mut u8,
    len_param: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out_buf_param: *mut u8,
    out_len_param: c_long,
    pos: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    let mut out_buf = out_buf_param;
    let mut out_len = out_len_param;
    // Non-null only when THIS call allocated the output buffer (`flush`
    // was set) -- matches `if (flush) free(out_buf);` (`gunzip_nomem2`)
    // exactly: that free is conditioned on `flush`, not on `out_buf`'s
    // null-ness, because when `flush` is unset `out_buf` is always the
    // caller's own pointer (or a caller-owned region reached via the
    // `~0 - out_buf` computation below), never ours to free.
    let mut out_owned: *mut c_void = core::ptr::null_mut();

    let mut zbuf: *mut u8 = buf;
    let mut len = len_param;
    // Non-null only when THIS call allocated the input buffer (the caller
    // passed `buf == NULL`) -- matches `if (!buf) free(zbuf);`
    // (`gunzip_nomem3`) exactly, same reasoning as `out_owned`.
    let mut zbuf_owned: *mut c_void = core::ptr::null_mut();

    let mut strm: *mut ZStream = core::ptr::null_mut();
    let mut workspace: *mut c_void = core::ptr::null_mut();

    let rc: c_int = 'body: {
        if flush.is_some() {
            out_len = 0x8000; /* 32K */
            out_owned = unsafe { decompress_inflate_alloc(out_len as c_ulong) };
            out_buf = out_owned as *mut u8;
        } else if out_len == 0 {
            out_len = (usize::MAX - out_buf as usize) as c_long; /* no limit */
        }
        if out_buf.is_null() {
            call_error(b"Out of memory while allocating output buffer\0");
            break 'body -1;
        }

        if zbuf.is_null() {
            zbuf_owned = unsafe { decompress_inflate_alloc(GZIP_IOBUF_SIZE as c_ulong) };
            zbuf = zbuf_owned as *mut u8;
            len = 0;
        }
        if zbuf.is_null() {
            call_error(b"Out of memory while allocating input buffer\0");
            break 'body -1;
        }

        strm = unsafe { decompress_inflate_alloc(core::mem::size_of::<ZStream>() as c_ulong) }
            as *mut ZStream;
        if strm.is_null() {
            call_error(b"Out of memory while allocating z_stream\0");
            break 'body -1;
        }

        // Under CONFIG_ZLIB_DFLTCC (s390 only), the !flush branch also
        // allocates the FULL zlib_inflate_workspacesize(), same as the
        // flush branch -- DFLTCC always keeps the window, so there is no
        // smaller single-call size to allocate instead. Found by
        // adversarial review: an earlier version took the non-DFLTCC arm
        // unconditionally, silently, which would under-allocate on the one
        // arch this actually applies to. inflate_rs.rs already carries the
        // equivalent DFLTCC hooks under this same #[cfg] for the identical
        // reason (logs/build-limits.md).
        #[cfg(CONFIG_ZLIB_DFLTCC)]
        let workspace_size: c_ulong = unsafe { zlib_inflate_workspacesize() as c_ulong };
        #[cfg(not(CONFIG_ZLIB_DFLTCC))]
        let workspace_size: c_ulong = if flush.is_some() {
            unsafe { zlib_inflate_workspacesize() as c_ulong }
        } else {
            unsafe { decompress_inflate_state_size() as c_ulong }
        };
        workspace = unsafe { decompress_inflate_alloc(workspace_size) };
        unsafe { (*strm).workspace = workspace };
        if workspace.is_null() {
            call_error(b"Out of memory while allocating workspace\0");
            break 'body -1;
        }

        let fill = fill.unwrap_or(nofill);

        if len == 0 {
            len = unsafe { fill(zbuf as *mut c_void, GZIP_IOBUF_SIZE as c_ulong) };
        }

        /* verify the gzip header */
        if len < 10
            || unsafe { *zbuf } != 0x1f
            || unsafe { *zbuf.add(1) } != 0x8b
            || unsafe { *zbuf.add(2) } != 0x08
        {
            if !pos.is_null() {
                unsafe { *pos = 0 };
            }
            call_error(b"Not a gzip file\0");
            break 'body -1;
        }

        /* skip over gzip header (1f,8b,08... 10 bytes total +
         * possible asciz filename) */
        unsafe {
            (*strm).next_in = zbuf.add(10);
            (*strm).avail_in = (len - 10) as c_ulong;
        }
        /* skip over asciz filename */
        if unsafe { *zbuf.add(3) } & 0x8 != 0 {
            loop {
                /*
                 * If the filename doesn't fit into the buffer, the file is
                 * very probably corrupt. Don't try to read more data.
                 */
                if unsafe { (*strm).avail_in } == 0 {
                    call_error(b"header error\0");
                    break 'body -1; /* does NOT set *pos -- see module doc */
                }
                unsafe { (*strm).avail_in -= 1 };
                let b = unsafe { *(*strm).next_in };
                unsafe { (*strm).next_in = (*strm).next_in.add(1) };
                if b == 0 {
                    break;
                }
            }
        }

        unsafe {
            (*strm).next_out = out_buf;
            (*strm).avail_out = out_len as c_ulong;
        }

        let mut rc = unsafe { zlib_inflateInit2(strm, -MAX_WBITS) };

        // Under CONFIG_ZLIB_DFLTCC, the window is ALWAYS kept (DFLTCC
        // requires it) -- this reset must not run at all there, matching
        // the C's own `#ifdef CONFIG_ZLIB_DFLTCC /* Always keep the window
        // for DFLTCC */ #else if (!flush) { ... } #endif`.
        #[cfg(not(CONFIG_ZLIB_DFLTCC))]
        if flush.is_none() {
            let head = workspace as *mut InflateStateHead;
            unsafe {
                (*head).wsize = 0;
                (*head).window = core::ptr::null_mut();
            }
        }

        while rc == Z_OK {
            if unsafe { (*strm).avail_in } == 0 {
                /* TODO: handle case where both pos and fill are set */
                len = unsafe { fill(zbuf as *mut c_void, GZIP_IOBUF_SIZE as c_ulong) };
                if len < 0 {
                    rc = -1;
                    call_error(b"read error\0");
                    break;
                }
                unsafe {
                    (*strm).next_in = zbuf;
                    (*strm).avail_in = len as c_ulong;
                }
            }
            rc = unsafe { zlib_inflate(strm, Z_NO_FLUSH) };

            /* Write any data generated */
            if let Some(f) = flush {
                let next_out = unsafe { (*strm).next_out };
                if (next_out as usize) > (out_buf as usize) {
                    let l = next_out as usize - out_buf as usize;
                    if unsafe { f(out_buf as *mut c_void, l as c_ulong) } != l as c_long {
                        rc = -1;
                        call_error(b"write error\0");
                        break;
                    }
                    unsafe {
                        (*strm).next_out = out_buf;
                        (*strm).avail_out = out_len as c_ulong;
                    }
                }
            }

            /* after Z_FINISH, only Z_STREAM_END is "we unpacked it all" */
            if rc == Z_STREAM_END {
                rc = 0;
                break;
            } else if rc != Z_OK {
                call_error(b"uncompression error\0");
                rc = -1;
            }
        }

        unsafe { zlib_inflateEnd(strm) };
        if !pos.is_null() {
            /* add + 8 to skip over trailer */
            // The pointer difference is bounded by real allocated buffer
            // sizes (never remotely near c_long::MAX), so this can't
            // overflow in practice; LLVM can't see that bound through
            // offset_from(), so wrapping_add matches the C's own plain `+ 8`
            // instead of a panic on an unreachable path. Found by the
            // CONFIG_RUST_OVERFLOW_CHECKS panic-symbol sweep, 2026-09-06.
            unsafe {
                *pos = ((*strm).next_in.offset_from(zbuf) as c_long).wrapping_add(8);
            }
        }

        rc
    };

    if !workspace.is_null() {
        unsafe { kfree(workspace as *const c_void) };
    }
    if !strm.is_null() {
        unsafe { kfree(strm as *const c_void) };
    }
    if !zbuf_owned.is_null() {
        unsafe { kfree(zbuf_owned as *const c_void) };
    }
    if !out_owned.is_null() {
        unsafe { kfree(out_owned as *const c_void) };
    }
    rc
}

/// `gunzip()`, `lib/decompress_inflate.c`. The dispatcher's `.decompressor`
/// entry for the `"gzip"` magic (`\x1f\x8b` / `\x1f\x9e`) -- this project's
/// own initramfs format (see module doc).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn gunzip(
    buf: *mut u8,
    len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    out_buf: *mut u8,
    pos: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    unsafe { __gunzip(buf, len, fill, flush, out_buf, 0, pos, error) }
}
