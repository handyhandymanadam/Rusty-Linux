// SPDX-License-Identifier: GPL-2.0-only

//! The LZ4 archive-chunk wrapper -- Rust behind `lib/decompress_unlz4.c`.
//!
//! Replaces: lib/decompress_unlz4.c (the non-`PREBOOT` arm only -- see
//! `decompress_bunzip2_rs.rs`'s module doc for why the pre-boot arm is out
//! of scope for every file in this family: a separate freestanding
//! translation unit neither of this project's builds compiles).
//!
//! `unlz4()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` table and is not `EXPORT_SYMBOL`'d, so this is a
//! full replacement, same shape as `decompress_bunzip2_rs.rs`.
//!
//! # This calls Rust, not C, and the C never notices
//!
//! The one substantive call in this wrapper, `LZ4_decompress_safe()`, is
//! `lib/lz4/lz4_decompress_rs.rs`'s own `#[no_mangle] extern "C" fn` --
//! already a full Rust port. Declaring it `extern "C"` here and letting the
//! linker resolve it is exactly what the C wrapper it replaces already did;
//! nothing about that call had to change.
//!
//! # `vmalloc` stays in C, `vfree` doesn't
//!
//! `large_malloc`/`large_free` are `vmalloc`/`vfree` under `mm.h`'s non-
//! `STATIC` arm. `vmalloc` is a macro over `alloc_hooks(vmalloc_noprof(...))`
//! since 6.10's allocation profiling and has no linkable symbol, so
//! `decompress_unlz4.c` (this port's C half) keeps a three-line wrapper,
//! `decompress_unlz4_alloc`. `vfree` is a real `EXPORT_SYMBOL` and is called
//! directly from here, same split every other file in this family uses.
//!
//! # The goto-cascade becomes two blocks, not a state machine
//!
//! Every `goto` here jumps FORWARD to one of four fall-through cleanup
//! labels (`exit_3` sets `ret = 0` then falls into `exit_2`, which frees
//! the input buffer if this function owns it and falls into `exit_1`,
//! which frees the output buffer if this function owns it and falls into
//! `exit_0`, which returns) -- unlike `decompress_bunzip2.c`'s labels, none
//! of these are ever jumped to from below or from outside a loop. That
//! makes the translation direct: the three earliest error returns (before
//! either buffer's ownership is fully decided) each inline their own
//! partial cleanup, and everything from "input buffer chosen" onward is one
//! labelled block ([`'body`]) whose `break` value is `ret`, followed by the
//! two cleanups written once, unconditionally, exactly as the C's
//! fall-through does.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

const LZ4_DEFAULT_UNCOMPRESSED_CHUNK_SIZE: usize = 8 << 20;
const ARCHIVE_MAGICNUMBER: u32 = 0x184C2102;
const LZ4_MAX_INPUT_SIZE: u32 = 0x7E00_0000;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

extern "C" {
    /// `lib/decompress_unlz4.c`. Three lines: `return vmalloc(size);` --
    /// `vmalloc` itself has no linkable symbol.
    fn decompress_unlz4_alloc(size: c_uint) -> *mut c_void;
    /// `mm/vmalloc.c`, `EXPORT_SYMBOL(vfree)`. Real out-of-line function.
    fn vfree(addr: *const c_void);
    /// `lib/lz4/lz4_decompress_rs.rs`. Already Rust; called exactly as the
    /// C wrapper this replaces already called it.
    #[cfg(not(boot_preboot))]
    fn LZ4_decompress_safe(
        source: *const c_char,
        dest: *mut c_char,
        compressed_size: c_int,
        max_decompressed_size: c_int,
    ) -> c_int;
}

// RUSTY-LINUX preboot: `--cfg boot_preboot` (set only by
// arch/x86/boot/compressed/Makefile for the boot stub) selects the C
// `#ifdef PREBOOT` arm of unlz4(), which calls LZ4_decompress_fast() and not
// LZ4_decompress_safe(). So LZ4_decompress_safe is cfg'd out above and not
// referenced, and the stub link does not need it. The kernel build never sets
// the cfg and is unchanged.
#[cfg(boot_preboot)]
extern "C" {
    /// `lib/lz4/lz4_decompress_rs.rs`, built for the stub.
    fn LZ4_decompress_fast(source: *const c_char, dest: *mut c_char, original_size: c_int)
        -> c_int;
}

/// `LZ4_COMPRESSBOUND()`, `include/linux/lz4.h` -- a `static inline` with no
/// linkable symbol, so the two-line formula is reproduced rather than
/// declared `extern`.
fn lz4_compress_bound(isize_: usize) -> u32 {
    if isize_ as u64 > LZ4_MAX_INPUT_SIZE as u64 {
        0
    } else {
        (isize_ + isize_ / 255 + 16) as u32
    }
}

/// `get_unaligned_le32()`, `include/linux/unaligned.h`: a little-endian
/// 32-bit read with no alignment requirement on `p`.
unsafe fn get_unaligned_le32(p: *const u8) -> u32 {
    let mut bytes = [0u8; 4];
    unsafe { core::ptr::copy_nonoverlapping(p, bytes.as_mut_ptr(), 4) };
    u32::from_le_bytes(bytes)
}

/// `unlz4()`, `lib/decompress_unlz4.c`. The dispatcher's `.decompressor`
/// entry for the `"lz4"` magic (`\x02\x21`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn unlz4(
    input: *mut u8,
    in_len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    output: *mut u8,
    posp: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    // Recorded divergence: C calls `error(...)` unconditionally, a crash
    // if the caller passed NULL for it. Every path here goes through this
    // closure, which tolerates `error == NULL` instead of reproducing a
    // caller contract violation that isn't this project's to enforce.
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    // RUSTY-LINUX preboot: mirrors the C `#ifdef PREBOOT` initialiser
    // `size_t out_len = get_unaligned_le32(input + in_len);` -- the stub
    // appends the uncompressed length 4 bytes after the input.
    #[cfg(boot_preboot)]
    let mut out_len: usize = unsafe { get_unaligned_le32(input.offset(in_len as isize)) } as usize;

    let uncomp_chunksize = LZ4_DEFAULT_UNCOMPRESSED_CHUNK_SIZE;

    let outp: *mut u8;
    let owns_outp;
    if !output.is_null() {
        outp = output;
        owns_outp = false;
    } else if flush.is_none() {
        call_error(b"NULL output pointer and no flush function provided\0");
        return -1;
    } else {
        outp = unsafe { decompress_unlz4_alloc(uncomp_chunksize as c_uint) } as *mut u8;
        if outp.is_null() {
            call_error(b"Could not allocate output buffer\0");
            return -1;
        }
        owns_outp = true;
    }

    let inp_start: *mut u8;
    let owns_inp;
    if !input.is_null() && fill.is_some() {
        call_error(b"Both input pointer and fill function provided,\0");
        if owns_outp {
            unsafe { vfree(outp as *const c_void) };
        }
        return -1;
    } else if !input.is_null() {
        inp_start = input;
        owns_inp = false;
    } else if fill.is_none() {
        call_error(b"NULL input pointer and missing fill function\0");
        if owns_outp {
            unsafe { vfree(outp as *const c_void) };
        }
        return -1;
    } else {
        inp_start =
            unsafe { decompress_unlz4_alloc(lz4_compress_bound(uncomp_chunksize)) } as *mut u8;
        if inp_start.is_null() {
            call_error(b"Could not allocate input buffer\0");
            if owns_outp {
                unsafe { vfree(outp as *const c_void) };
            }
            return -1;
        }
        owns_inp = true;
    }

    let ret: i32 = 'body: {
        let mut inp = inp_start;
        let mut outp = outp;
        let mut size = in_len;

        if !posp.is_null() {
            unsafe { *posp = 0 };
        }

        if let Some(f) = fill {
            size = unsafe { f(inp as *mut c_void, 4) };
            if size < 4 {
                call_error(b"data corrupted\0");
                break 'body -1;
            }
        }

        // `size`/`*posp` are `c_long` (signed), matching the C's `long`.
        // Overflow here is UB in C too, not a defined wraparound to
        // preserve -- both track buffer-length/position bookkeeping the
        // caller controls (in_len, chunk counts), not a value read
        // directly from the compressed stream, so realistically
        // unreachable regardless of arm. wrapping_* matches what the C
        // compiles to on this target (a plain add/sub) rather than
        // panicking on an overflow neither arm can hit in practice. Found
        // by the CONFIG_RUST_OVERFLOW_CHECKS panic-symbol sweep, 2026-09-06.
        let mut chunksize = unsafe { get_unaligned_le32(inp) };
        if chunksize == ARCHIVE_MAGICNUMBER {
            if fill.is_none() {
                inp = unsafe { inp.add(4) };
                size = size.wrapping_sub(4);
            }
        } else {
            call_error(b"invalid header\0");
            break 'body -1;
        }
        if !posp.is_null() {
            unsafe { *posp = (*posp).wrapping_add(4) };
        }

        loop {
            if let Some(f) = fill {
                size = unsafe { f(inp as *mut c_void, 4) };
                if size == 0 {
                    break;
                }
                if size < 4 {
                    call_error(b"data corrupted\0");
                    break 'body -1;
                }
            } else if size < 4 {
                break 'body 0; // exit_3: empty or end-of-file
            }

            chunksize = unsafe { get_unaligned_le32(inp) };
            if chunksize == ARCHIVE_MAGICNUMBER {
                if fill.is_none() {
                    inp = unsafe { inp.add(4) };
                    size = size.wrapping_sub(4);
                }
                if !posp.is_null() {
                    unsafe { *posp = (*posp).wrapping_add(4) };
                }
                continue;
            }

            if fill.is_none() && chunksize == 0 {
                break 'body 0; // exit_3: empty or end-of-file
            }

            if !posp.is_null() {
                unsafe { *posp = (*posp).wrapping_add(4) };
            }

            if fill.is_none() {
                inp = unsafe { inp.add(4) };
                size -= 4;
            } else {
                if chunksize > lz4_compress_bound(uncomp_chunksize) {
                    call_error(b"chunk length is longer than allocated\0");
                    break 'body -1;
                }
                size = unsafe { fill.unwrap()(inp as *mut c_void, chunksize as c_ulong) };
                // Recorded divergence, found by adversarial review: C's
                // `if (size < chunksize)` compares `long` against `size_t`,
                // so the usual arithmetic conversions make it an UNSIGNED
                // compare -- a negative `fill()` return (a real path: e.g.
                // do_mounts_rd.c's compr_fill() propagates kernel_read()'s
                // I/O-error return) reads as a huge positive value and is
                // NOT caught, so C proceeds to decompress a stale buffer.
                // This signed `c_long` compare catches it. Every valid
                // stream decodes identically either way; this only differs
                // when the caller's own fill() reports failure, and Rust's
                // behavior is the safer one -- kept rather than reproducing
                // the missed check.
                if size < chunksize as c_long {
                    call_error(b"data corrupted\0");
                    break 'body -1;
                }
            }

            // RUSTY-LINUX preboot: the C `#ifdef PREBOOT` arm. dest_len is
            // the remaining output (capped at one chunk) and the engine is
            // LZ4_decompress_fast(); chunksize becomes its return value
            // (input bytes consumed), as the C assigns `chunksize = ret`.
            #[cfg(boot_preboot)]
            let dest_len: c_long;
            #[cfg(boot_preboot)]
            {
                if out_len >= uncomp_chunksize {
                    dest_len = uncomp_chunksize as c_long;
                    out_len -= uncomp_chunksize;
                } else {
                    dest_len = out_len as c_long;
                }
                let ret = unsafe {
                    LZ4_decompress_fast(inp as *const c_char, outp as *mut c_char, dest_len as c_int)
                };
                if ret < 0 {
                    call_error(b"Decoding failed\0");
                    break 'body ret;
                }
                chunksize = ret as u32;
            }
            // Kernel arm (non-preboot): unchanged.
            #[cfg(not(boot_preboot))]
            let dest_len: c_long;
            #[cfg(not(boot_preboot))]
            {
                let dest_len_cap = uncomp_chunksize as c_int;
                let ret = unsafe {
                    LZ4_decompress_safe(
                        inp as *const c_char,
                        outp as *mut c_char,
                        chunksize as c_int,
                        dest_len_cap,
                    )
                };
                if ret < 0 {
                    call_error(b"Decoding failed\0");
                    // Recorded fix: C's `ret` still holds LZ4_decompress_safe's
                    // own negative error code here (`goto exit_2` falls all the
                    // way to `return ret;` unchanged) -- an earlier version of
                    // this line discarded it as a hardcoded -1, found by
                    // adversarial review. No in-tree caller distinguishes LZ4's
                    // error codes from a plain -1 (init/initramfs.c and
                    // do_mounts_rd.c only test `if (res)`), but the C is the
                    // reference and this is otherwise a silent behavior change.
                    break 'body ret;
                }
                dest_len = ret as c_long;
            }

            if let Some(f) = flush {
                if unsafe { f(outp as *mut c_void, dest_len as c_ulong) } != dest_len {
                    break 'body -1;
                }
            }
            if !output.is_null() {
                outp = unsafe { outp.add(dest_len as usize) };
            }
            if !posp.is_null() {
                unsafe { *posp = (*posp).wrapping_add(chunksize as c_long) };
            }

            if fill.is_none() {
                size -= chunksize as c_long;
                if size == 0 {
                    break;
                } else if size < 0 {
                    call_error(b"data corrupted\0");
                    break 'body -1;
                }
                inp = unsafe { inp.add(chunksize as usize) };
            }
        }

        0 // exit_3 via the loop's own `break`: ret = 0
    };

    // exit_2, exit_1: unconditional now that ownership is fully decided.
    if owns_inp {
        unsafe { vfree(inp_start as *const c_void) };
    }
    if owns_outp {
        unsafe { vfree(outp as *const c_void) };
    }
    ret
}
