// SPDX-License-Identifier: GPL-2.0-or-later

//! The LZO archive wrapper -- Rust behind `lib/decompress_unlzo.c`.
//!
//! Replaces: lib/decompress_unlzo.c (the non-`PREBOOT` arm only -- see
//! `decompress_bunzip2_rs.rs`'s module doc for why the pre-boot arm is out
//! of scope for every file in this family).
//!
//! `unlzo()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` table and is not `EXPORT_SYMBOL`'d, so this is a
//! full replacement, same shape as `decompress_bunzip2_rs.rs` and
//! `decompress_unlz4_rs.rs`.
//!
//! # This calls a real EXPORT_SYMBOL, same as any other caller
//!
//! `lzo1x_decompress_safe()` is the `lib/bcd` shape
//! (`lzo1x_decompress_safe_rs.rs`'s module doc): `EXPORT_SYMBOL_GPL`'d with
//! a MODVERSIONS CRC, so its C entry symbol stays and its body is Rust
//! behind it. From here that distinction is invisible -- it's declared
//! `extern "C"` and called exactly as the C wrapper being replaced already
//! called it, the same as any of `lzo1x_decompress_safe`'s other nine
//! callers (crypto/lzo*, zram, btrfs, f2fs, jffs2, squashfs).
//!
//! # `kmalloc`/`kfree` stay split, same pattern as `decompress_bunzip2_rs.rs`
//!
//! Unlike `decompress_unlz4.c` (`large_malloc`/`large_free` = `vmalloc`/
//! `vfree`), this file uses plain `malloc`/`free` under `mm.h`'s non-`STATIC`
//! arm, which are `kmalloc(a, GFP_KERNEL)`/`kfree(a)` -- `kmalloc` is a macro
//! with no linkable symbol, so `decompress_unlzo.c` (this port's C half)
//! keeps a three-line wrapper, `decompress_unlzo_alloc`. `kfree` is a real
//! `EXPORT_SYMBOL` and is called directly from here.
//!
//! # The goto-cascade, same shape as `decompress_unlz4_rs.rs`
//!
//! Every `goto` here jumps FORWARD to one of three fall-through cleanup
//! labels (`exit_2` frees the input buffer if owned and falls into `exit_1`,
//! which frees the output buffer if owned and falls into `exit`, which
//! returns) -- the same shape `decompress_unlz4_rs.rs`'s module doc
//! describes, translated the same way: the two earliest error returns
//! (before both buffers' ownership is decided) inline their own partial
//! cleanup, everything after is one labelled block whose `break` value is
//! the return code, followed by the two cleanups written once.
//!
//! # `parse_header`'s pointer walk stays a pointer walk
//!
//! It is a sequence of "check there's enough left, then advance" steps over
//! a single buffer with no other logic in between, which is exactly what
//! the C's raw pointer arithmetic already expresses as plainly as anything
//! else would; translating it into slice indexing would not remove a
//! bounds check, only rename it, so it stays pointer-based (`unsafe`,
//! matching the C's own lack of a safety net beyond the length checks it
//! already makes explicit).
//!
//! # `ptr::copy` in place of the C's manual byte-copy loop
//!
//! The C moves leftover unused input down to the start of its buffer with
//! a `for` loop copying one byte at a time, "to avoid memmove() dependency
//! ... missing from pre-boot environments of most archs" -- a constraint
//! that does not apply to the normal (non-`PREBOOT`) build this replaces.
//! [`core::ptr::copy`] is `core`'s `memmove` -- correct regardless of
//! overlap, which this genuinely has (unlike the OTHER copy in this file,
//! just after header parsing, which stays a plain non-overlapping copy:
//! that source position is bounded below by `HEADER_SIZE_MAX`, always past
//! where at most that many bytes could land). Recorded because a byte loop
//! turning into one call is the kind of change that looks like it might
//! have dropped something.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

const LZO_BLOCK_SIZE: usize = 256 * 1024;
const HEADER_HAS_FILTER: u32 = 0x0000_0800;
const HEADER_SIZE_MIN: c_long = 9 + 7 + 4 + 8 + 1 + 4;
const HEADER_SIZE_MAX: usize = 9 + 7 + 1 + 8 + 8 + 4 + 1 + 255 + 4;

const LZO_E_OK: c_int = 0;

const LZOP_MAGIC: [u8; 9] = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

extern "C" {
    /// `lib/decompress_unlzo.c`. Three lines: `return kmalloc(size,
    /// GFP_KERNEL);` -- `kmalloc` itself has no linkable symbol.
    fn decompress_unlzo_alloc(size: c_uint) -> *mut c_void;
    /// `mm/slub.c`, `EXPORT_SYMBOL(kfree)`. Real out-of-line function.
    fn kfree(objp: *const c_void);
    /// `lib/lzo/lzo1x_decompress_safe.c`. The `bcd` shape: a real C entry
    /// symbol (`EXPORT_SYMBOL_GPL`, MODVERSIONS CRC) whose body is
    /// `lzo1x_decompress_safe_rs.rs`.
    fn lzo1x_decompress_safe(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
    ) -> c_int;
}

/// `lzo1x_worst_compress()`, `include/linux/lzo.h` -- a macro, no linkable
/// symbol.
const fn lzo1x_worst_compress(x: usize) -> usize {
    x + x / 16 + 64 + 3 + 2
}

unsafe fn get_unaligned_be16(p: *const u8) -> u16 {
    let mut bytes = [0u8; 2];
    unsafe { core::ptr::copy_nonoverlapping(p, bytes.as_mut_ptr(), 2) };
    u16::from_be_bytes(bytes)
}

unsafe fn get_unaligned_be32(p: *const u8) -> u32 {
    let mut bytes = [0u8; 4];
    unsafe { core::ptr::copy_nonoverlapping(p, bytes.as_mut_ptr(), 4) };
    u32::from_be_bytes(bytes)
}

/// `parse_header()`, `lib/decompress_unlzo.c`. Returns the byte offset to
/// skip past the LZOP header, or `None` on anything short of or
/// inconsistent with a valid one.
unsafe fn parse_header(input: *const u8, in_len: c_long) -> Option<c_long> {
    if in_len < HEADER_SIZE_MIN {
        return None;
    }
    let mut parse = input;
    let end = unsafe { input.offset(in_len as isize) };
    let remaining = |p: *const u8| unsafe { end.offset_from(p) };

    for &magic_byte in LZOP_MAGIC.iter() {
        let b = unsafe { *parse };
        parse = unsafe { parse.add(1) };
        if b != magic_byte {
            return None;
        }
    }

    let version = unsafe { get_unaligned_be16(parse) };
    parse = unsafe { parse.add(7) };
    if version >= 0x0940 {
        parse = unsafe { parse.add(1) };
    }
    if unsafe { get_unaligned_be32(parse) } & HEADER_HAS_FILTER != 0 {
        parse = unsafe { parse.add(8) };
    } else {
        parse = unsafe { parse.add(4) };
    }

    if remaining(parse) < 8 + 1 + 4 {
        return None;
    }

    parse = unsafe { parse.add(8) };
    if version >= 0x0940 {
        parse = unsafe { parse.add(4) };
    }

    let l = unsafe { *parse } as isize;
    parse = unsafe { parse.add(1) };
    if remaining(parse) < l + 4 {
        return None;
    }
    parse = unsafe { parse.offset(l + 4) };

    Some(unsafe { parse.offset_from(input) } as c_long)
}

/// `unlzo()`, `lib/decompress_unlzo.c`. The dispatcher's `.decompressor`
/// entry for the `"lzo"` magic (`\x89L`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn unlzo(
    input: *mut u8,
    in_len_param: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    output: *mut u8,
    posp: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    // Recorded divergence: C calls `error(...)` unconditionally, a crash
    // if the caller passed NULL for it. Every path here goes through this
    // closure, which tolerates `error == NULL` (matching
    // decompress_unlz4_rs.rs's identical choice) instead of reproducing a
    // caller contract violation that isn't this project's to enforce.
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    let out_buf: *mut u8;
    let owns_outp;
    if !output.is_null() {
        out_buf = output;
        owns_outp = false;
    } else if flush.is_none() {
        call_error(b"NULL output pointer and no flush function provided\0");
        return -1;
    } else {
        out_buf = unsafe { decompress_unlzo_alloc(LZO_BLOCK_SIZE as c_uint) } as *mut u8;
        if out_buf.is_null() {
            call_error(b"Could not allocate output buffer\0");
            return -1;
        }
        owns_outp = true;
    }

    let in_buf_save: *mut u8;
    let owns_inp;
    if !input.is_null() && fill.is_some() {
        call_error(b"Both input pointer and fill function provided, don't know what to do\0");
        if owns_outp {
            unsafe { kfree(out_buf as *const c_void) };
        }
        return -1;
    } else if !input.is_null() {
        in_buf_save = input;
        owns_inp = false;
    } else if fill.is_none() {
        call_error(b"NULL input pointer and missing fill function\0");
        if owns_outp {
            unsafe { kfree(out_buf as *const c_void) };
        }
        return -1;
    } else {
        in_buf_save =
            unsafe { decompress_unlzo_alloc(lzo1x_worst_compress(LZO_BLOCK_SIZE) as c_uint) }
                as *mut u8;
        if in_buf_save.is_null() {
            call_error(b"Could not allocate input buffer\0");
            if owns_outp {
                unsafe { kfree(out_buf as *const c_void) };
            }
            return -1;
        }
        owns_inp = true;
    }

    let ret: i32 = 'body: {
        let mut out_buf = out_buf;
        let mut in_buf = in_buf_save;
        let mut in_len = in_len_param;

        if !posp.is_null() {
            unsafe { *posp = 0 };
        }

        if let Some(f) = fill {
            // Start HEADER_SIZE_MAX in so the leftover-data move below can
            // be a plain copy toward a lower address, never overlapping
            // upward -- see decompress_unlzo.c's own comment.
            in_buf = unsafe { in_buf.add(HEADER_SIZE_MAX) };
            in_len = unsafe { f(in_buf as *mut c_void, HEADER_SIZE_MAX as c_ulong) };
        }

        let skip = match unsafe { parse_header(in_buf, in_len) } {
            Some(s) => s,
            None => {
                call_error(b"invalid header\0");
                break 'body -1;
            }
        };
        // in_len/*posp bookkeeping below (this function's remaining-bytes
        // counter and the caller's output position) is provably bounded by
        // construction: parse_header()'s own `remaining(parse) < N` checks
        // guarantee `skip <= in_len`, and every in-loop `in_len -= N` is
        // preceded by an `if in_len < N` guard, so `in_len` never goes
        // negative and never approaches c_long's range limits -- LLVM can't
        // see that invariant across the parse_header() call boundary and
        // raw-pointer arithmetic, so it emits a check anyway.
        // wrapping_sub/wrapping_add match what the C compiles to here (a
        // plain subtract/add) rather than a panic on a path neither arm can
        // reach. Found by the CONFIG_RUST_OVERFLOW_CHECKS panic-symbol
        // sweep, 2026-09-06.
        in_buf = unsafe { in_buf.offset(skip as isize) };
        in_len = in_len.wrapping_sub(skip);

        if fill.is_some() {
            let src =
                unsafe { core::slice::from_raw_parts(in_buf, in_len as usize) };
            let dst = unsafe {
                core::slice::from_raw_parts_mut(in_buf_save, in_len as usize)
            };
            dst.copy_from_slice(src);
            in_buf = in_buf_save;
        }

        if !posp.is_null() {
            unsafe { *posp = skip };
        }

        loop {
            if let Some(f) = fill {
                if in_len < 4 {
                    let got = unsafe {
                        f(
                            in_buf.offset(in_len as isize) as *mut c_void,
                            (4 as c_long).wrapping_sub(in_len) as c_ulong,
                        )
                    };
                    if got > 0 {
                        in_len = in_len.wrapping_add(got);
                    }
                }
            }
            if in_len < 4 {
                call_error(b"file corrupted\0");
                break 'body -1;
            }
            let dst_len = unsafe { get_unaligned_be32(in_buf) };
            in_buf = unsafe { in_buf.add(4) };
            in_len = in_len.wrapping_sub(4);

            if dst_len == 0 {
                if !posp.is_null() {
                    unsafe { *posp = (*posp).wrapping_add(4) };
                }
                break;
            }
            if dst_len as usize > LZO_BLOCK_SIZE {
                call_error(b"dest len longer than block size\0");
                break 'body -1;
            }

            if let Some(f) = fill {
                if in_len < 8 {
                    let got = unsafe {
                        f(
                            in_buf.offset(in_len as isize) as *mut c_void,
                            (8 as c_long).wrapping_sub(in_len) as c_ulong,
                        )
                    };
                    if got > 0 {
                        in_len = in_len.wrapping_add(got);
                    }
                }
            }
            if in_len < 8 {
                call_error(b"file corrupted\0");
                break 'body -1;
            }
            let src_len = unsafe { get_unaligned_be32(in_buf) };
            in_buf = unsafe { in_buf.add(8) };
            in_len = in_len.wrapping_sub(8);

            if src_len == 0 || src_len > dst_len {
                call_error(b"file corrupted\0");
                break 'body -1;
            }

            if let Some(f) = fill {
                if in_len < src_len as c_long {
                    let got = unsafe {
                        f(
                            in_buf.offset(in_len as isize) as *mut c_void,
                            (src_len as c_long).wrapping_sub(in_len) as c_ulong,
                        )
                    };
                    if got > 0 {
                        in_len = in_len.wrapping_add(got);
                    }
                }
            }
            if in_len < src_len as c_long {
                call_error(b"file corrupted\0");
                break 'body -1;
            }

            let mut tmp: usize = dst_len as usize;
            if dst_len == src_len {
                unsafe {
                    core::ptr::copy_nonoverlapping(in_buf, out_buf, src_len as usize)
                };
            } else {
                let r = unsafe {
                    lzo1x_decompress_safe(in_buf, src_len as usize, out_buf, &mut tmp)
                };
                if r != LZO_E_OK || dst_len as usize != tmp {
                    call_error(b"Compressed data violation\0");
                    break 'body -1;
                }
            }

            if let Some(f) = flush {
                if unsafe { f(out_buf as *mut c_void, dst_len as c_ulong) } != dst_len as c_long {
                    break 'body -1;
                }
            }
            if !output.is_null() {
                out_buf = unsafe { out_buf.add(dst_len as usize) };
            }
            if !posp.is_null() {
                unsafe { *posp = (*posp).wrapping_add(src_len as c_long).wrapping_add(12) };
            }

            in_buf = unsafe { in_buf.add(src_len as usize) };
            in_len -= src_len as c_long;
            if fill.is_some() {
                // memmove, not memcpy: unlike the header-skip copy above,
                // `in_buf`'s distance from `in_buf_save` here shrinks over
                // successive iterations and the two regions can genuinely
                // overlap. `ptr::copy` is `core`'s `memmove` -- correct
                // regardless of overlap or copy direction, which is the
                // actual property the C's manual forward-copying loop
                // exists to get without an arch memmove available.
                if in_len > 0 {
                    unsafe { core::ptr::copy(in_buf, in_buf_save, in_len as usize) };
                }
                in_buf = in_buf_save;
            }
        }

        0
    };

    if owns_inp {
        unsafe { kfree(in_buf_save as *const c_void) };
    }
    if owns_outp {
        unsafe { kfree(out_buf as *const c_void) };
    }
    ret
}
