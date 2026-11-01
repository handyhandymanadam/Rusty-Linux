// SPDX-License-Identifier: GPL-2.0-only

//! LZO-RLE scomp glue -- the Rust behind `crypto/lzo-rle.c`'s two helper bodies.
//!
//! Ported from `crypto/lzo-rle.c` (6.18.49).
//!
//! Replaces: crypto/lzo-rle.c
//!
//! # What is here and what stayed in C (`lzorle_glue.c`)
//!
//! Here: `__lzorle_compress()` and `__lzorle_decompress()`, the only code in
//! `crypto/lzo-rle.c` that decides anything. Each widens the caller's `u32`
//! output length to the `size_t` the library wants, calls the (already Rust)
//! `lzorle1x_1_compress_safe()` / `lzo1x_decompress_safe()` (the RLE variant
//! has its own compressor and shares the LZO decompressor), turns every
//! non-`LZO_E_OK` result into `-EINVAL`, and writes the output length back
//! ONLY on success.
//!
//! In C: the `struct scomp_alg` table, `module_init`/`module_exit`, `MODULE_*`,
//! the one-line `crypto_scomp` callbacks, and `alloc_ctx`/`free_ctx`, which
//! call `kvmalloc()`/`kvfree()` -- `alloc_hooks()` macros with no linkable
//! symbol since 6.10 (same reason as `lib/string_helpers.c`).
//! That is about twenty lines of logic in a hundred-line file; the rest
//! is registration, and it stays where its Kconfig-dependent structs are.
//!
//! # Narrowing
//!
//! `*dlen = tmp_len` narrows `size_t` to `u32` (the C comment says
//! "size_t(ulong) <-> uint on 64 bit"). `as u32` truncates, like the C. The
//! library never reports more than the `u32` capacity it was given.

use core::ffi::{c_int, c_void};

/// `LZO_E_OK`.
const LZO_E_OK: c_int = 0;
/// `EINVAL`.
const EINVAL: c_int = 22;

extern "C" {
    // include/linux/lzo.h -- lib/lzo/lzo1x_compress_rs.rs / lzo1x_decompress_safe.c
    fn lzorle1x_1_compress_safe(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        wrkmem: *mut c_void,
    ) -> c_int;
    fn lzo1x_decompress_safe(src: *const u8, src_len: usize, dst: *mut u8, dst_len: *mut usize) -> c_int;
}

/// `__lzorle_compress()`.
///
/// # Safety
/// The arguments are `lzorle_scompress()`'s: `src` readable for `slen` bytes,
/// `dst` writable for `*dlen` bytes, `dlen` a valid pointer, `ctx` a
/// `LZO1X_MEM_COMPRESS`-byte work area.
#[no_mangle]
pub unsafe extern "C" fn crypto_lzorle_rs_compress(
    src: *const u8,
    slen: u32,
    dst: *mut u8,
    dlen: *mut u32,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: caller contract.
    let mut tmp_len = unsafe { *dlen } as usize;
    // SAFETY: caller contract; `tmp_len` is a live local.
    let err = unsafe { lzorle1x_1_compress_safe(src, slen as usize, dst, &mut tmp_len, ctx) };

    if err != LZO_E_OK {
        return -EINVAL;
    }

    // SAFETY: caller contract.
    unsafe { *dlen = tmp_len as u32 };
    0
}

/// `__lzorle_decompress()`.
///
/// # Safety
/// The arguments are `lzorle_sdecompress()`'s: `src` readable for `slen` bytes,
/// `dst` writable for `*dlen` bytes, `dlen` a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn crypto_lzorle_rs_decompress(
    src: *const u8,
    slen: u32,
    dst: *mut u8,
    dlen: *mut u32,
) -> c_int {
    // SAFETY: caller contract.
    let mut tmp_len = unsafe { *dlen } as usize;
    // SAFETY: caller contract; `tmp_len` is a live local.
    let err = unsafe { lzo1x_decompress_safe(src, slen as usize, dst, &mut tmp_len) };

    if err != LZO_E_OK {
        return -EINVAL;
    }

    // SAFETY: caller contract.
    unsafe { *dlen = tmp_len as u32 };
    0
}
