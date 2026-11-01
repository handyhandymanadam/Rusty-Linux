// SPDX-License-Identifier: GPL-2.0-or-later

//! Crypto API support for SHA-384/SHA-512 -- the Rust behind `crypto/sha512.c`.
//!
//! Ported from `crypto/sha512.c` (6.18.49), Copyright (c) Jean-Luc Cooke,
//! Andrew McDonald, 2003 Kyle McMartin, 2025 Google LLC.
//! The digests themselves are `lib/crypto/sha512`; this is the shash layer on
//! top of them.
//!
//! # What is here and what stayed in C (`sha512_glue.c`)
//!
//! Here: the four state import/export bodies (`__crypto_sha512_export`,
//! `__crypto_sha512_import`, `__crypto_sha512_export_core`,
//! `__crypto_sha512_import_core`). They are shared by SHA-384, SHA-512 and both
//! HMACs: all four contexts embed a `struct __sha512_ctx`.
//!
//! In C: the `struct shash_alg algs[]` table, `module_init`/`module_exit`,
//! `MODULE_*`/`MODULE_ALIAS_CRYPTO`, the thirty-two one-line shash callbacks
//! (each "fetch my context from `desc`/`tfm`, call the library"; the fetch is
//! `shash_desc_ctx()`/`crypto_shash_ctx()`, `static inline` accessors over
//! structs whose geometry depends on `CRYPTO_MINALIGN` and Kconfig), and the
//! exported `sha224_zero_message_hash`/`sha512_zero_message_hash` tables. Those
//! two are plain data with no logic, so they stay C data and keep the C
//! compiler's MODVERSIONS CRC unchanged.
//!
//! # Context layout
//!
//! `struct __sha512_ctx` (`include/crypto/sha2.h`) is mirrored here as a
//! `#[repr(C)]` struct with the C file's own offsets asserted at compile time
//! (state at 0, bytecount_lo at 64, bytecount_hi at 72, buf at 80, size 208:
//! 209 with the extra byte of the shash state). The struct is a stable lib type, not a
//! Kconfig-dependent one.
//!
//! # `bytecount_lo` arithmetic wraps, like the C
//!
//! The SHA-512 length is a 128-bit counter held as two `u64`s. The shash state
//! format only touches `bytecount_lo`: `export` rounds it down to a block and
//! `import` adds the extra byte back, with no carry into or borrow from
//! `bytecount_hi`, exactly as the C does (`bytecount_hi` is copied verbatim).
//! The block is 128 bytes, so the remainder is 0..=127 and fits the `u8`.
//!
//! `import` adds the extra trailing byte to `bytecount_lo`. The state comes from
//! a caller (AF_ALG import) so `bytecount_lo` may be anything; the C wraps, and
//! Rust built with overflow checks would panic. `wrapping_add` keeps the C's
//! behaviour.
//!
//! Replaces: crypto/sha512.c

use core::ffi::{c_int, c_void};

/// `SHA512_BLOCK_SIZE`.
const BLOCK_SIZE: u64 = 128;

/// Mirrors `struct __sha512_ctx` (`include/crypto/sha2.h`). `u64` gives it the
/// 8-byte alignment that `buf`'s `__aligned(__alignof__(__be64))` gives the C.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShashSha512Ctx {
    state: [u64; 8],
    bytecount_lo: u64,
    bytecount_hi: u64,
    buf: [u8; BLOCK_SIZE as usize],
}

const CTX_SIZE: usize = core::mem::size_of::<ShashSha512Ctx>();
/// `offsetof(struct __sha512_ctx, buf)`.
const BUF_OFFSET: usize = core::mem::offset_of!(ShashSha512Ctx, buf);

// The static_asserts of crypto/sha512.c.
const _: () = {
    assert!(core::mem::offset_of!(ShashSha512Ctx, state) == 0);
    assert!(core::mem::offset_of!(ShashSha512Ctx, bytecount_lo) == 64);
    assert!(core::mem::offset_of!(ShashSha512Ctx, bytecount_hi) == 72);
    assert!(BUF_OFFSET == 80);
    assert!(CTX_SIZE + 1 == 209);
};

/// `__crypto_sha512_export()`: the library context, with `bytecount_lo` rounded
/// down to a block boundary, followed by one byte holding the remainder.
///
/// # Safety
/// `ctx0` points to a valid `struct __sha512_ctx`; `out` has room for
/// `sizeof(struct __sha512_ctx) + 1` bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_sha512_rs_export(
    ctx0: *const ShashSha512Ctx,
    out: *mut c_void,
) -> c_int {
    // SAFETY: caller contract.
    let mut ctx = unsafe { *ctx0 };
    let partial = ctx.bytecount_lo % BLOCK_SIZE;
    let p = out as *mut u8;

    ctx.bytecount_lo -= partial; // partial <= bytecount_lo: cannot underflow
    // SAFETY: `p` has CTX_SIZE + 1 writable bytes (caller contract).
    unsafe {
        core::ptr::copy_nonoverlapping(&ctx as *const ShashSha512Ctx as *const u8, p, CTX_SIZE);
        *p.add(CTX_SIZE) = partial as u8;
    }
    0
}

/// `__crypto_sha512_import()`: the inverse of [`crypto_sha512_rs_export`].
///
/// # Safety
/// `ctx` points to a writable `struct __sha512_ctx`; `in_` has
/// `sizeof(struct __sha512_ctx) + 1` readable bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_sha512_rs_import(
    ctx: *mut ShashSha512Ctx,
    in_: *const c_void,
) -> c_int {
    let p = in_ as *const u8;

    // SAFETY: caller contract.
    unsafe {
        core::ptr::copy_nonoverlapping(p, ctx as *mut u8, CTX_SIZE);
        let extra = *p.add(CTX_SIZE) as u64;
        (*ctx).bytecount_lo = (*ctx).bytecount_lo.wrapping_add(extra);
    }
    0
}

/// `__crypto_sha512_export_core()`: the state and both byte count words, without `buf`.
///
/// # Safety
/// `ctx` points to a valid `struct __sha512_ctx`; `out` has `BUF_OFFSET`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha512_rs_export_core(
    ctx: *const ShashSha512Ctx,
    out: *mut c_void,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(ctx as *const u8, out as *mut u8, BUF_OFFSET) };
    0
}

/// `__crypto_sha512_import_core()`: the inverse of
/// [`crypto_sha512_rs_export_core`].
///
/// # Safety
/// `ctx` points to a writable `struct __sha512_ctx`; `in_` has `BUF_OFFSET`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha512_rs_import_core(
    ctx: *mut ShashSha512Ctx,
    in_: *const c_void,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(in_ as *const u8, ctx as *mut u8, BUF_OFFSET) };
    0
}
