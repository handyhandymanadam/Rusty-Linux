// SPDX-License-Identifier: GPL-2.0-or-later

//! Crypto API support for SHA-224/SHA-256 -- the Rust behind `crypto/sha256.c`.
//!
//! Ported from `crypto/sha256.c` (6.18.49), Copyright (c) Jean-Luc Cooke,
//! Andrew McDonald, 2002 James Morris, 2007 Intel Corporation, 2025 Google LLC.
//! The digests themselves are `lib/crypto/sha256`; this is the shash layer on
//! top of them.
//!
//! # What is here and what stayed in C (`sha256_glue.c`)
//!
//! Here: the four state import/export bodies (`__crypto_sha256_export`,
//! `__crypto_sha256_import`, `__crypto_sha256_export_core`,
//! `__crypto_sha256_import_core`). They are shared by SHA-224, SHA-256 and both
//! HMACs: all four contexts embed a `struct __sha256_ctx`.
//!
//! In C: the `struct shash_alg algs[]` table, `module_init`/`module_exit`,
//! `MODULE_*`/`MODULE_ALIAS_CRYPTO`, the thirty-two one-line shash callbacks
//! (each "fetch my context from `desc`/`tfm`, call the library"; the fetch is
//! `shash_desc_ctx()`/`crypto_shash_ctx()`, `static inline` accessors over
//! structs whose geometry depends on `CRYPTO_MINALIGN` and Kconfig), and the
//! exported `sha224_zero_message_hash`/`sha256_zero_message_hash` tables. Those
//! two are plain data with no logic, so they stay C data and keep the C
//! compiler's MODVERSIONS CRC unchanged.
//!
//! # Context layout
//!
//! `struct __sha256_ctx` (`include/crypto/sha2.h`) is mirrored here as a
//! `#[repr(C)]` struct with the C file's own offsets asserted at compile time
//! (state at 0, bytecount at 32, buf at 40, size 104: 105 with the extra byte
//! of the shash state). The struct is a stable lib type, not a
//! Kconfig-dependent one.
//!
//! # `bytecount` arithmetic wraps, like the C
//!
//! `import` adds the extra trailing byte to `bytecount`. The state comes from
//! a caller (AF_ALG import) so `bytecount` may be anything; the C wraps, and
//! Rust built with overflow checks would panic. `wrapping_add` keeps the C's
//! behaviour.
//!
//! Replaces: crypto/sha256.c

use core::ffi::{c_int, c_void};

/// `SHA256_BLOCK_SIZE`.
const BLOCK_SIZE: u64 = 64;

/// Mirrors `struct __sha256_ctx` (`include/crypto/sha2.h`). `u64` gives it the
/// 8-byte alignment that `buf`'s `__aligned(__alignof__(__be64))` gives the C.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShashSha256Ctx {
    state: [u32; 8],
    bytecount: u64,
    buf: [u8; BLOCK_SIZE as usize],
}

const CTX_SIZE: usize = core::mem::size_of::<ShashSha256Ctx>();
/// `offsetof(struct __sha256_ctx, buf)`.
const BUF_OFFSET: usize = core::mem::offset_of!(ShashSha256Ctx, buf);

// The static_asserts of crypto/sha256.c.
const _: () = {
    assert!(core::mem::offset_of!(ShashSha256Ctx, state) == 0);
    assert!(core::mem::offset_of!(ShashSha256Ctx, bytecount) == 32);
    assert!(BUF_OFFSET == 40);
    assert!(CTX_SIZE + 1 == 105);
};

/// `__crypto_sha256_export()`: the library context, with `bytecount` rounded
/// down to a block boundary, followed by one byte holding the remainder.
///
/// # Safety
/// `ctx0` points to a valid `struct __sha256_ctx`; `out` has room for
/// `sizeof(struct __sha256_ctx) + 1` bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_sha256_rs_export(
    ctx0: *const ShashSha256Ctx,
    out: *mut c_void,
) -> c_int {
    // SAFETY: caller contract.
    let mut ctx = unsafe { *ctx0 };
    let partial = ctx.bytecount % BLOCK_SIZE;
    let p = out as *mut u8;

    ctx.bytecount -= partial; // partial <= bytecount: cannot underflow
    // SAFETY: `p` has CTX_SIZE + 1 writable bytes (caller contract).
    unsafe {
        core::ptr::copy_nonoverlapping(&ctx as *const ShashSha256Ctx as *const u8, p, CTX_SIZE);
        *p.add(CTX_SIZE) = partial as u8;
    }
    0
}

/// `__crypto_sha256_import()`: the inverse of [`crypto_sha256_rs_export`].
///
/// # Safety
/// `ctx` points to a writable `struct __sha256_ctx`; `in_` has
/// `sizeof(struct __sha256_ctx) + 1` readable bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_sha256_rs_import(
    ctx: *mut ShashSha256Ctx,
    in_: *const c_void,
) -> c_int {
    let p = in_ as *const u8;

    // SAFETY: caller contract.
    unsafe {
        core::ptr::copy_nonoverlapping(p, ctx as *mut u8, CTX_SIZE);
        let extra = *p.add(CTX_SIZE) as u64;
        (*ctx).bytecount = (*ctx).bytecount.wrapping_add(extra);
    }
    0
}

/// `__crypto_sha256_export_core()`: the state and byte count, without `buf`.
///
/// # Safety
/// `ctx` points to a valid `struct __sha256_ctx`; `out` has `BUF_OFFSET`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha256_rs_export_core(
    ctx: *const ShashSha256Ctx,
    out: *mut c_void,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(ctx as *const u8, out as *mut u8, BUF_OFFSET) };
    0
}

/// `__crypto_sha256_import_core()`: the inverse of
/// [`crypto_sha256_rs_export_core`].
///
/// # Safety
/// `ctx` points to a writable `struct __sha256_ctx`; `in_` has `BUF_OFFSET`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha256_rs_import_core(
    ctx: *mut ShashSha256Ctx,
    in_: *const c_void,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(in_ as *const u8, ctx as *mut u8, BUF_OFFSET) };
    0
}
