// SPDX-License-Identifier: GPL-2.0-or-later

//! Crypto API support for MD5 and HMAC-MD5 -- the Rust behind `crypto/md5.c`.
//!
//! Ported from `crypto/md5.c` (6.18.49), Copyright 2025 Google LLC. The digest
//! itself is `lib/crypto/md5_rs.rs`, already Rust; this is the shash layer on
//! top of it.
//!
//! # What is here and what stayed in C (`md5_glue.c`)
//!
//! Here: the four state import/export bodies (`__crypto_md5_export`,
//! `__crypto_md5_import`, `__crypto_md5_export_core`,
//! `__crypto_md5_import_core`) and the exported `md5_zero_message_hash` table
//! (an `EXPORT_SYMBOL_GPL` data symbol, so it carries its MODVERSIONS
//! contract here, via `kernel::kabi_export!`).
//!
//! In C: the `struct shash_alg algs[]` table, `module_init`/`module_exit`,
//! `MODULE_*`/`MODULE_ALIAS_CRYPTO`, and the twelve one-line shash callbacks.
//! Every callback is "fetch my context from `desc`/`tfm`, call the library".
//! The fetch is `shash_desc_ctx()`/`crypto_shash_ctx()`, `static inline`
//! accessors over `struct shash_desc`/`struct crypto_tfm` whose geometry
//! depends on `CRYPTO_MINALIGN` and Kconfig; mirroring those structs in Rust
//! would add a layout risk to move code that has no logic in it. The callbacks
//! keep calling `md5_*()`/`hmac_md5_*()`, which are Rust already.
//!
//! # `bytecount` arithmetic wraps, like the C
//!
//! `import` adds the extra trailing byte to `bytecount`. The state comes from
//! a caller (AF_ALG `recvmsg`/`sendmsg` import) so `bytecount` may be
//! anything; the C wraps, and Rust built with overflow checks would panic.
//! `wrapping_add` keeps the C's behaviour.
//!
//! Replaces: crypto/md5.c

use core::ffi::{c_int, c_void};

/// `MD5_BLOCK_SIZE`.
const BLOCK_SIZE: u64 = 64;
/// `MD5_DIGEST_SIZE`.
const DIGEST_SIZE: usize = 16;

/// Mirrors `struct md5_block_state` (`include/crypto/md5.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShashMd5BlockState {
    h: [u32; 4],
}

/// Mirrors `struct md5_ctx` (`include/crypto/md5.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShashMd5Ctx {
    state: ShashMd5BlockState,
    bytecount: u64,
    buf: [u8; BLOCK_SIZE as usize],
}

const CTX_SIZE: usize = core::mem::size_of::<ShashMd5Ctx>();
/// `offsetof(struct md5_ctx, buf)`.
const BUF_OFFSET: usize = core::mem::offset_of!(ShashMd5Ctx, buf);

const _: () = {
    assert!(CTX_SIZE == 88);
    assert!(BUF_OFFSET == 24);
};

// Captured from the C object (crypto/md5.o, build-full) BEFORE the C definition
// was removed: `printf md5_zero_message_hash | gendwarfksyms --symtypes`,
// reproducing 0xa7c46ebf. Verified again by rig/kabi-contract-check.sh.
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    md5_zero_message_hash,
    license = "GPL",
    namespace = "",
    contract = "variable array_type[16] { const_type { t#u8 } }",
}

/// `md5_zero_message_hash[MD5_DIGEST_SIZE]`: the MD5 of the empty message.
#[no_mangle]
pub static md5_zero_message_hash: [u8; DIGEST_SIZE] = [
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
];

/// `__crypto_md5_export()`: the library context, with `bytecount` rounded
/// down to a block boundary, followed by one byte holding the remainder.
///
/// # Safety
/// `ctx0` points to a valid `struct md5_ctx`; `out` has room for
/// `sizeof(struct md5_ctx) + 1` bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_md5_rs_export(ctx0: *const ShashMd5Ctx, out: *mut c_void) -> c_int {
    // SAFETY: caller contract.
    let mut ctx = unsafe { *ctx0 };
    let partial = ctx.bytecount % BLOCK_SIZE;
    let p = out as *mut u8;

    ctx.bytecount -= partial; // partial <= bytecount: cannot underflow
    // SAFETY: `p` has CTX_SIZE + 1 writable bytes (caller contract).
    unsafe {
        core::ptr::copy_nonoverlapping(&ctx as *const ShashMd5Ctx as *const u8, p, CTX_SIZE);
        *p.add(CTX_SIZE) = partial as u8;
    }
    0
}

/// `__crypto_md5_import()`: the inverse of [`crypto_md5_rs_export`].
///
/// # Safety
/// `ctx` points to a writable `struct md5_ctx`; `in_` has
/// `sizeof(struct md5_ctx) + 1` readable bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_md5_rs_import(ctx: *mut ShashMd5Ctx, in_: *const c_void) -> c_int {
    let p = in_ as *const u8;

    // SAFETY: caller contract.
    unsafe {
        core::ptr::copy_nonoverlapping(p, ctx as *mut u8, CTX_SIZE);
        let extra = *p.add(CTX_SIZE) as u64;
        (*ctx).bytecount = (*ctx).bytecount.wrapping_add(extra);
    }
    0
}

/// `__crypto_md5_export_core()`: the state and byte count, without `buf`.
///
/// # Safety
/// `ctx` points to a valid `struct md5_ctx`; `out` has `BUF_OFFSET` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_md5_rs_export_core(ctx: *const ShashMd5Ctx, out: *mut c_void) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(ctx as *const u8, out as *mut u8, BUF_OFFSET) };
    0
}

/// `__crypto_md5_import_core()`: the inverse of [`crypto_md5_rs_export_core`].
///
/// # Safety
/// `ctx` points to a writable `struct md5_ctx`; `in_` has `BUF_OFFSET` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_md5_rs_import_core(ctx: *mut ShashMd5Ctx, in_: *const c_void) -> c_int {
    // SAFETY: caller contract.
    unsafe { core::ptr::copy_nonoverlapping(in_ as *const u8, ctx as *mut u8, BUF_OFFSET) };
    0
}
