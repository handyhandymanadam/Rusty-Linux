// SPDX-License-Identifier: GPL-2.0-only

//! GHASH (GCM's hash) -- the Rust behind `crypto/ghash-generic.c`.
//!
//! Ported from `crypto/ghash-generic.c` (6.18.49), Copyright (c) 2007 Nokia
//! Siemens Networks (Mikko Herranen) and (c) 2009 Intel Corp. (Huang Ying).
//!
//! Replaces: crypto/ghash-generic.c
//!
//! # What this is, and what it is NOT
//!
//! GHASH is Horner's rule for a polynomial over GF(2^128) evaluated at the
//! point H: `Y = (Y ^ block) * H` for every 16-byte block, the final partial
//! block zero-padded. **The GF(2^128) multiply is not in this file.** It is
//! `gf128mul_4k_lle()` in `lib/crypto/gf128mul.c` (still C: its table setup
//! allocates with `kzalloc()`), reached through the key's 4 KiB table
//! `struct gf128mul_4k` (`gf128mul_init_4k_lle()`). Rust holds that table only
//! as an opaque pointer and never looks inside it. What moved here is the
//! block loop, the zero-padded final block, the `setkey` protocol (length
//! check, free the old table, build the new one, wipe the key copy) and the
//! `cra_exit` free.
//!
//! In C (`ghash_glue.c`): the `struct shash_alg` table, `module_init`/
//! `module_exit`, `MODULE_*` and the five callbacks. They fetch their context
//! with `shash_desc_ctx()`/`crypto_shash_ctx()`/`crypto_tfm_ctx()`, static
//! inline accessors over Kconfig-dependent structs, so Rust mirrors none of
//! them (the shape of `crypto/md5.c`). Nothing in this file is exported.
//!
//! # Preconditions, kept from the C
//!
//! `update` is called by the shash layer only with `srclen >= 16`
//! (`CRYPTO_AHASH_ALG_BLOCK_ONLY`); like the C it is a do-while and returns the
//! remainder. `finup` is called with `len < 16`.
//!
//! # `crypto_xor()` and `gf128mul_free_4k()`
//!
//! `crypto_xor(dst, src, n)` is a byte-wise `dst[i] ^= src[i]` (the C has an
//! unaligned-word fast path for constant sizes; same result). `gf128mul_free_4k()`
//! is a `static inline` wrapper for `kfree_sensitive()`, which is a real
//! exported function, so Rust calls that.

use core::ffi::{c_int, c_void};
use core::ptr;

const GHASH_BLOCK_SIZE: usize = 16;
const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;

/// `be128` (two `__be64`): 16 bytes, 8-byte aligned.
#[repr(C, align(8))]
struct Be128([u8; GHASH_BLOCK_SIZE]);

// The C has BUILD_BUG_ON(sizeof(k) != GHASH_BLOCK_SIZE).
const _: () = assert!(core::mem::size_of::<Be128>() == GHASH_BLOCK_SIZE);

/// `struct gf128mul_4k`: opaque here, only ever passed back to the C.
#[repr(C)]
pub struct Gf128mul4k {
    _opaque: [u8; 0],
}

extern "C" {
    // lib/crypto/gf128mul.c, include/crypto/gf128mul.h. `be128` is two be64 = 16 bytes.
    fn gf128mul_init_4k_lle(g: *const Be128) -> *mut Gf128mul4k;
    fn gf128mul_4k_lle(a: *mut Be128, t: *const Gf128mul4k);
    // mm/slub.c; what `gf128mul_free_4k()` expands to.
    fn kfree_sensitive(p: *const c_void);
}

/// `memzero_explicit()` on a 16-byte buffer: volatile writes, like every other
/// port here, so the wipe of the key copy cannot be elided.
fn memzero_explicit(buf: &mut Be128) {
    for b in buf.0.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8`.
        unsafe { ptr::write_volatile(b, 0) };
    }
}

/// `ghash_init()`'s body: `memset(dctx, 0, sizeof(*dctx))`.
///
/// # Safety
/// `buffer` points to a writable `u8[16]` (`struct ghash_desc_ctx`).
#[no_mangle]
pub unsafe extern "C" fn crypto_ghash_rs_init(buffer: *mut u8) {
    // SAFETY: caller contract.
    unsafe { ptr::write_bytes(buffer, 0, GHASH_BLOCK_SIZE) };
}

/// `ghash_setkey()`'s body.
///
/// `slot` is `&ctx->gf128` (`struct ghash_ctx`'s only field).
///
/// # Safety
/// `slot` points to a valid `*mut gf128mul_4k` (null or a live table);
/// `key` is readable for `keylen` bytes (it need not be aligned).
#[no_mangle]
pub unsafe extern "C" fn crypto_ghash_rs_setkey(
    slot: *mut *mut Gf128mul4k,
    key: *const u8,
    keylen: u32,
) -> c_int {
    if keylen as usize != GHASH_BLOCK_SIZE {
        return -EINVAL;
    }

    // SAFETY: caller contract.
    unsafe {
        if !(*slot).is_null() {
            kfree_sensitive((*slot).cast());
        }
    }

    let mut k = Be128([0u8; GHASH_BLOCK_SIZE]);
    // SAFETY: `key` is readable for 16 bytes (`keylen` was just checked).
    unsafe { ptr::copy_nonoverlapping(key, k.0.as_mut_ptr(), GHASH_BLOCK_SIZE) };
    // SAFETY: `k` is a live 16-byte `be128`; `slot` is writable.
    let table = unsafe { gf128mul_init_4k_lle(&k) };
    unsafe { *slot = table };
    memzero_explicit(&mut k);

    if table.is_null() {
        return -ENOMEM;
    }
    0
}

/// `ghash_update()`'s body: `buffer = (buffer ^ block) * H` for each whole
/// 16-byte block; returns the bytes left over.
///
/// # Safety
/// `buffer` points to a writable `u8[16]` (aligned for `be128`'s needs: the C
/// casts it to `be128 *`); `gf128` is the key's table; `src` is readable for
/// `srclen` bytes with `srclen >= 16`.
#[no_mangle]
pub unsafe extern "C" fn crypto_ghash_rs_update(
    buffer: *mut u8,
    gf128: *const Gf128mul4k,
    mut src: *const u8,
    mut srclen: u32,
) -> u32 {
    loop {
        for i in 0..GHASH_BLOCK_SIZE {
            // SAFETY: caller contract: a whole block is readable at `src`.
            unsafe { *buffer.add(i) ^= *src.add(i) };
        }
        // SAFETY: caller contract.
        unsafe { gf128mul_4k_lle(buffer.cast(), gf128) };
        // SAFETY: still inside (or one past) the caller's buffer.
        src = unsafe { src.add(GHASH_BLOCK_SIZE) };
        srclen = srclen.wrapping_sub(GHASH_BLOCK_SIZE as u32);
        if srclen < GHASH_BLOCK_SIZE as u32 {
            break;
        }
    }
    srclen
}

/// `ghash_finup()`'s body (`ghash_flush()` + copy out): fold in the last
/// `len < 16` bytes (zero-padded, i.e. XOR into the front of the buffer) and
/// multiply once, then copy the 16-byte state to `dst`.
///
/// # Safety
/// `buffer` as for `update`; `gf128` the key's table; `src` readable for `len`
/// bytes (may be null when `len == 0`); `dst` writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn crypto_ghash_rs_finup(
    buffer: *mut u8,
    gf128: *const Gf128mul4k,
    src: *const u8,
    len: u32,
    dst: *mut u8,
) {
    if len != 0 {
        for i in 0..len as usize {
            // SAFETY: caller contract: `src` readable for `len` bytes, `len < 16`.
            unsafe { *buffer.add(i) ^= *src.add(i) };
        }
        // SAFETY: caller contract.
        unsafe { gf128mul_4k_lle(buffer.cast(), gf128) };
    }
    // SAFETY: caller contract: `dst` writable for 16 bytes.
    unsafe { ptr::copy_nonoverlapping(buffer, dst, GHASH_BLOCK_SIZE) };
}

/// `ghash_exit_tfm()`'s body: free the key table if there is one.
///
/// # Safety
/// `slot` points to a valid `*mut gf128mul_4k` (null or a live table).
#[no_mangle]
pub unsafe extern "C" fn crypto_ghash_rs_exit(slot: *mut *mut Gf128mul4k) {
    // SAFETY: caller contract.
    unsafe {
        if !(*slot).is_null() {
            kfree_sensitive((*slot).cast());
        }
    }
}
