// SPDX-License-Identifier: GPL-2.0

//! Generic AES -- the Rust behind `lib/crypto/aes.c`.
//!
//! Ported from `lib/crypto/aes.c` (6.18.49), Copyright (C) 2017-2019
//! Ard Biesheuvel <ard.biesheuvel@linaro.org>.
//!
//! Replaces: lib/crypto/aes.c
//!
//! # No C is left -- there is no x86 SIMD variant of this file at all
//!
//! Unlike `blake2s`/`sha1`/`sha256`/`sha512`, `CONFIG_CRYPTO_LIB_AES_ARCH`
//! does not exist as a Kconfig symbol; AES-NI lives entirely in
//! `arch/x86/crypto`, outside `lib/crypto`. So this file has nothing to
//! dispatch to and moves whole, the `lib/crypto/md5.c` shape rather than
//! the `blake2s.c` one -- see `logs/c-entry-rule.md`.
//!
//! # The sboxes are `read_volatile`, not a plain array index
//!
//! The C declares them `static volatile const` specifically "to prevent the
//! compiler from doing constant folding on sbox references involving fixed
//! indexes" -- a defence against a compiler resolving `aes_sbox[0]` to a
//! literal at compile time, which would help an attacker who can observe
//! which code paths execute (the value becomes independent of a runtime
//! memory access, defeating the whole point of loading the table into cache
//! uniformly). Rust has no `volatile` storage class; `sbox()`/`inv_sbox()`
//! below use `core::ptr::read_volatile()` at every lookup instead, which
//! is the same technique this port already uses for the opposite direction
//! in `memzero_explicit_bytes()` elsewhere (`blake2s_rs.rs`,
//! `sha512_rs.rs`): a volatile access the compiler cannot fold or elide.
//!
//! # `crypto_aes_sbox`/`crypto_aes_inv_sbox` don't need C's alias trick
//!
//! The C exports these as `extern ... __alias(aes_sbox)` because it wants
//! one array with two names (a private one for internal fixed-index use,
//! a public one for the ABI) without duplicating 256 bytes of storage.
//! Rust has no equivalent attribute, but also no need for one: there is
//! only one array here, `crypto_aes_sbox`/`crypto_aes_inv_sbox` themselves,
//! and every internal lookup reads through the same public statics the ABI
//! exposes.
//!
//! # `ctx->key_enc[key_len + 24]` is not a bug, and is reproduced literally
//!
//! `aes_expandkey()`'s decryption-key derivation indexes `key_enc` (a `u32`
//! array) using `key_len`, which is a byte count (16/24/32) -- reproduced
//! exactly as the C computes it rather than "fixed" to look more sensible;
//! it is FIPS-197's key-schedule size arithmetic, not a mistake, and
//! verified byte-for-byte against the real C via the differential.

use core::ffi::c_int;

const AES_MAX_KEYLENGTH_U32: usize = 60;
/// `-EINVAL`.
const EINVAL: c_int = 22;

/// Mirrors `struct crypto_aes_ctx` (`include/crypto/aes.h`).
#[repr(C)]
pub struct CryptoAesCtx {
    /// The encryption round-key schedule.
    pub key_enc: [u32; AES_MAX_KEYLENGTH_U32],
    /// The decryption round-key schedule (the Equivalent Inverse Cipher).
    pub key_dec: [u32; AES_MAX_KEYLENGTH_U32],
    /// The key length, in bytes (16, 24, or 32).
    pub key_length: u32,
}

kernel::kabi_export! {
    crypto_aes_sbox,
    license = "",
    namespace = "",
    contract = "variable array_type[256] { const_type { t#u8 } }",
}

/// The FIPS-197 S-box. See the module doc comment on why lookups go through
/// `sbox()` rather than direct indexing.
#[no_mangle]
pub static crypto_aes_sbox: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

kernel::kabi_export! {
    crypto_aes_inv_sbox,
    license = "",
    namespace = "",
    contract = "variable array_type[256] { const_type { t#u8 } }",
}

/// The inverse S-box.
#[no_mangle]
pub static crypto_aes_inv_sbox: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[inline(always)]
fn sbox(i: u8) -> u8 {
    // SAFETY: `crypto_aes_sbox` is a valid, fully-initialized 256-byte
    // static; `i` indexes it in bounds for every value of `u8`.
    unsafe { core::ptr::read_volatile(crypto_aes_sbox.as_ptr().add(i as usize)) }
}

#[inline(always)]
fn inv_sbox(i: u8) -> u8 {
    // SAFETY: same as `sbox()`.
    unsafe { core::ptr::read_volatile(crypto_aes_inv_sbox.as_ptr().add(i as usize)) }
}

/// Multiply by the polynomial `x` (0b10) in GF(2^8), on all four bytes of a
/// packed `u32` in parallel.
fn mul_by_x(w: u32) -> u32 {
    let x = w & 0x7f7f7f7f;
    let y = w & 0x80808080;
    (x << 1) ^ (y >> 7).wrapping_mul(0x1b)
}

/// Multiply by `x^2` (0b100) in GF(2^8), packed.
fn mul_by_x2(w: u32) -> u32 {
    let x = w & 0x3f3f3f3f;
    let y = w & 0x80808080;
    let z = w & 0x40404040;
    (x << 2) ^ (y >> 7).wrapping_mul(0x36) ^ (z >> 6).wrapping_mul(0x1b)
}

fn mix_columns(x: u32) -> u32 {
    let y = mul_by_x(x) ^ x.rotate_right(16);
    y ^ (x ^ y).rotate_right(8)
}

fn inv_mix_columns(x: u32) -> u32 {
    let y = mul_by_x2(x);
    mix_columns(x ^ y ^ y.rotate_right(16))
}

fn subshift(input: &[u32; 4], pos: usize) -> u32 {
    (sbox((input[pos] & 0xff) as u8) as u32)
        ^ ((sbox(((input[(pos + 1) % 4] >> 8) & 0xff) as u8) as u32) << 8)
        ^ ((sbox(((input[(pos + 2) % 4] >> 16) & 0xff) as u8) as u32) << 16)
        ^ ((sbox(((input[(pos + 3) % 4] >> 24) & 0xff) as u8) as u32) << 24)
}

fn inv_subshift(input: &[u32; 4], pos: usize) -> u32 {
    (inv_sbox((input[pos] & 0xff) as u8) as u32)
        ^ ((inv_sbox(((input[(pos + 3) % 4] >> 8) & 0xff) as u8) as u32) << 8)
        ^ ((inv_sbox(((input[(pos + 2) % 4] >> 16) & 0xff) as u8) as u32) << 16)
        ^ ((inv_sbox(((input[(pos + 1) % 4] >> 24) & 0xff) as u8) as u32) << 24)
}

fn subw(input: u32) -> u32 {
    (sbox((input & 0xff) as u8) as u32)
        ^ ((sbox(((input >> 8) & 0xff) as u8) as u32) << 8)
        ^ ((sbox(((input >> 16) & 0xff) as u8) as u32) << 16)
        ^ ((sbox(((input >> 24) & 0xff) as u8) as u32) << 24)
}

/// `get_unaligned_le32()`.
///
/// # Safety
/// `p` must be readable for 4 bytes.
unsafe fn get_le32(p: *const u8) -> u32 {
    // SAFETY: caller guarantees 4 readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(p, 4) };
    u32::from_le_bytes(bytes.try_into().unwrap())
}

/// `put_unaligned_le32()`.
///
/// # Safety
/// `p` must be writable for 4 bytes.
unsafe fn put_le32(v: u32, p: *mut u8) {
    // SAFETY: caller guarantees 4 writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 4) };
}

kernel::kabi_export! {
    aes_expandkey,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#crypto_aes_ctx } ctx , formal_parameter pointer_type { const_type { t#u8 } } in_key , formal_parameter base_type unsigned int byte_size(4) encoding(7) key_len ) -> base_type int byte_size(4) encoding(5)",
}

/// `aes_expandkey()`: expand a raw AES key into the round-key schedule, per
/// FIPS-197.
///
/// # Safety
/// `ctx` must be valid and writable; `in_key` readable for `key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn aes_expandkey(ctx: *mut CryptoAesCtx, in_key: *const u8, key_len: u32) -> c_int {
    if key_len != 16 && key_len != 24 && key_len != 32 {
        return -EINVAL;
    }

    // SAFETY: the caller guarantees a valid, writable `ctx`.
    let ctx = unsafe { &mut *ctx };
    ctx.key_length = key_len;
    let kwords = (key_len / 4) as usize;

    for i in 0..kwords {
        // SAFETY: `i < kwords` and `kwords * 4 == key_len`, so this is
        // within the caller-guaranteed `key_len` readable bytes.
        ctx.key_enc[i] = unsafe { get_le32(in_key.add(i * 4)) };
    }

    let mut rc: u32 = 1;
    let mut i = 0usize;
    while i < 10 {
        let rki_base = i * kwords;
        let rko_base = rki_base + kwords;
        let rki_last = ctx.key_enc[rki_base + kwords - 1];

        ctx.key_enc[rko_base] = subw(rki_last).rotate_right(8) ^ rc ^ ctx.key_enc[rki_base];
        ctx.key_enc[rko_base + 1] = ctx.key_enc[rko_base] ^ ctx.key_enc[rki_base + 1];
        ctx.key_enc[rko_base + 2] = ctx.key_enc[rko_base + 1] ^ ctx.key_enc[rki_base + 2];
        ctx.key_enc[rko_base + 3] = ctx.key_enc[rko_base + 2] ^ ctx.key_enc[rki_base + 3];

        if key_len == 24 {
            if i >= 7 {
                break;
            }
            ctx.key_enc[rko_base + 4] = ctx.key_enc[rko_base + 3] ^ ctx.key_enc[rki_base + 4];
            ctx.key_enc[rko_base + 5] = ctx.key_enc[rko_base + 4] ^ ctx.key_enc[rki_base + 5];
        } else if key_len == 32 {
            if i >= 6 {
                break;
            }
            ctx.key_enc[rko_base + 4] = subw(ctx.key_enc[rko_base + 3]) ^ ctx.key_enc[rki_base + 4];
            ctx.key_enc[rko_base + 5] = ctx.key_enc[rko_base + 4] ^ ctx.key_enc[rki_base + 5];
            ctx.key_enc[rko_base + 6] = ctx.key_enc[rko_base + 5] ^ ctx.key_enc[rki_base + 6];
            ctx.key_enc[rko_base + 7] = ctx.key_enc[rko_base + 6] ^ ctx.key_enc[rki_base + 7];
        }

        i += 1;
        rc = mul_by_x(rc);
    }

    // Generate the decryption keys for the Equivalent Inverse Cipher:
    // reverse the round-key order, and apply Inverse Mix Columns to all
    // but the first and last. `key_len` here is a BYTE count used to index
    // a u32 array -- see the module doc comment: this is FIPS-197's own
    // schedule-size arithmetic, not a translation error.
    let kl = key_len as usize;
    ctx.key_dec[0] = ctx.key_enc[kl + 24];
    ctx.key_dec[1] = ctx.key_enc[kl + 25];
    ctx.key_dec[2] = ctx.key_enc[kl + 26];
    ctx.key_dec[3] = ctx.key_enc[kl + 27];

    let mut i = 4usize;
    let mut j = kl + 20;
    while j > 0 {
        ctx.key_dec[i] = inv_mix_columns(ctx.key_enc[j]);
        ctx.key_dec[i + 1] = inv_mix_columns(ctx.key_enc[j + 1]);
        ctx.key_dec[i + 2] = inv_mix_columns(ctx.key_enc[j + 2]);
        ctx.key_dec[i + 3] = inv_mix_columns(ctx.key_enc[j + 3]);
        i += 4;
        j -= 4;
    }

    ctx.key_dec[i] = ctx.key_enc[0];
    ctx.key_dec[i + 1] = ctx.key_enc[1];
    ctx.key_dec[i + 2] = ctx.key_enc[2];
    ctx.key_dec[i + 3] = ctx.key_enc[3];

    0
}

kernel::kabi_export! {
    aes_encrypt,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#crypto_aes_ctx } } ctx , formal_parameter pointer_type { t#u8 } out , formal_parameter pointer_type { const_type { t#u8 } } in ) -> base_type void",
}

/// `aes_encrypt()`: encrypt one 16-byte block.
///
/// # Safety
/// `ctx` must be valid; `in_` readable for 16 bytes; `out` writable for 16
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn aes_encrypt(ctx: *const CryptoAesCtx, out: *mut u8, in_: *const u8) {
    // SAFETY: the caller guarantees a valid `ctx`.
    let ctx = unsafe { &*ctx };
    let rounds = 6 + ctx.key_length / 4;
    let mut rkp = 4usize;

    let mut st0 = [0u32; 4];
    let mut st1 = [0u32; 4];

    for k in 0..4 {
        // SAFETY: the caller guarantees `in_` readable for 16 bytes.
        st0[k] = ctx.key_enc[k] ^ unsafe { get_le32(in_.add(k * 4)) };
    }

    // Force data-independent Sbox references up front, pulling the whole
    // table into cache before any data-dependent lookup -- see the C's own
    // comment, reproduced as-is.
    st0[0] ^= sbox(0) as u32 ^ sbox(64) as u32 ^ sbox(134) as u32 ^ sbox(195) as u32;
    st0[1] ^= sbox(16) as u32 ^ sbox(82) as u32 ^ sbox(158) as u32 ^ sbox(221) as u32;
    st0[2] ^= sbox(32) as u32 ^ sbox(96) as u32 ^ sbox(160) as u32 ^ sbox(234) as u32;
    st0[3] ^= sbox(48) as u32 ^ sbox(112) as u32 ^ sbox(186) as u32 ^ sbox(241) as u32;

    let mut round = 0u32;
    loop {
        st1[0] = mix_columns(subshift(&st0, 0)) ^ ctx.key_enc[rkp];
        st1[1] = mix_columns(subshift(&st0, 1)) ^ ctx.key_enc[rkp + 1];
        st1[2] = mix_columns(subshift(&st0, 2)) ^ ctx.key_enc[rkp + 2];
        st1[3] = mix_columns(subshift(&st0, 3)) ^ ctx.key_enc[rkp + 3];

        if round == rounds - 2 {
            break;
        }

        st0[0] = mix_columns(subshift(&st1, 0)) ^ ctx.key_enc[rkp + 4];
        st0[1] = mix_columns(subshift(&st1, 1)) ^ ctx.key_enc[rkp + 5];
        st0[2] = mix_columns(subshift(&st1, 2)) ^ ctx.key_enc[rkp + 6];
        st0[3] = mix_columns(subshift(&st1, 3)) ^ ctx.key_enc[rkp + 7];

        round += 2;
        rkp += 8;
    }

    for k in 0..4 {
        let v = subshift(&st1, k) ^ ctx.key_enc[rkp + 4 + k];
        // SAFETY: the caller guarantees `out` writable for 16 bytes.
        unsafe { put_le32(v, out.add(k * 4)) };
    }
}

kernel::kabi_export! {
    aes_decrypt,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#crypto_aes_ctx } } ctx , formal_parameter pointer_type { t#u8 } out , formal_parameter pointer_type { const_type { t#u8 } } in ) -> base_type void",
}

/// `aes_decrypt()`: decrypt one 16-byte block.
///
/// # Safety
/// `ctx` must be valid; `in_` readable for 16 bytes; `out` writable for 16
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn aes_decrypt(ctx: *const CryptoAesCtx, out: *mut u8, in_: *const u8) {
    // SAFETY: the caller guarantees a valid `ctx`.
    let ctx = unsafe { &*ctx };
    let rounds = 6 + ctx.key_length / 4;
    let mut rkp = 4usize;

    let mut st0 = [0u32; 4];
    let mut st1 = [0u32; 4];

    for k in 0..4 {
        // SAFETY: the caller guarantees `in_` readable for 16 bytes.
        st0[k] = ctx.key_dec[k] ^ unsafe { get_le32(in_.add(k * 4)) };
    }

    st0[0] ^= inv_sbox(0) as u32 ^ inv_sbox(64) as u32 ^ inv_sbox(129) as u32 ^ inv_sbox(200) as u32;
    st0[1] ^= inv_sbox(16) as u32 ^ inv_sbox(83) as u32 ^ inv_sbox(150) as u32 ^ inv_sbox(212) as u32;
    st0[2] ^= inv_sbox(32) as u32 ^ inv_sbox(96) as u32 ^ inv_sbox(160) as u32 ^ inv_sbox(236) as u32;
    st0[3] ^= inv_sbox(48) as u32 ^ inv_sbox(112) as u32 ^ inv_sbox(187) as u32 ^ inv_sbox(247) as u32;

    let mut round = 0u32;
    loop {
        st1[0] = inv_mix_columns(inv_subshift(&st0, 0)) ^ ctx.key_dec[rkp];
        st1[1] = inv_mix_columns(inv_subshift(&st0, 1)) ^ ctx.key_dec[rkp + 1];
        st1[2] = inv_mix_columns(inv_subshift(&st0, 2)) ^ ctx.key_dec[rkp + 2];
        st1[3] = inv_mix_columns(inv_subshift(&st0, 3)) ^ ctx.key_dec[rkp + 3];

        if round == rounds - 2 {
            break;
        }

        st0[0] = inv_mix_columns(inv_subshift(&st1, 0)) ^ ctx.key_dec[rkp + 4];
        st0[1] = inv_mix_columns(inv_subshift(&st1, 1)) ^ ctx.key_dec[rkp + 5];
        st0[2] = inv_mix_columns(inv_subshift(&st1, 2)) ^ ctx.key_dec[rkp + 6];
        st0[3] = inv_mix_columns(inv_subshift(&st1, 3)) ^ ctx.key_dec[rkp + 7];

        round += 2;
        rkp += 8;
    }

    for k in 0..4 {
        let v = inv_subshift(&st1, k) ^ ctx.key_dec[rkp + 4 + k];
        // SAFETY: the caller guarantees `out` writable for 16 bytes.
        unsafe { put_le32(v, out.add(k * 4)) };
    }
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "s#crypto_aes_ctx",
    "structure_type crypto_aes_ctx { member array_type[60] { t#u32 } key_enc data_member_location(0) , member array_type[60] { t#u32 } key_dec data_member_location(240) , member t#u32 key_length data_member_location(480) } byte_size(484)");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
