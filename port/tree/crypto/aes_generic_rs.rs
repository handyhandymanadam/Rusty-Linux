// SPDX-License-Identifier: GPL-2.0-or-later

//! Generic T-table AES block cipher -- the Rust behind `crypto/aes_generic.c`.
//!
//! Ported from `crypto/aes_generic.c` (6.18.49), based on Brian Gladman's code,
//! Copyright (c) 2002, Dr Brian Gladman <brg@gladman.me.uk>, Worcester, UK
//! (dual BSD / GPL; the C file's licence text is kept in `aes_generic_glue.c`).
//!
//! Replaces: crypto/aes_generic.c
//!
//! # What is here, what stayed C
//!
//! Here: the block encrypt and decrypt (`f_rn`/`f_nround`/`f_rl` and
//! `i_rn`/`i_nround`/`i_rl` of the C, with the same structure: unaligned
//! little-endian loads of the four state words xor the first round key, two
//! extra rounds when `key_len > 24`, two more when `key_len > 16`, nine normal
//! rounds, then the last round with the `fl`/`il` tables), and the two tables
//! only the last round uses, `crypto_fl_tab` and `crypto_il_tab` (private,
//! `static` in the C). Those two are NOT literals here: they are built at compile
//! time (`const fn`) from the FIPS-197 definition of the S-box (multiplicative
//! inverse in GF(2^8) mod x^8+x^4+x^3+x+1, then the affine transform) and its
//! inverse. `fl[k][x] = S[x] << 8k`, `il[k][x] = Si[x] << 8k`.
//!
//! In C (`aes_generic_glue.c`): `crypto_ft_tab` and `crypto_it_tab`
//! (`EXPORT_SYMBOL_GPL` DATA, kept byte-identical to upstream; this file reads
//! them through `extern` statics, they are const data), `crypto_aes_set_key`
//! (`EXPORT_SYMBOL_GPL`; it fetches the context with `crypto_tfm_ctx()`, a
//! static inline over the Kconfig-dependent `struct crypto_tfm`, and calls the
//! already-ported `aes_expandkey()`), the two one-line callbacks that fetch the
//! context and call `crypto_aes_rs_encrypt`/`crypto_aes_rs_decrypt` below, the
//! `crypto_alg` table, `module_init`/`module_exit` and `MODULE_*`. Rust mirrors
//! neither `struct crypto_tfm` nor `struct crypto_alg`.
//!
//! # `key_length` values `aes_expandkey()` never writes
//!
//! The C copies `ctx->key_length` into an `int` and tests `> 24` and `> 16`;
//! that is reproduced exactly (`key_length as i32`). Whatever the value, the
//! round count is 10, 12 or 14 and the highest key word read is `key_enc[59]`
//! (14 rounds: `4 + 13*4 + 3`), so for EVERY `u32` value of `key_length` the
//! C's pointer walk stays inside `key_enc`/`key_dec` (60 words). There is
//! therefore no out-of-bounds hazard to guard and no divergence from the C:
//! `key_length <= 16` (including 0 and values that are negative as an `int`)
//! runs 10 rounds, 17..=24 runs 12, `> 24` runs 14. Indexing into the key
//! arrays stays CHECKED (`rig/uaccess-panic-check.sh`): it cannot fire, and if
//! the round structure were ever edited wrongly it would panic rather than read
//! out of bounds.
//!
//! # Not constant-time
//!
//! T-table AES is data-dependent table lookups: not cache-timing safe, in C or
//! Rust, exactly as upstream (which is why `lib/crypto/aes.c` carries the
//! volatile-sbox hardening and this file does not).
//!
//! # Memory
//!
//! `out` may equal `in` (the C reads all four input words before writing the
//! first output word; so does this). Partial overlap is not supported by either.

use core::ptr;

const AES_MAX_KEYLENGTH_U32: usize = 60;

/// Mirrors `struct crypto_aes_ctx` (`include/crypto/aes.h`), same layout as
/// `lib/crypto/aes_rs.rs`.
#[repr(C)]
pub struct CryptoAesCtx {
    /// The encryption round-key schedule.
    pub key_enc: [u32; AES_MAX_KEYLENGTH_U32],
    /// The decryption round-key schedule (the Equivalent Inverse Cipher).
    pub key_dec: [u32; AES_MAX_KEYLENGTH_U32],
    /// The key length, in bytes (16, 24, or 32).
    pub key_length: u32,
}

// {u32 key_enc[60]; u32 key_dec[60]; u32 key_length;} = 484 bytes, align 4.
const _: () = assert!(core::mem::size_of::<CryptoAesCtx>() == 484);
const _: () = assert!(core::mem::align_of::<CryptoAesCtx>() == 4);

extern "C" {
    // crypto/aes_generic_glue.c: `__visible const u32 [4][256] ____cacheline_aligned`,
    // EXPORT_SYMBOL_GPL. Const data, never written.
    static crypto_ft_tab: [[u32; 256]; 4];
    static crypto_it_tab: [[u32; 256]; 4];
}

// ---------------------------------------------------------------------------
// FIPS-197 S-box and its inverse, built at compile time.

/// Multiply by x in GF(2^8) mod x^8 + x^4 + x^3 + x + 1 (0x11b).
const fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

/// Multiplication in GF(2^8) mod 0x11b (shift-and-add).
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

/// Multiplicative inverse (0 maps to 0): `a^254`, because the group of units
/// has order 255. `254 = 2 + 4 + 8 + 16 + 32 + 64 + 128`.
const fn ginv(a: u8) -> u8 {
    let mut sq = gmul(a, a); // a^2
    let mut r = sq;
    let mut i = 0;
    while i < 6 {
        sq = gmul(sq, sq); // a^4 .. a^128
        r = gmul(r, sq);
        i += 1;
    }
    r
}

/// The FIPS-197 S-box: inverse, then `b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^
/// rotl(b,4) ^ 0x63` (section 5.1.1, equation 5.2).
const fn sbox_of(x: u8) -> u8 {
    let b = ginv(x);
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

/// The FIPS-197 inverse S-box: the inverse affine transform
/// (`rotl(s,1) ^ rotl(s,3) ^ rotl(s,6) ^ 0x05`, section 5.3.2, equation 5.14),
/// then the inverse in GF(2^8).
const fn inv_sbox_of(s: u8) -> u8 {
    ginv(s.rotate_left(1) ^ s.rotate_left(3) ^ s.rotate_left(6) ^ 0x05)
}

const fn build_sbox() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = sbox_of(i as u8);
        i += 1;
    }
    t
}

const fn build_inv_sbox() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = inv_sbox_of(i as u8);
        i += 1;
    }
    t
}

/// `tab[k][x] = sbox[x] << 8k`: what `crypto_fl_tab` / `crypto_il_tab` hold
/// (the last round has no MixColumns, so each lookup is the S-box byte moved to
/// the position the next stage expects).
const fn build_last_round(sbox: &[u8; 256]) -> [[u32; 256]; 4] {
    let mut t = [[0u32; 256]; 4];
    let mut k = 0;
    while k < 4 {
        let mut x = 0;
        while x < 256 {
            t[k][x] = (sbox[x] as u32) << (8 * k);
            x += 1;
        }
        k += 1;
    }
    t
}

/// `crypto_fl_tab` and `crypto_il_tab` are `____cacheline_aligned` in the C.
#[repr(C, align(64))]
struct Table([[u32; 256]; 4]);

const SBOX: [u8; 256] = build_sbox();
const INV_SBOX: [u8; 256] = build_inv_sbox();

/// `crypto_fl_tab`.
static FL_TAB: Table = Table(build_last_round(&SBOX));
/// `crypto_il_tab`.
static IL_TAB: Table = Table(build_last_round(&INV_SBOX));

// ---------------------------------------------------------------------------

/// `byte(x, n)`: `(u8)(x >> (n << 3))`.
#[inline(always)]
fn byte(x: u32, n: u32) -> usize {
    ((x >> (n << 3)) & 0xff) as usize
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
    unsafe { ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 4) };
}

/// `f_rn(bo, bi, n, k)`: one output word of a normal encryption round.
#[inline(always)]
fn f_rn(bi: &[u32; 4], n: usize, k: u32) -> u32 {
    // SAFETY: reading const data defined in aes_generic_glue.c.
    let ft = unsafe { &crypto_ft_tab };
    ft[0][byte(bi[n], 0)]
        ^ ft[1][byte(bi[(n + 1) & 3], 1)]
        ^ ft[2][byte(bi[(n + 2) & 3], 2)]
        ^ ft[3][byte(bi[(n + 3) & 3], 3)]
        ^ k
}

/// `f_rl(bo, bi, n, k)`: one output word of the last encryption round.
#[inline(always)]
fn f_rl(bi: &[u32; 4], n: usize, k: u32) -> u32 {
    let fl = &FL_TAB.0;
    fl[0][byte(bi[n], 0)]
        ^ fl[1][byte(bi[(n + 1) & 3], 1)]
        ^ fl[2][byte(bi[(n + 2) & 3], 2)]
        ^ fl[3][byte(bi[(n + 3) & 3], 3)]
        ^ k
}

/// `i_rn(bo, bi, n, k)`: one output word of a normal decryption round.
#[inline(always)]
fn i_rn(bi: &[u32; 4], n: usize, k: u32) -> u32 {
    // SAFETY: reading const data defined in aes_generic_glue.c.
    let it = unsafe { &crypto_it_tab };
    it[0][byte(bi[n], 0)]
        ^ it[1][byte(bi[(n + 3) & 3], 1)]
        ^ it[2][byte(bi[(n + 2) & 3], 2)]
        ^ it[3][byte(bi[(n + 1) & 3], 3)]
        ^ k
}

/// `i_rl(bo, bi, n, k)`: one output word of the last decryption round.
#[inline(always)]
fn i_rl(bi: &[u32; 4], n: usize, k: u32) -> u32 {
    let il = &IL_TAB.0;
    il[0][byte(bi[n], 0)]
        ^ il[1][byte(bi[(n + 3) & 3], 1)]
        ^ il[2][byte(bi[(n + 2) & 3], 2)]
        ^ il[3][byte(bi[(n + 1) & 3], 3)]
        ^ k
}

/// `f_nround`: `bo = round(bi)` with the next four key words; advances `kp`.
#[inline(always)]
fn f_nround(bi: &[u32; 4], ks: &[u32; AES_MAX_KEYLENGTH_U32], kp: &mut usize) -> [u32; 4] {
    let bo = [
        f_rn(bi, 0, ks[*kp]),
        f_rn(bi, 1, ks[*kp + 1]),
        f_rn(bi, 2, ks[*kp + 2]),
        f_rn(bi, 3, ks[*kp + 3]),
    ];
    *kp += 4;
    bo
}

/// `f_lround` (no `kp` advance, as in the C).
#[inline(always)]
fn f_lround(bi: &[u32; 4], ks: &[u32; AES_MAX_KEYLENGTH_U32], kp: usize) -> [u32; 4] {
    [
        f_rl(bi, 0, ks[kp]),
        f_rl(bi, 1, ks[kp + 1]),
        f_rl(bi, 2, ks[kp + 2]),
        f_rl(bi, 3, ks[kp + 3]),
    ]
}

/// `i_nround`.
#[inline(always)]
fn i_nround(bi: &[u32; 4], ks: &[u32; AES_MAX_KEYLENGTH_U32], kp: &mut usize) -> [u32; 4] {
    let bo = [
        i_rn(bi, 0, ks[*kp]),
        i_rn(bi, 1, ks[*kp + 1]),
        i_rn(bi, 2, ks[*kp + 2]),
        i_rn(bi, 3, ks[*kp + 3]),
    ];
    *kp += 4;
    bo
}

/// `i_lround`.
#[inline(always)]
fn i_lround(bi: &[u32; 4], ks: &[u32; AES_MAX_KEYLENGTH_U32], kp: usize) -> [u32; 4] {
    [
        i_rl(bi, 0, ks[kp]),
        i_rl(bi, 1, ks[kp + 1]),
        i_rl(bi, 2, ks[kp + 2]),
        i_rl(bi, 3, ks[kp + 3]),
    ]
}

/// `crypto_aes_encrypt()`'s body: encrypt one 16-byte block.
///
/// # Safety
/// `ctx` must be valid; `in_` readable for 16 bytes; `out` writable for 16
/// bytes (they may be the same pointer).
#[no_mangle]
pub unsafe extern "C" fn crypto_aes_rs_encrypt(ctx: *const CryptoAesCtx, out: *mut u8, in_: *const u8) {
    // SAFETY: the caller guarantees a valid `ctx`.
    let ctx = unsafe { &*ctx };
    let ks = &ctx.key_enc;
    let mut kp = 4usize;
    // `const int key_len = ctx->key_length;`
    let key_len = ctx.key_length as i32;

    // SAFETY: the caller guarantees `in_` readable for 16 bytes.
    let mut b0 = unsafe {
        [
            ks[0] ^ get_le32(in_),
            ks[1] ^ get_le32(in_.add(4)),
            ks[2] ^ get_le32(in_.add(8)),
            ks[3] ^ get_le32(in_.add(12)),
        ]
    };
    let mut b1;

    if key_len > 24 {
        b1 = f_nround(&b0, ks, &mut kp);
        b0 = f_nround(&b1, ks, &mut kp);
    }

    if key_len > 16 {
        b1 = f_nround(&b0, ks, &mut kp);
        b0 = f_nround(&b1, ks, &mut kp);
    }

    b1 = f_nround(&b0, ks, &mut kp);
    b0 = f_nround(&b1, ks, &mut kp);
    b1 = f_nround(&b0, ks, &mut kp);
    b0 = f_nround(&b1, ks, &mut kp);
    b1 = f_nround(&b0, ks, &mut kp);
    b0 = f_nround(&b1, ks, &mut kp);
    b1 = f_nround(&b0, ks, &mut kp);
    b0 = f_nround(&b1, ks, &mut kp);
    b1 = f_nround(&b0, ks, &mut kp);
    b0 = f_lround(&b1, ks, kp);

    // SAFETY: the caller guarantees `out` writable for 16 bytes.
    unsafe {
        put_le32(b0[0], out);
        put_le32(b0[1], out.add(4));
        put_le32(b0[2], out.add(8));
        put_le32(b0[3], out.add(12));
    }
}

/// `crypto_aes_decrypt()`'s body: decrypt one 16-byte block.
///
/// # Safety
/// `ctx` must be valid; `in_` readable for 16 bytes; `out` writable for 16
/// bytes (they may be the same pointer).
#[no_mangle]
pub unsafe extern "C" fn crypto_aes_rs_decrypt(ctx: *const CryptoAesCtx, out: *mut u8, in_: *const u8) {
    // SAFETY: the caller guarantees a valid `ctx`.
    let ctx = unsafe { &*ctx };
    let ks = &ctx.key_dec;
    let mut kp = 4usize;
    let key_len = ctx.key_length as i32;

    // SAFETY: the caller guarantees `in_` readable for 16 bytes.
    let mut b0 = unsafe {
        [
            ks[0] ^ get_le32(in_),
            ks[1] ^ get_le32(in_.add(4)),
            ks[2] ^ get_le32(in_.add(8)),
            ks[3] ^ get_le32(in_.add(12)),
        ]
    };
    let mut b1;

    if key_len > 24 {
        b1 = i_nround(&b0, ks, &mut kp);
        b0 = i_nround(&b1, ks, &mut kp);
    }

    if key_len > 16 {
        b1 = i_nround(&b0, ks, &mut kp);
        b0 = i_nround(&b1, ks, &mut kp);
    }

    b1 = i_nround(&b0, ks, &mut kp);
    b0 = i_nround(&b1, ks, &mut kp);
    b1 = i_nround(&b0, ks, &mut kp);
    b0 = i_nround(&b1, ks, &mut kp);
    b1 = i_nround(&b0, ks, &mut kp);
    b0 = i_nround(&b1, ks, &mut kp);
    b1 = i_nround(&b0, ks, &mut kp);
    b0 = i_nround(&b1, ks, &mut kp);
    b1 = i_nround(&b0, ks, &mut kp);
    b0 = i_lround(&b1, ks, kp);

    // SAFETY: the caller guarantees `out` writable for 16 bytes.
    unsafe {
        put_le32(b0[0], out);
        put_le32(b0[1], out.add(4));
        put_le32(b0[2], out.add(8));
        put_le32(b0[3], out.add(12));
    }
}
