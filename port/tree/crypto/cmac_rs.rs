// SPDX-License-Identifier: GPL-2.0-or-later

//! The byte-level logic of `crypto/cmac.c` (CMAC, NIST SP 800-38B).
//!
//! Ported from `crypto/cmac.c` (6.18.49), Copyright (c) 2013 Jussi Kivilinna
//! (based on work by Tom St Denis and Kazunori Miyazawa). Two pieces of that
//! file are pure byte arithmetic and are here:
//!
//! * `cmac_rs_derive_subkeys()`: the body of the `switch (bs)` in
//!   `crypto_cmac_digest_setkey()`. On entry `consts[0..bs]` holds the cipher's
//!   encryption of the zero block (L); on exit `consts[0..bs]` is K1 = L * x and
//!   `consts[bs..2*bs]` is K2 = L * x^2, in GF(2^128) (`bs == 16`, reduction
//!   constant 0x87) or GF(2^64) (`bs == 8`, 0x1B), big endian. Any other `bs`
//!   leaves `consts` alone, like the C (which has no `default:`; the crypto
//!   API's template refuses every other block size).
//! * `cmac_rs_finup_xor()`: the part of `crypto_cmac_digest_finup()` before the
//!   last cipher call: `prev ^= src[0..len]`; when `len != bs`, `prev[len] ^=
//!   0x80` and K2 is used instead of K1; `prev ^= K`.
//!
//! What stays C (`crypto/cmac_glue.c`, upstream's file with just these two
//! blocks replaced): every `crypto_cipher_*` call, the per-block loop of
//! `crypto_cmac_digest_update()`, and the shash_alg / template / instance /
//! `module_init` plumbing over Kconfig-dependent structs.
//!
//! In-contract (the C relies on it, the crypto API guarantees it): `bs` is 8 or
//! 16, `len <= bs` in finup, `prev` has `bs` bytes, `consts` has `2 * bs`
//! bytes. The C with `len > bs` would write past `prev`; this file clamps `len`
//! to `bs` instead (no memory outside `prev[0..bs]`, `src[0..len]`,
//! `consts[0..2*bs]` is ever touched). No messages.
//!
//! Replaces: the subkey derivation and the final-block xor in crypto/cmac.c

use core::ffi::c_uint;

/// Double a 64-bit big-endian field element: `(v << 1) ^ (0x1B if the top bit was set)`.
#[inline(always)]
fn dbl64(v: u64, poly: u8) -> u64 {
    // the C: msb_mask = ((s64)v >> 63) & gfmask  (all ones or zero, masked to the u8 constant)
    let msb_mask = (((v as i64) >> 63) as u8) & poly;
    (v << 1) ^ (msb_mask as u64)
}

/// Derive K1 and K2 in place from the encrypted zero block in `consts[0..bs]`.
///
/// # Safety
/// `consts` points to `2 * bs` writable bytes when `bs` is 8 or 16 (any other `bs`: nothing is
/// accessed); `consts[0..bs]` is initialised.
#[no_mangle]
pub unsafe extern "C" fn cmac_rs_derive_subkeys(consts: *mut u8, bs: c_uint) {
    // SAFETY (both arms): the offsets written are 0..2*bs, the caller's `2 * bs` bytes; reads are 0..bs.
    unsafe {
        match bs {
            16 => {
                // 128-bit value hi:lo, big endian: the C's _const[1] (high) and _const[0] (low)
                let mut hi = u64::from_be((consts as *const u64).read_unaligned());
                let mut lo = u64::from_be((consts.add(8) as *const u64).read_unaligned());
                let mut i = 0usize;
                // gf(2^128) multiply zero-ciphertext with u and u^2
                while i < 2 {
                    let msb_mask = (((hi as i64) >> 63) as u8) & 0x87;
                    hi = (hi << 1) | (lo >> 63);
                    lo = (lo << 1) ^ (msb_mask as u64);
                    (consts.add(16 * i) as *mut u64).write_unaligned(hi.to_be());
                    (consts.add(16 * i + 8) as *mut u64).write_unaligned(lo.to_be());
                    i += 1;
                }
            }
            8 => {
                let mut v = u64::from_be((consts as *const u64).read_unaligned());
                let mut i = 0usize;
                // gf(2^64) multiply zero-ciphertext with u and u^2
                while i < 2 {
                    v = dbl64(v, 0x1B);
                    (consts.add(8 * i) as *mut u64).write_unaligned(v.to_be());
                    i += 1;
                }
            }
            _ => {}
        }
    }
}

/// The final-block xor of `crypto_cmac_digest_finup()`, up to (not including) the cipher call.
///
/// # Safety
/// `prev` has `bs` writable bytes, `src` has `len` readable bytes (`len <= bs`; larger is clamped),
/// `consts` has `2 * bs` readable bytes, none overlapping `prev`.
#[no_mangle]
pub unsafe extern "C" fn cmac_rs_finup_xor(
    prev: *mut u8,
    src: *const u8,
    len: c_uint,
    consts: *const u8,
    bs: c_uint,
) {
    let bs = bs as usize;
    let len = core::cmp::min(len as usize, bs);
    let mut offset = 0usize;

    // SAFETY: prev[0..bs], src[0..len] (len <= bs), consts[0..2*bs]; prev[len] only when len < bs.
    unsafe {
        let mut i = 0;
        while i < len {
            *prev.add(i) ^= *src.add(i);
            i += 1;
        }
        if len != bs {
            *prev.add(len) ^= 0x80;
            offset += bs;
        }
        let mut i = 0;
        while i < bs {
            *prev.add(i) ^= *consts.add(offset + i);
            i += 1;
        }
    }
}

/// Kani proofs (`cd rig/cmac-kani && cargo kani`; inert in the kernel build): with buffers of EXACTLY the
/// contract sizes, no access outside them and no panic, for every content, every `len` (also `len > bs`,
/// which is clamped), and the results are the specification.
#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(20)]
    fn subkeys_16_in_bounds() {
        let mut c: [u8; 32] = kani::any();
        let l = c;
        unsafe { cmac_rs_derive_subkeys(c.as_mut_ptr(), 16) };
        let top = l[0] >> 7;
        // K1 = L << 1 (^ 0x87 in the last byte when the top bit was set)
        let mut i = 0;
        while i < 15 {
            assert!(c[i] == (l[i] << 1) | (l[i + 1] >> 7));
            i += 1;
        }
        assert!(c[15] == (l[15] << 1) ^ (if top == 1 { 0x87 } else { 0 }));
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn subkeys_8_in_bounds() {
        let mut c: [u8; 16] = kani::any();
        let l = c;
        unsafe { cmac_rs_derive_subkeys(c.as_mut_ptr(), 8) };
        let mut i = 0;
        while i < 7 {
            assert!(c[i] == (l[i] << 1) | (l[i + 1] >> 7));
            i += 1;
        }
        assert!(c[7] == (l[7] << 1) ^ (if l[0] >> 7 == 1 { 0x1B } else { 0 }));
    }

    #[kani::proof]
    fn subkeys_other_bs_untouched() {
        let mut c: [u8; 8] = kani::any();
        let l = c;
        let bs: c_uint = kani::any();
        kani::assume(bs != 8 && bs != 16);
        unsafe { cmac_rs_derive_subkeys(c.as_mut_ptr(), bs) };
        assert!(c == l);
    }

    macro_rules! finup {
        ($name:ident, $bs:expr) => {
            #[kani::proof]
            #[kani::unwind(20)]
            fn $name() {
                let mut prev: [u8; $bs] = kani::any();
                let p0 = prev;
                let consts: [u8; 2 * $bs] = kani::any();
                let src: [u8; $bs] = kani::any();
                let len: c_uint = kani::any();
                kani::assume(len as usize <= $bs);
                unsafe { cmac_rs_finup_xor(prev.as_mut_ptr(), src.as_ptr(), len, consts.as_ptr(), $bs) };
                let off = if len as usize == $bs { 0 } else { $bs };
                let mut i = 0;
                while i < $bs {
                    let mut e = p0[i];
                    if i < len as usize { e ^= src[i]; }
                    if i == len as usize { e ^= 0x80; }
                    e ^= consts[off + i];
                    assert!(prev[i] == e);
                    i += 1;
                }
            }
        };
    }
    finup!(finup_8, 8);
    finup!(finup_16, 16);

    /// `len > bs` (out of contract) is clamped: never reads past a `bs`-byte `src` nor writes past `prev`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn finup_len_above_bs_clamped() {
        let mut prev: [u8; 8] = kani::any();
        let consts: [u8; 16] = kani::any();
        let src: [u8; 8] = kani::any();
        let len: c_uint = kani::any();
        unsafe { cmac_rs_finup_xor(prev.as_mut_ptr(), src.as_ptr(), len, consts.as_ptr(), 8) };
    }
}
