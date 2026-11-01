// SPDX-License-Identifier: GPL-2.0-or-later

//! The chaining loops of `crypto/cbc.c` (CBC mode over an lskcipher).
//!
//! Ported from `crypto/cbc.c` (6.18.49), (C) 2006-2016 Herbert Xu. What is here, one function per upstream loop:
//!
//! * `cbc_rs_encrypt_segment()` (`crypto_cbc_encrypt_segment`, `dst != src`): per block `iv ^= src`,
//!   `dst = E(iv)`, `iv = dst`.
//! * `cbc_rs_encrypt_inplace()` (`dst == src`): per block `src ^= iv`, `src = E(src)`, the next
//!   chaining value is the block just written; the original IV buffer gets the last ciphertext block.
//! * `cbc_rs_decrypt_segment()`: per block `dst = D(src)`, `dst ^= iv`, the next chaining value is the
//!   source block just read; the IV buffer gets the last source block.
//! * `cbc_rs_decrypt_inplace()`: walks the blocks BACKWARDS from the last whole one (so the previous
//!   ciphertext block is still intact when it is xored in), saves the last ciphertext block first and
//!   hands it back as the new IV.
//!
//! All four return the remainder (`nbytes` modulo `bsize` for in-contract input), as the C does.
//!
//! What stays C (`crypto/cbc_glue.c`, upstream's file with exactly those four bodies replaced by calls):
//! the `crypto_cbc_encrypt` / `crypto_cbc_decrypt` dispatch (FINAL flag, in-place test, `-EINVAL` for a
//! remainder), the template, the instance creation and `module_init`, all over Kconfig-dependent
//! `lskcipher` structs that are never mirrored here. The block cipher is reached through the opaque
//! `cipher(tfm, src, dst, len)` callback (two one-line C wrappers over `crypto_lskcipher_encrypt` /
//! `_decrypt` with a NULL IV, return value ignored as upstream does).
//!
//! In contract (the C relies on it): `bsize` is a power of two not above `MAX_CIPHER_BLOCKSIZE` (16),
//! checked by the template (`is_power_of_2`) and by `crypto_check_alg`. Out of contract the C either
//! never terminates (`bsize == 0`) or overruns its 16-byte stack IV copy (`bsize > 16`); here
//! `bsize == 0` or `bsize > 16` touches nothing and returns `nbytes`, and the in-place decrypt start
//! offset uses `nbytes % bsize` (equal to the C's `nbytes & (bsize - 1)` for a power of two, in bounds
//! for any other size). No messages.
//!
//! Replaces: the four chaining loops of crypto/cbc.c

use core::ffi::{c_uint, c_void};

/// `void (*)(void *tfm, const u8 *src, u8 *dst, unsigned len)`: encrypt/decrypt `len` (= one) block(s); supplied by the C glue.
pub type Cipher = unsafe extern "C" fn(*mut c_void, *const u8, *mut u8, c_uint);

/// `MAX_CIPHER_BLOCKSIZE` (include/crypto/algapi.h).
const MAX_CIPHER_BLOCKSIZE: c_uint = 16;

/// `crypto_xor(dst, src, n)`: `dst[i] ^= src[i]`.
#[inline(always)]
unsafe fn xor_in_place(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        // SAFETY: caller: dst and src have n bytes.
        unsafe { *dst.add(i) ^= *src.add(i) };
        i += 1;
    }
}

/// Out-of-contract sizes: nothing is touched.
#[inline(always)]
fn bad_bsize(bsize: c_uint) -> bool {
    bsize == 0 || bsize > MAX_CIPHER_BLOCKSIZE
}

/// CBC encrypt, `dst != src`: returns the remainder.
///
/// # Safety
/// `iv` has `bsize` read-write bytes; `src` has `nbytes` readable bytes and `dst` `nbytes` writable bytes (disjoint
/// from `src` and `iv`); `cipher` encrypts one `bsize` block `src -> dst` (the two may be the same block).
#[no_mangle]
pub unsafe extern "C" fn cbc_rs_encrypt_segment(
    tfm: *mut c_void,
    cipher: Cipher,
    bsize: c_uint,
    mut src: *const u8,
    mut dst: *mut u8,
    mut nbytes: c_uint,
    iv: *mut u8,
) -> c_uint {
    if bad_bsize(bsize) {
        return nbytes;
    }
    // SAFETY: the loop runs only while a whole block is left (nbytes >= bsize), so each pass reads one source
    // block, writes one destination block inside the caller's nbytes, and `nbytes -= bsize` cannot underflow.
    unsafe {
        while nbytes >= bsize {
            xor_in_place(iv, src, bsize as usize);
            cipher(tfm, iv, dst, bsize);
            core::ptr::copy_nonoverlapping(dst, iv, bsize as usize);
            src = src.add(bsize as usize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;
        }
    }
    nbytes
}

/// CBC encrypt in place: returns the remainder; `oiv` receives the last ciphertext block.
///
/// # Safety
/// `src` has `nbytes` read-write bytes, `oiv` `bsize` read-write bytes (disjoint); `cipher` encrypts one block
/// `src -> dst` (the two may be the same block).
#[no_mangle]
pub unsafe extern "C" fn cbc_rs_encrypt_inplace(
    tfm: *mut c_void,
    cipher: Cipher,
    bsize: c_uint,
    mut src: *mut u8,
    mut nbytes: c_uint,
    oiv: *mut u8,
) -> c_uint {
    if bad_bsize(bsize) || nbytes < bsize {
        return nbytes;
    }
    let mut iv: *const u8 = oiv;
    // SAFETY: nbytes >= bsize on entry and the loop continues only while the remainder is >= bsize, so each pass
    // handles one whole block inside the caller's nbytes; `iv` is `oiv` or the block just written (inside src).
    unsafe {
        loop {
            xor_in_place(src, iv, bsize as usize);
            cipher(tfm, src, src, bsize);
            iv = src;
            src = src.add(bsize as usize);
            nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
        }
        core::ptr::copy(iv, oiv, bsize as usize);
    }
    nbytes
}

/// CBC decrypt, `dst != src`: returns the remainder; `oiv` receives the last source (ciphertext) block.
///
/// # Safety
/// As `cbc_rs_encrypt_segment`, `oiv` has `bsize` read-write bytes, `src` is not modified; `cipher` decrypts one
/// block `src -> dst`.
#[no_mangle]
pub unsafe extern "C" fn cbc_rs_decrypt_segment(
    tfm: *mut c_void,
    cipher: Cipher,
    bsize: c_uint,
    mut src: *const u8,
    mut dst: *mut u8,
    mut nbytes: c_uint,
    oiv: *mut u8,
) -> c_uint {
    if bad_bsize(bsize) || nbytes < bsize {
        return nbytes;
    }
    let mut iv: *const u8 = oiv;
    // SAFETY: as in cbc_rs_encrypt_inplace; `iv` is `oiv` or the source block just read.
    unsafe {
        loop {
            cipher(tfm, src, dst, bsize);
            xor_in_place(dst, iv, bsize as usize);
            iv = src;
            src = src.add(bsize as usize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
        }
        core::ptr::copy(iv, oiv, bsize as usize);
    }
    nbytes
}

/// CBC decrypt in place, last block first: returns the remainder; `iv` receives the last ciphertext block.
///
/// # Safety
/// `src` has `nbytes` read-write bytes, `iv` `bsize` read-write bytes (disjoint); `cipher` decrypts one block
/// `src -> dst` (the two may be the same block).
#[no_mangle]
pub unsafe extern "C" fn cbc_rs_decrypt_inplace(
    tfm: *mut c_void,
    cipher: Cipher,
    bsize: c_uint,
    mut src: *mut u8,
    mut nbytes: c_uint,
    iv: *mut u8,
) -> c_uint {
    if bad_bsize(bsize) || nbytes < bsize {
        return nbytes;
    }
    let mut last_iv = [0u8; MAX_CIPHER_BLOCKSIZE as usize];
    // SAFETY: nbytes >= bsize > 0, so `nbytes - nbytes % bsize - bsize` is the offset of the last whole block
    // (<= nbytes - bsize); every later step moves back one block while at least one more whole block remains
    // (`nbytes >= bsize` after the subtraction), so `src - bsize` stays inside the caller's buffer.
    unsafe {
        // Start of the last block. `nbytes - nbytes % bsize` is a multiple of bsize that is >= bsize (nbytes >= bsize),
        // so the subtractions cannot wrap; wrapping_sub keeps the overflow panic path (and its link dependency) out.
        src = src.add(nbytes.wrapping_sub(nbytes % bsize).wrapping_sub(bsize) as usize);
        core::ptr::copy_nonoverlapping(src, last_iv.as_mut_ptr(), bsize as usize);
        loop {
            cipher(tfm, src, src, bsize);
            nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
            xor_in_place(src, src.sub(bsize as usize), bsize as usize);
            src = src.sub(bsize as usize);
        }
        xor_in_place(src, iv, bsize as usize);
        core::ptr::copy_nonoverlapping(last_iv.as_ptr(), iv, bsize as usize);
    }
    nbytes
}

/// Kani proofs (`cd rig/cbc-kani && cargo kani`; inert in the kernel build). Buffers have EXACTLY the contract
/// sizes, so any access outside them is reported; the cipher is a Rust function that reads/writes exactly one
/// 4-byte block (an invertible byte map, so a CBC round trip can be asserted).
#[cfg(kani)]
mod proofs {
    use super::*;

    unsafe extern "C" fn enc4(_t: *mut c_void, src: *const u8, dst: *mut u8, len: c_uint) {
        assert!(len == 4);
        let mut t = [0u8; 4];
        let mut i = 0;
        while i < 4 {
            t[i] = (*src.add(i)).wrapping_add(i as u8 * 3 + 1) ^ 0x5a;
            i += 1;
        }
        i = 0;
        while i < 4 {
            *dst.add(i) = t[i];
            i += 1;
        }
    }
    unsafe extern "C" fn dec4(_t: *mut c_void, src: *const u8, dst: *mut u8, len: c_uint) {
        assert!(len == 4);
        let mut t = [0u8; 4];
        let mut i = 0;
        while i < 4 {
            t[i] = (*src.add(i) ^ 0x5a).wrapping_sub(i as u8 * 3 + 1);
            i += 1;
        }
        i = 0;
        while i < 4 {
            *dst.add(i) = t[i];
            i += 1;
        }
    }

    macro_rules! enc_seg {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(10)]
            fn $name() {
                let src: [u8; $n] = kani::any();
                let mut dst: [u8; $n] = kani::any();
                let mut iv: [u8; 4] = kani::any();
                let r = unsafe { cbc_rs_encrypt_segment(core::ptr::null_mut(), enc4, 4, src.as_ptr(), dst.as_mut_ptr(), $n, iv.as_mut_ptr()) };
                assert!(r == $n % 4);
            }
        };
    }
    enc_seg!(enc_segment_3, 3);
    enc_seg!(enc_segment_4, 4);
    enc_seg!(enc_segment_11, 11);

    macro_rules! enc_inp {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(10)]
            fn $name() {
                let mut buf: [u8; $n] = kani::any();
                let mut iv: [u8; 4] = kani::any();
                let r = unsafe { cbc_rs_encrypt_inplace(core::ptr::null_mut(), enc4, 4, buf.as_mut_ptr(), $n, iv.as_mut_ptr()) };
                assert!(r == $n % 4);
            }
        };
    }
    enc_inp!(enc_inplace_3, 3);
    enc_inp!(enc_inplace_4, 4);
    enc_inp!(enc_inplace_11, 11);

    macro_rules! dec_seg {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(10)]
            fn $name() {
                let src: [u8; $n] = kani::any();
                let mut dst: [u8; $n] = kani::any();
                let mut iv: [u8; 4] = kani::any();
                let r = unsafe { cbc_rs_decrypt_segment(core::ptr::null_mut(), dec4, 4, src.as_ptr(), dst.as_mut_ptr(), $n, iv.as_mut_ptr()) };
                assert!(r == $n % 4);
            }
        };
    }
    dec_seg!(dec_segment_3, 3);
    dec_seg!(dec_segment_4, 4);
    dec_seg!(dec_segment_11, 11);

    macro_rules! dec_inp {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(10)]
            fn $name() {
                let mut buf: [u8; $n] = kani::any();
                let mut iv: [u8; 4] = kani::any();
                let r = unsafe { cbc_rs_decrypt_inplace(core::ptr::null_mut(), dec4, 4, buf.as_mut_ptr(), $n, iv.as_mut_ptr()) };
                assert!(r == $n % 4);
            }
        };
    }
    dec_inp!(dec_inplace_3, 3);
    dec_inp!(dec_inplace_4, 4);
    dec_inp!(dec_inplace_11, 11);

    /// Round trip: decrypt-in-place of encrypt-in-place gives the plaintext and the same IV, for symbolic data and IV.
    #[kani::proof]
    #[kani::unwind(10)]
    fn roundtrip_inplace_8() {
        let orig: [u8; 8] = kani::any();
        let mut buf = orig;
        let iv0: [u8; 4] = kani::any();
        let mut ive = iv0;
        let mut ivd = iv0;
        unsafe {
            cbc_rs_encrypt_inplace(core::ptr::null_mut(), enc4, 4, buf.as_mut_ptr(), 8, ive.as_mut_ptr());
            cbc_rs_decrypt_inplace(core::ptr::null_mut(), dec4, 4, buf.as_mut_ptr(), 8, ivd.as_mut_ptr());
        }
        assert!(buf == orig);
        assert!(ive == ivd);
    }

    /// Out-of-contract block sizes touch nothing and return nbytes.
    #[kani::proof]
    #[kani::unwind(3)]
    fn out_of_contract_is_noop() {
        let n: c_uint = kani::any();
        let bs: c_uint = kani::any();
        kani::assume(bs == 0 || bs > 16);
        let mut z: [u8; 1] = [0];
        let mut iv: [u8; 1] = [0];
        let r1 = unsafe { cbc_rs_encrypt_segment(core::ptr::null_mut(), enc4, bs, z.as_ptr(), z.as_mut_ptr(), n, iv.as_mut_ptr()) };
        let r2 = unsafe { cbc_rs_decrypt_inplace(core::ptr::null_mut(), dec4, bs, z.as_mut_ptr(), n, iv.as_mut_ptr()) };
        let r3 = unsafe { cbc_rs_encrypt_inplace(core::ptr::null_mut(), enc4, bs, z.as_mut_ptr(), n, iv.as_mut_ptr()) };
        let r4 = unsafe { cbc_rs_decrypt_segment(core::ptr::null_mut(), dec4, bs, z.as_ptr(), z.as_mut_ptr(), n, iv.as_mut_ptr()) };
        assert!(r1 == n && r2 == n && r3 == n && r4 == n);
        assert!(z[0] == 0 && iv[0] == 0);
    }
}
