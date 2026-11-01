// SPDX-License-Identifier: GPL-2.0-or-later

//! The byte-level logic of `crypto/ctr.c` (CTR mode, RFC 3686 counter block).
//!
//! Ported from `crypto/ctr.c` (6.18.49), (C) Copyright IBM Corp. 2007 - Joy
//! Latten. What is here:
//!
//! * `ctr_rs_crypt_segment()` / `ctr_rs_crypt_inplace()`: the do-while block
//!   loops of `crypto_ctr_crypt_segment()` / `_inplace()`: keystream =
//!   encrypt(counter block); xor it into the data; `crypto_inc()` the counter;
//!   advance one block; `while ((nbytes -= bsize) >= bsize)`; return the
//!   remainder. `segment` writes the keystream straight into `dst` and xors
//!   `src` over it, `inplace` (dst == src) uses a keystream buffer.
//! * `ctr_rs_crypt_final()`: the last partial block of `crypto_ctr_crypt_final()`:
//!   one keystream block, `nbytes < bsize` of it xored into `dst`, one counter
//!   increment.
//! * `ctr_rs_rfc3686_iv()`: the counter block of `crypto_rfc3686_crypt()`:
//!   `nonce[4] || req_iv[8] || be32(1)`.
//!
//! What stays C (`crypto/ctr_glue.c`, upstream's file with exactly these
//! blocks replaced): everything over `struct skcipher_walk`,
//! `skcipher_request`, `crypto_cipher` and the templates (Kconfig-dependent
//! layouts, never mirrored here), the stack keystream buffer and its
//! `PTR_ALIGN` to the cipher's alignmask (a contract with the cipher callback:
//! the C allocates it and passes the aligned pointer), the rfc3686 setkey
//! (its only work is an `-EINVAL` length test and a 4-byte copy), and the
//! cipher calls, which Rust makes through the opaque `enc(tfm, dst, src)`
//! callback the glue passes (two one-line C wrappers: the raw `cia_encrypt` for
//! the loops, `crypto_cipher_encrypt_one` for the final block, as upstream).
//!
//! `crypto_inc()` (exported by `crypto/algapi.c`, big-endian counter
//! increment) is called, not duplicated. `crypto_xor()`/`crypto_xor_cpy()`
//! are static inlines in `include/crypto/utils.h` (word-wise or byte-wise,
//! same result); the Rust is a byte xor.
//!
//! In contract (the C relies on it): `bsize` is a multiple of 4 (the template
//! checks), the segment/inplace loops start with `nbytes >= bsize` (the walk
//! gives whole blocks), the final block has `nbytes < bsize`. Out of contract
//! the C runs a block past the data (and, with `nbytes < bsize`, wraps the
//! unsigned remainder and runs on); here `segment`/`inplace` with
//! `nbytes < bsize` or `bsize == 0` do nothing and return `nbytes`, and `final`
//! clamps `nbytes` to `bsize`. No messages.
//!
//! Replaces: the block loops and the counter-block construction of crypto/ctr.c

use core::ffi::{c_uint, c_void};

/// `void (*)(void *tfm, u8 *dst, const u8 *src)`: encrypt one block; supplied by the C glue.
pub type Enc = unsafe extern "C" fn(*mut c_void, *mut u8, *const u8);

#[cfg(not(kani))]
extern "C" {
    /// `crypto/algapi.c`: big-endian increment of the `size`-byte counter at `a`.
    fn crypto_inc(a: *mut u8, size: c_uint);
}

/// Kani model of `crypto_inc` (big-endian increment, wrapping), for the proofs only.
#[cfg(kani)]
unsafe fn crypto_inc(a: *mut u8, size: c_uint) {
    let mut i = size as usize;
    while i > 0 {
        i -= 1;
        let b = (*a.add(i)).wrapping_add(1);
        *a.add(i) = b;
        if b != 0 {
            break;
        }
    }
}

const CTR_RFC3686_NONCE_SIZE: usize = 4;
const CTR_RFC3686_IV_SIZE: usize = 8;

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

/// The last, partial block: `dst[0..nbytes] = encrypt(ctrblk)[0..nbytes] ^ src[0..nbytes]`, counter + 1.
///
/// # Safety
/// `ctrblk` has `bsize` bytes, `keystream` has `bsize` writable bytes (aligned as the cipher wants),
/// `src` and `dst` have `nbytes` bytes (equal or disjoint), `enc` encrypts one block of `bsize` bytes.
#[no_mangle]
pub unsafe extern "C" fn ctr_rs_crypt_final(
    ctrblk: *mut u8,
    bsize: c_uint,
    enc: Enc,
    tfm: *mut c_void,
    keystream: *mut u8,
    src: *const u8,
    dst: *mut u8,
    nbytes: c_uint,
) {
    let n = core::cmp::min(nbytes, bsize) as usize;
    // SAFETY: per the contract above; reads/writes stay inside [0, bsize) of ctrblk/keystream and [0, n) of src/dst.
    unsafe {
        enc(tfm, keystream, ctrblk);
        let mut i = 0;
        while i < n {
            // crypto_xor_cpy(dst, keystream, src, nbytes); index-wise, so dst == src is fine
            *dst.add(i) = *keystream.add(i) ^ *src.add(i);
            i += 1;
        }
        crypto_inc(ctrblk, bsize);
    }
}

/// Whole blocks, `dst != src`: returns the remainder (`nbytes mod bsize` for in-contract input).
///
/// # Safety
/// `ctrblk` has `bsize` bytes; `src` has `nbytes` readable bytes and `dst` `nbytes` writable bytes (disjoint);
/// `enc` encrypts one block into `dst` (which has the alignment the walk gave it).
#[no_mangle]
pub unsafe extern "C" fn ctr_rs_crypt_segment(
    ctrblk: *mut u8,
    bsize: c_uint,
    enc: Enc,
    tfm: *mut c_void,
    mut src: *const u8,
    mut dst: *mut u8,
    mut nbytes: c_uint,
) -> c_uint {
    if bsize == 0 || nbytes < bsize {
        return nbytes;
    }
    // SAFETY: nbytes >= bsize on entry and the loop continues only while the remainder is >= bsize, so each
    // pass reads/writes one whole block inside the caller's nbytes.
    unsafe {
        loop {
            // create keystream
            enc(tfm, dst, ctrblk);
            xor_in_place(dst, src, bsize as usize);
            // increment counter in counterblock
            crypto_inc(ctrblk, bsize);
            src = src.add(bsize as usize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
        }
    }
    nbytes
}

/// Whole blocks, `dst == src`: keystream goes through `keystream`; returns the remainder.
///
/// # Safety
/// As `ctr_rs_crypt_segment`, with `dst` read-write and `keystream` `bsize` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ctr_rs_crypt_inplace(
    ctrblk: *mut u8,
    bsize: c_uint,
    enc: Enc,
    tfm: *mut c_void,
    keystream: *mut u8,
    mut dst: *mut u8,
    mut nbytes: c_uint,
) -> c_uint {
    if bsize == 0 || nbytes < bsize {
        return nbytes;
    }
    // SAFETY: as in segment.
    unsafe {
        loop {
            enc(tfm, keystream, ctrblk);
            xor_in_place(dst, keystream, bsize as usize);
            crypto_inc(ctrblk, bsize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
        }
    }
    nbytes
}

/// RFC 3686 counter block: `iv = nonce[0..4] || req_iv[0..8] || be32(1)`.
///
/// # Safety
/// `iv` has 16 writable bytes, `nonce` 4 and `req_iv` 8 readable bytes, none overlapping `iv`.
#[no_mangle]
pub unsafe extern "C" fn ctr_rs_rfc3686_iv(iv: *mut u8, nonce: *const u8, req_iv: *const u8) {
    // SAFETY: per the contract.
    unsafe {
        core::ptr::copy_nonoverlapping(nonce, iv, CTR_RFC3686_NONCE_SIZE);
        core::ptr::copy_nonoverlapping(req_iv, iv.add(CTR_RFC3686_NONCE_SIZE), CTR_RFC3686_IV_SIZE);
        // initialize counter portion of counter block
        let ctr = iv.add(CTR_RFC3686_NONCE_SIZE + CTR_RFC3686_IV_SIZE);
        ctr.write(0);
        ctr.add(1).write(0);
        ctr.add(2).write(0);
        ctr.add(3).write(1);
    }
}

/// Kani proofs (`cd rig/ctr-kani && cargo kani`; inert in the kernel build). Pads/buffers have EXACTLY the
/// contract sizes, so any access outside them is reported; `crypto_inc` is modelled, `enc` is a Rust function
/// that writes one whole block.
#[cfg(kani)]
mod proofs {
    use super::*;

    unsafe extern "C" fn enc_model(_t: *mut c_void, dst: *mut u8, src: *const u8) {
        // a block "cipher" of 4 bytes that reads src[0..4] and writes dst[0..4] (bsize 4 harnesses)
        let mut i = 0;
        while i < 4 {
            *dst.add(i) = (*src.add(i)).wrapping_add(i as u8 + 1);
            i += 1;
        }
    }

    macro_rules! seg {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(12)]
            fn $name() {
                let src: [u8; $n] = kani::any();
                let mut dst: [u8; $n] = kani::any();
                let mut ctr: [u8; 4] = kani::any();
                let r = unsafe {
                    ctr_rs_crypt_segment(ctr.as_mut_ptr(), 4, enc_model, core::ptr::null_mut(), src.as_ptr(), dst.as_mut_ptr(), $n)
                };
                assert!(r == $n % 4);
            }
        };
    }
    seg!(segment_4, 4);
    seg!(segment_7, 7);
    seg!(segment_12, 12);
    seg!(segment_19, 19);

    macro_rules! inp {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(12)]
            fn $name() {
                let mut dst: [u8; $n] = kani::any();
                let mut ks: [u8; 4] = kani::any();
                let mut ctr: [u8; 4] = kani::any();
                let r = unsafe {
                    ctr_rs_crypt_inplace(ctr.as_mut_ptr(), 4, enc_model, core::ptr::null_mut(), ks.as_mut_ptr(), dst.as_mut_ptr(), $n)
                };
                assert!(r == $n % 4);
            }
        };
    }
    inp!(inplace_4, 4);
    inp!(inplace_11, 11);
    inp!(inplace_16, 16);

    /// Final block: only `nbytes` bytes of dst change, for every nbytes (also out of contract: clamped).
    #[kani::proof]
    #[kani::unwind(6)]
    fn final_block() {
        let src: [u8; 3] = kani::any();
        let mut dst: [u8; 3] = kani::any();
        let mut ks: [u8; 4] = kani::any();
        let mut ctr: [u8; 4] = kani::any();
        unsafe { ctr_rs_crypt_final(ctr.as_mut_ptr(), 4, enc_model, core::ptr::null_mut(), ks.as_mut_ptr(), src.as_ptr(), dst.as_mut_ptr(), 3) };
    }

    /// Out-of-contract arguments touch nothing and return nbytes.
    #[kani::proof]
    fn out_of_contract_is_noop() {
        let n: c_uint = kani::any();
        let bs: c_uint = kani::any();
        kani::assume(bs == 0 || n < bs);
        let mut ctr: [u8; 1] = [0];
        let mut dst: [u8; 1] = [0];
        let r = unsafe { ctr_rs_crypt_inplace(ctr.as_mut_ptr(), bs, enc_model, core::ptr::null_mut(), dst.as_mut_ptr(), dst.as_mut_ptr(), n) };
        assert!(r == n);
    }

    #[kani::proof]
    fn rfc3686_block() {
        let nonce: [u8; 4] = kani::any();
        let rv: [u8; 8] = kani::any();
        let mut iv: [u8; 16] = kani::any();
        unsafe { ctr_rs_rfc3686_iv(iv.as_mut_ptr(), nonce.as_ptr(), rv.as_ptr()) };
        assert!(iv[0..4] == nonce && iv[4..12] == rv && iv[12..16] == [0, 0, 0, 1]);
    }
}
