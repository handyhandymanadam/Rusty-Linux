// SPDX-License-Identifier: GPL-2.0-or-later

//! SHA-3 (Keccak) -- the Rust behind `crypto/sha3_generic.c`.
//!
//! Ported from `crypto/sha3_generic.c` (6.18.49), SHA-3 code by Jeff Garzik
//! and Ard Biesheuvel, as specified in NIST FIPS 202.
//!
//! Replaces: crypto/sha3_generic.c
//!
//! # What is here and what stayed in C (`sha3_glue.c`)
//!
//! Here: the Keccak-f[1600] permutation (`keccakf`, 24 rounds, the round
//! constants), the sponge absorb loop (`update`), and padding, final absorb
//! and squeeze (`finup`), plus zeroing the state (`init`).
//!
//! In C: `struct shash_alg algs[]`, `module_init`/`module_exit`,
//! `MODULE_*`, and the three entry functions. They fetch the context with
//! `shash_desc_ctx()` and the rate/digest sizes with
//! `crypto_shash_blocksize()`/`crypto_shash_digestsize()`, `static inline`
//! accessors over Kconfig-dependent structs (`struct shash_desc`,
//! `struct crypto_tfm`), then call the functions below. `crypto_sha3_init` is
//! `EXPORT_SYMBOL` (not `_GPL`) and stays a C entry: its CRC then comes from
//! the C, the way `logs/c-entry-rule.md` says (the shape of `crypto/md5.c`).
//!
//! # The round is the C's straight-line code, on purpose
//!
//! The Theta/Rho-Pi/Chi lines are the C's, transliterated mechanically
//! (`rol64(x, n)` -> `x.rotate_left(n)`). A table-driven loop would be
//! shorter but then nothing ties the index tables to the C. Instead,
//! `logs/proofs/keccak-round.py` parses THIS file's `keccakf_round` and
//! proves with Z3 that it equals the FIPS 202 definition of one round for
//! every one of the 2^1600 states, and that the 24 round constants are the
//! ones the spec's LFSR generates.
//!
//! # Preconditions, kept from the C
//!
//! `update` is called by the shash layer only with `len >= rsiz`
//! (`CRYPTO_AHASH_ALG_BLOCK_ONLY`); like the C it absorbs at least one block
//! (do-while) and returns the unprocessed remainder. `finup` is called with
//! `len < rsiz`. The C writes past its stack buffer if that is violated; the
//! Rust panics instead (logs/deviations.md).

use core::ptr;

const KECCAK_ROUNDS: usize = 24;
/// `SHA3_224_BLOCK_SIZE`, the largest rate (200 - 2 * 28).
const MAX_RATE: usize = 144;

static KECCAKF_RNDC: [u64; KECCAK_ROUNDS] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// One round of Keccak-f[1600] minus Iota (`keccakf_round()`).
#[inline(always)]
fn keccakf_round(st: &mut [u64; 25]) {

    let mut t = [0u64; 5];
    let mut bc = [0u64; 5];

    // Theta
    bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
    bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
    bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
    bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
    bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

    t[0] = bc[4] ^ (bc[1]).rotate_left(1);
    t[1] = bc[0] ^ (bc[2]).rotate_left(1);
    t[2] = bc[1] ^ (bc[3]).rotate_left(1);
    t[3] = bc[2] ^ (bc[4]).rotate_left(1);
    t[4] = bc[3] ^ (bc[0]).rotate_left(1);

    st[0] ^= t[0];

    // Rho Pi
    let tt = st[1];
    st[1] = (st[6] ^ t[1]).rotate_left(44);
    st[6] = (st[9] ^ t[4]).rotate_left(20);
    st[9] = (st[22] ^ t[2]).rotate_left(61);
    st[22] = (st[14] ^ t[4]).rotate_left(39);
    st[14] = (st[20] ^ t[0]).rotate_left(18);
    st[20] = (st[2] ^ t[2]).rotate_left(62);
    st[2] = (st[12] ^ t[2]).rotate_left(43);
    st[12] = (st[13] ^ t[3]).rotate_left(25);
    st[13] = (st[19] ^ t[4]).rotate_left(8);
    st[19] = (st[23] ^ t[3]).rotate_left(56);
    st[23] = (st[15] ^ t[0]).rotate_left(41);
    st[15] = (st[4] ^ t[4]).rotate_left(27);
    st[4] = (st[24] ^ t[4]).rotate_left(14);
    st[24] = (st[21] ^ t[1]).rotate_left(2);
    st[21] = (st[8] ^ t[3]).rotate_left(55);
    st[8] = (st[16] ^ t[1]).rotate_left(45);
    st[16] = (st[5] ^ t[0]).rotate_left(36);
    st[5] = (st[3] ^ t[3]).rotate_left(28);
    st[3] = (st[18] ^ t[3]).rotate_left(21);
    st[18] = (st[17] ^ t[2]).rotate_left(15);
    st[17] = (st[11] ^ t[1]).rotate_left(10);
    st[11] = (st[7] ^ t[2]).rotate_left(6);
    st[7] = (st[10] ^ t[0]).rotate_left(3);
    st[10] = (tt ^ t[1]).rotate_left(1);

    // Chi
    bc[0] = !st[1] & st[2];
    bc[1] = !st[2] & st[3];
    bc[2] = !st[3] & st[4];
    bc[3] = !st[4] & st[0];
    bc[4] = !st[0] & st[1];
    st[0] ^= bc[0];
    st[1] ^= bc[1];
    st[2] ^= bc[2];
    st[3] ^= bc[3];
    st[4] ^= bc[4];

    bc[0] = !st[6] & st[7];
    bc[1] = !st[7] & st[8];
    bc[2] = !st[8] & st[9];
    bc[3] = !st[9] & st[5];
    bc[4] = !st[5] & st[6];
    st[5] ^= bc[0];
    st[6] ^= bc[1];
    st[7] ^= bc[2];
    st[8] ^= bc[3];
    st[9] ^= bc[4];

    bc[0] = !st[11] & st[12];
    bc[1] = !st[12] & st[13];
    bc[2] = !st[13] & st[14];
    bc[3] = !st[14] & st[10];
    bc[4] = !st[10] & st[11];
    st[10] ^= bc[0];
    st[11] ^= bc[1];
    st[12] ^= bc[2];
    st[13] ^= bc[3];
    st[14] ^= bc[4];

    bc[0] = !st[16] & st[17];
    bc[1] = !st[17] & st[18];
    bc[2] = !st[18] & st[19];
    bc[3] = !st[19] & st[15];
    bc[4] = !st[15] & st[16];
    st[15] ^= bc[0];
    st[16] ^= bc[1];
    st[17] ^= bc[2];
    st[18] ^= bc[3];
    st[19] ^= bc[4];

    bc[0] = !st[21] & st[22];
    bc[1] = !st[22] & st[23];
    bc[2] = !st[23] & st[24];
    bc[3] = !st[24] & st[20];
    bc[4] = !st[20] & st[21];
    st[20] ^= bc[0];
    st[21] ^= bc[1];
    st[22] ^= bc[2];
    st[23] ^= bc[3];
    st[24] ^= bc[4];

}

/// `keccakf()`: all 24 rounds.
fn keccakf(st: &mut [u64; 25]) {
    for round in 0..KECCAK_ROUNDS {
        keccakf_round(st);
        // Iota
        st[0] ^= KECCAKF_RNDC[round];
    }
}

/// `memzero_explicit()`: volatile writes, like every other port here, so the
/// compiler cannot drop the zeroing of a buffer about to die.
fn memzero_explicit(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8`.
        unsafe { ptr::write_volatile(b, 0) };
    }
}

/// `crypto_sha3_init()`'s body: `memset(sctx->st, 0, sizeof(sctx->st))`.
///
/// # Safety
/// `st` points to a writable `u64[25]` (`struct sha3_state`'s `st`).
#[no_mangle]
pub unsafe extern "C" fn crypto_sha3_rs_init(st: *mut u64) {
    // SAFETY: caller contract.
    unsafe { ptr::write_bytes(st, 0, 25) };
}

/// `crypto_sha3_update()`'s body: absorb whole `rsiz`-byte blocks, return the
/// number of bytes left over.
///
/// Like the C this is a do-while: the first block is absorbed before `len` is
/// looked at, so `len >= rsiz` is the caller's contract.
///
/// # Safety
/// `st` points to a writable, aligned `u64[25]`; `data` is readable for `len`
/// bytes (it need not be aligned); `rsiz` is the algorithm's block size, a
/// multiple of 8 and at most `MAX_RATE`.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha3_rs_update(
    st: *mut u64,
    mut data: *const u8,
    mut len: u32,
    rsiz: u32,
) -> u32 {
    // SAFETY: caller contract (aligned `u64[25]`, exclusively ours).
    let st = unsafe { &mut *(st as *mut [u64; 25]) };
    let rsizw = (rsiz / 8) as usize;

    loop {
        for i in 0..rsizw {
            // SAFETY: caller contract: a whole block is readable at `data`.
            let w = unsafe { ptr::read_unaligned(data.add(8 * i) as *const u64) };
            st[i] ^= u64::from_le(w);
        }
        keccakf(st);

        // SAFETY: still inside (or one past) the caller's buffer.
        data = unsafe { data.add(rsiz as usize) };
        // The C subtracts unsigned and relies on len >= rsiz.
        len = len.wrapping_sub(rsiz);
        if len < rsiz {
            break;
        }
    }
    len
}

/// `crypto_sha3_finup()`'s body: pad `src[..len]` (domain bits 0x06, final
/// 0x80), absorb, permute, and write `digest_size` bytes to `out`.
///
/// # Safety
/// `st` points to a writable, aligned `u64[25]`; `src` is readable for `len`
/// bytes with `len < rsiz`; `out` is writable for `digest_size` bytes (it
/// need not be aligned); `rsiz` is a multiple of 8, at most `MAX_RATE`, and
/// `digest_size` is 28, 32, 48 or 64.
#[no_mangle]
pub unsafe extern "C" fn crypto_sha3_rs_finup(
    st: *mut u64,
    src: *const u8,
    len: u32,
    out: *mut u8,
    digest_size: u32,
    rsiz: u32,
) {
    // SAFETY: caller contract.
    let st = unsafe { &mut *(st as *mut [u64; 25]) };
    let mut block = [0u8; MAX_RATE];
    let len = len as usize;
    let rsiz = rsiz as usize;
    let rsizw = rsiz / 8;

    if len > 0 {
        // SAFETY: caller contract: `src` is readable for `len` bytes.
        let s = unsafe { core::slice::from_raw_parts(src, len) };
        block[..len].copy_from_slice(s);
    }
    block[len] = 0x06;
    block[rsiz - 1] |= 0x80;

    for i in 0..rsizw {
        let mut w = [0u8; 8];
        w.copy_from_slice(&block[8 * i..8 * i + 8]);
        st[i] ^= u64::from_le_bytes(w);
    }
    memzero_explicit(&mut block);

    keccakf(st);

    let full = (digest_size / 8) as usize;
    for i in 0..full {
        // SAFETY: `out` is writable for `digest_size` bytes (caller contract).
        unsafe { ptr::write_unaligned(out.add(8 * i) as *mut u64, st[i].to_le()) };
    }
    if digest_size & 4 != 0 {
        // SAFETY: as above; the trailing 4 bytes of a 28-byte digest.
        unsafe { ptr::write_unaligned(out.add(8 * full) as *mut u32, (st[full] as u32).to_le()) };
    }
}
