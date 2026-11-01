// SPDX-License-Identifier: GPL-2.0

//! The directory-hash functions of `fs/ext4/hash.c` -- the Rust behind them.
//!
//! Ported from `fs/ext4/hash.c` (6.18.49): `TEA_transform()`, `half_md4_transform()`, the two "dx hack" legacy hashes, the two `str2hashbuf` packers (signed and unsigned characters),
//! and the dispatch of `__ext4fs_dirhash()` for the legacy, half-MD4 and TEA hash versions with their signed / unsigned flavours. In C (`hash_glue.c`): `ext4fs_dirhash()` with the
//! casefold path, the siphash version (fscrypt), the invalid-version warning, and the final masking of the hash and the htree end-of-file adjustment.
//!
//! The arithmetic is 32-bit and wraps (the kernel is built with `-fwrapv`); characters are sign-extended for the signed versions exactly as C's `signed char` is.
//!
//! Replaces: fs/ext4/hash.c (the hash algorithms)

use core::ffi::{c_char, c_int};

const DELTA: u32 = 0x9E37_79B9;

const DX_HASH_LEGACY: c_int = 0;
const DX_HASH_HALF_MD4: c_int = 1;
const DX_HASH_TEA: c_int = 2;
const DX_HASH_LEGACY_UNSIGNED: c_int = 3;
const DX_HASH_HALF_MD4_UNSIGNED: c_int = 4;
const DX_HASH_TEA_UNSIGNED: c_int = 5;

/// `TEA_transform()`.
fn tea_transform(buf: &mut [u32; 4], inp: &[u32; 4]) {
    let mut sum: u32 = 0;
    let mut b0 = buf[0];
    let mut b1 = buf[1];
    let (a, b, c, d) = (inp[0], inp[1], inp[2], inp[3]);

    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add((b1 << 4).wrapping_add(a) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(b));
        b1 = b1.wrapping_add((b0 << 4).wrapping_add(c) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(d));
    }

    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

#[inline(always)]
fn f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}
#[inline(always)]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y).wrapping_add((x ^ y) & z)
}
#[inline(always)]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

const K1: u32 = 0;
const K2: u32 = 0o13240474631;
const K3: u32 = 0o15666365641;

/// `half_md4_transform()`.
fn half_md4_transform(buf: &mut [u32; 4], inp: &[u32; 8]) {
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);

    macro_rules! round {
        ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:expr) => {
            $a = $a.wrapping_add($f($b, $c, $d)).wrapping_add($x);
            $a = $a.rotate_left($s);
        };
    }

    // Round 1
    round!(f, a, b, c, d, inp[0].wrapping_add(K1), 3);
    round!(f, d, a, b, c, inp[1].wrapping_add(K1), 7);
    round!(f, c, d, a, b, inp[2].wrapping_add(K1), 11);
    round!(f, b, c, d, a, inp[3].wrapping_add(K1), 19);
    round!(f, a, b, c, d, inp[4].wrapping_add(K1), 3);
    round!(f, d, a, b, c, inp[5].wrapping_add(K1), 7);
    round!(f, c, d, a, b, inp[6].wrapping_add(K1), 11);
    round!(f, b, c, d, a, inp[7].wrapping_add(K1), 19);

    // Round 2
    round!(g, a, b, c, d, inp[1].wrapping_add(K2), 3);
    round!(g, d, a, b, c, inp[3].wrapping_add(K2), 5);
    round!(g, c, d, a, b, inp[5].wrapping_add(K2), 9);
    round!(g, b, c, d, a, inp[7].wrapping_add(K2), 13);
    round!(g, a, b, c, d, inp[0].wrapping_add(K2), 3);
    round!(g, d, a, b, c, inp[2].wrapping_add(K2), 5);
    round!(g, c, d, a, b, inp[4].wrapping_add(K2), 9);
    round!(g, b, c, d, a, inp[6].wrapping_add(K2), 13);

    // Round 3
    round!(h, a, b, c, d, inp[3].wrapping_add(K3), 3);
    round!(h, d, a, b, c, inp[7].wrapping_add(K3), 9);
    round!(h, c, d, a, b, inp[2].wrapping_add(K3), 11);
    round!(h, b, c, d, a, inp[6].wrapping_add(K3), 15);
    round!(h, a, b, c, d, inp[1].wrapping_add(K3), 3);
    round!(h, d, a, b, c, inp[5].wrapping_add(K3), 9);
    round!(h, c, d, a, b, inp[0].wrapping_add(K3), 11);
    round!(h, b, c, d, a, inp[4].wrapping_add(K3), 15);

    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

/// The character at `i` as C's `(int)` of a `signed char` or an `unsigned char`, as a 32-bit word.
#[inline(always)]
unsafe fn ch(name: *const c_char, i: usize, signed: bool) -> u32 {
    // SAFETY: the caller keeps `i` inside the name.
    let b = unsafe { *(name as *const u8).add(i) };
    if signed {
        b as i8 as i32 as u32
    } else {
        b as u32
    }
}

/// `dx_hack_hash_signed()` / `dx_hack_hash_unsigned()`.
unsafe fn dx_hack_hash(name: *const c_char, len: c_int, signed: bool) -> u32 {
    let mut hash0: u32 = 0x12a3fe2d;
    let mut hash1: u32 = 0x37abe8f9;
    let mut i = 0usize;
    let mut len = len;

    while len != 0 {
        len -= 1;
        // SAFETY: `i` is below the original `len`.
        let c = unsafe { ch(name, i, signed) };
        i += 1;
        let mut hash = hash1.wrapping_add(hash0 ^ c.wrapping_mul(7152373));
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    hash0 << 1
}

/// `str2hashbuf_signed()` / `str2hashbuf_unsigned()`: pack up to `num * 4` characters into `num` words, padded with the length byte pattern.
unsafe fn str2hashbuf(msg: *const c_char, len: c_int, buf: &mut [u32], num: c_int, signed: bool) {
    let mut len = len;
    let mut num = num;
    let mut pad: u32 = (len as u32) | ((len as u32) << 8);
    pad |= pad << 16;
    let mut val = pad;
    let mut out = 0usize;

    if len > num * 4 {
        len = num * 4;
    }
    let mut i = 0usize;
    while (i as c_int) < len {
        // SAFETY: `i` is below `len`, which is at most the message length.
        val = unsafe { ch(msg, i, signed) }.wrapping_add(val << 8);
        if i % 4 == 3 {
            buf[out] = val;
            out += 1;
            val = pad;
            num -= 1;
        }
        i += 1;
    }
    num -= 1;
    if num >= 0 {
        buf[out] = val;
        out += 1;
    }
    loop {
        num -= 1;
        if num < 0 {
            break;
        }
        buf[out] = pad;
        out += 1;
    }
}

/// The hash of `__ext4fs_dirhash()` for the legacy, half-MD4 and TEA versions: stores the hash and the minor hash before the final masking. `seed` may be NULL. Returns 0, or -1 for a
/// version this function does not handle.
///
/// # Safety
/// `name` is valid for `len` bytes; `seed` is NULL or four words; `hash` and `minor_hash` are valid for writes.
#[no_mangle]
pub unsafe extern "C" fn rust_ext4_dirhash(version: c_int, name: *const c_char, len: c_int, seed: *const u32, hash: *mut u32, minor_hash: *mut u32) -> c_int {
    // SAFETY: as the contract says.
    unsafe {
        let mut buf: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        let mut inp = [0u32; 8];

        // Check to see if the seed is all zero's
        if !seed.is_null() {
            for i in 0..4 {
                if *seed.add(i) != 0 {
                    for k in 0..4 {
                        buf[k] = *seed.add(k);
                    }
                    break;
                }
            }
        }

        let mut len = len;
        let mut p = name;
        match version {
            DX_HASH_LEGACY_UNSIGNED => {
                *hash = dx_hack_hash(name, len, false);
                *minor_hash = 0;
            }
            DX_HASH_LEGACY => {
                *hash = dx_hack_hash(name, len, true);
                *minor_hash = 0;
            }
            DX_HASH_HALF_MD4_UNSIGNED | DX_HASH_HALF_MD4 => {
                let signed = version == DX_HASH_HALF_MD4;
                while len > 0 {
                    str2hashbuf(p, len, &mut inp, 8, signed);
                    half_md4_transform(&mut buf, &inp);
                    len -= 32;
                    p = p.add(32);
                }
                *minor_hash = buf[2];
                *hash = buf[1];
            }
            DX_HASH_TEA_UNSIGNED | DX_HASH_TEA => {
                let signed = version == DX_HASH_TEA;
                while len > 0 {
                    str2hashbuf(p, len, &mut inp, 4, signed);
                    let words = [inp[0], inp[1], inp[2], inp[3]];
                    tea_transform(&mut buf, &words);
                    len -= 16;
                    p = p.add(16);
                }
                *hash = buf[0];
                *minor_hash = buf[1];
            }
            _ => return -1,
        }
        0
    }
}
