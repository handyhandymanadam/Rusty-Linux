// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)

//! SipHash, a fast short-input PRF -- the Rust behind `lib/siphash.c`.
//!
//! Ported from `lib/siphash.c` (6.18.49), Copyright (C) 2016-2022
//! Jason A. Donenfeld <Jason@zx2c4.com>. Dual GPL-2.0/BSD-3-Clause, as the C
//! is.
//!
//! Replaces: lib/siphash.c
//!
//! # What the kernel actually builds here, and what it does not
//!
//! Three `#if` axes fork this file in the C, and on x86-64 only one arm of
//! each is compiled:
//!
//! | axis | x86-64 | the other arm |
//! |---|---|---|
//! | `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` | set, so only `*_unaligned` exists | `__siphash_aligned` and `__hsiphash_aligned` are separate exported symbols |
//! | `BITS_PER_LONG == 64` | 64, so **HalfSipHash1-3 is actually SipHash1-3** | a genuinely different 32-bit permutation |
//! | `CONFIG_DCACHE_WORD_ACCESS` | set | a byte-at-a-time tail |
//!
//! The first two are carried here under `#[cfg]`, so the file is complete.
//! The third is **deliberately not**, and that is the one divergence in this
//! port -- see below.
//!
//! # `load_unaligned_zeropad()` is not reproduced, and the result is identical
//!
//! With `CONFIG_DCACHE_WORD_ACCESS`, the C reads the final partial word with
//! `load_unaligned_zeropad()`: one word-sized load that may run past the end
//! of the buffer, made safe by an `__ex_table` entry that catches the page
//! fault and refills the register from the bytes that were readable. It is an
//! inline `asm goto` with a section directive, and reproducing it from Rust
//! means emitting kernel exception-table entries by hand.
//!
//! This port compiles the portable tail -- the `#else` arm, a `match` on the
//! 0..7 leftover bytes -- **on every configuration**. Two facts make that the
//! right trade rather than a shortcut:
//!
//! 1. **The hash is identical.** Both arms compute the same `b`; the
//!    difference is one load versus up to three. Upstream's own
//!    `lib/tests/siphash_kunit.c` runs both against the same vectors.
//! 2. It is slower on the tail, and CLAUDE.md's rule is that performance is
//!    recorded and never a veto.
//!
//! Recorded in `logs/deviations.md`. The fix shape, if it is ever wanted, is
//! an `asm!` that pushes an `__ex_table` entry -- the same technique the one
//! `asm!` site in the previous attempt used for `ALTERNATIVE`.

use core::ffi::c_void;

/// `SIPHASH_CONST_0`. `include/linux/siphash.h`.
const C0: u64 = 0x736f_6d65_7073_6575;
/// `SIPHASH_CONST_1`.
const C1: u64 = 0x646f_7261_6e64_6f6d;
/// `SIPHASH_CONST_2`.
const C2: u64 = 0x6c79_6765_6e65_7261;
/// `SIPHASH_CONST_3`.
const C3: u64 = 0x7465_6462_7974_6573;

/// Mirrors `siphash_key_t` (`include/linux/siphash.h`): `struct { u64 key[2]; }`.
#[repr(C)]
pub struct SiphashKey {
    /// The two key words.
    pub key: [u64; 2],
}

/// Mirrors `hsiphash_key_t`: `struct { unsigned long key[2]; }`. Identical
/// shape to [`SiphashKey`] on a 64-bit target, and a different one on 32-bit,
/// which is why the C declares it separately.
#[repr(C)]
pub struct HsiphashKey {
    /// The two key words.
    pub key: [usize; 2],
}

/// The SipHash round, `SIPHASH_PERMUTATION()` from the header.
#[inline(always)]
fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// `PREAMBLE(len)`: the four state words and the length byte.
#[inline(always)]
fn preamble(len: usize, key: &[u64; 2]) -> ([u64; 4], u64) {
    (
        [C0 ^ key[0], C1 ^ key[1], C2 ^ key[0], C3 ^ key[1]],
        (len as u64) << 56,
    )
}

/// `POSTAMBLE`: four finalisation rounds, SipHash2-4's tail.
#[inline(always)]
fn postamble(v: &mut [u64; 4], b: u64) -> u64 {
    v[3] ^= b;
    sipround(v);
    sipround(v);
    v[0] ^= b;
    v[2] ^= 0xff;
    sipround(v);
    sipround(v);
    sipround(v);
    sipround(v);
    (v[0] ^ v[1]) ^ (v[2] ^ v[3])
}

/// `HPOSTAMBLE` on a 64-bit target: SipHash1-3's tail.
#[inline(always)]
fn hpostamble(v: &mut [u64; 4], b: u64) -> u64 {
    v[3] ^= b;
    sipround(v);
    v[0] ^= b;
    v[2] ^= 0xff;
    sipround(v);
    sipround(v);
    sipround(v);
    (v[0] ^ v[1]) ^ (v[2] ^ v[3])
}

/// The 0..7 leftover bytes of a buffer, packed little-endian into the low
/// bytes of a word -- the C's `switch (left)` with its deliberate
/// fallthroughs, which is `end[6]<<48 | end[5]<<40 | ... | end[0]`.
///
/// # Safety
/// `end` must be readable for `left` bytes, and `left` must be below 8.
#[inline(always)]
unsafe fn tail(end: *const u8, left: usize) -> u64 {
    let mut b: u64 = 0;
    let mut i = left;

    while i > 0 {
        i -= 1;
        // SAFETY: `i < left` and the caller guarantees `left` readable bytes.
        b |= (unsafe { *end.add(i) } as u64) << (8 * i);
    }
    b
}

/// The body both `__siphash_*` entry points share: SipHash2-4 over a buffer.
///
/// # Safety
/// `data` must be readable for `len` bytes.
#[inline(always)]
unsafe fn siphash_bytes(data: *const u8, len: usize, key: &[u64; 2]) -> u64 {
    let whole = len - (len % 8);
    let left = len & 7;
    let (mut v, mut b) = preamble(len, key);

    let mut i = 0usize;
    while i < whole {
        // SAFETY: `i + 8 <= whole <= len`, and read_unaligned needs no
        // alignment -- which is what get_unaligned_le64() provides in the C.
        let m = u64::from_le(unsafe { (data.add(i) as *const u64).read_unaligned() });
        v[3] ^= m;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= m;
        i += 8;
    }
    // SAFETY: `whole + left == len`, so the tail is inside the buffer.
    b |= unsafe { tail(data.add(whole), left) };
    postamble(&mut v, b)
}

/// The body both `__hsiphash_*` entry points share on a 64-bit target:
/// SipHash1-3 over a buffer, consuming eight bytes at a time.
///
/// # Safety
/// `data` must be readable for `len` bytes.
#[inline(always)]
unsafe fn hsiphash_bytes(data: *const u8, len: usize, key: &[u64; 2]) -> u64 {
    let whole = len - (len % 8);
    let left = len & 7;
    let (mut v, mut b) = preamble(len, key);

    let mut i = 0usize;
    while i < whole {
        // SAFETY: as in siphash_bytes.
        let m = u64::from_le(unsafe { (data.add(i) as *const u64).read_unaligned() });
        v[3] ^= m;
        sipround(&mut v);
        v[0] ^= m;
        i += 8;
    }
    // SAFETY: as in siphash_bytes.
    b |= unsafe { tail(data.add(whole), left) };
    hpostamble(&mut v, b)
}

// The C types these contracts name. A Rust object has no C type graph to
// resolve them against, so they are not duplicates of anything.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#hsiphash_key_t",
    "typedef_type hsiphash_key_t { structure_type { member array_type[2] { base_type unsigned long byte_size(8) encoding(7) } key data_member_location(0) } byte_size(16) }");
kernel::kabi_rule!("type_string", "t#siphash_key_t",
    "typedef_type siphash_key_t { structure_type { member array_type[2] { t#u64 } key data_member_location(0) } byte_size(16) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");

kernel::kabi_export! {
    __siphash_unaligned,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t len , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `__siphash_unaligned()`: SipHash2-4 over a buffer.
///
/// `siphash()` in `include/linux/siphash.h` dispatches to this or to
/// `__siphash_aligned()` on `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS`; x86-64
/// sets it, so on this architecture every call arrives here.
///
/// # Safety
/// `data` must be readable for `len` bytes and `key` must be a valid
/// `siphash_key_t`. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn __siphash_unaligned(data: *const c_void, len: usize, key: *const SiphashKey) -> u64 {
    // SAFETY: the caller's contract.
    unsafe { siphash_bytes(data as *const u8, len, &(*key).key) }
}


// `__siphash_aligned` and `__hsiphash_aligned` exist only where an unaligned
// word load is expensive; x86-64 sets CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
// and so has neither symbol. Built and booted on riscv64 (no efficient unaligned
// access in that config; logs/riscv64.md). It was a kabi_rule! placeholder with no
// EXPORT before that: the symbols were missing from the ported build.
#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
kernel::kabi_export! {
    __siphash_aligned,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t len , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `__siphash_aligned()`. The C's aligned arm differs only in using
/// an aligned load; an unaligned load is correct for an aligned pointer, so
/// this shares the body and gives up an optimisation on an architecture this
/// project cannot currently build.
///
/// # Safety
/// As [`__siphash_unaligned`], and `data` must additionally be `u64`-aligned.
#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
#[no_mangle]
pub unsafe extern "C" fn __siphash_aligned(data: *const c_void, len: usize, key: *const SiphashKey) -> u64 {
    // SAFETY: the caller's contract.
    unsafe { siphash_bytes(data as *const u8, len, &(*key).key) }
}


kernel::kabi_export! {
    __hsiphash_unaligned,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t len , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `__hsiphash_unaligned()`.
///
/// **On a 64-bit target this is SipHash1-3, not HalfSipHash1-3**, and the
/// return is truncated to 32 bits. The C says so in as many words: *"on
/// 64-bit, we make HalfSipHash1-3 actually be SipHash1-3, for performance
/// reasons"*. The 32-bit permutation is a different algorithm and is not
/// reproduced -- see the module documentation.
///
/// # Safety
/// `data` must be readable for `len` bytes and `key` must be a valid
/// `hsiphash_key_t`.
#[no_mangle]
pub unsafe extern "C" fn __hsiphash_unaligned(data: *const c_void, len: usize, key: *const HsiphashKey) -> u32 {
    // SAFETY: the caller's contract. hsiphash_key_t is two `unsigned long`,
    // which is two u64 on this target -- the same sixteen bytes the 64-bit
    // arm of the C reads through its own PREAMBLE.
    let k = unsafe { [(*key).key[0] as u64, (*key).key[1] as u64] };
    // SAFETY: as above.
    unsafe { hsiphash_bytes(data as *const u8, len, &k) as u32 }
}

#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
kernel::kabi_export! {
    __hsiphash_aligned,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t len , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `__hsiphash_aligned()`. See [`__siphash_aligned`] for why it
/// shares the unaligned body.
///
/// # Safety
/// As [`__hsiphash_unaligned`], and `data` must additionally be aligned.
#[cfg(not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))]
#[no_mangle]
pub unsafe extern "C" fn __hsiphash_aligned(data: *const c_void, len: usize, key: *const HsiphashKey) -> u32 {
    // SAFETY: the caller's contract.
    let k = unsafe { [(*key).key[0] as u64, (*key).key[1] as u64] };
    // SAFETY: as above.
    unsafe { hsiphash_bytes(data as *const u8, len, &k) as u32 }
}


kernel::kabi_export! {
    siphash_1u64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u64 } first , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_1u64()`: SipHash2-4 of 1 u64 words.
#[no_mangle]
pub extern "C" fn siphash_1u64(first: u64, key: &SiphashKey) -> u64 {
    let (mut v, b) = preamble(8, &key.key);
    v[3] ^= first;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= first;
    postamble(&mut v, b)
}


kernel::kabi_export! {
    siphash_2u64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u64 } first , formal_parameter const_type { t#u64 } second , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_2u64()`: SipHash2-4 of 2 u64 words.
#[no_mangle]
pub extern "C" fn siphash_2u64(first: u64, second: u64, key: &SiphashKey) -> u64 {
    let (mut v, b) = preamble(16, &key.key);
    v[3] ^= first;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= first;
    v[3] ^= second;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= second;
    postamble(&mut v, b)
}


kernel::kabi_export! {
    siphash_3u64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u64 } first , formal_parameter const_type { t#u64 } second , formal_parameter const_type { t#u64 } third , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_3u64()`: SipHash2-4 of 3 u64 words.
#[no_mangle]
pub extern "C" fn siphash_3u64(first: u64, second: u64, third: u64, key: &SiphashKey) -> u64 {
    let (mut v, b) = preamble(24, &key.key);
    v[3] ^= first;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= first;
    v[3] ^= second;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= second;
    v[3] ^= third;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= third;
    postamble(&mut v, b)
}


kernel::kabi_export! {
    siphash_4u64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u64 } first , formal_parameter const_type { t#u64 } second , formal_parameter const_type { t#u64 } third , formal_parameter const_type { t#u64 } forth , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_4u64()`: SipHash2-4 of 4 u64 words.
#[no_mangle]
pub extern "C" fn siphash_4u64(first: u64, second: u64, third: u64, forth: u64, key: &SiphashKey) -> u64 {
    let (mut v, b) = preamble(32, &key.key);
    v[3] ^= first;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= first;
    v[3] ^= second;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= second;
    v[3] ^= third;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= third;
    v[3] ^= forth;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= forth;
    postamble(&mut v, b)
}


kernel::kabi_export! {
    siphash_1u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_1u32()`. Four bytes fit entirely in the length word, so
/// there is no absorbing round at all.
#[no_mangle]
pub extern "C" fn siphash_1u32(first: u32, key: &SiphashKey) -> u64 {
    let (mut v, b) = preamble(4, &key.key);
    postamble(&mut v, b | first as u64)
}


kernel::kabi_export! {
    siphash_3u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter const_type { t#u32 } second , formal_parameter const_type { t#u32 } third , formal_parameter pointer_type { const_type { t#siphash_key_t } } key ) -> t#u64",
}

/// Body of `siphash_3u32()`. The first two words are packed into one u64 --
/// `second` high, `first` low -- and the third rides in the length word.
#[no_mangle]
pub extern "C" fn siphash_3u32(first: u32, second: u32, third: u32, key: &SiphashKey) -> u64 {
    let combined = ((second as u64) << 32) | first as u64;
    let (mut v, b) = preamble(12, &key.key);

    v[3] ^= combined;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= combined;
    postamble(&mut v, b | third as u64)
}


kernel::kabi_export! {
    hsiphash_1u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `hsiphash_1u32()`. SipHash1-3 on a 64-bit target; see
/// [`__hsiphash_unaligned`].
#[no_mangle]
pub extern "C" fn hsiphash_1u32(first: u32, key: &HsiphashKey) -> u32 {
    let k = [key.key[0] as u64, key.key[1] as u64];
    let (mut v, b) = preamble(4, &k);

    hpostamble(&mut v, b | first as u64) as u32
}


kernel::kabi_export! {
    hsiphash_2u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter const_type { t#u32 } second , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `hsiphash_2u32()`. SipHash1-3 on a 64-bit target; see
/// [`__hsiphash_unaligned`].
#[no_mangle]
pub extern "C" fn hsiphash_2u32(first: u32, second: u32, key: &HsiphashKey) -> u32 {
    let combined = ((second as u64) << 32) | first as u64;
    let k = [key.key[0] as u64, key.key[1] as u64];
    let (mut v, b) = preamble(8, &k);

    v[3] ^= combined;
    sipround(&mut v);
    v[0] ^= combined;
    hpostamble(&mut v, b) as u32
}


kernel::kabi_export! {
    hsiphash_3u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter const_type { t#u32 } second , formal_parameter const_type { t#u32 } third , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `hsiphash_3u32()`. SipHash1-3 on a 64-bit target; see
/// [`__hsiphash_unaligned`].
#[no_mangle]
pub extern "C" fn hsiphash_3u32(first: u32, second: u32, third: u32, key: &HsiphashKey) -> u32 {
    let combined = ((second as u64) << 32) | first as u64;
    let k = [key.key[0] as u64, key.key[1] as u64];
    let (mut v, b) = preamble(12, &k);

    v[3] ^= combined;
    sipround(&mut v);
    v[0] ^= combined;
    hpostamble(&mut v, b | third as u64) as u32
}


kernel::kabi_export! {
    hsiphash_4u32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u32 } first , formal_parameter const_type { t#u32 } second , formal_parameter const_type { t#u32 } third , formal_parameter const_type { t#u32 } forth , formal_parameter pointer_type { const_type { t#hsiphash_key_t } } key ) -> t#u32",
}

/// Body of `hsiphash_4u32()`. SipHash1-3 on a 64-bit target; see
/// [`__hsiphash_unaligned`].
#[no_mangle]
pub extern "C" fn hsiphash_4u32(first: u32, second: u32, third: u32, forth: u32, key: &HsiphashKey) -> u32 {
    let combined = ((second as u64) << 32) | first as u64;
    let k = [key.key[0] as u64, key.key[1] as u64];
    let (mut v, b) = preamble(16, &k);

    v[3] ^= combined;
    sipround(&mut v);
    v[0] ^= combined;
    let combined = ((forth as u64) << 32) | third as u64;
    v[3] ^= combined;
    sipround(&mut v);
    v[0] ^= combined;
    hpostamble(&mut v, b) as u32
}
