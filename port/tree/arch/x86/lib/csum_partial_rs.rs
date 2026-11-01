// SPDX-License-Identifier: GPL-2.0

//! The Internet checksum of `arch/x86/lib/csum-partial_64.c`: `csum_partial`
//! and `ip_compute_csum`.
//!
//! Ported from `arch/x86/lib/csum-partial_64.c` (6.18.49), which no longer
//! exists in the CONFIG_RUST build: this file is the whole of it. (The
//! `csum_partial_copy*` and `csum_and_copy_*` helpers are NOT in that file:
//! they are `csum-copy_64.S` and `csum-wrappers_64.c`, which are untouched.)
//!
//! `csum_partial(buff, len, sum)` adds `len` bytes at `buff` to the 32-bit
//! partial sum `sum`, as 64-bit little-endian words with end-around carry,
//! and folds the 64-bit accumulator to 32 bits. The result is the RFC 1071
//! ones' complement sum, but it is NOT canonical: all-ones and zero are both
//! "zero" and the exact 32-bit value depends on the order the carries are
//! taken. The C's order is reproduced step for step (two 40-byte chains in
//! parallel for the 80-byte loop, one for the 40-byte step, then 32/16/8 and a
//! 1..7-byte tail), so the result is bit-identical to the C, not merely
//! equivalent, and a caller that stores the raw 32-bit value sees no change.
//!
//! * The C's `adcq` chains are written as `adc()` over `overflowing_add`: the
//!   carry flag is an explicit `bool`. Nothing here can overflow-panic: every
//!   64-bit add is an `overflowing_add`/`wrapping_add`, and the only checked
//!   arithmetic is `len -= 80/40` under `len >= 80/40`.
//! * **Deliberate divergence (tail read):** for the last 1..7 bytes the C does
//!   `load_unaligned_zeropad(buff)`, an 8-byte load that may run past the end
//!   of the buffer (into a page that may be unmapped: the exception table
//!   fixes that up) and masks the extra bytes off. This file reads exactly the
//!   `len & 7` bytes that belong to the buffer instead, so it never touches
//!   memory outside `[buff, buff + len)` and needs no exception-table entry.
//!   The value added is the same (the low `len & 7` bytes, little endian).
//! * `len` keeps the C's `int` semantics, including its (never used) negative
//!   values: the same bit tests on the two's-complement value.
//!
//! `csum_fold` of `asm/checksum_64.h` (a static inline in the header, so not
//! linkable) is re-expressed here for `ip_compute_csum`: `addl`/`adcl $0xffff`
//! as explicit carry arithmetic, then the high half inverted.
//!
//! Both `EXPORT_SYMBOL`s and their MODVERSIONS contracts are carried here by
//! `kernel::kabi_export!`. Neither function has a guard, a static key or a
//! bug-table entry, so no C entry stays (`logs/c-entry-rule.md`).
//!
//! Checked against the pristine C and an independent RFC 1071 implementation
//! (`port/test/x86_csum/run.sh`), proved with Z3 (`logs/proofs/x86_csum.py`)
//! and Kani (`rig/x86-csum-kani`).
//!
//! Replaces: arch/x86/lib/csum-partial_64.c

use core::ffi::{c_int, c_void};

/// One `adcq`: `a + b + carry`, returning the 64-bit result and the carry out.
#[inline(always)]
fn adc(a: u64, b: u64, cf: bool) -> (u64, bool) {
    let (s, c1) = a.overflowing_add(b);
    let (s, c2) = s.overflowing_add(cf as u64);
    (s, c1 | c2)
}

/// Unaligned little-endian 64-bit load of word `i` (x86 is little endian).
///
/// # Safety
/// `p + 8 * i .. p + 8 * i + 8` is readable.
#[inline(always)]
unsafe fn word(p: *const u8, i: usize) -> u64 {
    // SAFETY: the caller guarantees the 8 bytes are readable.
    unsafe { (p.add(8 * i) as *const u64).read_unaligned() }
}

/// `csum_finalize_sum()`: fold the 64-bit accumulator to 32 bits.
#[inline(always)]
fn csum_finalize_sum(temp64: u64) -> u32 {
    (temp64.wrapping_add(temp64.rotate_right(32)) >> 32) as u32
}

/// `update_csum_40b()`: `addq; adcq x4; adcq $0` over five words.
///
/// # Safety
/// 40 bytes at `m` are readable.
#[inline(always)]
unsafe fn update_csum_40b(sum: u64, m: *const u8) -> u64 {
    // SAFETY: 40 readable bytes = words 0..5.
    unsafe {
        let (s, c) = sum.overflowing_add(word(m, 0));
        let (s, c) = adc(s, word(m, 1), c);
        let (s, c) = adc(s, word(m, 2), c);
        let (s, c) = adc(s, word(m, 3), c);
        let (s, c) = adc(s, word(m, 4), c);
        adc(s, 0, c).0
    }
}

/// The body of `csum_partial()`.
///
/// # Safety
/// `buff` points to `len` readable bytes (it may be NULL when `len` is 0).
#[inline(always)]
unsafe fn csum_partial_impl(mut buff: *const u8, mut len: c_int, sum: u32) -> u32 {
    let mut temp64 = sum as u64;

    // SAFETY (whole body): every read below is inside the `len` bytes the
    // caller vouches for: each step reads exactly the bytes its `len` test
    // says remain, and advances `buff` by what it read.
    unsafe {
        // Do two 40-byte chunks in parallel to get better ILP
        if len >= 80 {
            let mut temp64_2 = 0u64;
            loop {
                temp64 = update_csum_40b(temp64, buff);
                temp64_2 = update_csum_40b(temp64_2, buff.add(40));
                buff = buff.add(80);
                len -= 80;
                if len < 80 {
                    break;
                }
            }
            let (s, c) = temp64.overflowing_add(temp64_2);
            temp64 = adc(s, 0, c).0;
        }

        // len == 40 is the hot case due to IPv6 headers: return early for
        // that exact case without checking the tail bytes.
        if len >= 40 {
            temp64 = update_csum_40b(temp64, buff);
            len -= 40;
            if len == 0 {
                return csum_finalize_sum(temp64);
            }
            buff = buff.add(40);
        }

        if len & 32 != 0 {
            let (s, c) = temp64.overflowing_add(word(buff, 0));
            let (s, c) = adc(s, word(buff, 1), c);
            let (s, c) = adc(s, word(buff, 2), c);
            let (s, c) = adc(s, word(buff, 3), c);
            temp64 = adc(s, 0, c).0;
            buff = buff.add(32);
        }
        if len & 16 != 0 {
            let (s, c) = temp64.overflowing_add(word(buff, 0));
            let (s, c) = adc(s, word(buff, 1), c);
            temp64 = adc(s, 0, c).0;
            buff = buff.add(16);
        }
        if len & 8 != 0 {
            let (s, c) = temp64.overflowing_add(word(buff, 0));
            temp64 = adc(s, 0, c).0;
            buff = buff.add(8);
        }
        let n = (len & 7) as usize;
        if n != 0 {
            // The C loads 8 bytes and masks to the low `n`; read only the `n`.
            let mut trail = 0u64;
            let mut i = 0;
            while i < n {
                trail |= (*buff.add(i) as u64) << (8 * i);
                i += 1;
            }
            let (s, c) = temp64.overflowing_add(trail);
            temp64 = adc(s, 0, c).0;
        }
    }
    csum_finalize_sum(temp64)
}

/// `csum_fold()` of `asm/checksum_64.h`: `addl %1,%0; adcl $0xffff,%0` on
/// `(sum & 0xffff0000) + (sum << 16)`, then the high half, inverted.
#[inline(always)]
fn csum_fold(sum: u32) -> u16 {
    let (s, c) = (sum & 0xffff_0000).overflowing_add(sum << 16);
    let s = s.wrapping_add(0xffff).wrapping_add(c as u32);
    (!s >> 16) as u16
}

// The C types the two contracts name, as gendwarfksyms printed them for the C
// object (build-fast/arch/x86/lib/csum-partial_64.o, 2026-10-04); re-derived
// from port/pristine by rig/kabi-contract-check.sh.
#[cfg(not(kani))]
kernel::kabi_rule!("type_string", "t#__u16",
    "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }");
#[cfg(not(kani))]
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
#[cfg(not(kani))]
kernel::kabi_rule!("type_string", "t#__sum16", "typedef_type __sum16 { t#__u16 }");
#[cfg(not(kani))]
kernel::kabi_rule!("type_string", "t#__wsum", "typedef_type __wsum { t#__u32 }");

#[cfg(not(kani))]
kernel::kabi_export! {
    csum_partial,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } buff , formal_parameter base_type int byte_size(4) encoding(5) len , formal_parameter t#__wsum sum ) -> t#__wsum",
}

/// Internet checksum of `len` bytes at `buff`, added to `sum`
/// (`__wsum csum_partial(const void *buff, int len, __wsum sum)`).
///
/// # Safety
/// `buff` points to `len` readable bytes (NULL is fine for `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn csum_partial(buff: *const c_void, len: c_int, sum: u32) -> u32 {
    // SAFETY: forwarded.
    unsafe { csum_partial_impl(buff as *const u8, len, sum) }
}

#[cfg(not(kani))]
kernel::kabi_export! {
    ip_compute_csum,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } buff , formal_parameter base_type int byte_size(4) encoding(5) len ) -> t#__sum16",
}

/// 16-bit folded and inverted checksum of `len` bytes at `buff`
/// (`__sum16 ip_compute_csum(const void *buff, int len)`).
///
/// # Safety
/// `buff` points to `len` readable bytes (NULL is fine for `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn ip_compute_csum(buff: *const c_void, len: c_int) -> u16 {
    // SAFETY: forwarded.
    csum_fold(unsafe { csum_partial_impl(buff as *const u8, len, 0) })
}

/// Kani proofs (`cd rig/x86-csum-kani && cargo kani`; inert in the kernel build). For each length
/// below, every content of a buffer of EXACTLY that many bytes and every initial sum: the body reads
/// only inside the buffer (any read past either end is an out-of-bounds failure Kani reports) and
/// no arithmetic overflows (Kani checks every `+`, `-`, `<<` of the Rust). The lengths hit every
/// path: 0, the 1..7 tail bytes, the 8/16/32-byte steps, the 40-byte step (and its early return at
/// exactly 40), the 80-byte loop once and twice.
#[cfg(kani)]
mod proofs {
    use super::*;

    macro_rules! reads_inside {
        ($name:ident, $len:expr) => {
            #[kani::proof]
            #[kani::unwind(12)]
            fn $name() {
                let buf: [u8; $len] = kani::any();
                let sum: u32 = kani::any();
                let r = unsafe { csum_partial_impl(buf.as_ptr(), $len as c_int, sum) };
                // len 0: the accumulator is the initial sum folded once, not changed
                if $len == 0 {
                    assert!(r == sum);
                }
            }
        };
    }
    reads_inside!(len_0, 0);
    reads_inside!(len_1, 1);
    reads_inside!(len_3, 3);
    reads_inside!(len_7, 7);
    reads_inside!(len_8, 8);
    reads_inside!(len_13, 13);
    reads_inside!(len_16, 16);
    reads_inside!(len_31, 31);
    reads_inside!(len_32, 32);
    reads_inside!(len_39, 39);
    reads_inside!(len_40, 40);
    reads_inside!(len_41, 41);
    reads_inside!(len_79, 79);
    reads_inside!(len_80, 80);
    reads_inside!(len_87, 87);
    reads_inside!(len_119, 119);
    reads_inside!(len_160, 160);
    reads_inside!(len_167, 167);

    /// The pure fold has no overflow and `csum_fold` is the ones' complement fold, for every input.
    #[kani::proof]
    fn fold_and_finalize_total() {
        let t: u64 = kani::any();
        let f = csum_finalize_sum(t);
        assert!((f == 0) == (t == 0));
        let x: u32 = kani::any();
        let _ = csum_fold(x);
    }
}
