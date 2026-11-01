// SPDX-License-Identifier: GPL-2.0-only

//! Bitmap operations -- the Rust behind `lib/bitmap.c`.
//!
//! Ported from `lib/bitmap.c` (6.18.49): the out-of-line halves of the `bitmap_*()` family declared in
//! `include/linux/bitmap.h` (the header's inline wrappers take the single-word fast path and call these for
//! everything else): `__bitmap_equal`, `__bitmap_or_equal`, `__bitmap_complement`, `__bitmap_shift_right/left`,
//! `bitmap_cut`, `__bitmap_and/or/xor/andnot/replace`, `__bitmap_intersects/subset`, `__bitmap_weight[_and|_andnot]`,
//! `__bitmap_set/clear`, `bitmap_find_next_zero_area_off`, `bitmap_remap`, `bitmap_bitremap`, `bitmap_onto` and
//! `bitmap_fold` (CONFIG_NUMA only, as in the C), and `bitmap_from_arr32/to_arr32` (the 64-bit arm). In C
//! (`bitmap_glue.c`): the allocators (`bitmap_alloc*`, `bitmap_free`, the `devm_` pair), which are slab and device-
//! resource calls.
//!
//! Word size is 64 (x86-64; `compile_error!` elsewhere: the 32-bit arms `bitmap_from/to_arr64` are not ported).
//! `hweight_long()` is `count_ones()`. `set_bit()` is an atomic OR (the C's `set_bit()` is a `lock`ed read-
//! modify-write; `bitmap_remap` / `bitmap_onto` / `bitmap_fold` use it on `dst`, so it stays atomic here).
//! The C's unsigned/int mixing is kept where it decides behaviour (`__bitmap_shift_left`'s signed loop
//! counter, `__bitmap_set/clear`'s `int len`). Inputs the C leaves undefined (`shift` beyond `nbits`) are not
//! given a meaning here either.
//!
//! None of the exports has a guard, WARN or static key, so no C entry stays: `kernel::kabi_export!` carries each
//! export and its contract (C fingerprints taken from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: lib/bitmap.c (all but the allocators)

use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(target_pointer_width = "64"))]
compile_error!("bitmap_rs.rs: 64-bit words only (bitmap_from_arr64/bitmap_to_arr64 are not ported)");

const BITS_PER_LONG: u32 = 64;

extern "C" {
    fn _find_next_bit(addr: *const u64, nbits: u64, start: u64) -> u64;
    fn _find_next_zero_bit(addr: *const u64, nbits: u64, start: u64) -> u64;
    fn __find_nth_bit(addr: *const u64, size: u64, n: u64) -> u64;
}

/// `BITS_TO_LONGS()`.
#[inline(always)]
fn bits_to_longs(n: u32) -> u32 {
    ((n as u64 + 63) / 64) as u32
}

/// `BITMAP_LAST_WORD_MASK(nbits)`.
#[inline(always)]
fn last_word_mask(nbits: u32) -> u64 {
    !0u64 >> (nbits.wrapping_neg() & (BITS_PER_LONG - 1))
}

/// `BITMAP_FIRST_WORD_MASK(start)`.
#[inline(always)]
fn first_word_mask(start: u32) -> u64 {
    !0u64 << (start & (BITS_PER_LONG - 1))
}

#[inline(always)]
unsafe fn rd(p: *const u64, i: u32) -> u64 {
    unsafe { *p.add(i as usize) }
}

#[inline(always)]
unsafe fn wr(p: *mut u64, i: u32, v: u64) {
    unsafe { *p.add(i as usize) = v }
}

/// `test_bit()`.
#[inline(always)]
unsafe fn test_bit(nr: u32, addr: *const u64) -> bool {
    (unsafe { rd(addr, nr / BITS_PER_LONG) } >> (nr & (BITS_PER_LONG - 1))) & 1 != 0
}

/// `set_bit()`: atomic OR of one bit.
#[inline(always)]
unsafe fn set_bit(nr: u32, addr: *mut u64) {
    let word = unsafe { AtomicU64::from_ptr(addr.add((nr / BITS_PER_LONG) as usize)) };
    word.fetch_or(1u64 << (nr & (BITS_PER_LONG - 1)), Ordering::Relaxed);
}

/// `bitmap_zero()` for a runtime size.
#[inline(always)]
unsafe fn bitmap_zero(dst: *mut u64, nbits: u32) {
    unsafe { core::ptr::write_bytes(dst, 0, bits_to_longs(nbits) as usize) };
}

/// `BITMAP_WEIGHT()`: popcount over `bits` bits of the words `fetch` yields.
#[inline(always)]
unsafe fn weight(bits: u32, fetch: impl Fn(u32) -> u64) -> u32 {
    let mut w: u32 = 0;
    let mut idx: u32 = 0;
    while idx < bits / BITS_PER_LONG {
        w += fetch(idx).count_ones();
        idx += 1;
    }
    if bits % BITS_PER_LONG != 0 {
        w += (fetch(idx) & last_word_mask(bits)).count_ones();
    }
    w
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");

kernel::kabi_export! {
    __bitmap_equal,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> t#bool",
}
/// `__bitmap_equal()`.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_equal(bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut k: u32 = 0;
    while k < lim {
        if unsafe { rd(bitmap1, k) != rd(bitmap2, k) } {
            return false;
        }
        k += 1;
    }

    if bits % BITS_PER_LONG != 0 && unsafe { (rd(bitmap1, k) ^ rd(bitmap2, k)) & last_word_mask(bits) } != 0 {
        return false;
    }

    true
}

/// `__bitmap_or_equal()` (not exported).
///
/// # Safety
/// All three bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_or_equal(bitmap1: *const u64, bitmap2: *const u64, bitmap3: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut k: u32 = 0;

    while k < lim {
        if unsafe { (rd(bitmap1, k) | rd(bitmap2, k)) != rd(bitmap3, k) } {
            return false;
        }
        k += 1;
    }

    if bits % BITS_PER_LONG == 0 {
        return true;
    }

    let tmp = unsafe { (rd(bitmap1, k) | rd(bitmap2, k)) ^ rd(bitmap3, k) };
    (tmp & last_word_mask(bits)) == 0
}

kernel::kabi_export! {
    __bitmap_complement,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } src , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type void",
}
/// `__bitmap_complement()`.
///
/// # Safety
/// `dst` writable and `src` readable for `bits` bits (rounded up to words).
#[no_mangle]
pub unsafe extern "C" fn __bitmap_complement(dst: *mut u64, src: *const u64, bits: u32) {
    let lim = bits_to_longs(bits);
    let mut k: u32 = 0;
    while k < lim {
        unsafe { wr(dst, k, !rd(src, k)) };
        k += 1;
    }
}

kernel::kabi_export! {
    __bitmap_shift_right,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } src , formal_parameter base_type unsigned int byte_size(4) encoding(7) shift , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `__bitmap_shift_right()`.
///
/// # Safety
/// `dst` writable and `src` readable for `nbits` bits; `shift` at most `nbits`.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_shift_right(dst: *mut u64, src: *const u64, shift: u32, nbits: u32) {
    let lim = bits_to_longs(nbits);
    let off = shift / BITS_PER_LONG;
    let rem = shift % BITS_PER_LONG;
    let mask = last_word_mask(nbits);
    let mut k: u32 = 0;
    while off.wrapping_add(k) < lim {
        let mut upper: u64;
        let mut lower: u64;

        if rem == 0 || off.wrapping_add(k).wrapping_add(1) >= lim {
            upper = 0;
        } else {
            upper = unsafe { rd(src, off + k + 1) };
            if off + k + 1 == lim - 1 {
                upper &= mask;
            }
            upper <<= BITS_PER_LONG - rem;
        }
        lower = unsafe { rd(src, off + k) };
        if off + k == lim - 1 {
            lower &= mask;
        }
        lower >>= rem;
        unsafe { wr(dst, k, lower | upper) };
        k += 1;
    }
    if off != 0 {
        unsafe { core::ptr::write_bytes(dst.add(lim.wrapping_sub(off) as usize), 0, off as usize) };
    }
}

kernel::kabi_export! {
    __bitmap_shift_left,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } src , formal_parameter base_type unsigned int byte_size(4) encoding(7) shift , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `__bitmap_shift_left()`.
///
/// # Safety
/// `dst` writable and `src` readable for `nbits` bits; `shift` at most `nbits`.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_shift_left(dst: *mut u64, src: *const u64, shift: u32, nbits: u32) {
    let lim = bits_to_longs(nbits);
    let off = shift / BITS_PER_LONG;
    let rem = shift % BITS_PER_LONG;
    let mut k: i32 = lim.wrapping_sub(off).wrapping_sub(1) as i32;
    while k >= 0 {
        let upper: u64;
        let lower: u64;

        if rem != 0 && k > 0 {
            lower = unsafe { rd(src, (k - 1) as u32) } >> (BITS_PER_LONG - rem);
        } else {
            lower = 0;
        }
        upper = unsafe { rd(src, k as u32) } << rem;
        unsafe { wr(dst, (k as u32).wrapping_add(off), lower | upper) };
        k -= 1;
    }
    if off != 0 {
        unsafe { core::ptr::write_bytes(dst, 0, off as usize) };
    }
}

kernel::kabi_export! {
    bitmap_cut,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } src , formal_parameter base_type unsigned int byte_size(4) encoding(7) first , formal_parameter base_type unsigned int byte_size(4) encoding(7) cut , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `bitmap_cut()`: remove `cut` bits at `first`, shifting higher bits down.
///
/// # Safety
/// `dst` writable and `src` readable for `nbits` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_cut(dst: *mut u64, src: *const u64, first: u32, cut: u32, nbits: u32) {
    let len = bits_to_longs(nbits);
    let mut keep: u64 = 0;
    let mut cut = cut;

    if first % BITS_PER_LONG != 0 {
        keep = unsafe { rd(src, first / BITS_PER_LONG) } & (!0u64 >> (BITS_PER_LONG - first % BITS_PER_LONG));
    }

    unsafe { core::ptr::copy(src, dst, len as usize) };

    while cut != 0 {
        cut -= 1;
        let mut i: u32 = first / BITS_PER_LONG;
        while i < len {
            let carry: u64 = if i < len.wrapping_sub(1) { (unsafe { rd(dst, i + 1) }) & 1 } else { 0 };
            unsafe { wr(dst, i, (rd(dst, i) >> 1) | (carry << (BITS_PER_LONG - 1))) };
            i += 1;
        }
    }

    unsafe {
        let w = first / BITS_PER_LONG;
        wr(dst, w, rd(dst, w) & (!0u64 << (first % BITS_PER_LONG)));
        wr(dst, w, rd(dst, w) | keep);
    }
}

kernel::kabi_export! {
    __bitmap_and,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> t#bool",
}
/// `__bitmap_and()`: true if the result has any bit set.
///
/// # Safety
/// `dst` writable and both sources readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_and(dst: *mut u64, bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut result: u64 = 0;
    let mut k: u32 = 0;

    while k < lim {
        let v = unsafe { rd(bitmap1, k) & rd(bitmap2, k) };
        unsafe { wr(dst, k, v) };
        result |= v;
        k += 1;
    }
    if bits % BITS_PER_LONG != 0 {
        let v = unsafe { rd(bitmap1, k) & rd(bitmap2, k) } & last_word_mask(bits);
        unsafe { wr(dst, k, v) };
        result |= v;
    }
    result != 0
}

kernel::kabi_export! {
    __bitmap_or,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type void",
}
/// `__bitmap_or()`.
///
/// # Safety
/// `dst` writable and both sources readable for `bits` bits (rounded up to words).
#[no_mangle]
pub unsafe extern "C" fn __bitmap_or(dst: *mut u64, bitmap1: *const u64, bitmap2: *const u64, bits: u32) {
    let nr = bits_to_longs(bits);
    let mut k: u32 = 0;

    while k < nr {
        unsafe { wr(dst, k, rd(bitmap1, k) | rd(bitmap2, k)) };
        k += 1;
    }
}

kernel::kabi_export! {
    __bitmap_xor,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type void",
}
/// `__bitmap_xor()`.
///
/// # Safety
/// As [`__bitmap_or`].
#[no_mangle]
pub unsafe extern "C" fn __bitmap_xor(dst: *mut u64, bitmap1: *const u64, bitmap2: *const u64, bits: u32) {
    let nr = bits_to_longs(bits);
    let mut k: u32 = 0;

    while k < nr {
        unsafe { wr(dst, k, rd(bitmap1, k) ^ rd(bitmap2, k)) };
        k += 1;
    }
}

kernel::kabi_export! {
    __bitmap_andnot,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> t#bool",
}
/// `__bitmap_andnot()`: true if the result has any bit set.
///
/// # Safety
/// As [`__bitmap_and`].
#[no_mangle]
pub unsafe extern "C" fn __bitmap_andnot(dst: *mut u64, bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut result: u64 = 0;
    let mut k: u32 = 0;

    while k < lim {
        let v = unsafe { rd(bitmap1, k) & !rd(bitmap2, k) };
        unsafe { wr(dst, k, v) };
        result |= v;
        k += 1;
    }
    if bits % BITS_PER_LONG != 0 {
        let v = unsafe { rd(bitmap1, k) & !rd(bitmap2, k) } & last_word_mask(bits);
        unsafe { wr(dst, k, v) };
        result |= v;
    }
    result != 0
}

kernel::kabi_export! {
    __bitmap_replace,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } old , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } new , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } mask , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `__bitmap_replace()`: `dst = (old & ~mask) | (new & mask)`.
///
/// # Safety
/// `dst` writable and the others readable for `nbits` bits (rounded up to words).
#[no_mangle]
pub unsafe extern "C" fn __bitmap_replace(dst: *mut u64, old: *const u64, new: *const u64, mask: *const u64, nbits: u32) {
    let nr = bits_to_longs(nbits);
    let mut k: u32 = 0;

    while k < nr {
        unsafe { wr(dst, k, (rd(old, k) & !rd(mask, k)) | (rd(new, k) & rd(mask, k))) };
        k += 1;
    }
}

kernel::kabi_export! {
    __bitmap_intersects,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> t#bool",
}
/// `__bitmap_intersects()`.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_intersects(bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut k: u32 = 0;
    while k < lim {
        if unsafe { rd(bitmap1, k) & rd(bitmap2, k) } != 0 {
            return true;
        }
        k += 1;
    }

    if bits % BITS_PER_LONG != 0 && unsafe { (rd(bitmap1, k) & rd(bitmap2, k)) & last_word_mask(bits) } != 0 {
        return true;
    }
    false
}

kernel::kabi_export! {
    __bitmap_subset,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> t#bool",
}
/// `__bitmap_subset()`.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_subset(bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> bool {
    let lim = bits / BITS_PER_LONG;
    let mut k: u32 = 0;
    while k < lim {
        if unsafe { rd(bitmap1, k) & !rd(bitmap2, k) } != 0 {
            return false;
        }
        k += 1;
    }

    if bits % BITS_PER_LONG != 0 && unsafe { (rd(bitmap1, k) & !rd(bitmap2, k)) & last_word_mask(bits) } != 0 {
        return false;
    }
    true
}

kernel::kabi_export! {
    __bitmap_weight,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__bitmap_weight()`.
///
/// # Safety
/// Bitmap readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_weight(bitmap: *const u64, bits: u32) -> u32 {
    unsafe { weight(bits, |i| rd(bitmap, i)) }
}

kernel::kabi_export! {
    __bitmap_weight_and,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__bitmap_weight_and()`.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_weight_and(bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> u32 {
    unsafe { weight(bits, |i| rd(bitmap1, i) & rd(bitmap2, i)) }
}

kernel::kabi_export! {
    __bitmap_weight_andnot,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap2 , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__bitmap_weight_andnot()`.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_weight_andnot(bitmap1: *const u64, bitmap2: *const u64, bits: u32) -> u32 {
    unsafe { weight(bits, |i| rd(bitmap1, i) & !rd(bitmap2, i)) }
}

kernel::kabi_export! {
    __bitmap_set,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } map , formal_parameter base_type unsigned int byte_size(4) encoding(7) start , formal_parameter base_type int byte_size(4) encoding(5) len ) -> base_type void",
}
/// `__bitmap_set()`: set `len` bits from `start`.
///
/// # Safety
/// `map` writable for `start + len` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_set(map: *mut u64, start: u32, len: c_int) {
    let mut len = len;
    let mut p = unsafe { map.add((start / BITS_PER_LONG) as usize) };
    let size: u32 = start.wrapping_add(len as u32);
    let mut bits_to_set: c_int = (BITS_PER_LONG - (start % BITS_PER_LONG)) as c_int;
    let mut mask_to_set: u64 = first_word_mask(start);

    while len.wrapping_sub(bits_to_set) >= 0 {
        unsafe { *p |= mask_to_set };
        len -= bits_to_set;
        bits_to_set = BITS_PER_LONG as c_int;
        mask_to_set = !0u64;
        p = unsafe { p.add(1) };
    }
    if len != 0 {
        mask_to_set &= last_word_mask(size);
        unsafe { *p |= mask_to_set };
    }
}

kernel::kabi_export! {
    __bitmap_clear,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } map , formal_parameter base_type unsigned int byte_size(4) encoding(7) start , formal_parameter base_type int byte_size(4) encoding(5) len ) -> base_type void",
}
/// `__bitmap_clear()`: clear `len` bits from `start`.
///
/// # Safety
/// `map` writable for `start + len` bits.
#[no_mangle]
pub unsafe extern "C" fn __bitmap_clear(map: *mut u64, start: u32, len: c_int) {
    let mut len = len;
    let mut p = unsafe { map.add((start / BITS_PER_LONG) as usize) };
    let size: u32 = start.wrapping_add(len as u32);
    let mut bits_to_clear: c_int = (BITS_PER_LONG - (start % BITS_PER_LONG)) as c_int;
    let mut mask_to_clear: u64 = first_word_mask(start);

    while len.wrapping_sub(bits_to_clear) >= 0 {
        unsafe { *p &= !mask_to_clear };
        len -= bits_to_clear;
        bits_to_clear = BITS_PER_LONG as c_int;
        mask_to_clear = !0u64;
        p = unsafe { p.add(1) };
    }
    if len != 0 {
        mask_to_clear &= last_word_mask(size);
        unsafe { *p &= !mask_to_clear };
    }
}

kernel::kabi_export! {
    bitmap_find_next_zero_area_off,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } map , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) start , formal_parameter base_type unsigned int byte_size(4) encoding(7) nr , formal_parameter base_type unsigned long byte_size(8) encoding(7) align_mask , formal_parameter base_type unsigned long byte_size(8) encoding(7) align_offset ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `bitmap_find_next_zero_area_off()`: first run of `nr` zero bits at the requested alignment, or the
/// out-of-range index `end` when there is none.
///
/// # Safety
/// `map` readable for `size` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_find_next_zero_area_off(
    map: *mut u64,
    size: u64,
    start: u64,
    nr: u32,
    align_mask: u64,
    align_offset: u64,
) -> u64 {
    let mut start = start;
    loop {
        let mut index = unsafe { _find_next_zero_bit(map, size, start) };

        /* __ALIGN_MASK(index + align_offset, align_mask) - align_offset */
        index = (index.wrapping_add(align_offset).wrapping_add(align_mask) & !align_mask).wrapping_sub(align_offset);

        let end = index.wrapping_add(nr as u64);
        if end > size {
            return end;
        }
        let i = unsafe { _find_next_bit(map, end, index) };
        if i < end {
            start = i + 1;
            continue;
        }
        return index;
    }
}

/// `bitmap_pos_to_ord()`: ordinal of bit `pos` among the set bits of `buf`, or -1 if it is not set.
unsafe fn bitmap_pos_to_ord(buf: *const u64, pos: u32, nbits: u32) -> c_int {
    if pos >= nbits || !unsafe { test_bit(pos, buf) } {
        return -1;
    }

    unsafe { __bitmap_weight(buf, pos) as c_int }
}

/// `find_nth_bit()` (header inline): the `n`th set bit, or `size` if there are fewer.
#[inline(always)]
unsafe fn find_nth_bit(addr: *const u64, size: u64, n: u64) -> u64 {
    if n >= size {
        return size;
    }
    unsafe { __find_nth_bit(addr, size, n) }
}

kernel::kabi_export! {
    bitmap_remap,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } src , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } old , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } new , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `bitmap_remap()`: map each set bit of `src` through the `old` -> `new` ordinal correspondence.
///
/// # Safety
/// `dst` writable, others readable, for `nbits` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_remap(dst: *mut u64, src: *const u64, old: *const u64, new: *const u64, nbits: u32) {
    if dst as *const u64 == src {
        /* following doesn't handle inplace remaps */
        return;
    }
    unsafe { bitmap_zero(dst, nbits) };

    let w = unsafe { __bitmap_weight(new, nbits) };
    let mut oldbit = unsafe { _find_next_bit(src, nbits as u64, 0) } as u32;
    while oldbit < nbits {
        let n = unsafe { bitmap_pos_to_ord(old, oldbit, nbits) };

        if n < 0 || w == 0 {
            unsafe { set_bit(oldbit, dst) }; /* identity map */
        } else {
            unsafe { set_bit(find_nth_bit(new, nbits as u64, ((n as u32) % w) as u64) as u32, dst) };
        }
        oldbit = unsafe { _find_next_bit(src, nbits as u64, oldbit as u64 + 1) } as u32;
    }
}

kernel::kabi_export! {
    bitmap_bitremap,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type int byte_size(4) encoding(5) oldbit , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } old , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } new , formal_parameter base_type int byte_size(4) encoding(5) bits ) -> base_type int byte_size(4) encoding(5)",
}
/// `bitmap_bitremap()`: `bitmap_remap()` for a single bit number.
///
/// # Safety
/// Both bitmaps readable for `bits` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_bitremap(oldbit: c_int, old: *const u64, new: *const u64, bits: c_int) -> c_int {
    let w = unsafe { __bitmap_weight(new, bits as u32) } as c_int;
    let n = unsafe { bitmap_pos_to_ord(old, oldbit as u32, bits as u32) };
    if n < 0 || w == 0 {
        oldbit
    } else {
        unsafe { find_nth_bit(new, bits as u64, (n % w) as u64) as c_int }
    }
}

#[cfg(CONFIG_NUMA)]
kernel::kabi_export! {
    bitmap_onto,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } orig , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } relmap , formal_parameter base_type unsigned int byte_size(4) encoding(7) bits ) -> base_type void",
}
/// `bitmap_onto()` (CONFIG_NUMA): the `n`th set bit of `relmap` is set in `dst` iff bit `n` of `orig` is.
///
/// # Safety
/// `dst` writable, others readable, for `bits` bits.
#[cfg(CONFIG_NUMA)]
#[no_mangle]
pub unsafe extern "C" fn bitmap_onto(dst: *mut u64, orig: *const u64, relmap: *const u64, bits: u32) {
    if dst as *const u64 == orig {
        /* following doesn't handle inplace mappings */
        return;
    }
    unsafe { bitmap_zero(dst, bits) };

    let mut m: u32 = 0;
    let mut n = unsafe { _find_next_bit(relmap, bits as u64, 0) } as u32;
    while n < bits {
        if unsafe { test_bit(m, orig) } {
            unsafe { set_bit(n, dst) };
        }
        m += 1;
        n = unsafe { _find_next_bit(relmap, bits as u64, n as u64 + 1) } as u32;
    }
}

#[cfg(CONFIG_NUMA)]
kernel::kabi_export! {
    bitmap_fold,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } dst , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } orig , formal_parameter base_type unsigned int byte_size(4) encoding(7) sz , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `bitmap_fold()` (CONFIG_NUMA): set bit `oldbit % sz` of `dst` for every set bit of `orig`.
///
/// # Safety
/// `dst` writable and `orig` readable for `nbits` bits; `sz` non-zero.
#[cfg(CONFIG_NUMA)]
#[no_mangle]
pub unsafe extern "C" fn bitmap_fold(dst: *mut u64, orig: *const u64, sz: u32, nbits: u32) {
    if dst as *const u64 == orig {
        /* following doesn't handle inplace mappings */
        return;
    }
    unsafe { bitmap_zero(dst, nbits) };

    let mut oldbit = unsafe { _find_next_bit(orig, nbits as u64, 0) } as u32;
    while oldbit < nbits {
        unsafe { set_bit(oldbit % sz, dst) };
        oldbit = unsafe { _find_next_bit(orig, nbits as u64, oldbit as u64 + 1) } as u32;
    }
}

kernel::kabi_export! {
    bitmap_from_arr32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } bitmap , formal_parameter pointer_type { const_type { t#u32 } } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `bitmap_from_arr32()`: build a bitmap from `u32` words (little-endian halves of each long).
///
/// # Safety
/// `bitmap` writable for `nbits` bits (rounded up to words); `buf` readable for `nbits` bits (rounded up to u32s).
#[no_mangle]
pub unsafe extern "C" fn bitmap_from_arr32(bitmap: *mut u64, buf: *const u32, nbits: u32) {
    let halfwords = (nbits as u64 + 31) / 32;
    let halfwords = halfwords as u32;
    let mut i: u32 = 0;

    while i < halfwords {
        unsafe { wr(bitmap, i / 2, *buf.add(i as usize) as u64) };
        i += 1;
        if i < halfwords {
            unsafe { wr(bitmap, i / 2, rd(bitmap, i / 2) | ((*buf.add(i as usize) as u64) << 32)) };
        }
        i += 1;
    }

    if nbits % BITS_PER_LONG != 0 {
        unsafe { wr(bitmap, (halfwords - 1) / 2, rd(bitmap, (halfwords - 1) / 2) & last_word_mask(nbits)) };
    }
}

kernel::kabi_export! {
    bitmap_to_arr32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#u32 } buf , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } bitmap , formal_parameter base_type unsigned int byte_size(4) encoding(7) nbits ) -> base_type void",
}
/// `bitmap_to_arr32()`: store a bitmap as `u32` words.
///
/// # Safety
/// `buf` writable for `nbits` bits (rounded up to u32s); `bitmap` readable for `nbits` bits (rounded up to words).
#[no_mangle]
pub unsafe extern "C" fn bitmap_to_arr32(buf: *mut u32, bitmap: *const u64, nbits: u32) {
    let halfwords = ((nbits as u64 + 31) / 32) as u32;
    let mut i: u32 = 0;

    while i < halfwords {
        unsafe { *buf.add(i as usize) = (rd(bitmap, i / 2) & u32::MAX as u64) as u32 };
        i += 1;
        if i < halfwords {
            unsafe { *buf.add(i as usize) = (rd(bitmap, i / 2) >> 32) as u32 };
        }
        i += 1;
    }

    if nbits % BITS_PER_LONG != 0 {
        unsafe { *buf.add((halfwords - 1) as usize) &= u32::MAX >> (nbits.wrapping_neg() & 31) };
    }
}
