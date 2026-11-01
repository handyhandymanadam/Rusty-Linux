// SPDX-License-Identifier: GPL-2.0-or-later

//! Bit-search primitives -- the Rust behind `lib/find_bit.c`.
//!
//! Ported from `lib/find_bit.c` (6.18.49), Copyright (C) 2004 Red Hat,
//! Inc.; `_find_last_bit` Copyright (C) 2008 IBM Corporation.
//!
//! Replaces: lib/find_bit.c
//!
//! # No arch dispatch reaches here on x86-64
//!
//! Every exported function is guarded upstream by `#ifndef find_first_bit`
//! (etc.) -- an architecture CAN override these with its own inline
//! assembly. x86 does not (`grep -rn '#define find_next_bit'
//! arch/x86/include/asm/*.h` -- and the rest of the family -- is empty),
//! so all of it is live, ordinary C reached from `include/linux/find.h`'s
//! `find_first_bit()`/`find_next_bit()`/`find_nth_bit()` inline wrappers
//! whenever their `size` argument isn't a compile-time constant (the
//! `small_const_nbits()` fast path is a header-only inline that never
//! calls into this file at all, so there is nothing here for it to
//! displace).
//!
//! # The three `__BIG_ENDIAN` functions are dropped, not ported
//!
//! `_find_first_zero_bit_le`/`_find_next_zero_bit_le`/`_find_next_bit_le`
//! are compiled only `#ifdef __BIG_ENDIAN`, which x86-64 never defines --
//! unlike `errname_rs.rs`'s dropped `CONFIG_MIPS` branch (a config that
//! could theoretically be turned on for the same architecture), a
//! byte-order macro cannot become true without literally being a
//! different CPU architecture. Dead in every configuration this project
//! can ever build under, so not carried as unreachable code.
//!
//! # The C's macro-generated function FAMILY becomes a handful of generic
//! # Rust functions parameterized over closures, not 14 copy-pasted loops
//!
//! `FIND_FIRST_BIT`/`FIND_NEXT_BIT`/`FIND_NTH_BIT` are C preprocessor
//! macros taking a `FETCH` expression (which word to read, and from how
//! many bitmaps combined by which boolean operator) and a `MUNGE`
//! expression (always a no-op here, since none of the surviving,
//! little-endian-only functions apply byte-swapping). `find_first_bit_by`/
//! `find_next_bit_by`/`find_nth_bit_by` below take a `Fn(usize) -> usize`
//! closure in `FETCH`'s place, reproducing the identical control flow
//! once instead of fourteen times -- a legitimate structural
//! simplification `logs/c-entry-rule.md`'s reasoning already covers for
//! `generic_mpih_rs.rs`'s own eight-C-files-become-one case: nothing
//! outside this file can observe where the shared logic lives.

const BITS_PER_LONG: usize = usize::BITS as usize;

#[inline(always)]
fn bitmap_first_word_mask(start: usize) -> usize {
    usize::MAX << (start & (BITS_PER_LONG - 1))
}

#[inline(always)]
fn bitmap_last_word_mask(nbits: usize) -> usize {
    usize::MAX >> (nbits.wrapping_neg() & (BITS_PER_LONG - 1))
}

/// `fns()`: the position of the `n`-th (0-indexed) set bit in `word`, or
/// `BITS_PER_LONG` if `word` has `n` or fewer set bits.
fn fns(mut word: usize, mut n: usize) -> usize {
    while word != 0 && n > 0 {
        word &= word.wrapping_sub(1);
        n = n.wrapping_sub(1);
    }
    if word != 0 {
        word.trailing_zeros() as usize
    } else {
        BITS_PER_LONG
    }
}

/// `FIND_FIRST_BIT(FETCH, /* nop */, size)`.
fn find_first_bit_by(fetch: impl Fn(usize) -> usize, size: usize) -> usize {
    let mut sz = size;
    let mut idx: usize = 0;
    while idx.wrapping_mul(BITS_PER_LONG) < sz {
        let val = fetch(idx);
        if val != 0 {
            sz = core::cmp::min(idx.wrapping_mul(BITS_PER_LONG).wrapping_add(val.trailing_zeros() as usize), sz);
            break;
        }
        idx = idx.wrapping_add(1);
    }
    sz
}

/// `FIND_NEXT_BIT(FETCH, /* nop */, size, start)`.
fn find_next_bit_by(fetch: impl Fn(usize) -> usize, size: usize, start: usize) -> usize {
    let mut sz = size;
    if start >= sz {
        return sz;
    }
    let mask = bitmap_first_word_mask(start);
    let mut idx = start / BITS_PER_LONG;
    let mut tmp = fetch(idx) & mask;
    while tmp == 0 {
        if (idx.wrapping_add(1)).wrapping_mul(BITS_PER_LONG) >= sz {
            return sz;
        }
        idx = idx.wrapping_add(1);
        tmp = fetch(idx);
    }
    sz = core::cmp::min(idx.wrapping_mul(BITS_PER_LONG).wrapping_add(tmp.trailing_zeros() as usize), sz);
    sz
}

/// `FIND_NTH_BIT(FETCH, size, num)`.
fn find_nth_bit_by(fetch: impl Fn(usize) -> usize, size: usize, num: usize) -> usize {
    let sz = size;
    let mut nr = num;
    let mut idx = 0usize;
    let mut tmp: usize = 0;
    while (idx.wrapping_add(1)).wrapping_mul(BITS_PER_LONG) <= sz {
        if idx.wrapping_mul(BITS_PER_LONG).wrapping_add(nr) >= sz {
            return sz;
        }
        tmp = fetch(idx);
        let w = tmp.count_ones() as usize;
        if w > nr {
            return idx.wrapping_mul(BITS_PER_LONG).wrapping_add(fns(tmp, nr));
        }
        nr = nr.wrapping_sub(w);
        idx = idx.wrapping_add(1);
    }
    if sz % BITS_PER_LONG != 0 {
        tmp = fetch(idx) & bitmap_last_word_mask(sz);
    }
    idx.wrapping_mul(BITS_PER_LONG).wrapping_add(fns(tmp, nr))
}

unsafe extern "C" {
    /// `lib/bitmap.c`. The `small_const_nbits()`-ineligible (runtime
    /// `nbits`) arm of `bitmap_weight()`, which is itself header-only
    /// inline.
    fn __bitmap_weight(bitmap: *const usize, nbits: core::ffi::c_uint) -> core::ffi::c_uint;
    /// `include/linux/random.h`. The runtime-`ceil` arm of
    /// `get_random_u32_below()`, itself header-only inline.
    fn __get_random_u32_below(ceil: u32) -> u32;
}

kernel::kabi_export! {
    _find_first_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_first_bit(addr: *const usize, size: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `size` bits span.
    find_first_bit_by(|idx| unsafe { *addr.add(idx) }, size)
}

kernel::kabi_export! {
    _find_first_and_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_first_and_bit(addr1: *const usize, addr2: *const usize, size: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `size` bits span.
    find_first_bit_by(|idx| unsafe { *addr1.add(idx) & *addr2.add(idx) }, size)
}

kernel::kabi_export! {
    _find_first_andnot_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_first_andnot_bit(addr1: *const usize, addr2: *const usize, size: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `size` bits span.
    find_first_bit_by(|idx| unsafe { *addr1.add(idx) & !*addr2.add(idx) }, size)
}

kernel::kabi_export! {
    _find_first_and_and_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr3 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2`/`addr3` must be readable for `size.div_ceil(BITS_PER_LONG)`
/// `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_first_and_and_bit(
    addr1: *const usize,
    addr2: *const usize,
    addr3: *const usize,
    size: usize,
) -> usize {
    // SAFETY: caller guarantees all three readable for the words `size` bits span.
    find_first_bit_by(|idx| unsafe { *addr1.add(idx) & *addr2.add(idx) & *addr3.add(idx) }, size)
}

kernel::kabi_export! {
    _find_first_zero_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_first_zero_bit(addr: *const usize, size: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `size` bits span.
    find_first_bit_by(|idx| unsafe { !*addr.add(idx) }, size)
}

kernel::kabi_export! {
    _find_next_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) nbits , formal_parameter base_type unsigned long byte_size(8) encoding(7) start ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `nbits.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_next_bit(addr: *const usize, nbits: usize, start: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `nbits` bits span.
    find_next_bit_by(|idx| unsafe { *addr.add(idx) }, nbits, start)
}

kernel::kabi_export! {
    __find_nth_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) n ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn __find_nth_bit(addr: *const usize, size: usize, n: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `size` bits span.
    find_nth_bit_by(|idx| unsafe { *addr.add(idx) }, size, n)
}

kernel::kabi_export! {
    __find_nth_and_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) n ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn __find_nth_and_bit(addr1: *const usize, addr2: *const usize, size: usize, n: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `size` bits span.
    find_nth_bit_by(|idx| unsafe { *addr1.add(idx) & *addr2.add(idx) }, size, n)
}

kernel::kabi_export! {
    __find_nth_andnot_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) n ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn __find_nth_andnot_bit(addr1: *const usize, addr2: *const usize, size: usize, n: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `size` bits span.
    find_nth_bit_by(|idx| unsafe { *addr1.add(idx) & !*addr2.add(idx) }, size, n)
}

kernel::kabi_export! {
    __find_nth_and_andnot_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr3 , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) n ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2`/`addr3` must be readable for `size.div_ceil(BITS_PER_LONG)`
/// `usize`s.
#[no_mangle]
pub unsafe extern "C" fn __find_nth_and_andnot_bit(
    addr1: *const usize,
    addr2: *const usize,
    addr3: *const usize,
    size: usize,
    n: usize,
) -> usize {
    // SAFETY: caller guarantees all three readable for the words `size` bits span.
    find_nth_bit_by(|idx| unsafe { *addr1.add(idx) & *addr2.add(idx) & !*addr3.add(idx) }, size, n)
}

kernel::kabi_export! {
    _find_next_and_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) nbits , formal_parameter base_type unsigned long byte_size(8) encoding(7) start ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `nbits.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_next_and_bit(addr1: *const usize, addr2: *const usize, nbits: usize, start: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `nbits` bits span.
    find_next_bit_by(|idx| unsafe { *addr1.add(idx) & *addr2.add(idx) }, nbits, start)
}

kernel::kabi_export! {
    _find_next_andnot_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) nbits , formal_parameter base_type unsigned long byte_size(8) encoding(7) start ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `nbits.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_next_andnot_bit(addr1: *const usize, addr2: *const usize, nbits: usize, start: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `nbits` bits span.
    find_next_bit_by(|idx| unsafe { *addr1.add(idx) & !*addr2.add(idx) }, nbits, start)
}

kernel::kabi_export! {
    _find_next_or_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr1 , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr2 , formal_parameter base_type unsigned long byte_size(8) encoding(7) nbits , formal_parameter base_type unsigned long byte_size(8) encoding(7) start ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr1`/`addr2` must be readable for `nbits.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_next_or_bit(addr1: *const usize, addr2: *const usize, nbits: usize, start: usize) -> usize {
    // SAFETY: caller guarantees both readable for the words `nbits` bits span.
    find_next_bit_by(|idx| unsafe { *addr1.add(idx) | *addr2.add(idx) }, nbits, start)
}

kernel::kabi_export! {
    _find_next_zero_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) nbits , formal_parameter base_type unsigned long byte_size(8) encoding(7) start ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `nbits.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_next_zero_bit(addr: *const usize, nbits: usize, start: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `nbits` bits span.
    find_next_bit_by(|idx| unsafe { !*addr.add(idx) }, nbits, start)
}

kernel::kabi_export! {
    _find_last_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn _find_last_bit(addr: *const usize, size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    let mut val = bitmap_last_word_mask(size);
    let mut idx = (size.wrapping_sub(1)) / BITS_PER_LONG;
    loop {
        // SAFETY: `idx <= (size-1)/BITS_PER_LONG`, within the caller's
        // guaranteed readable range.
        val &= unsafe { *addr.add(idx) };
        if val != 0 {
            return idx.wrapping_mul(BITS_PER_LONG).wrapping_add((BITS_PER_LONG.wrapping_sub(1)).wrapping_sub(val.leading_zeros() as usize));
        }
        val = usize::MAX;
        if idx == 0 {
            break;
        }
        idx = idx.wrapping_sub(1);
    }
    size
}

kernel::kabi_export! {
    find_next_clump8,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } clump , formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size , formal_parameter base_type unsigned long byte_size(8) encoding(7) offset ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// `find_next_clump8()`: like `find_next_bit()`, but rounds down to an
/// 8-bit-aligned boundary and returns that boundary's whole byte through
/// `*clump`. `bitmap_get_value8()`'s general form (any bit offset, not
/// necessarily byte-aligned) is not reproduced here -- this file's only
/// caller always passes an offset already rounded down to a multiple of 8
/// (`round_down(offset, 8)`, right before the read), so the read never
/// spans two `usize` words and the simpler byte-aligned form is exact.
///
/// # Safety
/// `clump` must be valid and writable; `addr` must be readable for
/// `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn find_next_clump8(clump: *mut usize, addr: *const usize, size: usize, offset: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `size` bits span.
    let offset = find_next_bit_by(|idx| unsafe { *addr.add(idx) }, size, offset);
    if offset == size {
        return size;
    }
    let offset = offset & !7; // round_down(offset, 8)
    // SAFETY: `offset` is in-bounds per the check above, and byte-aligned,
    // so this 8-bit read stays within a single word; caller guarantees
    // `addr` readable that far.
    let word = unsafe { *addr.add(offset / BITS_PER_LONG) };
    let value = (word >> (offset % BITS_PER_LONG)) & 0xff;
    // SAFETY: the caller guarantees `clump` valid and writable.
    unsafe { *clump = value };
    offset
}

kernel::kabi_export! {
    find_random_bit,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type unsigned long byte_size(8) encoding(7) } } addr , formal_parameter base_type unsigned long byte_size(8) encoding(7) size ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// # Safety
/// `addr` must be readable for `size.div_ceil(BITS_PER_LONG)` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn find_random_bit(addr: *const usize, size: usize) -> usize {
    // SAFETY: caller guarantees `addr` readable for the words `size` bits span.
    let w = unsafe { __bitmap_weight(addr, size as core::ffi::c_uint) };
    match w {
        0 => size,
        // SAFETY: same as above.
        1 => find_first_bit_by(|idx| unsafe { *addr.add(idx) }, size),
        _ => {
            // SAFETY: `w` is a valid u32 here (checked above, `w > 1`).
            let n = unsafe { __get_random_u32_below(w) } as usize;
            // SAFETY: same as the `w == 1` arm.
            find_nth_bit_by(|idx| unsafe { *addr.add(idx) }, size, n)
        }
    }
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
