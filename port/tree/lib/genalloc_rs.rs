// SPDX-License-Identifier: GPL-2.0

//! The lock-free bitmap and the allocation arithmetic of the generic allocator -- the Rust behind `lib/genalloc.c`.
//!
//! Ported from `lib/genalloc.c` (6.18.49), "Basic general purpose allocator for managing special purpose memory" by Jes Sorensen /
//! Zhang Yanmin / Dmitry Safonov. In Rust: `set_bits_ll`, `clear_bits_ll`, `bitmap_set_ll`, `bitmap_clear_ll` (the cmpxchg loops
//! that let several allocators set and clear bits of one chunk bitmap without a lock) and the arithmetic of the five allocation
//! algorithms (`gen_pool_first_fit`, `_first_fit_align`, `_fixed_alloc`, `_first_fit_order_align`, `_best_fit`). In C
//! (`genalloc_glue.c`): everything that touches `struct gen_pool` (spinlock, RCU chunk list, `kmalloc`), the five exported
//! entry points themselves (their fingerprints come from the DWARF of the definition, and two read `pool->min_alloc_order` / the
//! caller's `data`, whose offsets depend on the lock size), and the `WARN_ON` in `gen_pool_fixed_alloc`.
//!
//! # The ordering contract (concurrency bar, item 1)
//! * `set_bits_ll`/`clear_bits_ll` are `try_cmpxchg()` loops on one word: fully ordered in the C (`lock cmpxchg` on x86), so `SeqCst`
//!   here -- both success and failure, since the C's `try_cmpxchg` has no `_relaxed` suffix. The initial `READ_ONCE()` is a `Relaxed`
//!   load: a stale value only costs one failed exchange, which refreshes it.
//! * A set that finds one of its bits already set (or a clear that finds one already clear) gives up with `-EBUSY` WITHOUT having
//!   touched that word; `bitmap_set_ll`/`bitmap_clear_ll` then return the number of bits still to do and leave the earlier words
//!   done. The caller (`gen_pool_alloc_algo_owner`) undoes exactly the words it did set.
//! * `cpu_relax()` is `pause` (`spin_loop`) before each exchange attempt, as in the C.
//!
//! # Quirk kept
//! `gen_pool_first_fit_order_align` is `roundup_pow_of_two(nr) - 1`. For `nr == 0` the C's `1UL << fls_long(~0)` shifts by 64, which
//! x86 masks to a shift by 0 (result 1, mask 0); `wrapping_shl` does the same. `gen_pool_alloc` never passes 0 (it returns early on
//! `size == 0`).
//!
//! Replaces: lib/genalloc.c (the bitmap helpers and the allocation algorithms; the pool, chunk and device plumbing stay C)

use core::ffi::{c_int, c_uint, c_ulong};
use core::sync::atomic::{AtomicU64, Ordering};

const BITS_PER_LONG: c_ulong = 64;
const EBUSY: c_int = 16;

extern "C" {
    /// `lib/bitmap.c`.
    fn bitmap_find_next_zero_area_off(
        map: *const c_ulong,
        size: c_ulong,
        start: c_ulong,
        nr: c_uint,
        align_mask: c_ulong,
        align_offset: c_ulong,
    ) -> c_ulong;
    /// `lib/find_bit.c`; `find_next_bit()` is an inline wrapper that calls it for a non-constant size.
    fn _find_next_bit(addr: *const c_ulong, nbits: c_ulong, start: c_ulong) -> c_ulong;
}

/// `BITMAP_FIRST_WORD_MASK(start)`.
#[inline(always)]
const fn first_word_mask(start: c_ulong) -> c_ulong {
    !0 << (start % BITS_PER_LONG)
}

/// `BITMAP_LAST_WORD_MASK(nbits)`.
#[inline(always)]
const fn last_word_mask(nbits: c_ulong) -> c_ulong {
    !0 >> (nbits.wrapping_neg() % BITS_PER_LONG)
}

/// `set_bits_ll()`: set `mask_to_set` in `*addr` unless one of those bits is already set (`-EBUSY`).
///
/// # Safety
/// `addr` is valid and 8-byte aligned.
#[inline(always)]
unsafe fn set_bits_ll(addr: *mut c_ulong, mask_to_set: c_ulong) -> c_int {
    // SAFETY: caller contract.
    let word = unsafe { AtomicU64::from_ptr(addr) };
    let mut val = word.load(Ordering::Relaxed); /* READ_ONCE() */
    loop {
        if val & mask_to_set != 0 {
            return -EBUSY;
        }
        core::hint::spin_loop(); /* cpu_relax() */
        match word.compare_exchange(val, val | mask_to_set, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return 0,
            Err(cur) => val = cur,
        }
    }
}

/// `clear_bits_ll()`: clear `mask_to_clear` in `*addr` unless one of those bits is already clear (`-EBUSY`).
///
/// # Safety
/// As [`set_bits_ll`].
#[inline(always)]
unsafe fn clear_bits_ll(addr: *mut c_ulong, mask_to_clear: c_ulong) -> c_int {
    // SAFETY: caller contract.
    let word = unsafe { AtomicU64::from_ptr(addr) };
    let mut val = word.load(Ordering::Relaxed);
    loop {
        if val & mask_to_clear != mask_to_clear {
            return -EBUSY;
        }
        core::hint::spin_loop();
        match word.compare_exchange(val, val & !mask_to_clear, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return 0,
            Err(cur) => val = cur,
        }
    }
}

/// `bitmap_set_ll()`: set `nr` bits starting at `start`, lock-lessly. Returns 0, or the number of bits NOT set because
/// another user had set one of the bits of a word.
///
/// # Safety
/// `map` covers `start + nr` bits.
#[no_mangle]
pub unsafe extern "C" fn rust_genalloc_bitmap_set_ll(map: *mut c_ulong, start: c_ulong, mut nr: c_ulong) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mut p = map.add((start / BITS_PER_LONG) as usize);
        let size = start.wrapping_add(nr);
        let mut bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
        let mut mask_to_set = first_word_mask(start);

        while nr >= bits_to_set {
            if set_bits_ll(p, mask_to_set) != 0 {
                return nr;
            }
            nr -= bits_to_set;
            bits_to_set = BITS_PER_LONG;
            mask_to_set = !0;
            p = p.add(1);
        }
        if nr != 0 {
            mask_to_set &= last_word_mask(size);
            if set_bits_ll(p, mask_to_set) != 0 {
                return nr;
            }
        }
        0
    }
}

/// `bitmap_clear_ll()`: the mirror of [`rust_genalloc_bitmap_set_ll`].
///
/// # Safety
/// `map` covers `start + nr` bits.
#[no_mangle]
pub unsafe extern "C" fn rust_genalloc_bitmap_clear_ll(map: *mut c_ulong, start: c_ulong, mut nr: c_ulong) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mut p = map.add((start / BITS_PER_LONG) as usize);
        let size = start.wrapping_add(nr);
        let mut bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
        let mut mask_to_clear = first_word_mask(start);

        while nr >= bits_to_clear {
            if clear_bits_ll(p, mask_to_clear) != 0 {
                return nr;
            }
            nr -= bits_to_clear;
            bits_to_clear = BITS_PER_LONG;
            mask_to_clear = !0;
            p = p.add(1);
        }
        if nr != 0 {
            mask_to_clear &= last_word_mask(size);
            if clear_bits_ll(p, mask_to_clear) != 0 {
                return nr;
            }
        }
        0
    }
}

/// `gen_pool_first_fit()`: `bitmap_find_next_zero_area(map, size, start, nr, 0)`.
///
/// # Safety
/// `map` covers `size` bits.
#[no_mangle]
pub unsafe extern "C" fn rust_gen_pool_first_fit(map: *const c_ulong, size: c_ulong, start: c_ulong, nr: c_uint) -> c_ulong {
    // SAFETY: caller contract.
    unsafe { bitmap_find_next_zero_area_off(map, size, start, nr, 0, 0) }
}

/// `gen_pool_first_fit_align()`'s arithmetic: `align` is `genpool_data_align::align`, `order` is `pool->min_alloc_order`.
///
/// # Safety
/// As [`rust_gen_pool_first_fit`].
#[no_mangle]
pub unsafe extern "C" fn rust_gen_pool_first_fit_align(
    map: *const c_ulong,
    size: c_ulong,
    start: c_ulong,
    nr: c_uint,
    align: c_ulong,
    order: c_int,
    start_addr: c_ulong,
) -> c_ulong {
    let order = order as u32;
    let align_mask = (align.wrapping_add(1u64.wrapping_shl(order)).wrapping_sub(1) >> order).wrapping_sub(1);
    let align_off = (start_addr & align.wrapping_sub(1)) >> order;
    // SAFETY: caller contract.
    unsafe { bitmap_find_next_zero_area_off(map, size, start, nr, align_mask, align_off) }
}

/// `gen_pool_fixed_alloc()`'s search, after the C has checked (`WARN_ON`) that `offset` is a multiple of the allocation unit:
/// the run of `nr` zero bits must start exactly at `offset >> order`, else `size` ("no fit").
///
/// # Safety
/// As [`rust_gen_pool_first_fit`].
#[no_mangle]
pub unsafe extern "C" fn rust_gen_pool_fixed_alloc(
    map: *const c_ulong,
    size: c_ulong,
    start: c_ulong,
    nr: c_uint,
    offset: c_ulong,
    order: c_int,
) -> c_ulong {
    let offset_bit = offset >> (order as u32);
    // SAFETY: caller contract.
    let start_bit = unsafe { bitmap_find_next_zero_area_off(map, size, start.wrapping_add(offset_bit), nr, 0, 0) };
    if start_bit != offset_bit {
        size
    } else {
        start_bit
    }
}

/// `gen_pool_first_fit_order_align()`: first fit aligned to `roundup_pow_of_two(nr)`.
///
/// # Safety
/// As [`rust_gen_pool_first_fit`].
#[no_mangle]
pub unsafe extern "C" fn rust_gen_pool_first_fit_order_align(
    map: *const c_ulong,
    size: c_ulong,
    start: c_ulong,
    nr: c_uint,
) -> c_ulong {
    // __roundup_pow_of_two(n) = 1UL << fls_long(n - 1); fls_long(0) = 0, else 64 - leading_zeros.
    let n = (nr as c_ulong).wrapping_sub(1);
    let fls = 64 - n.leading_zeros();
    let align_mask = 1u64.wrapping_shl(fls).wrapping_sub(1);
    // SAFETY: caller contract.
    unsafe { bitmap_find_next_zero_area_off(map, size, start, nr, align_mask, 0) }
}

/// `gen_pool_best_fit()`: the smallest free run of at least `nr` bits.
///
/// # Safety
/// As [`rust_gen_pool_first_fit`].
#[no_mangle]
pub unsafe extern "C" fn rust_gen_pool_best_fit(map: *const c_ulong, size: c_ulong, start: c_ulong, nr: c_uint) -> c_ulong {
    // SAFETY: caller contract.
    unsafe {
        let mut start_bit = size;
        let mut len = size.wrapping_add(1);

        let mut index = bitmap_find_next_zero_area_off(map, size, start, nr, 0, 0);
        while index < size {
            let next_bit = _find_next_bit(map, size, index.wrapping_add(nr as c_ulong));
            if next_bit.wrapping_sub(index) < len {
                len = next_bit.wrapping_sub(index);
                start_bit = index;
                if len == nr as c_ulong {
                    return start_bit;
                }
            }
            index = bitmap_find_next_zero_area_off(map, size, next_bit.wrapping_add(1), nr, 0, 0);
        }
        start_bit
    }
}
