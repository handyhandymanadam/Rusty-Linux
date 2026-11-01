// SPDX-License-Identifier: GPL-2.0

//! A fast, small, non-recursive O(n log n) sort -- the Rust body behind
//! `lib/sort.c`.
//!
//! Ported from `lib/sort.c` (6.18.49). Bottom-up heapsort: it does
//! n*log2(n) + 0.37*n + o(n) comparisons on average and 1.5*n*log2(n) + O(n)
//! in the contrived worst case, with no stack usage and no quicksort O(n^2)
//! cliff.
//!
//! # Why this is nearly all raw pointers
//!
//! `sort()` is generic over element type at the C level: it is handed a base
//! pointer, an element count, an element size in bytes, and a comparison
//! callback. Nothing here knows what it is sorting, and it may not — callers
//! sort arrays of structs, of pointers, of anything. So the arithmetic is
//! byte offsets, exactly as the C's is.
//!
//! # The function pointers that are not pointers
//!
//! The C tags its swap strategy by putting the small integers 0, 1, 2 and 3
//! in a `swap_r_func_t` and comparing against them, and `_CMP_WRAPPER` is a
//! null `cmp_r_func_t` meaning "the real callback is in `priv`". They are
//! never called; they are compared. So they arrive here as `*const c_void`
//! and are transmuted only on the path that has already established they are
//! genuine pointers.
//!
//! # What stays in C
//!
//! `cond_resched()`, via `rust_sort_cond_resched()` in `lib/sort.c`. It is a
//! scheduling primitive, and under `CONFIG_PREEMPT_DYNAMIC` it is a static
//! call patched at boot — not something to reach from here.
//!
//! Replaces: lib/sort.c

use core::ffi::{c_int, c_void};

/// `cmp_func_t`: compare two elements.
type CmpFunc = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
/// `cmp_r_func_t`: compare two elements, with caller private data.
type CmpRFunc = unsafe extern "C" fn(*const c_void, *const c_void, *const c_void) -> c_int;
/// `swap_func_t`: exchange two elements.
type SwapFunc = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int);
/// `swap_r_func_t`: exchange two elements, with caller private data.
type SwapRFunc = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int, *const c_void);

/// Mirrors `struct wrapper` in `lib/sort.c`: how `sort()` smuggles a
/// non-`_r` callback pair through `priv`.
#[repr(C)]
struct Wrapper {
    cmp: Option<CmpFunc>,
    swap: Option<SwapFunc>,
}

/// Swap in 64-bit chunks. `n` must be a non-zero multiple of 8.
///
/// # Safety
/// `a` and `b` must be distinct, non-overlapping, and readable and writable
/// for `n` bytes.
unsafe fn swap_words_64(a: *mut u8, b: *mut u8, n: usize) {
    let mut n = n;

    // SAFETY: the caller guarantees both regions are valid for `n` bytes and
    // do not overlap. `n` is a multiple of 8, so every 8-byte access is in
    // range, and the loop stops at zero.
    unsafe {
        loop {
            n = n.wrapping_sub(8);
            let pa = a.add(n) as *mut u64;
            let pb = b.add(n) as *mut u64;
            let t = pa.read_unaligned();

            pa.write_unaligned(pb.read_unaligned());
            pb.write_unaligned(t);
            if n == 0 {
                break;
            }
        }
    }
}

/// Swap in 32-bit chunks. `n` must be a non-zero multiple of 4.
///
/// # Safety
/// As [`swap_words_64`], with `n` a multiple of 4.
unsafe fn swap_words_32(a: *mut u8, b: *mut u8, n: usize) {
    let mut n = n;

    // SAFETY: as above, in 4-byte steps.
    unsafe {
        loop {
            n = n.wrapping_sub(4);
            let pa = a.add(n) as *mut u32;
            let pb = b.add(n) as *mut u32;
            let t = pa.read_unaligned();

            pa.write_unaligned(pb.read_unaligned());
            pb.write_unaligned(t);
            if n == 0 {
                break;
            }
        }
    }
}

/// Swap a byte at a time. `n` must be non-zero.
///
/// # Safety
/// As [`swap_words_64`], with no alignment requirement.
unsafe fn swap_bytes(a: *mut u8, b: *mut u8, n: usize) {
    let mut n = n;

    // SAFETY: as above, one byte at a time.
    unsafe {
        loop {
            n = n.wrapping_sub(1);
            let t = a.add(n).read();

            a.add(n).write(b.add(n).read());
            b.add(n).write(t);
            if n == 0 {
                break;
            }
        }
    }
}

/// The C's `SWAP_WORDS_64`, `SWAP_WORDS_32`, `SWAP_BYTES`, `SWAP_WRAPPER`.
const SWAP_WORDS_64: usize = 0;
const SWAP_WORDS_32: usize = 1;
const SWAP_BYTES: usize = 2;
const SWAP_WRAPPER: usize = 3;
/// The C's `_CMP_WRAPPER`.
const CMP_WRAPPER: usize = 0;

/// Dispatch a swap, honouring the sentinel tags.
///
/// # Safety
/// `a` and `b` must be distinct elements of `size` bytes within the array,
/// and `swap_func` must be a sentinel or a valid callback. `priv_` must be a
/// valid `struct wrapper` when `swap_func` is `SWAP_WRAPPER`.
unsafe fn do_swap(a: *mut u8, b: *mut u8, size: usize, swap_func: *const c_void, priv_: *const c_void) {
    // SAFETY: the caller's contract, discharged case by case below.
    unsafe {
        match swap_func as usize {
            SWAP_WRAPPER => {
                let w = &*(priv_ as *const Wrapper);

                if let Some(f) = w.swap {
                    f(a as *mut c_void, b as *mut c_void, size as c_int);
                }
            }
            SWAP_WORDS_64 => swap_words_64(a, b, size),
            SWAP_WORDS_32 => swap_words_32(a, b, size),
            SWAP_BYTES => swap_bytes(a, b, size),
            _ => {
                let f: SwapRFunc = core::mem::transmute(swap_func);

                f(a as *mut c_void, b as *mut c_void, size as c_int, priv_);
            }
        }
    }
}

/// Dispatch a comparison, honouring the `_CMP_WRAPPER` tag.
///
/// # Safety
/// `a` and `b` must be elements within the array, and `cmp_func` must be
/// `_CMP_WRAPPER` with a valid `struct wrapper` in `priv_`, or a valid
/// callback.
unsafe fn do_cmp(a: *const u8, b: *const u8, cmp_func: *const c_void, priv_: *const c_void) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if cmp_func as usize == CMP_WRAPPER {
            let w = &*(priv_ as *const Wrapper);

            // The C dereferences this unconditionally; a null cmp is a
            // caller bug there too, and there is nothing sensible to
            // return instead.
            return (w.cmp.unwrap_unchecked())(a as *const c_void, b as *const c_void);
        }
        let f: CmpRFunc = core::mem::transmute(cmp_func);

        f(a as *const c_void, b as *const c_void, priv_)
    }
}

/// Given the byte offset of a child, the byte offset of its parent.
///
/// In element indices the parent of `j` is `(j - 1) / 2`, but in byte
/// offsets there is no implicit truncation to lean on. Only one bit of the
/// quotient is actually needed: `size`'s lowest set bit is clear in `i` when
/// `i` is an even multiple of `size` and set when it is odd. This is
/// `if (i & lsbit) i -= size;` written branch-free, because that branch is
/// unpredictable.
#[inline]
fn parent(i: usize, lsbit: usize, size: usize) -> usize {
    let mut i = i.wrapping_sub(size);

    i = i.wrapping_sub(size & (i & lsbit).wrapping_neg());
    i / 2
}

/// Is this base and size safe for word-wide copying?
///
/// The size must be a multiple of the alignment, and so must the base
/// address unless the architecture does unaligned access efficiently —
/// which is what `efficient_unaligned` carries in from
/// `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS`. It is passed in rather than
/// guessed at, because guessing would silently pick a different swap
/// strategy on some architecture nobody was testing on.
#[inline]
fn is_aligned(base: *const u8, size: usize, align: usize, efficient_unaligned: bool) -> bool {
    let mut lsbits = size as u8;

    if !efficient_unaligned {
        lsbits |= base as usize as u8;
    }
    (lsbits as usize & (align.wrapping_sub(1))) == 0
}

extern "C" {
    /// `lib/sort.c`. Calls `cond_resched()`, which is a scheduling
    /// primitive and, under `CONFIG_PREEMPT_DYNAMIC`, a static call patched
    /// at boot.
    fn rust_sort_cond_resched();
}

/// Body of `sort_r()`, `sort_r_nonatomic()`, `sort()` and `sort_nonatomic()`.
///
/// # Safety
/// `base` must point at `num` elements of `size` bytes. `cmp_func` and
/// `swap_func` must each be a sentinel tag or a valid callback, with `priv_`
/// matching. Same contract as the C's `__sort_r()`.
#[no_mangle]
pub unsafe extern "C" fn rust_sort_r(
    base: *mut c_void,
    num: usize,
    size: usize,
    cmp_func: *const c_void,
    swap_func: *const c_void,
    priv_: *const c_void,
    may_schedule: bool,
    efficient_unaligned: bool,
) {
    let base = base as *mut u8;

    // Pre-scaled byte counters, as in the C.
    let mut n = num.wrapping_mul(size);
    let mut a = (num / 2).wrapping_mul(size);
    let lsbit = size & size.wrapping_neg();
    let mut shift = 0usize;

    if a == 0 {
        // num < 2 || size == 0
        return;
    }

    let mut swap_func = swap_func;

    // Called from sort() with no swap function: fall through to the default.
    if swap_func as usize == SWAP_WRAPPER {
        // SAFETY: SWAP_WRAPPER means priv_ is a `struct wrapper`.
        let w = unsafe { &*(priv_ as *const Wrapper) };

        if w.swap.is_none() {
            swap_func = core::ptr::null();
        }
    }

    if swap_func.is_null() {
        swap_func = if is_aligned(base, size, 8, efficient_unaligned) {
            SWAP_WORDS_64 as *const c_void
        } else if is_aligned(base, size, 4, efficient_unaligned) {
            SWAP_WORDS_32 as *const c_void
        } else {
            SWAP_BYTES as *const c_void
        };
    }

    // Loop invariants:
    //   1. elements [a, n) satisfy the heap property
    //   2. elements [n, num*size) are sorted
    //   3. a <= b <= c <= d <= n, whenever they are valid
    //
    // SAFETY for the whole loop: every offset formed below is a multiple of
    // `size` strictly less than `num * size`, so every pointer stays inside
    // the caller's array. The C's own bounds arguments carry over unchanged
    // because the arithmetic is identical.
    unsafe {
        loop {
            if a != 0 {
                // Building the heap: sift down a.
                a = a.wrapping_sub(size.wrapping_shl(shift as u32));
            } else if n > 3usize.wrapping_mul(size) {
                // Sorting: extract the two largest elements.
                n = n.wrapping_sub(size);
                do_swap(base, base.add(n), size, swap_func, priv_);
                shift = (do_cmp(base.add(size), base.add(2usize.wrapping_mul(size)), cmp_func, priv_) <= 0) as usize;
                a = size.wrapping_shl(shift as u32);
                n = n.wrapping_sub(size);
                do_swap(base.add(a), base.add(n), size, swap_func, priv_);
            } else {
                // Sort complete.
                break;
            }

            // Sift the element at "a" down into the heap, bottom-up: find
            // the sift-down path all the way to the leaves at one compare
            // per level, then backtrack to find where the target belongs.
            // Elements tend to sift close to the leaves, so this uses a bit
            // over half as many compares on average as two per level would.
            let mut b = a;
            let c;
            let d;

            loop {
                let cc = (2usize.wrapping_mul(b)).wrapping_add(size);
                let dd = cc.wrapping_add(size);

                if dd >= n {
                    c = cc;
                    d = dd;
                    break;
                }
                b = if do_cmp(base.add(cc), base.add(dd), cmp_func, priv_) > 0 { cc } else { dd };
            }
            if d == n {
                // Last leaf, with no sibling.
                b = c;
            }

            // Backtrack from "b" to where "a" belongs.
            while b != a && do_cmp(base.add(a), base.add(b), cmp_func, priv_) >= 0 {
                b = parent(b, lsbit, size);
            }
            let target = b;

            while b != a {
                b = parent(b, lsbit, size);
                do_swap(base.add(b), base.add(target), size, swap_func, priv_);
            }

            if may_schedule {
                rust_sort_cond_resched();
            }
        }

        n = n.wrapping_sub(size);
        do_swap(base, base.add(n), size, swap_func, priv_);
        if n == size.wrapping_mul(2) && do_cmp(base, base.add(size), cmp_func, priv_) > 0 {
            do_swap(base, base.add(size), size, swap_func, priv_);
        }
    }
}
