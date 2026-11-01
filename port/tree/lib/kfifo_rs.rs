// SPDX-License-Identifier: GPL-2.0-or-later

//! Generic kernel FIFO -- the Rust behind the core of `lib/kfifo.c`.
//!
//! Ported from `lib/kfifo.c` (6.18.49), "A generic kernel FIFO implementation" by Stefani Seibold: the copy-and-index core of the
//! single-producer / single-consumer ring buffer `struct __kfifo { in, out, mask, esize, data }` (indices free-running `u32`s, the
//! buffer a power of two of elements) -- `__kfifo_init`, `__kfifo_in`, `__kfifo_out_peek`, `__kfifo_out_linear`, `__kfifo_out`, and
//! the record FIFO (every record prefixed by a 1- or 2-byte length) `__kfifo_max_r`, `__kfifo_len_r`, `__kfifo_in_r`,
//! `__kfifo_out_peek_r`, `__kfifo_out_linear_r`, `__kfifo_out_r`, `__kfifo_skip_r`. In C (`kfifo.c`, thunk-shaped by omission:
//! it is upstream minus these): allocation (`__kfifo_alloc/free`, slab), the `*_user` copies (`copy_{from,to}_user`) and the
//! `*_dma_*` functions (`scatterlist`, `BUG_ON`).
//!
//! # The ordering contract (concurrency bar, item 1)
//! One producer and one consumer may run concurrently WITHOUT a lock (that is the point of the structure):
//! * the producer copies the data, then `smp_wmb()`, then advances `in`; the consumer therefore sees the new `in` only after the
//!   data is written (pairing with the consumer-side `smp_rmb()` in the `kfifo.h` macros);
//! * the consumer copies the data out, `smp_wmb()` (the C names it so; it orders the copy-out before the `out` update that frees
//!   the slot), then advances `out`;
//! * each index is written by exactly one side and read by the other, so every access is a plain 32-bit load or store (`Relaxed`
//!   atomics here: the same instruction on x86, and what makes the cross-thread read defined in Rust); `in += len` is load + store,
//!   NOT `fetch_add` (a single writer, and the C emits no `lock`).
//! * `smp_wmb()` is `fence(Release)`: no instruction on x86 (TSO already orders stores), a `dmb ishst`-class barrier elsewhere.
//!   x86 hides a missing barrier; the weak-memory check is the parked arm64 criterion.
//! The record functions poke/peek the 1- or 2-byte length byte by byte through `data[(i) & mask]` exactly as the C does.
//!
//! Every export is `#[inline(never)]` (an inlined callee gets its caller's MODVERSIONS fingerprint from `gendwarfksyms`, see
//! `time_rs.rs`). None has a guard, WARN or static key, so no C entry stays: `kernel::kabi_export!` carries each export and its
//! contract (C fingerprints taken from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: lib/kfifo.c (the copy-and-index core; allocation, user copies and DMA stay C)

use core::ffi::{c_int, c_void};
use core::sync::atomic::{fence, AtomicU32, Ordering};

const EINVAL: c_int = 22;

/// Mirrors `struct __kfifo` (`include/linux/kfifo.h`).
#[repr(C)]
pub struct Kfifo {
    in_: u32,
    out: u32,
    mask: u32,
    esize: u32,
    data: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<Kfifo>() == 24);
    assert!(core::mem::offset_of!(Kfifo, data) == 16);
};

/// `fifo->in` / `fifo->out`: a shared index, written by one side only.
#[inline(always)]
unsafe fn ld(p: *const u32) -> u32 {
    unsafe { AtomicU32::from_ptr(p as *mut u32) }.load(Ordering::Relaxed)
}

#[inline(always)]
unsafe fn st(p: *mut u32, v: u32) {
    unsafe { AtomicU32::from_ptr(p) }.store(v, Ordering::Relaxed)
}

/// `kfifo_unused()`.
#[inline(always)]
unsafe fn kfifo_unused(fifo: *const Kfifo) -> u32 {
    unsafe { (*fifo).mask.wrapping_add(1).wrapping_sub(ld(&raw const (*fifo).in_).wrapping_sub(ld(&raw const (*fifo).out))) }
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#__kfifo",
    "structure_type __kfifo { member base_type unsigned int byte_size(4) encoding(7) in data_member_location(0) , member base_type unsigned int byte_size(4) encoding(7) out data_member_location(4) , member base_type unsigned int byte_size(4) encoding(7) mask data_member_location(8) , member base_type unsigned int byte_size(4) encoding(7) esize data_member_location(12) , member pointer_type { base_type void } data data_member_location(16) } byte_size(24)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");

kernel::kabi_export! {
    __kfifo_init,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type void } buffer , formal_parameter base_type unsigned int byte_size(4) encoding(7) size , formal_parameter t#size_t esize ) -> base_type int byte_size(4) encoding(5)",
}
/// `__kfifo_init()`: use `buffer` (of `size` bytes) as a FIFO of `esize`-byte elements; the element count is rounded down to a power
/// of two. Returns 0, or -EINVAL if fewer than two elements fit.
///
/// # Safety
/// `fifo` writable; `buffer` valid for `size` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_init(fifo: *mut Kfifo, buffer: *mut c_void, size: u32, esize: usize) -> c_int {
    let mut size: u32 = (size as usize / esize) as u32;

    if size == 0 || (size & (size - 1)) != 0 {
        /* rounddown_pow_of_two(): 1UL << (fls_long(n) - 1); for 0 the shift is -1, i.e. 63 on x86 -> truncated to 0 */
        size = (1u64.wrapping_shl((64 - (size as u64).leading_zeros()).wrapping_sub(1))) as u32;
    }

    unsafe {
        st(&raw mut (*fifo).in_, 0);
        st(&raw mut (*fifo).out, 0);
        (*fifo).esize = esize as u32;
        (*fifo).data = buffer;
    }

    if size < 2 {
        unsafe { (*fifo).mask = 0 };
        return -EINVAL;
    }
    unsafe { (*fifo).mask = size - 1 };

    0
}

/// `kfifo_copy_in()`: copy `len` elements in at element offset `off`, wrapping, then `smp_wmb()`.
unsafe fn kfifo_copy_in(fifo: *mut Kfifo, src: *const c_void, len: u32, off: u32) {
    let mut size: u32 = unsafe { (*fifo).mask }.wrapping_add(1);
    let esize: u32 = unsafe { (*fifo).esize };
    let mut off = off & unsafe { (*fifo).mask };
    let mut len = len;

    if esize != 1 {
        off = off.wrapping_mul(esize);
        size = size.wrapping_mul(esize);
        len = len.wrapping_mul(esize);
    }
    let l = core::cmp::min(len, size.wrapping_sub(off));

    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, ((*fifo).data as *mut u8).add(off as usize), l as usize);
        core::ptr::copy_nonoverlapping((src as *const u8).add(l as usize), (*fifo).data as *mut u8, len.wrapping_sub(l) as usize);
    }
    fence(Ordering::Release); /* smp_wmb() */
}

kernel::kabi_export! {
    __kfifo_in,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { const_type { base_type void } } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_in()`: put up to `len` elements; returns how many fitted.
///
/// # Safety
/// `fifo` initialised; `buf` valid for `len` elements.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_in(fifo: *mut Kfifo, buf: *const c_void, len: u32) -> u32 {
    let l = unsafe { kfifo_unused(fifo) };
    let len = if len > l { l } else { len };

    unsafe {
        kfifo_copy_in(fifo, buf, len, ld(&raw const (*fifo).in_));
        st(&raw mut (*fifo).in_, ld(&raw const (*fifo).in_).wrapping_add(len));
    }
    len
}

/// `kfifo_copy_out()`: copy `len` elements out from element offset `off`, wrapping, then `smp_wmb()`.
unsafe fn kfifo_copy_out(fifo: *mut Kfifo, dst: *mut c_void, len: u32, off: u32) {
    let mut size: u32 = unsafe { (*fifo).mask }.wrapping_add(1);
    let esize: u32 = unsafe { (*fifo).esize };
    let mut off = off & unsafe { (*fifo).mask };
    let mut len = len;

    if esize != 1 {
        off = off.wrapping_mul(esize);
        size = size.wrapping_mul(esize);
        len = len.wrapping_mul(esize);
    }
    let l = core::cmp::min(len, size.wrapping_sub(off));

    unsafe {
        core::ptr::copy_nonoverlapping(((*fifo).data as *const u8).add(off as usize), dst as *mut u8, l as usize);
        core::ptr::copy_nonoverlapping((*fifo).data as *const u8, (dst as *mut u8).add(l as usize), len.wrapping_sub(l) as usize);
    }
    fence(Ordering::Release); /* smp_wmb() */
}

kernel::kabi_export! {
    __kfifo_out_peek,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type void } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out_peek()`: copy out up to `len` elements without consuming them; returns how many.
///
/// # Safety
/// `fifo` initialised; `buf` valid for `len` elements.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out_peek(fifo: *mut Kfifo, buf: *mut c_void, len: u32) -> u32 {
    let l = unsafe { ld(&raw const (*fifo).in_).wrapping_sub(ld(&raw const (*fifo).out)) };
    let len = if len > l { l } else { len };

    unsafe { kfifo_copy_out(fifo, buf, len, ld(&raw const (*fifo).out)) };
    len
}

kernel::kabi_export! {
    __kfifo_out_linear,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } tail , formal_parameter base_type unsigned int byte_size(4) encoding(7) n ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out_linear()`: how many elements can be read without wrapping, and where they start (`*tail`, if not NULL).
///
/// # Safety
/// `fifo` initialised; `tail` NULL or writable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out_linear(fifo: *mut Kfifo, tail: *mut u32, n: u32) -> u32 {
    let size: u32 = unsafe { (*fifo).mask }.wrapping_add(1);
    let off: u32 = unsafe { ld(&raw const (*fifo).out) } & unsafe { (*fifo).mask };

    if !tail.is_null() {
        unsafe { *tail = off };
    }

    core::cmp::min(core::cmp::min(n, unsafe { ld(&raw const (*fifo).in_).wrapping_sub(ld(&raw const (*fifo).out)) }), size.wrapping_sub(off))
}

kernel::kabi_export! {
    __kfifo_out,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type void } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out()`: take up to `len` elements out; returns how many.
///
/// # Safety
/// As [`__kfifo_out_peek`].
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out(fifo: *mut Kfifo, buf: *mut c_void, len: u32) -> u32 {
    let len = unsafe { __kfifo_out_peek(fifo, buf, len) };
    unsafe { st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(len)) };
    len
}

kernel::kabi_export! {
    __kfifo_max_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) len , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_max_r()`: the longest record a `recsize`-byte length prefix can describe, capped at `len`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn __kfifo_max_r(len: u32, recsize: usize) -> u32 {
    let max: u32 = (1u32.wrapping_shl((recsize << 3) as u32)).wrapping_sub(1);

    if len > max {
        return max;
    }
    len
}

/// `__kfifo_peek_n()`: the length stored in front of the record at `out`.
unsafe fn __kfifo_peek_n(fifo: *mut Kfifo, recsize: usize) -> u32 {
    let mask = unsafe { (*fifo).mask };
    let data = unsafe { (*fifo).data } as *const u8;
    let out = unsafe { ld(&raw const (*fifo).out) };

    let mut l: u32 = unsafe { *data.add((out & mask) as usize) } as u32;

    if recsize.wrapping_sub(1) != 0 {
        l |= (unsafe { *data.add((out.wrapping_add(1) & mask) as usize) } as u32) << 8;
    }

    l
}

/// `__kfifo_poke_n()`: store the length in front of the record at `in`.
unsafe fn __kfifo_poke_n(fifo: *mut Kfifo, n: u32, recsize: usize) {
    let mask = unsafe { (*fifo).mask };
    let data = unsafe { (*fifo).data } as *mut u8;
    let in_ = unsafe { ld(&raw const (*fifo).in_) };

    unsafe { *data.add((in_ & mask) as usize) = n as u8 };

    if recsize > 1 {
        unsafe { *data.add((in_.wrapping_add(1) & mask) as usize) = (n >> 8) as u8 };
    }
}

kernel::kabi_export! {
    __kfifo_len_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_len_r()`: length of the next record.
///
/// # Safety
/// `fifo` initialised.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_len_r(fifo: *mut Kfifo, recsize: usize) -> u32 {
    unsafe { __kfifo_peek_n(fifo, recsize) }
}

kernel::kabi_export! {
    __kfifo_in_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { const_type { base_type void } } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_in_r()`: put one record; returns its length, or 0 if it does not fit.
///
/// # Safety
/// `fifo` initialised; `buf` valid for `len` elements.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_in_r(fifo: *mut Kfifo, buf: *const c_void, len: u32, recsize: usize) -> u32 {
    if (len as usize).wrapping_add(recsize) > unsafe { kfifo_unused(fifo) } as usize {
        return 0;
    }

    unsafe {
        __kfifo_poke_n(fifo, len, recsize);

        kfifo_copy_in(fifo, buf, len, ld(&raw const (*fifo).in_).wrapping_add(recsize as u32));
        st(&raw mut (*fifo).in_, ld(&raw const (*fifo).in_).wrapping_add(len).wrapping_add(recsize as u32));
    }
    len
}

/// `kfifo_out_copy_r()`.
unsafe fn kfifo_out_copy_r(fifo: *mut Kfifo, buf: *mut c_void, len: u32, recsize: usize, n: *mut u32) -> u32 {
    let mut len = len;
    unsafe { *n = __kfifo_peek_n(fifo, recsize) };

    if len > unsafe { *n } {
        len = unsafe { *n };
    }

    unsafe { kfifo_copy_out(fifo, buf, len, ld(&raw const (*fifo).out).wrapping_add(recsize as u32)) };
    len
}

kernel::kabi_export! {
    __kfifo_out_peek_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type void } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out_peek_r()`: copy out the next record (up to `len`) without consuming it.
///
/// # Safety
/// `fifo` initialised; `buf` valid for `len` elements.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out_peek_r(fifo: *mut Kfifo, buf: *mut c_void, len: u32, recsize: usize) -> u32 {
    let mut n: u32 = 0;

    if unsafe { ld(&raw const (*fifo).in_) == ld(&raw const (*fifo).out) } {
        return 0;
    }

    unsafe { kfifo_out_copy_r(fifo, buf, len, recsize, &mut n) }
}

kernel::kabi_export! {
    __kfifo_out_linear_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } tail , formal_parameter base_type unsigned int byte_size(4) encoding(7) n , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out_linear_r()`: like `__kfifo_out_linear()` for the next record.
///
/// # Safety
/// `fifo` initialised; `tail` NULL or writable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out_linear_r(fifo: *mut Kfifo, tail: *mut u32, n: u32, recsize: usize) -> u32 {
    if unsafe { ld(&raw const (*fifo).in_) == ld(&raw const (*fifo).out) } {
        return 0;
    }

    if !tail.is_null() {
        unsafe { *tail = ld(&raw const (*fifo).out).wrapping_add(recsize as u32) };
    }

    core::cmp::min(n, unsafe { __kfifo_peek_n(fifo, recsize) })
}

kernel::kabi_export! {
    __kfifo_out_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter pointer_type { base_type void } buf , formal_parameter base_type unsigned int byte_size(4) encoding(7) len , formal_parameter t#size_t recsize ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `__kfifo_out_r()`: take the next record out (up to `len`); the rest of an over-long record is dropped.
///
/// # Safety
/// `fifo` initialised; `buf` valid for `len` elements.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_out_r(fifo: *mut Kfifo, buf: *mut c_void, len: u32, recsize: usize) -> u32 {
    let mut n: u32 = 0;

    if unsafe { ld(&raw const (*fifo).in_) == ld(&raw const (*fifo).out) } {
        return 0;
    }

    let len = unsafe { kfifo_out_copy_r(fifo, buf, len, recsize, &mut n) };
    unsafe { st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(n).wrapping_add(recsize as u32)) };
    len
}

kernel::kabi_export! {
    __kfifo_skip_r,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#__kfifo } fifo , formal_parameter t#size_t recsize ) -> base_type void",
}
/// `__kfifo_skip_r()`: drop the next record.
///
/// # Safety
/// `fifo` initialised.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __kfifo_skip_r(fifo: *mut Kfifo, recsize: usize) {
    let n = unsafe { __kfifo_peek_n(fifo, recsize) };
    unsafe { st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(n).wrapping_add(recsize as u32)) };
}
