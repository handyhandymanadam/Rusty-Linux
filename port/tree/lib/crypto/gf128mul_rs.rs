// SPDX-License-Identifier: GPL-2.0-or-later

//! GF(2^128) multiplication -- the Rust behind `lib/crypto/gf128mul.c`.
//!
//! Ported from `lib/crypto/gf128mul.c` (6.18.49), Copyright (c) 2003, Dr Brian
//! Gladman, Worcester, UK and (c) 2006, Rik Snel. The upstream licence text is
//! kept verbatim in `gf128mul_glue.c`.
//!
//! Replaces: lib/crypto/gf128mul.c
//!
//! # What is here, and what is in C (`gf128mul_glue.c`)
//!
//! Rust: the two reduction tables (`xda_le`/`xda_be`, built at compile time
//! from the closed form), every multiply by x and by x^8, the constant-time
//! `gf128mul_lle()`, the 4 KiB (lle) and 64 KiB (bbe) table FILL and the
//! table multiplies.
//!
//! C: all seven `EXPORT_SYMBOL`s (each a pure pass-through to a
//! `gf128mul_rs_*` function below), the allocation in `gf128mul_init_4k_lle()`
//! and `gf128mul_init_64k_bbe()` (`kzalloc()` is an `alloc_hooks` macro) and
//! `gf128mul_free_64k()`. Nothing in this file is exported by name to the
//! kernel; the `gf128mul_rs_*` symbols are only the glue's callees.
//!
//! # Endianness
//!
//! `be128` is two `__be64` (`a` first), `le128` two `__le64` (`b` first, then
//! `a`). The structs here hold the RAW stored words; `u64::from_be()` /
//! `to_be()` / `from_le()` / `to_le()` are `be64_to_cpu()` etc. The pure step
//! functions work on the CPU-order values and have a deliberately restricted
//! body (u64 locals, `<< >> ^ & | * as`) so `logs/proofs/gf128mul.py` can parse
//! and execute them in Z3.
//!
//! # Constant time
//!
//! `gf128mul_x8_lle_ti()` uses the closed form `xda_le()`, never a table, and
//! `gf128mul_lle()` keeps the C's manually 32-byte-aligned 19-element array
//! with zeroed odd entries (index `2*i + !bit`), as the C's comment explains.
//! The mask in `x_lle`/`x_bbe` is the header's `gf128mul_mask_from_bit()`.
//! Whether rustc preserves that is not proved (see the proof header).

use core::ptr;

/// `be128` (two `__be64`): the raw stored words.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Be128 {
    a: u64,
    b: u64,
}

/// `le128` (two `__le64`; `b` is stored first): the raw stored words.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Le128 {
    b: u64,
    a: u64,
}

/// `struct gf128mul_4k`: 256 `be128`, 4096 bytes.
#[repr(C)]
pub struct Gf128mul4k {
    t: [Be128; 256],
}

// ---------------------------------------------------------------------------
// Pure step functions (parsed by logs/proofs/gf128mul.py -- keep the body
// syntax restricted: `let` of u64 values, one final expression, and only
// `<< >> ^ & | *`, `as i64`/`as u64`, parentheses and integer literals).
// Each takes the CPU-order words (a, b) of the element and, where the C
// looks one up, the reduction word `tt`; it returns one CPU-order word.
// ---------------------------------------------------------------------------

/// `xda_be(i)`: reduction word for overflow byte `i`, "be" bit order.
const fn xda_be(i: u64) -> u64 {
    (((i >> 7) & 1) * 0x4380)
        ^ (((i >> 6) & 1) * 0x21c0)
        ^ (((i >> 5) & 1) * 0x10e0)
        ^ (((i >> 4) & 1) * 0x0870)
        ^ (((i >> 3) & 1) * 0x0438)
        ^ (((i >> 2) & 1) * 0x021c)
        ^ (((i >> 1) & 1) * 0x010e)
        ^ ((i & 1) * 0x0087)
}

/// `xda_le(i)`: reduction word for overflow byte `i`, "le" bit order.
const fn xda_le(i: u64) -> u64 {
    (((i >> 7) & 1) * 0xe100)
        ^ (((i >> 6) & 1) * 0x7080)
        ^ (((i >> 5) & 1) * 0x3840)
        ^ (((i >> 4) & 1) * 0x1c20)
        ^ (((i >> 3) & 1) * 0x0e10)
        ^ (((i >> 2) & 1) * 0x0708)
        ^ (((i >> 1) & 1) * 0x0384)
        ^ ((i & 1) * 0x01c2)
}

/// `gf128mul_x8_lle` / `_lle_ti`, new `a`: `(a >> 8) ^ (tt << 48)`.
fn x8_lle_a(a: u64, _b: u64, tt: u64) -> u64 {
    (a >> 8) ^ (tt << 48)
}

/// `gf128mul_x8_lle` / `_lle_ti`, new `b`: `(b >> 8) | (a << 56)`.
fn x8_lle_b(a: u64, b: u64, _tt: u64) -> u64 {
    (b >> 8) | (a << 56)
}

/// `gf128mul_x8_bbe` and `gf128mul_x8_ble`, new `a`: `(a << 8) | (b >> 56)`.
fn x8_be_a(a: u64, b: u64, _tt: u64) -> u64 {
    (a << 8) | (b >> 56)
}

/// `gf128mul_x8_bbe` and `gf128mul_x8_ble`, new `b`: `(b << 8) ^ tt`.
fn x8_be_b(_a: u64, b: u64, tt: u64) -> u64 {
    (b << 8) ^ tt
}

/// `gf128mul_x_lle`, new `a`. The mask is `gf128mul_mask_from_bit(b, 0)`:
/// `((s64)(b << 63)) >> 63`.
fn x_lle_a(a: u64, b: u64, _tt: u64) -> u64 {
    let m = (((b << 63) as i64) >> 63) as u64;
    (a >> 1) ^ (m & (0xe1 << 56))
}

/// `gf128mul_x_lle`, new `b`: `(b >> 1) | (a << 63)`.
fn x_lle_b(a: u64, b: u64, _tt: u64) -> u64 {
    (b >> 1) | (a << 63)
}

/// `gf128mul_x_bbe`, new `a`: `(a << 1) | (b >> 63)`.
fn x_bbe_a(a: u64, b: u64, _tt: u64) -> u64 {
    (a << 1) | (b >> 63)
}

/// `gf128mul_x_bbe`, new `b`. The mask is `gf128mul_mask_from_bit(a, 63)`.
fn x_bbe_b(a: u64, b: u64, _tt: u64) -> u64 {
    let m = ((a as i64) >> 63) as u64;
    (b << 1) ^ (m & 0x87)
}

// ---------------------------------------------------------------------------
// The two reduction tables, `gf128mul_table_le` / `gf128mul_table_be`.
// ---------------------------------------------------------------------------

const fn build_table(le: bool) -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = if le { xda_le(i as u64) } else { xda_be(i as u64) } as u16;
        i += 1;
    }
    t
}

static TABLE_LE: [u16; 256] = build_table(true);
static TABLE_BE: [u16; 256] = build_table(false);

// ---------------------------------------------------------------------------
// be128 helpers. All pointers are raw: the C aliases freely (r == x).
// ---------------------------------------------------------------------------

/// SAFETY (all four helpers): `p` is valid for reads/writes of one `Be128`.
unsafe fn load_be(p: *const Be128) -> (u64, u64) {
    // SAFETY: caller contract.
    unsafe { (u64::from_be((*p).a), u64::from_be((*p).b)) }
}

/// Stores `b` first then `a`, like the C (`r->b = ...; r->a = ...`).
unsafe fn store_be(p: *mut Be128, a: u64, b: u64) {
    // SAFETY: caller contract.
    unsafe {
        (*p).b = b.to_be();
        (*p).a = a.to_be();
    }
}

/// `be128_xor(r, p, q)`: on the raw words.
unsafe fn be128_xor(r: *mut Be128, p: *const Be128, q: *const Be128) {
    // SAFETY: caller contract.
    unsafe {
        (*r).a = (*p).a ^ (*q).a;
        (*r).b = (*p).b ^ (*q).b;
    }
}

/// `gf128mul_x_lle(r, x)`.
unsafe fn x_lle(r: *mut Be128, x: *const Be128) {
    // SAFETY: caller contract.
    unsafe {
        let (a, b) = load_be(x);
        store_be(r, x_lle_a(a, b, 0), x_lle_b(a, b, 0));
    }
}

/// `gf128mul_x_bbe(r, x)`.
unsafe fn x_bbe(r: *mut Be128, x: *const Be128) {
    // SAFETY: caller contract.
    unsafe {
        let (a, b) = load_be(x);
        store_be(r, x_bbe_a(a, b, 0), x_bbe_b(a, b, 0));
    }
}

/// `gf128mul_x8_lle(x)`: table version.
unsafe fn x8_lle(x: *mut Be128) {
    // SAFETY: caller contract.
    unsafe {
        let (a, b) = load_be(x);
        let tt = TABLE_LE[(b & 0xff) as usize] as u64;
        store_be(x, x8_lle_a(a, b, tt), x8_lle_b(a, b, tt));
    }
}

/// `gf128mul_x8_lle_ti(x)`: "time invariant" -- the closed form, no lookup.
unsafe fn x8_lle_ti(x: *mut Be128) {
    // SAFETY: caller contract.
    unsafe {
        let (a, b) = load_be(x);
        let tt = xda_le(b & 0xff); /* avoid table lookup */
        store_be(x, x8_lle_a(a, b, tt), x8_lle_b(a, b, tt));
    }
}

/// `gf128mul_x8_bbe(x)`.
unsafe fn x8_bbe(x: *mut Be128) {
    // SAFETY: caller contract.
    unsafe {
        let (a, b) = load_be(x);
        let tt = TABLE_BE[(a >> 56) as usize] as u64;
        store_be(x, x8_be_a(a, b, tt), x8_be_b(a, b, tt));
    }
}

// ---------------------------------------------------------------------------
// Entry points called by gf128mul_glue.c.
// ---------------------------------------------------------------------------

/// `gf128mul_x8_ble(r, x)`: `r = x * x^8` in the ble convention.
///
/// # Safety
/// `r` is writable and `x` readable for one `le128`; they may alias.
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_x8_ble(r: *mut Le128, x: *const Le128) {
    // SAFETY: caller contract.
    unsafe {
        let a = u64::from_le((*x).a);
        let b = u64::from_le((*x).b);
        let tt = TABLE_BE[(a >> 56) as usize] as u64;

        (*r).a = x8_be_a(a, b, tt).to_le();
        (*r).b = x8_be_b(a, b, tt).to_le();
    }
}

/// `gf128mul_lle(r, b)`: `*r = *r * *b`, the slow generic multiply whose
/// timing does not depend on `b`.
///
/// # Safety
/// `r` is readable and writable and `b` readable for one `be128` each. Like
/// the C, `r == b` is not supported (the C zeroes `*r` before it reads `b`).
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_lle(r: *mut Be128, b: *const Be128) {
    // 16 + 3 elements, zeroed; `p` is the array start rounded up to 32 bytes
    // (the C's PTR_ALIGN(&array[0], 2 * sizeof(be128))), so every even/odd
    // pair shares a cacheline. The odd elements stay zero.
    let mut array = [Be128 { a: 0, b: 0 }; 16 + 3];
    let base = array.as_mut_ptr().cast::<u8>();
    let addr = base as usize;
    let skew = ((addr + 31) & !31usize) - addr;
    // SAFETY: skew <= 31 and 16 + 3 elements are 304 bytes; p[0..16] ends at
    // skew + 256 <= 287 <= 304 bytes into `array`.
    let p = unsafe { base.add(skew) }.cast::<Be128>();

    // SAFETY: caller contract for `r`; `p[0..16]` is inside `array` (above).
    unsafe {
        *p = *r;
        for i in 0..7 {
            x_lle(p.add(2 * i + 2), p.add(2 * i));
        }

        ptr::write_bytes(r, 0, 1);
        let mut i = 0usize;
        loop {
            // `b` is re-read each round, like the C.
            let ch = *b.cast::<u8>().add(15 - i);

            be128_xor(r, r, p.add(usize::from(ch & 0x80 == 0)));
            be128_xor(r, r, p.add(2 + usize::from(ch & 0x40 == 0)));
            be128_xor(r, r, p.add(4 + usize::from(ch & 0x20 == 0)));
            be128_xor(r, r, p.add(6 + usize::from(ch & 0x10 == 0)));
            be128_xor(r, r, p.add(8 + usize::from(ch & 0x08 == 0)));
            be128_xor(r, r, p.add(10 + usize::from(ch & 0x04 == 0)));
            be128_xor(r, r, p.add(12 + usize::from(ch & 0x02 == 0)));
            be128_xor(r, r, p.add(14 + usize::from(ch & 0x01 == 0)));

            i += 1;
            if i >= 16 {
                break;
            }

            x8_lle_ti(r); /* use the time invariant version */
        }
    }
}

/// The fill half of `gf128mul_init_64k_bbe(g)`: `t[i]->t[b]` = `g * x^(8*i) * b`.
///
/// # Safety
/// `t` points to 16 pointers, each to a zeroed `Gf128mul4k` (256 `be128`);
/// `g` is readable for one `be128`.
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_fill_64k_bbe(t: *const *mut Gf128mul4k, g: *const Be128) {
    // SAFETY: caller contract: 16 live tables, each 256 elements.
    unsafe {
        let tab = |i: usize, j: usize| -> *mut Be128 {
            (*(*t.add(i))).t.as_mut_ptr().add(j)
        };

        *tab(0, 1) = *g;
        let mut j = 1usize;
        while j <= 64 {
            x_bbe(tab(0, j + j), tab(0, j));
            j <<= 1;
        }

        let mut i = 0usize;
        loop {
            let mut j = 2usize;
            while j < 256 {
                for k in 1..j {
                    be128_xor(tab(i, j + k), tab(i, j), tab(i, k));
                }
                j += j;
            }

            i += 1;
            if i >= 16 {
                break;
            }

            let mut j = 128usize;
            while j > 0 {
                *tab(i, j) = *tab(i - 1, j);
                x8_bbe(tab(i, j));
                j >>= 1;
            }
        }
    }
}

/// `gf128mul_64k_bbe(a, t)`: `*a = *a * g` for the table's `g`.
///
/// # Safety
/// `a` is readable and writable for one `be128`; `t` points to 16 pointers to
/// filled tables.
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_64k_bbe(a: *mut Be128, t: *const *mut Gf128mul4k) {
    // SAFETY: caller contract.
    unsafe {
        let ap = a.cast::<u8>();
        let ent = |i: usize, byte: u8| -> *const Be128 {
            (*(*t.add(i))).t.as_ptr().add(byte as usize)
        };
        let mut r = *ent(0, *ap.add(15));
        let rp: *mut Be128 = &mut r;
        for i in 1..16 {
            be128_xor(rp, rp, ent(i, *ap.add(15 - i)));
        }
        *a = r;
    }
}

/// The fill half of `gf128mul_init_4k_lle(g)`: `t->t[b]` = `g * b` (lle).
///
/// # Safety
/// `t` points to a zeroed `Gf128mul4k`; `g` is readable for one `be128`.
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_fill_4k_lle(t: *mut Gf128mul4k, g: *const Be128) {
    // SAFETY: caller contract.
    unsafe {
        let tab = (*t).t.as_mut_ptr();

        *tab.add(128) = *g;
        let mut j = 64usize;
        while j > 0 {
            x_lle(tab.add(j), tab.add(j + j));
            j >>= 1;
        }

        let mut j = 2usize;
        while j < 256 {
            for k in 1..j {
                be128_xor(tab.add(j + k), tab.add(j), tab.add(k));
            }
            j += j;
        }
    }
}

/// `gf128mul_4k_lle(a, t)`: `*a = *a * g` for the table's `g`.
///
/// # Safety
/// `a` is readable and writable for one `be128`; `t` points to a filled table.
#[no_mangle]
pub unsafe extern "C" fn gf128mul_rs_4k_lle(a: *mut Be128, t: *const Gf128mul4k) {
    // SAFETY: caller contract.
    unsafe {
        let ap = a.cast::<u8>();
        let tab = (*t).t.as_ptr();
        let mut r = *tab.add(*ap.add(15) as usize);
        let rp: *mut Be128 = &mut r;
        let mut i = 15usize;
        while i > 0 {
            i -= 1;
            x8_lle(rp);
            be128_xor(rp, rp, tab.add(*ap.add(i) as usize));
        }
        *a = r;
    }
}
