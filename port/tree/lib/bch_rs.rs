// SPDX-License-Identifier: GPL-2.0-only

//! Binary BCH encoder / decoder -- the Rust behind `lib/bch.c`.
//!
//! Ported from `lib/bch.c` (6.18.49), "Generic binary BCH encoding/decoding library" (Ivan Djelic, Parrot S.A.). Encoding processes 32 input bits at a
//! time through four remainder tables; decoding computes the syndromes, finds the error locator polynomial with the simplified binary Berlekamp-Massey
//! algorithm, and finds its roots with the Berlekamp Trace Algorithm down to degree 4 followed by ad hoc solvers (BTZ). All of it is here, together with
//! `bch_init` (Galois-field tables, generator polynomial, encoding tables) and `bch_free`. The C glue (`bch_glue.c`) keeps the four exports as thunks (their
//! MODVERSIONS fingerprints come from the DWARF of the definition), `kmalloc`/`kzalloc`/`kfree`, the `WARN_ON` site and the `struct bch_control` layout
//! assertions. Not ported: the `USE_CHIEN_SEARCH` reference implementation (dead code upstream) and the `CONFIG_BCH_CONST_PARAMS` variant, which keeps
//! building upstream's file (see the Makefile).
//!
//! The arithmetic follows the C integer promotions: `int` quantities are `i32`, `unsigned int` ones `u32`, and wrapping operations are used wherever the C
//! relies on modular arithmetic.
//!
//! Replaces: lib/bch.c (everything; allocation, the exports and the WARN site stay C)

use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("bch_rs.rs: x86-64 little-endian only (cpu_to_be32 is a byte swap, struct layouts)");

const BCH_MAX_M: usize = 15; // 2KB
const BCH_MAX_T: i32 = 64; // 64 bit correction
const BCH_ECC_MAX_WORDS: usize = (BCH_MAX_M * BCH_MAX_T as usize + 31) / 32;
const EINVAL: c_int = 22;
const EBADMSG: c_int = 74;

/// `struct bch_control` (include/linux/bch.h).
#[repr(C)]
pub struct BchControl {
    m: c_uint,
    n: c_uint,
    t: c_uint,
    ecc_bits: c_uint,
    ecc_bytes: c_uint,
    a_pow_tab: *mut u16,
    a_log_tab: *mut u16,
    mod8_tab: *mut u32,
    ecc_buf: *mut u32,
    ecc_buf2: *mut u32,
    xi_tab: *mut c_uint,
    syn: *mut c_uint,
    cache: *mut c_int,
    elp: *mut GfPoly,
    poly_2t: [*mut GfPoly; 4],
    swap_bits: bool,
}

/// `struct gf_poly`: a polynomial over GF(2^m); the terms follow the degree.
#[repr(C)]
pub struct GfPoly {
    deg: c_uint,
    // c[]: flexible array
}

extern "C" {
    static rust_bch_ctl_size: usize; // sizeof(struct bch_control)

    fn rust_bchw_kmalloc(size: usize) -> *mut c_void;
    fn rust_bchw_kzalloc(size: usize) -> *mut c_void;
    fn rust_bchw_kfree(p: *mut c_void);
    fn rust_bchw_warn_r_bytes(cond: bool) -> bool;
}

/// `GF_POLY_SZ(d)`.
#[inline(always)]
fn gf_poly_sz(d: u32) -> usize {
    4 + (d as usize + 1) * 4
}

/// `sizeof(struct gf_poly_deg1)`: the stride used by `factor_polynomial` to place `h` inside `f`.
const GF_POLY_DEG1_SZ: usize = 12;

/// `poly->c`.
#[inline(always)]
unsafe fn pc(p: *mut GfPoly) -> *mut u32 {
    unsafe { (p as *mut u8).add(4) as *mut u32 }
}

#[inline(always)]
unsafe fn ecc_words(b: &BchControl) -> u32 {
    (b.m.wrapping_mul(b.t) + 31) / 32
}

#[inline(always)]
unsafe fn ecc_bytes_of(b: &BchControl) -> u32 {
    (b.m.wrapping_mul(b.t) + 7) / 8
}

#[inline(always)]
fn swap_bits(b: &BchControl, v: u8) -> u8 {
    if !b.swap_bits {
        v
    } else {
        v.reverse_bits()
    }
}

/// `bch_encode_unaligned()`: process input data one byte at a time.
unsafe fn bch_encode_unaligned(b: &BchControl, mut data: *const u8, mut len: u32, ecc: *mut u32) {
    unsafe {
        let l = ecc_words(b) as usize - 1;
        while len != 0 {
            len -= 1;
            let tmp = swap_bits(b, *data) as u32;
            data = data.add(1);

            let mut p = b.mod8_tab.add((l + 1) * ((((*ecc) >> 24) ^ tmp) & 0xff) as usize);

            for i in 0..l {
                *ecc.add(i) = ((*ecc.add(i) << 8) | (*ecc.add(i + 1) >> 24)) ^ *p;
                p = p.add(1);
            }

            *ecc.add(l) = (*ecc.add(l) << 8) ^ *p;
        }
    }
}

/// `load_ecc8()`: ecc bytes to aligned, zero-padded 32-bit words.
unsafe fn load_ecc8(b: &BchControl, dst: *mut u32, mut src: *const u8) {
    unsafe {
        let mut pad = [0u8; 4];
        let nwords = ecc_words(b) as usize - 1;

        for i in 0..nwords {
            *dst.add(i) = ((swap_bits(b, *src) as u32) << 24)
                | ((swap_bits(b, *src.add(1)) as u32) << 16)
                | ((swap_bits(b, *src.add(2)) as u32) << 8)
                | swap_bits(b, *src.add(3)) as u32;
            src = src.add(4);
        }

        copy_nonoverlapping(src, pad.as_mut_ptr(), (ecc_bytes_of(b) as usize) - 4 * nwords);
        *dst.add(nwords) = ((swap_bits(b, pad[0]) as u32) << 24)
            | ((swap_bits(b, pad[1]) as u32) << 16)
            | ((swap_bits(b, pad[2]) as u32) << 8)
            | swap_bits(b, pad[3]) as u32;
    }
}

/// `store_ecc8()`: 32-bit ecc words to ecc bytes.
unsafe fn store_ecc8(b: &BchControl, mut dst: *mut u8, src: *const u32) {
    unsafe {
        let mut pad = [0u8; 4];
        let nwords = ecc_words(b) as usize - 1;

        for i in 0..nwords {
            let s = *src.add(i);
            *dst = swap_bits(b, (s >> 24) as u8);
            *dst.add(1) = swap_bits(b, (s >> 16) as u8);
            *dst.add(2) = swap_bits(b, (s >> 8) as u8);
            *dst.add(3) = swap_bits(b, s as u8);
            dst = dst.add(4);
        }
        let s = *src.add(nwords);
        pad[0] = swap_bits(b, (s >> 24) as u8);
        pad[1] = swap_bits(b, (s >> 16) as u8);
        pad[2] = swap_bits(b, (s >> 8) as u8);
        pad[3] = swap_bits(b, s as u8);
        copy_nonoverlapping(pad.as_ptr(), dst, (ecc_bytes_of(b) as usize) - 4 * nwords);
    }
}

/// `bch_encode()`: calculate the BCH ecc parity of `data`; `ecc` is both input and output (NULL = start from zero and keep the result internal).
#[no_mangle]
pub unsafe extern "C" fn rust_bch_encode(bch: *mut BchControl, mut data: *const u8, mut len: c_uint, ecc: *mut u8) {
    unsafe {
        let b = &*bch;
        let l = ecc_words(b) as usize - 1;
        let mut r = [0u32; BCH_ECC_MAX_WORDS];
        let r_bytes = ecc_words(b) as usize * 4;
        let tab0 = b.mod8_tab as *const u32;
        let tab1 = tab0.add(256 * (l + 1));
        let tab2 = tab1.add(256 * (l + 1));
        let tab3 = tab2.add(256 * (l + 1));

        if rust_bchw_warn_r_bytes(r_bytes > core::mem::size_of_val(&r)) {
            return;
        }

        if !ecc.is_null() {
            // load ecc parity bytes into internal 32-bit buffer
            load_ecc8(b, b.ecc_buf, ecc);
        } else {
            write_bytes(b.ecc_buf as *mut u8, 0, r_bytes);
        }

        // process first unaligned data bytes
        let m = (data as usize & 3) as u32;
        if m != 0 {
            let mlen = if len < 4 - m { len } else { 4 - m };
            bch_encode_unaligned(b, data, mlen, b.ecc_buf);
            data = data.add(mlen as usize);
            len -= mlen;
        }

        // process 32-bit aligned data words
        let mut pdata = data as *const u32;
        let mut mlen = len / 4;
        data = data.add(4 * mlen as usize);
        len -= 4 * mlen;
        copy_nonoverlapping(b.ecc_buf as *const u8, r.as_mut_ptr() as *mut u8, r_bytes);

        // split each 32-bit word into 4 polynomials of weight 8 (see the C source for the picture)
        while mlen != 0 {
            mlen -= 1;
            // input data is read in big-endian format
            let mut w = (*pdata).swap_bytes();
            pdata = pdata.add(1);
            if b.swap_bits {
                w = swap_bits(b, w as u8) as u32
                    | ((swap_bits(b, (w >> 8) as u8) as u32) << 8)
                    | ((swap_bits(b, (w >> 16) as u8) as u32) << 16)
                    | ((swap_bits(b, (w >> 24) as u8) as u32) << 24);
            }
            w ^= r[0];
            let p0 = tab0.add((l + 1) * ((w & 0xff) as usize));
            let p1 = tab1.add((l + 1) * (((w >> 8) & 0xff) as usize));
            let p2 = tab2.add((l + 1) * (((w >> 16) & 0xff) as usize));
            let p3 = tab3.add((l + 1) * (((w >> 24) & 0xff) as usize));

            for i in 0..l {
                r[i] = r[i + 1] ^ *p0.add(i) ^ *p1.add(i) ^ *p2.add(i) ^ *p3.add(i);
            }

            r[l] = *p0.add(l) ^ *p1.add(l) ^ *p2.add(l) ^ *p3.add(l);
        }
        copy_nonoverlapping(r.as_ptr() as *const u8, b.ecc_buf as *mut u8, r_bytes);

        // process last unaligned bytes
        if len != 0 {
            bch_encode_unaligned(b, data, len, b.ecc_buf);
        }

        // store ecc parity bytes into original parity buffer
        if !ecc.is_null() {
            store_ecc8(b, ecc, b.ecc_buf);
        }
    }
}

// ---- Galois field arithmetic ----

/// `modulo()`.
#[inline(always)]
fn modulo(b: &BchControl, mut v: u32) -> u32 {
    let n = b.n;
    while v >= n {
        v -= n;
        v = (v & n) + (v >> b.m);
    }
    v
}

/// `mod_s()`: shorter and faster modulo, only for v < 2N.
#[inline(always)]
fn mod_s(b: &BchControl, v: u32) -> u32 {
    let n = b.n;
    if v < n {
        v
    } else {
        v - n
    }
}

/// `deg()`: the most-significant bit index (`fls(poly) - 1`).
#[inline(always)]
fn deg(poly: u32) -> i32 {
    32 - poly.leading_zeros() as i32 - 1
}

/// `parity()`.
#[inline(always)]
fn parity(mut x: u32) -> u32 {
    x ^= x >> 1;
    x ^= x >> 2;
    x = (x & 0x1111_1111).wrapping_mul(0x1111_1111);
    (x >> 28) & 1
}

#[inline(always)]
unsafe fn lg(b: &BchControl, x: u32) -> u32 {
    unsafe { *b.a_log_tab.add(x as usize) as u32 }
}

#[inline(always)]
unsafe fn pw(b: &BchControl, i: u32) -> u32 {
    unsafe { *b.a_pow_tab.add(i as usize) as u32 }
}

#[inline(always)]
unsafe fn gf_mul(b: &BchControl, a: u32, c: u32) -> u32 {
    unsafe {
        if a != 0 && c != 0 {
            pw(b, mod_s(b, lg(b, a).wrapping_add(lg(b, c))))
        } else {
            0
        }
    }
}

#[inline(always)]
unsafe fn gf_sqr(b: &BchControl, a: u32) -> u32 {
    unsafe {
        if a != 0 {
            pw(b, mod_s(b, 2u32.wrapping_mul(lg(b, a))))
        } else {
            0
        }
    }
}

#[inline(always)]
unsafe fn gf_div(b: &BchControl, a: u32, c: u32) -> u32 {
    unsafe {
        if a != 0 {
            pw(b, mod_s(b, lg(b, a).wrapping_add(b.n).wrapping_sub(lg(b, c))))
        } else {
            0
        }
    }
}

#[inline(always)]
unsafe fn gf_inv(b: &BchControl, a: u32) -> u32 {
    unsafe { pw(b, b.n.wrapping_sub(lg(b, a))) }
}

/// `a_pow()`: the argument is a C `int`; its bit pattern is what `modulo()` sees as `unsigned`.
#[inline(always)]
unsafe fn a_pow(b: &BchControl, i: u32) -> u32 {
    unsafe { pw(b, modulo(b, i)) }
}

#[inline(always)]
unsafe fn a_ilog(b: &BchControl, x: u32) -> u32 {
    unsafe { mod_s(b, b.n.wrapping_sub(lg(b, x))) }
}

/// `compute_syndromes()`: ecc(a^j) for j = 1..2t.
unsafe fn compute_syndromes(b: &BchControl, mut ecc: *mut u32, syn: *mut u32) {
    unsafe {
        let t = b.t as i32;
        let mut s = b.ecc_bits as i32;

        // make sure extra bits in last ecc word are cleared
        let m = (s as u32) & 31;
        if m != 0 {
            *ecc.add((s / 32) as usize) &= !((1u32 << (32 - m)) - 1);
        }
        write_bytes(syn, 0, 2 * t as usize);

        // compute v(a^j) for j=1 .. 2t-1
        loop {
            let mut poly = *ecc;
            ecc = ecc.add(1);
            s -= 32;
            while poly != 0 {
                let i = deg(poly);
                let mut j = 0;
                while j < 2 * t {
                    *syn.add(j as usize) ^= a_pow(b, ((j + 1).wrapping_mul(i.wrapping_add(s))) as u32);
                    j += 2;
                }

                poly ^= 1u32.wrapping_shl(i as u32);
            }
            if s <= 0 {
                break;
            }
        }

        // v(a^(2j)) = v(a^j)^2
        for j in 0..t as usize {
            *syn.add(2 * j + 1) = gf_sqr(b, *syn.add(j));
        }
    }
}

/// `gf_poly_copy()`.
#[inline(always)]
unsafe fn gf_poly_copy(dst: *mut GfPoly, src: *mut GfPoly) {
    unsafe { copy_nonoverlapping(src as *const u8, dst as *mut u8, gf_poly_sz((*src).deg)) }
}

/// `compute_error_locator_polynomial()`: simplified binary Berlekamp-Massey; the degree of the locator or -1.
unsafe fn compute_error_locator_polynomial(b: &BchControl, syn: *const u32) -> i32 {
    unsafe {
        let t = b.t;
        let n = b.n;
        let mut pd: u32 = 1;
        let mut d: u32 = *syn;
        let elp = b.elp;
        let pelp = b.poly_2t[0];
        let elp_copy = b.poly_2t[1];
        let mut pp: i32 = -1;

        write_bytes(pelp as *mut u8, 0, gf_poly_sz(2 * t));
        write_bytes(elp as *mut u8, 0, gf_poly_sz(2 * t));

        (*pelp).deg = 0;
        *pc(pelp) = 1;
        (*elp).deg = 0;
        *pc(elp) = 1;

        // use simplified binary Berlekamp-Massey algorithm
        let mut i: u32 = 0;
        while i < t && (*elp).deg <= t {
            if d != 0 {
                let k = (2u32.wrapping_mul(i).wrapping_sub(pp as u32)) as i32;
                gf_poly_copy(elp_copy, elp);
                // e[i+1](X) = e[i](X)+di*dp^-1*X^2(i-p)*e[p](X)
                let mut tmp = lg(b, d).wrapping_add(n).wrapping_sub(lg(b, pd));
                let mut j = 0u32;
                while j <= (*pelp).deg {
                    if *pc(pelp).add(j as usize) != 0 {
                        let l = lg(b, *pc(pelp).add(j as usize));
                        *pc(elp).add(j.wrapping_add(k as u32) as usize) ^= a_pow(b, tmp.wrapping_add(l));
                    }
                    j += 1;
                }
                // compute l[i+1] = max(l[i]->c[l[p]+2*(i-p])
                tmp = (*pelp).deg.wrapping_add(k as u32);
                if tmp > (*elp).deg {
                    (*elp).deg = tmp;
                    gf_poly_copy(pelp, elp_copy);
                    pd = d;
                    pp = (2u32.wrapping_mul(i)) as i32;
                }
            }
            // di+1 = S(2i+3)+elp[i+1].1*S(2i+2)+...+elp[i+1].lS(2i+3-l)
            if i < t.wrapping_sub(1) {
                d = *syn.add((2 * i + 2) as usize);
                let mut j = 1u32;
                while j <= (*elp).deg {
                    d ^= gf_mul(b, *pc(elp).add(j as usize), *syn.add((2 * i + 2).wrapping_sub(j) as usize));
                    j += 1;
                }
            }
            i += 1;
        }
        if (*elp).deg > t {
            -1
        } else {
            (*elp).deg as i32
        }
    }
}

/// `solve_linear_system()`: solve an m x m linear system in GF(2) with an expected number of solutions; the number found.
unsafe fn solve_linear_system(b: &BchControl, rows: *mut u32, sol: *mut u32, nsol: i32) -> i32 {
    unsafe {
        let m = b.m as i32;
        let mut param = [0i32; BCH_MAX_M];

        let mut k: i32 = 0;
        let mut mask: u32 = 1u32.wrapping_shl(m as u32);

        // Gaussian elimination
        for c in 0..m {
            let mut rem: i32 = 0;
            let p = c - k;
            // find suitable row for elimination
            let mut r = p;
            while r < m {
                if *rows.add(r as usize) & mask != 0 {
                    if r != p {
                        core::ptr::swap(rows.add(r as usize), rows.add(p as usize));
                    }
                    rem = r + 1;
                    break;
                }
                r += 1;
            }
            if rem != 0 {
                // perform elimination on remaining rows
                let tmp = *rows.add(p as usize);
                let mut r = rem;
                while r < m {
                    if *rows.add(r as usize) & mask != 0 {
                        *rows.add(r as usize) ^= tmp;
                    }
                    r += 1;
                }
            } else {
                // elimination not needed, store defective row index
                param[k as usize] = c;
                k += 1;
            }
            mask >>= 1;
        }
        // rewrite system, inserting fake parameter rows
        if k > 0 {
            let mut p = k;
            let mut r = m - 1;
            while r >= 0 {
                if r > m - 1 - k && *rows.add(r as usize) != 0 {
                    // system has no solution
                    return 0;
                }

                if p != 0 && r == param[(p - 1) as usize] {
                    p -= 1;
                    *rows.add(r as usize) = 1u32.wrapping_shl((m - r) as u32);
                } else {
                    *rows.add(r as usize) = *rows.add((r - p) as usize);
                }
                r -= 1;
            }
        }

        if nsol != (1 << k) {
            // unexpected number of solutions
            return 0;
        }

        for p in 0..nsol {
            // set parameters for p-th solution
            for c in 0..k {
                let idx = param[c as usize] as usize;
                *rows.add(idx) = (*rows.add(idx) & !1) | (((p >> c) & 1) as u32);
            }

            // compute unique solution
            let mut tmp: u32 = 0;
            let mut r = m - 1;
            while r >= 0 {
                let mask = *rows.add(r as usize) & (tmp | 1);
                tmp |= parity(mask) << (m - r);
                r -= 1;
            }
            *sol.add(p as usize) = tmp >> 1;
        }
        nsol
    }
}

/// `find_affine4_roots()`: roots of the degree-4 affine monic polynomial X^4+aX^2+bX+c over GF(2^m).
unsafe fn find_affine4_roots(b: &BchControl, a: u32, bb: u32, c: u32, roots: *mut u32) -> i32 {
    unsafe {
        let m = b.m as i32;
        let mut mask: u32 = 0xff;
        let mut rows = [0u32; 16];

        let mut j = lg(b, bb) as i32;
        let mut k = lg(b, a) as i32;
        rows[0] = c;

        // build linear system to solve X^4+aX^2+bX+c = 0
        for i in 0..m as usize {
            rows[i + 1] = pw(b, 4 * i as u32)
                ^ (if a != 0 { pw(b, mod_s(b, k as u32)) } else { 0 })
                ^ (if bb != 0 { pw(b, mod_s(b, j as u32)) } else { 0 });
            j += 1;
            k += 2;
        }
        // transpose 16x16 matrix before passing it to linear solver; warning: this code assumes m < 16
        let mut j: u32 = 8;
        while j != 0 {
            let mut k: u32 = 0;
            while k < 16 {
                let t = ((rows[k as usize] >> j) ^ rows[(k + j) as usize]) & mask;
                rows[k as usize] ^= t << j;
                rows[(k + j) as usize] ^= t;
                k = (k + j + 1) & !j;
            }
            j >>= 1;
            mask ^= mask << j;
        }
        solve_linear_system(b, rows.as_mut_ptr(), roots, 4)
    }
}

/// `find_poly_deg1_roots()`: root r of a degree 1 polynomial (as log(1/r)).
unsafe fn find_poly_deg1_roots(b: &BchControl, poly: *mut GfPoly, roots: *mut u32) -> i32 {
    unsafe {
        let mut n = 0;
        let c = pc(poly);

        if *c != 0 {
            // poly[X] = bX+c with c!=0, root=c/b
            *roots.add(n) = mod_s(b, b.n.wrapping_sub(lg(b, *c)).wrapping_add(lg(b, *c.add(1))));
            n += 1;
        }
        n as i32
    }
}

/// `find_poly_deg2_roots()`.
unsafe fn find_poly_deg2_roots(b: &BchControl, poly: *mut GfPoly, roots: *mut u32) -> i32 {
    unsafe {
        let mut n = 0usize;
        let c = pc(poly);

        if *c != 0 && *c.add(1) != 0 {
            let l0 = lg(b, *c);
            let l1 = lg(b, *c.add(1));
            let l2 = lg(b, *c.add(2));

            // using z=a/bX, transform aX^2+bX+c into z^2+z+u (u=ac/b^2)
            let u = a_pow(b, l0.wrapping_add(l2).wrapping_add(2u32.wrapping_mul(b.n.wrapping_sub(l1))));
            // let u = sum(li.a^i) i=0..m-1; then compute r = sum(li.xi): r^2+r = u + a^k.Tr(u), i.e. r and r+1 are roots iff Tr(u)=0
            let mut r: u32 = 0;
            let mut v = u;
            while v != 0 {
                let i = deg(v);
                r ^= *b.xi_tab.add(i as usize);
                v ^= 1u32.wrapping_shl(i as u32);
            }
            // verify root
            if (gf_sqr(b, r) ^ r) == u {
                // reverse z=a/bX transformation and compute log(1/r)
                *roots.add(n) = modulo(b, 2u32.wrapping_mul(b.n).wrapping_sub(l1).wrapping_sub(lg(b, r)).wrapping_add(l2));
                n += 1;
                *roots.add(n) = modulo(b, 2u32.wrapping_mul(b.n).wrapping_sub(l1).wrapping_sub(lg(b, r ^ 1)).wrapping_add(l2));
                n += 1;
            }
        }
        n as i32
    }
}

/// `find_poly_deg3_roots()`.
unsafe fn find_poly_deg3_roots(b: &BchControl, poly: *mut GfPoly, roots: *mut u32) -> i32 {
    unsafe {
        let mut n = 0usize;
        let mut tmp = [0u32; 4];
        let c = pc(poly);

        if *c != 0 {
            // transform polynomial into monic X^3 + a2X^2 + b2X + c2
            let e3 = *c.add(3);
            let c2 = gf_div(b, *c, e3);
            let b2 = gf_div(b, *c.add(1), e3);
            let a2 = gf_div(b, *c.add(2), e3);

            // (X+a2)(X^3+a2X^2+b2X+c2) = X^4+aX^2+bX+c (affine)
            let cc = gf_mul(b, a2, c2); // c = a2c2
            let bb = gf_mul(b, a2, b2) ^ c2; // b = a2b2 + c2
            let aa = gf_sqr(b, a2) ^ b2; // a = a2^2 + b2

            // find the 4 roots of this affine polynomial
            if find_affine4_roots(b, aa, bb, cc, tmp.as_mut_ptr()) == 4 {
                // remove a2 from final list of roots
                for i in 0..4 {
                    if tmp[i] != a2 {
                        *roots.add(n) = a_ilog(b, tmp[i]);
                        n += 1;
                    }
                }
            }
        }
        n as i32
    }
}

/// `find_poly_deg4_roots()`.
unsafe fn find_poly_deg4_roots(b: &BchControl, poly: *mut GfPoly, roots: *mut u32) -> i32 {
    unsafe {
        let mut n = 0;
        let mut e: u32 = 0;
        let c = pc(poly);

        if *c == 0 {
            return 0;
        }

        // transform polynomial into monic X^4 + aX^3 + bX^2 + cX + d
        let e4 = *c.add(4);
        let mut d = gf_div(b, *c, e4);
        let cc = gf_div(b, *c.add(1), e4);
        let mut bb = gf_div(b, *c.add(2), e4);
        let a = gf_div(b, *c.add(3), e4);

        let (a2, b2, c2);
        // use Y=1/X transformation to get an affine polynomial
        if a != 0 {
            // first, eliminate cX by using z=X+e with ae^2+c=0
            if cc != 0 {
                // compute e such that e^2 = c/a
                let f = gf_div(b, cc, a);
                let mut l = lg(b, f);
                l = l.wrapping_add(if l & 1 != 0 { b.n } else { 0 });
                e = a_pow(b, l / 2);
                // use transformation z=X+e: z^4 + az^3 + b'z^2 + d' with b' = ae+b, d' = e^4+be^2+d
                d = a_pow(b, 2u32.wrapping_mul(l)) ^ gf_mul(b, bb, f) ^ d;
                bb = gf_mul(b, a, e) ^ bb;
            }
            // now, use Y=1/X to get Y^4 + b/dY^2 + a/dY + 1/d
            if d == 0 {
                // assume all roots have multiplicity 1
                return 0;
            }

            c2 = gf_inv(b, d);
            b2 = gf_div(b, a, d);
            a2 = gf_div(b, bb, d);
        } else {
            // polynomial is already affine
            c2 = d;
            b2 = cc;
            a2 = bb;
        }
        // find the 4 roots of this affine polynomial
        if find_affine4_roots(b, a2, b2, c2, roots) == 4 {
            for i in 0..4 {
                // post-process roots (reverse transformations)
                let f = if a != 0 { gf_inv(b, *roots.add(i)) } else { *roots.add(i) };
                *roots.add(i) = a_ilog(b, f ^ e);
            }
            n = 4;
        }
        n
    }
}

/// `gf_poly_logrep()`: build the monic, log-based representation of a polynomial.
unsafe fn gf_poly_logrep(b: &BchControl, a: *const GfPoly, rep: *mut i32) {
    unsafe {
        let d = (*a).deg as i32;
        let c = (a as *const u8).add(4) as *const u32;
        let l = b.n.wrapping_sub(lg(b, *c.add((*a).deg as usize))) as i32;

        // represent 0 values with -1; warning, rep[d] is not set to 1
        for i in 0..d as usize {
            *rep.add(i) = if *c.add(i) != 0 { mod_s(b, lg(b, *c.add(i)).wrapping_add(l as u32)) as i32 } else { -1 };
        }
    }
}

/// `gf_poly_mod()`: polynomial Euclidean division remainder in GF(2^m)[X] (modifies `a`).
unsafe fn gf_poly_mod(b: &BchControl, a: *mut GfPoly, bp: *const GfPoly, mut rep: *mut i32) {
    unsafe {
        let c = pc(a);
        let d = (*bp).deg;

        if (*a).deg < d {
            return;
        }

        // reuse or compute log representation of denominator
        if rep.is_null() {
            rep = b.cache;
            gf_poly_logrep(b, bp, rep);
        }

        let mut j = (*a).deg;
        while j >= d {
            if *c.add(j as usize) != 0 {
                let la = lg(b, *c.add(j as usize));
                let mut p = j.wrapping_sub(d) as i32;
                for i in 0..d as usize {
                    let m = *rep.add(i);
                    if m >= 0 {
                        *c.add(p as usize) ^= pw(b, mod_s(b, (m as u32).wrapping_add(la)));
                    }
                    p += 1;
                }
            }
            j = j.wrapping_sub(1);
        }
        (*a).deg = d.wrapping_sub(1);
        while *c.add((*a).deg as usize) == 0 && (*a).deg != 0 {
            (*a).deg -= 1;
        }
    }
}

/// `gf_poly_div()`: quotient (the remainder is left in `a`).
unsafe fn gf_poly_div(b: &BchControl, a: *mut GfPoly, bp: *const GfPoly, q: *mut GfPoly) {
    unsafe {
        if (*a).deg >= (*bp).deg {
            (*q).deg = (*a).deg - (*bp).deg;
            // compute a mod b (modifies a)
            gf_poly_mod(b, a, bp, null_mut());
            // quotient is stored in upper part of polynomial a
            copy_nonoverlapping(pc(a).add((*bp).deg as usize) as *const u32, pc(q), 1 + (*q).deg as usize);
        } else {
            (*q).deg = 0;
            *pc(q) = 0;
        }
    }
}

/// `gf_poly_gcd()`: polynomial GCD (destroys both arguments).
unsafe fn gf_poly_gcd(b: &BchControl, mut a: *mut GfPoly, mut bp: *mut GfPoly) -> *mut GfPoly {
    unsafe {
        if (*a).deg < (*bp).deg {
            core::mem::swap(&mut a, &mut bp);
        }

        while (*bp).deg > 0 {
            gf_poly_mod(b, a, bp, null_mut());
            core::mem::swap(&mut a, &mut bp);
        }

        a
    }
}

/// `compute_trace_bk_mod()`: Tr(a^kX) mod f, for the Berlekamp Trace algorithm.
unsafe fn compute_trace_bk_mod(b: &BchControl, k: i32, f: *const GfPoly, z: *mut GfPoly, out: *mut GfPoly) {
    unsafe {
        let m = b.m as i32;
        let zc = pc(z);
        let oc = pc(out);

        // z contains z^2j mod f
        (*z).deg = 1;
        *zc = 0;
        *zc.add(1) = pw(b, k as u32);

        (*out).deg = 0;
        write_bytes(out as *mut u8, 0, gf_poly_sz((*f).deg));

        // compute f log representation only once
        gf_poly_logrep(b, f, b.cache);

        for i in 0..m {
            // add a^(k*2^i)(z^(2^i) mod f) and compute (z^(2^i) mod f)^2
            let mut j = (*z).deg as i32;
            while j >= 0 {
                *oc.add(j as usize) ^= *zc.add(j as usize);
                *zc.add(2 * j as usize) = gf_sqr(b, *zc.add(j as usize));
                *zc.add(2 * j as usize + 1) = 0;
                j -= 1;
            }
            if (*z).deg > (*out).deg {
                (*out).deg = (*z).deg;
            }

            if i < m - 1 {
                (*z).deg *= 2;
                // z^(2(i+1)) mod f = (z^(2^i) mod f)^2 mod f
                gf_poly_mod(b, z, f, b.cache);
            }
        }
        while *oc.add((*out).deg as usize) == 0 && (*out).deg != 0 {
            (*out).deg -= 1;
        }
    }
}

/// `factor_polynomial()`: factor a polynomial using the Berlekamp Trace algorithm (BTA).
unsafe fn factor_polynomial(b: &BchControl, k: i32, f: *mut GfPoly, g: *mut *mut GfPoly, h: *mut *mut GfPoly) {
    unsafe {
        let f2 = b.poly_2t[0];
        let q = b.poly_2t[1];
        let tk = b.poly_2t[2];
        let z = b.poly_2t[3];

        *g = f;
        *h = null_mut();

        // tk = Tr(a^k.X) mod f
        compute_trace_bk_mod(b, k, f, z, tk);

        if (*tk).deg > 0 {
            // compute g = gcd(f, tk) (destructive operation)
            gf_poly_copy(f2, f);
            let gcd = gf_poly_gcd(b, f2, tk);
            if (*gcd).deg < (*f).deg {
                // compute h=f/gcd(f,tk); this will modify f and q
                gf_poly_div(b, f, gcd, q);
                // store g and h in-place (clobbering f)
                *h = (f as *mut u8).add(GF_POLY_DEG1_SZ * (*gcd).deg as usize) as *mut GfPoly;
                gf_poly_copy(*g, gcd);
                gf_poly_copy(*h, q);
            }
        }
    }
}

/// `find_poly_roots()`: find the roots of a polynomial using the BTZ algorithm.
unsafe fn find_poly_roots(b: &BchControl, k: u32, poly: *mut GfPoly, roots: *mut u32) -> i32 {
    unsafe {
        let mut cnt: i32;
        let mut f1: *mut GfPoly = null_mut();
        let mut f2: *mut GfPoly = null_mut();

        match (*poly).deg {
            // handle low degree polynomials with ad hoc techniques
            1 => cnt = find_poly_deg1_roots(b, poly, roots),
            2 => cnt = find_poly_deg2_roots(b, poly, roots),
            3 => cnt = find_poly_deg3_roots(b, poly, roots),
            4 => cnt = find_poly_deg4_roots(b, poly, roots),
            _ => {
                // factor polynomial using Berlekamp Trace Algorithm (BTA)
                cnt = 0;
                if (*poly).deg != 0 && k <= b.m {
                    factor_polynomial(b, k as i32, poly, &mut f1, &mut f2);
                    if !f1.is_null() {
                        cnt += find_poly_roots(b, k + 1, f1, roots);
                    }
                    if !f2.is_null() {
                        cnt += find_poly_roots(b, k + 1, f2, roots.add(cnt as usize));
                    }
                }
            }
        }
        cnt
    }
}

/// `bch_decode()`: decode a received codeword and find the bit error locations; the number of errors, -EBADMSG or -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_bch_decode(
    bch: *mut BchControl,
    data: *const u8,
    len: c_uint,
    recv_ecc: *const u8,
    calc_ecc: *const u8,
    mut syn: *const c_uint,
    errloc: *mut c_uint,
) -> c_int {
    unsafe {
        let b = &*bch;
        let words = ecc_words(b);

        // sanity check: make sure data length can be handled
        if 8u32.wrapping_mul(len) > b.n.wrapping_sub(b.ecc_bits) {
            return -EINVAL;
        }

        // if caller does not provide syndromes, compute them
        if syn.is_null() {
            if calc_ecc.is_null() {
                // compute received data ecc into an internal buffer
                if data.is_null() || recv_ecc.is_null() {
                    return -EINVAL;
                }
                rust_bch_encode(bch, data, len, null_mut());
            } else {
                // load provided calculated ecc
                load_ecc8(b, b.ecc_buf, calc_ecc);
            }
            // load received ecc or assume it was XORed in calc_ecc
            if !recv_ecc.is_null() {
                load_ecc8(b, b.ecc_buf2, recv_ecc);
                // XOR received and calculated ecc
                let mut sum: u32 = 0;
                for i in 0..words as usize {
                    *b.ecc_buf.add(i) ^= *b.ecc_buf2.add(i);
                    sum |= *b.ecc_buf.add(i);
                }
                if sum == 0 {
                    // no error found
                    return 0;
                }
            }
            compute_syndromes(b, b.ecc_buf, b.syn);
            syn = b.syn;
        }

        let mut err = compute_error_locator_polynomial(b, syn);
        if err > 0 {
            let nroots = find_poly_roots(b, 1, b.elp, errloc);
            if err != nroots {
                err = -1;
            }
        }
        if err > 0 {
            // post-process raw error locations for easier correction
            let nbits = len.wrapping_mul(8).wrapping_add(b.ecc_bits);
            for i in 0..err as usize {
                if *errloc.add(i) >= nbits {
                    err = -1;
                    break;
                }
                *errloc.add(i) = nbits - 1 - *errloc.add(i);
                if !b.swap_bits {
                    *errloc.add(i) = (*errloc.add(i) & !7) | (7 - (*errloc.add(i) & 7));
                }
            }
        }
        if err >= 0 {
            err
        } else {
            -EBADMSG
        }
    }
}

// ---- initialisation ----

/// `build_gf_tables()`: generate the Galois field lookup tables.
unsafe fn build_gf_tables(b: &BchControl, poly: u32) -> i32 {
    unsafe {
        let mut x: u32 = 1;
        let k: u32 = 1u32.wrapping_shl(deg(poly) as u32);

        // primitive polynomial must be of degree m
        if k != 1u32.wrapping_shl(b.m) {
            return -1;
        }

        for i in 0..b.n {
            *b.a_pow_tab.add(i as usize) = x as u16;
            *b.a_log_tab.add(x as usize) = i as u16;
            if i != 0 && x == 1 {
                // polynomial is not primitive (a^i=1 with 0<i<2^m-1)
                return -1;
            }
            x <<= 1;
            if x & k != 0 {
                x ^= poly;
            }
        }
        *b.a_pow_tab.add(b.n as usize) = 1;
        *b.a_log_tab = 0;

        0
    }
}

/// `build_mod8_tables()`: generator polynomial remainder tables for fast encoding.
unsafe fn build_mod8_tables(b: &BchControl, g: *const u32) {
    unsafe {
        let l = ecc_words(b) as i32;
        let plen = ((b.ecc_bits + 1) + 31) / 32;
        let ecclen = (b.ecc_bits + 31) / 32;

        write_bytes(b.mod8_tab, 0, 4 * 256 * l as usize);

        for i in 0..256i32 {
            // p(X)=i is a small polynomial of weight <= 8
            for bb in 0..4i32 {
                // we want to compute (p(X).X^(8*b+deg(g))) mod g(X)
                let tab = b.mod8_tab.add(((bb * 256 + i) * l) as usize);
                let mut data: u32 = (i as u32).wrapping_shl((8 * bb) as u32);
                while data != 0 {
                    let d = deg(data);
                    // subtract X^d.g(X) from p(X).X^(8*b+deg(g))
                    data ^= *g >> (31 - d);
                    for j in 0..ecclen as usize {
                        let hi = if d < 31 { *g.add(j) << (d + 1) } else { 0 };
                        let lo = if (j as u32) + 1 < plen { *g.add(j + 1) >> (31 - d) } else { 0 };
                        *tab.add(j) ^= hi | lo;
                    }
                }
            }
        }
    }
}

/// `build_deg2_base()`: a base for factoring degree 2 polynomials.
unsafe fn build_deg2_base(b: &BchControl) -> i32 {
    unsafe {
        let m = b.m as i32;
        let mut ak: u32 = 0;
        let mut xi = [0u32; BCH_MAX_M];

        // find k s.t. Tr(a^k) = 1 and 0 <= k < m
        for i in 0..m {
            let mut sum: u32 = 0;
            for j in 0..m {
                sum ^= a_pow(b, (i.wrapping_mul(1 << j)) as u32);
            }

            if sum != 0 {
                ak = pw(b, i as u32);
                break;
            }
        }
        // find xi, i=0..m-1 such that xi^2+xi = a^i+Tr(a^i).a^k
        let mut remaining = m as u32;

        let mut x: u32 = 0;
        while x <= b.n && remaining != 0 {
            let mut y = gf_sqr(b, x) ^ x;
            for _ in 0..2 {
                let r = lg(b, y) as i32;
                if y != 0 && r < m && xi[r as usize] == 0 {
                    *b.xi_tab.add(r as usize) = x;
                    xi[r as usize] = 1;
                    remaining -= 1;
                    break;
                }
                y ^= ak;
            }
            x += 1;
        }
        // should not happen but check anyway
        if remaining != 0 {
            -1
        } else {
            0
        }
    }
}

/// `bch_alloc()`: kmalloc, setting `*err` on failure.
#[inline(always)]
unsafe fn bch_alloc(size: usize, err: &mut i32) -> *mut c_void {
    unsafe {
        let p = rust_bchw_kmalloc(size);
        if p.is_null() {
            *err = 1;
        }
        p
    }
}

/// `compute_generator_polynomial()`: the generator polynomial for the given (m, t); NULL on allocation failure.
unsafe fn compute_generator_polynomial(b: &mut BchControl) -> *mut u32 {
    unsafe {
        let m = b.m;
        let t = b.t;
        let mut err = 0;

        let g = bch_alloc(gf_poly_sz(m.wrapping_mul(t)), &mut err) as *mut GfPoly;
        let roots = bch_alloc((b.n as usize + 1) * 4, &mut err) as *mut u32;
        let mut genpoly = bch_alloc(((m * t + 1 + 31) / 32) as usize * 4, &mut err) as *mut u32;

        if err != 0 {
            rust_bchw_kfree(genpoly as *mut c_void);
            genpoly = null_mut();
        } else {
            let gc = pc(g);

            // enumerate all roots of g(X)
            write_bytes(roots, 0, b.n as usize + 1);
            for i in 0..t {
                let mut r = 2 * i + 1;
                for _ in 0..m {
                    *roots.add(r as usize) = 1;
                    r = mod_s(b, 2u32.wrapping_mul(r));
                }
            }
            // build generator polynomial g(X)
            (*g).deg = 0;
            *gc = 1;
            for i in 0..b.n {
                if *roots.add(i as usize) != 0 {
                    // multiply g(X) by (X+root)
                    let r = pw(b, i);
                    *gc.add((*g).deg as usize + 1) = 1;
                    let mut j = (*g).deg;
                    while j > 0 {
                        *gc.add(j as usize) = gf_mul(b, *gc.add(j as usize), r) ^ *gc.add(j as usize - 1);
                        j -= 1;
                    }

                    *gc = gf_mul(b, *gc, r);
                    (*g).deg += 1;
                }
            }
            // store left-justified binary representation of g(X)
            let mut n = (*g).deg as i32 + 1;
            let mut i = 0usize;

            while n > 0 {
                let nbits = if n > 32 { 32 } else { n };
                let mut word: u32 = 0;
                for j in 0..nbits {
                    if *gc.add((n - 1 - j) as usize) != 0 {
                        word |= 1u32 << (31 - j);
                    }
                }
                *genpoly.add(i) = word;
                i += 1;
                n -= nbits;
            }
            b.ecc_bits = (*g).deg;
        }

        rust_bchw_kfree(g as *mut c_void);
        rust_bchw_kfree(roots as *mut c_void);

        genpoly
    }
}

/// `bch_free()`.
#[no_mangle]
pub unsafe extern "C" fn rust_bch_free(bch: *mut BchControl) {
    unsafe {
        if !bch.is_null() {
            let b = &*bch;
            rust_bchw_kfree(b.a_pow_tab as *mut c_void);
            rust_bchw_kfree(b.a_log_tab as *mut c_void);
            rust_bchw_kfree(b.mod8_tab as *mut c_void);
            rust_bchw_kfree(b.ecc_buf as *mut c_void);
            rust_bchw_kfree(b.ecc_buf2 as *mut c_void);
            rust_bchw_kfree(b.xi_tab as *mut c_void);
            rust_bchw_kfree(b.syn as *mut c_void);
            rust_bchw_kfree(b.cache as *mut c_void);
            rust_bchw_kfree(b.elp as *mut c_void);

            for i in 0..4 {
                rust_bchw_kfree(b.poly_2t[i] as *mut c_void);
            }

            rust_bchw_kfree(bch as *mut c_void);
        }
    }
}

/// `bch_init()`: initialize a BCH encoder/decoder; NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn rust_bch_init(m: c_int, t: c_int, mut prim_poly: c_uint, swap_bits: bool) -> *mut BchControl {
    unsafe {
        let mut err: i32 = 0;
        let min_m: c_int = 5;

        // default primitive polynomials
        const PRIM_POLY_TAB: [u32; 11] = [0x25, 0x43, 0x83, 0x11d, 0x211, 0x409, 0x805, 0x1053, 0x201b, 0x402b, 0x8003];

        'fail: {
            if m < min_m || m > BCH_MAX_M as c_int {
                // values of m greater than 15 are not currently supported; supporting m > 15 would require changing table base type (uint16_t)
                // and a small patch in matrix transposition
                break 'fail;
            }

            if t > BCH_MAX_T {
                // we can support larger than 64 bits if necessary, at the cost of higher stack usage
                break 'fail;
            }

            // sanity checks
            if t < 1 || m.wrapping_mul(t) >= ((1 << m) - 1) {
                // invalid t value
                break 'fail;
            }

            // select a primitive polynomial for generating GF(2^m)
            if prim_poly == 0 {
                prim_poly = PRIM_POLY_TAB[(m - min_m) as usize];
            }

            let bch = rust_bchw_kzalloc(rust_bch_ctl_size) as *mut BchControl;
            if bch.is_null() {
                break 'fail;
            }
            let b = &mut *bch;

            b.m = m as u32;
            b.t = t as u32;
            b.n = (1u32 << m) - 1;
            let words = (b.m * b.t + 31) / 32;
            b.ecc_bytes = (b.m * b.t + 7) / 8;
            b.a_pow_tab = bch_alloc((1 + b.n as usize) * 2, &mut err) as *mut u16;
            b.a_log_tab = bch_alloc((1 + b.n as usize) * 2, &mut err) as *mut u16;
            b.mod8_tab = bch_alloc(words as usize * 1024 * 4, &mut err) as *mut u32;
            b.ecc_buf = bch_alloc(words as usize * 4, &mut err) as *mut u32;
            b.ecc_buf2 = bch_alloc(words as usize * 4, &mut err) as *mut u32;
            b.xi_tab = bch_alloc(m as usize * 4, &mut err) as *mut c_uint;
            b.syn = bch_alloc(2 * t as usize * 4, &mut err) as *mut c_uint;
            b.cache = bch_alloc(2 * t as usize * 4, &mut err) as *mut c_int;
            b.elp = bch_alloc((t as usize + 1) * GF_POLY_DEG1_SZ, &mut err) as *mut GfPoly;
            b.swap_bits = swap_bits;

            for i in 0..4 {
                b.poly_2t[i] = bch_alloc(gf_poly_sz(2 * t as u32), &mut err) as *mut GfPoly;
            }

            if err != 0 {
                rust_bch_free(bch);
                return null_mut();
            }

            err = build_gf_tables(b, prim_poly);
            if err != 0 {
                rust_bch_free(bch);
                return null_mut();
            }

            // use generator polynomial for computing encoding tables
            let genpoly = compute_generator_polynomial(b);
            if genpoly.is_null() {
                rust_bch_free(bch);
                return null_mut();
            }

            build_mod8_tables(b, genpoly);
            rust_bchw_kfree(genpoly as *mut c_void);

            err = build_deg2_base(b);
            if err != 0 {
                rust_bch_free(bch);
                return null_mut();
            }

            return bch;
        }

        // fail: bch is still NULL here (every failure after the allocation frees it above)
        null_mut()
    }
}
