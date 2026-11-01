// SPDX-License-Identifier: GPL-2.0-or-later

//! The ASN.1 field callbacks of `crypto/rsa_helper.c` (RSA key extract helper).
//!
//! Ported from `crypto/rsa_helper.c` (6.18.49), (C) 2015 Intel Corporation, Tadeusz Struk. What is here:
//! `rsa_get_n/e/d/p/q/dp/dq/qinv`, the action functions the generated `rsapubkey.asn1.c` /
//! `rsaprivkey.asn1.c` decoder tables call for each INTEGER of an RSAPublicKey / RSAPrivateKey (PKCS#1) BER
//! document. Each checks its value and stores the pointer and length into the caller's `struct rsa_key`
//! (the raw big-endian bytes stay where they are in the BER buffer; nothing is copied):
//!
//! * `n`: a NULL value or zero length is `-EINVAL`; with `CONFIG_CRYPTO_FIPS` and `fips_enabled`, leading zero
//!   bytes are skipped and a modulus under 256 bytes is `-EINVAL` after
//!   `pr_err("RSA: key size not allowed in FIPS mode\n")` (the text, level and absence of a module prefix are
//!   upstream's; that arm is `#[cfg(CONFIG_CRYPTO_FIPS)]`, unset in both configs here);
//! * `e`, `d`: `-EINVAL` if the value is NULL, `n` has not been seen (`n_sz == 0`), the length is zero or the
//!   length is larger than `n_sz`;
//! * `p`, `q`, `dp`, `dq`, `qinv`: the same without the `n_sz == 0` test (a zero `n_sz` makes any length
//!   `vlen > 0` fail the `vlen > n_sz` test anyway).
//!
//! What stays C (`crypto/rsa_helper_glue.c`): `rsa_parse_pub_key()` and `rsa_parse_priv_key()` (each one
//! `asn1_ber_decoder()` call on a decoder table the ASN.1 compiler generates, with the two `EXPORT_SYMBOL_GPL`s).
//!
//! `struct rsa_key` (include/crypto/internal/rsa.h) has no Kconfig-dependent member; its layout is mirrored below
//! and checked by `rig/layout-check.sh`.
//!
//! Replaces: the eight `rsa_get_*` callbacks of crypto/rsa_helper.c

use core::ffi::{c_int, c_uchar, c_void};

/// Mirrors `struct rsa_key`.
#[repr(C)]
pub struct RsaKey {
    /// RSA modulus raw byte stream.
    pub n: *const u8,
    /// RSA public exponent.
    pub e: *const u8,
    /// RSA private exponent.
    pub d: *const u8,
    /// Prime factor p of n.
    pub p: *const u8,
    /// Prime factor q of n.
    pub q: *const u8,
    /// d mod (p - 1).
    pub dp: *const u8,
    /// d mod (q - 1).
    pub dq: *const u8,
    /// CRT coefficient q^(-1) mod p.
    pub qinv: *const u8,
    /// Length in bytes of n.
    pub n_sz: usize,
    /// Length in bytes of e.
    pub e_sz: usize,
    /// Length in bytes of d.
    pub d_sz: usize,
    /// Length in bytes of p.
    pub p_sz: usize,
    /// Length in bytes of q.
    pub q_sz: usize,
    /// Length in bytes of dp.
    pub dp_sz: usize,
    /// Length in bytes of dq.
    pub dq_sz: usize,
    /// Length in bytes of qinv.
    pub qinv_sz: usize,
}

const EINVAL: c_int = 22;

#[cfg(CONFIG_CRYPTO_FIPS)]
extern "C" {
    static fips_enabled: c_int;
    fn _printk(fmt: *const core::ffi::c_char, ...) -> c_int;
}

/// `rsa_get_n()`.
///
/// # Safety
/// `context` is a valid `struct rsa_key *`; `value` is NULL or has `vlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_n(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // invalid key provided
    if value.is_null() || vlen == 0 {
        return -EINVAL;
    }
    #[cfg(CONFIG_CRYPTO_FIPS)]
    // SAFETY: fips_enabled is a plain int; value has vlen bytes, the walk stays inside them.
    unsafe {
        if fips_enabled != 0 {
            let mut ptr = value as *const u8;
            let mut n_sz = vlen;
            while n_sz != 0 && *ptr == 0 {
                ptr = ptr.add(1);
                n_sz -= 1;
            }
            // In FIPS mode only allow key size 2K and higher
            if n_sz < 256 {
                // KERN_ERR, pr_err()
                _printk(c"\x013RSA: key size not allowed in FIPS mode\n".as_ptr());
                return -EINVAL;
            }
        }
    }
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        (*key).n = value as *const u8;
        (*key).n_sz = vlen;
    }
    0
}

/// `rsa_get_e()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_e(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || (*key).n_sz == 0 || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).e = value as *const u8;
        (*key).e_sz = vlen;
    }
    0
}

/// `rsa_get_d()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_d(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || (*key).n_sz == 0 || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).d = value as *const u8;
        (*key).d_sz = vlen;
    }
    0
}

/// `rsa_get_p()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_p(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).p = value as *const u8;
        (*key).p_sz = vlen;
    }
    0
}

/// `rsa_get_q()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_q(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).q = value as *const u8;
        (*key).q_sz = vlen;
    }
    0
}

/// `rsa_get_dp()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_dp(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).dp = value as *const u8;
        (*key).dp_sz = vlen;
    }
    0
}

/// `rsa_get_dq()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_dq(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).dq = value as *const u8;
        (*key).dq_sz = vlen;
    }
    0
}

/// `rsa_get_qinv()`.
///
/// # Safety
/// As `rsa_get_n`.
#[no_mangle]
pub unsafe extern "C" fn rsa_get_qinv(context: *mut c_void, _hdrlen: usize, _tag: c_uchar, value: *const c_void, vlen: usize) -> c_int {
    let key = context as *mut RsaKey;
    // SAFETY: context is a valid struct rsa_key.
    unsafe {
        // invalid key provided
        if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).qinv = value as *const u8;
        (*key).qinv_sz = vlen;
    }
    0
}

/// Kani proofs (`cd rig/rsa_helper-kani && cargo kani`; inert in the kernel build; the non-FIPS arm, which is what both
/// kernel configs compile). Symbolic `n_sz` and `vlen`, a NULL or valid `value`: every getter returns 0 or -EINVAL; on -EINVAL
/// the whole `struct rsa_key` is unchanged; on 0 exactly its own pointer and size changed.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn key(n_sz: usize) -> RsaKey {
        let z: *const u8 = core::ptr::null();
        RsaKey { n: z, e: z, d: z, p: z, q: z, dp: z, dq: z, qinv: z, n_sz, e_sz: 1, d_sz: 2, p_sz: 3, q_sz: 4, dp_sz: 5, dq_sz: 6, qinv_sz: 7 }
    }

    macro_rules! getter {
        ($name:ident, $f:ident, $ptr:ident, $sz:ident, $needs_n:expr) => {
            #[kani::proof]
            fn $name() {
                let buf = [0u8; 4];
                let n_sz: usize = kani::any();
                let vlen: usize = kani::any();
                let null: bool = kani::any();
                let mut k = key(n_sz);
                let before_n = k.n; let before_nsz = k.n_sz;
                let value: *const c_void = if null { core::ptr::null() } else { buf.as_ptr() as *const c_void };
                let r = unsafe { $f(&mut k as *mut RsaKey as *mut c_void, 7, 2, value, vlen) };
                assert!(r == 0 || r == -22);
                let accept = !null && vlen != 0 && vlen <= n_sz && (!$needs_n || n_sz != 0);
                assert!((r == 0) == accept);
                if r == 0 {
                    assert!(k.$ptr == value as *const u8 && k.$sz == vlen);
                } else {
                    assert!(k.$ptr.is_null() && k.$sz == key(n_sz).$sz);
                }
                // nothing else changed
                if stringify!($ptr) != "n" { assert!(k.n == before_n && k.n_sz == before_nsz); }
            }
        };
    }
    getter!(get_e, rsa_get_e, e, e_sz, true);
    getter!(get_d, rsa_get_d, d, d_sz, true);
    getter!(get_p, rsa_get_p, p, p_sz, false);
    getter!(get_q, rsa_get_q, q, q_sz, false);
    getter!(get_dp, rsa_get_dp, dp, dp_sz, false);
    getter!(get_dq, rsa_get_dq, dq, dq_sz, false);
    getter!(get_qinv, rsa_get_qinv, qinv, qinv_sz, false);

    #[kani::proof]
    fn get_n() {
        let buf = [0u8; 4];
        let vlen: usize = kani::any();
        let null: bool = kani::any();
        let mut k = key(99);
        let value: *const c_void = if null { core::ptr::null() } else { buf.as_ptr() as *const c_void };
        let r = unsafe { rsa_get_n(&mut k as *mut RsaKey as *mut c_void, 7, 2, value, vlen) };
        assert!(r == 0 || r == -22);
        assert!((r == 0) == (!null && vlen != 0));
        if r == 0 { assert!(k.n == value as *const u8 && k.n_sz == vlen); } else { assert!(k.n.is_null() && k.n_sz == 99); }
        assert!(k.e_sz == 1 && k.d_sz == 2 && k.p_sz == 3 && k.qinv_sz == 7);
    }
}
