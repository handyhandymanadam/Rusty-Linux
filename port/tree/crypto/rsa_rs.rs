// SPDX-License-Identifier: GPL-2.0-or-later

//! The RSA primitive of `crypto/rsa.c` (RSAEP / RSADP with the CRT, key loading, the key-size rules).
//!
//! Ported from `crypto/rsa.c` (6.18.49), (C) 2015 Intel Corporation, Tadeusz Struk. What is here:
//!
//! * `rsa_rs_enc()` / `rsa_rs_dec()`: the bodies of `rsa_enc()` / `rsa_dec()`: allocate the result, check the key is set
//!   (`-EINVAL` if `n`/`e` (encrypt) or `n`/`d` (decrypt) is NULL), read the payload from the scatterlist, run RSAEP
//!   (`c = m^e mod n`) or RSADP with the Chinese remainder theorem (`m1 = c^dP mod p`, `m2 = c^dQ mod q`,
//!   `h = (m1 - m2) * qInv mod p`, `m = m2 + q*h mod n`), write the result back, `-EBADMSG` if it came out negative, free everything
//!   in the order the C does. `rsa_check_payload()` (`1 < x < n - 1`, else `-EINVAL`) runs first, exactly as upstream (this is
//!   the SP 800-56B r2 rule, stricter than RFC 3447's `0 <= x <= n - 1`).
//! * `rsa_rs_set_pub_key()` / `rsa_rs_set_priv_key()`: free the old key, parse the BER key (`rsa_parse_pub_key` /
//!   `rsa_parse_priv_key`, still C in rsa_helper_glue.c), turn each raw field into an MPI in upstream's order (every
//!   `mpi_read_raw_data` failure frees the whole key and is `-ENOMEM`), then `rsa_check_key_length()` on the modulus
//!   (`mpi_get_size(n) << 3` must be 512/1024/1536 (not under FIPS), 2048, 3072 or 4096 bits, else `-EINVAL`; the size is
//!   limb-granular: 18 limbs = 1152 bits is rejected) and, with `CONFIG_CRYPTO_FIPS` and `fips_enabled`,
//!   `rsa_check_exponent_fips()` (`e` odd and `2^16 < e < 2^256`).
//! * `rsa_rs_max_size()` (`mpi_get_size(n)`) and `rsa_rs_free_key()` (`mpi_free` of the eight MPIs, then NULL them).
//!
//! What stays C (`crypto/rsa_glue.c`, upstream's file with those bodies replaced by calls): the `akcipher_alg` table,
//! `rsa_init`/`rsa_exit` (registration of the algorithm and the two templates), the `struct rsa_mpi_key` definition (it
//! sizes the transform context), and one-line wrappers that fetch `akcipher_tfm_ctx(tfm)` and the scatterlists from
//! `struct akcipher_request`, whose layout is not mirrored here. Every `mpi_*` call goes to the exported function
//! (all of lib/crypto/mpi is already Rust); `struct gcry_mpi` is mirrored only to read `nlimbs` for `mpi_get_size()`,
//! which is a `static inline` in include/linux/mpi.h.
//!
//! Out-of-contract: none added. Same call order as the C, so the memory-failure paths free in the same order.
//!
//! Replaces: the logic of crypto/rsa.c (everything but the registration)

use core::ffi::{c_int, c_uint, c_ulong, c_void};

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly per file, as every other file's mirror of this
/// struct is (`rig/layout-check.sh` looks the Rust name up in the whole vmlinux).
#[repr(C)]
pub struct RsaGcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Indicates a negative number.
    pub sign: c_int,
    /// Flags.
    pub flags: c_uint,
    /// Array with the limbs.
    pub d: *mut c_ulong,
}

/// `MPI`: a pointer to a `struct gcry_mpi`.
pub type Mpi = *mut RsaGcryMpi;

/// Mirrors `struct rsa_mpi_key` (`crypto/rsa.c`).
#[repr(C)]
pub struct RsaMpiKey {
    /// Modulus.
    pub n: Mpi,
    /// Public exponent.
    pub e: Mpi,
    /// Private exponent.
    pub d: Mpi,
    /// Prime p.
    pub p: Mpi,
    /// Prime q.
    pub q: Mpi,
    /// d mod (p - 1).
    pub dp: Mpi,
    /// d mod (q - 1).
    pub dq: Mpi,
    /// q^(-1) mod p.
    pub qinv: Mpi,
}

/// Mirrors `struct rsa_key` (`include/crypto/internal/rsa.h`): the raw big-endian fields the BER parser hands back.
#[repr(C)]
pub struct RsaRawKey {
    /// n.
    pub n: *const u8,
    /// e.
    pub e: *const u8,
    /// d.
    pub d: *const u8,
    /// p.
    pub p: *const u8,
    /// q.
    pub q: *const u8,
    /// dp.
    pub dp: *const u8,
    /// dq.
    pub dq: *const u8,
    /// qinv.
    pub qinv: *const u8,
    /// Length of n.
    pub n_sz: usize,
    /// Length of e.
    pub e_sz: usize,
    /// Length of d.
    pub d_sz: usize,
    /// Length of p.
    pub p_sz: usize,
    /// Length of q.
    pub q_sz: usize,
    /// Length of dp.
    pub dp_sz: usize,
    /// Length of dq.
    pub dq_sz: usize,
    /// Length of qinv.
    pub qinv_sz: usize,
}

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const EBADMSG: c_int = 74;

#[cfg(not(kani))]
extern "C" {
    fn mpi_alloc(nlimbs: c_uint) -> Mpi;
    fn mpi_free(a: Mpi);
    fn mpi_cmp_ui(u: Mpi, v: c_ulong) -> c_int;
    fn mpi_cmp(u: Mpi, v: Mpi) -> c_int;
    fn mpi_sub_ui(w: Mpi, u: Mpi, vval: c_ulong) -> c_int;
    fn mpi_powm(res: Mpi, base: Mpi, exp: Mpi, m: Mpi) -> c_int;
    fn mpi_sub(w: Mpi, u: Mpi, v: Mpi) -> c_int;
    fn mpi_mulm(w: Mpi, u: Mpi, v: Mpi, m: Mpi) -> c_int;
    fn mpi_mul(w: Mpi, u: Mpi, v: Mpi) -> c_int;
    fn mpi_addm(w: Mpi, u: Mpi, v: Mpi, m: Mpi) -> c_int;
    fn mpi_read_raw_from_sgl(sgl: *mut c_void, len: c_uint) -> Mpi;
    fn mpi_write_to_sgl(a: Mpi, sg: *mut c_void, nbytes: c_uint, sign: *mut c_int) -> c_int;
    fn mpi_read_raw_data(xbuffer: *const c_void, nbytes: usize) -> Mpi;
    /// `crypto/rsa_helper_glue.c` (EXPORT_SYMBOL_GPL).
    fn rsa_parse_pub_key(rsa_key: *mut RsaRawKey, key: *const c_void, key_len: c_uint) -> c_int;
    /// `crypto/rsa_helper_glue.c` (EXPORT_SYMBOL_GPL).
    fn rsa_parse_priv_key(rsa_key: *mut RsaRawKey, key: *const c_void, key_len: c_uint) -> c_int;
}

#[cfg(all(CONFIG_CRYPTO_FIPS, not(kani)))]
extern "C" {
    static fips_enabled: c_int;
    fn mpi_test_bit(a: Mpi, n: c_uint) -> c_int;
    fn mpi_set_bit(a: Mpi, n: c_uint) -> c_int;
}

/// Kani model of the MPI layer and the BER parser: every call may return any value; `mpi_alloc` and the two readers may fail;
/// a counter `LIVE` tracks allocations minus frees (all MPIs are the one dummy object: only the counts matter).
#[cfg(kani)]
mod model {
    use super::*;
    pub static mut LIVE: i32 = 0;
    static mut DUMMY: RsaGcryMpi = RsaGcryMpi { alloced: 0, nlimbs: 0, nbits: 0, sign: 0, flags: 0, d: core::ptr::null_mut() };
    unsafe fn create() -> Mpi {
        if kani::any() {
            core::ptr::null_mut()
        } else {
            unsafe { LIVE += 1 };
            core::ptr::addr_of_mut!(DUMMY)
        }
    }
    pub unsafe fn mpi_alloc(_nlimbs: c_uint) -> Mpi { unsafe { create() } }
    pub unsafe fn mpi_free(a: Mpi) {
        if !a.is_null() {
            unsafe {
                LIVE -= 1;
                assert!(LIVE >= 0, "double free");
            }
        }
    }
    pub unsafe fn mpi_cmp_ui(_u: Mpi, _v: c_ulong) -> c_int { kani::any() }
    pub unsafe fn mpi_cmp(_u: Mpi, _v: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_sub_ui(_w: Mpi, _u: Mpi, _v: c_ulong) -> c_int { kani::any() }
    pub unsafe fn mpi_powm(_r: Mpi, _b: Mpi, _e: Mpi, _m: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_sub(_w: Mpi, _u: Mpi, _v: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_mulm(_w: Mpi, _u: Mpi, _v: Mpi, _m: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_mul(_w: Mpi, _u: Mpi, _v: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_addm(_w: Mpi, _u: Mpi, _v: Mpi, _m: Mpi) -> c_int { kani::any() }
    pub unsafe fn mpi_read_raw_from_sgl(_s: *mut c_void, _len: c_uint) -> Mpi { unsafe { create() } }
    pub unsafe fn mpi_read_raw_data(_b: *const c_void, _n: usize) -> Mpi { unsafe { create() } }
    pub unsafe fn mpi_write_to_sgl(_a: Mpi, _sg: *mut c_void, _n: c_uint, sign: *mut c_int) -> c_int {
        unsafe { *sign = kani::any() };
        kani::any()
    }
    pub unsafe fn rsa_parse_pub_key(_k: *mut RsaRawKey, _key: *const c_void, _len: c_uint) -> c_int { kani::any() }
    pub unsafe fn rsa_parse_priv_key(_k: *mut RsaRawKey, _key: *const c_void, _len: c_uint) -> c_int { kani::any() }
}
#[cfg(kani)]
use model::*;

/// `mpi_get_size()`: `static inline` in include/linux/mpi.h: `a->nlimbs * BYTES_PER_MPI_LIMB`.
///
/// # Safety
/// `a` is a valid MPI.
#[inline(always)]
unsafe fn mpi_get_size(a: Mpi) -> c_uint {
    // SAFETY: caller. int * 8 converted to unsigned, as the C does.
    unsafe { (*a).nlimbs.wrapping_mul(8) as c_uint }
}

/// `rsa_check_payload()`: `1 < x < n - 1`.
unsafe fn rsa_check_payload(x: Mpi, n: Mpi) -> c_int {
    // SAFETY: x and n are valid MPIs (caller); the mpi_* functions are the exported ones.
    unsafe {
        if mpi_cmp_ui(x, 1) <= 0 {
            return -EINVAL;
        }
        let n1 = mpi_alloc(0);
        if n1.is_null() {
            return -ENOMEM;
        }
        if mpi_sub_ui(n1, n, 1) != 0 || mpi_cmp(x, n1) >= 0 {
            mpi_free(n1);
            return -EINVAL;
        }
        mpi_free(n1);
    }
    0
}

/// RSAEP, `c = m^e mod n` [RFC3447 sec 5.1.1] (with the SP 800-56Br2 payload range).
unsafe fn rsa_enc_core(key: *const RsaMpiKey, c: Mpi, m: Mpi) -> c_int {
    // SAFETY: key is a valid struct rsa_mpi_key with n and e set (the caller tested them).
    unsafe {
        if rsa_check_payload(m, (*key).n) != 0 {
            return -EINVAL;
        }
        // (2) c = m^e mod n
        mpi_powm(c, m, (*key).e, (*key).n)
    }
}

/// RSADP with the CRT [RFC3447 sec 5.1.2]: `m_or_m1_or_h` holds m_1, then h, then m.
unsafe fn rsa_dec_crt(key: *const RsaMpiKey, m_or_m1_or_h: Mpi, c: Mpi) -> c_int {
    // SAFETY: key is a valid struct rsa_mpi_key with every field set (the caller tested n and d; set_priv_key sets all).
    unsafe {
        if rsa_check_payload(c, (*key).n) != 0 {
            return -EINVAL;
        }
        let m2 = mpi_alloc(0);
        let m12_or_qh = mpi_alloc(0);
        let mut ret = -ENOMEM;
        if !m2.is_null() && !m12_or_qh.is_null() {
            // (2i) m_1 = c^dP mod p
            ret = mpi_powm(m_or_m1_or_h, c, (*key).dp, (*key).p);
            if ret == 0 {
                // (2i) m_2 = c^dQ mod q
                ret = mpi_powm(m2, c, (*key).dq, (*key).q);
                if ret == 0 {
                    // (2iii) h = (m_1 - m_2) * qInv mod p
                    ret = mpi_sub(m12_or_qh, m_or_m1_or_h, m2);
                    if ret == 0 {
                        ret = mpi_mulm(m_or_m1_or_h, m12_or_qh, (*key).qinv, (*key).p);
                    }
                    // (2iv) m = m_2 + q * h
                    if ret == 0 {
                        ret = mpi_mul(m12_or_qh, (*key).q, m_or_m1_or_h);
                        if ret == 0 {
                            ret = mpi_addm(m_or_m1_or_h, m2, m12_or_qh, (*key).n);
                        }
                    }
                }
            }
        }
        mpi_free(m12_or_qh);
        mpi_free(m2);
        ret
    }
}

unsafe fn enc_body(pkey: *const RsaMpiKey, c: Mpi, src: *mut c_void, src_len: c_uint, dst: *mut c_void, dst_len: c_uint) -> c_int {
    // SAFETY: pkey is the transform's key; the mpi_* and scatterlist arguments are the caller's.
    unsafe {
        if (*pkey).n.is_null() || (*pkey).e.is_null() {
            return -EINVAL;
        }
        let m = mpi_read_raw_from_sgl(src, src_len);
        if m.is_null() {
            return -ENOMEM;
        }
        let mut sign: c_int = 0;
        let mut ret = rsa_enc_core(pkey, c, m);
        if ret == 0 {
            ret = mpi_write_to_sgl(c, dst, dst_len, &mut sign);
            if ret == 0 && sign < 0 {
                ret = -EBADMSG;
            }
        }
        mpi_free(m);
        ret
    }
}

/// `rsa_enc()`: `src` and `dst` are the request's `struct scatterlist *`.
///
/// # Safety
/// `pkey` is the transform's `struct rsa_mpi_key`; `src` and `dst` are valid scatterlists of at least `src_len` / `dst_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_enc(pkey: *const RsaMpiKey, src: *mut c_void, src_len: c_uint, dst: *mut c_void, dst_len: c_uint) -> c_int {
    // SAFETY: per the contract.
    unsafe {
        let c = mpi_alloc(0);
        if c.is_null() {
            return -ENOMEM;
        }
        let ret = enc_body(pkey, c, src, src_len, dst, dst_len);
        mpi_free(c);
        ret
    }
}

unsafe fn dec_body(pkey: *const RsaMpiKey, m: Mpi, src: *mut c_void, src_len: c_uint, dst: *mut c_void, dst_len: c_uint) -> c_int {
    // SAFETY: pkey is the transform's key; the mpi_* and scatterlist arguments are the caller's.
    unsafe {
        if (*pkey).n.is_null() || (*pkey).d.is_null() {
            return -EINVAL;
        }
        let c = mpi_read_raw_from_sgl(src, src_len);
        if c.is_null() {
            return -ENOMEM;
        }
        let mut sign: c_int = 0;
        let mut ret = rsa_dec_crt(pkey, m, c);
        if ret == 0 {
            ret = mpi_write_to_sgl(m, dst, dst_len, &mut sign);
            if ret == 0 && sign < 0 {
                ret = -EBADMSG;
            }
        }
        mpi_free(c);
        ret
    }
}

/// `rsa_dec()`.
///
/// # Safety
/// As `rsa_rs_enc`.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_dec(pkey: *const RsaMpiKey, src: *mut c_void, src_len: c_uint, dst: *mut c_void, dst_len: c_uint) -> c_int {
    // SAFETY: per the contract.
    unsafe {
        let m = mpi_alloc(0);
        if m.is_null() {
            return -ENOMEM;
        }
        let ret = dec_body(pkey, m, src, src_len, dst, dst_len);
        mpi_free(m);
        ret
    }
}

/// `rsa_free_mpi_key()`: free all eight MPIs and NULL them.
///
/// # Safety
/// `key` is a valid `struct rsa_mpi_key` whose non-NULL fields are live MPIs.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_free_key(key: *mut RsaMpiKey) {
    // SAFETY: per the contract; mpi_free(NULL) is a no-op.
    unsafe {
        mpi_free((*key).d);
        mpi_free((*key).e);
        mpi_free((*key).n);
        mpi_free((*key).p);
        mpi_free((*key).q);
        mpi_free((*key).dp);
        mpi_free((*key).dq);
        mpi_free((*key).qinv);
        (*key).d = core::ptr::null_mut();
        (*key).e = core::ptr::null_mut();
        (*key).n = core::ptr::null_mut();
        (*key).p = core::ptr::null_mut();
        (*key).q = core::ptr::null_mut();
        (*key).dp = core::ptr::null_mut();
        (*key).dq = core::ptr::null_mut();
        (*key).qinv = core::ptr::null_mut();
    }
}

/// `rsa_check_key_length()`: the modulus size in bits (limb-granular) must be one of the accepted RSA sizes.
fn rsa_check_key_length(len: c_uint) -> c_int {
    match len {
        512 | 1024 | 1536 => {
            #[cfg(CONFIG_CRYPTO_FIPS)]
            // SAFETY: a plain int.
            if unsafe { fips_enabled } != 0 {
                return -EINVAL;
            }
            0
        }
        2048 | 3072 | 4096 => 0,
        _ => -EINVAL,
    }
}

/// `rsa_check_exponent_fips()`: `e` is odd and `2^16 < e < 2^256`.
#[cfg(CONFIG_CRYPTO_FIPS)]
unsafe fn rsa_check_exponent_fips(e: Mpi) -> c_int {
    // SAFETY: e is a valid MPI.
    unsafe {
        // check if odd
        if mpi_test_bit(e, 0) == 0 {
            return -EINVAL;
        }
        // check if 2^16 < e < 2^256.
        if mpi_cmp_ui(e, 65536) <= 0 {
            return -EINVAL;
        }
        let e_max = mpi_alloc(0);
        if e_max.is_null() {
            return -ENOMEM;
        }
        let err = mpi_set_bit(e_max, 256);
        if err != 0 {
            mpi_free(e_max);
            return err;
        }
        if mpi_cmp(e, e_max) >= 0 {
            mpi_free(e_max);
            return -EINVAL;
        }
        mpi_free(e_max);
    }
    0
}

/// Common tail of both set_key functions: the modulus size rule, then (FIPS) the exponent rule.
unsafe fn finish_key(mpi_key: *mut RsaMpiKey) -> c_int {
    // SAFETY: n and e are set (the caller read them).
    unsafe {
        if rsa_check_key_length(mpi_get_size((*mpi_key).n).wrapping_shl(3)) != 0 {
            rsa_rs_free_key(mpi_key);
            return -EINVAL;
        }
        #[cfg(CONFIG_CRYPTO_FIPS)]
        if fips_enabled != 0 && rsa_check_exponent_fips((*mpi_key).e) != 0 {
            rsa_rs_free_key(mpi_key);
            return -EINVAL;
        }
    }
    0
}

/// `rsa_set_pub_key()`.
///
/// # Safety
/// `mpi_key` is the transform's `struct rsa_mpi_key`; `key` has `keylen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_set_pub_key(mpi_key: *mut RsaMpiKey, key: *const c_void, keylen: c_uint) -> c_int {
    // SAFETY: per the contract.
    unsafe {
        let mut raw: RsaRawKey = core::mem::zeroed();
        // Free the old MPI key if any
        rsa_rs_free_key(mpi_key);
        let ret = rsa_parse_pub_key(&mut raw, key, keylen);
        if ret != 0 {
            return ret;
        }
        (*mpi_key).e = mpi_read_raw_data(raw.e as *const c_void, raw.e_sz);
        if (*mpi_key).e.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;
        }
        (*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;
        }
        finish_key(mpi_key)
    }
}

/// `rsa_set_priv_key()`.
///
/// # Safety
/// As `rsa_rs_set_pub_key`.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_set_priv_key(mpi_key: *mut RsaMpiKey, key: *const c_void, keylen: c_uint) -> c_int {
    // SAFETY: per the contract.
    unsafe {
        let mut raw: RsaRawKey = core::mem::zeroed();
        // Free the old MPI key if any
        rsa_rs_free_key(mpi_key);
        let ret = rsa_parse_priv_key(&mut raw, key, keylen);
        if ret != 0 {
            return ret;
        }
        macro_rules! field {
            ($f:ident, $sz:ident) => {
                (*mpi_key).$f = mpi_read_raw_data(raw.$f as *const c_void, raw.$sz);
                if (*mpi_key).$f.is_null() {
                    rsa_rs_free_key(mpi_key);
                    return -ENOMEM;
                }
            };
        }
        field!(d, d_sz);
        field!(e, e_sz);
        field!(n, n_sz);
        field!(p, p_sz);
        field!(q, q_sz);
        field!(dp, dp_sz);
        field!(dq, dq_sz);
        field!(qinv, qinv_sz);
        finish_key(mpi_key)
    }
}

/// `rsa_max_size()`: the size in bytes of the (limb-rounded) modulus.
///
/// # Safety
/// `pkey->n` is set.
#[no_mangle]
pub unsafe extern "C" fn rsa_rs_max_size(pkey: *const RsaMpiKey) -> c_uint {
    // SAFETY: per the contract.
    unsafe { mpi_get_size((*pkey).n) }
}

/// Kani proofs (`cd rig/rsa-kani && cargo kani`; inert in the kernel build; the non-FIPS arm). The MPI layer is modelled (see
/// `model`): every operation may return any int, every creation may fail. What is proved for ALL such behaviours: no error path
/// leaks an MPI or frees one twice (the live count is back where it started), the key is left consistent, and the size rule is the
/// six accepted sizes.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn dummy() -> Mpi {
        // a non-null "key MPI" that the key owns (not counted in LIVE by the harness: set LIVE accordingly)
        core::ptr::addr_of_mut!(model_dummy) as Mpi
    }
    #[allow(non_upper_case_globals)]
    static mut model_dummy: RsaGcryMpi = RsaGcryMpi { alloced: 0, nlimbs: 0, nbits: 0, sign: 0, flags: 0, d: core::ptr::null_mut() };

    fn key_with(n: bool, e: bool, d: bool) -> RsaMpiKey {
        let z: Mpi = core::ptr::null_mut();
        RsaMpiKey { n: if n { dummy() } else { z }, e: if e { dummy() } else { z }, d: if d { dummy() } else { z }, p: dummy(), q: dummy(), dp: dummy(), dq: dummy(), qinv: dummy() }
    }

    #[kani::proof]
    fn enc_never_leaks() {
        let key = key_with(kani::any(), kani::any(), kani::any());
        unsafe { model::LIVE = 0 };
        let r = unsafe { rsa_rs_enc(&key, core::ptr::null_mut(), kani::any(), core::ptr::null_mut(), kani::any()) };
        assert!(unsafe { model::LIVE } == 0);
        if key.n.is_null() || key.e.is_null() {
            assert!(r == -EINVAL || r == -ENOMEM);
        }
    }

    #[kani::proof]
    fn dec_never_leaks() {
        let key = key_with(kani::any(), kani::any(), kani::any());
        unsafe { model::LIVE = 0 };
        let r = unsafe { rsa_rs_dec(&key, core::ptr::null_mut(), kani::any(), core::ptr::null_mut(), kani::any()) };
        assert!(unsafe { model::LIVE } == 0);
        if key.n.is_null() || key.d.is_null() {
            assert!(r == -EINVAL || r == -ENOMEM);
        }
    }

    /// Every field of the key is one live MPI the key owns: free_key releases exactly those and NULLs them all.
    #[kani::proof]
    fn free_key_frees_each_field_once() {
        let mut key = key_with(kani::any(), kani::any(), kani::any());
        let owned = [key.d, key.e, key.n, key.p, key.q, key.dp, key.dq, key.qinv].iter().filter(|m| !m.is_null()).count() as i32;
        unsafe { model::LIVE = owned };
        unsafe { rsa_rs_free_key(&mut key) };
        assert!(unsafe { model::LIVE } == 0);
        assert!(key.n.is_null() && key.e.is_null() && key.d.is_null() && key.p.is_null());
        assert!(key.q.is_null() && key.dp.is_null() && key.dq.is_null() && key.qinv.is_null());
    }

    /// After set_pub_key (any outcome of the parser and the MPI layer), the live MPIs are exactly the non-NULL fields of the key,
    /// and a failure leaves the key empty.
    #[kani::proof]
    fn set_pub_key_consistent() {
        let mut key = key_with(kani::any(), kani::any(), kani::any());
        let owned = [key.d, key.e, key.n, key.p, key.q, key.dp, key.dq, key.qinv].iter().filter(|m| !m.is_null()).count() as i32;
        unsafe { model::LIVE = owned };
        let r = unsafe { rsa_rs_set_pub_key(&mut key, core::ptr::null(), kani::any()) };
        let now = [key.d, key.e, key.n, key.p, key.q, key.dp, key.dq, key.qinv].iter().filter(|m| !m.is_null()).count() as i32;
        assert!(unsafe { model::LIVE } == now);
        if r != 0 {
            assert!(now == 0);
        } else {
            assert!(!key.n.is_null() && !key.e.is_null() && key.d.is_null());
        }
    }

    #[kani::proof]
    fn set_priv_key_consistent() {
        let mut key = key_with(kani::any(), kani::any(), kani::any());
        let owned = [key.d, key.e, key.n, key.p, key.q, key.dp, key.dq, key.qinv].iter().filter(|m| !m.is_null()).count() as i32;
        unsafe { model::LIVE = owned };
        let r = unsafe { rsa_rs_set_priv_key(&mut key, core::ptr::null(), kani::any()) };
        let now = [key.d, key.e, key.n, key.p, key.q, key.dp, key.dq, key.qinv].iter().filter(|m| !m.is_null()).count() as i32;
        assert!(unsafe { model::LIVE } == now);
        if r != 0 {
            assert!(now == 0);
        } else {
            assert!(now == 8);
        }
    }

    /// The size rule for EVERY 32-bit length: exactly the six RSA sizes (non-FIPS).
    #[kani::proof]
    fn key_length_rule() {
        let len: c_uint = kani::any();
        let ok = rsa_check_key_length(len) == 0;
        assert!(ok == matches!(len, 512 | 1024 | 1536 | 2048 | 3072 | 4096));
        assert!(ok || rsa_check_key_length(len) == -EINVAL);
    }

    /// mpi_get_size for every nlimbs: nlimbs * 8 modulo 2^32, as the C's int * int -> unsigned.
    #[kani::proof]
    fn get_size_is_nlimbs_times_8() {
        let nl: c_int = kani::any();
        let mut m = RsaGcryMpi { alloced: 0, nlimbs: nl, nbits: 0, sign: 0, flags: 0, d: core::ptr::null_mut() };
        let sz = unsafe { mpi_get_size(&mut m) };
        assert!(sz == (nl as u32).wrapping_mul(8));
    }
}
