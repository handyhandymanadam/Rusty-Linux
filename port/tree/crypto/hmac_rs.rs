// SPDX-License-Identifier: GPL-2.0-or-later

//! The HMAC key-pad derivation of `crypto/hmac.c` (RFC 2104).
//!
//! Ported from `crypto/hmac.c` (6.18.49), Copyright (c) 2002 James Morris,
//! (c) 2006 Herbert Xu. `hmac_setkey()` and `hmac_setkey_ahash()` open-code the
//! same ten lines: with the key (digested first when longer than the block
//! size) already in `ipad[0..keylen]`,
//!
//! ```text
//! memset(ipad + keylen, 0, bs - keylen);
//! memcpy(opad, ipad, bs);
//! for (i = 0; i < bs; i++) { ipad[i] ^= 0x36; opad[i] ^= 0x5c; }
//! ```
//!
//! That is this file's one function. Everything else in `crypto/hmac.c` (shash
//! and ahash plumbing, `SHASH_DESC_ON_STACK`, the FIPS key-length test, the
//! template/spawn handling, `module_init`) is crypto-API glue over structs
//! whose layout depends on Kconfig, with no byte-level logic, and stays C in
//! `crypto/hmac_glue.c`, which calls this function from both setkey paths.
//!
//! The C passes `keylen <= bs` (it digests the key when it is longer, and
//! `ds <= bs` for every hash); a `keylen` above `bs` is clamped here rather
//! than letting `bs - keylen` wrap into a huge memset, and a negative `bs`
//! (also impossible) writes nothing. Neither changes any reachable result.
//! The function reads and writes only `[0, bs)` of each pad. No messages.
//!
//! Replaces: the pad derivation in crypto/hmac.c

use core::ffi::{c_int, c_uint};

/// `HMAC_IPAD_VALUE` (`include/crypto/hmac.h`).
const HMAC_IPAD_VALUE: u8 = 0x36;
/// `HMAC_OPAD_VALUE`.
const HMAC_OPAD_VALUE: u8 = 0x5c;

/// Derive the inner and outer pads from the key in `ipad[0..keylen]`.
///
/// # Safety
/// `ipad` and `opad` each point to `bs` writable bytes and do not overlap;
/// `ipad[0..keylen]` is initialised and `keylen <= bs`.
#[no_mangle]
pub unsafe extern "C" fn hmac_rs_derive_pads(ipad: *mut u8, opad: *mut u8, bs: c_int, keylen: c_uint) {
    let bs = if bs < 0 { 0 } else { bs as usize };
    let keylen = core::cmp::min(keylen as usize, bs);

    // SAFETY: both pads have `bs` writable bytes (caller); every offset below is < bs.
    unsafe {
        core::ptr::write_bytes(ipad.add(keylen), 0, bs - keylen);
        core::ptr::copy_nonoverlapping(ipad, opad, bs);

        let mut i = 0;
        while i < bs {
            *ipad.add(i) ^= HMAC_IPAD_VALUE;
            *opad.add(i) ^= HMAC_OPAD_VALUE;
            i += 1;
        }
    }
}

/// Kani proofs (`cd rig/hmac-kani && cargo kani`; inert in the kernel build): for every key content and
/// every `keylen <= bs`, with pads of EXACTLY `bs` bytes: no access outside either pad, no panic.
#[cfg(kani)]
mod proofs {
    use super::*;

    macro_rules! pads_in_bounds {
        ($name:ident, $bs:expr) => {
            #[kani::proof]
            #[kani::unwind(70)]
            fn $name() {
                let mut ipad: [u8; $bs] = kani::any();
                let mut opad: [u8; $bs] = kani::any();
                let keylen: c_uint = kani::any();
                kani::assume(keylen as usize <= $bs);
                let key = ipad;
                unsafe { hmac_rs_derive_pads(ipad.as_mut_ptr(), opad.as_mut_ptr(), $bs as c_int, keylen) };
                let mut i = 0;
                while i < $bs {
                    let k = if i < keylen as usize { key[i] } else { 0 };
                    assert!(ipad[i] == k ^ 0x36);
                    assert!(opad[i] == k ^ 0x5c);
                    i += 1;
                }
            }
        };
    }
    pads_in_bounds!(bs_1, 1);
    pads_in_bounds!(bs_8, 8);
    pads_in_bounds!(bs_20, 20);
    pads_in_bounds!(bs_64, 64);

    /// Out-of-contract arguments never touch memory: `bs <= 0` writes nothing; `keylen > bs` is clamped.
    #[kani::proof]
    #[kani::unwind(10)]
    fn clamps() {
        let mut ipad: [u8; 4] = kani::any();
        let mut opad: [u8; 4] = kani::any();
        let keylen: c_uint = kani::any();
        unsafe { hmac_rs_derive_pads(ipad.as_mut_ptr(), opad.as_mut_ptr(), 4, keylen) };
        let bs: c_int = kani::any();
        kani::assume(bs <= 0);
        let o = opad;
        unsafe { hmac_rs_derive_pads(ipad.as_mut_ptr(), opad.as_mut_ptr(), bs, keylen) };
        assert!(opad == o);
    }
}
