// SPDX-License-Identifier: GPL-2.0-or-later

//! The block loop of `crypto/ecb.c` (ECB mode over a bare `crypto_cipher`).
//!
//! Ported from `crypto/ecb.c` (6.18.49), (C) 2006 Herbert Xu. What is here:
//!
//! * `ecb_rs_crypt()`: the body of `crypto_ecb_crypt()`: while at least one
//!   whole block is left, call the cipher on it (`dst = fn(src)`) and advance
//!   one block; then the remainder rule `nbytes && final ? -EINVAL : nbytes`.
//!
//! What stays C (`crypto/ecb_glue.c`, upstream's file with exactly that body
//! replaced by the call): the lskcipher glue (`crypto_ecb_encrypt2/decrypt2`,
//! setkey, init/exit tfm, the instance allocator, both `create` functions, the
//! template and `module_init`), everything over `struct crypto_cipher`,
//! `struct crypto_lskcipher`, `struct lskcipher_instance` (Kconfig-dependent
//! layouts, never mirrored here). The cipher is reached through the pointer the
//! C passed (`cia_encrypt` / `cia_decrypt`, `void (*)(struct crypto_tfm *, u8 *,
//! const u8 *)`), an opaque callback here.
//!
//! In contract (the C relies on it): `bsize` is the cipher's block size, never 0
//! (`crypto_check_alg` and the cipher registrations guarantee a non-zero size
//! for any cipher an ECB instance is built on). Out of contract the C loops
//! forever when `bsize == 0` (`nbytes >= 0` is always true); here `bsize == 0`
//! calls the cipher never and returns as if no whole block fitted. No messages.
//!
//! Replaces: the loop and remainder rule of `crypto_ecb_crypt()` in crypto/ecb.c

use core::ffi::{c_int, c_uint, c_void};

/// `void (*)(struct crypto_tfm *, u8 *dst, const u8 *src)`: encrypt/decrypt one block; supplied by the C glue.
pub type Enc = unsafe extern "C" fn(*mut c_void, *mut u8, *const u8);

const EINVAL: c_int = 22;

/// `crypto_ecb_crypt()`: whole blocks through `enc`, returns the remainder (`nbytes mod bsize`), or `-EINVAL`
/// when a remainder is left and `final` is set.
///
/// # Safety
/// `src` has `nbytes` readable and `dst` `nbytes` writable bytes (equal or disjoint, as the lskcipher caller
/// guarantees: ECB is in-place safe block by block); `enc` encrypts exactly one block of `bsize` bytes from
/// `src` to `dst`.
#[no_mangle]
pub unsafe extern "C" fn ecb_rs_crypt(
    bsize: c_uint,
    tfm: *mut c_void,
    enc: Enc,
    mut src: *const u8,
    mut dst: *mut u8,
    mut nbytes: c_uint,
    final_: bool,
) -> c_int {
    // SAFETY: the loop runs only while nbytes >= bsize (> 0), so each pass touches one whole block inside the
    // caller's nbytes, and `nbytes -= bsize` cannot underflow.
    unsafe {
        while bsize != 0 && nbytes >= bsize {
            enc(tfm, dst, src);
            src = src.add(bsize as usize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;
        }
    }
    if nbytes != 0 && final_ {
        -EINVAL
    } else {
        nbytes as c_int
    }
}

/// Kani proofs (`cd rig/ecb-kani && cargo kani`; inert in the kernel build). Buffers have EXACTLY the contract
/// sizes, so any access outside them is reported.
#[cfg(kani)]
mod proofs {
    use super::*;

    unsafe extern "C" fn enc_model(_t: *mut c_void, dst: *mut u8, src: *const u8) {
        // a 4-byte "cipher": reads src[0..4], writes dst[0..4]
        let mut i = 0;
        while i < 4 {
            *dst.add(i) = (*src.add(i)).wrapping_add(i as u8 + 1);
            i += 1;
        }
    }

    macro_rules! blocks {
        ($name:ident, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(22)]
            fn $name() {
                let src: [u8; $n] = kani::any();
                let mut dst: [u8; $n] = kani::any();
                let fin: bool = kani::any();
                let r = unsafe { ecb_rs_crypt(4, core::ptr::null_mut(), enc_model, src.as_ptr(), dst.as_mut_ptr(), $n, fin) };
                let rem = ($n % 4) as c_int;
                assert!(if rem != 0 && fin { r == -22 } else { r == rem });
                // every whole block is the model cipher of the source block
                let mut i = 0;
                while i < $n / 4 * 4 {
                    assert!(dst[i] == src[i].wrapping_add((i % 4) as u8 + 1));
                    i += 1;
                }
            }
        };
    }
    blocks!(ecb_0, 0);
    blocks!(ecb_3, 3);
    blocks!(ecb_4, 4);
    blocks!(ecb_7, 7);
    blocks!(ecb_16, 16);
    blocks!(ecb_19, 19);

    /// bsize 0 touches nothing and never loops (the C would spin).
    #[kani::proof]
    fn bsize_zero_is_noop() {
        let n: c_uint = kani::any();
        let fin: bool = kani::any();
        let r = unsafe { ecb_rs_crypt(0, core::ptr::null_mut(), enc_model, core::ptr::null(), core::ptr::null_mut(), n, fin) };
        assert!(if n != 0 && fin { r == -22 } else { r == n as c_int });
    }
}
