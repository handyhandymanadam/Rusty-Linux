// SPDX-License-Identifier: GPL-2.0-or-later

//! `__crypto_xor()` -- the Rust body behind `lib/crypto/utils.c`.
//!
//! Ported from `lib/crypto/utils.c` (6.18.49). XORs two buffers into a
//! third, in the widest chunks the three pointers' relative alignment
//! allows.
//!
//! # `relalign` is the whole function
//!
//! On an architecture without efficient unaligned access, the C computes how
//! the three pointers agree modulo the word size, advances byte-wise until
//! `dst` is aligned, and then only uses a chunk width that all three can
//! manage. On x86-64 none of that runs: `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS`
//! is set, `relalign` stays 0, and every `!(relalign & n)` test is true.
//!
//! Both configuration flags are **passed in** rather than assumed here, for
//! the same reason as in `lib/sort_rs.rs`: guessing would silently change
//! which chunk width is used on an architecture nobody was testing on, and
//! the resulting bug would be an unaligned access, not a wrong answer.
//!
//! # The buffers may alias
//!
//! Callers XOR in place — `__crypto_xor(a, a, b, n)` is the normal case —
//! so `dst`, `src1` and `src2` stay raw pointers. Two overlapping slices
//! would be an aliasing claim that is not true.
//!
//! Replaces: lib/crypto/utils.c

use core::ffi::c_uint;

/// `__ffs()`: index of the lowest set bit. `d` must be non-zero.
#[inline]
fn ffs_index(d: usize) -> u32 {
    d.trailing_zeros()
}

/// Body of `__crypto_xor()`.
///
/// # Safety
/// `src1` and `src2` must be readable for `len` bytes and `dst` writable for
/// `len` bytes. Any of the three may alias any other, which is what callers
/// do. Same contract as the C.
///
/// See `include/crypto/utils.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_crypto_xor(
    dst: *mut u8,
    src1: *const u8,
    src2: *const u8,
    len: c_uint,
    efficient_unaligned: bool,
    is_64bit: bool,
) {
    let mut dst = dst;
    let mut src1 = src1;
    let mut src2 = src2;
    let mut len = len as usize;
    let mut relalign: usize = 0;

    // SAFETY: every read and write below is at an offset already established
    // to be under `len`, and the caller guarantees that many bytes in all
    // three buffers. The pointers advance in lockstep.
    unsafe {
        if !efficient_unaligned {
            let size = core::mem::size_of::<usize>();
            let d = ((dst as usize ^ src1 as usize) | (dst as usize ^ src2 as usize))
                & (size - 1);

            relalign = if d != 0 { 1usize << ffs_index(d) } else { size };

            // Advance byte-wise until dst is aligned to relalign.
            while (dst as usize & (relalign - 1)) != 0 && len > 0 {
                *dst = *src1 ^ *src2;
                dst = dst.add(1);
                src1 = src1.add(1);
                src2 = src2.add(1);
                len -= 1;
            }
        }

        while is_64bit && len >= 8 && relalign & 7 == 0 {
            let l = (src1 as *const u64).read_unaligned() ^ (src2 as *const u64).read_unaligned();

            (dst as *mut u64).write_unaligned(l);
            dst = dst.add(8);
            src1 = src1.add(8);
            src2 = src2.add(8);
            len -= 8;
        }

        while len >= 4 && relalign & 3 == 0 {
            let l = (src1 as *const u32).read_unaligned() ^ (src2 as *const u32).read_unaligned();

            (dst as *mut u32).write_unaligned(l);
            dst = dst.add(4);
            src1 = src1.add(4);
            src2 = src2.add(4);
            len -= 4;
        }

        while len >= 2 && relalign & 1 == 0 {
            let l = (src1 as *const u16).read_unaligned() ^ (src2 as *const u16).read_unaligned();

            (dst as *mut u16).write_unaligned(l);
            dst = dst.add(2);
            src1 = src1.add(2);
            src2 = src2.add(2);
            len -= 2;
        }

        while len > 0 {
            *dst = *src1 ^ *src2;
            dst = dst.add(1);
            src1 = src1.add(1);
            src2 = src2.add(1);
            len -= 1;
        }
    }
}
