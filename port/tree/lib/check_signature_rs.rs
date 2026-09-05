// SPDX-License-Identifier: GPL-2.0

//! BIOS signature matching -- the Rust body behind `lib/check_signature.c`.
//!
//! Ported from `lib/check_signature.c` (6.18.49). The whole function is a
//! byte-at-a-time compare of an MMIO window against a signature block, and
//! the port keeps it byte-at-a-time on purpose: every read must remain a
//! `readb()`, in the same order, against the same address. Widening the
//! compare would be correct for RAM and wrong for a device window.
//!
//! Replaces: lib/check_signature.c

use core::ffi::{c_int, c_void};

extern "C" {
    /// `rust/helpers/io.c`. `readb()` is a macro over `__raw_readb()` plus
    /// the architecture's ordering barriers; it is not something a Rust body
    /// can spell for itself, and the kernel already exports this helper for
    /// exactly that reason. Declared here rather than reached through
    /// `bindings::`, following `lib/earlycpio_rs.rs`.
    fn rust_helper_readb(addr: *const c_void) -> u8;
}

/// Body of `check_signature()`. Returns 1 on a match, 0 otherwise.
///
/// # Deliberate divergence
///
/// The C is `while (length--)`, which for a NEGATIVE length is true on the
/// first test and keeps going -- some two billion `readb()`s off the end of
/// the window, or until a byte happens not to match. That is not a behaviour
/// worth preserving. This returns 1 for any `length <= 0`, treating it as the
/// empty signature that `length == 0` already is in the C. No caller is
/// affected: all six in-tree callers pass a `sizeof` or a positive struct
/// field. Recorded in STATUS.md.
///
/// # Safety
///
/// `io_addr` must be an ioremapped window of at least `length` bytes and
/// `signature` must point to at least `length` readable bytes -- the same
/// contract the C has, unstated.
///
/// See `include/asm-generic/io.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_check_signature(
    io_addr: *const c_void,
    signature: *const u8,
    length: c_int,
) -> c_int {
    let n = if length > 0 { length as usize } else { 0 };

    for i in 0..n {
        // SAFETY: the caller guarantees `n` readable bytes at each pointer,
        // and `readb()` is the only legal way to touch the iomem one.
        let (got, want) = unsafe {
            (
                rust_helper_readb(io_addr.cast::<u8>().add(i).cast::<c_void>()),
                *signature.add(i),
            )
        };

        if got != want {
            return 0;
        }
    }

    1
}
