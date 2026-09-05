// SPDX-License-Identifier: GPL-2.0

//! Packed BCD conversion.
//!
//! Ported from `lib/bcd.c` (6.18.49), which no longer exists: this file is the
//! whole of it. Both bodies are exactly the C's arithmetic, including
//! `_bin2bcd`'s `(val * 103) >> 10` division-by-ten trick, which is only
//! correct for the range RTC drivers use and is left as it is.
//!
//! The exports and their MODVERSIONS contracts are below, carried in this
//! object rather than in a C file that would only exist to hold them. See
//! `rust/kernel/kabi.rs`.
//!
//! Replaces: lib/bcd.c

use core::ffi::c_uint;

kernel::kabi_export! {
    _bcd2bin,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned char byte_size(1) encoding(8) val ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// `_bcd2bin()` itself -- Rust defines and exports the symbol; there is no C.
///
/// See `include/linux/bcd.h` for the C declaration this must keep matching.
#[no_mangle]
pub extern "C" fn _bcd2bin(val: u8) -> c_uint {
    ((val & 0x0f) as c_uint) + (val >> 4) as c_uint * 10
}

kernel::kabi_export! {
    _bin2bcd,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) val ) -> base_type unsigned char byte_size(1) encoding(8)",
}

/// `_bin2bcd()` itself -- Rust defines and exports the symbol; there is no C.
///
/// The C computes `t = (val * 103) >> 10` as a cheap `val / 10`. That
/// identity holds up to `val == 636`; above it the multiply is also free to
/// overflow `unsigned`. Callers are RTC drivers passing 0..99, and the C
/// makes no promise beyond that, so the Rust reproduces the arithmetic
/// rather than correcting it — with `wrapping_mul`, because the kernel
/// builds Rust with overflow checks on and a panic here would be a new
/// behaviour, not a preserved one.
///
/// See `include/linux/bcd.h` for the C declaration.
#[no_mangle]
pub extern "C" fn _bin2bcd(val: c_uint) -> u8 {
    let t = val.wrapping_mul(103) >> 10;

    ((t << 4) | val.wrapping_sub(t.wrapping_mul(10))) as u8
}
