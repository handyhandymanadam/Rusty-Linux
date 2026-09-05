// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `inffast_rs.rs`.
//!
//! This pulls in the file the kernel build compiles, by path, rather than
//! copying it — a stale copy tested here while the kernel builds something
//! else is the failure PRIOR-ART.md §2 records four times.
//!
//! It carries ALL THREE ported files in this directory, so the Rust arm of the
//! differential is the real pipeline: `zlib_inflate()` in pristine C calling a
//! Rust `zlib_inflate_table()` and a Rust `inflate_fast()`.
//!
//! It exists only to add [`inffast_rs_abi`] and [`inftrees_rs_abi`], which report the offsets and
//! constants the port's struct mirrors assume so the C side can check them
//! against `offsetof()` on the real headers. A wrong offset is the one
//! mistake in this port that comparing output would not localise: it would
//! simply read the wrong field and diverge everywhere at once.

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zlib_inflate/inffast_rs.rs"]
mod inffast_rs;

/// The table builder, likewise by path rather than by copy.
#[path = "../../tree/lib/zlib_inflate/inftrees_rs.rs"]
mod inftrees_rs;

/// The state machine, likewise. It `include!`s `inffixed_rs.rs`, so the
/// generated fixed tables come in with it.
#[path = "../../tree/lib/zlib_inflate/inflate_rs.rs"]
mod inflate_rs;

use inffast_rs::{Code, InflateState, ZStream, MODE_BAD, MODE_TYPE};

/// Number of `u64` slots [`inffast_rs_abi`] fills.
pub const ABI_SLOTS: usize = 22;

/// Report what this port believes the C layout to be.
///
/// The slot order is fixed and duplicated in `main.c`; both ends name the
/// fields in the same comments.
///
/// # Safety
/// `out` must point at [`ABI_SLOTS`] writable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn inffast_rs_abi(out: *mut u64) {
    let v: [u64; ABI_SLOTS] = [
        // struct inflate_state
        core::mem::offset_of!(InflateState, mode) as u64,
        core::mem::offset_of!(InflateState, dmax) as u64,
        core::mem::offset_of!(InflateState, wsize) as u64,
        core::mem::offset_of!(InflateState, whave) as u64,
        core::mem::offset_of!(InflateState, write) as u64,
        core::mem::offset_of!(InflateState, window) as u64,
        core::mem::offset_of!(InflateState, hold) as u64,
        core::mem::offset_of!(InflateState, bits) as u64,
        core::mem::offset_of!(InflateState, lencode) as u64,
        core::mem::offset_of!(InflateState, distcode) as u64,
        core::mem::offset_of!(InflateState, lenbits) as u64,
        core::mem::offset_of!(InflateState, distbits) as u64,
        // struct z_stream_s
        core::mem::offset_of!(ZStream, next_in) as u64,
        core::mem::offset_of!(ZStream, avail_in) as u64,
        core::mem::offset_of!(ZStream, next_out) as u64,
        core::mem::offset_of!(ZStream, avail_out) as u64,
        core::mem::offset_of!(ZStream, msg) as u64,
        core::mem::offset_of!(ZStream, state) as u64,
        // code
        core::mem::size_of::<Code>() as u64,
        core::mem::offset_of!(Code, val) as u64,
        // inflate_mode values this port writes
        MODE_TYPE as u64,
        MODE_BAD as u64,
    ];
    // SAFETY: the caller guarantees room for ABI_SLOTS u64s.
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), out, ABI_SLOTS) }
}

/// Number of `u64` slots [`inftrees_rs_abi`] fills.
pub const INFTREES_ABI_SLOTS: usize = 6;

/// Report what `inftrees_rs.rs` believes the C layout and constants to be.
///
/// `struct code` is mirrored in TWO ported files in this directory, because
/// one crate per file leaves no way to share it. Checking only `inffast_rs`'s
/// copy would leave the other free to drift, so both are reported and
/// `main.c` compares both against `offsetof()` on the real header.
///
/// # Safety
/// `out` must point at [`INFTREES_ABI_SLOTS`] writable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn inftrees_rs_abi(out: *mut u64) {
    let v: [u64; INFTREES_ABI_SLOTS] = [
        core::mem::size_of::<inftrees_rs::Code>() as u64,
        core::mem::offset_of!(inftrees_rs::Code, op) as u64,
        core::mem::offset_of!(inftrees_rs::Code, bits) as u64,
        core::mem::offset_of!(inftrees_rs::Code, val) as u64,
        inftrees_rs::enough() as u64,
        inftrees_rs::maxd() as u64,
    ];
    // SAFETY: the caller guarantees room for INFTREES_ABI_SLOTS u64s.
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), out, INFTREES_ABI_SLOTS) }
}

/// Number of `u64` slots [`inflate_rs_abi`] fills.
pub const INFLATE_ABI_SLOTS: usize = 12;

/// Report what `inflate_rs.rs` believes the tail of `struct inflate_state` to
/// be — the fields `inffast_rs.rs` deliberately does not mirror, plus the
/// `inflate_mode` values this file writes.
///
/// This is the THIRD mirror of a caller-owned layout in this directory. Two
/// were already checked; leaving the third unchecked would be worse than not
/// having checked any, because the count implies coverage.
///
/// # Safety
/// `out` must point at [`INFLATE_ABI_SLOTS`] writable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn inflate_rs_abi(out: *mut u64) {
    use inflate_rs::InflateState;
    let v: [u64; INFLATE_ABI_SLOTS] = [
        core::mem::size_of::<InflateState>() as u64,
        core::mem::offset_of!(InflateState, ncode) as u64,
        core::mem::offset_of!(InflateState, nlen) as u64,
        core::mem::offset_of!(InflateState, ndist) as u64,
        core::mem::offset_of!(InflateState, have) as u64,
        core::mem::offset_of!(InflateState, next) as u64,
        core::mem::offset_of!(InflateState, lens) as u64,
        core::mem::offset_of!(InflateState, work) as u64,
        core::mem::offset_of!(InflateState, codes) as u64,
        inflate_rs::HEAD as u64,
        inflate_rs::MATCH as u64,
        inflate_rs::SYNC as u64,
    ];
    // SAFETY: the caller guarantees room for INFLATE_ABI_SLOTS u64s.
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), out, INFLATE_ABI_SLOTS) }
}

/// The generated fixed tables, as raw bytes, so `main.c` can compare them
/// against `inffixed.h`'s own `lenfix[]`/`distfix[]`.
///
/// 544 entries were machine-generated out of that header; this is what makes
/// a wrong entry a test failure rather than a silent one.
///
/// `which` selects: 0 is `lenfix`, anything else `distfix`.
#[no_mangle]
pub extern "C" fn inffixed_rs_table(which: core::ffi::c_int) -> *const u8 {
    if which == 0 {
        inflate_rs::LENFIX.as_ptr() as *const u8
    } else {
        inflate_rs::DISTFIX.as_ptr() as *const u8
    }
}

/// `zlib_adler32()` as this port reimplements it.
///
/// The C's is a `static inline` in `include/linux/zutil.h`, so there is no
/// symbol to call and the port had to carry its own. Comparing the two only
/// through a decompressed stream's check value would exercise it thinly and
/// only ever with the lengths a deflate stream happens to produce; this lets
/// the differential drive it directly, including past `NMAX`.
///
/// # Safety
/// `buf` must point at `len` readable bytes, or be null with `len == 0`.
#[no_mangle]
pub unsafe extern "C" fn rs_adler32(
    adler: core::ffi::c_ulong,
    buf: *const u8,
    len: usize,
) -> core::ffi::c_ulong {
    // SAFETY: the caller's contract; a zero-length slice may not be built
    // from a null pointer.
    let s: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(buf, len) }
    };
    inflate_rs::adler32(adler, s)
}
