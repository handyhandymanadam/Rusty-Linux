// SPDX-License-Identifier: 0BSD

//! Differential-harness wrapper around the real `xz_dec_bcj_rs.rs`.
//!
//! This pulls in the file the kernel build compiles, by path, rather than
//! copying it — a stale copy tested here while the kernel builds something
//! else is the failure notes/PRIOR-ART.md §2 records four times.
//!
//! It exists only to add [`rs_bcj_filter`], which reaches the seven filters
//! directly instead of through `xz_dec_bcj_run()`. That is the whole reason
//! this port is in a stronger testing position than the last two: the filters
//! are pure transforms over a byte window and can be compared against the C
//! one call at a time, rather than only through a pipeline.

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/xz/xz_dec_bcj_rs.rs"]
mod xz_dec_bcj_rs;

/// Run one BCJ filter directly on `buf[..size]`.
///
/// `kind` is the .xz Filter ID, the same number `xz_dec_bcj_reset()` takes.
/// `prev_mask` is read and written; it is state only the x86 filter carries.
/// Returns how many bytes were filtered.
///
/// # Safety
///
/// `buf` must point at `size` writable bytes and `prev_mask` at a live `u32`.
#[no_mangle]
pub unsafe extern "C" fn rs_bcj_filter(
    kind: u32,
    pos: u32,
    prev_mask: *mut u32,
    buf: *mut u8,
    size: usize,
) -> usize {
    // SAFETY: the caller guarantees both pointers, per the contract above.
    let b = unsafe { core::slice::from_raw_parts_mut(buf, size) };
    // SAFETY: as above.
    let m = unsafe { &mut *prev_mask };

    match kind {
        4 => xz_dec_bcj_rs::bcj_x86(pos, m, b),
        5 => xz_dec_bcj_rs::bcj_powerpc(pos, b),
        7 => xz_dec_bcj_rs::bcj_arm(pos, b),
        8 => xz_dec_bcj_rs::bcj_armthumb(pos, b),
        9 => xz_dec_bcj_rs::bcj_sparc(pos, b),
        10 => xz_dec_bcj_rs::bcj_arm64(pos, b),
        11 => xz_dec_bcj_rs::bcj_riscv(pos, b),
        _ => 0,
    }
}
