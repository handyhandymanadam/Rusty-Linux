// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `lz4_decompress_rs.rs`.
//!
//! This pulls in the file the kernel build compiles, by path, rather than
//! copying it — a stale copy tested here while the kernel builds something
//! else is the failure PRIOR-ART.md §2 records four times.
//!
//! It exists only to add [`lz4_rs_abi`], which reports the offsets the port's
//! `LZ4_streamDecode_t_internal` mirror assumes so the C side can check them
//! against `offsetof()` on `include/linux/lz4.h`. That struct is the caller's —
//! zram embeds it — so GOALS.md §5 puts its layout out of bounds.

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/lz4/lz4_decompress_rs.rs"]
mod lz4_decompress_rs;

/// Number of `u64` slots [`lz4_rs_abi`] fills.
pub const ABI_SLOTS: usize = 5;

/// Report what this port believes the C layout to be.
///
/// # Safety
/// `out` must point at [`ABI_SLOTS`] writable `u64`s.
#[no_mangle]
pub unsafe extern "C" fn lz4_rs_abi(out: *mut u64) {
    use lz4_decompress_rs::Lz4StreamDecode;
    let v: [u64; ABI_SLOTS] = [
        core::mem::size_of::<Lz4StreamDecode>() as u64,
        core::mem::offset_of!(Lz4StreamDecode, external_dict) as u64,
        core::mem::offset_of!(Lz4StreamDecode, ext_dict_size) as u64,
        core::mem::offset_of!(Lz4StreamDecode, prefix_end) as u64,
        core::mem::offset_of!(Lz4StreamDecode, prefix_size) as u64,
    ];
    // SAFETY: the caller guarantees room for ABI_SLOTS u64s.
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), out, ABI_SLOTS) }
}
