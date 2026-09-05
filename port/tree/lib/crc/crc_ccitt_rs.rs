// SPDX-License-Identifier: GPL-2.0-only

//! CRC-CCITT -- the Rust body behind `lib/crc/crc-ccitt.c`.
//!
//! Ported from `lib/crc/crc-ccitt.c` (6.18.49) and the `crc_ccitt_byte()`
//! it inlines from `include/linux/crc-ccitt.h`.
//!
//! # The table is passed in, and that is deliberate
//!
//! `crc_ccitt_table` is itself an `EXPORT_SYMBOL` — a **data** symbol, with
//! its own MODVERSIONS CRC and its own out-of-tree users — and
//! `crc_ccitt_byte()` in the header indexes it directly. There is no wrapper
//! trick for a data symbol the way there is for a function, so it has to
//! stay in C. Taking a pointer to it keeps one copy of the table in the
//! kernel rather than two that could drift.
//!
//! `lib/crc/crc16_rs.rs` is the opposite case and owns its table, because
//! `crc16_table` is `static` and nothing outside can see it.
//!
//! Replaces: lib/crc/crc-ccitt.c

/// Body of `crc_ccitt()`.
///
/// # Safety
/// `buffer` must be readable for `len` bytes and `table` must point at 256
/// `u16`s — in practice always `crc_ccitt_table`, passed in by
/// `lib/crc/crc-ccitt.c`.
///
/// See `include/linux/crc-ccitt.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_crc_ccitt(
    crc: u16,
    buffer: *const u8,
    len: usize,
    table: *const u16,
) -> u16 {
    if len == 0 {
        return crc;
    }

    // SAFETY: the caller guarantees `len` readable bytes at `buffer` and a
    // 256-entry table. Both slices are read-only and do not outlive the call.
    let (buf, tab) = unsafe {
        (
            core::slice::from_raw_parts(buffer, len),
            core::slice::from_raw_parts(table, 256),
        )
    };
    let mut crc = crc;

    for &b in buf {
        // crc_ccitt_byte(), from include/linux/crc-ccitt.h.
        crc = (crc >> 8) ^ tab[((crc ^ b as u16) & 0xff) as usize];
    }
    crc
}
