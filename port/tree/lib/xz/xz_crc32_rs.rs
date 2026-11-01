// SPDX-License-Identifier: 0BSD

//! CRC32 (IEEE 802.3, reflected, polynomial 0xEDB88320) for the XZ decoder in
//! the x86 boot stub -- the Rust replacement for `lib/xz/xz_crc32.c`.
//!
//! RUSTY-LINUX: built ONLY for arch/x86/boot/compressed (core-only, no
//! `kernel` crate). The running kernel does not use it: its XZ code calls the
//! kernel's `crc32_le()` (xz_stream.h). The stub has no such function, so this
//! file supplies both names:
//!
//!  - `xz_crc32()`: same signature and result as `xz_crc32.c`'s.
//!  - `crc32_le()`: what the Rust XZ engine (xz_dec_stream_rs.rs) calls.
//!    xz_stream.h defines `xz_crc32(b, n, c)` as `~crc32_le(~c, b, n)`; this is
//!    the inverse, `crc32_le(c, p, n) = ~xz_crc32(p, n, ~c)`, which is the bare
//!    table loop with no pre/post inversion -- the kernel's `crc32_le`
//!    semantics.
//!
//! Deliberate difference from the C: the 256-entry table is built by a `const
//! fn` at compile time, so there is nothing to initialise at run time.
//! `xz_crc32_init()` and the stub's `xz_boot_crc_ready()` once-flag therefore
//! disappear; a table in read-only data cannot be "not yet built".

const POLY: u32 = 0xEDB8_8320;

const fn make_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = i as u32;
        let mut j = 0;
        while j < 8 {
            // The C: r = (r >> 1) ^ (poly & ~((r & 1) - 1));
            r = (r >> 1) ^ (POLY & (!((r & 1).wrapping_sub(1))));
            j += 1;
        }
        t[i] = r;
        i += 1;
    }
    t
}

static XZ_CRC32_TABLE: [u32; 256] = make_table();

/// Body of `xz_crc32()`.
///
/// # Safety
/// `buf` must be readable for `size` bytes (it may be anything when `size` is 0).
#[no_mangle]
pub unsafe extern "C" fn xz_crc32(buf: *const u8, size: usize, crc: u32) -> u32 {
    let mut crc = !crc;
    let mut i = 0usize;
    while i < size {
        // SAFETY: the caller's contract: `buf` is readable for `size` bytes and i < size.
        let b = unsafe { *buf.add(i) };
        crc = XZ_CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
        i += 1;
    }
    !crc
}

/// The kernel's `crc32_le()` as the Rust XZ engine calls it.
///
/// # Safety
/// `p` must be readable for `len` bytes (it may be anything when `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn crc32_le(crc: u32, p: *const u8, len: usize) -> u32 {
    // SAFETY: forwarded caller contract.
    !unsafe { xz_crc32(p, len, !crc) }
}
