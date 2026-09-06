// SPDX-License-Identifier: GPL-2.0

//! `decompress_method()` -- the Rust behind `lib/decompress.c`.
//!
//! Replaces: lib/decompress.c
//!
//! Detects which of the seven boot-time decompressors a blob was made with,
//! by its first two magic bytes, and hands back a pointer to that
//! decompressor's entry point. Not exported -- called only from the
//! `__init` path that unpacks the kernel image and initramfs -- and every
//! entry point it returns is still C (`lib/decompress_*.c`, unported).
//!
//! # `Option<extern "C" fn(...)>` in place of a nullable C function pointer
//!
//! `decompress_fn` in `include/linux/decompress/generic.h` is an ordinary
//! C function pointer, nullable, and the original hands out `NULL` on "no
//! match" via a sentinel entry with a null `name` that the loop stops on.
//! `Option<unsafe extern "C" fn(...) -> c_int>` has the identical
//! representation as that raw pointer -- this is a guaranteed FFI niche
//! optimization, not an assumption -- so it is both the accurate translation
//! of the type and the idiomatic one; no physical sentinel entry is needed
//! in the Rust table, since `Option::None` already says what the sentinel's
//! null `name`/`decompressor` said.
//!
//! # `__init` / `__initconst` preserved as link sections
//!
//! Both the function and its lookup table are boot-only and, in the C, are
//! placed in the kernel's `.init.text`/`.init.rodata` sections so their
//! memory is reclaimed once boot finishes. `#[link_section]` reproduces
//! that placement directly; dropping it would not be a correctness bug, but
//! it would leave a small amount of memory permanently resident that
//! upstream reclaims, which is a real (if minor) behavior this port holds
//! faithfully rather than silently improving away.
//!
//! # `pr_debug!` is omitted, not silently dropped
//!
//! `pr_debug()` compiles to nothing at all -- not a call, a format check
//! only -- unless `CONFIG_DYNAMIC_DEBUG` or this file defines `DEBUG`.
//! Neither config this project builds sets `CONFIG_DYNAMIC_DEBUG`, and this
//! file never defined `DEBUG`, so the line was *already* dead code on every
//! kernel this project boots. Reproducing it as a real call would be adding
//! output the C never produced here, not preserving behavior.

use core::ffi::{c_char, c_int, c_long, c_ulong};

/// `decompress_fn` from `include/linux/decompress/generic.h`.
pub type DecompressFn = unsafe extern "C" fn(
    inbuf: *mut u8,
    len: c_long,
    fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
    flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
    outbuf: *mut u8,
    posp: *mut c_long,
    error: Option<unsafe extern "C" fn(*mut c_char)>,
) -> c_int;

extern "C" {
    fn gunzip(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn bunzip2(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn unlzma(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn unxz(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn unlzo(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn unlz4(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
    fn unzstd(
        inbuf: *mut u8,
        len: c_long,
        fill: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        flush: Option<unsafe extern "C" fn(*mut core::ffi::c_void, c_ulong) -> c_long>,
        outbuf: *mut u8,
        posp: *mut c_long,
        error: Option<unsafe extern "C" fn(*mut c_char)>,
    ) -> c_int;
}

struct CompressFormat {
    magic: [u8; 2],
    name: *const c_char,
    decompressor: DecompressFn,
}
// SAFETY: `name` points at a `'static` string literal and `decompressor` at
// a `'static` function; nothing here is mutated.
unsafe impl Sync for CompressFormat {}

#[link_section = ".init.rodata"]
static COMPRESSED_FORMATS: [CompressFormat; 8] = [
    CompressFormat { magic: [0x1f, 0x8b], name: c"gzip".as_ptr(), decompressor: gunzip },
    CompressFormat { magic: [0x1f, 0x9e], name: c"gzip".as_ptr(), decompressor: gunzip },
    CompressFormat { magic: [0x42, 0x5a], name: c"bzip2".as_ptr(), decompressor: bunzip2 },
    CompressFormat { magic: [0x5d, 0x00], name: c"lzma".as_ptr(), decompressor: unlzma },
    CompressFormat { magic: [0xfd, 0x37], name: c"xz".as_ptr(), decompressor: unxz },
    CompressFormat { magic: [0x89, 0x4c], name: c"lzo".as_ptr(), decompressor: unlzo },
    CompressFormat { magic: [0x02, 0x21], name: c"lz4".as_ptr(), decompressor: unlz4 },
    CompressFormat { magic: [0x28, 0xb5], name: c"zstd".as_ptr(), decompressor: unzstd },
];

/// `decompress_method()`: detect a compressed blob's format from its first
/// two bytes and return that format's decompressor entry point.
///
/// # Safety
/// `inbuf` must be valid to read `len.max(0).min(2)` bytes from; `name`,
/// if non-null, must be a valid `*mut *const c_char`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn decompress_method(
    inbuf: *const u8,
    len: c_long,
    name: *mut *const c_char,
) -> Option<DecompressFn> {
    if len < 2 {
        if !name.is_null() {
            // SAFETY: caller guarantees `name` is a valid `*mut *const c_char`.
            unsafe { *name = core::ptr::null() };
        }
        return None;
    }

    // SAFETY: `len >= 2`, so the caller's guarantee covers these two bytes.
    let magic = unsafe { [*inbuf, *inbuf.add(1)] };

    let found = COMPRESSED_FORMATS.iter().find(|cf| cf.magic == magic);

    if !name.is_null() {
        let n = found.map_or(core::ptr::null(), |cf| cf.name);
        // SAFETY: caller guarantees `name` is a valid `*mut *const c_char`.
        unsafe { *name = n };
    }
    found.map(|cf| cf.decompressor)
}
