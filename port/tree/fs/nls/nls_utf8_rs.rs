// SPDX-License-Identifier: GPL-2.0

//! NLS UTF-8 charset -- the Rust behind `fs/nls/nls_utf8.c`.
//!
//! Ported from `fs/nls/nls_utf8.c` (6.18.49), "Module for handling utf8 just
//! like any other charset", by Urban Widmark 2000.
//!
//! # What is here and what stayed in C (`nls_utf8_glue.c`)
//!
//! Here: `uni2char`, `char2uni`, the 256-entry identity table and the
//! `struct nls_table` itself (`nls_utf8_rs_table`). In C: `module_init`/
//! `module_exit`, `MODULE_*`, and the `register_nls()` call, a macro that
//! expands to `__register_nls(nls, THIS_MODULE)`.
//!
//! `__register_nls()` WRITES this table (`nls->owner`, `nls->next`), so it is
//! mutable shared state behind an `UnsafeCell` and must be laid out exactly as
//! the C struct: [`NlsTable`] mirrors it and `rig/layout-check.sh` compares
//! the geometry against the built vmlinux's DWARF.
//!
//! # Divergence (benign, recorded in logs/deviations.md)
//!
//! The C fills its `identity[]` array in a loop at init; here it is a constant
//! (`.rodata`) with the same 256 bytes. `identity` is `static` in the C, so no
//! symbol or caller can tell.
//!
//! Error values are the C's: `-ENAMETOOLONG` for `boundlen <= 0`, `-EINVAL`
//! (with `'?'` stored) for an unencodable code point or a malformed/too-wide
//! sequence. No message text is produced by this file.
//!
//! Replaces: fs/nls/nls_utf8.c

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};

const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;
/// `MAX_WCHAR_T` in `include/linux/nls.h`.
const MAX_WCHAR_T: u32 = 0xffff;

extern "C" {
    /// `fs/nls/nls_base.c`, still C.
    fn utf32_to_utf8(u: u32, s: *mut u8, maxlen: c_int) -> c_int;
    /// `fs/nls/nls_base.c`, still C.
    fn utf8_to_utf32(s: *const u8, len: c_int, pu: *mut u32) -> c_int;
}

/// Mirrors `struct nls_table` in `include/linux/nls.h`.
#[repr(C)]
pub struct NlsTable {
    charset: *const c_char,
    alias: *const c_char,
    uni2char: Option<unsafe extern "C" fn(u16, *mut u8, c_int) -> c_int>,
    char2uni: Option<unsafe extern "C" fn(*const u8, c_int, *mut u16) -> c_int>,
    charset2lower: *const u8,
    charset2upper: *const u8,
    owner: *mut c_void,
    next: *mut NlsTable,
}

/// The table is written by `__register_nls()` under `nls_lock`; Rust never
/// touches it after construction.
#[repr(transparent)]
pub struct SharedTable(UnsafeCell<NlsTable>);

// SAFETY: all mutation is by the C registry, serialised by its spinlock.
unsafe impl Sync for SharedTable {}

const fn identity_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = i as u8;
        i += 1;
    }
    t
}

/// `identity[]` in the C: no case conversion.
static IDENTITY: [u8; 256] = identity_table();

/// `uni2char()` of the C file.
unsafe extern "C" fn uni2char(uni: u16, out: *mut u8, boundlen: c_int) -> c_int {
    if boundlen <= 0 {
        return -ENAMETOOLONG;
    }

    // SAFETY: nls_base.c's utf32_to_utf8 writes at most `boundlen` bytes to
    // `out`, which the caller guarantees (the nls_table contract).
    let n = unsafe { utf32_to_utf8(uni as u32, out, boundlen) };
    if n < 0 {
        // SAFETY: boundlen >= 1, so out[0] is writable.
        unsafe { *out = b'?' };
        return -EINVAL;
    }
    n
}

/// `char2uni()` of the C file.
unsafe extern "C" fn char2uni(rawstring: *const u8, boundlen: c_int, uni: *mut u16) -> c_int {
    let mut u: u32 = 0;

    // SAFETY: utf8_to_utf32 reads at most `boundlen` bytes of `rawstring`.
    let n = unsafe { utf8_to_utf32(rawstring, boundlen, &mut u) };
    if n < 0 || u > MAX_WCHAR_T {
        // SAFETY: the caller passes a valid wchar_t out-parameter.
        unsafe { *uni = 0x003f }; // '?'
        return -EINVAL;
    }
    // SAFETY: as above.
    unsafe { *uni = u as u16 };
    n
}

/// `static struct nls_table table` of the C file, given a symbol so the glue
/// can pass it to `register_nls()`.
#[no_mangle]
pub static nls_utf8_rs_table: SharedTable = SharedTable(UnsafeCell::new(NlsTable {
    charset: b"utf8\0".as_ptr() as *const c_char,
    alias: core::ptr::null(),
    uni2char: Some(uni2char),
    char2uni: Some(char2uni),
    charset2lower: IDENTITY.as_ptr(),
    charset2upper: IDENTITY.as_ptr(),
    owner: core::ptr::null_mut(),
    next: core::ptr::null_mut(),
}));
