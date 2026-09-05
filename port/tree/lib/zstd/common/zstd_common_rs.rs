// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause

//! zstd's version and error-management entry points.
//!
//! Ported from `lib/zstd/common/zstd_common.c` (6.18.49), which carries
//! `Copyright (c) Meta Platforms, Inc. and affiliates.` and is
//! `GPL-2.0+ OR BSD-3-Clause`.
//!
//! # Shape: three thunks stay, three definitions move here
//!
//! `lib/zstd/zstd_common_module.c:24-26` `EXPORT_SYMBOL_GPL`s `ZSTD_isError`,
//! `ZSTD_getErrorName` and `ZSTD_getErrorCode`, so under
//! `CONFIG_GENDWARFKSYMS` their MODVERSIONS CRCs come from the DWARF of the
//! **definition** and the definitions must stay C. Those three are entry
//! thunks in `zstd_common.c` calling the `rust_*` bodies below — the `lib/bcd`
//! shape, forced rather than chosen, and the same arrangement
//! `common/entropy_common.c` already has.
//!
//! `ZSTD_versionNumber`, `ZSTD_versionString` and `ZSTD_getErrorString` are
//! **not** exported and have **no callers anywhere in the kernel** (verified
//! with `nm -u` across every object in the build, not inferred). They carry no
//! CRC, so Rust defines them directly under their own names — the
//! `lib/union_find` shape. They are kept rather than deleted because they are
//! part of the `zstd_lib.h` API contract this file exists to satisfy.
//!
//! # What this file is, honestly
//!
//! Six one-line wrappers over `error_private.h`'s `static inline`s. There is
//! no algorithm here and porting it buys no safety on its own. It is worth
//! doing for one reason: with it, **every line of `lib/zstd/common/` that the
//! kernel executes is Rust**, except the six mandatory export thunks and
//! `debug.c`, which compiles to an object with zero bytes of text, data and
//! bss at `DEBUGLEVEL 0`. That is GOALS.md §1's measure of a finished
//! subsystem, and it is the whole return.
//!
//! # Trusted surface
//!
//! **One `unsafe` block**, class B (boundary): the `extern "C"` call to
//! `ERR_getErrorString`, which is itself Rust now
//! (`common/error_private_rs.rs`) but lives in a separate crate because the
//! kernel builds one object per `.rs`. It is not a C crossing any more, and it
//! retires the day these two files become one crate.
//!
//! Replaces: lib/zstd/common/zstd_common.c

#![allow(non_snake_case)]

use core::ffi::{c_char, c_uint};

// lib/zstd/include/linux/zstd_lib.h:91-103
const ZSTD_VERSION_MAJOR: c_uint = 1;
const ZSTD_VERSION_MINOR: c_uint = 5;
const ZSTD_VERSION_RELEASE: c_uint = 7;
const ZSTD_VERSION_NUMBER: c_uint =
    ZSTD_VERSION_MAJOR * 100 * 100 + ZSTD_VERSION_MINOR * 100 + ZSTD_VERSION_RELEASE;

/// `ZSTD_VERSION_STRING`, which the C builds by stringifying the three numbers
/// above through `ZSTD_EXPAND_AND_QUOTE`. Rust has no token-pasting
/// preprocessor, so it is spelled out — and `main.c` in
/// `port/test/zstd_entropy/` compares it against the C's, so the two cannot
/// drift silently.
const ZSTD_VERSION_STRING: &[u8] = b"1.5.7\0";

/// `ERROR(maxCode)` — `(size_t)-ZSTD_error_maxCode`, the isError threshold.
const ZSTD_ERROR_MAX_CODE: usize = 0usize.wrapping_sub(120);

extern "C" {
    /// `lib/zstd/common/error_private.c`, now
    /// `common/error_private_rs.rs`.
    fn ERR_getErrorString(code: i32) -> *const c_char;
}

/// `error_private.h:45`.
#[inline(always)]
fn ERR_isError(code: usize) -> c_uint {
    (code > ZSTD_ERROR_MAX_CODE) as c_uint
}

/// `error_private.h:47`.
#[inline(always)]
fn ERR_getErrorCode(code: usize) -> i32 {
    if ERR_isError(code) == 0 {
        return 0;
    }
    // The C writes `(ERR_enum)(0-code)` on a size_t and narrows to the enum.
    // Reproduced exactly, wrap and all.
    (0usize.wrapping_sub(code)) as u32 as i32
}

/// `ZSTD_versionNumber()` — dead in-tree, still part of the API contract.
#[no_mangle]
pub extern "C" fn ZSTD_versionNumber() -> c_uint {
    ZSTD_VERSION_NUMBER
}

/// `ZSTD_versionString()` — dead in-tree, still part of the API contract.
#[no_mangle]
pub extern "C" fn ZSTD_versionString() -> *const c_char {
    ZSTD_VERSION_STRING.as_ptr() as *const c_char
}

/// Body of the `ZSTD_isError` entry thunk in `zstd_common.c`.
#[no_mangle]
pub extern "C" fn ZSTD_isError(code: usize) -> c_uint {
    ERR_isError(code)
}

/// Body of the `ZSTD_getErrorName` entry thunk in `zstd_common.c`.
#[no_mangle]
pub extern "C" fn ZSTD_getErrorName(code: usize) -> *const c_char {
    // SAFETY: class B (boundary). `ERR_getErrorString` is a pure lookup over a
    // table of string literals with static lifetime; it takes no pointer,
    // reads no memory we own, and is total -- its match has a catch-all arm.
    // It is Rust (`common/error_private_rs.rs`), reached through `extern "C"`
    // only because the kernel builds one object per `.rs` file.
    unsafe { ERR_getErrorString(ERR_getErrorCode(code)) }
}

/// Body of the `ZSTD_getErrorCode` entry thunk in `zstd_common.c`.
#[no_mangle]
pub extern "C" fn ZSTD_getErrorCode(code: usize) -> i32 {
    ERR_getErrorCode(code)
}

/// `ZSTD_getErrorString()` — dead in-tree; takes the enum, not a return code.
#[no_mangle]
pub extern "C" fn ZSTD_getErrorString(code: i32) -> *const c_char {
    // SAFETY: class B (boundary), as in `ZSTD_getErrorName` above.
    unsafe { ERR_getErrorString(code) }
}
