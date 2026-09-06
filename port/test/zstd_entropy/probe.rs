// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `entropy_common_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it -- a stale copy tested here while the kernel builds something else is
//! the failure PRIOR-ART.md §2 records four times.
//!
//! It presents the port under `rs_*` so both arms can live in one binary. The
//! three names the kernel keeps as C thunks (`FSE_readNCount`,
//! `HUF_readStats`, `HUF_readStats_wksp`) are reached through the `rust_*`
//! symbols those thunks call, which is exactly the path the kernel takes.

#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zstd/common/entropy_common_rs.rs"]
mod entropy_common_rs;

/// The error-string table, also ported. Linking it here rather than the C is
/// what makes `entropy_common_rs`'s only remaining `extern "C"` call resolve
/// to Rust -- which is the whole point of having ported it -- and it puts
/// `ERR_getErrorString` under test instead of merely under compilation.
#[path = "../../tree/lib/zstd/common/error_private_rs.rs"]
mod error_private_rs;

/// `zstd_common.c`'s six entry points, also ported. Three of them are reached
/// in the kernel through C thunks (their symbols are `EXPORT_SYMBOL_GPL`'d);
/// the harness calls the `rust_*` bodies those thunks call.
#[path = "../../tree/lib/zstd/common/zstd_common_rs.rs"]
mod zstd_common_rs;

use entropy_common_rs as p;

/// `FSE_readNCount_bmi2` as the kernel links it: a direct Rust definition.
/// # Safety
/// Same contract as the C: all pointers valid for the sizes implied.
#[no_mangle]
pub unsafe extern "C" fn rs_FSE_readNCount_bmi2(
    nc: *mut i16, maxSV: *mut c_uint, tableLog: *mut c_uint,
    hb: *const c_void, hbSize: usize, bmi2: c_int,
) -> usize {
    // SAFETY: the harness owns every buffer and passes the same ones to the C
    // arm; preconditions are identical for both.
    unsafe { p::FSE_readNCount_bmi2(nc, maxSV, tableLog, hb, hbSize, bmi2) }
}

/// `FSE_readNCount` reached through the body its C entry thunk calls.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_FSE_readNCount(
    nc: *mut i16, maxSV: *mut c_uint, tableLog: *mut c_uint,
    hb: *const c_void, hbSize: usize,
) -> usize {
    // SAFETY: as above. This is the body the C entry thunk calls.
    unsafe { p::FSE_readNCount(nc, maxSV, tableLog, hb, hbSize) }
}

/// `HUF_readStats_wksp` reached through the body its C entry thunk calls.
/// # Safety
/// Same contract as the C.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rs_HUF_readStats_wksp(
    hw: *mut u8, hwSize: usize, rank: *mut u32, nbSym: *mut u32,
    tableLog: *mut u32, src: *const c_void, srcSize: usize,
    wksp: *mut c_void, wkspSize: usize, flags: c_int,
) -> usize {
    // SAFETY: as above.
    unsafe {
        p::HUF_readStats_wksp(hw, hwSize, rank, nbSym, tableLog,
                                   src, srcSize, wksp, wkspSize, flags)
    }
}

/// `HUF_readStats` reached through the body its C entry thunk calls.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_HUF_readStats(
    hw: *mut u8, hwSize: usize, rank: *mut u32, nbSym: *mut u32,
    tableLog: *mut u32, src: *const c_void, srcSize: usize,
) -> usize {
    // SAFETY: as above.
    unsafe { p::rust_HUF_readStats(hw, hwSize, rank, nbSym, tableLog, src, srcSize) }
}

/// `FSE_buildDTable_wksp`, dead in-tree but still part of the ABI.
/// # Safety
/// Same contract as the C, which additionally requires `normalizedCounter`
/// to be a valid normalised distribution -- see main.c, and STATUS.md.
#[no_mangle]
pub unsafe extern "C" fn rs_FSE_buildDTable_wksp(
    dt: *mut u32, nc: *const i16, maxSV: c_uint, tableLog: c_uint,
    wksp: *mut c_void, wkspSize: usize,
) -> usize {
    // SAFETY: as above.
    unsafe { p::FSE_buildDTable_wksp(dt, nc, maxSV, tableLog, wksp, wkspSize) }
}

/// `FSE_decompress_wksp_bmi2` as the kernel links it.
/// # Safety
/// Same contract as the C.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rs_FSE_decompress_wksp_bmi2(
    dst: *mut c_void, dstCap: usize, cSrc: *const c_void, cSrcSize: usize,
    maxLog: c_uint, wksp: *mut c_void, wkspSize: usize, bmi2: c_int,
) -> usize {
    // SAFETY: as above.
    unsafe {
        p::FSE_decompress_wksp_bmi2(dst, dstCap, cSrc, cSrcSize, maxLog,
                                    wksp, wkspSize, bmi2)
    }
}

/* The five wrappers that are dead in-tree but still have to be right. */

/// `FSE_versionNumber`: dead in-tree, still has to be right.
#[no_mangle]
pub extern "C" fn rs_FSE_versionNumber() -> c_uint { p::FSE_versionNumber() }
/// `FSE_isError`: dead in-tree, still has to be right.
#[no_mangle]
pub extern "C" fn rs_FSE_isError(code: usize) -> c_uint { p::FSE_isError(code) }
/// `FSE_getErrorName`: dead in-tree, still has to be right.
#[no_mangle]
pub extern "C" fn rs_FSE_getErrorName(code: usize) -> *const c_char { p::FSE_getErrorName(code) }
/// `HUF_isError`: dead in-tree, still has to be right.
#[no_mangle]
pub extern "C" fn rs_HUF_isError(code: usize) -> c_uint { p::HUF_isError(code) }
/// `HUF_getErrorName`: dead in-tree, still has to be right.
#[no_mangle]
pub extern "C" fn rs_HUF_getErrorName(code: usize) -> *const c_char { p::HUF_getErrorName(code) }

/* The error-string table. Its one function is pure and total over i32, so the
   harness sweeps it rather than sampling. */

/// `ERR_getErrorString` as the kernel links it: the Rust definition.
#[no_mangle]
pub extern "C" fn rs_ERR_getErrorString(code: c_int) -> *const c_char {
    error_private_rs::ERR_getErrorString(code)
}

/* zstd_common.c's six. */

/// `ZSTD_versionNumber`: dead in-tree, still part of the API contract.
#[no_mangle]
pub extern "C" fn rs_ZSTD_versionNumber() -> c_uint { zstd_common_rs::ZSTD_versionNumber() }
/// `ZSTD_versionString`: dead in-tree, still part of the API contract.
#[no_mangle]
pub extern "C" fn rs_ZSTD_versionString() -> *const c_char { zstd_common_rs::ZSTD_versionString() }
/// `ZSTD_isError`, through the body its C entry thunk calls.
#[no_mangle]
pub extern "C" fn rs_ZSTD_isError(code: usize) -> c_uint { zstd_common_rs::ZSTD_isError(code) }
/// `ZSTD_getErrorName`, through the body its C entry thunk calls.
#[no_mangle]
pub extern "C" fn rs_ZSTD_getErrorName(code: usize) -> *const c_char {
    zstd_common_rs::ZSTD_getErrorName(code)
}
/// `ZSTD_getErrorCode`, through the body its C entry thunk calls.
#[no_mangle]
pub extern "C" fn rs_ZSTD_getErrorCode(code: usize) -> c_int {
    zstd_common_rs::ZSTD_getErrorCode(code)
}
/// `ZSTD_getErrorString`: dead in-tree, still part of the API contract.
#[no_mangle]
pub extern "C" fn rs_ZSTD_getErrorString(code: c_int) -> *const c_char {
    zstd_common_rs::ZSTD_getErrorString(code)
}
