// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `zstd_ddict_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than
//! copying it. Presents the port's entry points under `rs_*` so both arms
//! can live in one binary. None of them keep the `rs_` prefix in the
//! kernel: none is `EXPORT_SYMBOL`'d, so none carries a MODVERSIONS CRC and
//! there are no thunks -- the `lib/union_find` shape, same as
//! zstd_decompress_block/huf_decompress/entropy_common.

#![allow(non_snake_case)]

use std::os::raw::{c_uint, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zstd/decompress/zstd_ddict_rs.rs"]
mod zstd_ddict_rs;

use zstd_ddict_rs as p;

/// # Safety
/// Same contract as the C `ZSTD_DDict_dictContent`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_DDict_dictContent(ddict: *const p::ZstdDDict) -> *const c_void {
    unsafe { p::ZSTD_DDict_dictContent(ddict) }
}

/// # Safety
/// Same contract as the C `ZSTD_DDict_dictSize`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_DDict_dictSize(ddict: *const p::ZstdDDict) -> usize {
    unsafe { p::ZSTD_DDict_dictSize(ddict) }
}

/// # Safety
/// Same contract as the C `ZSTD_copyDDictParameters`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_copyDDictParameters(dctx: *mut p::ZstdDCtx, ddict: *const p::ZstdDDict) {
    unsafe { p::ZSTD_copyDDictParameters(dctx, ddict) }
}

/// # Safety
/// Same contract as the C `ZSTD_createDDict_advanced`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_createDDict_advanced(
    dict: *const c_void,
    dictSize: usize,
    dictLoadMethod: c_uint,
    dictContentType: c_uint,
    customAlloc: p::ZstdAllocFunction,
    customFree: p::ZstdFreeFunction,
    opaque: *mut c_void,
) -> *mut p::ZstdDDict {
    let customMem = p::ZstdCustomMem { customAlloc, customFree, opaque };
    unsafe { p::ZSTD_createDDict_advanced(dict, dictSize, dictLoadMethod, dictContentType, customMem) }
}

/// # Safety
/// Same contract as the C `ZSTD_initStaticDDict`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_initStaticDDict(
    sBuffer: *mut c_void,
    sBufferSize: usize,
    dict: *const c_void,
    dictSize: usize,
    dictLoadMethod: c_uint,
    dictContentType: c_uint,
) -> *const p::ZstdDDict {
    unsafe { p::ZSTD_initStaticDDict(sBuffer, sBufferSize, dict, dictSize, dictLoadMethod, dictContentType) }
}

/// # Safety
/// Same contract as the C `ZSTD_freeDDict`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_freeDDict(ddict: *mut p::ZstdDDict) -> usize {
    unsafe { p::ZSTD_freeDDict(ddict) }
}

/// `ZSTD_estimateDDictSize()`, as the kernel links it.
#[no_mangle]
pub extern "C" fn rs_ZSTD_estimateDDictSize(dictSize: usize, dictLoadMethod: c_uint) -> usize {
    p::ZSTD_estimateDDictSize(dictSize, dictLoadMethod)
}

/// # Safety
/// Same contract as the C `ZSTD_sizeof_DDict`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_sizeof_DDict(ddict: *const p::ZstdDDict) -> usize {
    unsafe { p::ZSTD_sizeof_DDict(ddict) }
}

/// # Safety
/// Same contract as the C `ZSTD_getDictID_fromDDict`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getDictID_fromDDict(ddict: *const p::ZstdDDict) -> c_uint {
    unsafe { p::ZSTD_getDictID_fromDDict(ddict) }
}
