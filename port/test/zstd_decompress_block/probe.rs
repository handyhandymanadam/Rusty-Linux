// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `zstd_decompress_block_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it. Presents the port's entry points under `rs_*` so both arms can live
//! in one binary. All of them keep their own names in the kernel: none is
//! `EXPORT_SYMBOL`'d, so none carries a MODVERSIONS CRC and there are no
//! thunks -- the `lib/union_find` shape, same as huf_decompress/
//! entropy_common.

#![allow(non_snake_case)]

use std::os::raw::{c_int, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zstd/decompress/zstd_decompress_block_rs.rs"]
mod zstd_decompress_block_rs;

use zstd_decompress_block_rs as p;

/// `ZSTD_decompressBlock_internal()`, as the kernel links it.
///
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompressBlock_internal(
    dctx: *mut p::ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
    streaming: c_int,
) -> usize {
    let streaming = if streaming != 0 {
        p::StreamingOperation::IsStreaming
    } else {
        p::StreamingOperation::NotStreaming
    };
    // SAFETY: the harness owns every buffer and passes the same ones to the
    // C arm; preconditions are identical for both.
    unsafe { p::ZSTD_decompressBlock_internal(dctx, dst, dstCapacity, src, srcSize, streaming) }
}

/// `ZSTD_checkContinuity()`, as the kernel links it.
///
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_checkContinuity(dctx: *mut p::ZstdDCtx, dst: *const c_void, dstSize: usize) {
    // SAFETY: as above.
    unsafe { p::ZSTD_checkContinuity(dctx, dst, dstSize) }
}

/// `ZSTD_decompressBlock_deprecated()`, as the kernel links it.
///
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompressBlock_deprecated(
    dctx: *mut p::ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    // SAFETY: as above.
    unsafe { p::ZSTD_decompressBlock_deprecated(dctx, dst, dstCapacity, src, srcSize) }
}

/// `ZSTD_getcBlockSize()`, as the kernel links it.
///
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getcBlockSize(
    src: *const c_void,
    srcSize: usize,
    bpPtr: *mut p::BlockProperties,
) -> usize {
    // SAFETY: as above.
    unsafe { p::ZSTD_getcBlockSize(src, srcSize, bpPtr) }
}
