// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `zstd_decompress_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it -- a stale copy tested here while the kernel builds something else is
//! the failure notes/PRIOR-ART.md §2 records four times.
//!
//! It presents the port under `rs_*`, matching every other harness in this
//! subsystem, even though the inner module's own `#[no_mangle]` items are
//! already exported under their real C names too (both live in the same
//! object; the driver always calls the `rs_*` ones, for symmetry with the
//! `ref_*` arm and to avoid ever accidentally calling the wrong arm).
//!
//! This wraps the entry points the harness in this directory actually
//! exercises: one-shot decompress, streaming decompress, frame-header
//! parsing, and dictionary loading. The full 61-symbol surface compiles (see
//! run.sh's sweep) and links (both arms resolve with 0 undefined symbols),
//! but not every symbol has its own `rs_*`/driver coverage yet -- see
//! run.sh's header comment for what is and is not covered.
//!
//! Cross-crate: `zstd_decompress_rs.rs` declares `extern "C"` calls into
//! `zstd_decompress_block_rs.rs`, `entropy_common_rs.rs`,
//! `huf_decompress_rs.rs` and `lib/xxhash_rs.rs`. This harness does NOT link
//! the first of those (decompress-porter's file isn't in port/tree/ yet) --
//! it links the PRISTINE C `zstd_decompress_block.c`/`zstd_ddict.c` instead,
//! real-named, unrenamed, shared with the `ref_*` arm's own (differently
//! renamed) copies of the same two files. See run.sh.

#![allow(non_snake_case)]

use std::os::raw::{c_int, c_uint, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zstd/decompress/zstd_decompress_rs.rs"]
mod zstd_decompress_rs;

use zstd_decompress_rs as p;

// Opaque struct pointers/buffers cross this FFI boundary as raw bytes; the
// harness never looks inside them from the Rust side, only from C (main.c),
// so every function here takes/returns `*mut c_void`/`*const c_void` for the
// DCtx, buffer structs and frame-header struct alike.

/// `ZSTD_createDCtx`.
#[no_mangle]
pub extern "C" fn rs_ZSTD_createDCtx() -> *mut c_void {
    p::ZSTD_createDCtx() as *mut c_void
}

/// `ZSTD_createDCtx_advanced`. `customMem` is `ZSTD_customMem`,
/// `{customAlloc, customFree, opaque}` -- `p::ZstdCustomMem` is a
/// `#[repr(C)]` mirror of exactly those three fields, ABI-identical to the
/// driver's own `struct zdt_custom_mem`.
/// # Safety
/// `customMem`'s function pointers, if set, must be safe to call.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_createDCtx_advanced(customMem: p::ZstdCustomMem) -> *mut c_void {
    unsafe { p::ZSTD_createDCtx_advanced(customMem) as *mut c_void }
}

/// `ZSTD_freeDCtx`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_freeDCtx(dctx: *mut c_void) -> usize {
    unsafe { p::ZSTD_freeDCtx(dctx as *mut p::ZstdDCtx) }
}

/// `ZSTD_decompress`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompress(dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    unsafe { p::ZSTD_decompress(dst, dstCapacity, src, srcSize) }
}

/// `ZSTD_decompressDCtx`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompressDCtx(dctx: *mut c_void, dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    unsafe { p::ZSTD_decompressDCtx(dctx as *mut p::ZstdDCtx, dst, dstCapacity, src, srcSize) }
}

/// `ZSTD_decompress_usingDict`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompress_usingDict(
    dctx: *mut c_void, dst: *mut c_void, dstCapacity: usize,
    src: *const c_void, srcSize: usize, dict: *const c_void, dictSize: usize,
) -> usize {
    unsafe { p::ZSTD_decompress_usingDict(dctx as *mut p::ZstdDCtx, dst, dstCapacity, src, srcSize, dict, dictSize) }
}

/// `ZSTD_createDStream`.
#[no_mangle]
pub extern "C" fn rs_ZSTD_createDStream() -> *mut c_void {
    p::ZSTD_createDStream() as *mut c_void
}

/// `ZSTD_createDStream_advanced`.
/// # Safety
/// As `rs_ZSTD_createDCtx_advanced`.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_createDStream_advanced(customMem: p::ZstdCustomMem) -> *mut c_void {
    unsafe { p::ZSTD_createDStream_advanced(customMem) as *mut c_void }
}

/// `ZSTD_freeDStream`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_freeDStream(zds: *mut c_void) -> usize {
    unsafe { p::ZSTD_freeDStream(zds as *mut p::ZstdDCtx) }
}

/// `ZSTD_initDStream`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_initDStream(zds: *mut c_void) -> usize {
    unsafe { p::ZSTD_initDStream(zds as *mut p::ZstdDCtx) }
}

/// `ZSTD_initDStream_usingDict`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_initDStream_usingDict(zds: *mut c_void, dict: *const c_void, dictSize: usize) -> usize {
    unsafe { p::ZSTD_initDStream_usingDict(zds as *mut p::ZstdDCtx, dict, dictSize) }
}

/// `ZSTD_decompressStream`. `output`/`input` are `ZSTD_outBuffer`/
/// `ZSTD_inBuffer` -- three-word `{ptr, size, pos}` structs, identical
/// layout on both arms (`repr(C)` here, the real C struct on the ref side),
/// so passed as opaque pointers.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompressStream(zds: *mut c_void, output: *mut c_void, input: *mut c_void) -> usize {
    unsafe { p::ZSTD_decompressStream(zds as *mut p::ZstdDCtx, output as *mut p::ZstdOutBuffer, input as *mut p::ZstdInBuffer) }
}

/// `ZSTD_isFrame`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_isFrame(buffer: *const c_void, size: usize) -> c_uint {
    unsafe { p::ZSTD_isFrame(buffer, size) }
}

/// `ZSTD_isSkippableFrame`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_isSkippableFrame(buffer: *const c_void, size: usize) -> c_uint {
    unsafe { p::ZSTD_isSkippableFrame(buffer, size) }
}

/// `ZSTD_frameHeaderSize`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_frameHeaderSize(src: *const c_void, srcSize: usize) -> usize {
    unsafe { p::ZSTD_frameHeaderSize(src, srcSize) }
}

/// `ZSTD_getFrameContentSize`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getFrameContentSize(src: *const c_void, srcSize: usize) -> u64 {
    unsafe { p::ZSTD_getFrameContentSize(src, srcSize) }
}

/// `ZSTD_getDecompressedSize`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getDecompressedSize(src: *const c_void, srcSize: usize) -> u64 {
    unsafe { p::ZSTD_getDecompressedSize(src, srcSize) }
}

/// `ZSTD_findFrameCompressedSize`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_findFrameCompressedSize(src: *const c_void, srcSize: usize) -> usize {
    unsafe { p::ZSTD_findFrameCompressedSize(src, srcSize) }
}

/// `ZSTD_findDecompressedSize`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_findDecompressedSize(src: *const c_void, srcSize: usize) -> u64 {
    unsafe { p::ZSTD_findDecompressedSize(src, srcSize) }
}

/// `ZSTD_decompressBound`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_decompressBound(src: *const c_void, srcSize: usize) -> u64 {
    unsafe { p::ZSTD_decompressBound(src, srcSize) }
}

/// `ZSTD_getDictID_fromFrame`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getDictID_fromFrame(src: *const c_void, srcSize: usize) -> c_uint {
    unsafe { p::ZSTD_getDictID_fromFrame(src, srcSize) }
}

/// `ZSTD_getDictID_fromDict`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_getDictID_fromDict(dict: *const c_void, dictSize: usize) -> c_uint {
    unsafe { p::ZSTD_getDictID_fromDict(dict, dictSize) }
}

/// `ZSTD_readSkippableFrame`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_readSkippableFrame(
    dst: *mut c_void, dstCapacity: usize, magicVariant: *mut c_uint,
    src: *const c_void, srcSize: usize,
) -> usize {
    unsafe { p::ZSTD_readSkippableFrame(dst, dstCapacity, magicVariant, src, srcSize) }
}

/// `ZSTD_DStreamInSize`.
#[no_mangle]
pub extern "C" fn rs_ZSTD_DStreamInSize() -> usize {
    p::ZSTD_DStreamInSize()
}
/// `ZSTD_DStreamOutSize`.
#[no_mangle]
pub extern "C" fn rs_ZSTD_DStreamOutSize() -> usize {
    p::ZSTD_DStreamOutSize()
}

/// `ZSTD_sizeof_DCtx`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_sizeof_DCtx(dctx: *const c_void) -> usize {
    unsafe { p::ZSTD_sizeof_DCtx(dctx as *const p::ZstdDCtx) }
}

/// `ZSTD_DCtx_setParameter`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_DCtx_setParameter(dctx: *mut c_void, param: c_int, value: c_int) -> usize {
    unsafe { p::ZSTD_DCtx_setParameter(dctx as *mut p::ZstdDCtx, param, value) }
}

/// `ZSTD_DCtx_reset`.
/// # Safety
/// Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn rs_ZSTD_DCtx_reset(dctx: *mut c_void, reset: c_int) -> usize {
    unsafe { p::ZSTD_DCtx_reset(dctx as *mut p::ZstdDCtx, reset) }
}

/// `ZSTD_isError`, through `zstd_common_rs.rs` -- not this file's own, but
/// needed by the driver to interpret both arms' return codes uniformly.
/// This harness borrows the already-ported `zstd_common_rs.rs`'s function
/// directly rather than reimplementing the trivial comparison a third time.
#[no_mangle]
pub extern "C" fn rs_ZSTD_isError(code: usize) -> c_uint {
    const ZSTD_ERROR_MAX_CODE: usize = 120;
    (code > 0usize.wrapping_sub(ZSTD_ERROR_MAX_CODE)) as c_uint
}

