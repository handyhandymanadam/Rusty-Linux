// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause

//! The single list of zstd error strings.
//!
//! Ported from `lib/zstd/common/error_private.c` (6.18.49), which carries
//! `Copyright (c) Meta Platforms, Inc. and affiliates.` and is
//! `GPL-2.0+ OR BSD-3-Clause`. The C file's own comment states its whole
//! purpose: *to have a single list of error strings embedded in binary*.
//!
//! # Shape: no thunk
//!
//! `ERR_getErrorString` is the only symbol the C file defines and it is **not**
//! `EXPORT_SYMBOL`'d — `lib/zstd/zstd_common_module.c` exports `ZSTD_isError`,
//! `ZSTD_getErrorName` and `ZSTD_getErrorCode`, all defined in
//! `zstd_common.c`, and none of them is this. So it carries no MODVERSIONS CRC,
//! GOALS.md §1's entry-thunk constraint does not reach it, and Rust defines it
//! directly under its own name. That is the `lib/union_find` shape, and the C
//! file drops out of the Makefile entirely.
//!
//! # Why this file was worth 40 lines
//!
//! It was the **last C symbol `entropy_common_rs.rs` called**. With it ported,
//! nothing in `lib/zstd/common/entropy_common_rs.rs` crosses into C at all:
//! that pair's only remaining `extern "C"` call is now into this Rust. The
//! other caller, `zstd_common.c`, is still C and now calls in the other
//! direction — a crossing that retires when `zstd_common.c` is ported, which
//! cannot happen while its three symbols are exported.
//!
//! # `ZSTD_STRIP_ERROR_STRINGS`
//!
//! The C wraps the whole table in `#ifdef ZSTD_STRIP_ERROR_STRINGS` and returns
//! a fixed string instead. Nothing in the kernel defines that macro — it is not
//! a Kconfig symbol and `grep -r ZSTD_STRIP_ERROR_STRINGS` over 6.18.49 finds
//! only the one `#ifdef` in the C file itself — so the arm is dead in-tree.
//! It is reproduced anyway, behind `#[cfg(zstd_strip_error_strings)]`, so that
//! a future build defining it gets the same behaviour rather than a surprise.
//!
//! # Trusted surface
//!
//! **Zero `unsafe` blocks.** Every string is a `&'static [u8]` with an explicit
//! trailing NUL and the function hands back `.as_ptr()`, which is a safe
//! operation; the C contract that the caller must not free or write the result
//! is upheld by the pointer being into `.rodata` exactly as in C.
//!
//! Replaces: lib/zstd/common/error_private.c

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::c_char;

/// `ZSTD_ErrorCode`, from `include/linux/zstd_errors.h`. The values are the
/// enumerators' own, not their ordinal positions -- zstd assigns them
/// explicitly and leaves gaps, and the gaps are part of the ABI.
mod code {
    pub(crate) const no_error: i32 = 0;
    pub(crate) const GENERIC: i32 = 1;
    pub(crate) const prefix_unknown: i32 = 10;
    pub(crate) const version_unsupported: i32 = 12;
    pub(crate) const frameParameter_unsupported: i32 = 14;
    pub(crate) const frameParameter_windowTooLarge: i32 = 16;
    pub(crate) const corruption_detected: i32 = 20;
    pub(crate) const checksum_wrong: i32 = 22;
    pub(crate) const literals_headerWrong: i32 = 24;
    pub(crate) const dictionary_corrupted: i32 = 30;
    pub(crate) const dictionary_wrong: i32 = 32;
    pub(crate) const dictionaryCreation_failed: i32 = 34;
    pub(crate) const parameter_unsupported: i32 = 40;
    pub(crate) const parameter_combination_unsupported: i32 = 41;
    pub(crate) const parameter_outOfBound: i32 = 42;
    pub(crate) const tableLog_tooLarge: i32 = 44;
    pub(crate) const maxSymbolValue_tooLarge: i32 = 46;
    pub(crate) const maxSymbolValue_tooSmall: i32 = 48;
    pub(crate) const cannotProduce_uncompressedBlock: i32 = 49;
    pub(crate) const stabilityCondition_notRespected: i32 = 50;
    pub(crate) const stage_wrong: i32 = 60;
    pub(crate) const init_missing: i32 = 62;
    pub(crate) const memory_allocation: i32 = 64;
    pub(crate) const workSpace_tooSmall: i32 = 66;
    pub(crate) const dstSize_tooSmall: i32 = 70;
    pub(crate) const srcSize_wrong: i32 = 72;
    pub(crate) const dstBuffer_null: i32 = 74;
    pub(crate) const noForwardProgress_destFull: i32 = 80;
    pub(crate) const noForwardProgress_inputEmpty: i32 = 82;
    pub(crate) const frameIndex_tooLarge: i32 = 100;
    pub(crate) const seekableIO: i32 = 102;
    pub(crate) const dstBuffer_wrong: i32 = 104;
    pub(crate) const srcBuffer_wrong: i32 = 105;
    pub(crate) const sequenceProducer_failed: i32 = 106;
    pub(crate) const externalSequences_invalid: i32 = 107;
    pub(crate) const maxCode: i32 = 120;
}

/// The `default:` and `case PREFIX(maxCode):` arm. One constant, as in the C,
/// where it is a `static const char *const` rather than a repeated literal.
const NOT_ERROR_CODE: &[u8] = b"Unspecified error code\0";

#[cfg(zstd_strip_error_strings)]
const STRIPPED: &[u8] = b"Error strings stripped\0";

/// `ERR_getErrorString()` — the message for one `ZSTD_ErrorCode`.
///
/// The returned pointer is into `.rodata` and outlives every caller, which is
/// the same contract the C offers. Callers must not free or write through it.
#[no_mangle]
pub extern "C" fn ERR_getErrorString(code: i32) -> *const c_char {
    #[cfg(zstd_strip_error_strings)]
    {
        let _ = code;
        return STRIPPED.as_ptr() as *const c_char;
    }

    #[cfg(not(zstd_strip_error_strings))]
    {
        let s: &[u8] = match code {
            code::no_error => b"No error detected\0",
            code::GENERIC => b"Error (generic)\0",
            code::prefix_unknown => b"Unknown frame descriptor\0",
            code::version_unsupported => b"Version not supported\0",
            code::frameParameter_unsupported => b"Unsupported frame parameter\0",
            code::frameParameter_windowTooLarge =>
                b"Frame requires too much memory for decoding\0",
            code::corruption_detected => b"Data corruption detected\0",
            code::checksum_wrong => b"Restored data doesn't match checksum\0",
            code::literals_headerWrong =>
                b"Header of Literals' block doesn't respect format specification\0",
            code::parameter_unsupported => b"Unsupported parameter\0",
            code::parameter_combination_unsupported =>
                b"Unsupported combination of parameters\0",
            code::parameter_outOfBound => b"Parameter is out of bound\0",
            code::init_missing => b"Context should be init first\0",
            code::memory_allocation => b"Allocation error : not enough memory\0",
            code::workSpace_tooSmall => b"workSpace buffer is not large enough\0",
            code::stage_wrong =>
                b"Operation not authorized at current processing stage\0",
            code::tableLog_tooLarge =>
                b"tableLog requires too much memory : unsupported\0",
            code::maxSymbolValue_tooLarge =>
                b"Unsupported max Symbol Value : too large\0",
            code::maxSymbolValue_tooSmall =>
                b"Specified maxSymbolValue is too small\0",
            code::cannotProduce_uncompressedBlock =>
                b"This mode cannot generate an uncompressed block\0",
            code::stabilityCondition_notRespected =>
                b"pledged buffer stability condition is not respected\0",
            code::dictionary_corrupted => b"Dictionary is corrupted\0",
            code::dictionary_wrong => b"Dictionary mismatch\0",
            code::dictionaryCreation_failed =>
                b"Cannot create Dictionary from provided samples\0",
            code::dstSize_tooSmall => b"Destination buffer is too small\0",
            code::srcSize_wrong => b"Src size is incorrect\0",
            code::dstBuffer_null => b"Operation on NULL destination buffer\0",
            code::noForwardProgress_destFull =>
                b"Operation made no progress over multiple calls, due to output buffer being full\0",
            code::noForwardProgress_inputEmpty =>
                b"Operation made no progress over multiple calls, due to input being empty\0",
            // following error codes are not stable and may be removed or
            // changed in a future version
            code::frameIndex_tooLarge => b"Frame index is too large\0",
            code::seekableIO => b"An I/O error occurred when reading/seeking\0",
            code::dstBuffer_wrong => b"Destination buffer is wrong\0",
            code::srcBuffer_wrong => b"Source buffer is wrong\0",
            code::sequenceProducer_failed =>
                b"Block-level external sequence producer returned an error code\0",
            code::externalSequences_invalid => b"External sequences are not valid\0",
            code::maxCode => NOT_ERROR_CODE,
            _ => NOT_ERROR_CODE,
        };
        s.as_ptr() as *const c_char
    }
}
