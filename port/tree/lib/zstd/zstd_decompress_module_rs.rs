// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the file it is ported from)

//! The kernel-facing `zstd_*` decompression API: seventeen thin wrappers
//! over the `ZSTD_*` entry points every other file in this subsystem
//! already ported.
//!
//! Ported from `lib/zstd/zstd_decompress_module.c` (6.18.49),
//! `Copyright (c) Meta Platforms, Inc. and affiliates.`, dual
//! GPL-2.0+/BSD-3-Clause.
//!
//! # Shape: thunk-required, and why
//!
//! Every one of the 17 functions here is `EXPORT_SYMBOL`'d and used by
//! external callers (btrfs, squashfs, f2fs, ...) under this file's own
//! `zstd_*` snake_case names -- not the `ZSTD_*` names the functions they
//! call already carry. Deleting the C loses those 17 definitions' DWARF, so
//! their MODVERSIONS CRCs are pinned below with `kernel::kabi_rule!`,
//! captured via `rig/kabi-pin.sh --capture` against the pristine C object
//! (`build-full/lib/zstd/zstd_decompress_module.o`) before this file
//! replaced it -- the `_bcd2bin` shape (`rig/kabi-pin.sh`'s own header).
//!
//! The `ZSTD_*` functions this file calls carry no MODVERSIONS CRC of their
//! own here (no in-tree caller outside this file takes their address
//! directly through a name that must stay stable) except
//! `ZSTD_isError`/`ZSTD_getErrorCode`/`ZSTD_getErrorName`, which
//! `common/zstd_common_rs.rs` already exports under their own real names --
//! called here the same way every other cross-file call in this subsystem
//! is made, `extern "C"` with opaque `*mut c_void` for anything whose
//! layout this file has no business knowing.
//!
//! `zstd_custom_mem` is the one non-opaque type crossing this boundary: the
//! kernel's public `<linux/zstd.h>` `typedef`s it directly from
//! `ZSTD_customMem` (`struct { customAlloc; customFree; opaque; }`, three
//! pointers, passed **by value**), so its layout has to be known here too --
//! this file's own copy, field-identical to
//! `decompress/zstd_decompress_rs.rs`'s, by the same "one crate per file,
//! nothing to share it with" convention that file's own comments describe.
//!
//! `zstd_dctx`/`zstd_ddict`/`zstd_dstream`/`zstd_in_buffer`/
//! `zstd_out_buffer`/`zstd_frame_header` are plain C `typedef` aliases of
//! `ZSTD_DCtx`/`ZSTD_DDict`/`ZSTD_DStream`/`ZSTD_inBuffer`/`ZSTD_outBuffer`/
//! `ZSTD_FrameHeader` (`include/linux/zstd.h`) -- zero ABI difference from
//! the internal names, so every pointer to one of them crosses as opaque
//! `*mut`/`*const c_void`, forwarded without being read.
//!
//! `zstd_init_dctx`/`zstd_init_dstream` keep the pristine C's NULL-workspace
//! guard even though the callee also checks -- faithful translation, not a
//! smarter one. `zstd_init_dstream` also keeps discarding `max_window_size`
//! unread, matching the C's own `(void)max_window_size;`.
//!
//! Replaces: lib/zstd/zstd_decompress_module.c

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_uint, c_void};

kernel::kabi_modinfo! {
    "zstd_decompress",
    file = "lib/zstd/zstd_decompress",
    description = "Zstd Decompressor",
    license = "Dual BSD/GPL",
}

/// `ZSTD_customMem`, `zstd_lib.h:1837` -- `{ customAlloc; customFree; opaque; }`.
/// Passed **by value**, so this file needs its own layout-identical copy;
/// see `decompress/zstd_decompress_rs.rs`'s own copy of the same struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZstdCustomMem {
    customAlloc: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    customFree: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    opaque: *mut c_void,
}

/// `ZSTD_dlm_byRef`, `zstd_lib.h:1348`.
const ZSTD_DLM_BY_REF: c_uint = 1;
/// `ZSTD_dct_auto`, `zstd_lib.h:1341`.
const ZSTD_DCT_AUTO: c_uint = 0;
/// `ZSTD_reset_session_only`, `zstd_lib.h:569`.
const ZSTD_RESET_SESSION_ONLY: c_int = 1;

extern "C" {
    /// `common/zstd_common_rs.rs` -- already `EXPORT_SYMBOL_GPL`'d there
    /// under its own name.
    fn ZSTD_isError(code: usize) -> c_uint;
    /// `common/zstd_common_rs.rs`.
    fn ZSTD_getErrorCode(code: usize) -> i32;
    /// `common/zstd_common_rs.rs`.
    fn ZSTD_getErrorName(code: usize) -> *const c_char;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_estimateDCtxSize() -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_createDCtx_advanced(customMem: ZstdCustomMem) -> *mut c_void;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_freeDCtx(dctx: *mut c_void) -> usize;
    /// `decompress/zstd_ddict_rs.rs`.
    fn ZSTD_createDDict_advanced(
        dict: *const c_void,
        dictSize: usize,
        dictLoadMethod: c_uint,
        dictContentType: c_uint,
        customMem: ZstdCustomMem,
    ) -> *mut c_void;
    /// `decompress/zstd_ddict_rs.rs`.
    fn ZSTD_freeDDict(ddict: *mut c_void) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_initStaticDCtx(workspace: *mut c_void, workspaceSize: usize) -> *mut c_void;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_decompressDCtx(
        dctx: *mut c_void,
        dst: *mut c_void,
        dstCapacity: usize,
        src: *const c_void,
        srcSize: usize,
    ) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_decompress_usingDDict(
        dctx: *mut c_void,
        dst: *mut c_void,
        dstCapacity: usize,
        src: *const c_void,
        srcSize: usize,
        ddict: *const c_void,
    ) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_estimateDStreamSize(windowSize: usize) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_initStaticDStream(workspace: *mut c_void, workspaceSize: usize) -> *mut c_void;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_DCtx_reset(dctx: *mut c_void, reset: c_int) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_decompressStream(
        zds: *mut c_void,
        output: *mut c_void,
        input: *mut c_void,
    ) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_findFrameCompressedSize(src: *const c_void, srcSize: usize) -> usize;
    /// `decompress/zstd_decompress_rs.rs`.
    fn ZSTD_getFrameHeader(zfhPtr: *mut c_void, src: *const c_void, srcSize: usize) -> usize;
}

// Captured via `rig/kabi-pin.sh --capture` against the still-C
// lib/zstd/zstd_decompress_module.o, build-full, 2026-09-06.
kernel::kabi_rule!("type_string", "s#ZSTD_DCtx_s",
    "structure_type ZSTD_DCtx_s { }");
kernel::kabi_rule!("type_string", "s#ZSTD_DDict_s",
    "structure_type ZSTD_DDict_s { }");
kernel::kabi_rule!("type_string", "s#ZSTD_inBuffer_s",
    "structure_type ZSTD_inBuffer_s { member pointer_type { const_type { base_type void } } src data_member_location(0) , member t#size_t size data_member_location(8) , member t#size_t pos data_member_location(16) } byte_size(24)");
kernel::kabi_rule!("type_string", "s#ZSTD_outBuffer_s",
    "structure_type ZSTD_outBuffer_s { member pointer_type { base_type void } dst data_member_location(0) , member t#size_t size data_member_location(8) , member t#size_t pos data_member_location(16) } byte_size(24)");
kernel::kabi_rule!("type_string", "t#ZSTD_DCtx",
    "typedef_type ZSTD_DCtx { s#ZSTD_DCtx_s }");
kernel::kabi_rule!("type_string", "t#ZSTD_DDict",
    "typedef_type ZSTD_DDict { s#ZSTD_DDict_s }");
kernel::kabi_rule!("type_string", "t#ZSTD_DStream",
    "typedef_type ZSTD_DStream { t#ZSTD_DCtx }");
kernel::kabi_rule!("type_string", "t#ZSTD_ErrorCode",
    "typedef_type ZSTD_ErrorCode { enumeration_type { enumerator ZSTD_error_no_error = 0 , enumerator ZSTD_error_GENERIC = 1 , enumerator ZSTD_error_prefix_unknown = 10 , enumerator ZSTD_error_version_unsupported = 12 , enumerator ZSTD_error_frameParameter_unsupported = 14 , enumerator ZSTD_error_frameParameter_windowTooLarge = 16 , enumerator ZSTD_error_corruption_detected = 20 , enumerator ZSTD_error_checksum_wrong = 22 , enumerator ZSTD_error_literals_headerWrong = 24 , enumerator ZSTD_error_dictionary_corrupted = 30 , enumerator ZSTD_error_dictionary_wrong = 32 , enumerator ZSTD_error_dictionaryCreation_failed = 34 , enumerator ZSTD_error_parameter_unsupported = 40 , enumerator ZSTD_error_parameter_combination_unsupported = 41 , enumerator ZSTD_error_parameter_outOfBound = 42 , enumerator ZSTD_error_tableLog_tooLarge = 44 , enumerator ZSTD_error_maxSymbolValue_tooLarge = 46 , enumerator ZSTD_error_maxSymbolValue_tooSmall = 48 , enumerator ZSTD_error_cannotProduce_uncompressedBlock = 49 , enumerator ZSTD_error_stabilityCondition_notRespected = 50 , enumerator ZSTD_error_stage_wrong = 60 , enumerator ZSTD_error_init_missing = 62 , enumerator ZSTD_error_memory_allocation = 64 , enumerator ZSTD_error_workSpace_tooSmall = 66 , enumerator ZSTD_error_dstSize_tooSmall = 70 , enumerator ZSTD_error_srcSize_wrong = 72 , enumerator ZSTD_error_dstBuffer_null = 74 , enumerator ZSTD_error_noForwardProgress_destFull = 80 , enumerator ZSTD_error_noForwardProgress_inputEmpty = 82 , enumerator ZSTD_error_frameIndex_tooLarge = 100 , enumerator ZSTD_error_seekableIO = 102 , enumerator ZSTD_error_dstBuffer_wrong = 104 , enumerator ZSTD_error_srcBuffer_wrong = 105 , enumerator ZSTD_error_sequenceProducer_failed = 106 , enumerator ZSTD_error_externalSequences_invalid = 107 , enumerator ZSTD_error_maxCode = 120 } byte_size(4) }");
kernel::kabi_rule!("type_string", "t#ZSTD_FrameHeader",
    "typedef_type ZSTD_FrameHeader { structure_type { member base_type unsigned long long byte_size(8) encoding(7) frameContentSize data_member_location(0) , member base_type unsigned long long byte_size(8) encoding(7) windowSize data_member_location(8) , member base_type unsigned int byte_size(4) encoding(7) blockSizeMax data_member_location(16) , member t#ZSTD_FrameType_e frameType data_member_location(20) , member base_type unsigned int byte_size(4) encoding(7) headerSize data_member_location(24) , member base_type unsigned int byte_size(4) encoding(7) dictID data_member_location(28) , member base_type unsigned int byte_size(4) encoding(7) checksumFlag data_member_location(32) , member base_type unsigned int byte_size(4) encoding(7) _reserved1 data_member_location(36) , member base_type unsigned int byte_size(4) encoding(7) _reserved2 data_member_location(40) } byte_size(48) }");
kernel::kabi_rule!("type_string", "t#ZSTD_FrameType_e",
    "typedef_type ZSTD_FrameType_e { enumeration_type { enumerator ZSTD_frame = 0 , enumerator ZSTD_skippableFrame = 1 } byte_size(4) }");
kernel::kabi_rule!("type_string", "t#ZSTD_allocFunction",
    "typedef_type ZSTD_allocFunction { pointer_type { subroutine_type ( formal_parameter pointer_type { base_type void } , formal_parameter t#size_t ) -> pointer_type { base_type void } } }");
kernel::kabi_rule!("type_string", "t#ZSTD_customMem",
    "typedef_type ZSTD_customMem { structure_type { member t#ZSTD_allocFunction customAlloc data_member_location(0) , member t#ZSTD_freeFunction customFree data_member_location(8) , member pointer_type { base_type void } opaque data_member_location(16) } byte_size(24) }");
kernel::kabi_rule!("type_string", "t#ZSTD_freeFunction",
    "typedef_type ZSTD_freeFunction { pointer_type { subroutine_type ( formal_parameter pointer_type { base_type void } , formal_parameter pointer_type { base_type void } ) -> base_type void } }");
kernel::kabi_rule!("type_string", "t#ZSTD_inBuffer",
    "typedef_type ZSTD_inBuffer { s#ZSTD_inBuffer_s }");
kernel::kabi_rule!("type_string", "t#ZSTD_outBuffer",
    "typedef_type ZSTD_outBuffer { s#ZSTD_outBuffer_s }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#zstd_custom_mem",
    "typedef_type zstd_custom_mem { t#ZSTD_customMem }");
kernel::kabi_rule!("type_string", "t#zstd_dctx",
    "typedef_type zstd_dctx { t#ZSTD_DCtx }");
kernel::kabi_rule!("type_string", "t#zstd_ddict",
    "typedef_type zstd_ddict { t#ZSTD_DDict }");
kernel::kabi_rule!("type_string", "t#zstd_dstream",
    "typedef_type zstd_dstream { t#ZSTD_DStream }");
kernel::kabi_rule!("type_string", "t#zstd_error_code",
    "typedef_type zstd_error_code { t#ZSTD_ErrorCode }");
kernel::kabi_rule!("type_string", "t#zstd_frame_header",
    "typedef_type zstd_frame_header { t#ZSTD_FrameHeader }");
kernel::kabi_rule!("type_string", "t#zstd_in_buffer",
    "typedef_type zstd_in_buffer { t#ZSTD_inBuffer }");
kernel::kabi_rule!("type_string", "t#zstd_out_buffer",
    "typedef_type zstd_out_buffer { t#ZSTD_outBuffer }");

kernel::kabi_export! {
    zstd_is_error,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#size_t code ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// Body of the `zstd_is_error` entry thunk in `zstd_decompress_module.c`.
#[no_mangle]
pub extern "C" fn zstd_is_error(code: usize) -> c_uint {
    // SAFETY: class B (boundary), pure pass-through to an already-exported
    // Rust function with an identical signature.
    unsafe { ZSTD_isError(code) }
}

kernel::kabi_export! {
    zstd_get_error_code,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#size_t code ) -> t#zstd_error_code",
}

/// Body of the `zstd_get_error_code` entry thunk. `zstd_error_code` is a
/// C enum, 4-byte representation -- `c_int` here is that representation,
/// not a narrowing.
#[no_mangle]
pub extern "C" fn zstd_get_error_code(code: usize) -> c_int {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_getErrorCode(code) }
}

kernel::kabi_export! {
    zstd_get_error_name,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#size_t code ) -> pointer_type { const_type { base_type char byte_size(1) encoding(8) } }",
}

/// Body of the `zstd_get_error_name` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_get_error_name(code: usize) -> *const c_char {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_getErrorName(code) }
}

kernel::kabi_export! {
    zstd_dctx_workspace_bound,
    license = "",
    namespace = "",
    contract = "subprogram ( ) -> t#size_t",
}

/// Body of the `zstd_dctx_workspace_bound` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_dctx_workspace_bound() -> usize {
    // SAFETY: class B (boundary), pure pass-through, no arguments.
    unsafe { ZSTD_estimateDCtxSize() }
}

kernel::kabi_export! {
    zstd_create_dctx_advanced,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#zstd_custom_mem custom_mem ) -> pointer_type { t#zstd_dctx }",
}

/// Body of the `zstd_create_dctx_advanced` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_create_dctx_advanced(custom_mem: ZstdCustomMem) -> *mut c_void {
    // SAFETY: class B (boundary), pure pass-through; `custom_mem` crosses
    // by value with an identical layout to the callee's own copy.
    unsafe { ZSTD_createDCtx_advanced(custom_mem) }
}

kernel::kabi_export! {
    zstd_free_dctx,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_dctx } dctx ) -> t#size_t",
}

/// Body of the `zstd_free_dctx` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_free_dctx(dctx: *mut c_void) -> usize {
    // SAFETY: class B (boundary), pure pass-through; `dctx` is forwarded
    // opaque, never dereferenced here.
    unsafe { ZSTD_freeDCtx(dctx) }
}

kernel::kabi_export! {
    zstd_create_ddict_byreference,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } dict , formal_parameter t#size_t dict_size , formal_parameter t#zstd_custom_mem custom_mem ) -> pointer_type { t#zstd_ddict }",
}

/// Body of the `zstd_create_ddict_byreference` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_create_ddict_byreference(
    dict: *const c_void,
    dict_size: usize,
    custom_mem: ZstdCustomMem,
) -> *mut c_void {
    // SAFETY: class B (boundary), pure pass-through; `dict` is forwarded
    // opaque, never dereferenced here.
    unsafe {
        ZSTD_createDDict_advanced(dict, dict_size, ZSTD_DLM_BY_REF, ZSTD_DCT_AUTO, custom_mem)
    }
}

kernel::kabi_export! {
    zstd_free_ddict,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_ddict } ddict ) -> t#size_t",
}

/// Body of the `zstd_free_ddict` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_free_ddict(ddict: *mut c_void) -> usize {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_freeDDict(ddict) }
}

kernel::kabi_export! {
    zstd_init_dctx,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } workspace , formal_parameter t#size_t workspace_size ) -> pointer_type { t#zstd_dctx }",
}

/// Body of the `zstd_init_dctx` entry thunk. Keeps the pristine C's
/// NULL-workspace guard even though the callee also checks -- faithful
/// translation, not a smarter one.
#[no_mangle]
pub extern "C" fn zstd_init_dctx(workspace: *mut c_void, workspace_size: usize) -> *mut c_void {
    if workspace.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary), pure pass-through; `workspace` is
    // forwarded opaque, never dereferenced here.
    unsafe { ZSTD_initStaticDCtx(workspace, workspace_size) }
}

kernel::kabi_export! {
    zstd_decompress_dctx,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_dctx } dctx , formal_parameter pointer_type { base_type void } dst , formal_parameter t#size_t dst_capacity , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter t#size_t src_size ) -> t#size_t",
}

/// Body of the `zstd_decompress_dctx` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_decompress_dctx(
    dctx: *mut c_void,
    dst: *mut c_void,
    dst_capacity: usize,
    src: *const c_void,
    src_size: usize,
) -> usize {
    // SAFETY: class B (boundary), pure pass-through; every pointer is
    // forwarded opaque, never dereferenced here.
    unsafe { ZSTD_decompressDCtx(dctx, dst, dst_capacity, src, src_size) }
}

kernel::kabi_export! {
    zstd_decompress_using_ddict,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_dctx } dctx , formal_parameter pointer_type { base_type void } dst , formal_parameter t#size_t dst_capacity , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter t#size_t src_size , formal_parameter pointer_type { const_type { t#zstd_ddict } } ddict ) -> t#size_t",
}

/// Body of the `zstd_decompress_using_ddict` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_decompress_using_ddict(
    dctx: *mut c_void,
    dst: *mut c_void,
    dst_capacity: usize,
    src: *const c_void,
    src_size: usize,
    ddict: *const c_void,
) -> usize {
    // SAFETY: class B (boundary), pure pass-through; every pointer is
    // forwarded opaque, never dereferenced here.
    unsafe { ZSTD_decompress_usingDDict(dctx, dst, dst_capacity, src, src_size, ddict) }
}

kernel::kabi_export! {
    zstd_dstream_workspace_bound,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#size_t max_window_size ) -> t#size_t",
}

/// Body of the `zstd_dstream_workspace_bound` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_dstream_workspace_bound(max_window_size: usize) -> usize {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_estimateDStreamSize(max_window_size) }
}

kernel::kabi_export! {
    zstd_init_dstream,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#size_t max_window_size , formal_parameter pointer_type { base_type void } workspace , formal_parameter t#size_t workspace_size ) -> pointer_type { t#zstd_dstream }",
}

/// Body of the `zstd_init_dstream` entry thunk. Keeps the pristine C's
/// NULL-workspace guard and its own discarding of `max_window_size`
/// (`(void)max_window_size;` in the C).
#[no_mangle]
pub extern "C" fn zstd_init_dstream(
    _max_window_size: usize,
    workspace: *mut c_void,
    workspace_size: usize,
) -> *mut c_void {
    if workspace.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary), pure pass-through; `workspace` is
    // forwarded opaque, never dereferenced here.
    unsafe { ZSTD_initStaticDStream(workspace, workspace_size) }
}

kernel::kabi_export! {
    zstd_reset_dstream,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_dstream } dstream ) -> t#size_t",
}

/// Body of the `zstd_reset_dstream` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_reset_dstream(dstream: *mut c_void) -> usize {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_DCtx_reset(dstream, ZSTD_RESET_SESSION_ONLY) }
}

kernel::kabi_export! {
    zstd_decompress_stream,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_dstream } dstream , formal_parameter pointer_type { t#zstd_out_buffer } output , formal_parameter pointer_type { t#zstd_in_buffer } input ) -> t#size_t",
}

/// Body of the `zstd_decompress_stream` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_decompress_stream(
    dstream: *mut c_void,
    output: *mut c_void,
    input: *mut c_void,
) -> usize {
    // SAFETY: class B (boundary), pure pass-through; `output`/`input` are
    // forwarded opaque, never dereferenced here.
    unsafe { ZSTD_decompressStream(dstream, output, input) }
}

kernel::kabi_export! {
    zstd_find_frame_compressed_size,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter t#size_t src_size ) -> t#size_t",
}

/// Body of the `zstd_find_frame_compressed_size` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_find_frame_compressed_size(src: *const c_void, src_size: usize) -> usize {
    // SAFETY: class B (boundary), pure pass-through.
    unsafe { ZSTD_findFrameCompressedSize(src, src_size) }
}

kernel::kabi_export! {
    zstd_get_frame_header,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#zstd_frame_header } header , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter t#size_t src_size ) -> t#size_t",
}

/// Body of the `zstd_get_frame_header` entry thunk.
#[no_mangle]
pub extern "C" fn zstd_get_frame_header(
    header: *mut c_void,
    src: *const c_void,
    src_size: usize,
) -> usize {
    // SAFETY: class B (boundary), pure pass-through; `header` is forwarded
    // opaque, never dereferenced here.
    unsafe { ZSTD_getFrameHeader(header, src, src_size) }
}
