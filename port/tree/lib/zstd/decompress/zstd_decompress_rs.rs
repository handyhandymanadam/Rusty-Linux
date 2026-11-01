// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the file it is ported from)

//! The zstd decompression state machine: frame header parsing, the
//! bufferless block-at-a-time decoder (`ZSTD_decompressContinue`), the
//! buffered streaming decoder (`ZSTD_decompressStream`), the multi-DDict
//! hash set, and the one-shot `ZSTD_decompress*` entry points.
//!
//! Ported from `lib/zstd/decompress/zstd_decompress.c` (6.18.49),
//! `Copyright (c) Meta Platforms, Inc. and affiliates.`, dual
//! GPL-2.0+/BSD-3-Clause.
//!
//! # Shape: no C entry thunks
//!
//! `nm` on the built object says nothing in this file is `EXPORT_SYMBOL`'d
//! directly -- every export a caller can see is a snake_case wrapper in
//! `lib/zstd/zstd_decompress_module.c` (`zstd_decompress_dctx`,
//! `zstd_decompress_stream`, ...) that calls straight through to the
//! `ZSTD_*` names this file defines. That C thunk file stays C -- it is not
//! this port's concern -- and keeps calling these functions by their C
//! names, so every function it references keeps its name and `#[no_mangle]`
//! here, matching the shape `huf_decompress_rs.rs` and
//! `zstd_decompress_block_rs.rs` already established. No MODVERSIONS CRC
//! attaches to anything in this file.
//!
//! # `struct ZSTD_DCtx_s` is mirrored again, not shared
//!
//! `zstd_decompress_block_rs.rs` already carries a full mirror of this
//! struct (`ZstdDCtx`), offsetof()-verified there. This file needs its own
//! copy -- Rust does not share a type across two separately-compiled crates
//! without a common library crate, and this project is one crate per
//! ported file throughout `lib/zstd/` -- so the field list below is copied
//! field-for-field from that file's derivation, not re-derived
//! independently, per the coordination on this port. Both copies must move
//! together if the real header ever changes; `port/test/zstd_decompress/`
//! is where that gets caught, the same as every other mirrored struct in
//! this project.
//!
//! # Cross-crate calls, both directions
//!
//! Four functions cross OUT of this file into
//! `zstd_decompress_block_rs.rs`, unchanged from the C's boundary:
//! `ZSTD_getcBlockSize`, `ZSTD_checkContinuity`,
//! `ZSTD_decompressBlock_internal`, `ZSTD_buildFSETable`. All four are
//! `#[no_mangle] pub extern "C" fn` there; declared `extern "C"` here.
//!
//! Three functions cross OUT into `common/entropy_common_rs.rs` and
//! `decompress/huf_decompress_rs.rs`, both already-Rust, C-ABI-linked the
//! same way every other file in this subsystem reaches them:
//! `FSE_readNCount`, `HUF_readDTableX2_wksp` (`HUF_readDTableX1_wksp` is
//! declared in the header but never called -- see [`ZSTD_loadDEntropy`]).
//!
//! Three functions cross OUT into `lib/xxhash_rs.rs`: `xxh64_reset`,
//! `xxh64_update`, `xxh64_digest`.
//!
//! Five functions cross OUT into `lib/zstd/decompress/zstd_ddict.c`, which
//! **stays C** (not this port's file, no call to change that here):
//! `ZSTD_DDict_dictContent`, `ZSTD_DDict_dictSize`,
//! `ZSTD_copyDDictParameters`, `ZSTD_freeDDict`,
//! `ZSTD_createDDict_advanced`, `ZSTD_getDictID_fromDDict`. `ZSTD_DDict` is
//! never looked inside from this file -- it is an opaque pointer,
//! `*const c_void` / `*mut c_void`, exactly the shape the C's own
//! `zstd_ddict.h` gives it (an incomplete type, accessed only through those
//! six accessor functions).
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **`ZSTD_customMalloc`/`ZSTD_customCalloc`/`ZSTD_customFree` reimplement
//!    the kernel's own stub, faithfully, not "improved".**
//!    `common/zstd_deps.h`'s `ZSTD_DEPS_NEED_MALLOC` arm defines
//!    `ZSTD_malloc(s)`/`ZSTD_calloc(n,s)` as `NULL` unconditionally and
//!    `ZSTD_free(p)` as a no-op -- there is no libc `malloc` in the kernel,
//!    so the "fall back to stdlib" arm of each customMem wrapper always
//!    fails. That means `ZSTD_createDCtx()`/`ZSTD_createDStream()` (which
//!    both use `ZSTD_defaultCMem = { NULL, NULL, NULL }`) allocate nothing
//!    and hand back a context whose first real allocation always fails --
//!    dead weight kept only because it is part of the public API surface,
//!    same shape as the HUF/FSE "nothing kernel-wide" symbols
//!    `huf_decompress_rs.rs` already documents. The only live in-kernel path
//!    is the static-workspace one (`ZSTD_initStaticDCtx`, reached from
//!    `zstd_init_dctx` in the C thunk module) or an explicit customMem with
//!    real allocator function pointers (`ZSTD_createDCtx_advanced`, reached
//!    from `zstd_create_dctx_advanced`). Ported as the C has it, not as it
//!    "should" work, per GOALS.md's C-is-a-reference-not-a-specification
//!    rule cutting the other way here: changing this would diverge
//!    behaviourally, not just stylistically.
//!
//! 2. **`assert()` in the C is either dropped or promoted, never
//!    `debug_assert!`.** Every `assert()` in the pristine file is either
//!    (a) purely informational / restating a precondition already enforced
//!    by an earlier `RETURN_ERROR_IF` on the same path, in which case it is
//!    dropped with a comment, or (b) the only thing standing between a
//!    later pointer computation and undefined behaviour, in which case it
//!    becomes a real Rust `assert!` -- this project runs with
//!    `overflow-checks=on` and treats a reachable panic as the intended
//!    catch, not a debug-only nicety. Each site says which.
//!
//! Replaces: lib/zstd/decompress/zstd_decompress.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uint, c_void};

// ---------------------------------------------------------------------------
// lib/zstd/common/zstd_internal.h -- format constants (copied from
// zstd_decompress_block_rs.rs / entropy_common_rs.rs; own copy per file,
// same reasoning as every other file in this subsystem).
// ---------------------------------------------------------------------------

const ZSTD_BLOCK_HEADER_SIZE: usize = 3;
const MAX_LL: u32 = 35;
const MAX_ML: u32 = 52;
const MAX_OFF: u32 = 31;
const LL_FSE_LOG: u32 = 9;
const OFF_FSE_LOG: u32 = 8;
const ML_FSE_LOG: u32 = 9;
const MAX_FSE_LOG: u32 = 9;
/// `ZSTD_REP_NUM`.
const ZSTD_REP_NUM: usize = 3;
/// `repStartValue`.
const REP_START_VALUE: [u32; ZSTD_REP_NUM] = [1, 4, 8];
/// `WILDCOPY_OVERLENGTH`.
const WILDCOPY_OVERLENGTH: usize = 32;
/// `ZSTD_BLOCKSIZELOG_MAX`.
const ZSTD_BLOCKSIZELOG_MAX: u32 = 17;
/// `ZSTD_BLOCKSIZE_MAX`.
const ZSTD_BLOCKSIZE_MAX: usize = 1 << ZSTD_BLOCKSIZELOG_MAX;
/// `ZSTD_FRAMEIDSIZE`.
const ZSTD_FRAMEIDSIZE: usize = 4;
/// `ZSTD_did_fieldSize[]`.
const ZSTD_did_fieldSize: [usize; 4] = [0, 1, 2, 4];
/// `ZSTD_fcs_fieldSize[]`.
const ZSTD_fcs_fieldSize: [usize; 4] = [0, 2, 4, 8];

/// `blockType_e`. Plain `u32` constants, not an enum, so they compare
/// directly against `ZstdDCtx::bType`/`BlockProperties::blockType`, which
/// are themselves plain `u32` (matching the cross-crate mirror).
const bt_raw: u32 = 0;
const bt_rle: u32 = 1;
const bt_compressed: u32 = 2;
const bt_reserved: u32 = 3;

/// `streaming_operation`, `zstd_decompress_block.h`. Passed to
/// `ZSTD_decompressBlock_internal` across the crate boundary as a plain
/// `c_uint` -- ABI-identical to `zstd_decompress_block_rs.rs`'s
/// `#[repr(u32)] enum StreamingOperation` at the call site, and this file
/// never inspects the value itself.
const not_streaming: c_uint = 0;
const is_streaming: c_uint = 1;

// ---------------------------------------------------------------------------
// zstd_decompress_internal.h -- ZSTD_seqSymbol and the entropy tables.
// Copied from zstd_decompress_block_rs.rs; own copy, same reasoning.
// ---------------------------------------------------------------------------

/// `ZSTD_seqSymbol`.
#[derive(Clone, Copy)]
#[repr(C)]
struct SeqSymbol {
    nextState: u16,
    nbAdditionalBits: u8,
    nbBits: u8,
    baseValue: u32,
}

const fn seqsymbol_table_size(log: u32) -> usize {
    1 + (1usize << log)
}

/// `HUF_DTable`, `huf.h:65` -- `typedef U32 HUF_DTable`.
type HufDTable = u32;
const fn huf_dtable_size(max_table_log: u32) -> usize {
    1 + (1usize << max_table_log)
}
const ZSTD_HUFFDTABLE_CAPACITY_LOG: u32 = 12;

/// `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE`, in bytes:
/// `sizeof(S16) * (MaxSeq + 1) + (1u << MaxFSELog) + sizeof(U64)`. `MaxSeq`
/// is `MAX(MaxLL, MaxML)` == 52.
const MAX_SEQ: u32 = 52;
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE: usize =
    2 * (MAX_SEQ as usize + 1) + (1usize << MAX_FSE_LOG) + 8;
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32: usize =
    (ZSTD_BUILD_FSE_TABLE_WKSP_SIZE + 4 - 1) / 4;

/// `HUF_DECOMPRESS_WORKSPACE_SIZE`, `huf.h:236` -- `((2 << 10) + (1 << 9))`.
const HUF_DECOMPRESS_WORKSPACE_SIZE: usize = (2 << 10) + (1 << 9);
const HUF_DECOMPRESS_WORKSPACE_SIZE_U32: usize = HUF_DECOMPRESS_WORKSPACE_SIZE / 4;

/// `ZSTD_entropyDTables_t`.
#[repr(C)]
pub struct EntropyDTables {
    LLTable: [SeqSymbol; seqsymbol_table_size(LL_FSE_LOG)],
    OFTable: [SeqSymbol; seqsymbol_table_size(OFF_FSE_LOG)],
    MLTable: [SeqSymbol; seqsymbol_table_size(ML_FSE_LOG)],
    hufTable: [HufDTable; huf_dtable_size(ZSTD_HUFFDTABLE_CAPACITY_LOG)],
    rep: [u32; ZSTD_REP_NUM],
    workspace: [u32; ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32],
}

/// `ZSTD_dStage`, `zstd_decompress_internal.h:90-93`. Plain `u32` constants
/// (matching `ZstdDCtx::stage`'s type in the cross-crate mirror), not an
/// enum -- this file both reads and writes `dctx.stage` across many
/// functions, and a plain `u32` avoids needing a checked conversion at
/// every one of those sites.
const ZSTDds_getFrameHeaderSize: u32 = 0;
const ZSTDds_decodeFrameHeader: u32 = 1;
const ZSTDds_decodeBlockHeader: u32 = 2;
const ZSTDds_decompressBlock: u32 = 3;
const ZSTDds_decompressLastBlock: u32 = 4;
const ZSTDds_checkChecksum: u32 = 5;
const ZSTDds_decodeSkippableHeader: u32 = 6;
const ZSTDds_skipFrame: u32 = 7;

/// `ZSTD_dStreamStage`, `zstd_decompress_internal.h:95-96`.
const zdss_init: u32 = 0;
const zdss_loadHeader: u32 = 1;
const zdss_read: u32 = 2;
const zdss_load: u32 = 3;
const zdss_flush: u32 = 4;

/// `ZSTD_dictUses_e`, `zstd_decompress_internal.h:98-102`. Signed: `-1` is a
/// real, distinct state (`ZSTD_use_indefinitely`), so this stays `c_int`
/// like the field it types (`ZstdDCtx::dictUses`).
const ZSTD_use_indefinitely: c_int = -1;
const ZSTD_dont_use: c_int = 0;
const ZSTD_use_once: c_int = 1;

// `ZSTD_litLocation_e` (`zstd_decompress_internal.h:121-125`) and
// `ZSTD_DCtx_get_bmi2()` (`:206-213`) are declared for `ZstdDCtx`'s
// `litBufferLocation`/`bmi2` fields, but neither is ever read or written by
// this file -- only by `zstd_decompress_block.c`, which owns them. Not
// ported here: dead code in a file that never uses it serves no purpose,
// per this project's own ratchet (no defect, no new code).

// ---------------------------------------------------------------------------
// include/linux/zstd_lib.h -- public enums and structs this file's DCtx
// mirror and its own signatures need.
// ---------------------------------------------------------------------------

const ZSTD_f_zstd1: u32 = 0;
const ZSTD_f_zstd1_magicless: u32 = 1;

const ZSTD_d_validateChecksum: u32 = 0;
const ZSTD_d_ignoreChecksum: u32 = 1;

const ZSTD_rmd_refSingleDDict: u32 = 0;
const ZSTD_rmd_refMultipleDDicts: u32 = 1;

const ZSTD_bm_buffered: u32 = 0;
const ZSTD_bm_stable: u32 = 1;

const ZSTD_frame: u32 = 0;
const ZSTD_skippableFrame: u32 = 1;

const ZSTD_dlm_byCopy: c_int = 0;
const ZSTD_dlm_byRef: c_int = 1;

const ZSTD_dct_auto: c_int = 0;
const ZSTD_dct_rawContent: c_int = 1;
#[allow(dead_code)]
const ZSTD_dct_fullDict: c_int = 2;

const ZSTD_reset_session_only: c_int = 1;
const ZSTD_reset_parameters: c_int = 2;
const ZSTD_reset_session_and_parameters: c_int = 3;

/// `ZSTD_dParameter`. `ZSTD_d_windowLogMax` is stable API; the rest are
/// `ZSTD_d_experimentalParam{1..6}` under the hood, per `zstd_lib.h:640-645`
/// -- never referred to by that name, per the header's own warning.
const ZSTD_d_windowLogMax: c_int = 100;
const ZSTD_d_format: c_int = 1000;
const ZSTD_d_stableOutBuffer: c_int = 1001;
const ZSTD_d_forceIgnoreChecksum: c_int = 1002;
const ZSTD_d_refMultipleDDicts: c_int = 1003;
const ZSTD_d_disableHuffmanAssembly: c_int = 1004;
const ZSTD_d_maxBlockSize: c_int = 1005;

/// `ZSTD_WINDOWLOG_ABSOLUTEMIN`.
const ZSTD_WINDOWLOG_ABSOLUTEMIN: c_int = 10;
/// `ZSTD_WINDOWLOG_MAX`, the 64-bit arm (`sizeof(size_t) == 8` on every
/// target this project builds).
const ZSTD_WINDOWLOG_MAX: c_int = 31;
/// `ZSTD_WINDOWLOG_LIMIT_DEFAULT`.
const ZSTD_WINDOWLOG_LIMIT_DEFAULT: u32 = 27;
/// `ZSTD_MAXWINDOWSIZE_DEFAULT`, `(((U32)1 << ZSTD_WINDOWLOG_LIMIT_DEFAULT) + 1)`.
const ZSTD_MAXWINDOWSIZE_DEFAULT: usize = ((1u32 << ZSTD_WINDOWLOG_LIMIT_DEFAULT) as usize) + 1;

/// `ZSTD_NO_FORWARD_PROGRESS_MAX`.
const ZSTD_NO_FORWARD_PROGRESS_MAX: u32 = 16;

/// `ZSTD_WORKSPACETOOLARGE_FACTOR`.
const ZSTD_WORKSPACETOOLARGE_FACTOR: usize = 3;
/// `ZSTD_WORKSPACETOOLARGE_MAXDURATION`.
const ZSTD_WORKSPACETOOLARGE_MAXDURATION: usize = 128;

const ZSTD_MAGICNUMBER: u32 = 0xFD2FB528;
const ZSTD_MAGIC_SKIPPABLE_START: u32 = 0x184D2A50;
const ZSTD_MAGIC_SKIPPABLE_MASK: u32 = 0xFFFFFFF0;
/// Not a real upstream name -- `MAGIC_DICTIONARY` from `zstd_internal.h`.
const ZSTD_MAGIC_DICTIONARY: u32 = 0xEC30A437;

const ZSTD_blockHeaderSize: usize = ZSTD_BLOCK_HEADER_SIZE;

const ZSTD_CONTENTSIZE_UNKNOWN: u64 = 0u64.wrapping_sub(1);
const ZSTD_CONTENTSIZE_ERROR: u64 = 0u64.wrapping_sub(2);

const ZSTD_SKIPPABLEHEADERSIZE: usize = 8;
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;

const fn ZSTD_FRAMEHEADERSIZE_PREFIX(format: u32) -> usize {
    if format == ZSTD_f_zstd1 {
        5
    } else {
        1
    }
}
const fn ZSTD_FRAMEHEADERSIZE_MIN(format: u32) -> usize {
    if format == ZSTD_f_zstd1 {
        6
    } else {
        2
    }
}

/// `ZSTD_bounds`.
#[repr(C)]
pub struct ZstdBounds {
    error: usize,
    lowerBound: c_int,
    upperBound: c_int,
}

/// `ZSTD_FrameHeader`. Copied from `zstd_decompress_block_rs.rs`'s
/// `ZstdFrameHeader`, but `pub(crate)`-visible here since this file reads
/// and writes every field, not just two.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZstdFrameHeader {
    frameContentSize: u64,
    windowSize: u64,
    blockSizeMax: u32,
    frameType: u32,
    headerSize: u32,
    dictID: u32,
    checksumFlag: u32,
    _reserved1: u32,
    _reserved2: u32,
}

/// `ZSTD_customMem`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZstdCustomMem {
    customAlloc: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    customFree: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    opaque: *mut c_void,
}

/// `ZSTD_defaultCMem`, `zstd_lib.h:1845` -- `{ NULL, NULL, NULL }`.
const ZSTD_defaultCMem: ZstdCustomMem = ZstdCustomMem {
    customAlloc: None,
    customFree: None,
    opaque: core::ptr::null_mut(),
};

/// `ZSTD_inBuffer`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZstdInBuffer {
    src: *const c_void,
    size: usize,
    pos: usize,
}

/// `ZSTD_outBuffer`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZstdOutBuffer {
    dst: *mut c_void,
    size: usize,
    pos: usize,
}

/// `struct xxh64_state`, `include/linux/xxhash.h`. Own copy -- see
/// `lib/xxhash_rs.rs`'s mirror, field-for-field identical; this file never
/// looks inside except through `xxh64_reset`/`_update`/`_digest`.
#[repr(C)]
struct Xxh64State {
    total_len: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    mem64: [u64; 4],
    memsize: u32,
}

/// `ZSTD_DDictHashSet`, `zstd_decompress_internal.h:104-109`. Unlike
/// `zstd_decompress_block_rs.rs`'s `ddictSet: *mut c_void` (opaque there --
/// that file never touches it), this file implements the hash set itself,
/// so its pointee type is real here. The field is still just a pointer at
/// the same offset either way, so both crates' `ZstdDCtx` mirrors stay
/// ABI-identical.
#[repr(C)]
struct DDictHashSet {
    /// `const ZSTD_DDict**`. Opaque `ZSTD_DDict`, so `*const c_void`.
    ddictPtrTable: *mut *const c_void,
    ddictPtrTableSize: usize,
    ddictPtrCount: usize,
}

/// `ZSTD_LITBUFFEREXTRASIZE`, `BOUNDED(ZSTD_LBMIN, ZSTD_DECODER_INTERNAL_BUFFER, ZSTD_LBMAX)`
/// == `BOUNDED(64, 1 << 16, 128 << 10)` == `1 << 16` (already inside the bound).
const ZSTD_LITBUFFEREXTRASIZE: usize = 1 << 16;

/// Mirrors `struct ZSTD_DCtx_s`, `zstd_decompress_internal.h`. Copied
/// field-for-field from `zstd_decompress_block_rs.rs`'s `ZstdDCtx` --
/// see this file's module docs. `ddictLocal`/`ddict`/`ddictSet` are typed
/// through this file's own opaque/real pointee types rather than that
/// file's blanket `*mut c_void`, which is layout-neutral (same pointer
/// width, same offset) so both mirrors stay ABI-identical.
#[repr(C)]
pub struct ZstdDCtx {
    LLTptr: *const SeqSymbol,
    MLTptr: *const SeqSymbol,
    OFTptr: *const SeqSymbol,
    HUFptr: *const HufDTable,
    entropy: EntropyDTables,
    workspace: [u32; HUF_DECOMPRESS_WORKSPACE_SIZE_U32],
    previousDstEnd: *const c_void,
    prefixStart: *const c_void,
    virtualStart: *const c_void,
    dictEnd: *const c_void,
    expected: usize,
    fParams: ZstdFrameHeader,
    processedCSize: u64,
    decodedSize: u64,
    bType: u32,
    stage: u32,
    litEntropy: u32,
    fseEntropy: u32,
    xxhState: Xxh64State,
    headerSize: usize,
    format: u32,
    forceIgnoreChecksum: u32,
    validateChecksum: u32,
    litPtr: *const u8,
    customMem: ZstdCustomMem,
    litSize: usize,
    rleSize: usize,
    staticSize: usize,
    isFrameDecompression: c_int,
    #[cfg(DYNAMIC_BMI2)]
    bmi2: c_int,
    /// Opaque `ZSTD_DDict*`.
    ddictLocal: *mut c_void,
    /// Opaque `const ZSTD_DDict*`.
    ddict: *const c_void,
    dictID: u32,
    ddictIsCold: c_int,
    dictUses: c_int,
    ddictSet: *mut DDictHashSet,
    refMultipleDDicts: u32,
    disableHufAsm: c_int,
    maxBlockSizeParam: c_int,
    streamStage: u32,
    inBuff: *mut c_char,
    inBuffSize: usize,
    inPos: usize,
    maxWindowSize: usize,
    outBuff: *mut c_char,
    outBuffSize: usize,
    outStart: usize,
    outEnd: usize,
    lhSize: usize,
    hostageByte: u32,
    noForwardProgress: c_int,
    outBufferMode: u32,
    expectedOutBuffer: ZstdOutBuffer,
    litBuffer: *mut u8,
    litBufferEnd: *const u8,
    litBufferLocation: u32,
    litExtraBuffer: [u8; ZSTD_LITBUFFEREXTRASIZE + WILDCOPY_OVERLENGTH],
    headerBuffer: [u8; ZSTD_FRAMEHEADERSIZE_MAX],
    oversizedDuration: usize,
}

// ---------------------------------------------------------------------------
// include/linux/zstd_errors.h -- the full error code enum this file needs
// (a larger subset than zstd_decompress_block_rs.rs's, since this file
// surfaces user-facing parameter/stage errors that block decode never does).
// ---------------------------------------------------------------------------

const ZSTD_error_no_error: usize = 0;
const ZSTD_error_GENERIC: usize = 1;
const ZSTD_error_prefix_unknown: usize = 10;
const ZSTD_error_frameParameter_unsupported: usize = 14;
const ZSTD_error_frameParameter_windowTooLarge: usize = 16;
const ZSTD_error_corruption_detected: usize = 20;
const ZSTD_error_checksum_wrong: usize = 22;
const ZSTD_error_dictionary_corrupted: usize = 30;
const ZSTD_error_dictionary_wrong: usize = 32;
const ZSTD_error_parameter_unsupported: usize = 40;
const ZSTD_error_parameter_outOfBound: usize = 42;
const ZSTD_error_stage_wrong: usize = 60;
const ZSTD_error_memory_allocation: usize = 64;
const ZSTD_error_dstSize_tooSmall: usize = 70;
const ZSTD_error_srcSize_wrong: usize = 72;
const ZSTD_error_dstBuffer_null: usize = 74;
const ZSTD_error_noForwardProgress_destFull: usize = 80;
const ZSTD_error_noForwardProgress_inputEmpty: usize = 82;
const ZSTD_error_dstBuffer_wrong: usize = 104;
const ZSTD_error_maxCode: usize = 120;

/// `error_private.h:42` -- `#define ZSTD_ERROR(name) ((size_t)-PREFIX(name))`.
#[inline(always)]
const fn ERROR(code: usize) -> usize {
    0usize.wrapping_sub(code)
}

/// `error_private.h:44` -- `return (code > ERROR(maxCode));`
#[inline(always)]
fn ZSTD_isError(code: usize) -> c_uint {
    (code > ERROR(ZSTD_error_maxCode)) as c_uint
}

/// `ZSTD_getErrorCode()`, `zstd_common.c`.
#[inline(always)]
fn ZSTD_getErrorCode(code: usize) -> usize {
    if ZSTD_isError(code) != 0 {
        0usize.wrapping_sub(code)
    } else {
        ZSTD_error_no_error
    }
}

// ---------------------------------------------------------------------------
// lib/zstd/common/mem.h -- unaligned access. Copied verbatim from the other
// files in this subsystem; see their module docs.
// ---------------------------------------------------------------------------

/// # Safety
/// `p .. p + 2` must be readable.
#[inline(always)]
unsafe fn MEM_readLE16(p: *const u8) -> u16 {
    // SAFETY: class C (construction). The caller guarantees 2 readable bytes.
    u16::from_le(unsafe { core::ptr::read_unaligned(p as *const u16) })
}

/// # Safety
/// `p .. p + 4` must be readable.
#[inline(always)]
unsafe fn MEM_readLE32(p: *const u8) -> u32 {
    // SAFETY: class C (construction). The caller guarantees 4 readable bytes.
    u32::from_le(unsafe { core::ptr::read_unaligned(p as *const u32) })
}

/// # Safety
/// `p .. p + 4` must be writable.
#[inline(always)]
unsafe fn MEM_writeLE32(p: *mut u8, value: u32) {
    // SAFETY: class C (construction). The caller guarantees 4 writable bytes.
    unsafe { core::ptr::write_unaligned(p as *mut u32, value.to_le()) }
}

/// # Safety
/// `p .. p + 8` must be readable.
#[inline(always)]
unsafe fn MEM_readLE64(p: *const u8) -> u64 {
    // SAFETY: class C (construction). The caller guarantees 8 readable bytes.
    u64::from_le(unsafe { core::ptr::read_unaligned(p as *const u64) })
}

/// `bits.h` -- `31 - __builtin_clz(val)`, `val != 0` required by the C too
/// (this file's one call site is guarded the same way `huf_decompress_rs.rs`
/// documents).
#[inline(always)]
fn ZSTD_highbit32(val: u32) -> u32 {
    31u32.wrapping_sub(val.leading_zeros())
}

/// `common.h` -- `MIN`.
#[inline(always)]
fn MIN_usize(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}
/// `common.h` -- `MAX`.
#[inline(always)]
fn MAX_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}
#[inline(always)]
fn MIN_u64(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}
#[inline(always)]
fn MAX_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}
/// `common.h` -- `BOUNDED(lo, val, hi)` == `MAX(lo, MIN(val, hi))`.
#[inline(always)]
fn BOUNDED_usize(lo: usize, val: usize, hi: usize) -> usize {
    MAX_usize(lo, MIN_usize(val, hi))
}

/// `zstd_internal.h:242` -- `ZSTD_limitCopy()`. `MEM_STATIC`, no linkable
/// symbol; reimplemented here per this subsystem's convention.
///
/// # Safety
/// `dst .. dst + MIN(dstCapacity, srcSize)` must be writable and
/// `src .. src + MIN(dstCapacity, srcSize)` must be readable.
#[inline(always)]
unsafe fn ZSTD_limitCopy(dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    let length = MIN_usize(dstCapacity, srcSize);
    if length > 0 {
        // SAFETY: class B (boundary). `length <= dstCapacity` and
        // `length <= srcSize`, both guaranteed by the caller.
        unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, length) };
    }
    length
}

// ---------------------------------------------------------------------------
// common/allocations.h -- MEM_STATIC, reimplemented faithfully. See the
// module docs' "deliberate divergences" #1: this always fails unless a real
// customAlloc/customFree is set, because the kernel's own zstd_deps.h stubs
// ZSTD_malloc/calloc/free to NULL/no-op.
// ---------------------------------------------------------------------------

/// # Safety
/// If `customMem.customAlloc` is set, it must be safe to call with
/// `(customMem.opaque, size)`.
#[inline(always)]
unsafe fn ZSTD_customMalloc(size: usize, customMem: ZstdCustomMem) -> *mut c_void {
    if let Some(customAlloc) = customMem.customAlloc {
        // SAFETY: class B (boundary), the caller's contract above.
        unsafe { customAlloc(customMem.opaque, size) }
    } else {
        core::ptr::null_mut()
    }
}

/// # Safety
/// As [`ZSTD_customMalloc`]; the allocated block, if any, must be
/// `size`-bytes writable (it is immediately zeroed).
#[inline(always)]
unsafe fn ZSTD_customCalloc(size: usize, customMem: ZstdCustomMem) -> *mut c_void {
    if let Some(customAlloc) = customMem.customAlloc {
        // SAFETY: class B (boundary), the caller's contract above.
        let ptr = unsafe { customAlloc(customMem.opaque, size) };
        if !ptr.is_null() {
            // SAFETY: class B (boundary). `ptr` was just allocated with
            // `size` bytes by the caller-supplied allocator.
            unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, size) };
        }
        ptr
    } else {
        core::ptr::null_mut()
    }
}

/// # Safety
/// If `customMem.customFree` is set, it must be safe to call with
/// `(customMem.opaque, ptr)`, and `ptr` must not be used again afterwards.
#[inline(always)]
unsafe fn ZSTD_customFree(ptr: *mut c_void, customMem: ZstdCustomMem) {
    if !ptr.is_null() {
        if let Some(customFree) = customMem.customFree {
            // SAFETY: class B (boundary), the caller's contract above.
            unsafe { customFree(customMem.opaque, ptr) };
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-crate calls.
// ---------------------------------------------------------------------------

extern "C" {
    /// `zstd_decompress_block_rs.rs` -- `#[no_mangle] pub extern "C" fn`.
    fn ZSTD_getcBlockSize(src: *const c_void, srcSize: usize, bpPtr: *mut BlockProperties) -> usize;
    /// `zstd_decompress_block_rs.rs`.
    fn ZSTD_checkContinuity(dctx: *mut ZstdDCtx, dst: *const c_void, dstSize: usize);
    /// `zstd_decompress_block_rs.rs`. `streaming` is `c_uint`
    /// (`not_streaming`/`is_streaming`) -- ABI-identical to that crate's
    /// `#[repr(u32)] StreamingOperation` at this call boundary.
    fn ZSTD_decompressBlock_internal(
        dctx: *mut ZstdDCtx,
        dst: *mut c_void,
        dstCapacity: usize,
        src: *const c_void,
        srcSize: usize,
        streaming: c_uint,
    ) -> usize;
    /// `zstd_decompress_block_rs.rs`.
    fn ZSTD_buildFSETable(
        dt: *mut SeqSymbol,
        normalizedCounter: *const i16,
        maxSymbolValue: c_uint,
        baseValue: *const u32,
        nbAdditionalBits: *const u8,
        tableLog: c_uint,
        wksp: *mut c_void,
        wkspSize: usize,
        bmi2: c_int,
    );

    /// `common/entropy_common_rs.rs`.
    fn FSE_readNCount(
        normalizedCounter: *mut i16,
        maxSVPtr: *mut c_uint,
        tableLogPtr: *mut c_uint,
        headerBuffer: *const c_void,
        hbSize: usize,
    ) -> usize;

    /// `decompress/huf_decompress_rs.rs`. `HUF_readDTableX1_wksp` is not
    /// declared here: `HUF_FORCE_DECOMPRESS_X1` is never defined anywhere
    /// in this tree, so `ZSTD_loadDEntropy`'s `#ifdef` arm calling it is
    /// dead code -- see that function's doc comment.
    fn HUF_readDTableX2_wksp(
        DTable: *mut u32,
        src: *const c_void,
        srcSize: usize,
        workSpace: *mut c_void,
        wkspSize: usize,
        flags: c_int,
    ) -> usize;

    /// `lib/xxhash_rs.rs`.
    fn xxh64_reset(state: *mut Xxh64State, seed: u64);
    /// `lib/xxhash_rs.rs`.
    fn xxh64_update(state: *mut Xxh64State, input: *const c_void, len: usize) -> c_int;
    /// `lib/xxhash_rs.rs`.
    fn xxh64_digest(state: *const Xxh64State) -> u64;
    /// `lib/xxhash_rs.rs` -- the one-shot form, used by the DDict hash set.
    fn xxh64(input: *const c_void, len: usize, seed: u64) -> u64;

    /// `lib/zstd/decompress/zstd_ddict.c` -- stays C, not this port's file.
    fn ZSTD_DDict_dictContent(ddict: *const c_void) -> *const c_void;
    /// `zstd_ddict.c`.
    fn ZSTD_DDict_dictSize(ddict: *const c_void) -> usize;
    /// `zstd_ddict.c`.
    fn ZSTD_copyDDictParameters(dctx: *mut ZstdDCtx, ddict: *const c_void);
    /// `zstd_ddict.c` (`zstd.h`-published, defined there).
    fn ZSTD_freeDDict(ddict: *mut c_void) -> usize;
    /// `zstd_ddict.c` -- now `zstd_ddict_rs.rs`. Its real signature takes
    /// `dictLoadMethod`/`dictContentType` as `c_uint` (the `ZSTD_dlm_*`/
    /// `ZSTD_dct_*` enum values passed here are always non-negative, and
    /// this is the exact width/signedness its real definition uses, not
    /// this file's own `c_int` convention for enum-valued parameters).
    fn ZSTD_createDDict_advanced(
        dict: *const c_void,
        dictSize: usize,
        dictLoadMethod: c_uint,
        dictContentType: c_uint,
        customMem: ZstdCustomMem,
    ) -> *mut c_void;
    /// `zstd_ddict.c`.
    fn ZSTD_getDictID_fromDDict(ddict: *const c_void) -> c_uint;
    /// `zstd_ddict.c` (`zstd.h`-published, defined there).
    fn ZSTD_sizeof_DDict(ddict: *const c_void) -> usize;
}

/// `blockProperties_t`. Own copy, matching
/// `zstd_decompress_block_rs.rs`'s `BlockProperties` field-for-field --
/// this file passes a `*mut BlockProperties` across the crate boundary to
/// [`ZSTD_getcBlockSize`], so the layout must match exactly.
#[repr(C)]
struct BlockProperties {
    blockType: u32,
    lastBlock: u32,
    origSize: u32,
}

impl Default for BlockProperties {
    fn default() -> Self {
        BlockProperties {
            blockType: bt_raw,
            lastBlock: 0,
            origSize: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Multiple DDicts Hashset internals. Only reachable when a caller explicitly
// enables ZSTD_d_refMultipleDDicts (an experimental parameter); nothing in
// this kernel tree does, so this whole section is dead-in-tree but ported
// faithfully as part of the public API surface, same as elsewhere in this
// file (see module docs #1).
// ---------------------------------------------------------------------------

const DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT: usize = 4;
const DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT: usize = 3;
const DDICT_HASHSET_TABLE_BASE_SIZE: usize = 64;
const DDICT_HASHSET_RESIZE_FACTOR: usize = 2;

/// `ZSTD_DDictHashSet_getIndex()`. `hashSet->ddictPtrTableSize` is always a
/// power of 2 `>= 64` by construction (`DDICT_HASHSET_TABLE_BASE_SIZE`,
/// doubled by `_expand`), so `ddictPtrTableSize - 1` never underflows;
/// checked (not wrapping) because a corrupted `ddictPtrTableSize` of 0 here
/// would otherwise silently turn into `hash & usize::MAX` -- an index with
/// no bound at all, worse than the panic it replaces.
///
/// # Safety
/// `hashSet` must be valid for reads.
unsafe fn ZSTD_DDictHashSet_getIndex(hashSet: *const DDictHashSet, dictID: u32) -> usize {
    // SAFETY: class B (boundary). The caller guarantees `hashSet` is valid.
    let hashSet = unsafe { &*hashSet };
    // SAFETY: class B (boundary). `xxh64` reads exactly `size_of::<u32>()`
    // bytes from `&dictID`, which is always that large.
    let hash = unsafe { xxh64(&dictID as *const u32 as *const c_void, 4, 0) };
    (hash as usize) & (hashSet.ddictPtrTableSize - 1)
}

/// `ZSTD_DDictHashSet_emplaceDDict()`.
///
/// **Deliberate divergence from the pristine C, confirmed by adversarial
/// review (2026-09-06) rather than assumed:** the C masks *before*
/// incrementing (`idx &= idxRangeMask; idx++;`). Since `idx` starts in
/// `[0, size)` and the mask is a no-op while it stays in range, the probe
/// walks up to exactly `idx == size` (one past the table) before the *next*
/// non-matching probe's mask corrects it -- one step too late. That is two
/// bugs, not one: (1) `table[size]` is read on the loop condition (OOB
/// read), and a non-NULL hit there calls `ZSTD_getDictID_fromDDict` on
/// whatever garbage pointer was there (OOB read + wild deref), and a NULL
/// hit at `size` WRITES `table[size]` (OOB write); (2) once `idx == size`,
/// `size & (size - 1) == 0` for a power-of-two table, so the eventual
/// correction always lands on slot 0 -- slot 0 is never re-probed after a
/// wrap, so the structure can fail to find a slot that provably exists,
/// not just on a rare edge. Fixed here as `idx += 1; idx &= idxRangeMask;`
/// (increment before mask), the ordinary and correct linear-probe
/// wraparound. This is GOALS.md's "the C is a reference, not a
/// specification" cutting the normal way, not the `ZSTD_limitCopy`-class
/// exception: **confirmed dead code, not merely untested** -- reaching this
/// requires `dctx->refMultipleDDicts` set via
/// `ZSTD_DCtx_setParameter(ZSTD_d_refMultipleDDicts)`, and neither that
/// function nor `ZSTD_DCtx_refDDict` is among `zstd_decompress_module.c`'s
/// 17 exported symbols -- the setter isn't in the kernel's zstd API at all,
/// in-tree or out. `ddictSet` is permanently NULL in every build this
/// project produces. Likely an upstream (facebook/zstd) bug independent of
/// this port; a candidate for the same hold-until-end upstream queue as
/// `upstream/zlib-inflate-oob/`, not filed yet.
///
/// The `debug_assert!` on every `idx` used to index the table is a
/// documented backstop, not a live safety net: with the corrected order
/// `idx < ddictPtrTableSize` is a proven invariant, not a runtime
/// possibility, mirroring the C's own `assert()` here compiling out at
/// `DEBUGLEVEL 0` (same reasoning `inffast_rs.rs` already applies).
///
/// # Safety
/// `hashSet` and `ddict` must be valid for reads; `hashSet` for writes too.
unsafe fn ZSTD_DDictHashSet_emplaceDDict(hashSet: *mut DDictHashSet, ddict: *const c_void) -> usize {
    // SAFETY: class B (boundary). The caller guarantees `ddict` is valid.
    let dictID = unsafe { ZSTD_getDictID_fromDDict(ddict) };
    // SAFETY: class B (boundary). The caller guarantees `hashSet` is valid.
    let mut idx = unsafe { ZSTD_DDictHashSet_getIndex(hashSet, dictID) };
    // SAFETY: class B (boundary).
    let hs = unsafe { &mut *hashSet };
    let idxRangeMask = hs.ddictPtrTableSize - 1;
    if hs.ddictPtrCount == hs.ddictPtrTableSize {
        return ERROR(ZSTD_error_GENERIC);
    }
    loop {
        debug_assert!(idx < hs.ddictPtrTableSize, "DDict hash set probe ran off the table");
        // SAFETY: class C (construction). `idx < ddictPtrTableSize` is a
        // proven invariant of the corrected wraparound below, and
        // `ddictPtrTable` is `ddictPtrTableSize` pointers long by
        // construction (see `_expand`/`_createDDictHashSet`).
        let slot = unsafe { *hs.ddictPtrTable.add(idx) };
        if slot.is_null() {
            break;
        }
        // SAFETY: class B (boundary). `slot` is a live `ZSTD_DDict*`
        // previously inserted into this table.
        if unsafe { ZSTD_getDictID_fromDDict(slot) } == dictID {
            // SAFETY: as above.
            unsafe { *hs.ddictPtrTable.add(idx) = ddict };
            return 0;
        }
        idx += 1;
        idx &= idxRangeMask;
    }
    // SAFETY: class C (construction). As the debug_assert above.
    unsafe { *hs.ddictPtrTable.add(idx) = ddict };
    hs.ddictPtrCount += 1;
    0
}

/// `ZSTD_DDictHashSet_expand()`.
///
/// # Safety
/// `hashSet` must be valid for reads and writes.
unsafe fn ZSTD_DDictHashSet_expand(hashSet: *mut DDictHashSet, customMem: ZstdCustomMem) -> usize {
    // SAFETY: class B (boundary).
    let hs = unsafe { &mut *hashSet };
    let newTableSize = hs.ddictPtrTableSize * DDICT_HASHSET_RESIZE_FACTOR;
    // SAFETY: class B (boundary). `customMem`'s contract, if set.
    let newTable = unsafe {
        ZSTD_customCalloc(newTableSize * core::mem::size_of::<*const c_void>(), customMem)
    } as *mut *const c_void;
    let oldTable = hs.ddictPtrTable;
    let oldTableSize = hs.ddictPtrTableSize;
    if newTable.is_null() {
        return ERROR(ZSTD_error_memory_allocation);
    }
    hs.ddictPtrTable = newTable;
    hs.ddictPtrTableSize = newTableSize;
    hs.ddictPtrCount = 0;
    for i in 0..oldTableSize {
        // SAFETY: class C (construction). `i < oldTableSize`, and
        // `oldTable` was `oldTableSize` pointers long.
        let entry = unsafe { *oldTable.add(i) };
        if !entry.is_null() {
            // SAFETY: class B (boundary). `hashSet` (now pointing at the
            // freshly-allocated, larger table) and `entry` are both valid.
            let r = unsafe { ZSTD_DDictHashSet_emplaceDDict(hashSet, entry) };
            if ZSTD_isError(r) != 0 {
                return r;
            }
        }
    }
    // SAFETY: class B (boundary). `oldTable` was allocated by
    // `ZSTD_customCalloc` with this same `customMem` (or is the initial
    // table from `_createDDictHashSet`, same allocator).
    unsafe { ZSTD_customFree(oldTable as *mut c_void, customMem) };
    0
}

/// `ZSTD_DDictHashSet_getDDict()`.
///
/// Same corrected wraparound as `_emplaceDDict` (see its doc comment for
/// the full account of the two upstream bugs this fixes); same
/// `debug_assert!` backstop, same reasoning.
///
/// # Safety
/// `hashSet` must be valid for reads.
unsafe fn ZSTD_DDictHashSet_getDDict(hashSet: *mut DDictHashSet, dictID: u32) -> *const c_void {
    // SAFETY: class B (boundary).
    let mut idx = unsafe { ZSTD_DDictHashSet_getIndex(hashSet, dictID) };
    // SAFETY: class B (boundary).
    let hs = unsafe { &*hashSet };
    let idxRangeMask = hs.ddictPtrTableSize - 1;
    loop {
        debug_assert!(idx < hs.ddictPtrTableSize, "DDict hash set probe ran off the table");
        // SAFETY: class C (construction). As `_emplaceDDict`.
        let slot = unsafe { *hs.ddictPtrTable.add(idx) };
        // SAFETY: class B (boundary). `slot`, if non-null, is a live
        // `ZSTD_DDict*` previously inserted into this table.
        let currDictID = if slot.is_null() { 0 } else { unsafe { ZSTD_getDictID_fromDDict(slot) } };
        if currDictID == dictID || currDictID == 0 {
            return slot;
        }
        idx += 1;
        idx &= idxRangeMask;
    }
}

/// `ZSTD_createDDictHashSet()`.
///
/// # Safety
/// `customMem`'s function pointers, if set, must be safe to call.
unsafe fn ZSTD_createDDictHashSet(customMem: ZstdCustomMem) -> *mut DDictHashSet {
    // SAFETY: class B (boundary).
    let ret = unsafe {
        ZSTD_customMalloc(core::mem::size_of::<DDictHashSet>(), customMem)
    } as *mut DDictHashSet;
    if ret.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary). `ret` was just allocated, large enough,
    // and not yet read.
    let table = unsafe {
        ZSTD_customCalloc(DDICT_HASHSET_TABLE_BASE_SIZE * core::mem::size_of::<*const c_void>(), customMem)
    } as *mut *const c_void;
    if table.is_null() {
        // SAFETY: class B (boundary). `ret` was allocated with this same
        // `customMem`.
        unsafe { ZSTD_customFree(ret as *mut c_void, customMem) };
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary). `ret` is a live, uninitialized allocation
    // exactly `size_of::<DDictHashSet>()` bytes.
    unsafe {
        (*ret).ddictPtrTable = table;
        (*ret).ddictPtrTableSize = DDICT_HASHSET_TABLE_BASE_SIZE;
        (*ret).ddictPtrCount = 0;
    }
    ret
}

/// `ZSTD_freeDDictHashSet()`.
///
/// # Safety
/// `hashSet`, if non-null, must be valid for reads and writes and must not
/// be used again afterwards; `customMem` must match the allocator used to
/// create it.
unsafe fn ZSTD_freeDDictHashSet(hashSet: *mut DDictHashSet, customMem: ZstdCustomMem) {
    if hashSet.is_null() {
        return;
    }
    // SAFETY: class B (boundary).
    let table = unsafe { (*hashSet).ddictPtrTable };
    if !table.is_null() {
        // SAFETY: class B (boundary).
        unsafe { ZSTD_customFree(table as *mut c_void, customMem) };
    }
    // SAFETY: class B (boundary).
    unsafe { ZSTD_customFree(hashSet as *mut c_void, customMem) };
}

/// `ZSTD_DDictHashSet_addDDict()`.
///
/// # Safety
/// `hashSet` and `ddict` must be valid for reads; `hashSet` for writes too.
unsafe fn ZSTD_DDictHashSet_addDDict(hashSet: *mut DDictHashSet, ddict: *const c_void, customMem: ZstdCustomMem) -> usize {
    // SAFETY: class B (boundary).
    let hs = unsafe { &*hashSet };
    if hs.ddictPtrCount * DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT / hs.ddictPtrTableSize
        * DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT
        != 0
    {
        // SAFETY: class B (boundary).
        let r = unsafe { ZSTD_DDictHashSet_expand(hashSet, customMem) };
        if ZSTD_isError(r) != 0 {
            return r;
        }
    }
    // SAFETY: class B (boundary).
    unsafe { ZSTD_DDictHashSet_emplaceDDict(hashSet, ddict) }
}

// ---------------------------------------------------------------------------
// Context management.
// ---------------------------------------------------------------------------

/// `ZSTD_sizeof_DCtx()`. Purely informational (a caller's memory-accounting
/// query, never used for a bounds decision anywhere in this file), so a
/// wrapped total that's technically wrong under an implausible multi-exabyte
/// buffer is harmless -- strictly better than a panic on a diagnostic-only
/// path. `dctx == NULL` returns 0, matching `sizeof NULL` support in the C.
///
/// # Safety
/// `dctx`, if non-null, must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_sizeof_DCtx(dctx: *const ZstdDCtx) -> usize {
    if dctx.is_null() {
        return 0;
    }
    // SAFETY: class B (boundary). `dctx` is non-null and the caller
    // guarantees it is valid.
    let d = unsafe { &*dctx };
    // SAFETY: class B (boundary). `d.ddictLocal` is either null (accepted
    // by `ZSTD_sizeof_DDict`, mirroring `ZSTD_sizeof_DCtx`'s own NULL
    // support) or a live `ZSTD_DDict*` this context owns.
    let ddictSize = unsafe { ZSTD_sizeof_DDict(d.ddictLocal) };
    core::mem::size_of::<ZstdDCtx>()
        .wrapping_add(ddictSize)
        .wrapping_add(d.inBuffSize)
        .wrapping_add(d.outBuffSize)
}

/// `ZSTD_estimateDCtxSize()`.
#[no_mangle]
pub extern "C" fn ZSTD_estimateDCtxSize() -> usize {
    core::mem::size_of::<ZstdDCtx>()
}

/// `ZSTD_startingInputLength()`. The C's `assert()` here just restates the
/// precondition every caller already satisfies (`format` is always one of
/// the two values `ZSTD_FRAMEHEADERSIZE_PREFIX` handles) -- dropped, not
/// promoted, since nothing downstream depends on the assert having fired.
fn ZSTD_startingInputLength(format: u32) -> usize {
    ZSTD_FRAMEHEADERSIZE_PREFIX(format)
}

/// `ZSTD_DCtx_resetParameters()`. The C's `assert(dctx->streamStage == zdss_init)`
/// restates a precondition every caller already checks with a real
/// `RETURN_ERROR_IF` before calling this -- dropped.
///
/// # Safety
/// `dctx` must be valid for writes.
unsafe fn ZSTD_DCtx_resetParameters(dctx: *mut ZstdDCtx) {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.format = ZSTD_f_zstd1;
    d.maxWindowSize = ZSTD_MAXWINDOWSIZE_DEFAULT;
    d.outBufferMode = ZSTD_bm_buffered;
    d.forceIgnoreChecksum = ZSTD_d_validateChecksum;
    d.refMultipleDDicts = ZSTD_rmd_refSingleDDict;
    d.disableHufAsm = 0;
    d.maxBlockSizeParam = 0;
}

/// `ZSTD_initDCtx_internal()`.
///
/// # Safety
/// `dctx` must be valid for writes and at least `size_of::<ZstdDCtx>()`
/// bytes.
unsafe fn ZSTD_initDCtx_internal(dctx: *mut ZstdDCtx) {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.staticSize = 0;
    d.ddict = core::ptr::null();
    d.ddictLocal = core::ptr::null_mut();
    d.dictEnd = core::ptr::null();
    d.ddictIsCold = 0;
    d.dictUses = ZSTD_dont_use;
    d.inBuff = core::ptr::null_mut();
    d.inBuffSize = 0;
    d.outBuffSize = 0;
    d.streamStage = zdss_init;
    d.noForwardProgress = 0;
    d.oversizedDuration = 0;
    d.isFrameDecompression = 1;
    #[cfg(DYNAMIC_BMI2)]
    {
        // ZSTD_cpuSupportsBmi2() -- always true on every build this project
        // produces (x86-64, `-Ctarget-cpu=native` with a Haswell-or-later
        // host under CONFIG_X86_NATIVE_CPU=y; see huf_decompress_rs.rs's
        // DYNAMIC_BMI2 module doc for the measurement). Left as a real
        // runtime check rather than hardcoded, since a non-native-CPU
        // config would need this to actually detect.
        d.bmi2 = zstd_cpu_supports_bmi2() as c_int;
    }
    d.ddictSet = core::ptr::null_mut();
    // SAFETY: class B (boundary). `dctx` is valid, as the caller's contract.
    unsafe { ZSTD_DCtx_resetParameters(dctx) };
}

#[cfg(DYNAMIC_BMI2)]
#[inline(always)]
fn zstd_cpu_supports_bmi2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        core::is_x86_feature_detected!("bmi2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// `ZSTD_initStaticDCtx()`.
///
/// # Safety
/// `workspace .. workspace + workspaceSize` must be valid for reads and
/// writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initStaticDCtx(workspace: *mut c_void, workspaceSize: usize) -> *mut ZstdDCtx {
    let dctx = workspace as *mut ZstdDCtx;
    if (workspace as usize) & 7 != 0 {
        return core::ptr::null_mut();
    }
    if workspaceSize < core::mem::size_of::<ZstdDCtx>() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary). `workspace` is at least `size_of::<ZstdDCtx>()`
    // bytes, 8-aligned, per the checks just above.
    unsafe { ZSTD_initDCtx_internal(dctx) };
    // SAFETY: class B (boundary). `dctx` is valid.
    let d = unsafe { &mut *dctx };
    d.staticSize = workspaceSize;
    // dctx->inBuff = (char*)(dctx+1) -- the remainder of the workspace,
    // right after the ZstdDCtx struct itself.
    d.inBuff = dctx.wrapping_add(1) as *mut c_char;
    dctx
}

/// `ZSTD_createDCtx_internal()`.
///
/// # Safety
/// `customMem`'s function pointers, if set, must be safe to call.
unsafe fn ZSTD_createDCtx_internal(customMem: ZstdCustomMem) -> *mut ZstdDCtx {
    if customMem.customAlloc.is_none() != customMem.customFree.is_none() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary).
    let dctx = unsafe {
        ZSTD_customMalloc(core::mem::size_of::<ZstdDCtx>(), customMem)
    } as *mut ZstdDCtx;
    if dctx.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary). `dctx` was just allocated, large enough.
    unsafe {
        (*dctx).customMem = customMem;
        ZSTD_initDCtx_internal(dctx);
    }
    dctx
}

/// `ZSTD_createDCtx_advanced()`.
///
/// # Safety
/// As [`ZSTD_createDCtx_internal`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_createDCtx_advanced(customMem: ZstdCustomMem) -> *mut ZstdDCtx {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_createDCtx_internal(customMem) }
}

/// `ZSTD_createDCtx()`. See module docs #1: with `ZSTD_defaultCMem`, this
/// context's first real allocation always fails in this kernel.
#[no_mangle]
pub extern "C" fn ZSTD_createDCtx() -> *mut ZstdDCtx {
    // SAFETY: `ZSTD_defaultCMem`'s function pointers are both `None`, so
    // `ZSTD_createDCtx_internal`'s only unsafe operation (calling them) is
    // never reached.
    unsafe { ZSTD_createDCtx_internal(ZSTD_defaultCMem) }
}

/// `ZSTD_clearDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
unsafe fn ZSTD_clearDict(dctx: *mut ZstdDCtx) {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    // SAFETY: class B (boundary). `d.ddictLocal` is either null (accepted
    // by `ZSTD_freeDDict`) or a live `ZSTD_DDict*` this context owns.
    unsafe { ZSTD_freeDDict(d.ddictLocal) };
    d.ddictLocal = core::ptr::null_mut();
    d.ddict = core::ptr::null();
    d.dictUses = ZSTD_dont_use;
}

/// `ZSTD_freeDCtx()`.
///
/// # Safety
/// `dctx`, if non-null, must be valid for reads and writes and must not be
/// used again afterwards (unless it was a static context -- see the C's own
/// "not compatible with static DCtx" error, preserved here).
#[no_mangle]
pub unsafe extern "C" fn ZSTD_freeDCtx(dctx: *mut ZstdDCtx) -> usize {
    if dctx.is_null() {
        return 0;
    }
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if d.staticSize != 0 {
        return ERROR(ZSTD_error_memory_allocation);
    }
    let cMem = d.customMem;
    // SAFETY: class B (boundary).
    unsafe { ZSTD_clearDict(dctx) };
    // Reborrowed fresh after the call above, which itself reborrows `*dctx`
    // through the raw pointer -- not reusing the `d` from before the call,
    // per the adversarial reborrow-aliasing review (2026-09-06).
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    // SAFETY: class B (boundary). `d.inBuff` is either null (accepted by
    // `ZSTD_customFree`) or a live allocation from this same `cMem`.
    unsafe { ZSTD_customFree(d.inBuff as *mut c_void, cMem) };
    d.inBuff = core::ptr::null_mut();
    if !d.ddictSet.is_null() {
        // SAFETY: class B (boundary). `d.ddictSet` is a live `DDictHashSet`
        // allocated with this same `cMem`.
        unsafe { ZSTD_freeDDictHashSet(d.ddictSet, cMem) };
        d.ddictSet = core::ptr::null_mut();
    }
    // SAFETY: class B (boundary). `dctx` is either heap-allocated with this
    // same `cMem` (the only way to reach here with `staticSize == 0`).
    unsafe { ZSTD_customFree(dctx as *mut c_void, cMem) };
    0
}

/// `ZSTD_copyDCtx()`. "no longer useful", per the C's own comment -- kept,
/// faithfully, as part of the public API surface.
///
/// # Safety
/// `dstDCtx` and `srcDCtx` must be valid for the byte range copied
/// (everything before `inBuff` in the struct's field order).
#[no_mangle]
pub unsafe extern "C" fn ZSTD_copyDCtx(dstDCtx: *mut ZstdDCtx, srcDCtx: *const ZstdDCtx) {
    let toCopy = core::mem::offset_of!(ZstdDCtx, inBuff);
    // SAFETY: class B (boundary). Both pointers are valid for `toCopy`
    // bytes -- `toCopy < size_of::<ZstdDCtx>()`, and both are real
    // `ZstdDCtx` allocations per the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(srcDCtx as *const u8, dstDCtx as *mut u8, toCopy) };
}

/// `ZSTD_DCtx_selectFrameDDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
unsafe fn ZSTD_DCtx_selectFrameDDict(dctx: *mut ZstdDCtx) {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    // Promoted from the C's `assert()`, not dropped: the very next branch
    // dereferences `d.ddictSet` through `ZSTD_DDictHashSet_getDDict`, and a
    // null `ddictSet` there would be a null-pointer deref (UB), not a
    // panic. This project's kernel build enables overflow-checks but not
    // debug-assertions, so a `debug_assert!` here would compile away in the
    // shipped kernel while still passing every differential-harness run --
    // a false-negative safety net. A real `assert!` stays live in both.
    assert!(
        d.refMultipleDDicts != 0 && !d.ddictSet.is_null(),
        "ZSTD_DCtx_selectFrameDDict called without multi-DDict mode active"
    );
    if !d.ddict.is_null() {
        // SAFETY: class B (boundary). `d.ddictSet` is live, just asserted.
        let frameDDict = unsafe { ZSTD_DDictHashSet_getDDict(d.ddictSet, d.fParams.dictID) };
        if !frameDDict.is_null() {
            // SAFETY: class B (boundary).
            unsafe { ZSTD_clearDict(dctx) };
            let d = unsafe { &mut *dctx };
            d.dictID = d.fParams.dictID;
            d.ddict = frameDDict;
            d.dictUses = ZSTD_use_indefinitely;
        }
    }
}

// ---------------------------------------------------------------------------
// Frame header decoding.
// ---------------------------------------------------------------------------

/// `ZSTD_isFrame()`.
///
/// # Safety
/// `buffer .. buffer + size` must be readable if `size >= ZSTD_FRAMEIDSIZE`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_isFrame(buffer: *const c_void, size: usize) -> c_uint {
    if size < ZSTD_FRAMEIDSIZE {
        return 0;
    }
    // SAFETY: class B (boundary). `size >= ZSTD_FRAMEIDSIZE` (4) was just
    // checked.
    let magic = unsafe { MEM_readLE32(buffer as *const u8) };
    if magic == ZSTD_MAGICNUMBER {
        return 1;
    }
    if (magic & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
        return 1;
    }
    0
}

/// `ZSTD_isSkippableFrame()`.
///
/// # Safety
/// As [`ZSTD_isFrame`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_isSkippableFrame(buffer: *const c_void, size: usize) -> c_uint {
    if size < ZSTD_FRAMEIDSIZE {
        return 0;
    }
    // SAFETY: class B (boundary). As `ZSTD_isFrame`.
    let magic = unsafe { MEM_readLE32(buffer as *const u8) };
    ((magic & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START) as c_uint
}

/// `ZSTD_frameHeaderSize_internal()`. Every term is small (`minInputSize`
/// <= 5, the flags 0/1, the two field-size table lookups <= 8) so the sum
/// cannot approach `usize` overflow; plain `+`, matching the C's own
/// implicit assumption.
///
/// # Safety
/// `src .. src + srcSize` must be readable if `srcSize >= minInputSize`,
/// where `minInputSize` is `ZSTD_startingInputLength(format)`.
unsafe fn ZSTD_frameHeaderSize_internal(src: *const c_void, srcSize: usize, format: u32) -> usize {
    let minInputSize = ZSTD_startingInputLength(format);
    if srcSize < minInputSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary). `srcSize >= minInputSize >= 1`, so byte
    // `minInputSize - 1` is in bounds.
    let fhd = unsafe { *(src as *const u8).add(minInputSize - 1) };
    let dictID = (fhd & 3) as usize;
    let singleSegment = (fhd >> 5) & 1;
    let fcsId = (fhd >> 6) as usize;
    minInputSize
        + (1 - singleSegment as usize)
        + ZSTD_did_fieldSize[dictID]
        + ZSTD_fcs_fieldSize[fcsId]
        + ((singleSegment != 0 && fcsId == 0) as usize)
}

/// `ZSTD_frameHeaderSize()`.
///
/// # Safety
/// As `ZSTD_frameHeaderSize_internal` with `format == ZSTD_f_zstd1`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_frameHeaderSize(src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_frameHeaderSize_internal(src, srcSize, ZSTD_f_zstd1) }
}

/// `ZSTD_getFrameHeader_advanced()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable; `zfhPtr` must be valid for
/// writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getFrameHeader_advanced(
    zfhPtr: *mut ZstdFrameHeader,
    src: *const c_void,
    srcSize: usize,
    format: u32,
) -> usize {
    let ip = src as *const u8;
    let minInputSize = ZSTD_startingInputLength(format);

    if srcSize > 0 && src.is_null() {
        return ERROR(ZSTD_error_GENERIC);
    }
    if srcSize < minInputSize {
        if srcSize > 0 && format != ZSTD_f_zstd1_magicless {
            let toCopy = MIN_usize(4, srcSize);
            let mut hbuf = [0u8; 4];
            // SAFETY: class B (boundary). `toCopy <= 4` and `toCopy <= srcSize`.
            unsafe {
                MEM_writeLE32(hbuf.as_mut_ptr(), ZSTD_MAGICNUMBER);
                core::ptr::copy_nonoverlapping(ip, hbuf.as_mut_ptr(), toCopy);
            }
            // SAFETY: class C (construction). `hbuf` is 4 bytes.
            if unsafe { MEM_readLE32(hbuf.as_ptr()) } != ZSTD_MAGICNUMBER {
                // SAFETY: as above.
                unsafe {
                    MEM_writeLE32(hbuf.as_mut_ptr(), ZSTD_MAGIC_SKIPPABLE_START);
                    core::ptr::copy_nonoverlapping(ip, hbuf.as_mut_ptr(), toCopy);
                }
                // SAFETY: as above.
                if (unsafe { MEM_readLE32(hbuf.as_ptr()) } & ZSTD_MAGIC_SKIPPABLE_MASK) != ZSTD_MAGIC_SKIPPABLE_START {
                    return ERROR(ZSTD_error_prefix_unknown);
                }
            }
        }
        return minInputSize;
    }

    // SAFETY: class B (boundary). `zfhPtr` is valid for writes.
    unsafe { core::ptr::write_bytes(zfhPtr, 0, 1) };
    // SAFETY: class B (boundary). `srcSize >= minInputSize >= 1`.
    let magic = unsafe { MEM_readLE32(ip) };
    if format != ZSTD_f_zstd1_magicless && magic != ZSTD_MAGICNUMBER {
        if (magic & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            if srcSize < ZSTD_SKIPPABLEHEADERSIZE {
                return ZSTD_SKIPPABLEHEADERSIZE;
            }
            // SAFETY: class B (boundary).
            unsafe { core::ptr::write_bytes(zfhPtr, 0, 1) };
            // SAFETY: class B (boundary). `zfhPtr` just zeroed and valid.
            let zfh = unsafe { &mut *zfhPtr };
            zfh.frameType = ZSTD_skippableFrame;
            zfh.dictID = magic.wrapping_sub(ZSTD_MAGIC_SKIPPABLE_START);
            zfh.headerSize = ZSTD_SKIPPABLEHEADERSIZE as u32;
            // SAFETY: class B (boundary). `srcSize >= ZSTD_SKIPPABLEHEADERSIZE`
            // (8), so bytes `[4, 8)` are in range.
            zfh.frameContentSize = unsafe { MEM_readLE32(ip.add(ZSTD_FRAMEIDSIZE)) } as u64;
            return 0;
        }
        return ERROR(ZSTD_error_prefix_unknown);
    }

    // SAFETY: class B (boundary). `srcSize >= minInputSize`.
    let fhsize = unsafe { ZSTD_frameHeaderSize_internal(src, srcSize, format) };
    if ZSTD_isError(fhsize) != 0 {
        return fhsize;
    }
    if srcSize < fhsize {
        return fhsize;
    }
    // SAFETY: class B (boundary).
    unsafe { (*zfhPtr).headerSize = fhsize as u32 };

    // SAFETY: class B (boundary). `srcSize >= minInputSize >= 1`.
    let fhdByte = unsafe { *ip.add(minInputSize - 1) };
    let mut pos = minInputSize;
    let dictIDSizeCode = fhdByte & 3;
    let checksumFlag = ((fhdByte >> 2) & 1) as u32;
    let singleSegment = (fhdByte >> 5) & 1;
    let fcsID = fhdByte >> 6;
    let mut windowSize: u64 = 0;
    let mut dictID: u32 = 0;
    let mut frameContentSize: u64 = ZSTD_CONTENTSIZE_UNKNOWN;

    if (fhdByte & 0x08) != 0 {
        return ERROR(ZSTD_error_frameParameter_unsupported);
    }

    if singleSegment == 0 {
        // SAFETY: class B (boundary). `fhsize` (already checked `<= srcSize`)
        // includes this byte at `pos == minInputSize` per
        // `ZSTD_frameHeaderSize_internal`'s own accounting.
        let wlByte = unsafe { *ip.add(pos) };
        pos += 1;
        let windowLog = ((wlByte >> 3) as c_int) + ZSTD_WINDOWLOG_ABSOLUTEMIN;
        if windowLog > ZSTD_WINDOWLOG_MAX {
            return ERROR(ZSTD_error_frameParameter_windowTooLarge);
        }
        windowSize = 1u64 << windowLog;
        windowSize += (windowSize >> 3) * ((wlByte & 7) as u64);
    }
    match dictIDSizeCode {
        0 => {}
        1 => {
            // SAFETY: class B (boundary). Within `fhsize`, as above.
            dictID = unsafe { *ip.add(pos) } as u32;
            pos += 1;
        }
        2 => {
            // SAFETY: class B (boundary).
            dictID = unsafe { MEM_readLE16(ip.add(pos)) } as u32;
            pos += 2;
        }
        _ => {
            // SAFETY: class B (boundary).
            dictID = unsafe { MEM_readLE32(ip.add(pos)) };
            pos += 4;
        }
    }
    match fcsID {
        0 => {
            if singleSegment != 0 {
                // SAFETY: class B (boundary).
                frameContentSize = unsafe { *ip.add(pos) } as u64;
            }
        }
        1 => {
            // SAFETY: class B (boundary).
            frameContentSize = (unsafe { MEM_readLE16(ip.add(pos)) } as u64).wrapping_add(256);
        }
        2 => {
            // SAFETY: class B (boundary).
            frameContentSize = unsafe { MEM_readLE32(ip.add(pos)) } as u64;
        }
        _ => {
            // SAFETY: class B (boundary).
            frameContentSize = unsafe { MEM_readLE64(ip.add(pos)) };
        }
    }
    if singleSegment != 0 {
        windowSize = frameContentSize;
    }

    // SAFETY: class B (boundary). `zfhPtr` is valid for writes.
    let zfh = unsafe { &mut *zfhPtr };
    zfh.frameType = ZSTD_frame;
    zfh.frameContentSize = frameContentSize;
    zfh.windowSize = windowSize;
    zfh.blockSizeMax = MIN_u64(windowSize, ZSTD_BLOCKSIZE_MAX as u64) as u32;
    zfh.dictID = dictID;
    zfh.checksumFlag = checksumFlag;
    0
}

/// `ZSTD_getFrameHeader()`.
///
/// # Safety
/// As `ZSTD_getFrameHeader_advanced` with `format == ZSTD_f_zstd1`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getFrameHeader(zfhPtr: *mut ZstdFrameHeader, src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_getFrameHeader_advanced(zfhPtr, src, srcSize, ZSTD_f_zstd1) }
}

/// `ZSTD_getFrameContentSize()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getFrameContentSize(src: *const c_void, srcSize: usize) -> u64 {
    let mut zfh = core::mem::MaybeUninit::<ZstdFrameHeader>::uninit();
    // SAFETY: class B (boundary), forwarded; `zfh` is valid for writes.
    if unsafe { ZSTD_getFrameHeader(zfh.as_mut_ptr(), src, srcSize) } != 0 {
        return ZSTD_CONTENTSIZE_ERROR;
    }
    // SAFETY: class C (construction). `ZSTD_getFrameHeader` returned 0,
    // meaning `zfh` was fully written.
    let zfh = unsafe { zfh.assume_init() };
    if zfh.frameType == ZSTD_skippableFrame {
        0
    } else {
        zfh.frameContentSize
    }
}

/// `readSkippableFrameSize()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable if `srcSize >= ZSTD_SKIPPABLEHEADERSIZE`.
unsafe fn readSkippableFrameSize(src: *const c_void, srcSize: usize) -> usize {
    if srcSize < ZSTD_SKIPPABLEHEADERSIZE {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary). `srcSize >= ZSTD_SKIPPABLEHEADERSIZE` (8).
    let sizeU32 = unsafe { MEM_readLE32((src as *const u8).add(ZSTD_FRAMEIDSIZE)) };
    // Overflow check kept, not wrapped: this is exactly the guard the C
    // computes it for -- `(U32)(sizeU32 + ZSTD_SKIPPABLEHEADERSIZE) < sizeU32`
    // detects the u32 wraparound the C's own arithmetic relies on, so a
    // Rust panic here would fire on the SAME adversarial input the C
    // catches, not on a new one. Reimplemented as a checked add.
    let wrapped = (sizeU32 as u64).wrapping_add(ZSTD_SKIPPABLEHEADERSIZE as u64) as u32;
    if wrapped < sizeU32 {
        return ERROR(ZSTD_error_frameParameter_unsupported);
    }
    let skippableSize = ZSTD_SKIPPABLEHEADERSIZE.wrapping_add(sizeU32 as usize);
    if skippableSize > srcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    skippableSize
}

/// `ZSTD_readSkippableFrame()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable; `dst .. dst + dstCapacity` must
/// be writable if non-null; `magicVariant`, if non-null, must be valid for
/// writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_readSkippableFrame(
    dst: *mut c_void,
    dstCapacity: usize,
    magicVariant: *mut c_uint,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    if srcSize < ZSTD_SKIPPABLEHEADERSIZE {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary).
    let magicNumber = unsafe { MEM_readLE32(src as *const u8) };
    // SAFETY: class B (boundary), forwarded.
    let skippableFrameSize = unsafe { readSkippableFrameSize(src, srcSize) };
    if ZSTD_isError(skippableFrameSize) != 0 {
        return skippableFrameSize;
    }
    let skippableContentSize = skippableFrameSize.wrapping_sub(ZSTD_SKIPPABLEHEADERSIZE);

    // SAFETY: class B (boundary), forwarded.
    if unsafe { ZSTD_isSkippableFrame(src, srcSize) } == 0 {
        return ERROR(ZSTD_error_frameParameter_unsupported);
    }
    if skippableFrameSize < ZSTD_SKIPPABLEHEADERSIZE || skippableFrameSize > srcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    if skippableContentSize > dstCapacity {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }

    if skippableContentSize > 0 && !dst.is_null() {
        // SAFETY: class B (boundary). `skippableContentSize <= dstCapacity`
        // and `skippableFrameSize <= srcSize`, so both ranges are in bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (src as *const u8).add(ZSTD_SKIPPABLEHEADERSIZE),
                dst as *mut u8,
                skippableContentSize,
            )
        };
    }
    if !magicVariant.is_null() {
        // SAFETY: class B (boundary).
        unsafe { *magicVariant = magicNumber.wrapping_sub(ZSTD_MAGIC_SKIPPABLE_START) };
    }
    skippableContentSize
}

/// `ZSTD_findDecompressedSize()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_findDecompressedSize(src: *const c_void, srcSize: usize) -> u64 {
    let mut totalDstSize: u64 = 0;
    let mut src = src;
    let mut srcSize = srcSize;
    while srcSize >= ZSTD_startingInputLength(ZSTD_f_zstd1) {
        // SAFETY: class B (boundary). `srcSize >= 4` here.
        let magicNumber = unsafe { MEM_readLE32(src as *const u8) };
        if (magicNumber & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            // SAFETY: class B (boundary), forwarded.
            let skippableSize = unsafe { readSkippableFrameSize(src, srcSize) };
            if ZSTD_isError(skippableSize) != 0 {
                return ZSTD_CONTENTSIZE_ERROR;
            }
            // SAFETY: class B (boundary). `skippableSize <= srcSize`,
            // established by `readSkippableFrameSize`.
            src = unsafe { (src as *const u8).add(skippableSize) as *const c_void };
            srcSize -= skippableSize;
            continue;
        }

        // SAFETY: class B (boundary), forwarded.
        let fcs = unsafe { ZSTD_getFrameContentSize(src, srcSize) };
        if fcs >= ZSTD_CONTENTSIZE_ERROR {
            return fcs;
        }
        if totalDstSize.wrapping_add(fcs) < totalDstSize {
            return ZSTD_CONTENTSIZE_ERROR;
        }
        totalDstSize = totalDstSize.wrapping_add(fcs);

        // SAFETY: class B (boundary), forwarded.
        let frameSrcSize = unsafe { ZSTD_findFrameCompressedSize(src, srcSize) };
        if ZSTD_isError(frameSrcSize) != 0 {
            return ZSTD_CONTENTSIZE_ERROR;
        }
        // SAFETY: class B (boundary). `frameSrcSize <= srcSize`, established
        // by `ZSTD_findFrameCompressedSize`.
        src = unsafe { (src as *const u8).add(frameSrcSize) as *const c_void };
        srcSize -= frameSrcSize;
    }

    if srcSize != 0 {
        return ZSTD_CONTENTSIZE_ERROR;
    }
    totalDstSize
}

/// `ZSTD_getDecompressedSize()`.
///
/// # Safety
/// As `ZSTD_getFrameContentSize`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getDecompressedSize(src: *const c_void, srcSize: usize) -> u64 {
    // SAFETY: class B (boundary), forwarded.
    let ret = unsafe { ZSTD_getFrameContentSize(src, srcSize) };
    if ret >= ZSTD_CONTENTSIZE_ERROR {
        0
    } else {
        ret
    }
}

/// `ZSTD_decodeFrameHeader()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `src .. src + headerSize`
/// must be readable.
unsafe fn ZSTD_decodeFrameHeader(dctx: *mut ZstdDCtx, src: *const c_void, headerSize: usize) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    // SAFETY: class B (boundary), forwarded.
    let result = unsafe { ZSTD_getFrameHeader_advanced(&mut d.fParams, src, headerSize, d.format) };
    if ZSTD_isError(result) != 0 {
        return result;
    }
    if result > 0 {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    if d.refMultipleDDicts == ZSTD_rmd_refMultipleDDicts && !d.ddictSet.is_null() {
        // SAFETY: class B (boundary).
        unsafe { ZSTD_DCtx_selectFrameDDict(dctx) };
    }
    let d = unsafe { &mut *dctx };

    if d.fParams.dictID != 0 && d.dictID != d.fParams.dictID {
        return ERROR(ZSTD_error_dictionary_wrong);
    }
    d.validateChecksum = (d.fParams.checksumFlag != 0 && d.forceIgnoreChecksum == 0) as u32;
    if d.validateChecksum != 0 {
        // SAFETY: class B (boundary).
        unsafe { xxh64_reset(&mut d.xxhState, 0) };
    }
    d.processedCSize = d.processedCSize.wrapping_add(headerSize as u64);
    0
}

// ---------------------------------------------------------------------------
// Frame size / bound functions.
// ---------------------------------------------------------------------------

/// `ZSTD_frameSizeInfo`, `zstd_internal.h:278-282`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ZstdFrameSizeInfo {
    nbBlocks: usize,
    compressedSize: usize,
    decompressedBound: u64,
}

/// `ZSTD_errorFrameSizeInfo()`.
fn ZSTD_errorFrameSizeInfo(ret: usize) -> ZstdFrameSizeInfo {
    ZstdFrameSizeInfo {
        nbBlocks: 0,
        compressedSize: ret,
        decompressedBound: ZSTD_CONTENTSIZE_ERROR,
    }
}

/// `ZSTD_findFrameSizeInfo()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
unsafe fn ZSTD_findFrameSizeInfo(src: *const c_void, srcSize: usize, format: u32) -> ZstdFrameSizeInfo {
    if format == ZSTD_f_zstd1
        && srcSize >= ZSTD_SKIPPABLEHEADERSIZE
        // SAFETY: class B (boundary). `srcSize >= ZSTD_SKIPPABLEHEADERSIZE`
        // (8) >= 4.
        && (unsafe { MEM_readLE32(src as *const u8) } & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
    {
        // SAFETY: class B (boundary), forwarded.
        let compressedSize = unsafe { readSkippableFrameSize(src, srcSize) };
        return ZstdFrameSizeInfo {
            nbBlocks: 0,
            compressedSize,
            decompressedBound: 0,
        };
    }

    let ip = src as *const u8;
    let ipstart = ip;
    let mut remainingSize = srcSize;
    let mut nbBlocks: usize = 0;
    let mut zfh = core::mem::MaybeUninit::<ZstdFrameHeader>::uninit();

    // SAFETY: class B (boundary), forwarded; `zfh` is valid for writes.
    let ret = unsafe { ZSTD_getFrameHeader_advanced(zfh.as_mut_ptr(), src, srcSize, format) };
    if ZSTD_isError(ret) != 0 {
        return ZSTD_errorFrameSizeInfo(ret);
    }
    if ret > 0 {
        return ZSTD_errorFrameSizeInfo(ERROR(ZSTD_error_srcSize_wrong));
    }
    // SAFETY: class C (construction). `ret == 0`, so `zfh` was fully written.
    let zfh = unsafe { zfh.assume_init() };

    // SAFETY: class B (boundary). `zfh.headerSize <= srcSize`, guaranteed
    // by `ZSTD_getFrameHeader_advanced` returning 0.
    let mut ip = unsafe { ip.add(zfh.headerSize as usize) };
    remainingSize -= zfh.headerSize as usize;

    loop {
        let mut blockProperties = BlockProperties::default();
        // SAFETY: class B (boundary). `ip .. ip + remainingSize` is within
        // the caller's `src .. src + srcSize`.
        let cBlockSize = unsafe {
            ZSTD_getcBlockSize(ip as *const c_void, remainingSize, &mut blockProperties)
        };
        if ZSTD_isError(cBlockSize) != 0 {
            return ZSTD_errorFrameSizeInfo(cBlockSize);
        }
        if ZSTD_blockHeaderSize.wrapping_add(cBlockSize) > remainingSize {
            return ZSTD_errorFrameSizeInfo(ERROR(ZSTD_error_srcSize_wrong));
        }
        // SAFETY: class B (boundary). Just checked to be within
        // `remainingSize`.
        ip = unsafe { ip.add(ZSTD_blockHeaderSize + cBlockSize) };
        remainingSize -= ZSTD_blockHeaderSize + cBlockSize;
        nbBlocks += 1;
        if blockProperties.lastBlock != 0 {
            break;
        }
    }

    if zfh.checksumFlag != 0 {
        if remainingSize < 4 {
            return ZSTD_errorFrameSizeInfo(ERROR(ZSTD_error_srcSize_wrong));
        }
        // SAFETY: class B (boundary). `remainingSize >= 4` just checked;
        // the pointer itself does not need to stay valid, only computed.
        ip = unsafe { ip.add(4) };
    }

    ZstdFrameSizeInfo {
        nbBlocks,
        compressedSize: ip as usize - ipstart as usize,
        decompressedBound: if zfh.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN {
            zfh.frameContentSize
        } else {
            nbBlocks as u64 * zfh.blockSizeMax as u64
        },
    }
}

/// `ZSTD_findFrameCompressedSize_advanced()`.
///
/// # Safety
/// As `ZSTD_findFrameSizeInfo`.
unsafe fn ZSTD_findFrameCompressedSize_advanced(src: *const c_void, srcSize: usize, format: u32) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_findFrameSizeInfo(src, srcSize, format) }.compressedSize
}

/// `ZSTD_findFrameCompressedSize()`.
///
/// # Safety
/// As `ZSTD_findFrameSizeInfo` with `format == ZSTD_f_zstd1`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_findFrameCompressedSize(src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_findFrameCompressedSize_advanced(src, srcSize, ZSTD_f_zstd1) }
}

/// `ZSTD_decompressBound()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBound(src: *const c_void, srcSize: usize) -> u64 {
    let mut bound: u64 = 0;
    let mut src = src;
    let mut srcSize = srcSize;
    while srcSize > 0 {
        // SAFETY: class B (boundary), forwarded.
        let frameSizeInfo = unsafe { ZSTD_findFrameSizeInfo(src, srcSize, ZSTD_f_zstd1) };
        let compressedSize = frameSizeInfo.compressedSize;
        let decompressedBound = frameSizeInfo.decompressedBound;
        if ZSTD_isError(compressedSize) != 0 || decompressedBound == ZSTD_CONTENTSIZE_ERROR {
            return ZSTD_CONTENTSIZE_ERROR;
        }
        // SAFETY: class B (boundary). `compressedSize <= srcSize`,
        // established by `ZSTD_findFrameSizeInfo`.
        src = unsafe { (src as *const u8).add(compressedSize) as *const c_void };
        srcSize -= compressedSize;
        bound = bound.wrapping_add(decompressedBound);
    }
    bound
}

/// `ZSTD_decompressionMargin()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressionMargin(src: *const c_void, srcSize: usize) -> usize {
    let mut margin: usize = 0;
    let mut maxBlockSize: u32 = 0;
    let mut src = src;
    let mut srcSize = srcSize;

    while srcSize > 0 {
        // SAFETY: class B (boundary), forwarded.
        let frameSizeInfo = unsafe { ZSTD_findFrameSizeInfo(src, srcSize, ZSTD_f_zstd1) };
        let compressedSize = frameSizeInfo.compressedSize;
        let decompressedBound = frameSizeInfo.decompressedBound;
        let mut zfh = core::mem::MaybeUninit::<ZstdFrameHeader>::uninit();
        // SAFETY: class B (boundary), forwarded.
        let hErr = unsafe { ZSTD_getFrameHeader(zfh.as_mut_ptr(), src, srcSize) };
        // Divergence from the C, deliberately: the C's `FORWARD_IF_ERROR`
        // only returns early on `ZSTD_isError(hErr)`, not on `hErr > 0`
        // ("need more input", `zfhPtr` left unfilled) -- reachable there
        // only via reading `zfh` off the stack uninitialized, since nothing
        // re-checks that case before using it. In practice `hErr > 0` can
        // never happen here: `frameSizeInfo` above already parsed this
        // exact header successfully (its own `ret > 0` case converts to a
        // real error code, caught by the `ZSTD_isError(compressedSize)`
        // check below), so by construction `srcSize` is already enough.
        // But `MaybeUninit::assume_init()` on a genuinely-uninitialized
        // value is UB even before any field is read -- stricter than the
        // C's own UB -- so this checks `hErr != 0` rather than only
        // `ZSTD_isError(hErr)`, closing a gap that is unreachable today
        // without leaving one anyway.
        if hErr != 0 {
            return if ZSTD_isError(hErr) != 0 { hErr } else { ERROR(ZSTD_error_corruption_detected) };
        }
        // SAFETY: class C (construction). `hErr == 0`, so `zfh` was fully
        // written by `ZSTD_getFrameHeader`.
        let zfh = unsafe { zfh.assume_init() };
        if ZSTD_isError(compressedSize) != 0 || decompressedBound == ZSTD_CONTENTSIZE_ERROR {
            return ERROR(ZSTD_error_corruption_detected);
        }

        if zfh.frameType == ZSTD_frame {
            margin = margin.wrapping_add(zfh.headerSize as usize);
            margin = margin.wrapping_add(if zfh.checksumFlag != 0 { 4 } else { 0 });
            margin = margin.wrapping_add(3usize.wrapping_mul(frameSizeInfo.nbBlocks));
            maxBlockSize = maxBlockSize.max(zfh.blockSizeMax);
        } else {
            margin = margin.wrapping_add(compressedSize);
        }

        // SAFETY: class B (boundary). `compressedSize <= srcSize`.
        src = unsafe { (src as *const u8).add(compressedSize) as *const c_void };
        srcSize -= compressedSize;
    }

    margin.wrapping_add(maxBlockSize as usize)
}

// ---------------------------------------------------------------------------
// Frame decoding.
// ---------------------------------------------------------------------------

/// `ZSTD_insertBlock()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_insertBlock(dctx: *mut ZstdDCtx, blockStart: *const c_void, blockSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_checkContinuity(dctx, blockStart, blockSize) };
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.previousDstEnd = (blockStart as *const u8).wrapping_add(blockSize) as *const c_void;
    blockSize
}

/// `ZSTD_copyRawBlock()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable if `dst` is non-null;
/// `dst .. dst + srcSize` must be writable if `dst` is non-null and
/// `srcSize <= dstCapacity`.
unsafe fn ZSTD_copyRawBlock(dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    if srcSize > dstCapacity {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if dst.is_null() {
        if srcSize == 0 {
            return 0;
        }
        return ERROR(ZSTD_error_dstBuffer_null);
    }
    // SAFETY: class B (boundary). `srcSize <= dstCapacity`, checked above;
    // the caller's contract covers the rest. `memmove`, not
    // `copy_nonoverlapping`, since the C uses `ZSTD_memmove` here
    // (in-place decompression can make `src`/`dst` overlap).
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, srcSize) };
    srcSize
}

/// `ZSTD_setRleBlock()`.
///
/// # Safety
/// `dst .. dst + regenSize` must be writable if `dst` is non-null and
/// `regenSize <= dstCapacity`.
unsafe fn ZSTD_setRleBlock(dst: *mut c_void, dstCapacity: usize, b: u8, regenSize: usize) -> usize {
    if regenSize > dstCapacity {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if dst.is_null() {
        if regenSize == 0 {
            return 0;
        }
        return ERROR(ZSTD_error_dstBuffer_null);
    }
    // SAFETY: class B (boundary). `regenSize <= dstCapacity`, checked above.
    unsafe { core::ptr::write_bytes(dst as *mut u8, b, regenSize) };
    regenSize
}

/// `ZSTD_DCtx_trace_end()`. A no-op even in the C (tracepoints are compiled
/// out here) -- dropped entirely rather than ported as an empty function,
/// since nothing calls through a function pointer to reach it.
#[inline(always)]
fn ZSTD_DCtx_trace_end(_dctx: *const ZstdDCtx, _uncompressedSize: u64, _compressedSize: u64, _streaming: c_int) {}

/// `ZSTD_decompressFrame()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `srcPtr`/`srcSizePtr` must be
/// valid for reads and writes, and `*srcPtr .. *srcPtr + *srcSizePtr` must
/// be readable; `dst .. dst + dstCapacity` must be writable.
unsafe fn ZSTD_decompressFrame(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    srcPtr: *mut *const c_void,
    srcSizePtr: *mut usize,
) -> usize {
    // SAFETY: class B (boundary).
    let istart = unsafe { *srcPtr } as *const u8;
    let mut ip = istart;
    let ostart = dst as *mut u8;
    let oend = if dstCapacity != 0 { ostart.wrapping_add(dstCapacity) } else { ostart };
    let mut op = ostart;
    // SAFETY: class B (boundary).
    let mut remainingSrcSize = unsafe { *srcSizePtr };

    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if remainingSrcSize < ZSTD_FRAMEHEADERSIZE_MIN(d.format).wrapping_add(ZSTD_blockHeaderSize) {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    {
        // SAFETY: class B (boundary). `ip .. ip + ZSTD_FRAMEHEADERSIZE_PREFIX(d.format)`
        // is within `remainingSrcSize`, just checked above (>= FRAMEHEADERSIZE_MIN
        // >= FRAMEHEADERSIZE_PREFIX for both formats).
        let frameHeaderSize = unsafe {
            ZSTD_frameHeaderSize_internal(ip as *const c_void, ZSTD_FRAMEHEADERSIZE_PREFIX(d.format), d.format)
        };
        if ZSTD_isError(frameHeaderSize) != 0 {
            return frameHeaderSize;
        }
        if remainingSrcSize < frameHeaderSize.wrapping_add(ZSTD_blockHeaderSize) {
            return ERROR(ZSTD_error_srcSize_wrong);
        }
        // SAFETY: class B (boundary), forwarded.
        let r = unsafe { ZSTD_decodeFrameHeader(dctx, ip as *const c_void, frameHeaderSize) };
        if ZSTD_isError(r) != 0 {
            return r;
        }
        // SAFETY: class B (boundary). Within `remainingSrcSize`, just checked.
        ip = unsafe { ip.add(frameHeaderSize) };
        remainingSrcSize -= frameHeaderSize;
    }

    let d = unsafe { &mut *dctx };
    if d.maxBlockSizeParam != 0 {
        d.fParams.blockSizeMax = MIN_u64(d.fParams.blockSizeMax as u64, d.maxBlockSizeParam as u64) as u32;
    }

    loop {
        let mut oBlockEnd = oend;
        let decodedSize: usize;
        let mut blockProperties = BlockProperties::default();
        // SAFETY: class B (boundary). `ip .. ip + remainingSrcSize` is
        // within the caller's input.
        let cBlockSize = unsafe {
            ZSTD_getcBlockSize(ip as *const c_void, remainingSrcSize, &mut blockProperties)
        };
        if ZSTD_isError(cBlockSize) != 0 {
            return cBlockSize;
        }

        // SAFETY: class B (boundary). `remainingSrcSize >= ZSTD_blockHeaderSize`,
        // guaranteed by every path that reaches this loop (checked before
        // the loop, and re-established at the bottom of each iteration
        // before looping, matching the C's own invariant).
        ip = unsafe { ip.add(ZSTD_blockHeaderSize) };
        remainingSrcSize -= ZSTD_blockHeaderSize;
        if cBlockSize > remainingSrcSize {
            return ERROR(ZSTD_error_srcSize_wrong);
        }

        if (ip as usize) >= (op as usize) && (ip as usize) < (oBlockEnd as usize) {
            // SAFETY: class C (construction). `ip >= op` was just checked,
            // so this is a forward offset from `op`, and `ip < oBlockEnd`
            // bounds it within the output buffer.
            oBlockEnd = op.wrapping_add(ip as usize - op as usize);
        }

        let d = unsafe { &mut *dctx };
        match blockProperties.blockType {
            bt_compressed => {
                debug_assert!(d.isFrameDecompression == 1);
                // SAFETY: class B (boundary). `op .. oBlockEnd` is within
                // the output buffer; `ip .. ip + cBlockSize` within the
                // input, just checked.
                decodedSize = unsafe {
                    ZSTD_decompressBlock_internal(
                        dctx,
                        op as *mut c_void,
                        oBlockEnd as usize - op as usize,
                        ip as *const c_void,
                        cBlockSize,
                        not_streaming,
                    )
                };
            }
            bt_raw => {
                // SAFETY: class B (boundary). Uses `oend`, not `oBlockEnd`
                // -- safe to overlap, per the C's own comment (`memmove`).
                decodedSize = unsafe {
                    ZSTD_copyRawBlock(op as *mut c_void, oend as usize - op as usize, ip as *const c_void, cBlockSize)
                };
            }
            bt_rle => {
                // SAFETY: class B (boundary). `cBlockSize >= 1` is implied
                // by `blockType == bt_rle` (`ZSTD_getcBlockSize`'s own
                // contract -- an RLE block's compressed payload is always
                // exactly one byte).
                decodedSize = unsafe {
                    ZSTD_setRleBlock(op as *mut c_void, oBlockEnd as usize - op as usize, *ip, blockProperties.origSize as usize)
                };
            }
            _ => {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }
        if ZSTD_isError(decodedSize) != 0 {
            return decodedSize;
        }
        // Reborrowed fresh: the match arm above may have called
        // `ZSTD_decompressBlock_internal(dctx, ...)`, itself reborrowing
        // `*dctx` through the raw pointer -- not reusing the `d` from
        // before that call, per the adversarial reborrow-aliasing review
        // (2026-09-06).
        // SAFETY: class B (boundary).
        let d = unsafe { &mut *dctx };
        if d.validateChecksum != 0 {
            // SAFETY: class B (boundary). `op .. op + decodedSize` was just
            // written by the block decoder above.
            unsafe { xxh64_update(&mut d.xxhState, op as *const c_void, decodedSize) };
        }
        if decodedSize != 0 {
            op = op.wrapping_add(decodedSize);
        }
        // SAFETY: class B (boundary). Within `remainingSrcSize`, checked
        // above (`cBlockSize <= remainingSrcSize`).
        ip = unsafe { ip.add(cBlockSize) };
        remainingSrcSize -= cBlockSize;
        if blockProperties.lastBlock != 0 {
            break;
        }
    }

    let d = unsafe { &mut *dctx };
    if d.fParams.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN {
        if (op as usize - ostart as usize) as u64 != d.fParams.frameContentSize {
            return ERROR(ZSTD_error_corruption_detected);
        }
    }
    if d.fParams.checksumFlag != 0 {
        if remainingSrcSize < 4 {
            return ERROR(ZSTD_error_checksum_wrong);
        }
        if d.forceIgnoreChecksum == 0 {
            // SAFETY: class B (boundary).
            let checkCalc = unsafe { xxh64_digest(&d.xxhState) } as u32;
            // SAFETY: class B (boundary). `remainingSrcSize >= 4`, just checked.
            let checkRead = unsafe { MEM_readLE32(ip) };
            if checkRead != checkCalc {
                return ERROR(ZSTD_error_checksum_wrong);
            }
        }
        // SAFETY: class B (boundary). `remainingSrcSize >= 4`.
        ip = unsafe { ip.add(4) };
        remainingSrcSize -= 4;
    }
    // Not a reborrow-aliasing violation today only because ZSTD_DCtx_trace_end
    // is an empty stub that never dereferences `dctx` -- if it ever gains a
    // real body, `d` above would need re-fetching after this call before any
    // further use, same as every other call taking `dctx`/`zds` in this file.
    ZSTD_DCtx_trace_end(dctx, (op as usize - ostart as usize) as u64, (ip as usize - istart as usize) as u64, 0);
    // SAFETY: class B (boundary).
    unsafe {
        *srcPtr = ip as *const c_void;
        *srcSizePtr = remainingSrcSize;
    }
    op as usize - ostart as usize
}

/// `ZSTD_decompressMultiFrame()`. `ZSTD_ALLOW_POINTER_OVERFLOW_ATTR` in the
/// C is a `-fno-strict-overflow`-class attribute with no Rust equivalent or
/// need -- pointer arithmetic here is expressed via `usize` address math
/// throughout this port, which has no analogous UB to suppress.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `src .. src + srcSize` must
/// be readable; `dst .. dst + dstCapacity` must be writable; `dict`, if
/// non-null, `.. dict + dictSize` must be readable; `ddict`, if non-null,
/// must be a live `ZSTD_DDict*`.
unsafe fn ZSTD_decompressMultiFrame(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
    dict: *const c_void,
    dictSize: usize,
    ddict: *const c_void,
) -> usize {
    let dststart = dst;
    let mut dst = dst;
    let mut dstCapacity = dstCapacity;
    let mut moreThan1Frame = false;
    let mut src = src;
    let mut srcSize = srcSize;
    let mut dict = dict;
    let mut dictSize = dictSize;

    debug_assert!(dict.is_null() || ddict.is_null());

    if !ddict.is_null() {
        // SAFETY: class B (boundary), forwarded.
        dict = unsafe { ZSTD_DDict_dictContent(ddict) };
        // SAFETY: class B (boundary), forwarded.
        dictSize = unsafe { ZSTD_DDict_dictSize(ddict) };
    }

    let d = unsafe { &*dctx };
    while srcSize >= ZSTD_startingInputLength(d.format) {
        let d = unsafe { &*dctx };
        if d.format == ZSTD_f_zstd1 && srcSize >= 4 {
            // SAFETY: class B (boundary). `srcSize >= 4`.
            let magicNumber = unsafe { MEM_readLE32(src as *const u8) };
            if (magicNumber & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
                // SAFETY: class B (boundary), forwarded.
                let skippableSize = unsafe { readSkippableFrameSize(src, srcSize) };
                if ZSTD_isError(skippableSize) != 0 {
                    return skippableSize;
                }
                // SAFETY: class B (boundary). `skippableSize <= srcSize`.
                src = unsafe { (src as *const u8).add(skippableSize) as *const c_void };
                srcSize -= skippableSize;
                continue;
            }
        }

        if !ddict.is_null() {
            // SAFETY: class B (boundary), forwarded.
            let r = unsafe { ZSTD_decompressBegin_usingDDict(dctx, ddict) };
            if ZSTD_isError(r) != 0 {
                return r;
            }
        } else {
            // SAFETY: class B (boundary), forwarded.
            let r = unsafe { ZSTD_decompressBegin_usingDict(dctx, dict, dictSize) };
            if ZSTD_isError(r) != 0 {
                return r;
            }
        }
        // SAFETY: class B (boundary), forwarded.
        unsafe { ZSTD_checkContinuity(dctx, dst, dstCapacity) };

        {
            let mut srcMut = src;
            let mut srcSizeMut = srcSize;
            // SAFETY: class B (boundary), forwarded.
            let res = unsafe { ZSTD_decompressFrame(dctx, dst, dstCapacity, &mut srcMut, &mut srcSizeMut) };
            if ZSTD_getErrorCode(res) == ZSTD_error_prefix_unknown && moreThan1Frame {
                return ERROR(ZSTD_error_srcSize_wrong);
            }
            if ZSTD_isError(res) != 0 {
                return res;
            }
            debug_assert!(res <= dstCapacity);
            if res != 0 {
                dst = (dst as *mut u8).wrapping_add(res) as *mut c_void;
            }
            dstCapacity -= res;
            src = srcMut;
            srcSize = srcSizeMut;
        }
        moreThan1Frame = true;
    }

    if srcSize != 0 {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    dst as usize - dststart as usize
}

/// `ZSTD_decompress_usingDict()`.
///
/// # Safety
/// As `ZSTD_decompressMultiFrame` with `ddict == NULL`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompress_usingDict(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
    dict: *const c_void,
    dictSize: usize,
) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_decompressMultiFrame(dctx, dst, dstCapacity, src, srcSize, dict, dictSize, core::ptr::null()) }
}

/// `ZSTD_getDDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
unsafe fn ZSTD_getDDict(dctx: *mut ZstdDCtx) -> *const c_void {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    match d.dictUses {
        ZSTD_dont_use => {
            // SAFETY: class B (boundary), forwarded.
            unsafe { ZSTD_clearDict(dctx) };
            core::ptr::null()
        }
        ZSTD_use_indefinitely => d.ddict,
        ZSTD_use_once => {
            d.dictUses = ZSTD_dont_use;
            d.ddict
        }
        _ => {
            // Unreachable per the C's own `assert(0)`: `dictUses` is only
            // ever set to one of the three values above.
            unreachable!("ZSTD_DCtx::dictUses holds an impossible value")
        }
    }
}

/// `ZSTD_decompressDCtx()`.
///
/// # Safety
/// As `ZSTD_decompress_usingDDict`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressDCtx(dctx: *mut ZstdDCtx, dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let ddict = unsafe { ZSTD_getDDict(dctx) };
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_decompress_usingDDict(dctx, dst, dstCapacity, src, srcSize, ddict) }
}

/// `ZSTD_decompress()`. `ZSTD_HEAPMODE` defaults to (and is never
/// redefined away from) 1 in this tree, so only the heap-allocating arm is
/// ported; the `#else` stack-mode arm is dead code no build compiles.
///
/// # Safety
/// `src .. src + srcSize` must be readable; `dst .. dst + dstCapacity` must
/// be writable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompress(dst: *mut c_void, dstCapacity: usize, src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: `ZSTD_defaultCMem`'s function pointers are both `None`.
    let dctx = unsafe { ZSTD_createDCtx_internal(ZSTD_defaultCMem) };
    if dctx.is_null() {
        return ERROR(ZSTD_error_memory_allocation);
    }
    // SAFETY: class B (boundary), forwarded.
    let regenSize = unsafe { ZSTD_decompressDCtx(dctx, dst, dstCapacity, src, srcSize) };
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_freeDCtx(dctx) };
    regenSize
}

// ---------------------------------------------------------------------------
// Advanced Streaming Decompression API -- bufferless and synchronous.
// ---------------------------------------------------------------------------

/// `ZSTD_nextSrcSizeToDecompress()`.
///
/// # Safety
/// `dctx` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_nextSrcSizeToDecompress(dctx: *mut ZstdDCtx) -> usize {
    // SAFETY: class B (boundary).
    unsafe { (*dctx).expected }
}

/// `ZSTD_nextSrcSizeToDecompressWithInputSize()`.
///
/// # Safety
/// `dctx` must be valid for reads.
unsafe fn ZSTD_nextSrcSizeToDecompressWithInputSize(dctx: *mut ZstdDCtx, inputSize: usize) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &*dctx };
    if !(d.stage == ZSTDds_decompressBlock || d.stage == ZSTDds_decompressLastBlock) {
        return d.expected;
    }
    if d.bType != bt_raw {
        return d.expected;
    }
    BOUNDED_usize(1, inputSize, d.expected)
}

/// `ZSTD_nextInputType()`.
///
/// # Safety
/// `dctx` must be valid for reads.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_nextInputType(dctx: *mut ZstdDCtx) -> c_uint {
    // ZSTD_nextInputType_e: frameHeader=0, blockHeader=1, block=2,
    // lastBlock=3, checksum=4, skippableFrame=5.
    // SAFETY: class B (boundary).
    let stage = unsafe { (*dctx).stage };
    match stage {
        ZSTDds_getFrameHeaderSize | ZSTDds_decodeFrameHeader => 0,
        ZSTDds_decodeBlockHeader => 1,
        ZSTDds_decompressBlock => 2,
        ZSTDds_decompressLastBlock => 3,
        ZSTDds_checkChecksum => 4,
        ZSTDds_decodeSkippableHeader | ZSTDds_skipFrame => 5,
        _ => unreachable!("ZSTD_DCtx::stage holds an impossible value"),
    }
}

/// `ZSTD_isSkipFrame()`.
///
/// # Safety
/// `dctx` must be valid for reads.
unsafe fn ZSTD_isSkipFrame(dctx: *mut ZstdDCtx) -> bool {
    // SAFETY: class B (boundary).
    unsafe { (*dctx).stage == ZSTDds_skipFrame }
}

/// `ZSTD_decompressContinue()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `src .. src + srcSize` must
/// be readable; `dst .. dst + dstCapacity` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressContinue(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    // SAFETY: class B (boundary), forwarded.
    if srcSize != unsafe { ZSTD_nextSrcSizeToDecompressWithInputSize(dctx, srcSize) } {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_checkContinuity(dctx, dst, dstCapacity) };

    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.processedCSize = d.processedCSize.wrapping_add(srcSize as u64);

    match d.stage {
        ZSTDds_getFrameHeaderSize => {
            if d.format == ZSTD_f_zstd1 {
                debug_assert!(srcSize >= ZSTD_FRAMEIDSIZE);
                // SAFETY: class B (boundary). `srcSize >= ZSTD_FRAMEIDSIZE` (4),
                // guaranteed by every caller (the streaming state machine
                // never requests fewer than `ZSTD_startingInputLength`,
                // which is >= 4 for `ZSTD_f_zstd1`).
                if (unsafe { MEM_readLE32(src as *const u8) } & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
                    // Real catch, not restated: `headerBuffer` is exactly
                    // `ZSTD_FRAMEHEADERSIZE_MAX` (18) bytes, and `srcSize`
                    // here is caller-supplied (via the public
                    // `ZSTD_decompressContinue` API, not just the
                    // streaming wrapper) -- an out-of-contract caller
                    // passing an oversized `srcSize` at this exact stage
                    // would otherwise overflow the buffer.
                    assert!(srcSize <= ZSTD_FRAMEHEADERSIZE_MAX, "frame header buffer overflow");
                    // SAFETY: class C (construction). `srcSize <= headerBuffer.len()`,
                    // just asserted; `src .. src + srcSize` readable per caller.
                    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, d.headerBuffer.as_mut_ptr(), srcSize) };
                    d.expected = ZSTD_SKIPPABLEHEADERSIZE.wrapping_sub(srcSize);
                    d.stage = ZSTDds_decodeSkippableHeader;
                    return 0;
                }
            }
            // SAFETY: class B (boundary), forwarded.
            d.headerSize = unsafe { ZSTD_frameHeaderSize_internal(src, srcSize, d.format) };
            if ZSTD_isError(d.headerSize) != 0 {
                return d.headerSize;
            }
            assert!(srcSize <= ZSTD_FRAMEHEADERSIZE_MAX, "frame header buffer overflow");
            // SAFETY: class C (construction). As above.
            unsafe { core::ptr::copy_nonoverlapping(src as *const u8, d.headerBuffer.as_mut_ptr(), srcSize) };
            d.expected = d.headerSize.wrapping_sub(srcSize);
            d.stage = ZSTDds_decodeFrameHeader;
            0
        }

        ZSTDds_decodeFrameHeader => {
            let offset = d.headerSize.wrapping_sub(srcSize);
            // Real catch: `offset + srcSize` must land inside `headerBuffer`
            // (18 bytes). `headerSize` was computed by the previous stage
            // and `srcSize` is caller-supplied; a caller violating the
            // streaming protocol here would otherwise write past the
            // buffer.
            assert!(offset <= ZSTD_FRAMEHEADERSIZE_MAX && srcSize <= ZSTD_FRAMEHEADERSIZE_MAX - offset, "frame header buffer overflow");
            // SAFETY: class C (construction). Just asserted in-bounds.
            unsafe { core::ptr::copy_nonoverlapping(src as *const u8, d.headerBuffer.as_mut_ptr().add(offset), srcSize) };
            let headerSize = d.headerSize;
            // SAFETY: class B (boundary), forwarded. `d.headerBuffer` now
            // holds the full frame header, `headerSize` bytes of it.
            let r = unsafe { ZSTD_decodeFrameHeader(dctx, d.headerBuffer.as_ptr() as *const c_void, headerSize) };
            if ZSTD_isError(r) != 0 {
                return r;
            }
            let d = unsafe { &mut *dctx };
            d.expected = ZSTD_blockHeaderSize;
            d.stage = ZSTDds_decodeBlockHeader;
            0
        }

        ZSTDds_decodeBlockHeader => {
            let mut bp = BlockProperties::default();
            // SAFETY: class B (boundary). `src .. src + ZSTD_blockHeaderSize`
            // is readable -- `srcSize == ZSTD_blockHeaderSize` here, per
            // `d.expected` set by the previous stage and the entry check
            // above.
            let cBlockSize = unsafe { ZSTD_getcBlockSize(src, ZSTD_blockHeaderSize, &mut bp) };
            if ZSTD_isError(cBlockSize) != 0 {
                return cBlockSize;
            }
            if cBlockSize > d.fParams.blockSizeMax as usize {
                return ERROR(ZSTD_error_corruption_detected);
            }
            d.expected = cBlockSize;
            d.bType = bp.blockType;
            d.rleSize = bp.origSize as usize;
            if cBlockSize != 0 {
                d.stage = if bp.lastBlock != 0 { ZSTDds_decompressLastBlock } else { ZSTDds_decompressBlock };
                return 0;
            }
            if bp.lastBlock != 0 {
                if d.fParams.checksumFlag != 0 {
                    d.expected = 4;
                    d.stage = ZSTDds_checkChecksum;
                } else {
                    d.expected = 0;
                    d.stage = ZSTDds_getFrameHeaderSize;
                }
            } else {
                d.expected = ZSTD_blockHeaderSize;
                d.stage = ZSTDds_decodeBlockHeader;
            }
            0
        }

        ZSTDds_decompressLastBlock | ZSTDds_decompressBlock => {
            let rSize: usize;
            match d.bType {
                bt_compressed => {
                    debug_assert!(d.isFrameDecompression == 1);
                    // SAFETY: class B (boundary), forwarded.
                    rSize = unsafe {
                        ZSTD_decompressBlock_internal(dctx, dst, dstCapacity, src, srcSize, is_streaming)
                    };
                    let d = unsafe { &mut *dctx };
                    d.expected = 0;
                }
                bt_raw => {
                    debug_assert!(srcSize <= d.expected);
                    // SAFETY: class B (boundary), forwarded.
                    rSize = unsafe { ZSTD_copyRawBlock(dst, dstCapacity, src, srcSize) };
                    if ZSTD_isError(rSize) != 0 {
                        return rSize;
                    }
                    debug_assert!(rSize == srcSize);
                    let d = unsafe { &mut *dctx };
                    d.expected -= rSize;
                }
                bt_rle => {
                    // SAFETY: class B (boundary). `srcSize == d.expected`,
                    // and an RLE block's `d.expected` is always 1 (its
                    // `ZSTDds_decodeBlockHeader` stage sets `d.expected =
                    // cBlockSize`, and `ZSTD_getcBlockSize` gives an RLE
                    // block a one-byte compressed payload).
                    rSize = unsafe { ZSTD_setRleBlock(dst, dstCapacity, *(src as *const u8), d.rleSize) };
                    let d = unsafe { &mut *dctx };
                    d.expected = 0;
                }
                _ => {
                    return ERROR(ZSTD_error_corruption_detected);
                }
            }
            if ZSTD_isError(rSize) != 0 {
                return rSize;
            }
            let d = unsafe { &mut *dctx };
            if rSize > d.fParams.blockSizeMax as usize {
                return ERROR(ZSTD_error_corruption_detected);
            }
            d.decodedSize = d.decodedSize.wrapping_add(rSize as u64);
            if d.validateChecksum != 0 {
                // SAFETY: class B (boundary). `dst .. dst + rSize` was just
                // written by the block decoder above.
                unsafe { xxh64_update(&mut d.xxhState, dst as *const c_void, rSize) };
            }
            d.previousDstEnd = (dst as *const u8).wrapping_add(rSize) as *const c_void;

            if d.expected > 0 {
                return rSize;
            }

            if d.stage == ZSTDds_decompressLastBlock {
                if d.fParams.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN && d.decodedSize != d.fParams.frameContentSize {
                    return ERROR(ZSTD_error_corruption_detected);
                }
                if d.fParams.checksumFlag != 0 {
                    d.expected = 4;
                    d.stage = ZSTDds_checkChecksum;
                } else {
                    // Not a reborrow-aliasing violation today: see the
                    // comment on ZSTD_decompressFrame's trace_end call.
                    ZSTD_DCtx_trace_end(dctx, d.decodedSize, d.processedCSize, 1);
                    d.expected = 0;
                    d.stage = ZSTDds_getFrameHeaderSize;
                }
            } else {
                d.stage = ZSTDds_decodeBlockHeader;
                d.expected = ZSTD_blockHeaderSize;
            }
            rSize
        }

        ZSTDds_checkChecksum => {
            debug_assert!(srcSize == 4);
            if d.validateChecksum != 0 {
                // SAFETY: class B (boundary).
                let h32 = unsafe { xxh64_digest(&d.xxhState) } as u32;
                // SAFETY: class B (boundary). `srcSize == 4`.
                let check32 = unsafe { MEM_readLE32(src as *const u8) };
                if check32 != h32 {
                    return ERROR(ZSTD_error_checksum_wrong);
                }
            }
            // Not a reborrow-aliasing violation today: see the comment on
            // ZSTD_decompressFrame's trace_end call.
            ZSTD_DCtx_trace_end(dctx, d.decodedSize, d.processedCSize, 1);
            d.expected = 0;
            d.stage = ZSTDds_getFrameHeaderSize;
            0
        }

        ZSTDds_decodeSkippableHeader => {
            debug_assert!(srcSize <= ZSTD_SKIPPABLEHEADERSIZE);
            debug_assert!(d.format != ZSTD_f_zstd1_magicless);
            let offset = ZSTD_SKIPPABLEHEADERSIZE.wrapping_sub(srcSize);
            // Real catch: `ZSTD_SKIPPABLEHEADERSIZE` (8) is well inside
            // `headerBuffer`'s 18 bytes, but an out-of-contract `srcSize`
            // (a caller-suppliable value on the public API) could still
            // make `offset` wrap past it.
            assert!(offset <= ZSTD_SKIPPABLEHEADERSIZE && srcSize <= ZSTD_SKIPPABLEHEADERSIZE - offset, "skippable header buffer overflow");
            // SAFETY: class C (construction). Just asserted in-bounds.
            unsafe { core::ptr::copy_nonoverlapping(src as *const u8, d.headerBuffer.as_mut_ptr().add(offset), srcSize) };
            // SAFETY: class C (construction). `headerBuffer` has 18 bytes;
            // `ZSTD_FRAMEIDSIZE` (4) + 4 = 8 <= 18.
            d.expected = unsafe { MEM_readLE32(d.headerBuffer.as_ptr().add(ZSTD_FRAMEIDSIZE)) } as usize;
            d.stage = ZSTDds_skipFrame;
            0
        }

        ZSTDds_skipFrame => {
            d.expected = 0;
            d.stage = ZSTDds_getFrameHeaderSize;
            0
        }

        _ => unreachable!("ZSTD_DCtx::stage holds an impossible value"),
    }
}

// ---------------------------------------------------------------------------
// Dictionary.
// ---------------------------------------------------------------------------

/// `LL_base`, `zstd_decompress_internal.h:31-36`.
const LL_base: [u32; MAX_LL as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
];
/// `LL_bits`, `common/zstd_internal.h:113-119`.
const LL_bits: [u8; MAX_LL as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
/// `OF_base`, `zstd_decompress_internal.h:38-42`.
const OF_base: [u32; MAX_OFF as usize + 1] = [
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D, 0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD, 0xFFFFFD, 0x1FFFFFD,
    0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
];
/// `OF_bits`, `zstd_decompress_internal.h:44-48`.
const OF_bits: [u8; MAX_OFF as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
/// `ML_base`, `zstd_decompress_internal.h:50-57`.
const ML_base: [u32; MAX_ML as usize + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 0x83, 0x103, 0x203,
    0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];
/// `ML_bits`, `common/zstd_internal.h:130-138`.
const ML_bits: [u8; MAX_ML as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// `ZSTD_refDictContent()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
unsafe fn ZSTD_refDictContent(dctx: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.dictEnd = d.previousDstEnd;
    d.virtualStart = (dict as *const u8)
        .wrapping_sub(d.previousDstEnd as usize - d.prefixStart as usize)
        as *const c_void;
    d.prefixStart = dict;
    d.previousDstEnd = (dict as *const u8).wrapping_add(dictSize) as *const c_void;
    0
}

/// `ZSTD_loadDEntropy()`.
///
/// Only the `HUF_readDTableX2_wksp` arm is ported -- `HUF_FORCE_DECOMPRESS_X1`
/// is never defined anywhere in this tree (`huf_decompress_rs.rs`'s own
/// module doc already establishes this), so the `#ifdef` arm calling
/// `HUF_readDTableX1_wksp` is dead code no build compiles.
///
/// # Safety
/// `entropy` must be valid for writes; `dict .. dict + dictSize` must be
/// readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_loadDEntropy(entropy: *mut EntropyDTables, dict: *const c_void, dictSize: usize) -> usize {
    let mut dictPtr = dict as *const u8;
    // SAFETY: class B (boundary). `dictSize` bytes from `dict`.
    let dictEnd = dictPtr.wrapping_add(dictSize);

    if dictSize <= 8 {
        return ERROR(ZSTD_error_dictionary_corrupted);
    }
    debug_assert!({
        // SAFETY: class B (boundary). `dictSize > 8`.
        unsafe { MEM_readLE32(dict as *const u8) == ZSTD_MAGIC_DICTIONARY }
    });
    // SAFETY: class B (boundary). `dictSize > 8`.
    dictPtr = unsafe { dictPtr.add(8) };

    // SAFETY: class B (boundary).
    let e = unsafe { &mut *entropy };
    // Compile-time layout checks, `ZSTD_STATIC_ASSERT` in the C.
    const _: () = assert!(
        core::mem::offset_of!(EntropyDTables, OFTable)
            == core::mem::offset_of!(EntropyDTables, LLTable) + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(LL_FSE_LOG)]>()
    );
    const _: () = assert!(
        core::mem::offset_of!(EntropyDTables, MLTable)
            == core::mem::offset_of!(EntropyDTables, OFTable) + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(OFF_FSE_LOG)]>()
    );
    const _: () = assert!(
        core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(LL_FSE_LOG)]>()
            + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(OFF_FSE_LOG)]>()
            + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(ML_FSE_LOG)]>()
            >= HUF_DECOMPRESS_WORKSPACE_SIZE
    );

    {
        let workspace = e.LLTable.as_mut_ptr() as *mut c_void;
        let workspaceSize = core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(LL_FSE_LOG)]>()
            + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(OFF_FSE_LOG)]>()
            + core::mem::size_of::<[SeqSymbol; seqsymbol_table_size(ML_FSE_LOG)]>();
        // SAFETY: class B (boundary). `dictPtr .. dictEnd` readable, per
        // the caller's contract; `e.hufTable` is caller-owned and large
        // enough (`HUF_DTABLE_SIZE(ZSTD_HUFFDTABLE_CAPACITY_LOG)`);
        // `workspace` aliases `e.LLTable`/`OFTable`/`MLTable`, matching the
        // C's own aliasing (temporary workspace reused before those tables
        // are built later in this same function).
        let hSize = unsafe {
            HUF_readDTableX2_wksp(
                e.hufTable.as_mut_ptr(),
                dictPtr as *const c_void,
                dictEnd as usize - dictPtr as usize,
                workspace,
                workspaceSize,
                0,
            )
        };
        // SAFETY: class B (boundary), forwarded (HUF_isError == ZSTD_isError,
        // same error-code space).
        if ZSTD_isError(hSize) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        // SAFETY: class B (boundary). `hSize <= dictEnd - dictPtr`,
        // guaranteed by `HUF_readDTableX2_wksp`'s own contract (it never
        // reports consuming more than it was given).
        dictPtr = unsafe { dictPtr.add(hSize) };
    }

    {
        let mut offcodeNCount = [0i16; MAX_OFF as usize + 1];
        let mut offcodeMaxValue: c_uint = MAX_OFF;
        let mut offcodeLog: c_uint = 0;
        // SAFETY: class B (boundary). `dictPtr .. dictEnd` readable.
        let offcodeHeaderSize = unsafe {
            FSE_readNCount(
                offcodeNCount.as_mut_ptr(),
                &mut offcodeMaxValue,
                &mut offcodeLog,
                dictPtr as *const c_void,
                dictEnd as usize - dictPtr as usize,
            )
        };
        if ZSTD_isError(offcodeHeaderSize) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        if offcodeMaxValue > MAX_OFF || offcodeLog > OFF_FSE_LOG {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        // SAFETY: class B (boundary). `e.workspace` is
        // `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32` words, exactly the size
        // `ZSTD_buildFSETable`'s contract requires.
        unsafe {
            ZSTD_buildFSETable(
                e.OFTable.as_mut_ptr(),
                offcodeNCount.as_ptr(),
                offcodeMaxValue,
                OF_base.as_ptr(),
                OF_bits.as_ptr(),
                offcodeLog,
                e.workspace.as_mut_ptr() as *mut c_void,
                core::mem::size_of_val(&e.workspace),
                0,
            )
        };
        // SAFETY: class B (boundary). `offcodeHeaderSize <= dictEnd - dictPtr`.
        dictPtr = unsafe { dictPtr.add(offcodeHeaderSize) };
    }

    {
        let mut matchlengthNCount = [0i16; MAX_ML as usize + 1];
        let mut matchlengthMaxValue: c_uint = MAX_ML;
        let mut matchlengthLog: c_uint = 0;
        // SAFETY: class B (boundary).
        let matchlengthHeaderSize = unsafe {
            FSE_readNCount(
                matchlengthNCount.as_mut_ptr(),
                &mut matchlengthMaxValue,
                &mut matchlengthLog,
                dictPtr as *const c_void,
                dictEnd as usize - dictPtr as usize,
            )
        };
        if ZSTD_isError(matchlengthHeaderSize) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        if matchlengthMaxValue > MAX_ML || matchlengthLog > ML_FSE_LOG {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        // SAFETY: class B (boundary).
        unsafe {
            ZSTD_buildFSETable(
                e.MLTable.as_mut_ptr(),
                matchlengthNCount.as_ptr(),
                matchlengthMaxValue,
                ML_base.as_ptr(),
                ML_bits.as_ptr(),
                matchlengthLog,
                e.workspace.as_mut_ptr() as *mut c_void,
                core::mem::size_of_val(&e.workspace),
                0,
            )
        };
        // SAFETY: class B (boundary).
        dictPtr = unsafe { dictPtr.add(matchlengthHeaderSize) };
    }

    {
        let mut litlengthNCount = [0i16; MAX_LL as usize + 1];
        let mut litlengthMaxValue: c_uint = MAX_LL;
        let mut litlengthLog: c_uint = 0;
        // SAFETY: class B (boundary).
        let litlengthHeaderSize = unsafe {
            FSE_readNCount(
                litlengthNCount.as_mut_ptr(),
                &mut litlengthMaxValue,
                &mut litlengthLog,
                dictPtr as *const c_void,
                dictEnd as usize - dictPtr as usize,
            )
        };
        if ZSTD_isError(litlengthHeaderSize) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        if litlengthMaxValue > MAX_LL || litlengthLog > LL_FSE_LOG {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        // SAFETY: class B (boundary).
        unsafe {
            ZSTD_buildFSETable(
                e.LLTable.as_mut_ptr(),
                litlengthNCount.as_ptr(),
                litlengthMaxValue,
                LL_base.as_ptr(),
                LL_bits.as_ptr(),
                litlengthLog,
                e.workspace.as_mut_ptr() as *mut c_void,
                core::mem::size_of_val(&e.workspace),
                0,
            )
        };
        // SAFETY: class B (boundary).
        dictPtr = unsafe { dictPtr.add(litlengthHeaderSize) };
    }

    // Real catch, not restated: the C's own `RETURN_ERROR_IF(dictPtr+12 >
    // dictEnd, ...)` -- an adversarial dictionary shorter than the three
    // repcodes it claims to carry.
    if (dictEnd as usize).wrapping_sub(dictPtr as usize) < 12 {
        return ERROR(ZSTD_error_dictionary_corrupted);
    }
    {
        let dictContentSize = dictEnd as usize - (dictPtr as usize + 12);
        for i in 0..3 {
            // SAFETY: class B (boundary). `dictPtr + 12 <= dictEnd`, just
            // checked, so each of the three 4-byte reads is in range.
            let rep = unsafe { MEM_readLE32(dictPtr) };
            dictPtr = unsafe { dictPtr.add(4) };
            if rep == 0 || rep as usize > dictContentSize {
                return ERROR(ZSTD_error_dictionary_corrupted);
            }
            e.rep[i] = rep;
        }
    }

    dictPtr as usize - dict as usize
}

/// `ZSTD_decompress_insertDictionary()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `dict .. dict + dictSize`
/// must be readable.
unsafe fn ZSTD_decompress_insertDictionary(dctx: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    if dictSize < 8 {
        // SAFETY: class B (boundary), forwarded.
        return unsafe { ZSTD_refDictContent(dctx, dict, dictSize) };
    }
    // SAFETY: class B (boundary). `dictSize >= 8`.
    let magic = unsafe { MEM_readLE32(dict as *const u8) };
    if magic != ZSTD_MAGIC_DICTIONARY {
        // SAFETY: class B (boundary), forwarded.
        return unsafe { ZSTD_refDictContent(dctx, dict, dictSize) };
    }
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    // SAFETY: class B (boundary). `dictSize >= 8 >= ZSTD_FRAMEIDSIZE + 4`.
    d.dictID = unsafe { MEM_readLE32((dict as *const u8).add(ZSTD_FRAMEIDSIZE)) };

    let mut dict = dict;
    let mut dictSize = dictSize;
    {
        // SAFETY: class B (boundary), forwarded.
        let eSize = unsafe { ZSTD_loadDEntropy(&mut d.entropy, dict, dictSize) };
        if ZSTD_isError(eSize) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
        dict = (dict as *const u8).wrapping_add(eSize) as *const c_void;
        dictSize -= eSize;
    }
    d.litEntropy = 1;
    d.fseEntropy = 1;

    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_refDictContent(dctx, dict, dictSize) }
}

/// `ZSTD_decompressBegin()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBegin(dctx: *mut ZstdDCtx) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    d.expected = ZSTD_startingInputLength(d.format);
    d.stage = ZSTDds_getFrameHeaderSize;
    d.processedCSize = 0;
    d.decodedSize = 0;
    d.previousDstEnd = core::ptr::null();
    d.prefixStart = core::ptr::null();
    d.virtualStart = core::ptr::null();
    d.dictEnd = core::ptr::null();
    // `dctx->entropy.hufTable[0] = (HUF_DTable)((ZSTD_HUFFDTABLE_CAPACITY_LOG)*0x1000001)`
    // -- `HUF_DTable` is `U32`, so this is a plain `u32` store.
    d.entropy.hufTable[0] = ZSTD_HUFFDTABLE_CAPACITY_LOG.wrapping_mul(0x1000001);
    d.litEntropy = 0;
    d.fseEntropy = 0;
    d.dictID = 0;
    d.bType = bt_reserved;
    d.isFrameDecompression = 1;
    const _: () = assert!(ZSTD_REP_NUM == 3);
    d.entropy.rep = REP_START_VALUE;
    d.LLTptr = d.entropy.LLTable.as_ptr();
    d.MLTptr = d.entropy.MLTable.as_ptr();
    d.OFTptr = d.entropy.OFTable.as_ptr();
    d.HUFptr = d.entropy.hufTable.as_ptr();
    0
}

/// `ZSTD_decompressBegin_usingDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `dict .. dict + dictSize`
/// must be readable if `dict` is non-null.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBegin_usingDict(dctx: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_decompressBegin(dctx) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    if !dict.is_null() && dictSize != 0 {
        // SAFETY: class B (boundary), forwarded.
        let r = unsafe { ZSTD_decompress_insertDictionary(dctx, dict, dictSize) };
        if ZSTD_isError(r) != 0 {
            return ERROR(ZSTD_error_dictionary_corrupted);
        }
    }
    0
}

/// `ZSTD_decompressBegin_usingDDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `ddict`, if non-null, must be
/// a live `ZSTD_DDict*`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBegin_usingDDict(dctx: *mut ZstdDCtx, ddict: *const c_void) -> usize {
    if !ddict.is_null() {
        // SAFETY: class B (boundary), forwarded.
        let dictStart = unsafe { ZSTD_DDict_dictContent(ddict) } as *const u8;
        // SAFETY: class B (boundary), forwarded.
        let dictSize = unsafe { ZSTD_DDict_dictSize(ddict) };
        let dictEnd = dictStart.wrapping_add(dictSize) as *const c_void;
        // SAFETY: class B (boundary).
        let d = unsafe { &mut *dctx };
        d.ddictIsCold = (d.dictEnd as usize != dictEnd as usize) as c_int;
    }
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_decompressBegin(dctx) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    if !ddict.is_null() {
        // SAFETY: class B (boundary), forwarded.
        unsafe { ZSTD_copyDDictParameters(dctx, ddict) };
    }
    0
}

/// `ZSTD_getDictID_fromDict()`.
///
/// # Safety
/// `dict .. dict + dictSize` must be readable if `dictSize >= 8`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getDictID_fromDict(dict: *const c_void, dictSize: usize) -> c_uint {
    if dictSize < 8 {
        return 0;
    }
    // SAFETY: class B (boundary). `dictSize >= 8`.
    if unsafe { MEM_readLE32(dict as *const u8) } != ZSTD_MAGIC_DICTIONARY {
        return 0;
    }
    // SAFETY: class B (boundary). `dictSize >= 8 >= ZSTD_FRAMEIDSIZE + 4`.
    unsafe { MEM_readLE32((dict as *const u8).add(ZSTD_FRAMEIDSIZE)) }
}

/// `ZSTD_getDictID_fromFrame()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getDictID_fromFrame(src: *const c_void, srcSize: usize) -> c_uint {
    let mut zfp = ZstdFrameHeader {
        frameContentSize: 0,
        windowSize: 0,
        blockSizeMax: 0,
        frameType: ZSTD_frame,
        headerSize: 0,
        dictID: 0,
        checksumFlag: 0,
        _reserved1: 0,
        _reserved2: 0,
    };
    // SAFETY: class B (boundary), forwarded.
    let hError = unsafe { ZSTD_getFrameHeader(&mut zfp, src, srcSize) };
    if ZSTD_isError(hError) != 0 {
        return 0;
    }
    zfp.dictID
}

/// `ZSTD_decompress_usingDDict()`.
///
/// # Safety
/// As `ZSTD_decompressMultiFrame`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompress_usingDDict(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
    ddict: *const c_void,
) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_decompressMultiFrame(dctx, dst, dstCapacity, src, srcSize, core::ptr::null(), 0, ddict) }
}

// ---------------------------------------------------------------------------
// Streaming decompression.
// ---------------------------------------------------------------------------

/// `ZSTD_createDStream()`. See module docs #1: allocation always fails
/// with `ZSTD_defaultCMem` in this kernel.
#[no_mangle]
pub extern "C" fn ZSTD_createDStream() -> *mut ZstdDCtx {
    // SAFETY: `ZSTD_defaultCMem`'s function pointers are both `None`.
    unsafe { ZSTD_createDCtx_internal(ZSTD_defaultCMem) }
}

/// `ZSTD_initStaticDStream()`.
///
/// # Safety
/// As `ZSTD_initStaticDCtx`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initStaticDStream(workspace: *mut c_void, workspaceSize: usize) -> *mut ZstdDCtx {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_initStaticDCtx(workspace, workspaceSize) }
}

/// `ZSTD_createDStream_advanced()`.
///
/// # Safety
/// As `ZSTD_createDCtx_internal`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_createDStream_advanced(customMem: ZstdCustomMem) -> *mut ZstdDCtx {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_createDCtx_internal(customMem) }
}

/// `ZSTD_freeDStream()`.
///
/// # Safety
/// As `ZSTD_freeDCtx`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_freeDStream(zds: *mut ZstdDCtx) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_freeDCtx(zds) }
}

/// `ZSTD_DStreamInSize()`.
#[no_mangle]
pub extern "C" fn ZSTD_DStreamInSize() -> usize {
    ZSTD_BLOCKSIZE_MAX.wrapping_add(ZSTD_blockHeaderSize)
}
/// `ZSTD_DStreamOutSize()`.
#[no_mangle]
pub extern "C" fn ZSTD_DStreamOutSize() -> usize {
    ZSTD_BLOCKSIZE_MAX
}

/// `ZSTD_DCtx_loadDictionary_advanced()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `dict .. dict + dictSize`
/// must be readable if `dict` is non-null.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_loadDictionary_advanced(
    dctx: *mut ZstdDCtx,
    dict: *const c_void,
    dictSize: usize,
    dictLoadMethod: c_int,
    dictContentType: c_int,
) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if d.streamStage != zdss_init {
        return ERROR(ZSTD_error_stage_wrong);
    }
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_clearDict(dctx) };
    let d = unsafe { &mut *dctx };
    if !dict.is_null() && dictSize != 0 {
        // SAFETY: class B (boundary), forwarded.
        let ddictLocal = unsafe {
            ZSTD_createDDict_advanced(dict, dictSize, dictLoadMethod as c_uint, dictContentType as c_uint, d.customMem)
        };
        d.ddictLocal = ddictLocal;
        if d.ddictLocal.is_null() {
            return ERROR(ZSTD_error_memory_allocation);
        }
        d.ddict = d.ddictLocal;
        d.dictUses = ZSTD_use_indefinitely;
    }
    0
}

/// `ZSTD_DCtx_loadDictionary_byReference()`.
///
/// # Safety
/// As `ZSTD_DCtx_loadDictionary_advanced`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_loadDictionary_byReference(dctx: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_DCtx_loadDictionary_advanced(dctx, dict, dictSize, ZSTD_dlm_byRef, ZSTD_dct_auto) }
}

/// `ZSTD_DCtx_loadDictionary()`.
///
/// # Safety
/// As `ZSTD_DCtx_loadDictionary_advanced`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_loadDictionary(dctx: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_DCtx_loadDictionary_advanced(dctx, dict, dictSize, ZSTD_dlm_byCopy, ZSTD_dct_auto) }
}

/// `ZSTD_DCtx_refPrefix_advanced()`.
///
/// # Safety
/// As `ZSTD_DCtx_loadDictionary_advanced`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_refPrefix_advanced(dctx: *mut ZstdDCtx, prefix: *const c_void, prefixSize: usize, dictContentType: c_int) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_loadDictionary_advanced(dctx, prefix, prefixSize, ZSTD_dlm_byRef, dictContentType) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary).
    unsafe { (*dctx).dictUses = ZSTD_use_once };
    0
}

/// `ZSTD_DCtx_refPrefix()`.
///
/// # Safety
/// As `ZSTD_DCtx_refPrefix_advanced`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_refPrefix(dctx: *mut ZstdDCtx, prefix: *const c_void, prefixSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_DCtx_refPrefix_advanced(dctx, prefix, prefixSize, ZSTD_dct_rawContent) }
}

/// `ZSTD_initDStream_usingDict()`.
///
/// # Safety
/// `zds` must be valid for reads and writes; `dict .. dict + dictSize` must
/// be readable if `dict` is non-null.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initDStream_usingDict(zds: *mut ZstdDCtx, dict: *const c_void, dictSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_reset(zds, ZSTD_reset_session_only) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_loadDictionary(zds, dict, dictSize) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary).
    ZSTD_startingInputLength(unsafe { (*zds).format })
}

/// `ZSTD_initDStream()`.
///
/// # Safety
/// `zds` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initDStream(zds: *mut ZstdDCtx) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_reset(zds, ZSTD_reset_session_only) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_refDDict(zds, core::ptr::null()) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary).
    ZSTD_startingInputLength(unsafe { (*zds).format })
}

/// `ZSTD_initDStream_usingDDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `ddict`, if non-null, must be
/// a live `ZSTD_DDict*` that outlives this streaming session.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initDStream_usingDDict(dctx: *mut ZstdDCtx, ddict: *const c_void) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_reset(dctx, ZSTD_reset_session_only) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_refDDict(dctx, ddict) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary).
    ZSTD_startingInputLength(unsafe { (*dctx).format })
}

/// `ZSTD_resetDStream()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_resetDStream(dctx: *mut ZstdDCtx) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_DCtx_reset(dctx, ZSTD_reset_session_only) };
    if ZSTD_isError(r) != 0 {
        return r;
    }
    // SAFETY: class B (boundary).
    ZSTD_startingInputLength(unsafe { (*dctx).format })
}

/// `ZSTD_DCtx_refDDict()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `ddict`, if non-null, must be
/// a live `ZSTD_DDict*`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_refDDict(dctx: *mut ZstdDCtx, ddict: *const c_void) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if d.streamStage != zdss_init {
        return ERROR(ZSTD_error_stage_wrong);
    }
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_clearDict(dctx) };
    let d = unsafe { &mut *dctx };
    if !ddict.is_null() {
        d.ddict = ddict;
        d.dictUses = ZSTD_use_indefinitely;
        if d.refMultipleDDicts == ZSTD_rmd_refMultipleDDicts {
            if d.ddictSet.is_null() {
                // SAFETY: class B (boundary), forwarded.
                d.ddictSet = unsafe { ZSTD_createDDictHashSet(d.customMem) };
                if d.ddictSet.is_null() {
                    return ERROR(ZSTD_error_memory_allocation);
                }
            }
            debug_assert!(d.staticSize == 0);
            // SAFETY: class B (boundary), forwarded.
            let r = unsafe { ZSTD_DDictHashSet_addDDict(d.ddictSet, ddict, d.customMem) };
            if ZSTD_isError(r) != 0 {
                return r;
            }
        }
    }
    0
}

/// `ZSTD_DCtx_setMaxWindowSize()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_setMaxWindowSize(dctx: *mut ZstdDCtx, maxWindowSize: usize) -> usize {
    let bounds = ZSTD_dParam_getBounds(ZSTD_d_windowLogMax);
    let min = 1usize << bounds.lowerBound;
    let max = 1usize << bounds.upperBound;
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if d.streamStage != zdss_init {
        return ERROR(ZSTD_error_stage_wrong);
    }
    if maxWindowSize < min {
        return ERROR(ZSTD_error_parameter_outOfBound);
    }
    if maxWindowSize > max {
        return ERROR(ZSTD_error_parameter_outOfBound);
    }
    d.maxWindowSize = maxWindowSize;
    0
}

/// `ZSTD_DCtx_setFormat()`.
///
/// # Safety
/// As `ZSTD_DCtx_setParameter`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_setFormat(dctx: *mut ZstdDCtx, format: u32) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_DCtx_setParameter(dctx, ZSTD_d_format, format as c_int) }
}

/// `ZSTD_dParam_getBounds()`.
#[no_mangle]
pub extern "C" fn ZSTD_dParam_getBounds(dParam: c_int) -> ZstdBounds {
    let mut bounds = ZstdBounds { error: 0, lowerBound: 0, upperBound: 0 };
    match dParam {
        ZSTD_d_windowLogMax => {
            bounds.lowerBound = ZSTD_WINDOWLOG_ABSOLUTEMIN;
            bounds.upperBound = ZSTD_WINDOWLOG_MAX;
            return bounds;
        }
        ZSTD_d_format => {
            bounds.lowerBound = ZSTD_f_zstd1 as c_int;
            bounds.upperBound = ZSTD_f_zstd1_magicless as c_int;
            return bounds;
        }
        ZSTD_d_stableOutBuffer => {
            bounds.lowerBound = ZSTD_bm_buffered as c_int;
            bounds.upperBound = ZSTD_bm_stable as c_int;
            return bounds;
        }
        ZSTD_d_forceIgnoreChecksum => {
            bounds.lowerBound = ZSTD_d_validateChecksum as c_int;
            bounds.upperBound = ZSTD_d_ignoreChecksum as c_int;
            return bounds;
        }
        ZSTD_d_refMultipleDDicts => {
            bounds.lowerBound = ZSTD_rmd_refSingleDDict as c_int;
            bounds.upperBound = ZSTD_rmd_refMultipleDDicts as c_int;
            return bounds;
        }
        ZSTD_d_disableHuffmanAssembly => {
            bounds.lowerBound = 0;
            bounds.upperBound = 1;
            return bounds;
        }
        ZSTD_d_maxBlockSize => {
            // `ZSTD_BLOCKSIZE_MAX_MIN`, `zstd_lib.h` -- `1 << 10`.
            bounds.lowerBound = 1 << 10;
            bounds.upperBound = ZSTD_BLOCKSIZE_MAX as c_int;
            return bounds;
        }
        _ => {}
    }
    bounds.error = ERROR(ZSTD_error_parameter_unsupported);
    bounds
}

/// `ZSTD_dParam_withinBounds()`.
fn ZSTD_dParam_withinBounds(dParam: c_int, value: c_int) -> bool {
    let bounds = ZSTD_dParam_getBounds(dParam);
    if ZSTD_isError(bounds.error) != 0 {
        return false;
    }
    if value < bounds.lowerBound {
        return false;
    }
    if value > bounds.upperBound {
        return false;
    }
    true
}

/// `ZSTD_DCtx_getParameter()`.
///
/// # Safety
/// `dctx` must be valid for reads; `value` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_getParameter(dctx: *mut ZstdDCtx, param: c_int, value: *mut c_int) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &*dctx };
    match param {
        ZSTD_d_windowLogMax => {
            // SAFETY: class B (boundary).
            unsafe { *value = ZSTD_highbit32(d.maxWindowSize as u32) as c_int };
            0
        }
        ZSTD_d_format => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.format as c_int };
            0
        }
        ZSTD_d_stableOutBuffer => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.outBufferMode as c_int };
            0
        }
        ZSTD_d_forceIgnoreChecksum => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.forceIgnoreChecksum as c_int };
            0
        }
        ZSTD_d_refMultipleDDicts => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.refMultipleDDicts as c_int };
            0
        }
        ZSTD_d_disableHuffmanAssembly => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.disableHufAsm };
            0
        }
        ZSTD_d_maxBlockSize => {
            // SAFETY: class B (boundary).
            unsafe { *value = d.maxBlockSizeParam };
            0
        }
        _ => ERROR(ZSTD_error_parameter_unsupported),
    }
}

/// `ZSTD_DCtx_setParameter()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_setParameter(dctx: *mut ZstdDCtx, dParam: c_int, mut value: c_int) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if d.streamStage != zdss_init {
        return ERROR(ZSTD_error_stage_wrong);
    }
    match dParam {
        ZSTD_d_windowLogMax => {
            if value == 0 {
                value = ZSTD_WINDOWLOG_LIMIT_DEFAULT as c_int;
            }
            if !ZSTD_dParam_withinBounds(ZSTD_d_windowLogMax, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.maxWindowSize = 1usize << value;
            0
        }
        ZSTD_d_format => {
            if !ZSTD_dParam_withinBounds(ZSTD_d_format, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.format = value as u32;
            0
        }
        ZSTD_d_stableOutBuffer => {
            if !ZSTD_dParam_withinBounds(ZSTD_d_stableOutBuffer, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.outBufferMode = value as u32;
            0
        }
        ZSTD_d_forceIgnoreChecksum => {
            if !ZSTD_dParam_withinBounds(ZSTD_d_forceIgnoreChecksum, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.forceIgnoreChecksum = value as u32;
            0
        }
        ZSTD_d_refMultipleDDicts => {
            if !ZSTD_dParam_withinBounds(ZSTD_d_refMultipleDDicts, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            if d.staticSize != 0 {
                return ERROR(ZSTD_error_parameter_unsupported);
            }
            d.refMultipleDDicts = value as u32;
            0
        }
        ZSTD_d_disableHuffmanAssembly => {
            if !ZSTD_dParam_withinBounds(ZSTD_d_disableHuffmanAssembly, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.disableHufAsm = (value != 0) as c_int;
            0
        }
        ZSTD_d_maxBlockSize => {
            if value != 0 && !ZSTD_dParam_withinBounds(ZSTD_d_maxBlockSize, value) {
                return ERROR(ZSTD_error_parameter_outOfBound);
            }
            d.maxBlockSizeParam = value;
            0
        }
        _ => ERROR(ZSTD_error_parameter_unsupported),
    }
}

/// `ZSTD_DCtx_reset()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DCtx_reset(dctx: *mut ZstdDCtx, reset: c_int) -> usize {
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *dctx };
    if reset == ZSTD_reset_session_only || reset == ZSTD_reset_session_and_parameters {
        d.streamStage = zdss_init;
        d.noForwardProgress = 0;
        d.isFrameDecompression = 1;
    }
    if reset == ZSTD_reset_parameters || reset == ZSTD_reset_session_and_parameters {
        if d.streamStage != zdss_init {
            return ERROR(ZSTD_error_stage_wrong);
        }
        // SAFETY: class B (boundary), forwarded.
        unsafe { ZSTD_clearDict(dctx) };
        // SAFETY: class B (boundary), forwarded.
        unsafe { ZSTD_DCtx_resetParameters(dctx) };
    }
    0
}

/// `ZSTD_sizeof_DStream()`.
///
/// # Safety
/// As `ZSTD_sizeof_DCtx`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_sizeof_DStream(dctx: *const ZstdDCtx) -> usize {
    // SAFETY: class B (boundary), forwarded.
    unsafe { ZSTD_sizeof_DCtx(dctx) }
}

/// `ZSTD_decodingBufferSize_internal()`. `RETURN_ERROR_IF((unsigned long
/// long)minRBSize != neededSize, ...)` is a real, reachable catch (an
/// enormous `windowSize`/`frameContentSize` on a 32-bit `size_t` target),
/// but every target this project builds is 64-bit, so `size_t` and
/// `unsigned long long` are the same width and the truncation this guards
/// against can never fire -- kept as a real check anyway (`usize::try_from`),
/// not dropped, since the comparison is cheap and the C's own intent is
/// explicit.
fn ZSTD_decodingBufferSize_internal(windowSize: u64, frameContentSize: u64, blockSizeMax: usize) -> usize {
    let blockSize = MIN_u64(windowSize, ZSTD_BLOCKSIZE_MAX as u64).min(blockSizeMax as u64) as usize;
    let neededRBSize = windowSize
        .wrapping_add((blockSize as u64).wrapping_mul(2))
        .wrapping_add((WILDCOPY_OVERLENGTH as u64).wrapping_mul(2));
    let neededSize = MIN_u64(frameContentSize, neededRBSize);
    match usize::try_from(neededSize) {
        Ok(minRBSize) => minRBSize,
        Err(_) => ERROR(ZSTD_error_frameParameter_windowTooLarge),
    }
}

/// `ZSTD_decodingBufferSize_min()`.
#[no_mangle]
pub extern "C" fn ZSTD_decodingBufferSize_min(windowSize: u64, frameContentSize: u64) -> usize {
    ZSTD_decodingBufferSize_internal(windowSize, frameContentSize, ZSTD_BLOCKSIZE_MAX)
}

/// `ZSTD_estimateDStreamSize()`.
#[no_mangle]
pub extern "C" fn ZSTD_estimateDStreamSize(windowSize: usize) -> usize {
    let blockSize = MIN_usize(windowSize, ZSTD_BLOCKSIZE_MAX);
    let inBuffSize = blockSize;
    let outBuffSize = ZSTD_decodingBufferSize_min(windowSize as u64, ZSTD_CONTENTSIZE_UNKNOWN);
    ZSTD_estimateDCtxSize().wrapping_add(inBuffSize).wrapping_add(outBuffSize)
}

/// `ZSTD_estimateDStreamSize_fromFrame()`.
///
/// # Safety
/// `src .. src + srcSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_estimateDStreamSize_fromFrame(src: *const c_void, srcSize: usize) -> usize {
    let windowSizeMax: u32 = 1u32 << ZSTD_WINDOWLOG_MAX;
    let mut zfh = core::mem::MaybeUninit::<ZstdFrameHeader>::uninit();
    // SAFETY: class B (boundary), forwarded.
    let err = unsafe { ZSTD_getFrameHeader(zfh.as_mut_ptr(), src, srcSize) };
    if ZSTD_isError(err) != 0 {
        return err;
    }
    if err > 0 {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class C (construction). `err == 0`.
    let zfh = unsafe { zfh.assume_init() };
    if zfh.windowSize > windowSizeMax as u64 {
        return ERROR(ZSTD_error_frameParameter_windowTooLarge);
    }
    ZSTD_estimateDStreamSize(zfh.windowSize as usize)
}

/// `ZSTD_DCtx_isOverflow()`.
fn ZSTD_DCtx_isOverflow(zds: &ZstdDCtx, neededInBuffSize: usize, neededOutBuffSize: usize) -> bool {
    (zds.inBuffSize + zds.outBuffSize) >= (neededInBuffSize + neededOutBuffSize) * ZSTD_WORKSPACETOOLARGE_FACTOR
}

/// `ZSTD_DCtx_updateOversizedDuration()`.
fn ZSTD_DCtx_updateOversizedDuration(zds: &mut ZstdDCtx, neededInBuffSize: usize, neededOutBuffSize: usize) {
    if ZSTD_DCtx_isOverflow(zds, neededInBuffSize, neededOutBuffSize) {
        zds.oversizedDuration += 1;
    } else {
        zds.oversizedDuration = 0;
    }
}

/// `ZSTD_DCtx_isOversizedTooLong()`.
fn ZSTD_DCtx_isOversizedTooLong(zds: &ZstdDCtx) -> bool {
    zds.oversizedDuration >= ZSTD_WORKSPACETOOLARGE_MAXDURATION
}

/// `ZSTD_checkOutBuffer()`.
///
/// # Safety
/// `zds` and `output` must be valid for reads.
unsafe fn ZSTD_checkOutBuffer(zds: *const ZstdDCtx, output: *const ZstdOutBuffer) -> usize {
    // SAFETY: class B (boundary).
    let zds = unsafe { &*zds };
    // SAFETY: class B (boundary).
    let output = unsafe { &*output };
    let expect = zds.expectedOutBuffer;
    if zds.outBufferMode != ZSTD_bm_stable {
        return 0;
    }
    if zds.streamStage == zdss_init {
        return 0;
    }
    if expect.dst as usize == output.dst as usize && expect.pos == output.pos && expect.size == output.size {
        return 0;
    }
    ERROR(ZSTD_error_dstBuffer_wrong)
}

/// `ZSTD_decompressContinueStream()`.
///
/// # Safety
/// `zds` must be valid for reads and writes; `*op .. oend` must be
/// writable; `src .. src + srcSize` must be readable.
unsafe fn ZSTD_decompressContinueStream(zds: *mut ZstdDCtx, op: *mut *mut c_char, oend: *mut c_char, src: *const c_void, srcSize: usize) -> usize {
    // SAFETY: class B (boundary), forwarded.
    let isSkipFrame = unsafe { ZSTD_isSkipFrame(zds) };
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *zds };
    if d.outBufferMode == ZSTD_bm_buffered {
        let dstSize = if isSkipFrame { 0 } else { d.outBuffSize - d.outStart };
        // SAFETY: class B (boundary), forwarded. `d.outBuff + d.outStart`
        // is within the `d.outBuff .. d.outBuff + d.outBuffSize` allocation
        // -- `d.outStart <= d.outBuffSize`, an invariant this same state
        // machine maintains across every stage.
        let decodedSize = unsafe {
            ZSTD_decompressContinue(zds, d.outBuff.wrapping_add(d.outStart) as *mut c_void, dstSize, src, srcSize)
        };
        if ZSTD_isError(decodedSize) != 0 {
            return decodedSize;
        }
        let d = unsafe { &mut *zds };
        if decodedSize == 0 && !isSkipFrame {
            d.streamStage = zdss_read;
        } else {
            d.outEnd = d.outStart + decodedSize;
            d.streamStage = zdss_flush;
        }
    } else {
        let dstSize = if isSkipFrame { 0 } else { oend as usize - (unsafe { *op } as usize) };
        // SAFETY: class B (boundary), forwarded.
        let decodedSize = unsafe { ZSTD_decompressContinue(zds, *op as *mut c_void, dstSize, src, srcSize) };
        if ZSTD_isError(decodedSize) != 0 {
            return decodedSize;
        }
        let d = unsafe { &mut *zds };
        // SAFETY: class B (boundary). `decodedSize <= dstSize == oend - *op`,
        // guaranteed by `ZSTD_decompressContinue`'s own contract (it never
        // writes past `dstCapacity`).
        unsafe { *op = (*op).add(decodedSize) };
        d.streamStage = zdss_read;
        // SAFETY: class B (boundary). `op` is valid for reads (the
        // caller's contract).
        debug_assert!(unsafe { *op } as usize <= oend as usize);
        debug_assert!(d.outBufferMode == ZSTD_bm_stable);
    }
    0
}

/// `ZSTD_decompressStream()`.
///
/// # Safety
/// `zds`, `output` and `input` must be valid for reads and writes;
/// `(*input).src .. (*input).src + (*input).size` must be readable;
/// `(*output).dst .. (*output).dst + (*output).size` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressStream(zds: *mut ZstdDCtx, output: *mut ZstdOutBuffer, input: *mut ZstdInBuffer) -> usize {
    // SAFETY: class B (boundary).
    let inp = unsafe { *input };
    let src = inp.src as *const c_char;
    let istart = if inp.pos != 0 { src.wrapping_add(inp.pos) } else { src };
    let iend = if inp.size != 0 { src.wrapping_add(inp.size) } else { src };
    let mut ip = istart;
    // SAFETY: class B (boundary).
    let outp = unsafe { *output };
    let dst = outp.dst as *mut c_char;
    let ostart = if outp.pos != 0 { dst.wrapping_add(outp.pos) } else { dst };
    let oend = if outp.size != 0 { dst.wrapping_add(outp.size) } else { dst };
    let mut op = ostart;
    let mut someMoreWork = true;

    if inp.pos > inp.size {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    if outp.pos > outp.size {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    // SAFETY: class B (boundary), forwarded.
    let r = unsafe { ZSTD_checkOutBuffer(zds, output) };
    if ZSTD_isError(r) != 0 {
        return r;
    }

    'outer: while someMoreWork {
        // SAFETY: class B (boundary).
        let d = unsafe { &mut *zds };
        match d.streamStage {
            zdss_init => {
                d.streamStage = zdss_loadHeader;
                d.lhSize = 0;
                d.inPos = 0;
                d.outStart = 0;
                d.outEnd = 0;
                d.hostageByte = 0;
                d.expectedOutBuffer = outp;
                continue 'outer;
            }

            zdss_loadHeader => {
                {
                    // SAFETY: class B (boundary). `d.lhSize <=
                    // ZSTD_FRAMEHEADERSIZE_MAX` (`headerBuffer`'s own size),
                    // an invariant this same loop maintains.
                    let hSize = unsafe {
                        ZSTD_getFrameHeader_advanced(&mut d.fParams, d.headerBuffer.as_ptr() as *const c_void, d.lhSize, d.format)
                    };
                    if d.refMultipleDDicts != 0 && !d.ddictSet.is_null() {
                        // SAFETY: class B (boundary), forwarded.
                        unsafe { ZSTD_DCtx_selectFrameDDict(zds) };
                    }
                    let d = unsafe { &mut *zds };
                    if ZSTD_isError(hSize) != 0 {
                        return hSize;
                    }
                    if hSize != 0 {
                        let toLoad = hSize - d.lhSize;
                        let remainingInput = iend as usize - ip as usize;
                        debug_assert!(iend as usize >= ip as usize);
                        if toLoad > remainingInput {
                            if remainingInput > 0 {
                                // Real catch: `d.lhSize + remainingInput` must
                                // stay inside `headerBuffer` (18 bytes).
                                assert!(d.lhSize <= ZSTD_FRAMEHEADERSIZE_MAX && remainingInput <= ZSTD_FRAMEHEADERSIZE_MAX - d.lhSize, "frame header buffer overflow");
                                // SAFETY: class C (construction). Just asserted.
                                unsafe { core::ptr::copy_nonoverlapping(ip as *const u8, d.headerBuffer.as_mut_ptr().add(d.lhSize), remainingInput) };
                                d.lhSize += remainingInput;
                            }
                            // SAFETY: class B (boundary). `input` is valid
                            // for writes, per the caller's contract.
                            unsafe { (*input).pos = (*input).size };
                            // SAFETY: class B (boundary), forwarded.
                            let r = unsafe {
                                ZSTD_getFrameHeader_advanced(&mut d.fParams, d.headerBuffer.as_ptr() as *const c_void, d.lhSize, d.format)
                            };
                            if ZSTD_isError(r) != 0 {
                                return r;
                            }
                            return (MAX_usize(ZSTD_FRAMEHEADERSIZE_MIN(d.format), hSize) - d.lhSize) + ZSTD_blockHeaderSize;
                        }
                        // Real catch: as above.
                        assert!(d.lhSize <= ZSTD_FRAMEHEADERSIZE_MAX && toLoad <= ZSTD_FRAMEHEADERSIZE_MAX - d.lhSize, "frame header buffer overflow");
                        // SAFETY: class C (construction). Just asserted.
                        unsafe { core::ptr::copy_nonoverlapping(ip as *const u8, d.headerBuffer.as_mut_ptr().add(d.lhSize), toLoad) };
                        d.lhSize = hSize;
                        // SAFETY: class B (boundary). `toLoad <= remainingInput`.
                        ip = unsafe { ip.add(toLoad) };
                        continue 'outer;
                    }
                }

                let d = unsafe { &mut *zds };
                if d.fParams.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN
                    && d.fParams.frameType != ZSTD_skippableFrame
                    && (oend as usize - op as usize) as u64 >= d.fParams.frameContentSize
                {
                    // SAFETY: class B (boundary), forwarded.
                    let cSize = unsafe {
                        ZSTD_findFrameCompressedSize_advanced(istart as *const c_void, iend as usize - istart as usize, d.format)
                    };
                    if cSize <= iend as usize - istart as usize {
                        // SAFETY: class B (boundary), forwarded.
                        let ddict = unsafe { ZSTD_getDDict(zds) };
                        // SAFETY: class B (boundary), forwarded.
                        let decompressedSize = unsafe {
                            ZSTD_decompress_usingDDict(zds, op as *mut c_void, oend as usize - op as usize, istart as *const c_void, cSize, ddict)
                        };
                        if ZSTD_isError(decompressedSize) != 0 {
                            return decompressedSize;
                        }
                        // SAFETY: class B (boundary). `cSize <= iend - istart`.
                        ip = unsafe { istart.add(cSize) };
                        op = op.wrapping_add(decompressedSize);
                        let d = unsafe { &mut *zds };
                        d.expected = 0;
                        d.streamStage = zdss_init;
                        someMoreWork = false;
                        continue 'outer;
                    }
                }

                let d = unsafe { &mut *zds };
                if d.outBufferMode == ZSTD_bm_stable
                    && d.fParams.frameType != ZSTD_skippableFrame
                    && d.fParams.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN
                    && ((oend as usize - op as usize) as u64) < d.fParams.frameContentSize
                {
                    return ERROR(ZSTD_error_dstSize_tooSmall);
                }

                // SAFETY: class B (boundary), forwarded.
                let ddict = unsafe { ZSTD_getDDict(zds) };
                // SAFETY: class B (boundary), forwarded.
                let r = unsafe { ZSTD_decompressBegin_usingDDict(zds, ddict) };
                if ZSTD_isError(r) != 0 {
                    return r;
                }

                let d = unsafe { &mut *zds };
                // SAFETY: class B (boundary). `d.lhSize >= 4` here -- the
                // only path reaching this point had `hSize == 0`, meaning
                // `ZSTD_getFrameHeader_advanced` fully parsed a header from
                // `headerBuffer`, which requires at least `ZSTD_FRAMEIDSIZE`
                // (4) bytes.
                if d.format == ZSTD_f_zstd1 && (unsafe { MEM_readLE32(d.headerBuffer.as_ptr()) } & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
                    // SAFETY: class B (boundary). `d.lhSize >= 8`, since a
                    // recognized skippable-frame magic number implies the
                    // header parse consumed the full `ZSTD_SKIPPABLEHEADERSIZE`.
                    d.expected = unsafe { MEM_readLE32(d.headerBuffer.as_ptr().add(ZSTD_FRAMEIDSIZE)) } as usize;
                    d.stage = ZSTDds_skipFrame;
                } else {
                    let lhSize = d.lhSize;
                    // SAFETY: class B (boundary), forwarded.
                    let r = unsafe { ZSTD_decodeFrameHeader(zds, d.headerBuffer.as_ptr() as *const c_void, lhSize) };
                    if ZSTD_isError(r) != 0 {
                        return r;
                    }
                    let d = unsafe { &mut *zds };
                    d.expected = ZSTD_blockHeaderSize;
                    d.stage = ZSTDds_decodeBlockHeader;
                }

                let d = unsafe { &mut *zds };
                d.fParams.windowSize = MAX_u64(d.fParams.windowSize, 1u64 << ZSTD_WINDOWLOG_ABSOLUTEMIN);
                if d.fParams.windowSize > d.maxWindowSize as u64 {
                    return ERROR(ZSTD_error_frameParameter_windowTooLarge);
                }
                if d.maxBlockSizeParam != 0 {
                    d.fParams.blockSizeMax = MIN_u64(d.fParams.blockSizeMax as u64, d.maxBlockSizeParam as u64) as u32;
                }

                {
                    let neededInBuffSize = MAX_usize(d.fParams.blockSizeMax as usize, 4);
                    let neededOutBuffSize = if d.outBufferMode == ZSTD_bm_buffered {
                        ZSTD_decodingBufferSize_internal(d.fParams.windowSize, d.fParams.frameContentSize, d.fParams.blockSizeMax as usize)
                    } else {
                        0
                    };
                    if ZSTD_isError(neededOutBuffSize) != 0 {
                        return neededOutBuffSize;
                    }

                    ZSTD_DCtx_updateOversizedDuration(d, neededInBuffSize, neededOutBuffSize);

                    let tooSmall = d.inBuffSize < neededInBuffSize || d.outBuffSize < neededOutBuffSize;
                    let tooLarge = ZSTD_DCtx_isOversizedTooLong(d);

                    if tooSmall || tooLarge {
                        let bufferSize = neededInBuffSize + neededOutBuffSize;
                        if d.staticSize != 0 {
                            debug_assert!(d.staticSize >= core::mem::size_of::<ZstdDCtx>());
                            if bufferSize > d.staticSize - core::mem::size_of::<ZstdDCtx>() {
                                return ERROR(ZSTD_error_memory_allocation);
                            }
                        } else {
                            let cMem = d.customMem;
                            // SAFETY: class B (boundary). `d.inBuff` is
                            // either null or a live allocation from `cMem`.
                            unsafe { ZSTD_customFree(d.inBuff as *mut c_void, cMem) };
                            d.inBuffSize = 0;
                            d.outBuffSize = 0;
                            // SAFETY: class B (boundary), forwarded.
                            d.inBuff = unsafe { ZSTD_customMalloc(bufferSize, cMem) } as *mut c_char;
                            if d.inBuff.is_null() {
                                return ERROR(ZSTD_error_memory_allocation);
                            }
                        }
                        d.inBuffSize = neededInBuffSize;
                        d.outBuff = d.inBuff.wrapping_add(d.inBuffSize);
                        d.outBuffSize = neededOutBuffSize;
                    }
                }
                d.streamStage = zdss_read;
                continue 'outer;
            }

            zdss_read => {
                // SAFETY: class B (boundary), forwarded.
                let neededInSize = unsafe { ZSTD_nextSrcSizeToDecompressWithInputSize(zds, iend as usize - ip as usize) };
                if neededInSize == 0 {
                    let d = unsafe { &mut *zds };
                    d.streamStage = zdss_init;
                    someMoreWork = false;
                    continue 'outer;
                }
                if iend as usize - ip as usize >= neededInSize {
                    // SAFETY: class B (boundary), forwarded.
                    let r = unsafe { ZSTD_decompressContinueStream(zds, &mut op, oend, ip as *const c_void, neededInSize) };
                    if ZSTD_isError(r) != 0 {
                        return r;
                    }
                    debug_assert!(!ip.is_null());
                    // SAFETY: class B (boundary). `neededInSize <= iend - ip`.
                    ip = unsafe { ip.add(neededInSize) };
                    continue 'outer;
                }
                if ip as usize == iend as usize {
                    someMoreWork = false;
                    continue 'outer;
                }
                let d = unsafe { &mut *zds };
                d.streamStage = zdss_load;
                continue 'outer;
            }

            zdss_load => {
                let inPos = d.inPos;
                // SAFETY: class B (boundary), forwarded. `d` (the match's
                // outer borrow) is not read again until a fresh `&mut *zds`
                // is taken below -- avoids interleaving a stale `&mut`
                // across a raw-pointer call into the same allocation.
                let neededInSize = unsafe { ZSTD_nextSrcSizeToDecompress(zds) };
                let toLoad = neededInSize - inPos;
                // SAFETY: class B (boundary), forwarded.
                let isSkipFrame = unsafe { ZSTD_isSkipFrame(zds) };
                let loadedSize: usize;
                debug_assert!(neededInSize == unsafe { ZSTD_nextSrcSizeToDecompressWithInputSize(zds, iend as usize - ip as usize) });
                let d = unsafe { &mut *zds };
                if isSkipFrame {
                    loadedSize = MIN_usize(toLoad, iend as usize - ip as usize);
                } else {
                    if toLoad > d.inBuffSize - d.inPos {
                        return ERROR(ZSTD_error_corruption_detected);
                    }
                    // SAFETY: class B (boundary), forwarded. `d.inBuff +
                    // d.inPos .. + toLoad` is within `d.inBuff ..
                    // d.inBuff + d.inBuffSize`, just checked.
                    loadedSize = unsafe {
                        ZSTD_limitCopy(d.inBuff.wrapping_add(d.inPos) as *mut c_void, toLoad, ip as *const c_void, iend as usize - ip as usize)
                    };
                }
                if loadedSize != 0 {
                    // SAFETY: class B (boundary). `loadedSize <= iend - ip`.
                    ip = unsafe { ip.add(loadedSize) };
                    let d = unsafe { &mut *zds };
                    d.inPos += loadedSize;
                }
                if loadedSize < toLoad {
                    someMoreWork = false;
                    continue 'outer;
                }

                let d = unsafe { &mut *zds };
                d.inPos = 0;
                let inBuff = d.inBuff;
                // SAFETY: class B (boundary), forwarded.
                let r = unsafe { ZSTD_decompressContinueStream(zds, &mut op, oend, inBuff as *const c_void, neededInSize) };
                if ZSTD_isError(r) != 0 {
                    return r;
                }
                continue 'outer;
            }

            zdss_flush => {
                let toFlushSize = d.outEnd - d.outStart;
                // SAFETY: class B (boundary), forwarded. `d.outBuff +
                // d.outStart .. + toFlushSize` is within `d.outBuff ..
                // d.outBuff + d.outBuffSize` (`d.outStart <= d.outEnd <=
                // d.outBuffSize`, this state machine's own invariant).
                let flushedSize = unsafe {
                    ZSTD_limitCopy(op as *mut c_void, oend as usize - op as usize, d.outBuff.wrapping_add(d.outStart) as *const c_void, toFlushSize)
                };
                op = op.wrapping_add(flushedSize);
                let d = unsafe { &mut *zds };
                d.outStart += flushedSize;
                if flushedSize == toFlushSize {
                    d.streamStage = zdss_read;
                    if d.outBuffSize < d.fParams.frameContentSize as usize && d.outStart + d.fParams.blockSizeMax as usize > d.outBuffSize {
                        d.outStart = 0;
                        d.outEnd = 0;
                    }
                    continue 'outer;
                }
                someMoreWork = false;
            }

            _ => unreachable!("ZSTD_DCtx::streamStage holds an impossible value"),
        }
    }

    // SAFETY: class B (boundary). `input`/`output` valid for writes.
    unsafe {
        (*input).pos = ip as usize - inp.src as usize;
        (*output).pos = op as usize - outp.dst as usize;
    }

    // SAFETY: class B (boundary).
    let d = unsafe { &mut *zds };
    d.expectedOutBuffer = unsafe { *output };

    if ip as usize == istart as usize && op as usize == ostart as usize {
        d.noForwardProgress += 1;
        if d.noForwardProgress >= ZSTD_NO_FORWARD_PROGRESS_MAX as c_int {
            if op as usize == oend as usize {
                return ERROR(ZSTD_error_noForwardProgress_destFull);
            }
            if ip as usize == iend as usize {
                return ERROR(ZSTD_error_noForwardProgress_inputEmpty);
            }
            debug_assert!(false, "unreachable: no forward progress with room on both sides");
        }
    } else {
        d.noForwardProgress = 0;
    }

    // SAFETY: class B (boundary), forwarded.
    let mut nextSrcSizeHint = unsafe { ZSTD_nextSrcSizeToDecompress(zds) };
    // Reborrowed fresh after the call above, which reborrows `*zds` through
    // the raw pointer -- not reusing the `d` from before it, per the
    // adversarial reborrow-aliasing review (2026-09-06).
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *zds };
    if nextSrcSizeHint == 0 {
        if d.outEnd == d.outStart {
            if d.hostageByte != 0 {
                // SAFETY: class B (boundary).
                if unsafe { (*input).pos } >= unsafe { (*input).size } {
                    d.streamStage = zdss_read;
                    return 1;
                }
                // SAFETY: class B (boundary).
                unsafe { (*input).pos += 1 };
                return 0;
            }
            return 0;
        }
        if d.hostageByte == 0 {
            // SAFETY: class B (boundary). `input.pos > 0`, guaranteed by
            // the same reasoning the C's own comment gives: it is
            // impossible to finish reading the last block with `pos == 0`.
            unsafe { (*input).pos -= 1 };
            d.hostageByte = 1;
        }
        return 1;
    }
    // SAFETY: class B (boundary), forwarded.
    let nit = unsafe { ZSTD_nextInputType(zds) };
    // Reborrowed fresh after the call above, same reasoning as the
    // reborrow following ZSTD_nextSrcSizeToDecompress a few lines up.
    // SAFETY: class B (boundary).
    let d = unsafe { &mut *zds };
    nextSrcSizeHint += ZSTD_blockHeaderSize * ((nit == 2) as usize);
    debug_assert!(d.inPos <= nextSrcSizeHint);
    nextSrcSizeHint -= d.inPos;
    nextSrcSizeHint
}

/// `ZSTD_decompressStream_simpleArgs()`.
///
/// # Safety
/// `dctx` must be valid for reads and writes; `dstPos`/`srcPos` must be
/// valid for reads and writes; `src .. src + srcSize` must be readable;
/// `dst .. dst + dstCapacity` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressStream_simpleArgs(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    dstPos: *mut usize,
    src: *const c_void,
    srcSize: usize,
    srcPos: *mut usize,
) -> usize {
    // SAFETY: class B (boundary).
    let mut output = ZstdOutBuffer { dst, size: dstCapacity, pos: unsafe { *dstPos } };
    // SAFETY: class B (boundary).
    let mut input = ZstdInBuffer { src, size: srcSize, pos: unsafe { *srcPos } };
    // SAFETY: class B (boundary), forwarded.
    let cErr = unsafe { ZSTD_decompressStream(dctx, &mut output, &mut input) };
    // SAFETY: class B (boundary).
    unsafe {
        *dstPos = output.pos;
        *srcPos = input.pos;
    }
    cErr
}

