// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the file it is ported from)

//! The digested-dictionary object: `struct ZSTD_DDict_s`'s only owner, and
//! every function that knows its internal layout.
//!
//! Ported from `lib/zstd/decompress/zstd_ddict.c` (6.18.49),
//! `Copyright (c) Meta Platforms, Inc. and affiliates.`, dual
//! GPL-2.0+/BSD-3-Clause.
//!
//! # Shape: no C entry thunks
//!
//! `nm` on the built object says **nothing in this file is `EXPORT_SYMBOL`'d**
//! -- the same shape every other file in `lib/zstd/decompress/` already took.
//! `zstd_decompress_module.c` calls `ZSTD_createDDict_advanced`/
//! `ZSTD_freeDDict` directly (not through a thunk); `zstd_decompress.c` calls
//! the rest. Every function is defined here directly under its own name
//! (`#[no_mangle] pub extern "C" fn`).
//!
//! `ZSTD_loadDEntropy` crosses the other way -- defined in
//! `zstd_decompress.c`, called from here -- and is declared `extern "C"`
//! below, same as every other cross-file call in this subsystem.
//!
//! # `struct ZSTD_DCtx_s` is mirrored here too, not shared
//!
//! `ZSTD_copyDDictParameters` writes nine `ZSTD_DCtx` fields scattered from
//! the struct's first field (`LLTptr`) to well past its middle (`dictID`),
//! so -- same reasoning as `zstd_decompress_block_rs.rs`'s `ZstdDCtx` -- a
//! full field-for-field mirror is required, not a truncated prefix. This is
//! a SEPARATE copy of that mirror, not a shared one: "one crate per ported
//! file, nothing to share it with" is this subsystem's standing convention
//! (see `zstd_decompress_block_rs.rs`'s own `HUF_flags_bmi2` comment), and
//! the two copies are kept field-identical by convention and by both being
//! checked against the same `offsetof()` proof
//! (`port/test/zstd_ddict/check_offsets.sh`, sharing its C half with
//! `port/test/zstd_decompress_block/check_offsets.c` since both check the
//! same real header), not by sharing a type.
//!
//! `struct ZSTD_DDict_s` mirrors fully too, but trivially: this file touches
//! every one of its seven fields, so there is no truncation question at all.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. `ZSTD_createDDict()`/`ZSTD_createDDict_byReference()` pass an
//!    all-`NULL` `ZSTD_customMem`, and this kernel's `ZSTD_malloc()` /
//!    `ZSTD_calloc()` (`zstd_deps.h`, behind `ZSTD_DEPS_NEED_MALLOC`) are
//!    hardcoded to always return `NULL` -- there is no libc allocator to
//!    fall back to. So both functions always fail whenever `dictLoadMethod`
//!    requires an internal copy, and even for `ZSTD_dlm_byRef` return a
//!    `ZSTD_DDict` that can never free anything it mallocs later through
//!    this path either. Neither has any in-tree caller (grep confirms only
//!    `zstd_decompress_module.c` calls `ZSTD_createDDict_advanced`
//!    directly, always with a real allocator). Ported anyway, faithfully:
//!    both still compile on x86-64 (SCOPE.md §3a only defers code that does
//!    not), and matching the pristine C's own dead-but-present shape is the
//!    point.
//!
//! Replaces: lib/zstd/decompress/zstd_ddict.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_uint, c_void};

// ---------------------------------------------------------------------------
// lib/zstd/common/zstd_internal.h -- format constants this file reads.
// ---------------------------------------------------------------------------

/// `ZSTD_FRAMEIDSIZE`, magic number size.
const ZSTD_FRAMEIDSIZE: usize = 4;

// ---------------------------------------------------------------------------
// include/linux/zstd_lib.h -- ZSTD_MAGIC_DICTIONARY and the three small
// enums this file's public functions take by value.
// ---------------------------------------------------------------------------

/// `ZSTD_MAGIC_DICTIONARY`.
const ZSTD_MAGIC_DICTIONARY: u32 = 0xEC30A437;

/// `ZSTD_dlm_byCopy`.
const ZSTD_DLM_BY_COPY: c_uint = 0;
/// `ZSTD_dlm_byRef`.
const ZSTD_DLM_BY_REF: c_uint = 1;

/// `ZSTD_dct_rawContent`.
const ZSTD_DCT_RAW_CONTENT: c_uint = 1;
/// `ZSTD_dct_fullDict`.
const ZSTD_DCT_FULL_DICT: c_uint = 2;

// ---------------------------------------------------------------------------
// zstd_decompress_internal.h -- ZSTD_seqSymbol and the entropy tables.
// Identical to zstd_decompress_block_rs.rs's own copy; see that file's
// module doc for why this subsystem keeps one copy per ported file rather
// than sharing a crate.
// ---------------------------------------------------------------------------

/// `ZSTD_seqSymbol`. Never read by this file; sized so `EntropyDTables`'s
/// three FSE tables land at the C's offsets.
#[derive(Clone, Copy)]
#[repr(C)]
struct SeqSymbol {
    nextState: u16,
    nbAdditionalBits: u8,
    nbBits: u8,
    baseValue: u32,
}

/// `SEQSYMBOL_TABLE_SIZE(log)`, `1 + (1 << log)`.
const fn seqsymbol_table_size(log: u32) -> usize {
    1 + (1usize << log)
}

/// `HUF_DTable`, `huf.h:65` -- `typedef U32 HUF_DTable`.
type HufDTable = u32;
/// `HUF_DTABLE_SIZE(maxTableLog)`, `1 + (1 << maxTableLog)`.
const fn huf_dtable_size(max_table_log: u32) -> usize {
    1 + (1usize << max_table_log)
}
/// `ZSTD_HUFFDTABLE_CAPACITY_LOG`.
const ZSTD_HUFFDTABLE_CAPACITY_LOG: u32 = 12;

/// `LLFSELog`.
const LL_FSE_LOG: u32 = 9;
/// `OffFSELog`.
const OFF_FSE_LOG: u32 = 8;
/// `MLFSELog`.
const ML_FSE_LOG: u32 = 9;
/// `MaxSeq`, `MAX(MaxLL, MaxML)`.
const MAX_SEQ: u32 = 52;
/// `MaxFSELog`, `MAX(MAX(MLFSELog, LLFSELog), OffFSELog)`.
const MAX_FSE_LOG: u32 = 9;
/// `ZSTD_REP_NUM`.
const ZSTD_REP_NUM: usize = 3;

/// `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE`, in bytes:
/// `sizeof(S16) * (MaxSeq + 1) + (1 << MaxFSELog) + sizeof(U64)`.
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE: usize =
    2 * (MAX_SEQ as usize + 1) + (1usize << MAX_FSE_LOG) + 8;
/// `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32`.
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32: usize = (ZSTD_BUILD_FSE_TABLE_WKSP_SIZE + 3) / 4;

/// `HUF_DECOMPRESS_WORKSPACE_SIZE`, `(2 << 10) + (1 << 9)` bytes.
const HUF_DECOMPRESS_WORKSPACE_SIZE: usize = (2 << 10) + (1 << 9);
/// `HUF_DECOMPRESS_WORKSPACE_SIZE_U32`.
const HUF_DECOMPRESS_WORKSPACE_SIZE_U32: usize = HUF_DECOMPRESS_WORKSPACE_SIZE / 4;

/// `ZSTD_entropyDTables_t`. `rep` is the only field this file's own
/// `ZstdDDict.entropy` ever reads; the rest, and every field of
/// `ZstdDCtx.entropy`, exist only for size and offset.
#[repr(C)]
struct EntropyDTables {
    LLTable: [SeqSymbol; seqsymbol_table_size(LL_FSE_LOG)],
    OFTable: [SeqSymbol; seqsymbol_table_size(OFF_FSE_LOG)],
    MLTable: [SeqSymbol; seqsymbol_table_size(ML_FSE_LOG)],
    hufTable: [HufDTable; huf_dtable_size(ZSTD_HUFFDTABLE_CAPACITY_LOG)],
    rep: [u32; ZSTD_REP_NUM],
    workspace: [u32; ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32],
}

// ---------------------------------------------------------------------------
// include/linux/zstd_lib.h -- ZSTD_customMem, and the rest of ZstdDCtx's
// never-touched-here field types.
// ---------------------------------------------------------------------------

/// `ZSTD_allocFunction`.
pub type ZstdAllocFunction = Option<unsafe extern "C" fn(opaque: *mut c_void, size: usize) -> *mut c_void>;
/// `ZSTD_freeFunction`.
pub type ZstdFreeFunction = Option<unsafe extern "C" fn(opaque: *mut c_void, address: *mut c_void)>;

/// `ZSTD_customMem`. Unlike `zstd_decompress_block_rs.rs`'s inert copy
/// (never called there), this file actually calls through both function
/// pointers, so they are typed as real `fn` pointers rather than
/// `*const c_void` -- `Option<extern "C" fn(..)>` is niche-optimized to a
/// single pointer-sized value, so the layout is unchanged either way.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ZstdCustomMem {
    /// `ZSTD_allocFunction`, or `None` to fall back to `ZSTD_malloc`
    /// (always `NULL` in this kernel -- see the module doc).
    pub customAlloc: ZstdAllocFunction,
    /// `ZSTD_freeFunction`, or `None` to fall back to `ZSTD_free` (a no-op
    /// in this kernel).
    pub customFree: ZstdFreeFunction,
    /// Opaque context passed to both functions above.
    pub opaque: *mut c_void,
}

/// `ZSTD_FrameHeader`. Never read by this file; exists only so `ZstdDCtx`'s
/// `fParams` field is sized correctly.
#[repr(C)]
struct ZstdFrameHeader {
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

/// `ZSTD_outBuffer`. Never read by this file; `{ void* dst; size_t size;
/// size_t pos; }`, three words.
#[repr(C)]
struct ZstdOutBuffer {
    dst: *mut c_void,
    size: usize,
    pos: usize,
}

/// `struct xxh64_state`, `include/linux/xxhash.h`. Never read by this file;
/// mirrored only so its 76 bytes push every later `ZstdDCtx` field to the
/// C's offset.
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

/// `ZSTD_LITBUFFEREXTRASIZE`.
const ZSTD_LITBUFFEREXTRASIZE: usize = 1 << 16;
/// `ZSTD_FRAMEHEADERSIZE_MAX`.
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;
/// `WILDCOPY_OVERLENGTH`.
const WILDCOPY_OVERLENGTH: usize = 32;

/// Mirrors `struct ZSTD_DCtx_s`, `zstd_decompress_internal.h`, field for
/// field, in the C's declaration order. Verified against `offsetof()` on
/// the real header by `port/test/zstd_ddict/check_offsets.sh` (the same
/// check `zstd_decompress_block_rs.rs`'s own copy already passed).
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
    isFrameDecompression: c_uint,
    #[cfg(DYNAMIC_BMI2)]
    bmi2: c_uint,
    ddictLocal: *mut c_void,
    ddict: *const c_void,
    dictID: u32,
    ddictIsCold: c_uint,
    dictUses: c_uint,
    ddictSet: *mut c_void,
    refMultipleDDicts: u32,
    disableHufAsm: c_uint,
    maxBlockSizeParam: c_uint,
    streamStage: u32,
    inBuff: *mut core::ffi::c_char,
    inBuffSize: usize,
    inPos: usize,
    maxWindowSize: usize,
    outBuff: *mut core::ffi::c_char,
    outBuffSize: usize,
    outStart: usize,
    outEnd: usize,
    lhSize: usize,
    hostageByte: u32,
    noForwardProgress: c_uint,
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
// zstd_ddict.c's own type
// ---------------------------------------------------------------------------

/// Mirrors `struct ZSTD_DDict_s`, `zstd_ddict.c:34-42`. Every field is read
/// or written somewhere in this file -- no truncation question here.
#[repr(C)]
pub struct ZstdDDict {
    dictBuffer: *mut c_void,
    dictContent: *const c_void,
    dictSize: usize,
    entropy: EntropyDTables,
    dictID: u32,
    entropyPresent: u32,
    cMem: ZstdCustomMem,
}

// ---------------------------------------------------------------------------
// Cross-file call into zstd_decompress.c (or, once ported, its Rust body
// under the same name -- the lib/union_find shape means that call resolves
// directly with no thunk either way).
// ---------------------------------------------------------------------------

extern "C" {
    fn ZSTD_loadDEntropy(entropy: *mut EntropyDTables, dict: *const c_void, dictSize: usize) -> usize;
}

// ---------------------------------------------------------------------------
// error codes and helpers -- own copy, same values as every other file in
// this subsystem (include/linux/zstd_errors.h).
// ---------------------------------------------------------------------------

const ZSTD_ERROR_DICTIONARY_CORRUPTED: usize = 30;
const ZSTD_ERROR_MEMORY_ALLOCATION: usize = 64;
const ZSTD_ERROR_MAX_CODE: usize = 120;

/// `ERROR(name)`, `error_private.h` -- `(size_t)-ZSTD_error_##name`.
const fn ERROR(code: usize) -> usize {
    0usize.wrapping_sub(code)
}

/// `ERR_isError()`.
fn ERR_isError(code: usize) -> bool {
    code > ERROR(ZSTD_ERROR_MAX_CODE)
}

/// `MEM_readLE32()`, `mem.h`.
///
/// # Safety
/// `p .. p + 4` must be readable.
unsafe fn MEM_readLE32(p: *const u8) -> u32 {
    // SAFETY: class C (construction). The caller guarantees 4 readable bytes.
    u32::from_le(unsafe { core::ptr::read_unaligned(p as *const u32) })
}

// ---------------------------------------------------------------------------
// allocations.h -- ZSTD_customMalloc/ZSTD_customFree, transcribed directly
// rather than called: both are `MEM_STATIC` (static inline) in the C, so
// there is no external symbol to bind an `extern "C"` declaration to, the
// same reason zstd_decompress_block_rs.rs transcribes ZSTD_highbit32
// instead of calling it. `ZSTD_malloc`/`ZSTD_calloc`/`ZSTD_free`
// (`zstd_deps.h`, behind `ZSTD_DEPS_NEED_MALLOC`) are hardcoded in this
// kernel to `NULL`/no-op unconditionally -- there is no libc fallback to
// reach -- so the "no custom allocator" arm below is that hardcoding
// inlined directly, not a stand-in for it.
// ---------------------------------------------------------------------------

/// `ZSTD_customMalloc()`.
///
/// # Safety
/// If `cmem.customAlloc` is set, it must be safe to call with `cmem.opaque`
/// and `size`.
unsafe fn zstd_custom_malloc(size: usize, cmem: &ZstdCustomMem) -> *mut c_void {
    match cmem.customAlloc {
        // SAFETY: class B (boundary). The caller's contract.
        Some(alloc) => unsafe { alloc(cmem.opaque, size) },
        None => core::ptr::null_mut(),
    }
}

/// `ZSTD_customFree()`.
///
/// # Safety
/// If `cmem.customFree` is set, it must be safe to call with `cmem.opaque`
/// and `ptr`.
unsafe fn zstd_custom_free(ptr: *mut c_void, cmem: &ZstdCustomMem) {
    if !ptr.is_null() {
        if let Some(free) = cmem.customFree {
            // SAFETY: class B (boundary). The caller's contract.
            unsafe { free(cmem.opaque, ptr) };
        }
    }
}

// ---------------------------------------------------------------------------
// zstd_ddict.c's own functions
// ---------------------------------------------------------------------------

/// `ZSTD_DDict_dictContent()`.
///
/// # Safety
/// `ddict` must be a live `ZstdDDict`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DDict_dictContent(ddict: *const ZstdDDict) -> *const c_void {
    debug_assert!(!ddict.is_null());
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { (*ddict).dictContent }
}

/// `ZSTD_DDict_dictSize()`.
///
/// # Safety
/// `ddict` must be a live `ZstdDDict`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_DDict_dictSize(ddict: *const ZstdDDict) -> usize {
    debug_assert!(!ddict.is_null());
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { (*ddict).dictSize }
}

/// `ZSTD_copyDDictParameters()`.
///
/// # Safety
/// `dctx` and `ddict` must both be live.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_copyDDictParameters(dctx: *mut ZstdDCtx, ddict: *const ZstdDDict) {
    debug_assert!(!dctx.is_null());
    debug_assert!(!ddict.is_null());
    // SAFETY: class B (boundary). The caller's contract.
    unsafe {
        (*dctx).dictID = (*ddict).dictID;
        (*dctx).prefixStart = (*ddict).dictContent;
        (*dctx).virtualStart = (*ddict).dictContent;
        (*dctx).dictEnd = ((*ddict).dictContent as *const u8).wrapping_add((*ddict).dictSize) as *const c_void;
        (*dctx).previousDstEnd = (*dctx).dictEnd;
        if (*ddict).entropyPresent != 0 {
            (*dctx).litEntropy = 1;
            (*dctx).fseEntropy = 1;
            (*dctx).LLTptr = (*ddict).entropy.LLTable.as_ptr();
            (*dctx).MLTptr = (*ddict).entropy.MLTable.as_ptr();
            (*dctx).OFTptr = (*ddict).entropy.OFTable.as_ptr();
            (*dctx).HUFptr = (*ddict).entropy.hufTable.as_ptr();
            (*dctx).entropy.rep[0] = (*ddict).entropy.rep[0];
            (*dctx).entropy.rep[1] = (*ddict).entropy.rep[1];
            (*dctx).entropy.rep[2] = (*ddict).entropy.rep[2];
        } else {
            (*dctx).litEntropy = 0;
            (*dctx).fseEntropy = 0;
        }
    }
}

/// `ZSTD_loadEntropy_intoDDict()`.
///
/// # Safety
/// `ddict` must be a live, writable `ZstdDDict` whose `dictContent`/
/// `dictSize` are already set.
unsafe fn zstd_load_entropy_into_ddict(ddict: *mut ZstdDDict, dictContentType: c_uint) -> usize {
    // SAFETY: class B (boundary). The caller's contract.
    unsafe {
        (*ddict).dictID = 0;
        (*ddict).entropyPresent = 0;
        if dictContentType == ZSTD_DCT_RAW_CONTENT {
            return 0;
        }
        if (*ddict).dictSize < 8 {
            if dictContentType == ZSTD_DCT_FULL_DICT {
                return ERROR(ZSTD_ERROR_DICTIONARY_CORRUPTED);
            }
            return 0;
        }
        // SAFETY: class C (construction). `dictSize >= 8` was just checked.
        let magic = MEM_readLE32((*ddict).dictContent as *const u8);
        if magic != ZSTD_MAGIC_DICTIONARY {
            if dictContentType == ZSTD_DCT_FULL_DICT {
                return ERROR(ZSTD_ERROR_DICTIONARY_CORRUPTED);
            }
            return 0;
        }
        // SAFETY: class C (construction). `dictSize >= 8 >= ZSTD_FRAMEIDSIZE + 4`.
        (*ddict).dictID = MEM_readLE32(((*ddict).dictContent as *const u8).wrapping_add(ZSTD_FRAMEIDSIZE));

        let r = ZSTD_loadDEntropy(&mut (*ddict).entropy, (*ddict).dictContent, (*ddict).dictSize);
        if ERR_isError(r) {
            return ERROR(ZSTD_ERROR_DICTIONARY_CORRUPTED);
        }
        (*ddict).entropyPresent = 1;
        0
    }
}

/// `ZSTD_initDDict_internal()`.
///
/// # Safety
/// `ddict` must be a live, writable, not-yet-initialized `ZstdDDict` whose
/// `cMem` is already set.
unsafe fn zstd_init_ddict_internal(
    ddict: *mut ZstdDDict,
    dict: *const c_void,
    mut dictSize: usize,
    dictLoadMethod: c_uint,
    dictContentType: c_uint,
) -> usize {
    // SAFETY: class B (boundary) for `ddict`'s own fields; class B (the
    // caller's contract) for `dict .. dict + dictSize` in the copy branch.
    unsafe {
        if dictLoadMethod == ZSTD_DLM_BY_REF || dict.is_null() || dictSize == 0 {
            (*ddict).dictBuffer = core::ptr::null_mut();
            (*ddict).dictContent = dict;
            if dict.is_null() {
                dictSize = 0;
            }
        } else {
            let internalBuffer = zstd_custom_malloc(dictSize, &(*ddict).cMem);
            (*ddict).dictBuffer = internalBuffer;
            (*ddict).dictContent = internalBuffer;
            if internalBuffer.is_null() {
                return ERROR(ZSTD_ERROR_MEMORY_ALLOCATION);
            }
            core::ptr::copy_nonoverlapping(dict as *const u8, internalBuffer as *mut u8, dictSize);
        }
        (*ddict).dictSize = dictSize;
        // "cover both little and big endian" -- ZSTD_HUFFDTABLE_CAPACITY_LOG
        // packed into both halves of the first table cell.
        (*ddict).entropy.hufTable[0] = ZSTD_HUFFDTABLE_CAPACITY_LOG.wrapping_mul(0x1000001);

        let r = zstd_load_entropy_into_ddict(ddict, dictContentType);
        if ERR_isError(r) {
            return r;
        }
        0
    }
}

/// `ZSTD_createDDict_advanced()`.
///
/// # Safety
/// If `customMem.customAlloc`/`customFree` are set, they must be safe to
/// call as described by `ZSTD_customMem`'s contract. `dict .. dict +
/// dictSize` must be readable if `dict` is non-null.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_createDDict_advanced(
    dict: *const c_void,
    dictSize: usize,
    dictLoadMethod: c_uint,
    dictContentType: c_uint,
    customMem: ZstdCustomMem,
) -> *mut ZstdDDict {
    if customMem.customAlloc.is_none() ^ customMem.customFree.is_none() {
        return core::ptr::null_mut();
    }
    // SAFETY: class B (boundary), for both the allocator call and the
    // "not yet initialized" contract `zstd_init_ddict_internal` documents.
    unsafe {
        let ddict = zstd_custom_malloc(core::mem::size_of::<ZstdDDict>(), &customMem) as *mut ZstdDDict;
        if ddict.is_null() {
            return core::ptr::null_mut();
        }
        (*ddict).cMem = customMem;
        let initResult = zstd_init_ddict_internal(ddict, dict, dictSize, dictLoadMethod, dictContentType);
        if ERR_isError(initResult) {
            ZSTD_freeDDict(ddict);
            return core::ptr::null_mut();
        }
        ddict
    }
}

/// `ZSTD_createDDict()`. See the module doc's divergence note: with this
/// kernel's always-`NULL` `ZSTD_malloc`, this always fails.
///
/// # Safety
/// `dict .. dict + dictSize` must be readable if `dict` is non-null.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_createDDict(dict: *const c_void, dictSize: usize) -> *mut ZstdDDict {
    let allocator = ZstdCustomMem { customAlloc: None, customFree: None, opaque: core::ptr::null_mut() };
    // SAFETY: class B (boundary). The caller's contract, forwarded.
    unsafe { ZSTD_createDDict_advanced(dict, dictSize, ZSTD_DLM_BY_COPY, /* ZSTD_dct_auto */ 0, allocator) }
}

/// `ZSTD_createDDict_byReference()`. See the module doc's divergence note.
///
/// # Safety
/// `dictBuffer` must outlive the returned `ZSTD_DDict` and be readable for
/// `dictSize` bytes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_createDDict_byReference(dictBuffer: *const c_void, dictSize: usize) -> *mut ZstdDDict {
    let allocator = ZstdCustomMem { customAlloc: None, customFree: None, opaque: core::ptr::null_mut() };
    // SAFETY: class B (boundary). The caller's contract, forwarded.
    unsafe { ZSTD_createDDict_advanced(dictBuffer, dictSize, ZSTD_DLM_BY_REF, /* ZSTD_dct_auto */ 0, allocator) }
}

/// `ZSTD_initStaticDDict()`.
///
/// # Safety
/// `sBuffer .. sBuffer + sBufferSize` must be writable; `dict .. dict +
/// dictSize` must be readable.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_initStaticDDict(
    sBuffer: *mut c_void,
    sBufferSize: usize,
    dict: *const c_void,
    dictSize: usize,
    dictLoadMethod: c_uint,
    dictContentType: c_uint,
) -> *const ZstdDDict {
    let neededSpace =
        core::mem::size_of::<ZstdDDict>() + if dictLoadMethod == ZSTD_DLM_BY_REF { 0 } else { dictSize };
    let ddict = sBuffer as *mut ZstdDDict;
    debug_assert!(!sBuffer.is_null());
    debug_assert!(!dict.is_null());
    if (sBuffer as usize) & 7 != 0 {
        return core::ptr::null();
    }
    if sBufferSize < neededSpace {
        return core::ptr::null();
    }
    let mut dict = dict;
    if dictLoadMethod == ZSTD_DLM_BY_COPY {
        // SAFETY: class C (construction). `sBufferSize >= neededSpace`,
        // which for the byCopy arm includes `dictSize` bytes right after
        // `ddict + 1` for exactly this copy; the caller's contract covers
        // `dict .. dict + dictSize`.
        unsafe {
            core::ptr::copy_nonoverlapping(dict as *const u8, ddict.wrapping_add(1) as *mut u8, dictSize);
        }
        dict = ddict.wrapping_add(1) as *const c_void;
    }
    // SAFETY: class C (construction). `ddict` is `sBuffer`, 8-aligned and
    // sized for a `ZstdDDict` (both just checked); not-yet-initialized, as
    // `zstd_init_ddict_internal` requires.
    let initResult = unsafe { zstd_init_ddict_internal(ddict, dict, dictSize, ZSTD_DLM_BY_REF, dictContentType) };
    if ERR_isError(initResult) {
        return core::ptr::null();
    }
    ddict
}

/// `ZSTD_freeDDict()`.
///
/// # Safety
/// `ddict` must be either null or a pointer this file returned from one of
/// its own `create`/`init` functions (or, for the `byRef`/static case, the
/// backing buffer must otherwise be `ddict`'s to free -- matching the C).
#[no_mangle]
pub unsafe extern "C" fn ZSTD_freeDDict(ddict: *mut ZstdDDict) -> usize {
    if ddict.is_null() {
        return 0;
    }
    // SAFETY: class B (boundary). The caller's contract. `cMem` is copied
    // out before either free, matching the C's own `const cMem = ddict->
    // cMem` -- freeing `ddict` first would leave `ddict->cMem` dangling.
    unsafe {
        let cMem = (*ddict).cMem;
        zstd_custom_free((*ddict).dictBuffer, &cMem);
        zstd_custom_free(ddict as *mut c_void, &cMem);
    }
    0
}

/// `ZSTD_estimateDDictSize()`.
#[no_mangle]
pub extern "C" fn ZSTD_estimateDDictSize(dictSize: usize, dictLoadMethod: c_uint) -> usize {
    core::mem::size_of::<ZstdDDict>() + if dictLoadMethod == ZSTD_DLM_BY_REF { 0 } else { dictSize }
}

/// `ZSTD_sizeof_DDict()`.
///
/// # Safety
/// `ddict` must be either null or a live `ZstdDDict`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_sizeof_DDict(ddict: *const ZstdDDict) -> usize {
    if ddict.is_null() {
        return 0;
    }
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { core::mem::size_of::<ZstdDDict>() + if !(*ddict).dictBuffer.is_null() { (*ddict).dictSize } else { 0 } }
}

/// `ZSTD_getDictID_fromDDict()`.
///
/// # Safety
/// `ddict` must be either null or a live `ZstdDDict`.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getDictID_fromDDict(ddict: *const ZstdDDict) -> c_uint {
    if ddict.is_null() {
        return 0;
    }
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { (*ddict).dictID }
}
