// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the file it is ported from)

//! Block decompression: literals, FSE sequence-header tables, and the
//! sequence-execution loops that are the direct consumer of everything in
//! `lib/zstd/common` and `lib/zstd/decompress/huf_decompress_rs.rs`.
//!
//! Ported from `lib/zstd/decompress/zstd_decompress_block.c` (6.18.49),
//! `Copyright (c) Meta Platforms, Inc. and affiliates.`, dual
//! GPL-2.0+/BSD-3-Clause.
//!
//! # Shape: no C entry thunks
//!
//! `nm` on the built object says **nothing in this file is `EXPORT_SYMBOL`'d**
//! -- the same shape `entropy_common.c`/`fse_decompress.c` and
//! `huf_decompress.c` already took. `ZSTD_decompressBlock()` is declared in
//! the public `zstd_lib.h` but has zero callers anywhere in this kernel tree;
//! every in-tree path reaches this file's decoder through
//! `ZSTD_decompressBlock_internal()`, called from `zstd_decompress.c`, which
//! stays C and is this file's only caller. So: every function crossing that
//! boundary is defined here directly under its own name
//! (`#[no_mangle] pub extern "C" fn`), `zstd_decompress_block.c` has no code
//! left to compile, and it is dropped from the Makefile.
//!
//! Five functions cross into this file from `zstd_decompress.c`:
//! `ZSTD_decompressBlock_internal`, `ZSTD_checkContinuity`,
//! `ZSTD_buildFSETable` (called directly when loading a dictionary's
//! pre-built entropy tables, not just internally when decoding a block's own
//! sequence headers), `ZSTD_getcBlockSize` and `ZSTD_decodeSeqHeaders`
//! (both declared in `zstd_internal.h` for `fullbench`, per the pristine
//! header's own comment). All five keep their C names and `#[no_mangle]`.
//!
//! # `struct ZSTD_DCtx_s` is mirrored here, not truncated
//!
//! Unlike `inffast_rs.rs`'s deliberately truncated copy of `InflateState`
//! (safe there because every field it drops comes *after* the last one it
//! touches), this file's 24 touched fields are scattered from the first
//! field to the last, so a prefix truncation is not available. Every field
//! is declared, in the C's order, with a type of the same size and alignment
//! -- untouched fields get an honestly-named but never-read type (a raw
//! pointer, a plain integer, a same-sized nested struct) rather than being
//! skipped. `#[repr(C)]` then reproduces the same layout the C compiler
//! computes, field by field, the same reasoning `InflateState`'s own (full)
//! mirror rests on. **Not yet independently checked against `offsetof()` on
//! the real header** -- that is `port/test/zstd_decompress_block/`'s job,
//! same as every other mirrored struct in this project; until that harness
//! exists this layout is a careful hand-derivation, not a proven one.
//!
//! `ZSTD_DCtx` is never allocated or freed here -- `zstd_decompress.c` (and,
//! for the one-shot API, `zstd_decompress_module.c`) own it entirely. This
//! file only ever receives a live `*mut ZstdDCtx` and touches the fields
//! listed below.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **`ZSTD_dictionaryIsActive()` and `ZSTD_assertValidSequence()` are not
//!    ported.** Both, and every call to the latter, are wrapped in
//!    `#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) &&
//!    defined(FUZZING_ASSERT_VALID_SEQUENCE)` in the pristine C --
//!    upstream zstd's own fuzzing harness gate, never defined anywhere in
//!    this kernel tree or its Kconfig. No build this project produces
//!    compiles that code, which is SCOPE.md §3a's deferral rule exactly:
//!    code no x86-64 build compiles is deferred, not ported. The two fields
//!    that only exist to feed it, `dictContentBeginForFuzzing` and
//!    `dictContentEndForFuzzing`, are likewise absent from the `ZstdDCtx`
//!    mirror below -- they are `#ifdef`'d out of the real struct on every
//!    build this project produces too, so including them would make the
//!    mirror wrong, not conservative.
//!
//! Replaces: lib/zstd/decompress/zstd_decompress_block.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uint, c_void};

// ---------------------------------------------------------------------------
// lib/zstd/common/zstd_internal.h -- format constants
// ---------------------------------------------------------------------------

/// `ZSTD_BLOCKHEADERSIZE`.
const ZSTD_BLOCK_HEADER_SIZE: usize = 3;
/// `MIN_SEQUENCES_SIZE`.
const MIN_SEQUENCES_SIZE: usize = 1;
/// `MIN_CBLOCK_SIZE`.
const MIN_CBLOCK_SIZE: usize = 2;
/// `MIN_LITERALS_FOR_4_STREAMS`.
const MIN_LITERALS_FOR_4_STREAMS: usize = 6;
/// `LONGNBSEQ`.
const LONGNBSEQ: i32 = 0x7F00;
/// `LL_DEFAULTNORMLOG`.
const LL_DEFAULTNORMLOG: u32 = 6;
/// `OF_DEFAULTNORMLOG`.
const OF_DEFAULTNORMLOG: u32 = 5;
/// `ML_DEFAULTNORMLOG`.
const ML_DEFAULTNORMLOG: u32 = 6;
/// `MaxLL`.
const MAX_LL: u32 = 35;
/// `MaxML`.
const MAX_ML: u32 = 52;
/// `MaxOff`.
const MAX_OFF: u32 = 31;
/// `MaxSeq`, `MAX(MaxLL, MaxML)`.
const MAX_SEQ: u32 = 52;
/// `LLFSELog`.
const LL_FSE_LOG: u32 = 9;
/// `OffFSELog`.
const OFF_FSE_LOG: u32 = 8;
/// `MLFSELog`.
const ML_FSE_LOG: u32 = 9;
/// `MaxFSELog`, `MAX(MAX(MLFSELog, LLFSELog), OffFSELog)`.
const MAX_FSE_LOG: u32 = 9;
/// `ZSTD_REP_NUM`.
const ZSTD_REP_NUM: usize = 3;
/// `WILDCOPY_OVERLENGTH`.
const WILDCOPY_OVERLENGTH: usize = 32;
/// `ZSTD_BLOCKSIZE_MAX`, `1 << ZSTD_BLOCKSIZELOG_MAX(17)`.
const ZSTD_BLOCKSIZE_MAX: usize = 1 << 17;

/// `blockType_e`.
/// `Raw`/`Compressed` are never matched by name: the C only special-cases
/// `bt_rle` and `bt_reserved` in `ZSTD_getcBlockSize`, checking the other
/// two only by falling through, so this mirrors that asymmetry rather than
/// inventing uses for the other two variants.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[allow(dead_code)]
enum BlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Reserved = 3,
}

/// `streaming_operation`, `zstd_decompress_block.h`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StreamingOperation {
    /// `not_streaming`.
    NotStreaming = 0,
    /// `is_streaming`.
    IsStreaming = 1,
}

/// `blockProperties_t`, `zstd_internal.h`. Caller-owned, out-parameter only.
#[repr(C)]
pub struct BlockProperties {
    /// `blockType_e` as a raw `u32` (`bt_raw`/`bt_rle`/`bt_compressed`/`bt_reserved`).
    pub blockType: u32,
    /// Nonzero if this is the frame's last block.
    pub lastBlock: u32,
    /// Decompressed size of this block.
    pub origSize: u32,
}

// ---------------------------------------------------------------------------
// lib/zstd/common/huf.h -- flags this file OR's into HUF_decompress*'s flags
// argument. Own copy, same reasoning as every other file in this subsystem:
// one crate per ported file, nothing to share it with.
// ---------------------------------------------------------------------------

/// `HUF_flags_bmi2`.
const HUF_FLAGS_BMI2: c_int = 1;
/// `HUF_flags_disableAsm`.
const HUF_FLAGS_DISABLE_ASM: c_int = 1 << 4;

// ---------------------------------------------------------------------------
// zstd_decompress_internal.h -- ZSTD_seqSymbol and the entropy tables
// ---------------------------------------------------------------------------

/// `ZSTD_seqSymbol`. Four bytes, no internal padding: `U16`+`BYTE`+`BYTE`
/// packs to offset 0/2/3, `U32` at offset 4 needs no filler. `pub` because
/// [`ZSTD_buildFSETable`] exposes `*mut SeqSymbol` in its own `pub` C ABI.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SeqSymbol {
    /// Next FSE state.
    pub nextState: u16,
    /// Number of additional raw bits this symbol's value carries.
    pub nbAdditionalBits: u8,
    /// Number of bits to read to select the next state.
    pub nbBits: u8,
    /// This symbol's base value, before adding the raw bits read.
    pub baseValue: u32,
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

/// `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE`, in bytes:
/// `sizeof(S16) * (MaxSeq + 1) + (1 << MaxFSELog) + sizeof(U64)`.
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE: usize =
    2 * (MAX_SEQ as usize + 1) + (1usize << MAX_FSE_LOG) + 8;
/// `ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32`.
const ZSTD_BUILD_FSE_TABLE_WKSP_SIZE_U32: usize =
    (ZSTD_BUILD_FSE_TABLE_WKSP_SIZE + 3) / 4;

/// `HUF_DECOMPRESS_WORKSPACE_SIZE`, `(2 << 10) + (1 << 9)` bytes.
const HUF_DECOMPRESS_WORKSPACE_SIZE: usize = (2 << 10) + (1 << 9);
/// `HUF_DECOMPRESS_WORKSPACE_SIZE_U32`.
const HUF_DECOMPRESS_WORKSPACE_SIZE_U32: usize = HUF_DECOMPRESS_WORKSPACE_SIZE / 4;

/// `ZSTD_entropyDTables_t`. Every array is exactly the size the C's macros
/// give it; `workspace` is never read by this file (only ever passed by
/// pointer via the outer `ZstdDCtx::workspace` field instead) but must stay
/// correctly sized so every field the outer struct declares after `entropy`
/// lands at the C's offset.
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
// include/linux/zstd_lib.h -- the pieces of ZSTD_FrameHeader, ZSTD_customMem
// and ZSTD_outBuffer this file's DCtx mirror needs, sized but mostly opaque.
// ---------------------------------------------------------------------------

/// `ZSTD_FrameHeader`. Only `blockSizeMax` and `windowSize` are ever read by
/// this file; the rest exists so the struct's size and the offset of
/// `blockSizeMax`/`windowSize` within it match the C exactly.
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

/// `ZSTD_customMem`. Never read by this file; two function pointers and an
/// opaque pointer, three words.
#[repr(C)]
struct ZstdCustomMem {
    customAlloc: *const c_void,
    customFree: *const c_void,
    opaque: *mut c_void,
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
/// mirrored only so its 76 bytes (9 `u64`s' worth, the last one narrowed to
/// `u32`) push every later `ZstdDCtx` field to the C's offset.
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

/// `ZSTD_LITBUFFEREXTRASIZE`, `BOUNDED(64, 1 << 16, 128 << 10)` == `1 << 16`
/// (already inside the bound).
const ZSTD_LITBUFFEREXTRASIZE: usize = 1 << 16;
/// `ZSTD_FRAMEHEADERSIZE_MAX`.
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;

/// `ZSTD_litLocation_e`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum LitLocation {
    NotInDst = 0,
    InDst = 1,
    Split = 2,
}

/// Mirrors `struct ZSTD_DCtx_s`, `zstd_decompress_internal.h`. See the module
/// docs: every field is declared, in the C's order, with a same-size type --
/// untouched ones exist only to keep every later field's offset correct.
/// **Not yet checked against `offsetof()` on the real header.**
///
/// `#[cfg(DYNAMIC_BMI2)]` on `bmi2` matches the C's `#if DYNAMIC_BMI2` around
/// the same field -- true on every build this project produces (x86-64, GCC
/// >= 11 (clang here), `__BMI2__` unset), but spelled as a real condition
/// rather than assumed, the same discipline `entropy_common_rs.rs`'s
/// `HUF_flags_bmi2` constant already applies.
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
    ddictLocal: *mut c_void,
    ddict: *const c_void,
    dictID: u32,
    ddictIsCold: c_int,
    dictUses: c_int,
    ddictSet: *mut c_void,
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

/// `ZSTD_DCtx_get_bmi2()`, `zstd_decompress_internal.h`.
#[inline]
fn dctx_get_bmi2(dctx: &ZstdDCtx) -> c_int {
    #[cfg(DYNAMIC_BMI2)]
    {
        dctx.bmi2
    }
    #[cfg(not(DYNAMIC_BMI2))]
    {
        let _ = dctx;
        0
    }
}

// ---------------------------------------------------------------------------
// include/linux/zstd_errors.h and lib/zstd/common/error_private.h
//
// Copied from entropy_common_rs.rs/huf_decompress_rs.rs; see the module docs
// on why each ported file carries its own copy.
// ---------------------------------------------------------------------------

const ZSTD_error_GENERIC: usize = 1;
const ZSTD_error_corruption_detected: usize = 20;
const ZSTD_error_literals_headerWrong: usize = 24;
const ZSTD_error_dictionary_corrupted: usize = 30;
const ZSTD_error_dstSize_tooSmall: usize = 70;
const ZSTD_error_srcSize_wrong: usize = 72;
const ZSTD_error_maxCode: usize = 120;

/// `error_private.h:42` — `#define ZSTD_ERROR(name) ((size_t)-PREFIX(name))`.
#[inline(always)]
const fn ERROR(code: usize) -> usize {
    0usize.wrapping_sub(code)
}

/// `error_private.h:44` — `return (code > ERROR(maxCode));`
#[inline(always)]
fn ERR_isError(code: usize) -> bool {
    code > ERROR(ZSTD_error_maxCode)
}

// ---------------------------------------------------------------------------
// lib/zstd/common/mem.h — unaligned access. Copied verbatim from the other
// files in this subsystem; see their module docs for why LE vs native
// endianness matters here.
// ---------------------------------------------------------------------------

/// `mem.h:149` — `get_unaligned_le16()`.
///
/// # Safety
/// `p .. p + 2` must be readable.
#[inline(always)]
unsafe fn MEM_readLE16(p: *const u8) -> u16 {
    // SAFETY: class C (construction). The caller guarantees 2 readable bytes.
    u16::from_le(unsafe { core::ptr::read_unaligned(p as *const u16) })
}

/// `mem.h:159` — `MEM_readLE16(p) + (p[2] << 16)`.
///
/// # Safety
/// `p .. p + 3` must be readable.
#[inline(always)]
unsafe fn MEM_readLE24(p: *const u8) -> u32 {
    // SAFETY: class C (construction). The caller guarantees 3 readable bytes,
    // which covers both the 2-byte read and the single byte at offset 2.
    (unsafe { MEM_readLE16(p) } as u32) + ((unsafe { *p.add(2) } as u32) << 16)
}

/// `mem.h:172` — `get_unaligned_le32()`.
///
/// # Safety
/// `p .. p + 4` must be readable.
#[inline(always)]
unsafe fn MEM_readLE32(p: *const u8) -> u32 {
    // SAFETY: class C (construction). The caller guarantees 4 readable bytes.
    u32::from_le(unsafe { core::ptr::read_unaligned(p as *const u32) })
}

/// `mem.h:142` — `put_unaligned()`, **native** endianness, not LE.
///
/// # Safety
/// `p .. p + 8` must be writable.
#[inline(always)]
unsafe fn MEM_write64(p: *mut u8, value: u64) {
    // SAFETY: class C (construction). The caller guarantees 8 writable bytes.
    unsafe { core::ptr::write_unaligned(p as *mut u64, value) }
}

const SIZE_BYTES: usize = core::mem::size_of::<usize>();
const SIZE_BITS: u32 = (SIZE_BYTES * 8) as u32;
/// `mem.h:91` — `MEM_32bits()`.
const MEM_32BITS: bool = SIZE_BYTES == 4;
/// `mem.h:96` — `MEM_64bits()`.
const MEM_64BITS: bool = SIZE_BYTES == 8;

/// `mem.h:182` — `MEM_readLEST()`, `get_unaligned_le64()` on 64-bit and
/// `get_unaligned_le32()` on 32-bit.
///
/// # Safety
/// `p .. p + SIZE_BYTES` must be readable.
#[inline(always)]
unsafe fn MEM_readLEST(p: *const u8) -> usize {
    // SAFETY: class C (construction). The caller guarantees `SIZE_BYTES`
    // readable bytes; nearly every call site reaches this through
    // `BitDStream::read_st`, which asserts it.
    usize::from_le(unsafe { core::ptr::read_unaligned(p as *const usize) })
}

// ---------------------------------------------------------------------------
// lib/zstd/common/bitstream.h
//
// Copied from entropy_common_rs.rs/huf_decompress_rs.rs; see their module
// docs for why each ported file carries its own copy. `BIT_reloadDStreamFast`
// (used by neither of those two files) is added here because this file's
// decode loops use it.
// ---------------------------------------------------------------------------

/// `bitstream.h:92`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
enum BIT_DStream_status {
    unfinished = 0,
    endOfBuffer = 1,
    completed = 2,
    overflow = 3,
}

/// `bitstream.h:400-405` — the zero word `BIT_reloadDStream()` parks `ptr` on
/// once the stream has overflowed. Never dereferenced afterwards.
static BIT_ZERO_FILLED: usize = 0;

/// `bitstream.h:84`, plus `src_size` (divergence, per `huf_decompress_rs.rs`).
struct BitDStream {
    bitContainer: usize,
    bitsConsumed: u32,
    ptr: *const u8,
    start: *const u8,
    limitPtr: *const u8,
    /// Not in the C. The length of the buffer `start` points at, so
    /// [`BitDStream::read_st`] can check a whole-word read.
    src_size: usize,
}

impl BitDStream {
    /// `MEM_readLEST(bitD->ptr)`, bounds-checked.
    #[inline(always)]
    fn read_st(&self) -> usize {
        let off = (self.ptr as usize).wrapping_sub(self.start as usize);
        assert!(SIZE_BYTES <= self.src_size && off <= self.src_size - SIZE_BYTES);
        // SAFETY: class C (construction). `off + SIZE_BYTES <= src_size` was
        // just checked, and `start .. start + src_size` is the caller's
        // buffer.
        unsafe { MEM_readLEST(self.ptr) }
    }
}

/// `bitstream.h:239` — `BIT_initDStream()`.
///
/// # Safety
/// `srcBuffer` must point at `srcSize` readable bytes.
#[inline(always)]
unsafe fn BIT_initDStream(bitD: &mut BitDStream, srcBuffer: *const u8, srcSize: usize) -> usize {
    if srcSize < 1 {
        bitD.bitContainer = 0;
        bitD.bitsConsumed = 0;
        bitD.ptr = core::ptr::null();
        bitD.start = core::ptr::null();
        bitD.limitPtr = core::ptr::null();
        bitD.src_size = 0;
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    bitD.start = srcBuffer;
    bitD.src_size = srcSize;
    bitD.limitPtr = bitD.start.wrapping_add(SIZE_BYTES);

    if srcSize >= SIZE_BYTES {
        bitD.ptr = srcBuffer.wrapping_add(srcSize.wrapping_sub(SIZE_BYTES));
        bitD.bitContainer = bitD.read_st();
        // SAFETY: class C (construction). `srcSize >= 1`.
        let lastByte = unsafe { *srcBuffer.add(srcSize.wrapping_sub(1)) };
        bitD.bitsConsumed = if lastByte != 0 {
            8u32.wrapping_sub(ZSTD_highbit32(lastByte as u32))
        } else {
            0
        };
        if lastByte == 0 {
            return ERROR(ZSTD_error_GENERIC);
        }
    } else {
        bitD.ptr = bitD.start;
        // SAFETY: class C (construction). `srcSize >= 1`, and every access
        // below is guarded by `srcSize` being at least that large.
        unsafe {
            bitD.bitContainer = *bitD.start as usize;
            if srcSize >= 7 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(6) as usize).wrapping_shl(SIZE_BITS - 16));
            }
            if srcSize >= 6 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(5) as usize).wrapping_shl(SIZE_BITS - 24));
            }
            if srcSize >= 5 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(4) as usize).wrapping_shl(SIZE_BITS - 32));
            }
            if srcSize >= 4 {
                bitD.bitContainer =
                    bitD.bitContainer.wrapping_add((*srcBuffer.add(3) as usize) << 24);
            }
            if srcSize >= 3 {
                bitD.bitContainer =
                    bitD.bitContainer.wrapping_add((*srcBuffer.add(2) as usize) << 16);
            }
            if srcSize >= 2 {
                bitD.bitContainer =
                    bitD.bitContainer.wrapping_add((*srcBuffer.add(1) as usize) << 8);
            }
            let lastByte = *srcBuffer.add(srcSize.wrapping_sub(1));
            bitD.bitsConsumed = if lastByte != 0 {
                8u32.wrapping_sub(ZSTD_highbit32(lastByte as u32))
            } else {
                0
            };
            if lastByte == 0 {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }
        bitD.bitsConsumed = bitD
            .bitsConsumed
            .wrapping_add((SIZE_BYTES.wrapping_sub(srcSize).wrapping_mul(8)) as u32);
    }

    srcSize
}

/// `bitstream.h:292` — `BIT_getMiddleBits()`.
#[inline(always)]
fn BIT_getMiddleBits(bitContainer: usize, start: u32, nbBits: u32) -> usize {
    let regMask: u32 = SIZE_BITS - 1;
    (bitContainer.wrapping_shr(start & regMask))
        & (1u64.wrapping_shl(nbBits).wrapping_sub(1)) as usize
}

/// `bitstream.h:315` — `BIT_lookBits()`.
#[inline(always)]
fn BIT_lookBits(bitD: &BitDStream, nbBits: u32) -> usize {
    BIT_getMiddleBits(
        bitD.bitContainer,
        SIZE_BITS.wrapping_sub(bitD.bitsConsumed).wrapping_sub(nbBits),
        nbBits,
    )
}

/// `bitstream.h:331` — `BIT_lookBitsFast()`; only works if `nbBits >= 1`.
#[inline(always)]
fn BIT_lookBitsFast(bitD: &BitDStream, nbBits: u32) -> usize {
    let regMask: u32 = SIZE_BITS - 1;
    bitD.bitContainer
        .wrapping_shl(bitD.bitsConsumed & regMask)
        .wrapping_shr((regMask.wrapping_add(1).wrapping_sub(nbBits)) & regMask)
}

/// `bitstream.h:338` — `BIT_skipBits()`.
#[inline(always)]
fn BIT_skipBits(bitD: &mut BitDStream, nbBits: u32) {
    bitD.bitsConsumed = bitD.bitsConsumed.wrapping_add(nbBits);
}

/// `bitstream.h:347` — `BIT_readBits()`.
#[inline(always)]
fn BIT_readBits(bitD: &mut BitDStream, nbBits: u32) -> usize {
    let value = BIT_lookBits(bitD, nbBits);
    BIT_skipBits(bitD, nbBits);
    value
}

/// `bitstream.h:356` — `BIT_readBitsFast()`; only works if `nbBits >= 1`.
#[inline(always)]
fn BIT_readBitsFast(bitD: &mut BitDStream, nbBits: u32) -> usize {
    let value = BIT_lookBitsFast(bitD, nbBits);
    BIT_skipBits(bitD, nbBits);
    value
}

/// `bitstream.h:369` — `BIT_reloadDStream_internal()`.
#[inline(always)]
fn BIT_reloadDStream_internal(bitD: &mut BitDStream) -> BIT_DStream_status {
    bitD.ptr = bitD.ptr.wrapping_sub((bitD.bitsConsumed >> 3) as usize);
    bitD.bitsConsumed &= 7;
    bitD.bitContainer = bitD.read_st();
    BIT_DStream_status::unfinished
}

/// `bitstream.h:397` — `BIT_reloadDStream()`.
#[inline(always)]
fn BIT_reloadDStream(bitD: &mut BitDStream) -> BIT_DStream_status {
    if bitD.bitsConsumed > SIZE_BITS {
        bitD.ptr = &BIT_ZERO_FILLED as *const usize as *const u8;
        return BIT_DStream_status::overflow;
    }

    if bitD.ptr as usize >= bitD.limitPtr as usize {
        return BIT_reloadDStream_internal(bitD);
    }
    if bitD.ptr == bitD.start {
        if bitD.bitsConsumed < SIZE_BITS {
            return BIT_DStream_status::endOfBuffer;
        }
        return BIT_DStream_status::completed;
    }
    {
        let mut nbBytes: u32 = bitD.bitsConsumed >> 3;
        let mut result = BIT_DStream_status::unfinished;
        if (bitD.ptr.wrapping_sub(nbBytes as usize) as usize) < bitD.start as usize {
            nbBytes = ((bitD.ptr as usize).wrapping_sub(bitD.start as usize)) as u32;
            result = BIT_DStream_status::endOfBuffer;
        }
        bitD.ptr = bitD.ptr.wrapping_sub(nbBytes as usize);
        bitD.bitsConsumed = bitD.bitsConsumed.wrapping_sub(nbBytes.wrapping_mul(8));
        bitD.bitContainer = bitD.read_st();
        result
    }
}

/// `bits.h:119` — `31 - ZSTD_countLeadingZeros32(val)`. `val` is never 0 at
/// any call site in this file (each caller derives it from a count or a
/// distribution total already checked positive).
#[inline(always)]
fn ZSTD_highbit32(val: u32) -> u32 {
    31u32.wrapping_sub(val.leading_zeros())
}

// ---------------------------------------------------------------------------
// Functions this file reaches through their C ABI. Each is already Rust, but
// still crossed as FFI because every ported file is its own crate in the
// kernel build (the same reasoning `xz_dec_stream_rs.rs` gives for calling
// `xz_dec_bcj_run`).
// ---------------------------------------------------------------------------

extern "C" {
    /// `lib/zstd/common/entropy_common_rs.rs`.
    fn FSE_readNCount(
        normalizedCounter: *mut i16,
        maxSVPtr: *mut c_uint,
        tableLogPtr: *mut c_uint,
        headerBuffer: *const c_void,
        hbSize: usize,
    ) -> usize;

    /// `lib/zstd/decompress/huf_decompress_rs.rs`.
    fn HUF_decompress1X_usingDTable(
        dst: *mut c_void,
        maxDstSize: usize,
        cSrc: *const c_void,
        cSrcSize: usize,
        DTable: *const HufDTable,
        flags: c_int,
    ) -> usize;

    /// `lib/zstd/decompress/huf_decompress_rs.rs`.
    fn HUF_decompress4X_usingDTable(
        dst: *mut c_void,
        maxDstSize: usize,
        cSrc: *const c_void,
        cSrcSize: usize,
        DTable: *const HufDTable,
        flags: c_int,
    ) -> usize;

    /// `lib/zstd/decompress/huf_decompress_rs.rs`. `HUF_FORCE_DECOMPRESS_X2`
    /// is not defined anywhere in this kernel tree, so the pristine C's
    /// `#else` arm -- this function, not `HUF_decompress1X_DCtx_wksp` -- is
    /// the one that ever compiles.
    fn HUF_decompress1X1_DCtx_wksp(
        dctx: *mut HufDTable,
        dst: *mut c_void,
        dstSize: usize,
        cSrc: *const c_void,
        cSrcSize: usize,
        workSpace: *mut c_void,
        wkspSize: usize,
        flags: c_int,
    ) -> usize;

    /// `lib/zstd/decompress/huf_decompress_rs.rs`.
    fn HUF_decompress4X_hufOnly_wksp(
        dctx: *mut HufDTable,
        dst: *mut c_void,
        dstSize: usize,
        cSrc: *const c_void,
        cSrcSize: usize,
        workSpace: *mut c_void,
        wkspSize: usize,
        flags: c_int,
    ) -> usize;
}

/// `PREFETCH_AREA`, `compiler.h`. A hint, never a correctness requirement;
/// `core::hint::black_box` is not the right tool (it is about optimizer
/// barriers, not cache prefetch) and `core` has no stable software-prefetch
/// intrinsic, so this is a no-op. Matches what happens on any target where
/// the C's own `PREFETCH_AREA` expands to nothing (its `#else` arm).
#[inline(always)]
fn PREFETCH_AREA(_ptr: *const c_void, _size: usize) {}

// ---------------------------------------------------------------------------
// Block decoding
// ---------------------------------------------------------------------------

/// `ZSTD_blockSizeMax()`.
fn ZSTD_blockSizeMax(dctx: &ZstdDCtx) -> usize {
    let blockSizeMax = if dctx.isFrameDecompression != 0 {
        dctx.fParams.blockSizeMax as usize
    } else {
        ZSTD_BLOCKSIZE_MAX
    };
    debug_assert!(blockSizeMax <= ZSTD_BLOCKSIZE_MAX);
    blockSizeMax
}

/// `ZSTD_getcBlockSize()`.
///
/// # Safety
/// `src` must point at `srcSize` readable bytes and `bpPtr` at a live,
/// writable [`BlockProperties`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_getcBlockSize(
    src: *const c_void,
    srcSize: usize,
    bpPtr: *mut BlockProperties,
) -> usize {
    if srcSize < ZSTD_BLOCK_HEADER_SIZE {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    // SAFETY: class B (boundary). `srcSize >= 3` was just checked.
    let cBlockHeader = unsafe { MEM_readLE24(src as *const u8) };
    let cSize = cBlockHeader >> 3;
    // SAFETY: class B (boundary). Caller-owned out-parameter.
    unsafe {
        (*bpPtr).lastBlock = cBlockHeader & 1;
        (*bpPtr).blockType = (cBlockHeader >> 1) & 3;
        (*bpPtr).origSize = cSize;
        if (*bpPtr).blockType == BlockType::Rle as u32 {
            return 1;
        }
        if (*bpPtr).blockType == BlockType::Reserved as u32 {
            return ERROR(ZSTD_error_corruption_detected);
        }
    }
    cSize as usize
}

/// `ZSTD_allocateLiteralsBuffer()`.
///
/// # Safety
/// `dst .. dst + dstCapacity` must be writable when `streaming ==
/// NotStreaming` and the arithmetic below stays inside it; this mirrors the
/// C's own unchecked pointer arithmetic exactly, so the same contract that
/// protects the C protects this.
unsafe fn ZSTD_allocateLiteralsBuffer(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    litSize: usize,
    streaming: StreamingOperation,
    expectedWriteSize: usize,
    splitImmediately: bool,
) {
    let blockSizeMax = ZSTD_blockSizeMax(dctx);
    debug_assert!(litSize <= blockSizeMax);
    debug_assert!(
        dctx.isFrameDecompression != 0 || streaming == StreamingOperation::NotStreaming
    );
    debug_assert!(expectedWriteSize <= blockSizeMax);

    // Pointer arithmetic throughout is `wrapping_add`/`wrapping_sub` rather
    // than `add`/`sub`: the C computes these as plain pointer arithmetic,
    // with no requirement that every intermediate step stay inside the
    // allocation (only the *final*, dereferenced value has to, and the
    // `debug_assert!`s below are the C's own asserts checking exactly that).
    // `add`/`sub` require every step to stay in bounds or the computation
    // itself is UB; `wrapping_*` has no such requirement and is what makes
    // this a faithful transcription rather than a new way to be undefined.
    if streaming == StreamingOperation::NotStreaming
        && dstCapacity > blockSizeMax + WILDCOPY_OVERLENGTH + litSize + WILDCOPY_OVERLENGTH
    {
        dctx.litBuffer =
            (dst as *mut u8).wrapping_add(blockSizeMax.wrapping_add(WILDCOPY_OVERLENGTH));
        dctx.litBufferEnd = dctx.litBuffer.wrapping_add(litSize);
        dctx.litBufferLocation = LitLocation::InDst as u32;
    } else if litSize <= ZSTD_LITBUFFEREXTRASIZE {
        dctx.litBuffer = dctx.litExtraBuffer.as_mut_ptr();
        dctx.litBufferEnd = dctx.litBuffer.wrapping_add(litSize);
        dctx.litBufferLocation = LitLocation::NotInDst as u32;
    } else {
        debug_assert!(blockSizeMax > ZSTD_LITBUFFEREXTRASIZE);
        if splitImmediately {
            dctx.litBuffer = (dst as *mut u8)
                .wrapping_add(expectedWriteSize)
                .wrapping_sub(litSize)
                .wrapping_add(ZSTD_LITBUFFEREXTRASIZE)
                .wrapping_sub(WILDCOPY_OVERLENGTH);
            dctx.litBufferEnd = dctx.litBuffer.wrapping_add(litSize).wrapping_sub(ZSTD_LITBUFFEREXTRASIZE);
        } else {
            dctx.litBuffer = (dst as *mut u8).wrapping_add(expectedWriteSize).wrapping_sub(litSize);
            dctx.litBufferEnd = (dst as *mut u8).wrapping_add(expectedWriteSize);
        }
        dctx.litBufferLocation = LitLocation::Split as u32;
        debug_assert!(dctx.litBufferEnd as usize <= (dst as usize).wrapping_add(expectedWriteSize));
    }
}

/// `SymbolEncodingType_e` raw values, matched on directly (`istart[0] & 3`
/// is exactly this encoding) rather than cast through the enum -- the C's
/// own `(SymbolEncodingType_e)(istart[0] & 3)` cast is what this mirrors.
const SET_BASIC: u8 = 0;
const SET_RLE: u8 = 1;
const SET_COMPRESSED: u8 = 2;
const SET_REPEAT: u8 = 3;

/// `ZSTD_decodeLiteralsBlock()`.
///
/// # Safety
/// `src` must point at `srcSize` readable bytes, `dst` at `dstCapacity`
/// writable ones (or be null with `dstCapacity == 0`, which the length
/// checks below make unreachable before any write), and `dctx` must be a
/// live `ZstdDCtx` whose `litExtraBuffer` this function may write through
/// `dctx.litBuffer`.
unsafe fn ZSTD_decodeLiteralsBlock(
    dctx: &mut ZstdDCtx,
    src: *const c_void,
    srcSize: usize,
    dst: *mut c_void,
    dstCapacity: usize,
    streaming: StreamingOperation,
) -> usize {
    if srcSize < MIN_CBLOCK_SIZE {
        return ERROR(ZSTD_error_corruption_detected);
    }

    let istart = src as *const u8;
    // SAFETY: class B (boundary). `srcSize >= MIN_CBLOCK_SIZE == 2`.
    let litEncType = unsafe { *istart } & 3;
    let blockSizeMax = ZSTD_blockSizeMax(dctx);

    match litEncType {
        SET_REPEAT | SET_COMPRESSED => {
            if litEncType == SET_REPEAT && dctx.litEntropy == 0 {
                return ERROR(ZSTD_error_dictionary_corrupted);
            }
            if srcSize < 5 {
                return ERROR(ZSTD_error_corruption_detected);
            }
            // SAFETY: class B (boundary). `srcSize >= 5`, and every access
            // below through `istart` is bounded by `lhSize`/`litCSize`
            // checks against `srcSize` before it is dereferenced.
            let lhlCode = (unsafe { *istart } >> 2) & 3;
            let lhc = unsafe { MEM_readLE32(istart) };
            let mut singleStream = false;
            let lhSize: usize;
            let litSize: usize;
            let litCSize: usize;
            match lhlCode {
                0 | 1 => {
                    // 2 - 2 - 10 - 10
                    singleStream = lhlCode == 0;
                    lhSize = 3;
                    litSize = ((lhc >> 4) & 0x3FF) as usize;
                    litCSize = ((lhc >> 14) & 0x3FF) as usize;
                }
                2 => {
                    // 2 - 2 - 14 - 14
                    lhSize = 4;
                    litSize = ((lhc >> 4) & 0x3FFF) as usize;
                    litCSize = (lhc >> 18) as usize;
                }
                _ => {
                    // 2 - 2 - 18 - 18
                    lhSize = 5;
                    litSize = ((lhc >> 4) & 0x3FFFF) as usize;
                    // SAFETY: class B (boundary). `srcSize >= 5`.
                    litCSize = ((lhc >> 22) as usize) + ((unsafe { *istart.add(4) } as usize) << 10);
                }
            }
            if litSize > 0 && dst.is_null() {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            if litSize > blockSizeMax {
                return ERROR(ZSTD_error_corruption_detected);
            }
            if !singleStream && litSize < MIN_LITERALS_FOR_4_STREAMS {
                return ERROR(ZSTD_error_literals_headerWrong);
            }
            if litCSize.wrapping_add(lhSize) > srcSize {
                return ERROR(ZSTD_error_corruption_detected);
            }
            let expectedWriteSize = blockSizeMax.min(dstCapacity);
            if expectedWriteSize < litSize {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            // SAFETY: class B (boundary). The caller's contract; every
            // bound this function relies on has just been checked.
            unsafe {
                ZSTD_allocateLiteralsBuffer(
                    dctx,
                    dst,
                    dstCapacity,
                    litSize,
                    streaming,
                    expectedWriteSize,
                    false,
                )
            };

            // Prefetch huffman table if cold.
            if dctx.ddictIsCold != 0 && litSize > 768 {
                PREFETCH_AREA(dctx.HUFptr as *const c_void, core::mem::size_of_val(&dctx.entropy.hufTable));
            }

            let flags = (if dctx_get_bmi2(dctx) != 0 { HUF_FLAGS_BMI2 } else { 0 })
                | (if dctx.disableHufAsm != 0 { HUF_FLAGS_DISABLE_ASM } else { 0 });
            // SAFETY: class C (construction). `istart + lhSize .. + litCSize`
            // is inside `src` (`litCSize + lhSize <= srcSize` was just
            // checked); `dctx.litBuffer .. + litSize` is what
            // `ZSTD_allocateLiteralsBuffer` just carved out, sized exactly
            // `litSize`; `dctx.workspace` is this struct's own fixed array.
            let hufSuccess = unsafe {
                if litEncType == SET_REPEAT {
                    if singleStream {
                        HUF_decompress1X_usingDTable(
                            dctx.litBuffer as *mut c_void,
                            litSize,
                            istart.add(lhSize) as *const c_void,
                            litCSize,
                            dctx.HUFptr,
                            flags,
                        )
                    } else {
                        HUF_decompress4X_usingDTable(
                            dctx.litBuffer as *mut c_void,
                            litSize,
                            istart.add(lhSize) as *const c_void,
                            litCSize,
                            dctx.HUFptr,
                            flags,
                        )
                    }
                } else if singleStream {
                    HUF_decompress1X1_DCtx_wksp(
                        dctx.entropy.hufTable.as_mut_ptr(),
                        dctx.litBuffer as *mut c_void,
                        litSize,
                        istart.add(lhSize) as *const c_void,
                        litCSize,
                        dctx.workspace.as_mut_ptr() as *mut c_void,
                        core::mem::size_of_val(&dctx.workspace),
                        flags,
                    )
                } else {
                    HUF_decompress4X_hufOnly_wksp(
                        dctx.entropy.hufTable.as_mut_ptr(),
                        dctx.litBuffer as *mut c_void,
                        litSize,
                        istart.add(lhSize) as *const c_void,
                        litCSize,
                        dctx.workspace.as_mut_ptr() as *mut c_void,
                        core::mem::size_of_val(&dctx.workspace),
                        flags,
                    )
                }
            };

            if dctx.litBufferLocation == LitLocation::Split as u32 {
                debug_assert!(litSize > ZSTD_LITBUFFEREXTRASIZE);
                // SAFETY: class C (construction). `litBufferEnd` and
                // `litBuffer` bound a `litSize`-byte region this function's
                // own allocation step just established; the C's memcpy/
                // memmove become copy_from_slice-shaped raw-pointer copies
                // over the same bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        dctx.litBufferEnd.wrapping_sub(ZSTD_LITBUFFEREXTRASIZE),
                        dctx.litExtraBuffer.as_mut_ptr(),
                        ZSTD_LITBUFFEREXTRASIZE,
                    );
                    core::ptr::copy(
                        dctx.litBuffer,
                        dctx.litBuffer.wrapping_add(ZSTD_LITBUFFEREXTRASIZE).wrapping_sub(WILDCOPY_OVERLENGTH),
                        litSize.wrapping_sub(ZSTD_LITBUFFEREXTRASIZE),
                    );
                    dctx.litBuffer = dctx
                        .litBuffer
                        .wrapping_add(ZSTD_LITBUFFEREXTRASIZE)
                        .wrapping_sub(WILDCOPY_OVERLENGTH);
                    dctx.litBufferEnd = dctx.litBufferEnd.wrapping_sub(WILDCOPY_OVERLENGTH);
                }
                debug_assert!(dctx.litBufferEnd as usize <= dst as usize + blockSizeMax);
            }

            if ERR_isError(hufSuccess) {
                return ERROR(ZSTD_error_corruption_detected);
            }

            dctx.litPtr = dctx.litBuffer;
            dctx.litSize = litSize;
            dctx.litEntropy = 1;
            if litEncType == SET_COMPRESSED {
                dctx.HUFptr = dctx.entropy.hufTable.as_ptr();
            }
            litCSize.wrapping_add(lhSize)
        }

        SET_BASIC => {
            // SAFETY: class B (boundary). `srcSize >= MIN_CBLOCK_SIZE == 2`.
            let lhlCode = (unsafe { *istart } >> 2) & 3;
            let expectedWriteSize = blockSizeMax.min(dstCapacity);
            let (lhSize, litSize): (usize, usize) = match lhlCode {
                0 | 2 => (1, (unsafe { *istart } >> 3) as usize),
                1 => (2, (unsafe { MEM_readLE16(istart) } >> 4) as usize),
                _ => {
                    if srcSize < 3 {
                        return ERROR(ZSTD_error_corruption_detected);
                    }
                    (3, (unsafe { MEM_readLE24(istart) } >> 4) as usize)
                }
            };

            if litSize > 0 && dst.is_null() {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            if litSize > blockSizeMax {
                return ERROR(ZSTD_error_corruption_detected);
            }
            if expectedWriteSize < litSize {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            // SAFETY: class B (boundary). As above.
            unsafe {
                ZSTD_allocateLiteralsBuffer(
                    dctx,
                    dst,
                    dstCapacity,
                    litSize,
                    streaming,
                    expectedWriteSize,
                    true,
                )
            };
            if lhSize.wrapping_add(litSize).wrapping_add(WILDCOPY_OVERLENGTH) > srcSize {
                // risk reading beyond src buffer with wildcopy
                if litSize.wrapping_add(lhSize) > srcSize {
                    return ERROR(ZSTD_error_corruption_detected);
                }
                // SAFETY: class C (construction). `lhSize + litSize <=
                // srcSize`, and `litBuffer`/`litExtraBuffer` were just sized
                // for exactly `litSize` bytes by the allocation step above.
                unsafe {
                    if dctx.litBufferLocation == LitLocation::Split as u32 {
                        core::ptr::copy_nonoverlapping(
                            istart.add(lhSize),
                            dctx.litBuffer,
                            litSize.wrapping_sub(ZSTD_LITBUFFEREXTRASIZE),
                        );
                        core::ptr::copy_nonoverlapping(
                            istart.add(lhSize).add(litSize.wrapping_sub(ZSTD_LITBUFFEREXTRASIZE)),
                            dctx.litExtraBuffer.as_mut_ptr(),
                            ZSTD_LITBUFFEREXTRASIZE,
                        );
                    } else {
                        core::ptr::copy_nonoverlapping(istart.add(lhSize), dctx.litBuffer, litSize);
                    }
                }
                dctx.litPtr = dctx.litBuffer;
                dctx.litSize = litSize;
                return lhSize.wrapping_add(litSize);
            }
            // direct reference into compressed stream
            dctx.litPtr = unsafe { istart.add(lhSize) };
            dctx.litSize = litSize;
            dctx.litBufferEnd = unsafe { dctx.litPtr.add(litSize) };
            dctx.litBufferLocation = LitLocation::NotInDst as u32;
            lhSize.wrapping_add(litSize)
        }

        SET_RLE => {
            // SAFETY: class B (boundary). As above.
            let lhlCode = (unsafe { *istart } >> 2) & 3;
            let expectedWriteSize = blockSizeMax.min(dstCapacity);
            let (lhSize, litSize): (usize, usize) = match lhlCode {
                0 | 2 => (1, (unsafe { *istart } >> 3) as usize),
                1 => {
                    if srcSize < 3 {
                        return ERROR(ZSTD_error_corruption_detected);
                    }
                    (2, (unsafe { MEM_readLE16(istart) } >> 4) as usize)
                }
                _ => {
                    if srcSize < 4 {
                        return ERROR(ZSTD_error_corruption_detected);
                    }
                    (3, (unsafe { MEM_readLE24(istart) } >> 4) as usize)
                }
            };
            if litSize > 0 && dst.is_null() {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            if litSize > blockSizeMax {
                return ERROR(ZSTD_error_corruption_detected);
            }
            if expectedWriteSize < litSize {
                return ERROR(ZSTD_error_dstSize_tooSmall);
            }
            // SAFETY: class B (boundary). As above.
            unsafe {
                ZSTD_allocateLiteralsBuffer(
                    dctx,
                    dst,
                    dstCapacity,
                    litSize,
                    streaming,
                    expectedWriteSize,
                    true,
                )
            };
            // SAFETY: class C (construction). `litBuffer`/`litExtraBuffer`
            // were just sized for exactly `litSize` bytes.
            let fillByte = unsafe { *istart.add(lhSize) };
            if dctx.litBufferLocation == LitLocation::Split as u32 {
                unsafe {
                    core::ptr::write_bytes(dctx.litBuffer, fillByte, litSize.wrapping_sub(ZSTD_LITBUFFEREXTRASIZE));
                    core::ptr::write_bytes(dctx.litExtraBuffer.as_mut_ptr(), fillByte, ZSTD_LITBUFFEREXTRASIZE);
                }
            } else {
                unsafe { core::ptr::write_bytes(dctx.litBuffer, fillByte, litSize) };
            }
            dctx.litPtr = dctx.litBuffer;
            dctx.litSize = litSize;
            lhSize.wrapping_add(1)
        }

        _ => ERROR(ZSTD_error_corruption_detected), // "impossible"
    }
}

/// `ZSTD_decodeLiteralsBlock_wrapper()`. Hidden declaration for fullbench;
/// note symbol not declared but exposed, matching the pristine C.
///
/// # Safety
/// As [`ZSTD_decodeLiteralsBlock`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decodeLiteralsBlock_wrapper(
    dctx: *mut ZstdDCtx,
    src: *const c_void,
    srcSize: usize,
    dst: *mut c_void,
    dstCapacity: usize,
) -> usize {
    // SAFETY: the caller guarantees `dctx` is live.
    let dctx = unsafe { &mut *dctx };
    dctx.isFrameDecompression = 0;
    // SAFETY: the caller's contract matches `ZSTD_decodeLiteralsBlock`'s.
    unsafe {
        ZSTD_decodeLiteralsBlock(dctx, src, srcSize, dst, dstCapacity, StreamingOperation::NotStreaming)
    }
}

// ---------------------------------------------------------------------------
// Default FSE distribution tables. Pre-calculated using default
// distributions as defined in the compression format spec; transcribed
// literally rather than regenerated at build or run time, matching the C.
// ---------------------------------------------------------------------------

const fn ss(nextState: u16, nbAdditionalBits: u8, nbBits: u8, baseValue: u32) -> SeqSymbol {
    SeqSymbol { nextState, nbAdditionalBits, nbBits, baseValue }
}

/// `LL_defaultDTable`.
static LL_defaultDTable: [SeqSymbol; (1 << LL_DEFAULTNORMLOG) + 1] = [
    ss(1, 1, 1, LL_DEFAULTNORMLOG), // header : fastMode, tableLog
    // nextState, nbAddBits, nbBits, baseVal
    ss(0, 0, 4, 0),      ss(16, 0, 4, 0),
    ss(32, 0, 5, 1),     ss(0, 0, 5, 3),
    ss(0, 0, 5, 4),      ss(0, 0, 5, 6),
    ss(0, 0, 5, 7),      ss(0, 0, 5, 9),
    ss(0, 0, 5, 10),     ss(0, 0, 5, 12),
    ss(0, 0, 6, 14),     ss(0, 1, 5, 16),
    ss(0, 1, 5, 20),     ss(0, 1, 5, 22),
    ss(0, 2, 5, 28),     ss(0, 3, 5, 32),
    ss(0, 4, 5, 48),     ss(32, 6, 5, 64),
    ss(0, 7, 5, 128),    ss(0, 8, 6, 256),
    ss(0, 10, 6, 1024),  ss(0, 12, 6, 4096),
    ss(32, 0, 4, 0),     ss(0, 0, 4, 1),
    ss(0, 0, 5, 2),      ss(32, 0, 5, 4),
    ss(0, 0, 5, 5),      ss(32, 0, 5, 7),
    ss(0, 0, 5, 8),      ss(32, 0, 5, 10),
    ss(0, 0, 5, 11),     ss(0, 0, 6, 13),
    ss(32, 1, 5, 16),    ss(0, 1, 5, 18),
    ss(32, 1, 5, 22),    ss(0, 2, 5, 24),
    ss(32, 3, 5, 32),    ss(0, 3, 5, 40),
    ss(0, 6, 4, 64),     ss(16, 6, 4, 64),
    ss(32, 7, 5, 128),   ss(0, 9, 6, 512),
    ss(0, 11, 6, 2048),  ss(48, 0, 4, 0),
    ss(16, 0, 4, 1),     ss(32, 0, 5, 2),
    ss(32, 0, 5, 3),     ss(32, 0, 5, 5),
    ss(32, 0, 5, 6),     ss(32, 0, 5, 8),
    ss(32, 0, 5, 9),     ss(32, 0, 5, 11),
    ss(32, 0, 5, 12),    ss(0, 0, 6, 15),
    ss(32, 1, 5, 18),    ss(32, 1, 5, 20),
    ss(32, 2, 5, 24),    ss(32, 2, 5, 28),
    ss(32, 3, 5, 40),    ss(32, 4, 5, 48),
    ss(0, 16, 6, 65536), ss(0, 15, 6, 32768),
    ss(0, 14, 6, 16384), ss(0, 13, 6, 8192),
];

/// `OF_defaultDTable`.
static OF_defaultDTable: [SeqSymbol; (1 << OF_DEFAULTNORMLOG) + 1] = [
    ss(1, 1, 1, OF_DEFAULTNORMLOG), // header : fastMode, tableLog
    // nextState, nbAddBits, nbBits, baseVal
    ss(0, 0, 5, 0),          ss(0, 6, 4, 61),
    ss(0, 9, 5, 509),        ss(0, 15, 5, 32765),
    ss(0, 21, 5, 2097149),   ss(0, 3, 5, 5),
    ss(0, 7, 4, 125),        ss(0, 12, 5, 4093),
    ss(0, 18, 5, 262141),    ss(0, 23, 5, 8388605),
    ss(0, 5, 5, 29),         ss(0, 8, 4, 253),
    ss(0, 14, 5, 16381),     ss(0, 20, 5, 1048573),
    ss(0, 2, 5, 1),          ss(16, 7, 4, 125),
    ss(0, 11, 5, 2045),      ss(0, 17, 5, 131069),
    ss(0, 22, 5, 4194301),   ss(0, 4, 5, 13),
    ss(16, 8, 4, 253),       ss(0, 13, 5, 8189),
    ss(0, 19, 5, 524285),    ss(0, 1, 5, 1),
    ss(16, 6, 4, 61),        ss(0, 10, 5, 1021),
    ss(0, 16, 5, 65533),     ss(0, 28, 5, 268435453),
    ss(0, 27, 5, 134217725), ss(0, 26, 5, 67108861),
    ss(0, 25, 5, 33554429),  ss(0, 24, 5, 16777213),
];

/// `ML_defaultDTable`.
static ML_defaultDTable: [SeqSymbol; (1 << ML_DEFAULTNORMLOG) + 1] = [
    ss(1, 1, 1, ML_DEFAULTNORMLOG), // header : fastMode, tableLog
    // nextState, nbAddBits, nbBits, baseVal
    ss(0, 0, 6, 3),    ss(0, 0, 4, 4),
    ss(32, 0, 5, 5),   ss(0, 0, 5, 6),
    ss(0, 0, 5, 8),    ss(0, 0, 5, 9),
    ss(0, 0, 5, 11),   ss(0, 0, 6, 13),
    ss(0, 0, 6, 16),   ss(0, 0, 6, 19),
    ss(0, 0, 6, 22),   ss(0, 0, 6, 25),
    ss(0, 0, 6, 28),   ss(0, 0, 6, 31),
    ss(0, 0, 6, 34),   ss(0, 1, 6, 37),
    ss(0, 1, 6, 41),   ss(0, 2, 6, 47),
    ss(0, 3, 6, 59),   ss(0, 4, 6, 83),
    ss(0, 7, 6, 131),  ss(0, 9, 6, 515),
    ss(16, 0, 4, 4),   ss(0, 0, 4, 5),
    ss(32, 0, 5, 6),   ss(0, 0, 5, 7),
    ss(32, 0, 5, 9),   ss(0, 0, 5, 10),
    ss(0, 0, 6, 12),   ss(0, 0, 6, 15),
    ss(0, 0, 6, 18),   ss(0, 0, 6, 21),
    ss(0, 0, 6, 24),   ss(0, 0, 6, 27),
    ss(0, 0, 6, 30),   ss(0, 0, 6, 33),
    ss(0, 1, 6, 35),   ss(0, 1, 6, 39),
    ss(0, 2, 6, 43),   ss(0, 3, 6, 51),
    ss(0, 4, 6, 67),   ss(0, 5, 6, 99),
    ss(0, 8, 6, 259),  ss(32, 0, 4, 4),
    ss(48, 0, 4, 4),   ss(16, 0, 4, 5),
    ss(32, 0, 5, 7),   ss(32, 0, 5, 8),
    ss(32, 0, 5, 10),  ss(32, 0, 5, 11),
    ss(0, 0, 6, 14),   ss(0, 0, 6, 17),
    ss(0, 0, 6, 20),   ss(0, 0, 6, 23),
    ss(0, 0, 6, 26),   ss(0, 0, 6, 29),
    ss(0, 0, 6, 32),   ss(0, 16, 6, 65539),
    ss(0, 15, 6, 32771), ss(0, 14, 6, 16387),
    ss(0, 13, 6, 8195), ss(0, 12, 6, 4099),
    ss(0, 11, 6, 2051), ss(0, 10, 6, 1027),
];

// ---------------------------------------------------------------------------
// zstd_decompress_internal.h -- base/extra-bits tables for building an
// FSE-decoded distribution into a real ZSTD_seqSymbol table.
// ---------------------------------------------------------------------------

/// `LL_base`.
const LL_base: [u32; MAX_LL as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40,
    48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
    0x2000, 0x4000, 0x8000, 0x10000,
];
/// `LL_bits`.
const LL_bits: [u8; MAX_LL as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
];
/// `OF_base`.
const OF_base: [u32; MAX_OFF as usize + 1] = [
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D,
    0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD,
    0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
];
/// `OF_bits`.
const OF_bits: [u8; MAX_OFF as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
];
/// `ML_base`.
const ML_base: [u32; MAX_ML as usize + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59,
    67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803,
    0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];
/// `ML_bits`.
const ML_bits: [u8; MAX_ML as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// `ZSTD_buildSeqTable_rle()`.
///
/// # Safety
/// `dt` must point at 2 writable [`SeqSymbol`]s.
unsafe fn ZSTD_buildSeqTable_rle(dt: *mut SeqSymbol, baseValue: u32, nbAddBits: u8) {
    debug_assert!(nbAddBits < 255);
    // `dt[0]` is reinterpreted as the header cell; see
    // `write_seqsymbol_header`'s doc for why that is a byte-level overlay
    // rather than a named-field write.
    // SAFETY: class B (boundary). The caller's contract.
    write_seqsymbol_header(unsafe { &mut *dt }, 0, 0);

    // SAFETY: class B (boundary). As above.
    unsafe {
        let cell = &mut *dt.add(1);
        cell.nbBits = 0;
        cell.nextState = 0;
        cell.nbAdditionalBits = nbAddBits;
        cell.baseValue = baseValue;
    }
}

/// Writes `ZSTD_seqSymbol_header{fastMode, tableLog}` into the storage of
/// `dt[0]`, which the C reaches by reinterpreting the same four bytes as a
/// `ZSTD_seqSymbol_header` instead of a `ZSTD_seqSymbol`. Both are 8-byte,
/// 4-byte-aligned types; `ZSTD_seqSymbol_header` is `{U32 fastMode; U32
/// tableLog;}` and a `ZSTD_seqSymbol`'s first four bytes are
/// `{U16 nextState; BYTE nbAdditionalBits; BYTE nbBits;}` -- NOT the same
/// bit pattern as `fastMode` alone. So the header is written through its own
/// two `U32`s laid over the cell's 8 bytes, matching the C's `ZSTD_memcpy`
/// byte for byte rather than trying to name the overlap through named
/// fields that do not correspond to it.
fn write_seqsymbol_header(cell: &mut SeqSymbol, fastMode: u32, tableLog: u32) {
    // SAFETY: `SeqSymbol` is `#[repr(C)]`, 8 bytes, 4-byte aligned -- the
    // same size and alignment as `ZSTD_seqSymbol_header`. Writing two `u32`s
    // through it is exactly the C's `ZSTD_memcpy(dt, &DTableH,
    // sizeof(DTableH))`.
    unsafe {
        let p = cell as *mut SeqSymbol as *mut u32;
        p.write(fastMode);
        p.add(1).write(tableLog);
    }
}

/// `ZSTD_buildFSETable_body()`.
///
/// # Safety
/// `dt` must have room for `1 + (1 << tableLog)` entries, `normalizedCounter`
/// for `maxSymbolValue + 1` entries, `baseValue`/`nbAdditionalBits` for
/// `maxSymbolValue + 1` each, and `wksp` for `wkspSize >=
/// ZSTD_BUILD_FSE_TABLE_WKSP_SIZE` bytes, 4-byte aligned.
unsafe fn ZSTD_buildFSETable_body(
    dt: *mut SeqSymbol,
    normalizedCounter: *const i16,
    maxSymbolValue: u32,
    baseValue: &[u32],
    nbAdditionalBits: &[u8],
    tableLog: u32,
    wksp: *mut u8,
    wkspSize: usize,
) {
    // SAFETY: class C (construction). `dt` has `1 + tableSize` entries; this
    // is the payload half, one past the header.
    let tableDecode = unsafe { dt.add(1) };
    let maxSV1 = maxSymbolValue.wrapping_add(1);
    let tableSize: u32 = 1u32.wrapping_shl(tableLog);

    let symbolNext = wksp as *mut u16;
    // SAFETY: class C (construction). `symbolNext` has `MaxSeq + 1` `u16`
    // slots reserved by the caller's `wkspSize` contract; `spread` starts
    // exactly where those end.
    let spread = unsafe { (symbolNext.add(MAX_SEQ as usize + 1)) as *mut u8 };
    let mut highThreshold = tableSize.wrapping_sub(1);

    debug_assert!(maxSymbolValue <= MAX_SEQ);
    debug_assert!(tableLog <= MAX_FSE_LOG);
    debug_assert!(wkspSize >= ZSTD_BUILD_FSE_TABLE_WKSP_SIZE);
    let _ = wkspSize;

    // Init, lay down lowprob symbols
    {
        let mut fastMode: u32 = 1;
        let largeLimit: i16 = 1i16.wrapping_shl(tableLog.wrapping_sub(1));
        for s in 0..maxSV1 {
            // SAFETY: class B (boundary). `s < maxSV1`, the caller's length
            // for `normalizedCounter`.
            let nc = unsafe { *normalizedCounter.add(s as usize) };
            if nc == -1 {
                // SAFETY: class C (construction). `highThreshold` starts at
                // `tableSize - 1` and decrements once per `-1` count; the
                // C's own invariant (normalized counts sum to `tableSize`)
                // keeps it from underflowing past 0 on valid input, and
                // `ZSTD_buildSeqTable`'s caller only reaches here with
                // `FSE_readNCount()`-validated counts. Not re-checked here,
                // matching the C's own "cannot fail if input is valid"
                // contract for this function.
                unsafe {
                    (*tableDecode.add(highThreshold as usize)).baseValue = s;
                    symbolNext.add(s as usize).write(1);
                }
                highThreshold = highThreshold.wrapping_sub(1);
            } else {
                if nc >= largeLimit {
                    fastMode = 0;
                }
                debug_assert!(nc >= 0);
                // SAFETY: class C (construction). As above.
                unsafe { symbolNext.add(s as usize).write(nc as u16) };
            }
        }
        // SAFETY: class C (construction). `dt[0]` is this table's header
        // cell.
        write_seqsymbol_header(unsafe { &mut *dt }, fastMode, tableLog);
    }

    // Spread symbols
    debug_assert!(tableSize <= 512);
    if highThreshold == tableSize.wrapping_sub(1) {
        let tableMask = (tableSize as usize).wrapping_sub(1);
        let step = fse_tablestep(tableSize as usize);
        {
            const ADD: u64 = 0x0101_0101_0101_0101;
            let mut pos: usize = 0;
            let mut sv: u64 = 0;
            for s in 0..maxSV1 {
                // SAFETY: class B (boundary). `s < maxSV1`.
                let n = unsafe { *normalizedCounter.add(s as usize) } as i32;
                // SAFETY: class C (construction). `spread` has `tableSize +
                // 8` bytes of room (the workspace-size contract), and every
                // `pos` reached is bounded by the sum of counts, which is
                // `tableSize` on valid input -- see `spread_write64`'s
                // divergence note in `entropy_common_rs.rs` for the same
                // deliberate 8-byte over-write shape.
                unsafe { MEM_write64(spread.wrapping_add(pos), sv) };
                let mut i: i32 = 8;
                while i < n {
                    unsafe { MEM_write64(spread.wrapping_add(pos.wrapping_add(i as usize)), sv) };
                    i += 8;
                }
                debug_assert!(n >= 0);
                pos = pos.wrapping_add(n as usize);
                sv = sv.wrapping_add(ADD);
            }
        }
        {
            let mut position: usize = 0;
            const UNROLL: usize = 2;
            debug_assert!(tableSize as usize % UNROLL == 0);
            let mut s = 0usize;
            while s < tableSize as usize {
                for u in 0..UNROLL {
                    let uPosition = (position.wrapping_add(u.wrapping_mul(step))) & tableMask;
                    // SAFETY: class C (construction). `uPosition <=
                    // tableMask`, inside `tableDecode`'s `tableSize`
                    // entries; `spread[s + u]` is inside the bytes the
                    // previous block filled.
                    unsafe {
                        (*tableDecode.add(uPosition)).baseValue =
                            *spread.add(s.wrapping_add(u)) as u32;
                    }
                }
                position = (position.wrapping_add(UNROLL.wrapping_mul(step))) & tableMask;
                s = s.wrapping_add(UNROLL);
            }
            debug_assert!(position == 0);
        }
    } else {
        let tableMask = tableSize.wrapping_sub(1);
        let step = fse_tablestep(tableSize as usize) as u32;
        let mut position: u32 = 0;
        for s in 0..maxSV1 {
            // SAFETY: class B (boundary). As above.
            let n = unsafe { *normalizedCounter.add(s as usize) } as i32;
            let mut i = 0;
            while i < n {
                // SAFETY: class C (construction). `position <= tableMask`.
                unsafe { (*tableDecode.add(position as usize)).baseValue = s };
                position = (position.wrapping_add(step)) & tableMask;
                while position > highThreshold {
                    position = (position.wrapping_add(step)) & tableMask;
                }
                i += 1;
            }
        }
        debug_assert!(position == 0);
    }

    // Build Decoding table
    for u in 0..tableSize {
        // SAFETY: class C (construction). `u < tableSize`.
        let symbol = unsafe { (*tableDecode.add(u as usize)).baseValue };
        // SAFETY: class C (construction). `symbol <= maxSymbolValue <=
        // MaxSeq`, inside `symbolNext`'s `MaxSeq + 1` slots.
        let nextState = unsafe {
            let p = symbolNext.add(symbol as usize);
            let v = p.read();
            p.write(v.wrapping_add(1));
            v as u32
        };
        let nbBits = (tableLog.wrapping_sub(ZSTD_highbit32(nextState))) as u8;
        // SAFETY: class C (construction). As above.
        unsafe {
            let cell = &mut *tableDecode.add(u as usize);
            cell.nbBits = nbBits;
            cell.nextState = ((nextState.wrapping_shl(nbBits as u32)).wrapping_sub(tableSize)) as u16;
            debug_assert!(nbAdditionalBits[symbol as usize] < 255);
            cell.nbAdditionalBits = nbAdditionalBits[symbol as usize];
            cell.baseValue = baseValue[symbol as usize];
        }
    }
}

/// `FSE_TABLESTEP(tableSize)`, `fse.h`.
const fn fse_tablestep(tableSize: usize) -> usize {
    (tableSize >> 1) + (tableSize >> 3) + 3
}

/// Avoids the `FORCE_INLINE` of the `_body()` function.
///
/// # Safety
/// As [`ZSTD_buildFSETable_body`].
unsafe fn ZSTD_buildFSETable_body_default(
    dt: *mut SeqSymbol,
    normalizedCounter: *const i16,
    maxSymbolValue: u32,
    baseValue: &[u32],
    nbAdditionalBits: &[u8],
    tableLog: u32,
    wksp: *mut u8,
    wkspSize: usize,
) {
    // SAFETY: forwarded unchanged.
    unsafe {
        ZSTD_buildFSETable_body(
            dt, normalizedCounter, maxSymbolValue, baseValue, nbAdditionalBits, tableLog, wksp,
            wkspSize,
        )
    }
}

/// # Safety
/// As [`ZSTD_buildFSETable_body`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn ZSTD_buildFSETable_body_bmi2(
    dt: *mut SeqSymbol,
    normalizedCounter: *const i16,
    maxSymbolValue: u32,
    baseValue: &[u32],
    nbAdditionalBits: &[u8],
    tableLog: u32,
    wksp: *mut u8,
    wkspSize: usize,
) {
    // SAFETY: forwarded unchanged.
    unsafe {
        ZSTD_buildFSETable_body(
            dt, normalizedCounter, maxSymbolValue, baseValue, nbAdditionalBits, tableLog, wksp,
            wkspSize,
        )
    }
}

/// `ZSTD_buildFSETable()`.
///
/// # Safety
/// As [`ZSTD_buildFSETable_body`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_buildFSETable(
    dt: *mut SeqSymbol,
    normalizedCounter: *const i16,
    maxSymbolValue: c_uint,
    baseValue: *const u32,
    nbAdditionalBits: *const u8,
    tableLog: c_uint,
    wksp: *mut c_void,
    wkspSize: usize,
    bmi2: c_int,
) {
    // SAFETY: class B (boundary). The caller's contract; `baseValue`/
    // `nbAdditionalBits` are read as slices of `maxSymbolValue + 1` here
    // because the `_body` function only ever indexes them up to `symbol <=
    // maxSymbolValue`.
    let baseValue = unsafe { core::slice::from_raw_parts(baseValue, maxSymbolValue as usize + 1) };
    let nbAdditionalBits =
        unsafe { core::slice::from_raw_parts(nbAdditionalBits, maxSymbolValue as usize + 1) };
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if bmi2 != 0 {
        // SAFETY: class B (boundary) plus the `#[target_feature]` contract,
        // upheld the same way `dctx_get_bmi2()`'s only true caller upholds
        // it: `bmi2 != 0` only when `ZSTD_DCtx_get_bmi2()` measured runtime
        // CPU support.
        unsafe {
            ZSTD_buildFSETable_body_bmi2(
                dt,
                normalizedCounter,
                maxSymbolValue,
                baseValue,
                nbAdditionalBits,
                tableLog,
                wksp as *mut u8,
                wkspSize,
            )
        };
        return;
    }
    let _ = bmi2;
    // SAFETY: class B (boundary). As above.
    unsafe {
        ZSTD_buildFSETable_body_default(
            dt,
            normalizedCounter,
            maxSymbolValue,
            baseValue,
            nbAdditionalBits,
            tableLog,
            wksp as *mut u8,
            wkspSize,
        )
    };
}

/// `ZSTD_buildSeqTable()`.
///
/// `DTableSpace` and `DTablePtr` are the C's `ZSTD_seqSymbol* DTableSpace,
/// const ZSTD_seqSymbol** DTablePtr` -- a fixed table this call may fill,
/// and an out-parameter naming which table (this one, or a shared default)
/// the caller should actually use.
///
/// # Safety
/// `DTableSpace` must point at `SEQSYMBOL_TABLE_SIZE(maxLog)` writable
/// [`SeqSymbol`]s, `DTablePtr` at a live, writable pointer, `src` at
/// `srcSize` readable bytes, `baseValue`/`nbAdditionalBits` at `max + 1`
/// entries each, `defaultTable` at a live table, and `wksp` at `wkspSize`
/// writable bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn ZSTD_buildSeqTable(
    DTableSpace: *mut SeqSymbol,
    DTablePtr: *mut *const SeqSymbol,
    ty: u8,
    max: u32,
    maxLog: u32,
    src: *const c_void,
    srcSize: usize,
    baseValue: &[u32],
    nbAdditionalBits: &[u8],
    defaultTable: *const SeqSymbol,
    flagRepeatTable: u32,
    ddictIsCold: c_int,
    nbSeq: i32,
    wksp: *mut u32,
    wkspSize: usize,
    bmi2: c_int,
) -> usize {
    match ty {
        SET_RLE => {
            if srcSize == 0 {
                return ERROR(ZSTD_error_srcSize_wrong);
            }
            // SAFETY: class B (boundary). `srcSize >= 1`.
            let symbol = unsafe { *(src as *const u8) };
            if symbol as u32 > max {
                return ERROR(ZSTD_error_corruption_detected);
            }
            let baseline = baseValue[symbol as usize];
            let nbBits = nbAdditionalBits[symbol as usize];
            // SAFETY: class B (boundary). The caller's contract.
            unsafe { ZSTD_buildSeqTable_rle(DTableSpace, baseline, nbBits) };
            // SAFETY: class B (boundary). Caller-owned out-parameter.
            unsafe { *DTablePtr = DTableSpace };
            1
        }
        SET_BASIC => {
            // SAFETY: class B (boundary). Caller-owned out-parameter.
            unsafe { *DTablePtr = defaultTable };
            0
        }
        SET_REPEAT => {
            if flagRepeatTable == 0 {
                return ERROR(ZSTD_error_corruption_detected);
            }
            // prefetch FSE table if used
            if ddictIsCold != 0 && nbSeq > 24 {
                // SAFETY: class B (boundary). Caller-owned out-parameter,
                // already pointing at a live table from a previous call.
                let pStart = unsafe { *DTablePtr } as *const c_void;
                let pSize = core::mem::size_of::<SeqSymbol>() * seqsymbol_table_size(maxLog);
                PREFETCH_AREA(pStart, pSize);
            }
            0
        }
        SET_COMPRESSED => {
            let mut tableLog: c_uint = 0;
            let mut max = max;
            let mut norm = [0i16; MAX_SEQ as usize + 1];
            // SAFETY: class C (construction). `norm` has `MaxSeq + 1`
            // entries; `src`/`srcSize` are the caller's.
            let headerSize = unsafe {
                FSE_readNCount(norm.as_mut_ptr(), &mut max, &mut tableLog, src, srcSize)
            };
            if ERR_isError(headerSize) {
                return ERROR(ZSTD_error_corruption_detected);
            }
            if tableLog > maxLog {
                return ERROR(ZSTD_error_corruption_detected);
            }
            // SAFETY: class B (boundary) plus class C: `DTableSpace` has
            // `SEQSYMBOL_TABLE_SIZE(maxLog) >= SEQSYMBOL_TABLE_SIZE(tableLog)`
            // room (`tableLog <= maxLog` was just checked), `norm` and the
            // base/bits slices are sized for `max + 1`, and `wksp` is the
            // caller's contract.
            unsafe {
                ZSTD_buildFSETable(
                    DTableSpace,
                    norm.as_ptr(),
                    max,
                    baseValue.as_ptr(),
                    nbAdditionalBits.as_ptr(),
                    tableLog,
                    wksp as *mut c_void,
                    wkspSize,
                    bmi2,
                )
            };
            // SAFETY: class B (boundary). Caller-owned out-parameter.
            unsafe { *DTablePtr = DTableSpace };
            headerSize
        }
        _ => {
            debug_assert!(false, "impossible SymbolEncodingType");
            ERROR(ZSTD_error_GENERIC)
        }
    }
}

/// `ZSTD_decodeSeqHeaders()`.
///
/// # Safety
/// `dctx` must be a live [`ZstdDCtx`], `nbSeqPtr` a live writable `c_int`,
/// and `src` must point at `srcSize` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decodeSeqHeaders(
    dctx: *mut ZstdDCtx,
    nbSeqPtr: *mut c_int,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    // SAFETY: the caller guarantees `dctx` is live.
    let dctx = unsafe { &mut *dctx };
    let istart = src as *const u8;
    let iend = istart.wrapping_add(srcSize);
    let mut ip = istart;

    if srcSize < MIN_SEQUENCES_SIZE {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    // SeqHead
    // SAFETY: class B (boundary). `srcSize >= 1`.
    let mut nbSeq = unsafe { *ip } as i32;
    ip = ip.wrapping_add(1);
    if nbSeq > 0x7F {
        if nbSeq == 0xFF {
            if ip.wrapping_add(2) as usize > iend as usize {
                return ERROR(ZSTD_error_srcSize_wrong);
            }
            // SAFETY: class C (construction). Just checked.
            nbSeq = unsafe { MEM_readLE16(ip) as i32 }.wrapping_add(LONGNBSEQ);
            ip = ip.wrapping_add(2);
        } else {
            if ip as usize >= iend as usize {
                return ERROR(ZSTD_error_srcSize_wrong);
            }
            // SAFETY: class C (construction). Just checked.
            nbSeq = ((nbSeq.wrapping_sub(0x80)) << 8).wrapping_add(unsafe { *ip } as i32);
            ip = ip.wrapping_add(1);
        }
    }
    // SAFETY: class B (boundary). Caller-owned out-parameter.
    unsafe { *nbSeqPtr = nbSeq };

    if nbSeq == 0 {
        // No sequence : section ends immediately
        if ip as usize != iend as usize {
            return ERROR(ZSTD_error_corruption_detected);
        }
        return ip as usize - istart as usize;
    }

    // FSE table descriptors
    if ip.wrapping_add(1) as usize > iend as usize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary). Just checked.
    if unsafe { *ip } & 3 != 0 {
        return ERROR(ZSTD_error_corruption_detected);
    }
    // SAFETY: class B (boundary). As above.
    let header = unsafe { *ip };
    let LLtype = header >> 6;
    let OFtype = (header >> 4) & 3;
    let MLtype = (header >> 2) & 3;
    ip = ip.wrapping_add(1);

    let bmi2 = dctx_get_bmi2(dctx);

    // Build DTables
    {
        // SAFETY: class C (construction). `dctx.entropy.LLTable` is exactly
        // `SEQSYMBOL_TABLE_SIZE(LLFSELog)` entries; `ip .. iend` is the
        // remaining input.
        let llhSize = unsafe {
            ZSTD_buildSeqTable(
                dctx.entropy.LLTable.as_mut_ptr(),
                &mut dctx.LLTptr,
                LLtype,
                MAX_LL,
                LL_FSE_LOG,
                ip as *const c_void,
                iend as usize - ip as usize,
                &LL_base,
                &LL_bits,
                LL_defaultDTable.as_ptr(),
                dctx.fseEntropy,
                dctx.ddictIsCold,
                nbSeq,
                dctx.workspace.as_mut_ptr(),
                core::mem::size_of_val(&dctx.workspace),
                bmi2,
            )
        };
        if ERR_isError(llhSize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        ip = ip.wrapping_add(llhSize);
    }

    {
        // SAFETY: class C (construction). As above.
        let ofhSize = unsafe {
            ZSTD_buildSeqTable(
                dctx.entropy.OFTable.as_mut_ptr(),
                &mut dctx.OFTptr,
                OFtype,
                MAX_OFF,
                OFF_FSE_LOG,
                ip as *const c_void,
                iend as usize - ip as usize,
                &OF_base,
                &OF_bits,
                OF_defaultDTable.as_ptr(),
                dctx.fseEntropy,
                dctx.ddictIsCold,
                nbSeq,
                dctx.workspace.as_mut_ptr(),
                core::mem::size_of_val(&dctx.workspace),
                bmi2,
            )
        };
        if ERR_isError(ofhSize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        ip = ip.wrapping_add(ofhSize);
    }

    {
        // SAFETY: class C (construction). As above.
        let mlhSize = unsafe {
            ZSTD_buildSeqTable(
                dctx.entropy.MLTable.as_mut_ptr(),
                &mut dctx.MLTptr,
                MLtype,
                MAX_ML,
                ML_FSE_LOG,
                ip as *const c_void,
                iend as usize - ip as usize,
                &ML_base,
                &ML_bits,
                ML_defaultDTable.as_ptr(),
                dctx.fseEntropy,
                dctx.ddictIsCold,
                nbSeq,
                dctx.workspace.as_mut_ptr(),
                core::mem::size_of_val(&dctx.workspace),
                bmi2,
            )
        };
        if ERR_isError(mlhSize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        ip = ip.wrapping_add(mlhSize);
    }

    ip as usize - istart as usize
}

// ---------------------------------------------------------------------------
// seq_t, ZSTD_fseState, seqState_t
// ---------------------------------------------------------------------------

/// `seq_t`.
#[derive(Clone, Copy)]
struct Seq {
    litLength: usize,
    matchLength: usize,
    offset: usize,
}

/// `ZSTD_fseState`.
struct ZstdFseState {
    state: usize,
    table: *const SeqSymbol,
}

// ---------------------------------------------------------------------------
// zstd_internal.h -- ZSTD_copy4/8/16, ZSTD_wildcopy, ZSTD_overlap_e
// ---------------------------------------------------------------------------

/// `ZSTD_overlap_e`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Overlap {
    NoOverlap,
    OverlapSrcBeforeDst,
}

/// `ZSTD_copy4()`.
///
/// # Safety
/// `dst`/`src` must be non-overlapping and each point at 4 valid bytes.
#[inline(always)]
unsafe fn ZSTD_copy4(dst: *mut u8, src: *const u8) {
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 4) };
}

/// `ZSTD_copy8()`. `ZSTD_ARCH_ARM_NEON`/`ZSTD_ARCH_X86_SSE2` are never
/// defined in this kernel tree's `portability_macros.h`, so the C's own
/// `#else` (`ZSTD_memcpy`) is what actually compiles on every target this
/// project builds.
///
/// # Safety
/// `dst`/`src` must be non-overlapping and each point at 8 valid bytes.
#[inline(always)]
unsafe fn ZSTD_copy8(dst: *mut u8, src: *const u8) {
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 8) };
}

/// `ZSTD_copy16()`. Same reasoning as [`ZSTD_copy8`] for why the arch-SIMD
/// arms never compile here; the remaining choice is `__clang__`'s
/// `ZSTD_memmove` versus the plain-GCC stack-buffer shuffle, and this
/// kernel builds with clang -- so `ZSTD_memmove` (`core::ptr::copy`,
/// overlap-safe) is the arm that matters, not `ZSTD_memcpy`.
///
/// # Safety
/// `dst .. dst + 16` and `src .. src + 16` must each be valid; they may
/// overlap.
#[inline(always)]
unsafe fn ZSTD_copy16(dst: *mut u8, src: *const u8) {
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { core::ptr::copy(src, dst, 16) };
}

/// `ZSTD_wildcopy()`.
///
/// # Safety
/// `dst .. dst + length` and `src .. src + length` must be valid, allowing
/// up to `WILDCOPY_OVERLENGTH` bytes of over-read/over-write past `length`
/// on both ends -- the caller's contract, same as the C's.
unsafe fn ZSTD_wildcopy(dst: *mut u8, src: *const u8, length: isize, ovtype: Overlap) {
    let diff = (dst as isize).wrapping_sub(src as isize);
    let mut ip = src;
    let mut op = dst;
    let oend = op.wrapping_offset(length);

    if ovtype == Overlap::OverlapSrcBeforeDst && diff < WILDCOPY_VECLEN as isize {
        // Handle short offset copies.
        loop {
            // SAFETY: class B (boundary). The caller's contract; each
            // 8-byte step is inside the over-read/over-write allowance.
            unsafe { ZSTD_copy8(op, ip) };
            op = op.wrapping_add(8);
            ip = ip.wrapping_add(8);
            if op >= oend {
                break;
            }
        }
    } else {
        debug_assert!(diff >= WILDCOPY_VECLEN as isize || diff <= -(WILDCOPY_VECLEN as isize));
        // SAFETY: class B (boundary). As above.
        unsafe { ZSTD_copy16(op, ip) };
        if 16 >= length {
            return;
        }
        op = op.wrapping_add(16);
        ip = ip.wrapping_add(16);
        loop {
            // SAFETY: class B (boundary). As above.
            unsafe {
                ZSTD_copy16(op, ip);
            }
            op = op.wrapping_add(16);
            ip = ip.wrapping_add(16);
            unsafe {
                ZSTD_copy16(op, ip);
            }
            op = op.wrapping_add(16);
            ip = ip.wrapping_add(16);
            if op >= oend {
                break;
            }
        }
    }
}

/// `WILDCOPY_VECLEN`.
const WILDCOPY_VECLEN: usize = 16;

// ---------------------------------------------------------------------------
// Sequence execution
// ---------------------------------------------------------------------------

/// `ZSTD_overlapCopy8()`.
///
/// # Safety
/// `*ip <= *op`; `*op .. *op + 8` and `*ip .. *ip + 8` must be valid, and
/// after the offset spread below, `*ip - dec64table[offset] .. + 8` too.
unsafe fn ZSTD_overlapCopy8(op: &mut *mut u8, ip: &mut *const u8, offset: usize) {
    debug_assert!(*ip as usize <= *op as usize);
    if offset < 8 {
        const DEC32_TABLE: [u32; 8] = [0, 1, 2, 1, 4, 4, 4, 4];
        const DEC64_TABLE: [i32; 8] = [8, 8, 8, 7, 8, 9, 10, 11];
        let sub2 = DEC64_TABLE[offset];
        // SAFETY: class B (boundary). The caller's contract covers the
        // 4-byte read/write and the subsequent 4-byte copy after the
        // offset spread.
        unsafe {
            (*op).write(*ip.add(0));
            (*op).add(1).write(*ip.add(1));
            (*op).add(2).write(*ip.add(2));
            (*op).add(3).write(*ip.add(3));
            *ip = ip.wrapping_add(DEC32_TABLE[offset] as usize);
            ZSTD_copy4(op.wrapping_add(4), *ip);
            *ip = ip.wrapping_offset(-(sub2 as isize));
        }
    } else {
        // SAFETY: class B (boundary). As above.
        unsafe { ZSTD_copy8(*op, *ip) };
    }
    *ip = ip.wrapping_add(8);
    *op = op.wrapping_add(8);
    debug_assert!((*op as isize).wrapping_sub(*ip as isize) >= 8);
}

/// `ZSTD_safecopy()`.
///
/// # Safety
/// The C's own contract: for [`Overlap::NoOverlap`], `op`/`ip` are at least
/// `WILDCOPY_VECLEN` apart or `op >= oend_w`; for
/// [`Overlap::OverlapSrcBeforeDst`], `op >= ip`. Reads up to
/// `WILDCOPY_OVERLENGTH` past `ip + length` and writes up to that much past
/// `oend_w` are the whole point of this function and must be valid in the
/// caller's buffers.
unsafe fn ZSTD_safecopy(mut op: *mut u8, oend_w: *const u8, mut ip: *const u8, length: isize, ovtype: Overlap) {
    let diff = (op as isize).wrapping_sub(ip as isize);
    let oend = op.wrapping_offset(length);

    debug_assert!(
        (ovtype == Overlap::NoOverlap && (diff <= -8 || diff >= 8 || op as usize >= oend_w as usize))
            || (ovtype == Overlap::OverlapSrcBeforeDst && diff >= 0)
    );

    if length < 8 {
        // SAFETY: class B (boundary). The caller's contract.
        while (op as usize) < oend as usize {
            unsafe {
                *op = *ip;
                op = op.wrapping_add(1);
                ip = ip.wrapping_add(1);
            }
        }
        return;
    }
    if ovtype == Overlap::OverlapSrcBeforeDst {
        debug_assert!(length >= 8);
        // SAFETY: class B (boundary). As above.
        unsafe { ZSTD_overlapCopy8(&mut op, &mut ip, diff as usize) };
        let length = length.wrapping_sub(8);
        debug_assert!((op as isize).wrapping_sub(ip as isize) >= 8);
        debug_assert!(op as usize <= oend as usize);
        // SAFETY: class B (boundary). This function's own contract.
        return unsafe { ZSTD_safecopy_tail(op, oend_w, ip, oend, length, ovtype) };
    }
    // SAFETY: class B (boundary). As above.
    unsafe { ZSTD_safecopy_tail(op, oend_w, ip, oend, length, ovtype) }
}

/// Shared tail of [`ZSTD_safecopy`], split out only because Rust's `length`
/// binding in the `OverlapSrcBeforeDst` arm above is a fresh, shorter value
/// after `ZSTD_overlapCopy8` -- the C reassigns the same local in place.
///
/// # Safety
/// As [`ZSTD_safecopy`].
unsafe fn ZSTD_safecopy_tail(
    mut op: *mut u8,
    oend_w: *const u8,
    mut ip: *const u8,
    oend: *mut u8,
    length: isize,
    ovtype: Overlap,
) {
    if oend as usize <= oend_w as usize {
        // No risk of overwrite.
        // SAFETY: class B (boundary). The caller's contract.
        unsafe { ZSTD_wildcopy(op, ip, length, ovtype) };
        return;
    }
    if op as usize <= oend_w as usize {
        debug_assert!(oend as usize > oend_w as usize);
        let n = (oend_w as isize).wrapping_sub(op as isize);
        // SAFETY: class B (boundary). As above.
        unsafe { ZSTD_wildcopy(op, ip, n, ovtype) };
        ip = ip.wrapping_offset(n);
        op = op.wrapping_offset(n);
    }
    // Handle the leftovers.
    // SAFETY: class B (boundary). As above.
    while (op as usize) < oend as usize {
        unsafe {
            *op = *ip;
            op = op.wrapping_add(1);
            ip = ip.wrapping_add(1);
        }
    }
}

/// `ZSTD_safecopyDstBeforeSrc()`.
///
/// # Safety
/// The C's own contract: overlap with dst before src, or no overlap with
/// dst after src. Reads/writes up to `WILDCOPY_OVERLENGTH` past `length`
/// must be valid when the wildcopy branch below is taken.
unsafe fn ZSTD_safecopyDstBeforeSrc(mut op: *mut u8, mut ip: *const u8, length: isize) {
    let diff = (op as isize).wrapping_sub(ip as isize);
    let oend = op.wrapping_offset(length);

    if length < 8 || diff > -8 {
        // SAFETY: class B (boundary). The caller's contract.
        while (op as usize) < oend as usize {
            unsafe {
                *op = *ip;
                op = op.wrapping_add(1);
                ip = ip.wrapping_add(1);
            }
        }
        return;
    }

    if (op as usize) <= (oend as usize).wrapping_sub(WILDCOPY_OVERLENGTH)
        && diff < -(WILDCOPY_VECLEN as isize)
    {
        let n = (oend as isize)
            .wrapping_sub(WILDCOPY_OVERLENGTH as isize)
            .wrapping_sub(op as isize);
        // SAFETY: class B (boundary). As above.
        unsafe { ZSTD_wildcopy(op, ip, n, Overlap::NoOverlap) };
        ip = ip.wrapping_offset(n);
        op = op.wrapping_offset(n);
    }

    // Handle the leftovers.
    while (op as usize) < oend as usize {
        // SAFETY: class B (boundary). As above.
        unsafe {
            *op = *ip;
            op = op.wrapping_add(1);
            ip = ip.wrapping_add(1);
        }
    }
}

/// `ZSTD_execSequenceEnd()`.
///
/// # Safety
/// `op .. oend` must be writable, `*litPtr .. litLimit` readable, and
/// `prefixStart`/`virtualStart`/`dictEnd` must describe the caller's
/// window/dictionary layout, same as the C's unchecked pointer arithmetic.
unsafe fn ZSTD_execSequenceEnd(
    mut op: *mut u8,
    oend: *mut u8,
    mut sequence: Seq,
    litPtr: &mut *const u8,
    litLimit: *const u8,
    prefixStart: *const u8,
    virtualStart: *const u8,
    dictEnd: *const u8,
) -> usize {
    let oLitEnd = op.wrapping_add(sequence.litLength);
    let sequenceLength = sequence.litLength.wrapping_add(sequence.matchLength);
    let iLitEnd = litPtr.wrapping_add(sequence.litLength);
    let mut match_ = oLitEnd.wrapping_sub(sequence.offset) as *const u8;
    let oend_w = oend.wrapping_sub(WILDCOPY_OVERLENGTH);

    if sequenceLength > (oend as usize).wrapping_sub(op as usize) {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if sequence.litLength > (litLimit as usize).wrapping_sub(*litPtr as usize) {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // copy literals
    // SAFETY: class B (boundary). The caller's contract; the two length
    // checks above are exactly what the C relies on for this call's safety.
    unsafe { ZSTD_safecopy(op, oend_w, *litPtr, sequence.litLength as isize, Overlap::NoOverlap) };
    op = oLitEnd;
    *litPtr = iLitEnd;

    // copy Match
    if sequence.offset > (oLitEnd as usize).wrapping_sub(prefixStart as usize) {
        // offset beyond prefix
        if sequence.offset > (oLitEnd as usize).wrapping_sub(virtualStart as usize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        match_ = dictEnd.wrapping_sub((prefixStart as usize).wrapping_sub(match_ as usize));
        if (match_ as usize).wrapping_add(sequence.matchLength) <= dictEnd as usize {
            // SAFETY: class C (construction). `match_ + matchLength <=
            // dictEnd`, and `oLitEnd .. + matchLength` was already bounded
            // by the `sequenceLength` check above.
            unsafe { core::ptr::copy(match_, oLitEnd, sequence.matchLength) };
            return sequenceLength;
        }
        // span extDict & currentPrefixSegment
        let length1 = (dictEnd as usize).wrapping_sub(match_ as usize);
        // SAFETY: class C (construction). As above.
        unsafe { core::ptr::copy(match_, oLitEnd, length1) };
        op = oLitEnd.wrapping_add(length1);
        sequence.matchLength = sequence.matchLength.wrapping_sub(length1);
        match_ = prefixStart;
    }
    // SAFETY: class B (boundary). As above.
    unsafe {
        ZSTD_safecopy(
            op,
            oend_w,
            match_,
            sequence.matchLength as isize,
            Overlap::OverlapSrcBeforeDst,
        )
    };
    sequenceLength
}

/// `ZSTD_execSequenceEndSplitLitBuffer()`.
///
/// # Safety
/// As [`ZSTD_execSequenceEnd`].
unsafe fn ZSTD_execSequenceEndSplitLitBuffer(
    mut op: *mut u8,
    oend: *mut u8,
    oend_w: *const u8,
    mut sequence: Seq,
    litPtr: &mut *const u8,
    litLimit: *const u8,
    prefixStart: *const u8,
    virtualStart: *const u8,
    dictEnd: *const u8,
) -> usize {
    let oLitEnd = op.wrapping_add(sequence.litLength);
    let sequenceLength = sequence.litLength.wrapping_add(sequence.matchLength);
    let iLitEnd = litPtr.wrapping_add(sequence.litLength);
    let mut match_ = oLitEnd.wrapping_sub(sequence.offset) as *const u8;

    if sequenceLength > (oend as usize).wrapping_sub(op as usize) {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if sequence.litLength > (litLimit as usize).wrapping_sub(*litPtr as usize) {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // copy literals
    if op as usize > *litPtr as usize && (op as usize) < (*litPtr as usize).wrapping_add(sequence.litLength) {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    // SAFETY: class B (boundary). The caller's contract.
    unsafe { ZSTD_safecopyDstBeforeSrc(op, *litPtr, sequence.litLength as isize) };
    op = oLitEnd;
    *litPtr = iLitEnd;

    // copy Match
    if sequence.offset > (oLitEnd as usize).wrapping_sub(prefixStart as usize) {
        if sequence.offset > (oLitEnd as usize).wrapping_sub(virtualStart as usize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        match_ = dictEnd.wrapping_sub((prefixStart as usize).wrapping_sub(match_ as usize));
        if (match_ as usize).wrapping_add(sequence.matchLength) <= dictEnd as usize {
            // SAFETY: class C (construction). As `ZSTD_execSequenceEnd`.
            unsafe { core::ptr::copy(match_, oLitEnd, sequence.matchLength) };
            return sequenceLength;
        }
        let length1 = (dictEnd as usize).wrapping_sub(match_ as usize);
        // SAFETY: class C (construction). As above.
        unsafe { core::ptr::copy(match_, oLitEnd, length1) };
        op = oLitEnd.wrapping_add(length1);
        sequence.matchLength = sequence.matchLength.wrapping_sub(length1);
        match_ = prefixStart;
    }
    // SAFETY: class B (boundary). As above.
    unsafe {
        ZSTD_safecopy(
            op,
            oend_w,
            match_,
            sequence.matchLength as isize,
            Overlap::OverlapSrcBeforeDst,
        )
    };
    sequenceLength
}

/// `ZSTD_execSequence()`.
///
/// # Safety
/// As [`ZSTD_execSequenceEnd`] -- the fast path this function takes when
/// none of the edge-case checks below fire relies on the same buffer
/// layout, just without re-deriving every bound explicitly.
unsafe fn ZSTD_execSequence(
    mut op: *mut u8,
    oend: *mut u8,
    mut sequence: Seq,
    litPtr: &mut *const u8,
    litLimit: *const u8,
    prefixStart: *const u8,
    virtualStart: *const u8,
    dictEnd: *const u8,
) -> usize {
    let oLitEnd = op.wrapping_add(sequence.litLength);
    let sequenceLength = sequence.litLength.wrapping_add(sequence.matchLength);
    let oMatchEnd = op.wrapping_add(sequenceLength);
    let oend_w = oend.wrapping_sub(WILDCOPY_OVERLENGTH);
    let iLitEnd = litPtr.wrapping_add(sequence.litLength);
    let mut match_ = oLitEnd.wrapping_sub(sequence.offset) as *const u8;

    if iLitEnd as usize > litLimit as usize
        || oMatchEnd as usize > oend_w as usize
        || (MEM_32BITS
            && (oend as usize).wrapping_sub(op as usize)
                < sequenceLength.wrapping_add(WILDCOPY_OVERLENGTH))
    {
        // SAFETY: class B (boundary). Forwarded unchanged.
        return unsafe {
            ZSTD_execSequenceEnd(op, oend, sequence, litPtr, litLimit, prefixStart, virtualStart, dictEnd)
        };
    }

    // Copy Literals
    // SAFETY: class B (boundary). The slow-path checks above just excluded
    // every case where this 16-byte (and possible wildcopy) step could run
    // past `litLimit`/`oend_w`.
    unsafe {
        ZSTD_copy16(op, *litPtr);
        if sequence.litLength > 16 {
            ZSTD_wildcopy(
                op.wrapping_add(16),
                litPtr.wrapping_add(16),
                (sequence.litLength.wrapping_sub(16)) as isize,
                Overlap::NoOverlap,
            );
        }
    }
    op = oLitEnd;
    *litPtr = iLitEnd;

    // Copy Match
    if sequence.offset > (oLitEnd as usize).wrapping_sub(prefixStart as usize) {
        if sequence.offset > (oLitEnd as usize).wrapping_sub(virtualStart as usize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        match_ = dictEnd.wrapping_add((match_ as usize).wrapping_sub(prefixStart as usize));
        if (match_ as usize).wrapping_add(sequence.matchLength) <= dictEnd as usize {
            // SAFETY: class C (construction). As `ZSTD_execSequenceEnd`.
            unsafe { core::ptr::copy(match_, oLitEnd, sequence.matchLength) };
            return sequenceLength;
        }
        let length1 = (dictEnd as usize).wrapping_sub(match_ as usize);
        // SAFETY: class C (construction). As above.
        unsafe { core::ptr::copy(match_, oLitEnd, length1) };
        op = oLitEnd.wrapping_add(length1);
        sequence.matchLength = sequence.matchLength.wrapping_sub(length1);
        match_ = prefixStart;
    }

    if sequence.offset >= WILDCOPY_VECLEN {
        // SAFETY: class B (boundary). The slow-path checks above bound this
        // wildcopy inside `oend_w`.
        unsafe { ZSTD_wildcopy(op, match_, sequence.matchLength as isize, Overlap::NoOverlap) };
        return sequenceLength;
    }

    // SAFETY: class B (boundary). As above.
    unsafe { ZSTD_overlapCopy8(&mut op, &mut match_, sequence.offset) };
    if sequence.matchLength > 8 {
        // SAFETY: class B (boundary). As above.
        unsafe {
            ZSTD_wildcopy(
                op,
                match_,
                (sequence.matchLength as isize).wrapping_sub(8),
                Overlap::OverlapSrcBeforeDst,
            )
        };
    }
    sequenceLength
}

/// `ZSTD_execSequenceSplitLitBuffer()`.
///
/// # Safety
/// As [`ZSTD_execSequence`].
unsafe fn ZSTD_execSequenceSplitLitBuffer(
    mut op: *mut u8,
    oend: *mut u8,
    oend_w: *const u8,
    mut sequence: Seq,
    litPtr: &mut *const u8,
    litLimit: *const u8,
    prefixStart: *const u8,
    virtualStart: *const u8,
    dictEnd: *const u8,
) -> usize {
    let oLitEnd = op.wrapping_add(sequence.litLength);
    let sequenceLength = sequence.litLength.wrapping_add(sequence.matchLength);
    let oMatchEnd = op.wrapping_add(sequenceLength);
    let iLitEnd = litPtr.wrapping_add(sequence.litLength);
    let mut match_ = oLitEnd.wrapping_sub(sequence.offset) as *const u8;

    if iLitEnd as usize > litLimit as usize
        || oMatchEnd as usize > oend_w as usize
        || (MEM_32BITS
            && (oend as usize).wrapping_sub(op as usize)
                < sequenceLength.wrapping_add(WILDCOPY_OVERLENGTH))
    {
        // SAFETY: class B (boundary). Forwarded unchanged.
        return unsafe {
            ZSTD_execSequenceEndSplitLitBuffer(
                op, oend, oend_w, sequence, litPtr, litLimit, prefixStart, virtualStart, dictEnd,
            )
        };
    }

    // Copy Literals
    // SAFETY: class B (boundary). As `ZSTD_execSequence`.
    unsafe {
        ZSTD_copy16(op, *litPtr);
        if sequence.litLength > 16 {
            ZSTD_wildcopy(
                op.wrapping_add(16),
                litPtr.wrapping_add(16),
                (sequence.litLength.wrapping_sub(16)) as isize,
                Overlap::NoOverlap,
            );
        }
    }
    op = oLitEnd;
    *litPtr = iLitEnd;

    // Copy Match
    if sequence.offset > (oLitEnd as usize).wrapping_sub(prefixStart as usize) {
        if sequence.offset > (oLitEnd as usize).wrapping_sub(virtualStart as usize) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        match_ = dictEnd.wrapping_add((match_ as usize).wrapping_sub(prefixStart as usize));
        if (match_ as usize).wrapping_add(sequence.matchLength) <= dictEnd as usize {
            // SAFETY: class C (construction). As `ZSTD_execSequenceEnd`.
            unsafe { core::ptr::copy(match_, oLitEnd, sequence.matchLength) };
            return sequenceLength;
        }
        let length1 = (dictEnd as usize).wrapping_sub(match_ as usize);
        // SAFETY: class C (construction). As above.
        unsafe { core::ptr::copy(match_, oLitEnd, length1) };
        op = oLitEnd.wrapping_add(length1);
        sequence.matchLength = sequence.matchLength.wrapping_sub(length1);
        match_ = prefixStart;
    }

    if sequence.offset >= WILDCOPY_VECLEN {
        // SAFETY: class B (boundary). As `ZSTD_execSequence`.
        unsafe { ZSTD_wildcopy(op, match_, sequence.matchLength as isize, Overlap::NoOverlap) };
        return sequenceLength;
    }

    // SAFETY: class B (boundary). As above.
    unsafe { ZSTD_overlapCopy8(&mut op, &mut match_, sequence.offset) };
    if sequence.matchLength > 8 {
        // SAFETY: class B (boundary). As above.
        unsafe {
            ZSTD_wildcopy(
                op,
                match_,
                (sequence.matchLength as isize).wrapping_sub(8),
                Overlap::OverlapSrcBeforeDst,
            )
        };
    }
    sequenceLength
}


/// `seqState_t`.
struct SeqState {
    DStream: BitDStream,
    stateLL: ZstdFseState,
    stateOffb: ZstdFseState,
    stateML: ZstdFseState,
    prevOffset: [usize; ZSTD_REP_NUM],
}

/// `ZSTD_initFseState()`.
///
/// # Safety
/// `dt` must point at a live table this file built (header cell plus
/// `1 << tableLog` payload cells).
unsafe fn ZSTD_initFseState(DStatePtr: &mut ZstdFseState, bitD: &mut BitDStream, dt: *const SeqSymbol) {
    // SAFETY: class B (boundary). `dt[0]` is the header cell.
    let tableLog = unsafe { *(dt as *const u32).add(1) };
    DStatePtr.state = BIT_readBits(bitD, tableLog);
    BIT_reloadDStream(bitD);
    DStatePtr.table = dt.wrapping_add(1);
}

/// `ZSTD_updateFseStateWithDInfo()`.
fn ZSTD_updateFseStateWithDInfo(DStatePtr: &mut ZstdFseState, bitD: &mut BitDStream, nextState: u16, nbBits: u32) {
    let lowBits = BIT_readBits(bitD, nbBits);
    DStatePtr.state = (nextState as usize).wrapping_add(lowBits);
}

/// `LONG_OFFSETS_MAX_EXTRA_BITS_32`.
const LONG_OFFSETS_MAX_EXTRA_BITS_32: u32 = 5;
/// `STREAM_ACCUMULATOR_MIN_32`.
const STREAM_ACCUMULATOR_MIN_32: u32 = 25;
/// `STREAM_ACCUMULATOR_MIN_64`.
const STREAM_ACCUMULATOR_MIN_64: u32 = 57;

/// `ZSTD_longOffset_e`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LongOffset {
    IsRegularOffset,
    IsLongOffset,
}

/// `ZSTD_decodeSequence()`.
///
/// The `#if defined(__aarch64__) && (defined(__GNUC__) && !defined(__clang__))`
/// arm (a `ZSTD_memcpy` hack for a GCC/aarch64 codegen quirk) is not taken:
/// this kernel builds with clang on every target the config sweep covers.
/// Only the plain-pointer `#else` arm is ported.
fn ZSTD_decodeSequence(seqState: &mut SeqState, longOffsets: LongOffset, isLastSeq: bool) -> Seq {
    // SAFETY: class C (construction). `state` is always `< tableSize` for
    // the table it indexes -- the initial state is `BIT_readBits(tableLog)`,
    // masked to `tableLog` bits, and `ZSTD_updateFseStateWithDInfo` only
    // ever advances it to `nextState`, which `ZSTD_buildFSETable_body`
    // built to stay in range.
    let llDInfo = unsafe { &*seqState.stateLL.table.add(seqState.stateLL.state) };
    let mlDInfo = unsafe { &*seqState.stateML.table.add(seqState.stateML.state) };
    let ofDInfo = unsafe { &*seqState.stateOffb.table.add(seqState.stateOffb.state) };

    let mut seq = Seq {
        matchLength: mlDInfo.baseValue as usize,
        litLength: llDInfo.baseValue as usize,
        offset: 0,
    };

    let ofBase = ofDInfo.baseValue;
    let llBits = llDInfo.nbAdditionalBits;
    let mlBits = mlDInfo.nbAdditionalBits;
    let ofBits = ofDInfo.nbAdditionalBits;
    let totalBits = llBits.wrapping_add(mlBits).wrapping_add(ofBits);

    let llNext = llDInfo.nextState;
    let mlNext = mlDInfo.nextState;
    let ofNext = ofDInfo.nextState;
    let llnbBits = llDInfo.nbBits as u32;
    let mlnbBits = mlDInfo.nbBits as u32;
    let ofnbBits = ofDInfo.nbBits as u32;

    debug_assert!((llBits as u32) <= 16); // MaxLLBits
    debug_assert!((mlBits as u32) <= 16); // MaxMLBits
    debug_assert!((ofBits as u32) <= MAX_OFF);

    // sequence
    {
        if ofBits > 1 {
            if MEM_32BITS
                && longOffsets == LongOffset::IsLongOffset
                && (ofBits as u32) >= STREAM_ACCUMULATOR_MIN_32
            {
                let extraBits = LONG_OFFSETS_MAX_EXTRA_BITS_32;
                let offset = (ofBase as usize).wrapping_add(
                    BIT_readBitsFast(&mut seqState.DStream, (ofBits as u32).wrapping_sub(extraBits))
                        << extraBits,
                );
                BIT_reloadDStream(&mut seqState.DStream);
                let offset = offset.wrapping_add(BIT_readBitsFast(&mut seqState.DStream, extraBits));
                seqState.prevOffset[2] = seqState.prevOffset[1];
                seqState.prevOffset[1] = seqState.prevOffset[0];
                seqState.prevOffset[0] = offset;
                seq.offset = offset;
            } else {
                let offset = (ofBase as usize)
                    .wrapping_add(BIT_readBitsFast(&mut seqState.DStream, ofBits as u32));
                if MEM_32BITS {
                    BIT_reloadDStream(&mut seqState.DStream);
                }
                seqState.prevOffset[2] = seqState.prevOffset[1];
                seqState.prevOffset[1] = seqState.prevOffset[0];
                seqState.prevOffset[0] = offset;
                seq.offset = offset;
            }
        } else {
            let ll0 = (llDInfo.baseValue == 0) as usize;
            if ofBits == 0 {
                let offset = seqState.prevOffset[ll0];
                seqState.prevOffset[1] = seqState.prevOffset[1usize.wrapping_sub(ll0)];
                seqState.prevOffset[0] = offset;
                seq.offset = offset;
            } else {
                let offset = (ofBase as usize)
                    .wrapping_add(ll0)
                    .wrapping_add(BIT_readBitsFast(&mut seqState.DStream, 1));
                let mut temp = if offset == 3 {
                    seqState.prevOffset[0].wrapping_sub(1)
                } else {
                    seqState.prevOffset[offset]
                };
                // 0 is not valid: input corrupted => force offset to -1 =>
                // corruption detected at execSequence.
                temp = temp.wrapping_sub((temp == 0) as usize);
                if offset != 1 {
                    seqState.prevOffset[2] = seqState.prevOffset[1];
                }
                seqState.prevOffset[1] = seqState.prevOffset[0];
                seqState.prevOffset[0] = temp;
                seq.offset = temp;
            }
        }
    }

    if mlBits > 0 {
        seq.matchLength = seq
            .matchLength
            .wrapping_add(BIT_readBitsFast(&mut seqState.DStream, mlBits as u32));
    }

    if MEM_32BITS
        && (mlBits as u32).wrapping_add(llBits as u32)
            >= STREAM_ACCUMULATOR_MIN_32.wrapping_sub(LONG_OFFSETS_MAX_EXTRA_BITS_32)
    {
        BIT_reloadDStream(&mut seqState.DStream);
    }
    if MEM_64BITS
        && (totalBits as u32)
            >= STREAM_ACCUMULATOR_MIN_64.wrapping_sub(LL_FSE_LOG + ML_FSE_LOG + OFF_FSE_LOG)
    {
        BIT_reloadDStream(&mut seqState.DStream);
    }

    if llBits > 0 {
        seq.litLength = seq
            .litLength
            .wrapping_add(BIT_readBitsFast(&mut seqState.DStream, llBits as u32));
    }

    if MEM_32BITS {
        BIT_reloadDStream(&mut seqState.DStream);
    }

    if !isLastSeq {
        // don't update FSE state for last Sequence
        ZSTD_updateFseStateWithDInfo(&mut seqState.stateLL, &mut seqState.DStream, llNext, llnbBits);
        ZSTD_updateFseStateWithDInfo(&mut seqState.stateML, &mut seqState.DStream, mlNext, mlnbBits);
        if MEM_32BITS {
            BIT_reloadDStream(&mut seqState.DStream);
        }
        ZSTD_updateFseStateWithDInfo(&mut seqState.stateOffb, &mut seqState.DStream, ofNext, ofnbBits);
        BIT_reloadDStream(&mut seqState.DStream);
    }

    seq
}


/// `compiler.h:271` — `ZSTD_maybeNullPtrAdd()`: `ptr + add` except that
/// `NULL + 0 == NULL`.
#[inline(always)]
fn ZSTD_maybeNullPtrAdd(ptr: *mut u8, add: isize) -> *mut u8 {
    if add > 0 {
        ptr.wrapping_offset(add)
    } else {
        ptr
    }
}

/// `compiler.h:246` — `ZSTD_wrappedPtrAdd()`.
#[inline(always)]
fn ZSTD_wrappedPtrAdd(ptr: *const u8, add: isize) -> *const u8 {
    ptr.wrapping_offset(add)
}

/// `compiler.h:259` — `ZSTD_wrappedPtrSub()`.
#[inline(always)]
fn ZSTD_wrappedPtrSub(ptr: *const u8, sub: isize) -> *const u8 {
    ptr.wrapping_offset(-sub)
}

/// `CACHELINE_SIZE`.
const CACHELINE_SIZE: usize = 64;

/// `PREFETCH_L1`/`PREFETCH_L2`, `compiler.h`. Hints only; see
/// [`PREFETCH_AREA`] for why this is a no-op on every target `core` supports.
#[inline(always)]
fn PREFETCH_L1(_ptr: *const u8) {}

/// `ZSTD_prefetchMatch()`.
fn ZSTD_prefetchMatch(prefetchPos: usize, sequence: Seq, prefixStart: *const u8, dictEnd: *const u8) -> usize {
    let prefetchPos = prefetchPos.wrapping_add(sequence.litLength);
    let matchBase = if sequence.offset > prefetchPos { dictEnd } else { prefixStart };
    // note: this operation can overflow when seq.offset is really too
    // large, which can only happen when input is corrupted. No consequence
    // though: memory address is only used for prefetching, not for
    // dereferencing.
    let match_ = ZSTD_wrappedPtrSub(
        ZSTD_wrappedPtrAdd(matchBase, prefetchPos as isize),
        sequence.offset as isize,
    );
    PREFETCH_L1(match_);
    PREFETCH_L1(match_.wrapping_add(CACHELINE_SIZE));
    prefetchPos.wrapping_add(sequence.matchLength)
}

/// `ZSTD_decompressSequences_bodySplitLitBuffer()`.
///
/// The `#if defined(__x86_64__)` `.p2align`/`nop` inline-asm blocks (GCC-
/// version-tuned decode-loop alignment, no correctness effect, tuned for
/// GCC codegen quirks this clang-built kernel does not share) are not
/// ported -- pure micro-optimisation with nothing to be faithful to on this
/// toolchain.
///
/// # Safety
/// `dctx` must be live with a literals block and sequence-header tables
/// already decoded; `dst .. + maxDstSize` writable; `seqStart .. + seqSize`
/// readable. Matches the C's own unchecked contract for this function.
unsafe fn ZSTD_decompressSequences_bodySplitLitBuffer(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    mut nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    let ip = seqStart as *const u8;
    let iend = ip.wrapping_add(seqSize);
    let ostart = dst as *mut u8;
    let oend = ZSTD_maybeNullPtrAdd(ostart, maxDstSize as isize);
    let mut op = ostart;
    let mut litPtr = dctx.litPtr;
    let mut litBufferEnd = dctx.litBufferEnd;
    let prefixStart = dctx.prefixStart as *const u8;
    let vBase = dctx.virtualStart as *const u8;
    let dictEnd = dctx.dictEnd as *const u8;

    if nbSeq != 0 {
        let mut seqState = SeqState {
            DStream: BitDStream {
                bitContainer: 0,
                bitsConsumed: 0,
                ptr: core::ptr::null(),
                start: core::ptr::null(),
                limitPtr: core::ptr::null(),
                src_size: 0,
            },
            stateLL: ZstdFseState { state: 0, table: core::ptr::null() },
            stateOffb: ZstdFseState { state: 0, table: core::ptr::null() },
            stateML: ZstdFseState { state: 0, table: core::ptr::null() },
            prevOffset: [0; ZSTD_REP_NUM],
        };
        dctx.fseEntropy = 1;
        for i in 0..ZSTD_REP_NUM {
            seqState.prevOffset[i] = dctx.entropy.rep[i] as usize;
        }
        // SAFETY: class B (boundary). The caller's contract.
        if ERR_isError(unsafe {
            BIT_initDStream(&mut seqState.DStream, ip, iend as usize - ip as usize)
        }) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // SAFETY: class B (boundary) plus class C: `dctx.LLTptr`/`OFTptr`/
        // `MLTptr` are tables `ZSTD_decodeSeqHeaders` just built.
        unsafe {
            ZSTD_initFseState(&mut seqState.stateLL, &mut seqState.DStream, dctx.LLTptr);
            ZSTD_initFseState(&mut seqState.stateOffb, &mut seqState.DStream, dctx.OFTptr);
            ZSTD_initFseState(&mut seqState.stateML, &mut seqState.DStream, dctx.MLTptr);
        }
        debug_assert!(!dst.is_null());

        let mut sequence = Seq { litLength: 0, matchLength: 0, offset: 0 };
        // Handle the initial state where litBuffer is currently split
        // between dst and litExtraBuffer.
        while nbSeq != 0 {
            sequence = ZSTD_decodeSequence(&mut seqState, isLongOffset, nbSeq == 1);
            if (litPtr.wrapping_add(sequence.litLength) as usize) > dctx.litBufferEnd as usize {
                break;
            }
            // SAFETY: class B (boundary). The caller's contract; every
            // pointer here is one this function derived from `dctx`'s own
            // fields the same way the C does.
            let oneSeqSize = unsafe {
                ZSTD_execSequenceSplitLitBuffer(
                    op,
                    oend,
                    litPtr.wrapping_add(sequence.litLength).wrapping_sub(WILDCOPY_OVERLENGTH),
                    sequence,
                    &mut litPtr,
                    litBufferEnd,
                    prefixStart,
                    vBase,
                    dictEnd,
                )
            };
            if ERR_isError(oneSeqSize) {
                return oneSeqSize;
            }
            op = op.wrapping_add(oneSeqSize);
            nbSeq -= 1;
        }

        // If there are more sequences, they will need to read literals from
        // litExtraBuffer; copy over the remainder from dst and update
        // litPtr and litEnd.
        if nbSeq > 0 {
            let leftoverLit = litBufferEnd as usize - litPtr as usize;
            if leftoverLit != 0 {
                if leftoverLit > (oend as usize).wrapping_sub(op as usize) {
                    return ERROR(ZSTD_error_dstSize_tooSmall);
                }
                // SAFETY: class B (boundary). As above.
                unsafe { ZSTD_safecopyDstBeforeSrc(op, litPtr, leftoverLit as isize) };
                sequence.litLength = sequence.litLength.wrapping_sub(leftoverLit);
                op = op.wrapping_add(leftoverLit);
            }
            litPtr = dctx.litExtraBuffer.as_ptr();
            litBufferEnd = dctx.litExtraBuffer.as_ptr().wrapping_add(ZSTD_LITBUFFEREXTRASIZE);
            dctx.litBufferLocation = LitLocation::NotInDst as u32;
            // SAFETY: class B (boundary). As above.
            let oneSeqSize = unsafe {
                ZSTD_execSequence(op, oend, sequence, &mut litPtr, litBufferEnd, prefixStart, vBase, dictEnd)
            };
            if ERR_isError(oneSeqSize) {
                return oneSeqSize;
            }
            op = op.wrapping_add(oneSeqSize);
            nbSeq -= 1;
        }

        if nbSeq > 0 {
            // there is remaining lit from extra buffer
            while nbSeq != 0 {
                let sequence = ZSTD_decodeSequence(&mut seqState, isLongOffset, nbSeq == 1);
                // SAFETY: class B (boundary). As above.
                let oneSeqSize = unsafe {
                    ZSTD_execSequence(op, oend, sequence, &mut litPtr, litBufferEnd, prefixStart, vBase, dictEnd)
                };
                if ERR_isError(oneSeqSize) {
                    return oneSeqSize;
                }
                op = op.wrapping_add(oneSeqSize);
                nbSeq -= 1;
            }
        }

        // check if reached exact end
        if nbSeq != 0 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        if BIT_endOfDStream(&seqState.DStream) == 0 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // save reps for next block
        for i in 0..ZSTD_REP_NUM {
            dctx.entropy.rep[i] = seqState.prevOffset[i] as u32;
        }
    }

    // last literal segment
    if dctx.litBufferLocation == LitLocation::Split as u32 {
        // split hasn't been reached yet, first get dst then copy litExtraBuffer
        let lastLLSize = litBufferEnd as usize - litPtr as usize;
        if lastLLSize > (oend as usize).wrapping_sub(op as usize) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if !op.is_null() {
            // SAFETY: class C (construction). `lastLLSize <= oend - op`
            // was just checked.
            unsafe { core::ptr::copy(litPtr, op, lastLLSize) };
            op = op.wrapping_add(lastLLSize);
        }
        litPtr = dctx.litExtraBuffer.as_ptr();
        litBufferEnd = dctx.litExtraBuffer.as_ptr().wrapping_add(ZSTD_LITBUFFEREXTRASIZE);
        dctx.litBufferLocation = LitLocation::NotInDst as u32;
    }
    // copy last literals from internal buffer
    {
        let lastLLSize = litBufferEnd as usize - litPtr as usize;
        if lastLLSize > (oend as usize).wrapping_sub(op as usize) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if !op.is_null() {
            // SAFETY: class C (construction). As above.
            unsafe { core::ptr::copy_nonoverlapping(litPtr, op, lastLLSize) };
            op = op.wrapping_add(lastLLSize);
        }
    }

    op as usize - ostart as usize
}

/// `ZSTD_decompressSequences_body()`.
///
/// # Safety
/// As [`ZSTD_decompressSequences_bodySplitLitBuffer`].
unsafe fn ZSTD_decompressSequences_body(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    mut nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    let ip = seqStart as *const u8;
    let iend = ip.wrapping_add(seqSize);
    let ostart = dst as *mut u8;
    let oend = if dctx.litBufferLocation == LitLocation::NotInDst as u32 {
        ZSTD_maybeNullPtrAdd(ostart, maxDstSize as isize)
    } else {
        dctx.litBuffer
    };
    let mut op = ostart;
    let mut litPtr = dctx.litPtr;
    let litEnd = litPtr.wrapping_add(dctx.litSize);
    let prefixStart = dctx.prefixStart as *const u8;
    let vBase = dctx.virtualStart as *const u8;
    let dictEnd = dctx.dictEnd as *const u8;

    if nbSeq != 0 {
        let mut seqState = SeqState {
            DStream: BitDStream {
                bitContainer: 0,
                bitsConsumed: 0,
                ptr: core::ptr::null(),
                start: core::ptr::null(),
                limitPtr: core::ptr::null(),
                src_size: 0,
            },
            stateLL: ZstdFseState { state: 0, table: core::ptr::null() },
            stateOffb: ZstdFseState { state: 0, table: core::ptr::null() },
            stateML: ZstdFseState { state: 0, table: core::ptr::null() },
            prevOffset: [0; ZSTD_REP_NUM],
        };
        dctx.fseEntropy = 1;
        for i in 0..ZSTD_REP_NUM {
            seqState.prevOffset[i] = dctx.entropy.rep[i] as usize;
        }
        // SAFETY: class B (boundary). The caller's contract.
        if ERR_isError(unsafe {
            BIT_initDStream(&mut seqState.DStream, ip, iend as usize - ip as usize)
        }) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // SAFETY: class B (boundary) plus class C. As above.
        unsafe {
            ZSTD_initFseState(&mut seqState.stateLL, &mut seqState.DStream, dctx.LLTptr);
            ZSTD_initFseState(&mut seqState.stateOffb, &mut seqState.DStream, dctx.OFTptr);
            ZSTD_initFseState(&mut seqState.stateML, &mut seqState.DStream, dctx.MLTptr);
        }
        debug_assert!(!dst.is_null());

        while nbSeq != 0 {
            let sequence = ZSTD_decodeSequence(&mut seqState, isLongOffset, nbSeq == 1);
            // SAFETY: class B (boundary). As above.
            let oneSeqSize = unsafe {
                ZSTD_execSequence(op, oend, sequence, &mut litPtr, litEnd, prefixStart, vBase, dictEnd)
            };
            if ERR_isError(oneSeqSize) {
                return oneSeqSize;
            }
            op = op.wrapping_add(oneSeqSize);
            nbSeq -= 1;
        }

        debug_assert!(nbSeq == 0);
        if BIT_endOfDStream(&seqState.DStream) == 0 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        for i in 0..ZSTD_REP_NUM {
            dctx.entropy.rep[i] = seqState.prevOffset[i] as u32;
        }
    }

    // last literal segment
    {
        let lastLLSize = litEnd as usize - litPtr as usize;
        if lastLLSize > (oend as usize).wrapping_sub(op as usize) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if !op.is_null() {
            // SAFETY: class C (construction). Just checked.
            unsafe { core::ptr::copy_nonoverlapping(litPtr, op, lastLLSize) };
            op = op.wrapping_add(lastLLSize);
        }
    }

    op as usize - ostart as usize
}

/// `BIT_endOfDStream()`.
#[inline(always)]
fn BIT_endOfDStream(DStream: &BitDStream) -> c_uint {
    ((DStream.ptr == DStream.start) && (DStream.bitsConsumed == SIZE_BITS)) as c_uint
}

/// # Safety
/// As [`ZSTD_decompressSequences_body`].
unsafe fn ZSTD_decompressSequences_default(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: forwarded unchanged.
    unsafe { ZSTD_decompressSequences_body(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}

/// # Safety
/// As [`ZSTD_decompressSequences_bodySplitLitBuffer`].
unsafe fn ZSTD_decompressSequencesSplitLitBuffer_default(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: forwarded unchanged.
    unsafe {
        ZSTD_decompressSequences_bodySplitLitBuffer(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
    }
}

/// `ZSTD_decompressSequencesLong_body()`.
///
/// # Safety
/// As [`ZSTD_decompressSequences_bodySplitLitBuffer`].
#[allow(clippy::too_many_arguments)]
unsafe fn ZSTD_decompressSequencesLong_body(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    const STORED_SEQS: usize = 8;
    const STORED_SEQS_MASK: usize = STORED_SEQS - 1;
    const ADVANCED_SEQS: i32 = STORED_SEQS as i32;

    let ip = seqStart as *const u8;
    let iend = ip.wrapping_add(seqSize);
    let ostart = dst as *mut u8;
    let oend = if dctx.litBufferLocation == LitLocation::InDst as u32 {
        dctx.litBuffer
    } else {
        ZSTD_maybeNullPtrAdd(ostart, maxDstSize as isize)
    };
    let mut op = ostart;
    let mut litPtr = dctx.litPtr;
    let mut litBufferEnd = dctx.litBufferEnd;
    let prefixStart = dctx.prefixStart as *const u8;
    let dictStart = dctx.virtualStart as *const u8;
    let dictEnd = dctx.dictEnd as *const u8;

    if nbSeq != 0 {
        let mut sequences = [Seq { litLength: 0, matchLength: 0, offset: 0 }; STORED_SEQS];
        let seqAdvance = nbSeq.min(ADVANCED_SEQS);
        let mut seqState = SeqState {
            DStream: BitDStream {
                bitContainer: 0,
                bitsConsumed: 0,
                ptr: core::ptr::null(),
                start: core::ptr::null(),
                limitPtr: core::ptr::null(),
                src_size: 0,
            },
            stateLL: ZstdFseState { state: 0, table: core::ptr::null() },
            stateOffb: ZstdFseState { state: 0, table: core::ptr::null() },
            stateML: ZstdFseState { state: 0, table: core::ptr::null() },
            prevOffset: [0; ZSTD_REP_NUM],
        };
        let mut prefetchPos = op as usize - prefixStart as usize;

        dctx.fseEntropy = 1;
        for i in 0..ZSTD_REP_NUM {
            seqState.prevOffset[i] = dctx.entropy.rep[i] as usize;
        }
        debug_assert!(!dst.is_null());
        debug_assert!(iend as usize >= ip as usize);
        // SAFETY: class B (boundary). The caller's contract.
        if ERR_isError(unsafe {
            BIT_initDStream(&mut seqState.DStream, ip, iend as usize - ip as usize)
        }) {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // SAFETY: class B (boundary) plus class C. As above.
        unsafe {
            ZSTD_initFseState(&mut seqState.stateLL, &mut seqState.DStream, dctx.LLTptr);
            ZSTD_initFseState(&mut seqState.stateOffb, &mut seqState.DStream, dctx.OFTptr);
            ZSTD_initFseState(&mut seqState.stateML, &mut seqState.DStream, dctx.MLTptr);
        }

        // prepare in advance
        let mut seqNb = 0i32;
        while seqNb < seqAdvance {
            let sequence = ZSTD_decodeSequence(&mut seqState, isLongOffset, seqNb == nbSeq - 1);
            prefetchPos = ZSTD_prefetchMatch(prefetchPos, sequence, prefixStart, dictEnd);
            sequences[seqNb as usize] = sequence;
            seqNb += 1;
        }

        // decompress without stomping litBuffer
        while seqNb < nbSeq {
            let sequence = ZSTD_decodeSequence(&mut seqState, isLongOffset, seqNb == nbSeq - 1);
            let storedIdx = ((seqNb - ADVANCED_SEQS) as usize) & STORED_SEQS_MASK;

            if dctx.litBufferLocation == LitLocation::Split as u32
                && (litPtr.wrapping_add(sequences[storedIdx].litLength) as usize) > dctx.litBufferEnd as usize
            {
                let leftoverLit = dctx.litBufferEnd as usize - litPtr as usize;
                if leftoverLit != 0 {
                    if leftoverLit > (oend as usize).wrapping_sub(op as usize) {
                        return ERROR(ZSTD_error_dstSize_tooSmall);
                    }
                    // SAFETY: class B (boundary). As above.
                    unsafe { ZSTD_safecopyDstBeforeSrc(op, litPtr, leftoverLit as isize) };
                    sequences[storedIdx].litLength = sequences[storedIdx].litLength.wrapping_sub(leftoverLit);
                    op = op.wrapping_add(leftoverLit);
                }
                litPtr = dctx.litExtraBuffer.as_ptr();
                litBufferEnd = dctx.litExtraBuffer.as_ptr().wrapping_add(ZSTD_LITBUFFEREXTRASIZE);
                dctx.litBufferLocation = LitLocation::NotInDst as u32;
                // SAFETY: class B (boundary). As above.
                let oneSeqSize = unsafe {
                    ZSTD_execSequence(
                        op, oend, sequences[storedIdx], &mut litPtr, litBufferEnd, prefixStart, dictStart, dictEnd,
                    )
                };
                if ERR_isError(oneSeqSize) {
                    return oneSeqSize;
                }
                prefetchPos = ZSTD_prefetchMatch(prefetchPos, sequence, prefixStart, dictEnd);
                sequences[(seqNb as usize) & STORED_SEQS_MASK] = sequence;
                op = op.wrapping_add(oneSeqSize);
            } else {
                // SAFETY: class B (boundary). As above.
                let oneSeqSize = unsafe {
                    if dctx.litBufferLocation == LitLocation::Split as u32 {
                        ZSTD_execSequenceSplitLitBuffer(
                            op,
                            oend,
                            litPtr.wrapping_add(sequences[storedIdx].litLength).wrapping_sub(WILDCOPY_OVERLENGTH),
                            sequences[storedIdx],
                            &mut litPtr,
                            litBufferEnd,
                            prefixStart,
                            dictStart,
                            dictEnd,
                        )
                    } else {
                        ZSTD_execSequence(
                            op, oend, sequences[storedIdx], &mut litPtr, litBufferEnd, prefixStart, dictStart, dictEnd,
                        )
                    }
                };
                if ERR_isError(oneSeqSize) {
                    return oneSeqSize;
                }
                prefetchPos = ZSTD_prefetchMatch(prefetchPos, sequence, prefixStart, dictEnd);
                sequences[(seqNb as usize) & STORED_SEQS_MASK] = sequence;
                op = op.wrapping_add(oneSeqSize);
            }
            seqNb += 1;
        }
        if BIT_endOfDStream(&seqState.DStream) == 0 {
            return ERROR(ZSTD_error_corruption_detected);
        }

        // finish queue
        seqNb -= seqAdvance;
        while seqNb < nbSeq {
            let idx = (seqNb as usize) & STORED_SEQS_MASK;
            if dctx.litBufferLocation == LitLocation::Split as u32
                && (litPtr.wrapping_add(sequences[idx].litLength) as usize) > dctx.litBufferEnd as usize
            {
                let leftoverLit = dctx.litBufferEnd as usize - litPtr as usize;
                if leftoverLit != 0 {
                    if leftoverLit > (oend as usize).wrapping_sub(op as usize) {
                        return ERROR(ZSTD_error_dstSize_tooSmall);
                    }
                    // SAFETY: class B (boundary). As above.
                    unsafe { ZSTD_safecopyDstBeforeSrc(op, litPtr, leftoverLit as isize) };
                    sequences[idx].litLength = sequences[idx].litLength.wrapping_sub(leftoverLit);
                    op = op.wrapping_add(leftoverLit);
                }
                litPtr = dctx.litExtraBuffer.as_ptr();
                litBufferEnd = dctx.litExtraBuffer.as_ptr().wrapping_add(ZSTD_LITBUFFEREXTRASIZE);
                dctx.litBufferLocation = LitLocation::NotInDst as u32;
                // SAFETY: class B (boundary). As above.
                let oneSeqSize = unsafe {
                    ZSTD_execSequence(
                        op, oend, sequences[idx], &mut litPtr, litBufferEnd, prefixStart, dictStart, dictEnd,
                    )
                };
                if ERR_isError(oneSeqSize) {
                    return oneSeqSize;
                }
                op = op.wrapping_add(oneSeqSize);
            } else {
                // SAFETY: class B (boundary). As above.
                let oneSeqSize = unsafe {
                    if dctx.litBufferLocation == LitLocation::Split as u32 {
                        ZSTD_execSequenceSplitLitBuffer(
                            op,
                            oend,
                            litPtr.wrapping_add(sequences[idx].litLength).wrapping_sub(WILDCOPY_OVERLENGTH),
                            sequences[idx],
                            &mut litPtr,
                            litBufferEnd,
                            prefixStart,
                            dictStart,
                            dictEnd,
                        )
                    } else {
                        ZSTD_execSequence(
                            op, oend, sequences[idx], &mut litPtr, litBufferEnd, prefixStart, dictStart, dictEnd,
                        )
                    }
                };
                if ERR_isError(oneSeqSize) {
                    return oneSeqSize;
                }
                op = op.wrapping_add(oneSeqSize);
            }
            seqNb += 1;
        }

        // save reps for next block
        for i in 0..ZSTD_REP_NUM {
            dctx.entropy.rep[i] = seqState.prevOffset[i] as u32;
        }
    }

    // last literal segment
    if dctx.litBufferLocation == LitLocation::Split as u32 {
        let lastLLSize = litBufferEnd as usize - litPtr as usize;
        if lastLLSize > (oend as usize).wrapping_sub(op as usize) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if !op.is_null() {
            // SAFETY: class C (construction). Just checked.
            unsafe { core::ptr::copy(litPtr, op, lastLLSize) };
            op = op.wrapping_add(lastLLSize);
        }
        litPtr = dctx.litExtraBuffer.as_ptr();
        litBufferEnd = dctx.litExtraBuffer.as_ptr().wrapping_add(ZSTD_LITBUFFEREXTRASIZE);
    }
    {
        let lastLLSize = litBufferEnd as usize - litPtr as usize;
        if lastLLSize > (oend as usize).wrapping_sub(op as usize) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if !op.is_null() {
            // SAFETY: class C (construction). Just checked.
            unsafe { core::ptr::copy(litPtr, op, lastLLSize) };
            op = op.wrapping_add(lastLLSize);
        }
    }

    op as usize - ostart as usize
}

/// # Safety
/// As [`ZSTD_decompressSequencesLong_body`].
unsafe fn ZSTD_decompressSequencesLong_default(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: forwarded unchanged.
    unsafe { ZSTD_decompressSequencesLong_body(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}

/// # Safety
/// As [`ZSTD_decompressSequences_body`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn ZSTD_decompressSequences_bmi2(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: forwarded unchanged, plus the `#[target_feature]` contract
    // upheld by this function's only caller checking `ZSTD_DCtx_get_bmi2`.
    unsafe { ZSTD_decompressSequences_body(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}

/// # Safety
/// As [`ZSTD_decompressSequences_bodySplitLitBuffer`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn ZSTD_decompressSequencesSplitLitBuffer_bmi2(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: as `ZSTD_decompressSequences_bmi2`.
    unsafe {
        ZSTD_decompressSequences_bodySplitLitBuffer(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
    }
}

/// # Safety
/// As [`ZSTD_decompressSequencesLong_body`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn ZSTD_decompressSequencesLong_bmi2(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    // SAFETY: as `ZSTD_decompressSequences_bmi2`.
    unsafe { ZSTD_decompressSequencesLong_body(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}

/// `ZSTD_decompressSequences()`.
///
/// # Safety
/// As [`ZSTD_decompressSequences_body`].
unsafe fn ZSTD_decompressSequences(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if dctx_get_bmi2(dctx) != 0 {
        // SAFETY: class B (boundary) plus the `#[target_feature]` contract,
        // upheld by `dctx_get_bmi2()` measuring runtime CPU support.
        return unsafe {
            ZSTD_decompressSequences_bmi2(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
        };
    }
    // SAFETY: forwarded unchanged.
    unsafe { ZSTD_decompressSequences_default(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}

/// `ZSTD_decompressSequencesSplitLitBuffer()`.
///
/// # Safety
/// As [`ZSTD_decompressSequences_bodySplitLitBuffer`].
unsafe fn ZSTD_decompressSequencesSplitLitBuffer(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if dctx_get_bmi2(dctx) != 0 {
        // SAFETY: as `ZSTD_decompressSequences`.
        return unsafe {
            ZSTD_decompressSequencesSplitLitBuffer_bmi2(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
        };
    }
    // SAFETY: forwarded unchanged.
    unsafe {
        ZSTD_decompressSequencesSplitLitBuffer_default(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
    }
}

/// `ZSTD_decompressSequencesLong()`.
///
/// # Safety
/// As [`ZSTD_decompressSequencesLong_body`].
unsafe fn ZSTD_decompressSequencesLong(
    dctx: &mut ZstdDCtx,
    dst: *mut c_void,
    maxDstSize: usize,
    seqStart: *const c_void,
    seqSize: usize,
    nbSeq: i32,
    isLongOffset: LongOffset,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if dctx_get_bmi2(dctx) != 0 {
        // SAFETY: as `ZSTD_decompressSequences`.
        return unsafe {
            ZSTD_decompressSequencesLong_bmi2(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset)
        };
    }
    // SAFETY: forwarded unchanged.
    unsafe { ZSTD_decompressSequencesLong_default(dctx, dst, maxDstSize, seqStart, seqSize, nbSeq, isLongOffset) }
}


/// `ZSTD_OffsetInfo`.
struct ZstdOffsetInfo {
    longOffsetShare: u32,
    maxNbAdditionalBits: u32,
}

/// `STREAM_ACCUMULATOR_MIN`, `MEM_32bits() ? STREAM_ACCUMULATOR_MIN_32 :
/// STREAM_ACCUMULATOR_MIN_64` -- always the 64-bit arm on every target this
/// project builds for (x86-64, aarch64).
const STREAM_ACCUMULATOR_MIN: u32 = if MEM_32BITS {
    STREAM_ACCUMULATOR_MIN_32
} else {
    STREAM_ACCUMULATOR_MIN_64
};

/// `ZSTD_getOffsetInfo()`.
///
/// # Safety
/// `offTable` must point at a live table (header cell plus `1 << tableLog`
/// payload cells) when `nbSeq != 0`.
unsafe fn ZSTD_getOffsetInfo(offTable: *const SeqSymbol, nbSeq: i32) -> ZstdOffsetInfo {
    let mut info = ZstdOffsetInfo { longOffsetShare: 0, maxNbAdditionalBits: 0 };
    // If nbSeq == 0, then the offTable is uninitialized, but we have no
    // sequences, so both values should be 0.
    if nbSeq != 0 {
        // SAFETY: class B (boundary). The caller's contract.
        let tableLog = unsafe { *(offTable as *const u32).add(1) };
        let table = offTable.wrapping_add(1);
        let max = 1u32.wrapping_shl(tableLog);
        debug_assert!(max <= 1u32.wrapping_shl(OFF_FSE_LOG));
        for u in 0..max {
            // SAFETY: class C (construction). `u < max == 1 << tableLog`,
            // inside the table this call's caller built.
            let cell = unsafe { &*table.add(u as usize) };
            info.maxNbAdditionalBits = info.maxNbAdditionalBits.max(cell.nbAdditionalBits as u32);
            if cell.nbAdditionalBits > 22 {
                info.longOffsetShare += 1;
            }
        }
        debug_assert!(tableLog <= OFF_FSE_LOG);
        info.longOffsetShare = info.longOffsetShare.wrapping_shl(OFF_FSE_LOG.wrapping_sub(tableLog));
    }
    info
}

/// `ZSTD_maxShortOffset()`.
fn ZSTD_maxShortOffset() -> usize {
    if MEM_64BITS {
        // We can decode any offset without reloading bits. This might
        // change if the max window size grows.
        usize::MAX
    } else {
        let maxOffbase = (1usize << (STREAM_ACCUMULATOR_MIN + 1)) - 1;
        maxOffbase - ZSTD_REP_NUM
    }
}

/// `ZSTD_decompressBlock_internal()`.
///
/// # Safety
/// `dctx` must be a live [`ZstdDCtx`], `src .. + srcSize` readable, and
/// `dst .. + dstCapacity` writable (or `dst` null with `dstCapacity == 0`).
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBlock_internal(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    mut srcSize: usize,
    streaming: StreamingOperation,
) -> usize {
    // SAFETY: the caller guarantees `dctx` is live.
    let dctx = unsafe { &mut *dctx };
    let mut ip = src as *const u8;

    if srcSize > ZSTD_blockSizeMax(dctx) {
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    // Decode literals section
    {
        // SAFETY: class B (boundary). The caller's contract.
        let litCSize = unsafe { ZSTD_decodeLiteralsBlock(dctx, src, srcSize, dst, dstCapacity, streaming) };
        if ERR_isError(litCSize) {
            return litCSize;
        }
        ip = ip.wrapping_add(litCSize);
        srcSize = srcSize.wrapping_sub(litCSize);
    }

    // Build Decoding Tables
    {
        let blockSizeMax = dstCapacity.min(ZSTD_blockSizeMax(dctx));
        let totalHistorySize = ZSTD_totalHistorySize(
            ZSTD_maybeNullPtrAdd(dst as *mut u8, blockSizeMax as isize),
            dctx.virtualStart as *const u8,
        );
        let mut isLongOffset = if MEM_32BITS && totalHistorySize > ZSTD_maxShortOffset() {
            LongOffset::IsLongOffset
        } else {
            LongOffset::IsRegularOffset
        };
        // These macros control at build-time which decompressor
        // implementation we use; neither `ZSTD_FORCE_DECOMPRESS_SEQUENCES_*`
        // is ever defined in this kernel tree, so the runtime-dispatch arm
        // is the only one that ever compiles.
        let mut usePrefetchDecoder = dctx.ddictIsCold != 0;
        let mut nbSeq: c_int = 0;
        // SAFETY: class B (boundary). As above.
        let seqHSize = unsafe { ZSTD_decodeSeqHeaders(dctx, &mut nbSeq, ip as *const c_void, srcSize) };
        if ERR_isError(seqHSize) {
            return seqHSize;
        }
        ip = ip.wrapping_add(seqHSize);
        srcSize = srcSize.wrapping_sub(seqHSize);

        if (dst.is_null() || dstCapacity == 0) && nbSeq > 0 {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        if MEM_64BITS && usize::MAX.wrapping_sub(dst as usize) < (1usize << 20) {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }

        // If we could potentially have long offsets, or we might want to
        // use the prefetch decoder, compute information about the share of
        // long offsets, and the maximum nbAdditionalBits.
        if isLongOffset == LongOffset::IsLongOffset
            || (!usePrefetchDecoder && totalHistorySize > (1usize << 24) && nbSeq > 8)
        {
            // SAFETY: class C (construction). `dctx.OFTptr` is a table
            // `ZSTD_decodeSeqHeaders` just built (or the shared default, if
            // `nbSeq == 0`, in which case `ZSTD_getOffsetInfo` never reads
            // through it).
            let info = unsafe { ZSTD_getOffsetInfo(dctx.OFTptr, nbSeq) };
            if isLongOffset == LongOffset::IsLongOffset && info.maxNbAdditionalBits <= STREAM_ACCUMULATOR_MIN {
                isLongOffset = LongOffset::IsRegularOffset;
            }
            if !usePrefetchDecoder {
                let minShare = if MEM_64BITS { 7 } else { 20 };
                usePrefetchDecoder = info.longOffsetShare >= minShare;
            }
        }

        dctx.ddictIsCold = 0;

        if usePrefetchDecoder {
            // SAFETY: class B (boundary). As above.
            return unsafe {
                ZSTD_decompressSequencesLong(dctx, dst, dstCapacity, ip as *const c_void, srcSize, nbSeq, isLongOffset)
            };
        }

        // SAFETY: class B (boundary). As above.
        unsafe {
            if dctx.litBufferLocation == LitLocation::Split as u32 {
                ZSTD_decompressSequencesSplitLitBuffer(
                    dctx, dst, dstCapacity, ip as *const c_void, srcSize, nbSeq, isLongOffset,
                )
            } else {
                ZSTD_decompressSequences(dctx, dst, dstCapacity, ip as *const c_void, srcSize, nbSeq, isLongOffset)
            }
        }
    }
}

/// `ZSTD_checkContinuity()`.
///
/// # Safety
/// `dctx` must be a live [`ZstdDCtx`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_checkContinuity(dctx: *mut ZstdDCtx, dst: *const c_void, dstSize: usize) {
    // SAFETY: the caller guarantees `dctx` is live.
    let dctx = unsafe { &mut *dctx };
    if dst as usize != dctx.previousDstEnd as usize && dstSize > 0 {
        // not contiguous
        dctx.dictEnd = dctx.previousDstEnd;
        dctx.virtualStart = (dst as *const u8)
            .wrapping_sub((dctx.previousDstEnd as usize).wrapping_sub(dctx.prefixStart as usize))
            as *const c_void;
        dctx.prefixStart = dst;
        dctx.previousDstEnd = dst;
    }
}

/// `ZSTD_decompressBlock_deprecated()`.
///
/// # Safety
/// As [`ZSTD_decompressBlock_internal`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBlock_deprecated(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    // SAFETY: the caller guarantees `dctx` is live. Not held as `&mut`
    // across the calls below: both take the raw `dctx` and do their own
    // `&mut *dctx` reborrow, which would invalidate a parent `&mut`
    // reference under Stacked/Tree Borrows (found by adversarial review,
    // 2026-09-06 -- same shape as the earlier zdss_load fix).
    unsafe { (*dctx).isFrameDecompression = 0 };
    // SAFETY: as above.
    unsafe { ZSTD_checkContinuity(dctx, dst, dstCapacity) };
    // SAFETY: as above.
    let dSize =
        unsafe { ZSTD_decompressBlock_internal(dctx, dst, dstCapacity, src, srcSize, StreamingOperation::NotStreaming) };
    if ERR_isError(dSize) {
        return dSize;
    }
    // SAFETY: as above.
    unsafe { (*dctx).previousDstEnd = (dst as *const u8).wrapping_add(dSize) as *const c_void };
    dSize
}

/// `ZSTD_decompressBlock()`. Must just wrap
/// [`ZSTD_decompressBlock_deprecated`].
///
/// # Safety
/// As [`ZSTD_decompressBlock_internal`].
#[no_mangle]
pub unsafe extern "C" fn ZSTD_decompressBlock(
    dctx: *mut ZstdDCtx,
    dst: *mut c_void,
    dstCapacity: usize,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    // SAFETY: forwarded unchanged.
    unsafe { ZSTD_decompressBlock_deprecated(dctx, dst, dstCapacity, src, srcSize) }
}

/// `ZSTD_totalHistorySize()`.
fn ZSTD_totalHistorySize(op: *const u8, virtualStart: *const u8) -> usize {
    op as usize - virtualStart as usize
}
