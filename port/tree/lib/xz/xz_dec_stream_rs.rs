// SPDX-License-Identifier: 0BSD

//! .xz Stream decoder — the container layer of the XZ decompressor.
//!
//! Ported from `lib/xz/xz_dec_stream.c` (6.18.49), which carries
//! `Author: Lasse Collin <lasse.collin@tukaani.org>` and is 0BSD.
//!
//! This is the state machine that walks a `.xz` file: Stream Header, a chain
//! of Blocks, the Index, and the Stream Footer. It hands the Compressed Data
//! of each Block to `xz_dec_bcj_run()` (already Rust, in
//! `lib/xz/xz_dec_bcj_rs.rs`) or straight to `xz_dec_lzma2_run()` (still C).
//!
//! # Shape: four C entry thunks, plus the allocator
//!
//! **`xz_dec_run`, `xz_dec_reset`, `xz_dec_end` and `xz_dec_init` stay C.**
//! All four are `EXPORT_SYMBOL`'d in `lib/xz/xz_dec_syms.c`, and under
//! `CONFIG_GENDWARFKSYMS` the MODVERSIONS CRC is computed from the DWARF of
//! the *definition* — a Rust definition changes the CRC and breaks module
//! loading, which is GOALS.md §2 criterion 4. That is GOALS.md §1's first
//! exception, the mandatory entry thunk, and it is forced rather than chosen.
//! This is the `lib/bcd` shape, not the `lib/union_find` shape that
//! `xz_dec_bcj_rs.rs` was able to take.
//!
//! `xz_dec_init()` additionally **allocates** (`kmalloc`, pristine `:787`) and
//! `xz_dec_end()` **frees** (`kfree`, and `xz_dec_bcj_end(s)` which
//! `xz_private.h` defines as `kfree(s)`). `kmalloc` is a macro over a
//! `static inline` with no linkable symbol, so those bodies cannot move — the
//! same reasoning that kept `xz_dec_bcj_create()` in C. That is GOALS.md §1's
//! second exception.
//!
//! **The C never sees this layout.** As with the BCJ port, `struct xz_dec` is
//! defined here and nowhere else in the built kernel, so the two cannot drift.
//! `xz_dec_stream.c` becomes:
//!
//! ```c
//! /* lib/xz/xz_dec_stream_rs.rs */
//! size_t rust_xz_dec_size(void);
//! void rust_xz_dec_init(void *s, int mode,
//!                       struct xz_dec_bcj *bcj,      /* #ifdef XZ_DEC_BCJ */
//!                       struct xz_dec_lzma2 *lzma2);
//! enum xz_ret xz_dec_run(struct xz_dec *s, struct xz_buf *b);
//! void xz_dec_reset(struct xz_dec *s);
//! struct xz_dec_lzma2 *rust_xz_dec_lzma2(struct xz_dec *s);
//! struct xz_dec_bcj *rust_xz_dec_bcj(struct xz_dec *s);  /* #ifdef XZ_DEC_BCJ */
//!
//! enum xz_ret xz_dec_run(struct xz_dec *s, struct xz_buf *b)
//! {
//!         return xz_dec_run(s, b);
//! }
//!
//! void xz_dec_reset(struct xz_dec *s)
//! {
//!         xz_dec_reset(s);
//! }
//!
//! struct xz_dec *xz_dec_init(enum xz_mode mode, uint32_t dict_max)
//! {
//!         struct xz_dec_lzma2 *lzma2;
//! #ifdef XZ_DEC_BCJ
//!         struct xz_dec_bcj *bcj;
//! #endif
//!         void *s = kmalloc(rust_xz_dec_size(), GFP_KERNEL);
//!         if (s == NULL)
//!                 return NULL;
//! #ifdef XZ_DEC_BCJ
//!         bcj = xz_dec_bcj_create(DEC_IS_SINGLE(mode));
//!         if (bcj == NULL)
//!                 goto error_bcj;
//! #endif
//!         lzma2 = xz_dec_lzma2_create(mode, dict_max);
//!         if (lzma2 == NULL)
//!                 goto error_lzma2;
//!
//!         rust_xz_dec_init(s, mode, bcj, lzma2);   /* also does the reset */
//!         return s;
//! ...
//! }
//!
//! void xz_dec_end(struct xz_dec *s)
//! {
//!         if (s != NULL) {
//!                 xz_dec_lzma2_end(rust_xz_dec_lzma2(s));
//! #ifdef XZ_DEC_BCJ
//!                 xz_dec_bcj_end(rust_xz_dec_bcj(s));
//! #endif
//!                 kfree(s);
//!         }
//! }
//! ```
//!
//! The two accessors exist for exactly one reason: `xz_dec_end()` has to reach
//! `s->lzma2` and `s->bcj` to free them, and the C is no longer allowed to
//! know where they live. The C's own ordering — `s->mode = mode` before the
//! sub-allocations, `xz_dec_reset(s)` after them — is not observable, because
//! nothing between the two reads any field of `*s`, so
//! [`rust_xz_dec_init`] does the whole thing in one call at the end.
//!
//! # `XZ_DEC_ANY_CHECK` is preserved, gated, and unreachable in this kernel
//!
//! The C has six `#ifdef XZ_DEC_ANY_CHECK` sites. **No kernel build can define
//! that macro**: `xz_private.h` maps `CONFIG_XZ_DEC_*` to `XZ_DEC_*` for the
//! seven BCJ filters and MicroLZMA and nothing else, there is no
//! `XZ_DEC_ANY_CHECK` stanza in `lib/xz/Kconfig`, and `include/linux/xz.h:63`
//! says so outright — "this return value is used only if XZ_DEC_ANY_CHECK was
//! defined at build time, **which is not used in the kernel**". It exists for
//! XZ Embedded's userspace builds, which set it from `xz_config.h`.
//!
//! That is the same situation `bcj_ia64()` was in, and the resolution here is
//! deliberately the *opposite* one: **it is kept**, behind
//! `#[cfg(XZ_DEC_ANY_CHECK)]`. Deleting reachable-nowhere code is Adam's call,
//! it was his call for IA64, and it has not been made for this. Everything the
//! arm needs — [`CHECK_SIZES`], `XZ_UNSUPPORTED_CHECK`, [`check_skip`] — is
//! gated on the same symbol, which is floor.md's RAISE 1 obligation: a
//! constant defined ungated but used only under a `#[cfg]` is
//! `constant is never used`, and `CONFIG_WERROR=y` makes that a build failure.
//!
//! **The cfg is spelled `XZ_DEC_ANY_CHECK`, not `CONFIG_XZ_DEC_ANY_CHECK`**,
//! because inventing a `CONFIG_` name for a symbol Kconfig does not have would
//! lie to `rig/config-fidelity.sh`. The cost is that `port/test/xz/run.sh`'s
//! subset sweep — which finds its symbols by grepping `CONFIG_[A-Z0-9_]+` out
//! of `#[cfg(...)]` lines — will not cover it, so the arm is compiled by
//! nothing unless the harness is told to build it both ways. **That is a real
//! coverage hole and it is recorded here rather than papered over.**
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **The two hashes are compared field by field, and hashed from an
//!    explicit 24-byte image, instead of through a pointer to the struct.**
//!    The C does `xz_crc32((const uint8_t *)&s->block.hash, sizeof(...), ...)`
//!    and `memeq(&s->block.hash, &s->index.hash, sizeof(...))` — both of which
//!    include `struct xz_dec_hash`'s four bytes of tail padding. Those bytes
//!    are always zero, because `xz_dec_reset()` `memzero`s the whole enclosing
//!    `block`/`index` structs and nothing ever writes them again. [`hash_crc32`]
//!    rebuilds that image explicitly with the padding written as zero, so the
//!    CRC input is SELF-CONSISTENT: both hashes go through [`hash_crc32`] and
//!    are only ever compared with each other, so the number never leaves this
//!    file. It is NOT necessarily byte-for-byte the C's — the compile-time
//!    assert checks *Rust's* `size_of::<XzDecHash>() == 24`, and on an ABI
//!    that gives `u64` 4-byte alignment (i386-style) C's `sizeof` is 20 while
//!    `#[repr(C)]` Rust still gives 24. The assert would pass and the two
//!    would compute different numbers. Unobservable, and corrected here on
//!    2026-09-04 after an adversarial review caught the claim overreaching:
//!    a wrong comment is worse than a missing one. Reading a
//!    struct's padding bytes is UB in Rust; this reaches the same number
//!    without doing that, and drops two `unsafe` blocks.
//!
//!    GOALS.md §5's three questions are all "no": the hash never leaves this
//!    file (it is only ever compared against the other hash), so no format, no
//!    layout and no caller can observe how it was computed.
//!
//! 2. **`rust_xz_dec_init` writes every field.** The C's `xz_dec_init()` sets
//!    only `s->mode`, `s->bcj`, `s->lzma2` and whatever `xz_dec_reset()`
//!    touches; `check_type`, `vli`, `in_start`, `out_start`, `block_header`
//!    and `temp.buf` are left uninitialised until something writes them.
//!    Reading uninitialised memory is UB in Rust. Nothing outside can observe
//!    the difference on any path a caller that stops at the first non-`XZ_OK`
//!    return can reach — see divergence 4 for the paths it cannot.
//!
//! 3. **Bounds checks are real.** The C indexes `s->temp.buf` and `b->in` with
//!    offsets it has reasoned safe; here they are slices. Every index is
//!    transcribed one for one and only the checking is added, so a
//!    mistranscribed bound is a panic at the wrong access rather than a read
//!    past the caller's buffer. None of them fires on a well-formed call —
//!    including on corrupt input, which is the whole job of this file.
//!
//! 4. **Places where the C has undefined behaviour and this does not.**
//!    All are reachable only by calling `xz_dec_run()` *again* after it has
//!    returned an error, which `include/linux/xz.h` neither permits nor
//!    forbids and which no in-tree caller does. Neither is "fixed" — the
//!    arithmetic is transcribed exactly — but Rust's semantics make the shift
//!    defined and turn the subtractions into panics instead of
//!    `SIZE_MAX`-length reads.
//!
//!    - [`dec_vli`]: `s->pos` is left at 63 by the error return and never
//!      reset, so a re-entry shifts a `u64` by 70. UB in C; `wrapping_shl`
//!      here.
//!    - [`dec_block_header`]: `s->temp.size -= 4` underflows, handing
//!      `xz_crc32()` a near-`SIZE_MAX` length. **Demonstrated, not argued:**
//!      an adversarial review on 2026-09-04 built the input — a valid
//!      12-byte Stream Header with Check=NONE, `in[12] = 255`, then 400 KB of
//!      `0xAB` — and on the 256th call the pristine C **SIGSEGVs** while this
//!      port aborts on `attempt to subtract with overflow`.
//!    - **THREE MORE ON THE SAME PATH**, added after that review pointed out
//!      this list was incomplete: `s.temp.size - s.temp.pos` in
//!      [`dec_block_header`] (three sites, C:500/517/529) underflows once
//!      `temp.size` reaches 0 with `temp.pos == 2`. The C computes `SIZE_MAX`
//!      and sails past its own `< 2` test. In the constructed input above the
//!      `-= 4` fires first and no input was found where one of these fires
//!      first, but GOALS.md §5 says a divergence record is not optional and
//!      an incomplete enumeration is a defect in its own right.
//!
//! # What is NOT changed
//!
//! The state machine is transcribed case for case, including every early
//! return, the post-increments that advance `b->in_pos` on the byte that
//! *failed* a comparison, and `dec_main()`'s fallthrough chain — each C
//! `fallthrough` sets `s->sequence` to exactly the case it falls into, so
//! `continue`-ing the dispatch loop is the same program.
//!
//! Replaces: lib/xz/xz_dec_stream.c


use core::ffi::{c_int, c_uchar, c_void};

// ---------------------------------------------------------------------------
// The pieces of the XZ ABI this file touches. `struct xz_buf` is the caller's,
// so GOALS.md §5's layout rule applies: it mirrors include/linux/xz.h exactly.
// `struct xz_dec` is ours alone -- include/linux/xz.h only forward-declares it
// and nothing outside this file has ever seen a field of it.
// ---------------------------------------------------------------------------

/// `struct xz_buf`, `include/linux/xz.h`. Owned by the caller of
/// `xz_dec_run()`; only `out[out_pos..]`, `in_pos` and `out_pos` may be
/// modified.
#[repr(C)]
pub struct XzBuf {
    /// Beginning of the input buffer. May be null if `in_pos == in_size`.
    pub input: *const c_uchar,
    /// Current position in the input buffer.
    pub in_pos: usize,
    /// Size of the input buffer.
    pub in_size: usize,
    /// Beginning of the output buffer. May be null if `out_pos == out_size`.
    pub out: *mut c_uchar,
    /// Current position in the output buffer.
    pub out_pos: usize,
    /// Size of the output buffer.
    pub out_size: usize,
}

/// `struct xz_dec_lzma2`, opaque here exactly as it is in `xz_private.h`.
pub enum XzDecLzma2 {}

/// `struct xz_dec_bcj`, opaque here. Its layout lives in
/// `lib/xz/xz_dec_bcj_rs.rs` and this file only ever holds the pointer, which
/// is what `xz_dec_stream.c` did too.
#[cfg(CONFIG_XZ_DEC_BCJ)]
pub enum XzDecBcj {}

// `enum xz_ret`, include/linux/xz.h. Carried as c_int rather than as a
// `#[repr(C)] enum` on purpose: xz_dec_lzma2_run() is C, and a value outside
// the enumerators would be instant UB in a Rust enum while it is merely a
// number here. Only the codes this file actually produces or inspects are
// declared -- floor.md RAISE 1: an unused constant is a build failure under
// CONFIG_WERROR=y, so XZ_MEM_ERROR and XZ_MEMLIMIT_ERROR (raised by LZMA2,
// never by this file) are deliberately absent.
/// `XZ_OK`.
const XZ_OK: c_int = 0;
/// `XZ_STREAM_END`.
const XZ_STREAM_END: c_int = 1;
/// `XZ_UNSUPPORTED_CHECK`. Only ever returned from the `XZ_DEC_ANY_CHECK`
/// arm of [`dec_stream_header`].
#[cfg(XZ_DEC_ANY_CHECK)]
const XZ_UNSUPPORTED_CHECK: c_int = 2;
/// `XZ_FORMAT_ERROR`.
const XZ_FORMAT_ERROR: c_int = 5;
/// `XZ_OPTIONS_ERROR`.
const XZ_OPTIONS_ERROR: c_int = 6;
/// `XZ_DATA_ERROR`.
const XZ_DATA_ERROR: c_int = 7;
/// `XZ_BUF_ERROR`.
const XZ_BUF_ERROR: c_int = 8;

/// `XZ_SINGLE`, the first enumerator of `enum xz_mode`. `DEC_IS_SINGLE(mode)`
/// in `xz_private.h` expands to `(mode) == XZ_SINGLE` in every kernel build,
/// because none of `XZ_DEC_SINGLE`/`PREALLOC`/`DYNALLOC` is defined and the
/// header therefore defines all three.
const XZ_SINGLE: c_int = 0;

/// `XZ_CHECK_CRC32`, `lib/xz/xz_stream.h`. The only integrity check this
/// decoder verifies.
const XZ_CHECK_CRC32: u32 = 1;

/// `XZ_CHECK_MAX`, the largest Check ID the .xz format defines.
const XZ_CHECK_MAX: u8 = 15;

// ---------------------------------------------------------------------------
// lib/xz/xz_stream.h
// ---------------------------------------------------------------------------

/// `vli_type`. A variable-length integer holds a 63-bit unsigned value or the
/// special "unknown" marker.
type VliType = u64;

/// `VLI_UNKNOWN` — Compressed/Uncompressed Size is not present in the Block
/// Header.
const VLI_UNKNOWN: VliType = VliType::MAX;

/// `VLI_BYTES_MAX`, the maximum encoded size of a VLI:
/// `sizeof(vli_type) * 8 / 7`, which is `64 / 7 == 9`.
const VLI_BYTES_MAX: u32 = 9;

/// `STREAM_HEADER_SIZE`.
const STREAM_HEADER_SIZE: usize = 12;

/// `HEADER_MAGIC`. The C compares `HEADER_MAGIC_SIZE == 6` bytes of the string
/// literal `"\3757zXZ"`, which is five characters plus its terminating NUL.
const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// `HEADER_MAGIC_SIZE`.
const HEADER_MAGIC_SIZE: usize = 6;

/// `FOOTER_MAGIC`, `FOOTER_MAGIC_SIZE == 2`.
const FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];

/// Sizes of the Check field for each of the sixteen Check IDs.
///
/// Only the `XZ_DEC_ANY_CHECK` build reads this; without it the decoder
/// accepts nothing above `XZ_CHECK_CRC32` and never has to skip a check it
/// does not understand.
#[cfg(XZ_DEC_ANY_CHECK)]
const CHECK_SIZES: [u8; 16] = [
    0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64,
];

// ---------------------------------------------------------------------------
// The C this file calls.
// ---------------------------------------------------------------------------

extern "C" {
    /// `lib/xz/xz_dec_lzma2.c`. Decodes a raw LZMA2 stream from `b->in` to
    /// `b->out`.
    fn xz_dec_lzma2_run(s: *mut XzDecLzma2, b: *mut XzBuf) -> c_int;

    /// `lib/xz/xz_dec_lzma2.c`. Decodes the one-byte LZMA2 Filter Properties
    /// and resets the decoder.
    fn xz_dec_lzma2_reset(s: *mut XzDecLzma2, props: u8) -> c_int;

    /// `lib/crc/crc32-main.c`. `xz_stream.h` defines `xz_crc32(buf, size, crc)`
    /// as `~crc32_le(~(uint32_t)(crc), buf, size)` for every `__KERNEL__`
    /// build that does not set `XZ_INTERNAL_CRC32` — that is, for the module,
    /// though not for the pre-boot decompressor, which never reaches this
    /// file. `crc32_le()` is a real out-of-line `EXPORT_SYMBOL`, not one of
    /// the `static inline` shims, so it is linkable from here.
    fn crc32_le(crc: u32, p: *const c_void, len: usize) -> u32;

    /// `lib/xz/xz_dec_bcj_rs.rs`. Already Rust, but reached through its C ABI
    /// because each ported file is its own crate in the kernel build.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    fn xz_dec_bcj_run(s: *mut XzDecBcj, lzma2: *mut XzDecLzma2, b: *mut XzBuf) -> c_int;

    /// `lib/xz/xz_dec_bcj_rs.rs`. Decodes the BCJ Filter ID.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    fn xz_dec_bcj_reset(s: *mut XzDecBcj, id: u8) -> c_int;
}

/// `xz_crc32()`, `lib/xz/xz_stream.h`.
fn xz_crc32(buf: &[u8], crc: u32) -> u32 {
    // SAFETY: `crc32_le` reads exactly `buf.len()` bytes from `buf.as_ptr()`
    // and writes nothing. For an empty slice the pointer is dangling but
    // well-aligned and the length is zero, which `crc32_le` never
    // dereferences.
    let crc = unsafe { crc32_le(!crc, buf.as_ptr().cast::<c_void>(), buf.len()) };
    !crc
}

/// `get_le32()`, `lib/xz/xz_private.h`.
///
/// The C is `le32_to_cpup((const uint32_t *)(p))`, an *aligned* load — which
/// is why `struct xz_dec`'s comment insists `temp.buf[]` be four-byte
/// aligned. This byte-wise form has no alignment requirement, is correct on
/// every target, and lowers to the same wide load wherever one exists.
fn get_le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

// ---------------------------------------------------------------------------
// struct xz_dec. Ours alone; the C sees only a pointer.
// ---------------------------------------------------------------------------

/// Position in [`dec_main`]. The C's anonymous enum in `struct xz_dec`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Sequence {
    /// `SEQ_STREAM_HEADER`.
    StreamHeader = 0,
    /// `SEQ_BLOCK_START`.
    BlockStart,
    /// `SEQ_BLOCK_HEADER`.
    BlockHeader,
    /// `SEQ_BLOCK_UNCOMPRESS`.
    BlockUncompress,
    /// `SEQ_BLOCK_PADDING`.
    BlockPadding,
    /// `SEQ_BLOCK_CHECK`.
    BlockCheck,
    /// `SEQ_INDEX`.
    Index,
    /// `SEQ_INDEX_PADDING`.
    IndexPadding,
    /// `SEQ_INDEX_CRC32`.
    IndexCrc32,
    /// `SEQ_STREAM_FOOTER`.
    StreamFooter,
}

/// Position in [`dec_index`]. The C's anonymous enum inside `s->index`.
///
/// `SEQ_INDEX_COUNT == 0` matters: `xz_dec_reset()` `memzero`s the whole
/// `index` struct, and this is the state that zero has to mean.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum IndexSequence {
    /// `SEQ_INDEX_COUNT`.
    Count = 0,
    /// `SEQ_INDEX_UNPADDED`.
    Unpadded,
    /// `SEQ_INDEX_UNCOMPRESSED`.
    Uncompressed,
}

/// `struct xz_dec_hash` — the hash used to validate the Index field.
///
/// The C hashes and compares this **including its four bytes of tail
/// padding**; see divergence 1 in the module docs for how that is reproduced
/// without reading padding bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct XzDecHash {
    /// Running sum of the Unpadded Sizes.
    unpadded: VliType,
    /// Running sum of the Uncompressed Sizes.
    uncompressed: VliType,
    /// CRC32 folded over this struct after every update.
    crc32: u32,
}

impl XzDecHash {
    /// What `memzero()` leaves behind.
    const ZERO: Self = Self {
        unpadded: 0,
        uncompressed: 0,
        crc32: 0,
    };
}

/// Number of bytes the C hashes and compares per `struct xz_dec_hash`:
/// `sizeof(vli_type) * 2 + sizeof(uint32_t)` rounded up to the struct's
/// alignment. If a target ever makes this untrue the assert below fires and
/// [`hash_crc32`] needs revisiting rather than silently computing a different
/// number than the C would.
const HASH_IMAGE_SIZE: usize = 24;
const _: () = assert!(core::mem::size_of::<XzDecHash>() == HASH_IMAGE_SIZE);

/// Information stored in the Block Header. The C's `s->block_header`.
#[repr(C)]
struct BlockHeader {
    /// Value of the Compressed Size field, or [`VLI_UNKNOWN`] if absent.
    compressed: VliType,
    /// Value of the Uncompressed Size field, or [`VLI_UNKNOWN`] if absent.
    uncompressed: VliType,
    /// Size of the Block Header field in bytes.
    size: u32,
}

/// Information collected while decoding Blocks. The C's `s->block`.
#[repr(C)]
struct Block {
    /// Observed compressed size of the current Block.
    compressed: VliType,
    /// Observed uncompressed size of the current Block.
    uncompressed: VliType,
    /// Number of Blocks decoded so far.
    count: VliType,
    /// Hash calculated from the Block sizes.
    hash: XzDecHash,
}

impl Block {
    /// What `memzero(&s->block, sizeof(s->block))` leaves behind.
    const ZERO: Self = Self {
        compressed: 0,
        uncompressed: 0,
        count: 0,
        hash: XzDecHash::ZERO,
    };
}

/// Variables needed when verifying the Index field. The C's `s->index`.
#[repr(C)]
struct Index {
    /// Position in [`dec_index`].
    sequence: IndexSequence,
    /// Size of the Index in bytes.
    size: VliType,
    /// Number of Records; matches `block.count` in valid files.
    count: VliType,
    /// Hash calculated from the Records; matches `block.hash` in valid files.
    hash: XzDecHash,
}

impl Index {
    /// What `memzero(&s->index, sizeof(s->index))` leaves behind.
    const ZERO: Self = Self {
        sequence: IndexSequence::Count,
        size: 0,
        count: 0,
        hash: XzDecHash::ZERO,
    };
}

/// Size of `s->temp.buf`. The Block Header is the biggest thing staged
/// through it, and its maximum is `(255 + 1) * 4` bytes.
const TEMP_BUF_SIZE: usize = 1024;

/// Temporary buffer holding Stream Header, Block Header or Stream Footer while
/// it is assembled out of however little input the caller supplied.
#[repr(C)]
struct Temp {
    /// How much of `buf` has been filled this round.
    pos: usize,
    /// How much [`fill_temp`] is trying to collect.
    size: usize,
    /// The staging bytes. The C requires four-byte alignment here for
    /// `get_le32()`'s sake; [`get_le32`] in this file is byte-wise, so the
    /// requirement is gone and only the size matters.
    buf: [u8; TEMP_BUF_SIZE],
}

/// `struct xz_dec`. Private to `xz_dec_stream.c` in the C and private to this
/// crate here; `include/linux/xz.h` only forward-declares the tag and every
/// caller in the kernel holds nothing but the pointer.
#[repr(C)]
pub struct XzDec {
    /// Position in [`dec_main`].
    sequence: Sequence,
    /// Position within a variable-length integer or a Check field.
    pos: u32,
    /// Variable-length integer decoded by [`dec_vli`].
    vli: VliType,
    /// Saved `b->in_pos`.
    in_start: usize,
    /// Saved `b->out_pos`.
    out_start: usize,
    /// CRC32 value being accumulated for a Block or for the Index.
    crc32: u32,
    /// Type of the integrity check calculated from the uncompressed data.
    ///
    /// `enum xz_check` in the C, but the C assigns it a raw header byte in
    /// `dec_stream_header()`, so it routinely holds values that are not
    /// enumerators. Carried as a plain integer for the same reason
    /// `enum xz_ret` is.
    check_type: u32,
    /// Operation mode, one of `enum xz_mode`.
    mode: c_int,
    /// True if the next call to `xz_dec_run()` is allowed to return
    /// `XZ_BUF_ERROR`.
    allow_buf_error: bool,
    /// Information stored in the Block Header.
    block_header: BlockHeader,
    /// Information collected when decoding Blocks.
    block: Block,
    /// Variables needed when verifying the Index field.
    index: Index,
    /// Staging buffer for the fixed-size header fields.
    temp: Temp,
    /// The LZMA2 decoder, allocated by `xz_dec_init()` in C.
    lzma2: *mut XzDecLzma2,
    /// The BCJ decoder, allocated by `xz_dec_init()` in C.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    bcj: *mut XzDecBcj,
    /// True while the current Block's filter chain starts with a BCJ filter.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    bcj_active: bool,
}

// ---------------------------------------------------------------------------
// The caller's struct xz_buf, reached through a raw pointer.
//
// Everything below goes through `Buf` rather than holding a `&mut XzBuf`,
// because the same pointer is handed to xz_dec_lzma2_run() and
// xz_dec_bcj_run(), which write through it. A long-lived `&mut` derived from
// it would be invalidated by those calls.
// ---------------------------------------------------------------------------

/// A live `struct xz_buf` belonging to the caller of `xz_dec_run()`.
#[derive(Clone, Copy)]
struct Buf(*mut XzBuf);

impl Buf {
    /// Wrap the caller's pointer.
    ///
    /// # Safety
    ///
    /// `b` must point at a live `struct xz_buf` for the whole lifetime of the
    /// returned value, and neither `b->in` nor `b->out` may point into `*b`
    /// itself — [`Buf::input`] holds a shared slice over `b->in` across a raw
    /// write to `b->in_pos`. No caller does this and `xz_dec_run`'s contract
    /// did not previously say so; an adversarial review found the gap on
    /// 2026-09-04. `in[..in_size]` must be readable, `out[..out_size]`
    /// writable, and neither may overlap the `XzDec` being driven. This is the
    /// contract `xz_dec_run()`'s callers already uphold.
    const unsafe fn new(b: *mut XzBuf) -> Self {
        Self(b)
    }

    /// The raw pointer, for handing straight back to the C.
    const fn as_ptr(self) -> *mut XzBuf {
        self.0
    }

    /// `b->in[0 .. b->in_size]`.
    ///
    /// The whole input buffer, not the unconsumed tail: the C indexes it with
    /// absolute `b->in_pos`, and so does everything here.
    fn input(&self) -> &[u8] {
        // SAFETY: the `Buf` invariant says the struct is live and that
        // `in[..in_size]` is readable. `in` is allowed to be null when
        // `in_size == 0` (include/linux/xz.h), and `from_raw_parts` may not be
        // given a null pointer even for a zero length, hence the early return.
        // The slice borrows the caller's input buffer, which `Buf::new`'s
        // contract requires to be a different allocation from `*self.0` --
        // i.e. `b->in` may not point into the `struct xz_buf` itself. So it
        // stays valid across the writes below.
        unsafe {
            let b = &*self.0;
            if b.in_size == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(b.input, b.in_size)
            }
        }
    }

    /// `b->out[start .. end]`, for CRC32-ing what LZMA2 just produced.
    fn out_range(&self, start: usize, end: usize) -> &[u8] {
        // SAFETY: as `input()`, on the output side. Callers pass
        // `start <= end <= out_size`, both read out of the same struct, so the
        // range is inside the caller's buffer.
        unsafe {
            let b = &*self.0;
            if end <= start {
                &[]
            } else {
                core::slice::from_raw_parts(b.out.add(start).cast_const(), end - start)
            }
        }
    }

    /// `b->in_pos`.
    fn in_pos(&self) -> usize {
        // SAFETY: the `Buf` invariant. Reads one `usize` field.
        unsafe { (*self.0).in_pos }
    }

    /// `b->in_pos = pos`.
    fn set_in_pos(&self, pos: usize) {
        // SAFETY: the `Buf` invariant. `in_pos` is one of the three things
        // include/linux/xz.h permits the XZ code to modify.
        unsafe { (*self.0).in_pos = pos };
    }

    /// `b->out_pos`.
    fn out_pos(&self) -> usize {
        // SAFETY: the `Buf` invariant. Reads one `usize` field.
        unsafe { (*self.0).out_pos }
    }

    /// `b->out_pos = pos`.
    fn set_out_pos(&self, pos: usize) {
        // SAFETY: the `Buf` invariant. `out_pos` is permitted to be modified.
        unsafe { (*self.0).out_pos = pos };
    }
}

// ---------------------------------------------------------------------------
// The decoder.
// ---------------------------------------------------------------------------

/// `xz_crc32((const uint8_t *)&hash, sizeof(hash), hash.crc32)`.
///
/// The seed is the hash's *own* current `crc32`, and the input includes that
/// field's pre-update value — the C folds the struct over itself. See
/// divergence 1 in the module docs for why the image is rebuilt explicitly
/// instead of being read out of the struct.
fn hash_crc32(h: &XzDecHash) -> u32 {
    let mut image = [0u8; HASH_IMAGE_SIZE];
    image[0..8].copy_from_slice(&h.unpadded.to_ne_bytes());
    image[8..16].copy_from_slice(&h.uncompressed.to_ne_bytes());
    image[16..20].copy_from_slice(&h.crc32.to_ne_bytes());
    // image[20..24] is `struct xz_dec_hash`'s tail padding. It is zero in the
    // C too: xz_dec_reset() memzero()s the enclosing `block`/`index` structs
    // and nothing writes it afterwards.
    xz_crc32(&image, h.crc32)
}

/// Fill `s->temp` by copying data starting from `b->in[b->in_pos]`.
///
/// The caller must have set `s->temp.size` to say how much to collect. Returns
/// true once `s->temp.pos` has reached it, and resets `s->temp.pos` to zero on
/// the way out so the buffer can be read from the start.
fn fill_temp(s: &mut XzDec, b: Buf) -> bool {
    let in_pos = b.in_pos();
    let input = b.input();
    // `in_pos <= input.len()` and `s.temp.pos <= s.temp.size` are maintained
    // by every caller (each sets `temp.size`/resets `temp.pos` together
    // before calling this), unlike the `dec_block_header()` subtractions in
    // divergence 4 -- wrapping_* is faithful to the C's plain arithmetic on
    // these unsigned types regardless, per the CONFIG_RUST_OVERFLOW_CHECKS
    // sweep, 2026-09-06.
    let copy_size = core::cmp::min(
        input.len().wrapping_sub(in_pos),
        s.temp.size.wrapping_sub(s.temp.pos),
    );

    s.temp.buf[s.temp.pos..s.temp.pos.wrapping_add(copy_size)]
        .copy_from_slice(&input[in_pos..in_pos.wrapping_add(copy_size)]);
    b.set_in_pos(in_pos + copy_size);
    s.temp.pos += copy_size;

    if s.temp.pos == s.temp.size {
        s.temp.pos = 0;
        return true;
    }

    false
}

/// Decode a variable-length integer (little-endian base-128 encoding).
///
/// Split out of `struct xz_dec` into four `&mut`s because the C passes `s`
/// *and* `s->temp.buf`/`&s->temp.pos` to the same call, which Rust will not
/// let a single `&mut XzDec` do. The four places are disjoint fields, so the
/// borrows are exactly the C's aliasing.
///
/// # The shift the C leaves undefined
///
/// On the normal path `*pos` runs 0, 7, … 56 and then the `== 7 *
/// VLI_BYTES_MAX` test returns `XZ_DATA_ERROR` at 63, so the C's
/// `<< s->pos` never shifts a `uint64_t` by more than 56. **But that error
/// return leaves `s->pos` at 63**, and neither `dec_index()` nor
/// `dec_block_header()` resets it. A caller that calls `xz_dec_run()` again
/// after `XZ_DATA_ERROR` re-enters here with `*pos == 63`, and the second
/// iteration shifts by 70 — undefined behaviour in C, and a panic in Rust,
/// because the kernel sets `CONFIG_RUST_OVERFLOW_CHECKS=y`.
///
/// `wrapping_shl` is used instead: it masks the shift to its low six bits,
/// which is exactly what the C compiles to on x86-64 (`shlq %cl`) and what
/// this file's differential oracle therefore does. It cannot panic and it
/// cannot be UB. Nothing on a path a well-behaved caller reaches is affected —
/// there the shift is 0..=56 and the mask is a no-op.
fn dec_vli(pos: &mut u32, vli: &mut VliType, input: &[u8], in_pos: &mut usize) -> c_int {
    if *pos == 0 {
        *vli = 0;
    }

    while *in_pos < input.len() {
        let byte = input[*in_pos];
        *in_pos += 1;

        *vli |= VliType::from(byte & 0x7F).wrapping_shl(*pos);

        if byte & 0x80 == 0 {
            // Don't allow non-minimal encodings.
            if byte == 0 && *pos != 0 {
                return XZ_DATA_ERROR;
            }

            *pos = 0;
            return XZ_STREAM_END;
        }

        // The C's `s->pos += 7` on a uint32_t. Wrapping is spelled out for the
        // same reason as the shift above: past the error return described in
        // this function's docs `*pos` is no longer bounded by 63, and a
        // sufficiently large single-call input buffer could otherwise climb it
        // to `u32::MAX` and panic. On every reachable path it is 0..=63.
        *pos = pos.wrapping_add(7);
        if *pos == 7 * VLI_BYTES_MAX {
            return XZ_DATA_ERROR;
        }
    }

    XZ_OK
}

/// Run the Block's filter chain for one call's worth of data.
///
/// The C spells this as an `#ifdef`'d `if`/`else` around the two calls; it is
/// a function here so that the `CONFIG_XZ_DEC_BCJ=n` build has nothing left
/// referring to `s->bcj`.
fn run_filters(s: &XzDec, b: Buf) -> c_int {
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    if s.bcj_active {
        // SAFETY: `s.bcj` came from `xz_dec_bcj_create()` in `xz_dec_init()`
        // and has been reset by `xz_dec_bcj_reset()` in `dec_block_header()`,
        // which is the only path that sets `bcj_active`. `s.lzma2` and `b` are
        // live per the `XzDec` and `Buf` contracts, and neither overlaps `*s`.
        return unsafe { xz_dec_bcj_run(s.bcj, s.lzma2, b.as_ptr()) };
    }

    // SAFETY: `s.lzma2` came from `xz_dec_lzma2_create()` in `xz_dec_init()`
    // and `b` is live per the `Buf` contract; neither overlaps `*s`.
    unsafe { xz_dec_lzma2_run(s.lzma2, b.as_ptr()) }
}

/// Decode the Compressed Data field from a Block.
///
/// Updates and validates the observed compressed and uncompressed sizes so
/// that they do not exceed the values possibly stored in the Block Header, and
/// updates the CRC32 if Stream Header said one is present. Once decoding
/// finishes, validates that the observed sizes match the stored ones and
/// updates the hash and Block count that later validate the Index.
fn dec_block(s: &mut XzDec, b: Buf) -> c_int {
    s.in_start = b.in_pos();
    s.out_start = b.out_pos();

    let ret = run_filters(s, b);

    // Byte counts of data this call actually moved, so they are bounded by
    // real I/O and cannot overflow a u64. The C's own comment says the
    // validation below "assumes that no integer overflow occurs, since
    // vli_type is normally uint64_t" -- wrapping_* is faithful to that
    // unsigned arithmetic regardless, per the CONFIG_RUST_OVERFLOW_CHECKS
    // sweep, 2026-09-06.
    s.block.compressed = s
        .block
        .compressed
        .wrapping_add((b.in_pos().wrapping_sub(s.in_start)) as VliType);
    s.block.uncompressed = s
        .block
        .uncompressed
        .wrapping_add((b.out_pos().wrapping_sub(s.out_start)) as VliType);

    // There is no need to separately check for VLI_UNKNOWN, since the observed
    // sizes are always smaller than VLI_UNKNOWN.
    if s.block.compressed > s.block_header.compressed
        || s.block.uncompressed > s.block_header.uncompressed
    {
        return XZ_DATA_ERROR;
    }

    if s.check_type == XZ_CHECK_CRC32 {
        s.crc32 = xz_crc32(b.out_range(s.out_start, b.out_pos()), s.crc32);
    }

    if ret == XZ_STREAM_END {
        if s.block_header.compressed != VLI_UNKNOWN
            && s.block_header.compressed != s.block.compressed
        {
            return XZ_DATA_ERROR;
        }

        if s.block_header.uncompressed != VLI_UNKNOWN
            && s.block_header.uncompressed != s.block.uncompressed
        {
            return XZ_DATA_ERROR;
        }

        // Unsigned throughout in the C; wrapping_* is faithful to it
        // regardless of whether these hash accumulators are ever provably
        // bounded, per the CONFIG_RUST_OVERFLOW_CHECKS sweep, 2026-09-06.
        s.block.hash.unpadded = s
            .block
            .hash
            .unpadded
            .wrapping_add(VliType::from(s.block_header.size).wrapping_add(s.block.compressed));

        #[cfg(XZ_DEC_ANY_CHECK)]
        {
            s.block.hash.unpadded = s
                .block
                .hash
                .unpadded
                .wrapping_add(VliType::from(CHECK_SIZES[s.check_type as usize]));
        }
        #[cfg(not(XZ_DEC_ANY_CHECK))]
        if s.check_type == XZ_CHECK_CRC32 {
            s.block.hash.unpadded = s.block.hash.unpadded.wrapping_add(4);
        }

        s.block.hash.uncompressed = s.block.hash.uncompressed.wrapping_add(s.block.uncompressed);
        s.block.hash.crc32 = hash_crc32(&s.block.hash);

        s.block.count = s.block.count.wrapping_add(1);
    }

    ret
}

/// Update the Index size and the CRC32 value.
fn index_update(s: &mut XzDec, b: Buf) {
    // `in_start <= in_pos` is a `dec_main`/`dec_index` invariant the C also
    // relies on unchecked; wrapping_* is faithful to the C's plain unsigned
    // arithmetic regardless, per the CONFIG_RUST_OVERFLOW_CHECKS sweep,
    // 2026-09-06.
    let in_used = b.in_pos().wrapping_sub(s.in_start);
    s.index.size = s.index.size.wrapping_add(in_used as VliType);
    s.crc32 = xz_crc32(
        &b.input()[s.in_start..s.in_start.wrapping_add(in_used)],
        s.crc32,
    );
}

/// Decode the Number of Records, Unpadded Size, and Uncompressed Size fields
/// from the Index field. Index Padding and CRC32 are not decoded here.
///
/// Returns `XZ_OK` (more input needed), `XZ_STREAM_END` (everything
/// successfully decoded), or `XZ_DATA_ERROR` (input is corrupt).
fn dec_index(s: &mut XzDec, b: Buf) -> c_int {
    // The C is a do/while, so the body always runs once even when
    // `s->index.count` is already zero.
    loop {
        let mut in_pos = b.in_pos();
        let ret = dec_vli(&mut s.pos, &mut s.vli, b.input(), &mut in_pos);
        b.set_in_pos(in_pos);
        if ret != XZ_STREAM_END {
            index_update(s, b);
            return ret;
        }

        match s.index.sequence {
            IndexSequence::Count => {
                s.index.count = s.vli;

                // Validate that the Number of Records field indicates the same
                // number of Records as there were Blocks in the Stream.
                if s.index.count != s.block.count {
                    return XZ_DATA_ERROR;
                }

                s.index.sequence = IndexSequence::Unpadded;
            }

            IndexSequence::Unpadded => {
                // `s.vli` is straight out of the file and reaches VLI_MAX
                // (2^63 - 1), so two Records are enough to wrap this. The C
                // wraps too, and the wrapped sum then fails the hash
                // comparison in SEQ_INDEX_PADDING, which is the intended error
                // path for a corrupt Index. A plain `+` would panic there
                // instead, under CONFIG_RUST_OVERFLOW_CHECKS=y.
                s.index.hash.unpadded = s.index.hash.unpadded.wrapping_add(s.vli);
                s.index.sequence = IndexSequence::Uncompressed;
            }

            IndexSequence::Uncompressed => {
                // Wraps for the same reason as `unpadded` above.
                s.index.hash.uncompressed = s.index.hash.uncompressed.wrapping_add(s.vli);
                s.index.hash.crc32 = hash_crc32(&s.index.hash);
                // Only reached with `count > 0`: the do/while below exits at
                // zero and the Count arm above is the only other way in --
                // a purely local, single-function loop invariant enforced by
                // this same `if s.index.count == 0 { break }` after every
                // iteration, unlike `dict_repeat`'s cross-function one (see
                // that file's note, 2026-09-06). Even if it were ever wrong,
                // nothing here is an unsafe write or an unbounded loop: this
                // function only accumulates `wrapping_add`-already hash state
                // and returns once the input runs out. wrapping_sub is
                // faithful to the C's plain unsigned decrement regardless.
                s.index.count = s.index.count.wrapping_sub(1);
                s.index.sequence = IndexSequence::Unpadded;
            }
        }

        if s.index.count == 0 {
            break;
        }
    }

    XZ_STREAM_END
}

/// Validate that the next four input bytes match the value of `s->crc32`.
///
/// `s->pos` must be zero when starting to validate the first byte.
fn crc32_validate(s: &mut XzDec, b: Buf) -> c_int {
    let input = b.input();
    let mut in_pos = b.in_pos();

    // The C is a do/while on `s->pos < 32`.
    loop {
        if in_pos == input.len() {
            b.set_in_pos(in_pos);
            return XZ_OK;
        }

        // `b->in[b->in_pos++]` — the post-increment lands even when the
        // comparison then fails, so the mismatching byte is consumed.
        let byte = input[in_pos];
        in_pos += 1;

        // `s->pos` is 0, 8, 16 or 24 here; the C would be undefined at 32.
        // `wrapping_shr` masks the shift to the type's bit width, matching
        // the C's own behavior on every target that compiles `>>` to a
        // hardware shift instruction, per the CONFIG_RUST_OVERFLOW_CHECKS
        // sweep, 2026-09-06.
        debug_assert!(s.pos < 32);
        if ((s.crc32.wrapping_shr(s.pos)) & 0xFF) as u8 != byte {
            b.set_in_pos(in_pos);
            return XZ_DATA_ERROR;
        }

        // Converting the shift above to `wrapping_shr` removed the implicit
        // proof LLVM previously drew from the plain `>>`'s own guard that
        // `s.pos < 32`; without that, this addition needs its own guard too.
        // `s.pos` is a bit-offset counter with no downstream unsafe use, so
        // wrapping_* is faithful regardless, same as everywhere else in this
        // pass.
        s.pos = s.pos.wrapping_add(8);
        if s.pos >= 32 {
            break;
        }
    }

    b.set_in_pos(in_pos);
    s.crc32 = 0;
    s.pos = 0;

    XZ_STREAM_END
}

/// Skip over the Check field when the Check ID is not supported.
///
/// Returns true once the whole Check field has been skipped over.
#[cfg(XZ_DEC_ANY_CHECK)]
fn check_skip(s: &mut XzDec, b: Buf) -> bool {
    let in_size = b.input().len();
    let mut in_pos = b.in_pos();

    // `s->check_type` is 0..=15: dec_stream_header() rejects anything above
    // XZ_CHECK_MAX before it is ever stored.
    while s.pos < u32::from(CHECK_SIZES[s.check_type as usize]) {
        if in_pos == in_size {
            b.set_in_pos(in_pos);
            return false;
        }

        in_pos += 1;
        s.pos += 1;
    }

    b.set_in_pos(in_pos);
    s.pos = 0;

    true
}

/// Decode the Stream Header field (the first 12 bytes of the .xz Stream).
fn dec_stream_header(s: &mut XzDec) -> c_int {
    if s.temp.buf[..HEADER_MAGIC_SIZE] != HEADER_MAGIC {
        return XZ_FORMAT_ERROR;
    }

    if xz_crc32(&s.temp.buf[HEADER_MAGIC_SIZE..HEADER_MAGIC_SIZE + 2], 0)
        != get_le32(&s.temp.buf, HEADER_MAGIC_SIZE + 2)
    {
        return XZ_DATA_ERROR;
    }

    if s.temp.buf[HEADER_MAGIC_SIZE] != 0 {
        return XZ_OPTIONS_ERROR;
    }

    // Of integrity checks, we support only none (Check ID = 0) and CRC32
    // (Check ID = 1). However, if XZ_DEC_ANY_CHECK is defined, we will accept
    // other check types too, but then the check won't be verified and a
    // warning (XZ_UNSUPPORTED_CHECK) will be given.
    if s.temp.buf[HEADER_MAGIC_SIZE + 1] > XZ_CHECK_MAX {
        return XZ_OPTIONS_ERROR;
    }

    s.check_type = u32::from(s.temp.buf[HEADER_MAGIC_SIZE + 1]);

    if s.check_type > XZ_CHECK_CRC32 {
        #[cfg(XZ_DEC_ANY_CHECK)]
        return XZ_UNSUPPORTED_CHECK;
        #[cfg(not(XZ_DEC_ANY_CHECK))]
        return XZ_OPTIONS_ERROR;
    }

    XZ_OK
}

/// Decode the Stream Footer field (the last 12 bytes of the .xz Stream).
fn dec_stream_footer(s: &mut XzDec) -> c_int {
    if s.temp.buf[10..10 + FOOTER_MAGIC.len()] != FOOTER_MAGIC {
        return XZ_DATA_ERROR;
    }

    if xz_crc32(&s.temp.buf[4..10], 0) != get_le32(&s.temp.buf, 0) {
        return XZ_DATA_ERROR;
    }

    // Validate Backward Size. Note that we never added the size of the Index
    // CRC32 field to s->index.size, thus we use s->index.size / 4 instead of
    // s->index.size / 4 - 1.
    if (s.index.size >> 2) != VliType::from(get_le32(&s.temp.buf, 4)) {
        return XZ_DATA_ERROR;
    }

    if s.temp.buf[8] != 0 || u32::from(s.temp.buf[9]) != s.check_type {
        return XZ_DATA_ERROR;
    }

    // Use XZ_STREAM_END instead of XZ_OK to be more convenient for the caller.
    XZ_STREAM_END
}

/// `s->temp.buf[s->temp.pos++]` — read one staged byte and advance.
///
/// The C uses the post-increment inside the comparisons below, so `temp.pos`
/// moves even on the branches that immediately return an error. That is
/// reproduced rather than tidied: it is state a caller could observe by
/// re-entering after an error return.
fn take_temp(s: &mut XzDec) -> u8 {
    let byte = s.temp.buf[s.temp.pos];
    s.temp.pos += 1;
    byte
}

/// Decode the Block Header and initialize the filter chain.
///
/// # The subtraction the C leaves unguarded
///
/// `s->temp.size -= 4` is safe every time `dec_main()` reaches here normally:
/// `SEQ_BLOCK_START` has just set `temp.size = (in[in_pos] + 1) * 4` with
/// `in[in_pos] != 0`, so it is at least 8 — the C's own comment says "we know
/// that the temp buffer is at least eight bytes so this is safe".
///
/// It is *not* safe on re-entry after an error. This function's error returns
/// leave `s->sequence` at `SEQ_BLOCK_HEADER` with the already-shortened
/// `temp.size`, so a caller that calls `xz_dec_run()` again after
/// `XZ_DATA_ERROR` subtracts another 4, and after a few rounds the C wraps
/// `size_t` and hands `xz_crc32()` a length near `SIZE_MAX` — an out-of-bounds
/// read of the kernel heap. The subtraction is transcribed as a plain `-`,
/// which encodes the C author's stated invariant: it panics on that path
/// rather than reading past the buffer. No in-tree caller of `xz_dec_run()`
/// continues after an error, and `include/linux/xz.h` documents no way to
/// resume from one.
fn dec_block_header(s: &mut XzDec) -> c_int {
    // Validate the CRC32. We know that the temp buffer is at least eight bytes
    // so this is safe.
    s.temp.size -= 4;
    if xz_crc32(&s.temp.buf[..s.temp.size], 0) != get_le32(&s.temp.buf, s.temp.size) {
        return XZ_DATA_ERROR;
    }

    s.temp.pos = 2;

    // Catch unsupported Block Flags. We support only one or two filters in the
    // chain, so we catch that with the same test.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    const FLAG_MASK: u8 = 0x3E;
    #[cfg(not(CONFIG_XZ_DEC_BCJ))]
    const FLAG_MASK: u8 = 0x3F;
    if s.temp.buf[1] & FLAG_MASK != 0 {
        return XZ_OPTIONS_ERROR;
    }

    // Compressed Size
    if s.temp.buf[1] & 0x40 != 0 {
        let size = s.temp.size;
        if dec_vli(
            &mut s.pos,
            &mut s.vli,
            &s.temp.buf[..size],
            &mut s.temp.pos,
        ) != XZ_STREAM_END
        {
            return XZ_DATA_ERROR;
        }

        s.block_header.compressed = s.vli;
    } else {
        s.block_header.compressed = VLI_UNKNOWN;
    }

    // Uncompressed Size
    if s.temp.buf[1] & 0x80 != 0 {
        let size = s.temp.size;
        if dec_vli(
            &mut s.pos,
            &mut s.vli,
            &s.temp.buf[..size],
            &mut s.temp.pos,
        ) != XZ_STREAM_END
        {
            return XZ_DATA_ERROR;
        }

        s.block_header.uncompressed = s.vli;
    } else {
        s.block_header.uncompressed = VLI_UNKNOWN;
    }

    // If there are two filters, the first one must be a BCJ filter.
    #[cfg(CONFIG_XZ_DEC_BCJ)]
    {
        s.bcj_active = s.temp.buf[1] & 0x01 != 0;
        if s.bcj_active {
            if s.temp.size - s.temp.pos < 2 {
                return XZ_OPTIONS_ERROR;
            }

            let id = take_temp(s);
            // SAFETY: `s.bcj` came from `xz_dec_bcj_create()` in
            // `xz_dec_init()` and is not aliased — nothing else in the kernel
            // holds it.
            let ret = unsafe { xz_dec_bcj_reset(s.bcj, id) };
            if ret != XZ_OK {
                return ret;
            }

            // We don't support custom start offset, so Size of Properties must
            // be zero.
            if take_temp(s) != 0x00 {
                return XZ_OPTIONS_ERROR;
            }
        }
    }

    // Valid Filter Flags always take at least two bytes.
    if s.temp.size - s.temp.pos < 2 {
        return XZ_DATA_ERROR;
    }

    // Filter ID = LZMA2
    if take_temp(s) != 0x21 {
        return XZ_OPTIONS_ERROR;
    }

    // Size of Properties = 1-byte Filter Properties
    if take_temp(s) != 0x01 {
        return XZ_OPTIONS_ERROR;
    }

    // Filter Properties contains LZMA2 dictionary size.
    if s.temp.size - s.temp.pos < 1 {
        return XZ_DATA_ERROR;
    }

    let props = take_temp(s);
    // SAFETY: `s.lzma2` came from `xz_dec_lzma2_create()` in `xz_dec_init()`
    // and is not aliased.
    let ret = unsafe { xz_dec_lzma2_reset(s.lzma2, props) };
    if ret != XZ_OK {
        return ret;
    }

    // The rest must be Header Padding.
    while s.temp.pos < s.temp.size {
        if take_temp(s) != 0x00 {
            return XZ_OPTIONS_ERROR;
        }
    }

    s.temp.pos = 0;
    s.block.compressed = 0;
    s.block.uncompressed = 0;

    XZ_OK
}

/// The Stream state machine.
///
/// The C is a `switch` inside a `while (true)` whose cases fall through. Every
/// `fallthrough` there is preceded by `s->sequence = <the case fallen into>`,
/// and `SEQ_BLOCK_START`'s Index branch and `SEQ_BLOCK_CHECK` `break` out of
/// the switch after setting `s->sequence` as well — so re-dispatching on the
/// freshly stored `sequence` is the same program, and every arm below ends in
/// `return` or `continue`.
fn dec_main(s: &mut XzDec, b: Buf) -> c_int {
    // Store the start position for the case when we are in the middle of the
    // Index field.
    s.in_start = b.in_pos();

    loop {
        match s.sequence {
            Sequence::StreamHeader => {
                // Stream Header is copied to s->temp, and then decoded from
                // there. This way if the caller gives us only little input at
                // a time, we can still keep the Stream Header decoding code
                // simple. Similar approach is used in many places in this
                // file.
                if !fill_temp(s, b) {
                    return XZ_OK;
                }

                // If dec_stream_header() returns XZ_UNSUPPORTED_CHECK, it is
                // still possible to continue decoding if working in multi-call
                // mode. Thus, update s->sequence before calling
                // dec_stream_header().
                s.sequence = Sequence::BlockStart;

                let ret = dec_stream_header(s);
                if ret != XZ_OK {
                    return ret;
                }

                continue;
            }

            Sequence::BlockStart => {
                let input = b.input();
                let in_pos = b.in_pos();

                // We need one byte of input to continue.
                if in_pos == input.len() {
                    return XZ_OK;
                }

                // See if this is the beginning of the Index field.
                if input[in_pos] == 0 {
                    // `s->in_start = b->in_pos++` — in_start takes the
                    // pre-increment value.
                    s.in_start = in_pos;
                    b.set_in_pos(in_pos + 1);
                    s.sequence = Sequence::Index;
                    continue;
                }

                // Calculate the size of the Block Header and prepare to decode
                // it. The largest byte value gives (255 + 1) * 4 == 1024, so
                // this cannot overflow and cannot exceed `temp.buf`.
                s.block_header.size = (u32::from(input[in_pos]) + 1) * 4;

                s.temp.size = s.block_header.size as usize;
                s.temp.pos = 0;
                s.sequence = Sequence::BlockHeader;

                continue;
            }

            Sequence::BlockHeader => {
                if !fill_temp(s, b) {
                    return XZ_OK;
                }

                let ret = dec_block_header(s);
                if ret != XZ_OK {
                    return ret;
                }

                s.sequence = Sequence::BlockUncompress;
                continue;
            }

            Sequence::BlockUncompress => {
                let ret = dec_block(s, b);
                if ret != XZ_STREAM_END {
                    return ret;
                }

                s.sequence = Sequence::BlockPadding;
                continue;
            }

            Sequence::BlockPadding => {
                // Size of Compressed Data + Block Padding must be a multiple of
                // four. We don't need s->block.compressed for anything else
                // anymore, so we use it here to test the size of the Block
                // Padding field.
                let input = b.input();
                let mut in_pos = b.in_pos();

                while s.block.compressed & 3 != 0 {
                    if in_pos == input.len() {
                        b.set_in_pos(in_pos);
                        return XZ_OK;
                    }

                    // `b->in[b->in_pos++] != 0` — consumed either way.
                    let byte = input[in_pos];
                    in_pos += 1;
                    if byte != 0 {
                        b.set_in_pos(in_pos);
                        return XZ_DATA_ERROR;
                    }

                    // Unsigned in the C; wrapping_* is faithful regardless,
                    // per the CONFIG_RUST_OVERFLOW_CHECKS sweep, 2026-09-06.
                    s.block.compressed = s.block.compressed.wrapping_add(1);
                }

                b.set_in_pos(in_pos);
                s.sequence = Sequence::BlockCheck;
                continue;
            }

            Sequence::BlockCheck => {
                if s.check_type == XZ_CHECK_CRC32 {
                    let ret = crc32_validate(s, b);
                    if ret != XZ_STREAM_END {
                        return ret;
                    }
                } else {
                    // Without XZ_DEC_ANY_CHECK the only other Check ID that
                    // reaches here is XZ_CHECK_NONE, which has nothing to
                    // skip; the C has no `else` at all in that build.
                    #[cfg(XZ_DEC_ANY_CHECK)]
                    if !check_skip(s, b) {
                        return XZ_OK;
                    }
                }

                s.sequence = Sequence::BlockStart;
                continue;
            }

            Sequence::Index => {
                let ret = dec_index(s, b);
                if ret != XZ_STREAM_END {
                    return ret;
                }

                s.sequence = Sequence::IndexPadding;
                continue;
            }

            Sequence::IndexPadding => {
                let input = b.input();
                let mut in_pos = b.in_pos();

                // `in_start <= in_pos` as elsewhere; unsigned arithmetic in
                // the C throughout, so wrapping_* is faithful regardless,
                // per the CONFIG_RUST_OVERFLOW_CHECKS sweep, 2026-09-06.
                while (s.index.size.wrapping_add((in_pos.wrapping_sub(s.in_start)) as VliType))
                    & 3
                    != 0
                {
                    if in_pos == input.len() {
                        b.set_in_pos(in_pos);
                        index_update(s, b);
                        return XZ_OK;
                    }

                    let byte = input[in_pos];
                    in_pos += 1;
                    if byte != 0 {
                        b.set_in_pos(in_pos);
                        return XZ_DATA_ERROR;
                    }
                }

                b.set_in_pos(in_pos);

                // Finish the CRC32 value and Index size.
                index_update(s, b);

                // Compare the hashes to validate the Index field. The C's
                // memeq() covers the struct's tail padding too; that padding is
                // zero in both hashes, so field equality is the same test. See
                // divergence 1.
                if s.block.hash != s.index.hash {
                    return XZ_DATA_ERROR;
                }

                s.sequence = Sequence::IndexCrc32;
                continue;
            }

            Sequence::IndexCrc32 => {
                let ret = crc32_validate(s, b);
                if ret != XZ_STREAM_END {
                    return ret;
                }

                s.temp.size = STREAM_HEADER_SIZE;
                s.sequence = Sequence::StreamFooter;
                continue;
            }

            Sequence::StreamFooter => {
                if !fill_temp(s, b) {
                    return XZ_OK;
                }

                return dec_stream_footer(s);
            }
        }
    }
}

/// `DEC_IS_SINGLE(mode)`, `lib/xz/xz_private.h`.
fn dec_is_single(mode: c_int) -> bool {
    mode == XZ_SINGLE
}

/// The body of `xz_dec_reset()`.
fn reset(s: &mut XzDec) {
    s.sequence = Sequence::StreamHeader;
    s.allow_buf_error = false;
    s.pos = 0;
    s.crc32 = 0;
    s.block = Block::ZERO;
    s.index = Index::ZERO;
    s.temp.pos = 0;
    s.temp.size = STREAM_HEADER_SIZE;
}

/// The body of `xz_dec_run()`.
///
/// In multi-call mode, we must return `XZ_BUF_ERROR` when it seems clear that
/// we are not going to make any progress anymore. This is to prevent the caller
/// from calling us infinitely when the input file is truncated or otherwise
/// corrupt. Since the zlib-style API allows that the caller fills the input
/// buffer only when the decoder doesn't produce any new output, we have to be
/// careful to avoid returning `XZ_BUF_ERROR` too easily: it is returned only
/// after the second consecutive call that makes no progress.
///
/// In single-call mode, if we couldn't decode everything and no error occurred,
/// either the input is truncated or the output buffer is too small. Since we
/// know that the last input byte never produces any output, we know that if all
/// the input was consumed and decoding wasn't finished, the file must be
/// corrupt. Otherwise the output buffer has to be too small or the file is
/// corrupt in a way that decoding it produces too big output.
///
/// If single-call decoding fails, we reset `b->in_pos` and `b->out_pos` back to
/// their original values. This is because with some filter chains there won't
/// be any valid uncompressed data in the output buffer unless the decoding
/// actually succeeds (that's the price to pay of using the output buffer as the
/// workspace).
fn run(s: &mut XzDec, b: Buf) -> c_int {
    if dec_is_single(s.mode) {
        reset(s);
    }

    let in_start = b.in_pos();
    let out_start = b.out_pos();
    let mut ret = dec_main(s, b);

    if dec_is_single(s.mode) {
        if ret == XZ_OK {
            ret = if b.in_pos() == b.input().len() {
                XZ_DATA_ERROR
            } else {
                XZ_BUF_ERROR
            };
        }

        if ret != XZ_STREAM_END {
            b.set_in_pos(in_start);
            b.set_out_pos(out_start);
        }
    } else if ret == XZ_OK && in_start == b.in_pos() && out_start == b.out_pos() {
        if s.allow_buf_error {
            ret = XZ_BUF_ERROR;
        }

        s.allow_buf_error = true;
    } else {
        s.allow_buf_error = false;
    }

    ret
}

// ---------------------------------------------------------------------------
// The C ABI. Four thunks in xz_dec_stream.c call in here; xz_dec_init() and
// xz_dec_end() additionally need the size, an initialiser and two accessors,
// because they own the allocation and this file owns the layout.
// ---------------------------------------------------------------------------

/// Body of `xz_dec_run()`.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_init()` and not concurrently used
/// elsewhere; `b` must point at a live `struct xz_buf` whose `in`/`out` match
/// its `in_size`/`out_size` and overlap neither `*s` nor each other. This is
/// the contract `xz_dec_run()`'s callers already uphold.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_run(s: *mut XzDec, b: *mut XzBuf) -> c_int {
    // SAFETY: the caller guarantees `s` is live, initialised by
    // `rust_xz_dec_init()` and unaliased for the duration of the call, and
    // that `b` upholds the `Buf` contract. `*b` does not overlap `*s`, so the
    // `&mut XzDec` and the writes through `Buf` cannot alias.
    let (s, b) = unsafe { (&mut *s, Buf::new(b)) };
    run(s, b)
}

/// Body of `xz_dec_reset()`.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_init()` and not concurrently used
/// elsewhere.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_reset(s: *mut XzDec) {
    // SAFETY: the caller guarantees `s` is live, initialised by
    // `rust_xz_dec_init()` and unaliased for the duration of the call.
    reset(unsafe { &mut *s });
}

/// How many bytes `xz_dec_init()` must `kmalloc()`.
#[no_mangle]
pub extern "C" fn rust_xz_dec_size() -> usize {
    // kmalloc returns memory aligned to at least ARCH_KMALLOC_MINALIGN, which
    // is 8 on every architecture the kernel builds Rust for. Anything stricter
    // would need a different allocator, so refuse at compile time.
    const _: () = assert!(core::mem::align_of::<XzDec>() <= 8);
    core::mem::size_of::<XzDec>()
}

/// Initialise a freshly allocated decoder, then reset it.
///
/// This is the tail of the C's `xz_dec_init()`: everything after the three
/// allocations have succeeded. It writes every field, including the ones the C
/// leaves uninitialised until something happens to store to them, because
/// reading uninitialised memory is UB in Rust. See divergence 2 in the module
/// docs.
///
/// `mode` is `enum xz_mode` widened to `int`; only `DEC_IS_SINGLE()` ever looks
/// at it, and that is a comparison against `XZ_SINGLE == 0`.
///
/// # Safety
///
/// `s` must point at `rust_xz_dec_size()` writable bytes aligned to at least 8.
/// `lzma2` must be a live pointer from `xz_dec_lzma2_create()`, and — where
/// `CONFIG_XZ_DEC_BCJ` is set — `bcj` a live pointer from
/// `xz_dec_bcj_create()`. Both are owned by this struct from here until
/// `xz_dec_end()` frees them.
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_init(
    s: *mut XzDec,
    mode: c_int,
    #[cfg(CONFIG_XZ_DEC_BCJ)] bcj: *mut XzDecBcj,
    lzma2: *mut XzDecLzma2,
) {
    // SAFETY: the caller guarantees `s` covers a correctly aligned allocation
    // of `rust_xz_dec_size()` bytes. `write` does not read the old contents,
    // which are whatever kmalloc() left there.
    unsafe {
        s.write(XzDec {
            sequence: Sequence::StreamHeader,
            pos: 0,
            vli: 0,
            in_start: 0,
            out_start: 0,
            crc32: 0,
            check_type: 0,
            mode,
            allow_buf_error: false,
            block_header: BlockHeader {
                compressed: VLI_UNKNOWN,
                uncompressed: VLI_UNKNOWN,
                size: 0,
            },
            block: Block::ZERO,
            index: Index::ZERO,
            temp: Temp {
                pos: 0,
                size: STREAM_HEADER_SIZE,
                buf: [0; TEMP_BUF_SIZE],
            },
            lzma2,
            #[cfg(CONFIG_XZ_DEC_BCJ)]
            bcj,
            #[cfg(CONFIG_XZ_DEC_BCJ)]
            bcj_active: false,
        });
    }
}

/// `s->lzma2`, so that the C's `xz_dec_end()` can `xz_dec_lzma2_end()` it.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_init()`.
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_lzma2(s: *mut XzDec) -> *mut XzDecLzma2 {
    // SAFETY: the caller guarantees `s` is live and initialised. Reads one
    // pointer field.
    unsafe { (*s).lzma2 }
}

/// `s->bcj`, so that the C's `xz_dec_end()` can `xz_dec_bcj_end()` it — which
/// `xz_private.h` defines as `kfree(s)`.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_init()`.
#[cfg(CONFIG_XZ_DEC_BCJ)]
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_bcj(s: *mut XzDec) -> *mut XzDecBcj {
    // SAFETY: the caller guarantees `s` is live and initialised. Reads one
    // pointer field.
    unsafe { (*s).bcj }
}
