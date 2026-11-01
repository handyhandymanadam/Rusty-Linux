// SPDX-License-Identifier: GPL-2.0-only

//! Huffman-coded output for DEFLATE compression: builds the literal/length
//! and distance trees per block, decides stored/static/dynamic encoding,
//! and emits the compressed bit stream.
//!
//! Ported from `lib/zlib_deflate/deftree.c` (originally `trees.c`,
//! Copyright (C) 1995-1996 Jean-loup Gailly, zlib license).
//!
//! # Shape: no entry thunks
//!
//! `nm` on the built object says none of this file's six globals is
//! `EXPORT_SYMBOL`'d -- `lib/zlib_deflate/deflate_syms.c`'s six
//! `EXPORT_SYMBOL`s all belong to `deflate.c`'s own functions, not this
//! file's. `deflate.o` calls all six of
//! `zlib_tr_init`/`zlib_tr_tally`/`zlib_tr_flush_block`/`zlib_tr_align`/
//! `zlib_tr_stored_block`/`zlib_tr_stored_type_only`; nothing here calls
//! back into `deflate.o` (confirmed with `nm`, not assumed -- the only
//! undefined symbols in the pristine object are `memcpy` and
//! `byte_rev_table`). So: the `lib/union_find` shape, same as
//! `huf_decompress_rs.rs`/`zstd_decompress_block_rs.rs` -- all six keep
//! their C names and `#[no_mangle]`, `deflate.c` stays C for now and calls
//! into these directly, and `lib/zlib_deflate/deflate.c` is untouched by
//! this port.
//!
//! # `struct deflate_state` is mirrored in full, not truncated
//!
//! This file's 6 entry points and their helpers touch fields scattered from
//! the struct's first quarter (`strm`, `pending_buf`, `pending`,
//! `data_type`) to its last (`bi_buf`, `bi_valid`), so a prefix truncation
//! (the `inffast_rs.rs` shape) is not available -- every field is declared,
//! in the C's order, with a same-size type, matching the full-mirror
//! reasoning `zstd_decompress_block_rs.rs`'s `ZstdDCtx` already rests on.
//! `strm` (`z_streamp`) is never dereferenced by this file (grepped the
//! pristine C: zero uses of `s->strm`), so it stays `*mut c_void`, opaque.
//! **Not yet checked against `offsetof()` on the real header** -- that is
//! `port/test/deftree/`'s job, same as every other mirrored struct in this
//! project.
//!
//! # Deliberate divergence: the lazily-initialized static tables are real
//! # `const`s instead
//!
//! The C computes `static_ltree`/`static_dtree`/`dist_code`/`length_code`/
//! `base_length`/`base_dist` once, lazily, on the first call to
//! `zlib_tr_init()`, guarded by a plain (unlocked) `static int
//! static_init_done` -- safe only because, per the C's own comment, "this
//! is harmless since both invocations do exactly the same thing" if two
//! threads race into it. Every one of those tables is a pure, deterministic
//! function of compile-time-constant inputs (`extra_lbits`/`extra_dbits`/
//! `extra_blbits`/`bl_order`), so this port computes them as real `const`s
//! (`const fn`, evaluated by the compiler) instead: no lazy-init, no
//! benign-race pattern to reproduce, no runtime cost at all. `gen_codes()`
//! is written once, as a `const fn`, and called from both this compile-time
//! setup and its normal runtime use in `build_tree()` -- a `const fn` is
//! callable from either context as long as its body is const-evaluable,
//! which pure array/loop arithmetic over `u16`/`i32` is. A differential
//! test against the pristine C's *runtime-computed* values is what proves
//! this produces the identical tables, not just that it compiles.
//!
//! `bitrev32()` is similarly not ported as the C's table-lookup
//! `__bitrev32()` (`byte_rev_table`, already real Rust in `bitrev_rs.rs`,
//! but not itself callable as a function -- `__bitrev32` is a `static
//! inline`, no linkable symbol). `bitrev.h`'s own `bitrev32(x)` macro
//! already picks between two implementations depending on
//! `__builtin_constant_p`: the table-based `__bitrev32()` and the purely
//! arithmetic `__constant_bitrev32()` cascading-bit-swap formula -- both
//! compute the same "reverse the bits of a `u32`" function by construction
//! (that is the whole point of `__builtin_constant_p` picking between
//! them), so this file implements only the arithmetic one. No table, no
//! `extern`, and every call site here is inside what was compile-time
//! table construction in the C anyway.
//!
//! # Known unaudited risk: `tree`/`desc` pointers that alias `s`'s own fields
//!
//! `gen_bitlen()`/`build_tree()`/`scan_tree()`/`send_tree()`/
//! `compress_block()` all take a `tree`/`ltree`/`dtree` pointer that, at
//! every real call site, is one of `s`'s own arrays
//! (`s.dyn_ltree`/`dyn_dtree`/`bl_tree`) -- the C has no concept of this
//! being a problem (it is all just pointers), but Rust's raw-pointer
//! aliasing model (Stacked/Tree Borrows) can in principle care whether a
//! `&mut DeflateState` reborrow and a separately-passed pointer into one of
//! its own fields overlap in a way that invalidates one or the other. This
//! file follows the same reborrow-fresh-after-any-intervening-call
//! discipline the zstd files' adversarial review established, but the
//! specific `tree`-aliases-`s` shape has NOT been Miri-checked (this
//! project has no Miri in its toolchain -- see `zstd_decompress_rs.rs`'s
//! module docs for the identical caveat there). Flagged rather than
//! asserted clean.
//!
//! Replaces: lib/zlib_deflate/deftree.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

// ---------------------------------------------------------------------------
// include/linux/zconf.h, include/linux/zutil.h -- base zlib types.
// ---------------------------------------------------------------------------

/// `Byte`.
type Byte = u8;
/// `uch`, `zutil.h`.
type Uch = u8;
/// `ush`, `zutil.h`.
type Ush = u16;
/// `ulg`, `zutil.h`.
type Ulg = c_ulong;
/// `uInt`.
type UInt = c_uint;
/// `Pos`, `defutil.h` -- `typedef ush Pos`.
type Pos = u16;
/// `IPos`, `defutil.h` -- `typedef unsigned IPos`.
type IPos = c_uint;

const STORED_BLOCK: c_int = 0;
const STATIC_TREES: c_int = 1;
const DYN_TREES: c_int = 2;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;

/// `MIN_LOOKAHEAD`, `defutil.h:262-265`. Used only by [`zlib_tr_tally`]'s
/// `debug_assert!` (the C's `MAX_DIST(s)` macro), which is the only real
/// call site left after this port -- `deflate.c` (unported) carries its own
/// copy for the match-finding it does itself.
const MIN_LOOKAHEAD: UInt = (MAX_MATCH + MIN_MATCH + 1) as UInt;

const Z_BINARY: u8 = 0;
const Z_ASCII: u8 = 1;
const Z_UNKNOWN: u8 = 2;

// ---------------------------------------------------------------------------
// defutil.h -- shared with deflate.c (which stays C for now).
// ---------------------------------------------------------------------------

const LENGTH_CODES: usize = 29;
const LITERALS: usize = 256;
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
const D_CODES: usize = 30;
const BL_CODES: usize = 19;
const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;

// INIT_STATE/BUSY_STATE/FINISH_STATE (defutil.h) are deflate.c's state
// machine values -- deftree.c never references any of them (grepped), so
// they are not declared here.

/// `ct_data`, `defutil.h`. A union of `{freq, code}` and a union of
/// `{dad, len}`, both `ush` either way -- represented as plain fields with
/// both names available as accessors (`Freq`/`Code` alias the same bits, as
/// do `Dad`/`Len`), matching the C's `#define Freq fc.freq` etc exactly:
/// nothing is ever read through one name after being written through the
/// other's DIFFERENT type, so no reinterpretation is needed, only naming.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CtData {
    fc: Ush,
    dl: Ush,
}

impl CtData {
    #[inline(always)]
    const fn freq(&self) -> Ush {
        self.fc
    }
    #[inline(always)]
    const fn set_freq(&mut self, v: Ush) {
        self.fc = v;
    }
    #[inline(always)]
    const fn code(&self) -> Ush {
        self.fc
    }
    #[inline(always)]
    const fn set_code(&mut self, v: Ush) {
        self.fc = v;
    }
    #[inline(always)]
    const fn dad(&self) -> Ush {
        self.dl
    }
    #[inline(always)]
    const fn set_dad(&mut self, v: Ush) {
        self.dl = v;
    }
    #[inline(always)]
    const fn len(&self) -> Ush {
        self.dl
    }
    #[inline(always)]
    const fn set_len(&mut self, v: Ush) {
        self.dl = v;
    }
    const fn zero() -> Self {
        CtData { fc: 0, dl: 0 }
    }
}

/// `static_tree_desc_s`, `deftree.c`.
#[repr(C)]
struct StaticTreeDesc {
    static_tree: *const CtData,
    extra_bits: *const c_int,
    extra_base: c_int,
    elems: c_int,
    max_length: c_int,
}
// SAFETY: every `StaticTreeDesc` this file constructs points at `'static`
// data (the const tables below); sharing the pointer across threads is as
// safe as sharing the data itself (read-only after construction).
unsafe impl Sync for StaticTreeDesc {}

/// `tree_desc_s`, `defutil.h`.
#[repr(C)]
struct TreeDesc {
    dyn_tree: *mut CtData,
    max_code: c_int,
    stat_desc: *const StaticTreeDesc,
}

impl Default for TreeDesc {
    fn default() -> Self {
        TreeDesc {
            dyn_tree: core::ptr::null_mut(),
            max_code: 0,
            stat_desc: core::ptr::null(),
        }
    }
}

/// Mirrors `struct deflate_state`, `defutil.h`. See the module docs: every
/// field is declared, in the C's order, with a same-size type; untouched
/// ones (`strm`, `noheader`, `method`, ...) exist only to keep every later
/// field's offset correct.
#[repr(C)]
pub struct DeflateState {
    /// `z_streamp strm`. Opaque -- never dereferenced by this file.
    strm: *mut c_void,
    status: c_int,
    pending_buf: *mut Byte,
    pending_buf_size: Ulg,
    pending_out: *mut Byte,
    pending: c_int,
    noheader: c_int,
    data_type: Byte,
    method: Byte,
    last_flush: c_int,

    w_size: UInt,
    w_bits: UInt,
    w_mask: UInt,

    window: *mut Byte,
    window_size: Ulg,

    prev: *mut Pos,
    head: *mut Pos,

    ins_h: UInt,
    hash_size: UInt,
    hash_bits: UInt,
    hash_mask: UInt,
    hash_shift: UInt,

    block_start: c_long,

    match_length: UInt,
    prev_match: IPos,
    match_available: c_int,
    strstart: UInt,
    match_start: UInt,
    lookahead: UInt,

    prev_length: UInt,
    max_chain_length: UInt,
    /// `max_lazy_match` (aka `max_insert_length`).
    max_lazy_match: UInt,

    level: c_int,
    strategy: c_int,

    good_match: UInt,
    nice_match: c_int,

    dyn_ltree: [CtData; HEAP_SIZE],
    dyn_dtree: [CtData; 2 * D_CODES + 1],
    bl_tree: [CtData; 2 * BL_CODES + 1],

    l_desc: TreeDesc,
    d_desc: TreeDesc,
    bl_desc: TreeDesc,

    bl_count: [Ush; MAX_BITS + 1],

    heap: [c_int; 2 * L_CODES + 1],
    heap_len: c_int,
    heap_max: c_int,

    depth: [Uch; 2 * L_CODES + 1],

    l_buf: *mut Uch,

    lit_bufsize: UInt,
    last_lit: UInt,

    d_buf: *mut Ush,

    opt_len: Ulg,
    static_len: Ulg,
    compressed_len: Ulg,
    matches: UInt,
    last_eob_len: c_int,

    // `#ifdef DEBUG_ZLIB` -- `bits_sent`. Never defined in any build this
    // project produces (grepped: not in configs/*.fragment, not selected by
    // any Kconfig this tree ships), so the field genuinely does not exist
    // in the real struct -- omitted here too, not `#[cfg]`'d out, since a
    // `#[cfg]` that is always false either way would just be misleading
    // decoration.
    bi_buf: Ush,
    bi_valid: c_int,
}

// ---------------------------------------------------------------------------
// defutil.h -- MEM_STATIC-equivalent (`static inline` / macro) helpers.
// No linkable symbol in the C, so reimplemented here, same convention as
// every other file in this project.
// ---------------------------------------------------------------------------

/// `put_byte(s, c)`, `defutil.h:260` -- `s->pending_buf[s->pending++] = c;`.
///
/// Real catch, not restated: the C has no bounds check here at all, relying
/// entirely on the algorithm's own invariant that `pending` never reaches
/// `pending_buf_size` (established by the caller sizing `pending_buf` to
/// `zlib_deflate_workspacesize()`, in `deflate.c`, not this file). An
/// assert here turns a violated invariant into a loud panic instead of a
/// silent heap write past the allocation -- strictly better than
/// reproducing the C's unchecked write, and this is a genuine bounds
/// catch (per this project's "would leaving it checked catch something a
/// wrap couldn't" test), not restating a precondition already enforced on
/// this exact path.
///
/// # Safety
/// `s` must be valid for writes; `(*s).pending_buf` must be valid for
/// `(*s).pending_buf_size` bytes.
#[inline(always)]
unsafe fn put_byte(s: *mut DeflateState, c: u8) {
    // SAFETY: class B (boundary), the caller's contract.
    let s = unsafe { &mut *s };
    assert!((s.pending as c_ulong) < s.pending_buf_size, "pending_buf overflow");
    // SAFETY: class C (construction). Just asserted `s.pending <
    // s.pending_buf_size`, and `s.pending_buf` is `s.pending_buf_size`
    // bytes by the caller's contract.
    unsafe { *s.pending_buf.add(s.pending as usize) = c };
    s.pending += 1;
}

/// `put_short(s, w)`, `defutil.h:288-291` -- LSB first.
///
/// # Safety
/// As `put_byte`, twice.
#[inline(always)]
unsafe fn put_short(s: *mut DeflateState, w: Ush) {
    // SAFETY: class B (boundary), forwarded, twice.
    unsafe {
        put_byte(s, (w & 0xff) as u8);
        put_byte(s, (w >> 8) as u8);
    }
}

/// `bi_flush(s)`, `defutil.h:314-325`.
///
/// # Safety
/// As `put_byte`/`put_short`.
unsafe fn bi_flush(s: *mut DeflateState) {
    // SAFETY: class B (boundary), the caller's contract.
    let sr = unsafe { &mut *s };
    if sr.bi_valid == 16 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { put_short(s, sr.bi_buf) };
        let sr = unsafe { &mut *s };
        sr.bi_buf = 0;
        sr.bi_valid = 0;
    } else if sr.bi_valid >= 8 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { put_byte(s, sr.bi_buf as u8) };
        let sr = unsafe { &mut *s };
        sr.bi_buf = sr.bi_buf.wrapping_shr(8);
        sr.bi_valid -= 8;
    }
}

/// `bi_windup(s)`, `defutil.h:330-342`. `DEBUG_ZLIB`'s `bits_sent` update is
/// omitted -- that field does not exist in this build (see the struct's own
/// note).
///
/// # Safety
/// As `put_byte`/`put_short`.
unsafe fn bi_windup(s: *mut DeflateState) {
    // SAFETY: class B (boundary), the caller's contract.
    let sr = unsafe { &mut *s };
    if sr.bi_valid > 8 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { put_short(s, sr.bi_buf) };
    } else if sr.bi_valid > 0 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { put_byte(s, sr.bi_buf as u8) };
    }
    // SAFETY: class B (boundary). Reborrowed fresh after the calls above,
    // which themselves reborrow `*s`.
    let sr = unsafe { &mut *s };
    sr.bi_buf = 0;
    sr.bi_valid = 0;
}

/// `send_bits(s, value, length)`, `defutil.h:389-401` (the `!DEBUG_ZLIB`
/// macro arm -- `DEBUG_ZLIB` is never defined in any build this project
/// produces).
///
/// Every real call site passes `length` in `1..=16` and `value` fitting in
/// `length` bits (the C's own `Assert`, compiled out at `!DEBUG_ZLIB` and
/// not reinstated here for the same reason `bi_windup`'s `bits_sent` isn't:
/// this file's differential test exercises every call site with real
/// tree-encoding data, which is what actually proves the contract holds --
/// an `assert!` here would just restate it).
///
/// # Safety
/// As `put_byte`/`put_short`.
///
/// Every shift below is done in `u32`, not `Ush` (`u16`): the C computes
/// these in `int` (`value`'s own type, and `bi_buf`/`bi_valid` promoted to
/// it by the usual arithmetic conversions) and only truncates to `ush` on
/// the store into `bi_buf`. `bi_valid` legitimately reaches exactly
/// `Buf_size` (16) on entry here (whenever the previous call's non-overflow
/// branch filled it exactly full), and at `bi_valid == Buf_size` this
/// function's own shift amounts hit 16 -- a shift by the full width of a
/// 16-bit type. `u16::wrapping_shl`/`wrapping_shr` mask the shift amount
/// modulo 16, silently turning a by-16 shift into a no-op instead of
/// zeroing the value the way C's wider-precision shift-then-truncate does;
/// an earlier version of this function used `Ush` shifts and shipped
/// exactly that bug (caught by `port/test/deftree/`, not by inspection).
/// `u32` has room to spare for every shift amount this function ever uses
/// (0..=16), so no wraparound is possible.
unsafe fn send_bits(s: *mut DeflateState, value: c_int, length: c_int) {
    const Buf_size: c_int = 16;
    // SAFETY: class B (boundary), the caller's contract.
    let sr = unsafe { &mut *s };
    if sr.bi_valid > Buf_size - length {
        let val = value;
        sr.bi_buf = ((sr.bi_buf as u32) | ((val as u32) << (sr.bi_valid as u32))) as Ush;
        // SAFETY: class B (boundary), forwarded.
        unsafe { put_short(s, sr.bi_buf) };
        // SAFETY: class B (boundary). Reborrowed fresh after the call above.
        let sr = unsafe { &mut *s };
        sr.bi_buf = ((val as u32) >> ((Buf_size - sr.bi_valid) as u32)) as Ush;
        sr.bi_valid += length - Buf_size;
    } else {
        sr.bi_buf = ((sr.bi_buf as u32) | ((value as u32) << (sr.bi_valid as u32))) as Ush;
        sr.bi_valid += length;
    }
}

/// `zlib_tr_send_bits`, `defutil.h:404-411`. Not actually called anywhere
/// in `deftree.c` itself (only `deflate.c` uses this name, per `nm` -- and
/// `deflate.c` isn't part of this port), but it is declared `extern` from
/// `defutil.h` and this file's the only place its body could live once
/// ported; not exposed here since nothing in-tree reaches it through this
/// file and `deflate.c` stays C, calling the header's own inline version.

/// `send_code(s, c, tree)`, `deftree.c:150-151` (the `!DEBUG_ZLIB` arm).
///
/// # Safety
/// As `send_bits`; `tree` must be valid for reads at index `c`.
#[inline(always)]
unsafe fn send_code(s: *mut DeflateState, c: usize, tree: *const CtData) {
    // SAFETY: class B (boundary), the caller's contract.
    let (code, len) = unsafe { ((*tree.add(c)).code(), (*tree.add(c)).len()) };
    // SAFETY: class B (boundary), forwarded.
    unsafe { send_bits(s, code as c_int, len as c_int) };
}

/// `bitrev32(x)`. See the module docs: the arithmetic
/// (`__constant_bitrev32`) form, not the table-lookup (`__bitrev32`) form
/// -- both compute the same function by construction.
#[inline(always)]
const fn bitrev32(x: u32) -> u32 {
    let mut v = x;
    v = (v >> 16) | (v << 16);
    v = ((v & 0xFF00FF00u32) >> 8) | ((v & 0x00FF00FFu32) << 8);
    v = ((v & 0xF0F0F0F0u32) >> 4) | ((v & 0x0F0F0F0Fu32) << 4);
    v = ((v & 0xCCCCCCCCu32) >> 2) | ((v & 0x33333333u32) << 2);
    v = ((v & 0xAAAAAAAAu32) >> 1) | ((v & 0x55555555u32) << 1);
    v
}

// ---------------------------------------------------------------------------
// Constants, `deftree.c:64-125`.
// ---------------------------------------------------------------------------

const MAX_BL_BITS: usize = 7;
const END_BLOCK: usize = 256;
const REP_3_6: usize = 16;
const REPZ_3_10: usize = 17;
const REPZ_11_138: usize = 18;

// `static`, not `const`: their addresses are taken below
// (`StaticTreeDesc::extra_bits`/`static_tree`), and a `const`'s value is
// re-materialized at each use site with no fixed address -- only a
// `static` item has the one stable location a raw pointer can validly
// point at for the process lifetime. `bl_order`'s address is never taken
// (only indexed), kept `static` anyway for consistency with the C's own
// `static const` and because there is no benefit to it being different.
static extra_lbits: [i32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
static extra_dbits: [i32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
static extra_blbits: [i32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
static bl_order: [u8; BL_CODES] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// ---------------------------------------------------------------------------
// `tr_static_init()`, `deftree.c:171-236`, as real `const`s. See the module
// docs: pure functions of the four tables above, computed once by the
// compiler instead of lazily at runtime.
// ---------------------------------------------------------------------------

/// `base_length[]`/`length_code[]`, computed together (the C's first loop
/// in `tr_static_init`).
const fn compute_length_tables() -> ([i32; LENGTH_CODES], [u8; MAX_MATCH - MIN_MATCH + 1]) {
    let mut out_base_length = [0i32; LENGTH_CODES];
    let mut out_length_code = [0u8; MAX_MATCH - MIN_MATCH + 1];
    let mut length: usize = 0;
    let mut code: usize = 0;
    while code < LENGTH_CODES - 1 {
        out_base_length[code] = length as i32;
        let mut n = 0usize;
        while n < (1usize << extra_lbits[code]) {
            out_length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    // code == LENGTH_CODES - 1 here, matching the C's post-loop value.
    out_length_code[length - 1] = code as u8;
    (out_base_length, out_length_code)
}
const LENGTH_TABLES: ([i32; LENGTH_CODES], [u8; MAX_MATCH - MIN_MATCH + 1]) = compute_length_tables();
static base_length: [i32; LENGTH_CODES] = LENGTH_TABLES.0;
static length_code: [u8; MAX_MATCH - MIN_MATCH + 1] = LENGTH_TABLES.1;

/// `base_dist[]`/`dist_code[]`, computed together (the C's second loop).
const fn compute_dist_tables() -> ([i32; D_CODES], [u8; 512]) {
    let mut out_base_dist = [0i32; D_CODES];
    let mut out_dist_code = [0u8; 512];
    let mut dist: usize = 0;
    let mut code: usize = 0;
    while code < 16 {
        out_base_dist[code] = dist as i32;
        let mut n = 0usize;
        while n < (1usize << extra_dbits[code]) {
            out_dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    dist >>= 7;
    while code < D_CODES {
        out_base_dist[code] = (dist << 7) as i32;
        let mut n = 0usize;
        while n < (1usize << (extra_dbits[code] - 7)) {
            out_dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    (out_base_dist, out_dist_code)
}
const DIST_TABLES: ([i32; D_CODES], [u8; 512]) = compute_dist_tables();
static base_dist: [i32; D_CODES] = DIST_TABLES.0;
static dist_code: [u8; 512] = DIST_TABLES.1;

/// `gen_codes()`, `deftree.c:441-474`. Written once as a `const fn`; used
/// both here (compile-time, for `static_ltree`) and at runtime, from
/// `build_tree()` (for the dynamic trees) -- see the module docs.
const fn gen_codes(tree: &mut [CtData], max_code: i32, bl_count: &[Ush; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code: u16 = 0;
    let mut bits = 1usize;
    while bits <= MAX_BITS {
        code = (code.wrapping_add(bl_count[bits - 1])).wrapping_shl(1);
        next_code[bits] = code;
        bits += 1;
    }
    let mut n: i32 = 0;
    while n <= max_code {
        let len = tree[n as usize].len();
        if len != 0 {
            let c = next_code[len as usize];
            next_code[len as usize] = c.wrapping_add(1);
            tree[n as usize].set_code((bitrev32(c as u32) >> (32 - len as u32)) as u16);
        }
        n += 1;
    }
}

/// `static_ltree[]`/`static_dtree[]`, computed together (the C's third and
/// fourth sections of `tr_static_init`).
const fn compute_static_trees() -> ([CtData; L_CODES + 2], [CtData; D_CODES]) {
    let mut out_static_ltree = [CtData::zero(); L_CODES + 2];
    let mut out_static_dtree = [CtData::zero(); D_CODES];
    let mut bl_count = [0u16; MAX_BITS + 1];

    let mut n = 0usize;
    while n <= 143 {
        out_static_ltree[n].set_len(8);
        bl_count[8] += 1;
        n += 1;
    }
    while n <= 255 {
        out_static_ltree[n].set_len(9);
        bl_count[9] += 1;
        n += 1;
    }
    while n <= 279 {
        out_static_ltree[n].set_len(7);
        bl_count[7] += 1;
        n += 1;
    }
    while n <= 287 {
        out_static_ltree[n].set_len(8);
        bl_count[8] += 1;
        n += 1;
    }
    gen_codes(&mut out_static_ltree, (L_CODES + 1) as i32, &bl_count);

    let mut n = 0usize;
    while n < D_CODES {
        out_static_dtree[n].set_len(5);
        out_static_dtree[n].set_code((bitrev32(n as u32) >> (32 - 5)) as u16);
        n += 1;
    }

    (out_static_ltree, out_static_dtree)
}
const STATIC_TREES_TUPLE: ([CtData; L_CODES + 2], [CtData; D_CODES]) = compute_static_trees();
static static_ltree: [CtData; L_CODES + 2] = STATIC_TREES_TUPLE.0;
static static_dtree: [CtData; D_CODES] = STATIC_TREES_TUPLE.1;

static static_l_desc: StaticTreeDesc = StaticTreeDesc {
    static_tree: static_ltree.as_ptr(),
    extra_bits: extra_lbits.as_ptr(),
    extra_base: (LITERALS + 1) as c_int,
    elems: L_CODES as c_int,
    max_length: MAX_BITS as c_int,
};
static static_d_desc: StaticTreeDesc = StaticTreeDesc {
    static_tree: static_dtree.as_ptr(),
    extra_bits: extra_dbits.as_ptr(),
    extra_base: 0,
    elems: D_CODES as c_int,
    max_length: MAX_BITS as c_int,
};
static static_bl_desc: StaticTreeDesc = StaticTreeDesc {
    static_tree: core::ptr::null(),
    extra_bits: extra_blbits.as_ptr(),
    extra_base: 0,
    elems: BL_CODES as c_int,
    max_length: MAX_BL_BITS as c_int,
};

// ---------------------------------------------------------------------------
// Private helpers, `deftree.c:238-1058`.
// ---------------------------------------------------------------------------

const SMALLEST: usize = 1;

/// `smaller(tree, n, m, depth)`, `deftree.c:307-309`.
///
/// # Safety
/// `tree` must be valid for reads at indices `n` and `m`; `depth` must be
/// valid for reads at indices `n` and `m`.
#[inline(always)]
unsafe fn smaller(tree: *const CtData, n: usize, m: usize, depth: *const Uch) -> bool {
    // SAFETY: class B (boundary), the caller's contract.
    unsafe {
        (*tree.add(n)).freq() < (*tree.add(m)).freq()
            || ((*tree.add(n)).freq() == (*tree.add(m)).freq() && *depth.add(n) <= *depth.add(m))
    }
}

/// `init_block(s)`, `deftree.c:272-286`. No aliasing with any other
/// pointer parameter (there is none), so one continuous reborrow for the
/// whole function is fine -- nothing here calls out to another
/// `s`-touching function.
///
/// # Safety
/// `s` must be valid for writes.
unsafe fn init_block(s: *mut DeflateState) {
    // SAFETY: class B (boundary), the caller's contract. No intervening
    // call reborrows `*s`, so this one reference is live for the whole
    // function body.
    let s = unsafe { &mut *s };
    for n in 0..L_CODES {
        s.dyn_ltree[n].set_freq(0);
    }
    for n in 0..D_CODES {
        s.dyn_dtree[n].set_freq(0);
    }
    for n in 0..BL_CODES {
        s.bl_tree[n].set_freq(0);
    }
    s.dyn_ltree[END_BLOCK].set_freq(1);
    s.opt_len = 0;
    s.static_len = 0;
    s.last_lit = 0;
    s.matches = 0;
}

/// `pqdownheap(s, tree, k)`, `deftree.c:317-341`. `tree` may alias one of
/// `s`'s own tree arrays (`build_tree` calls this with `desc->dyn_tree`,
/// which is always `&mut s.dyn_ltree`/`dyn_dtree`/`bl_tree`) -- read-only
/// here, never written, so aliasing a read-only view against `s`'s own
/// `&mut` reborrow is fine as long as neither is held across a call into
/// another function (there is none in this leaf function: `smaller` is
/// `#[inline(always)]` and touches only its own raw-pointer arguments, not
/// `s`, so it does not reborrow `*s` at all).
///
/// # Safety
/// `s` must be valid for writes; `tree` must be valid for reads at every
/// index this function's own algorithm reaches (bounded by `s.heap`'s
/// contents, which the caller establishes).
unsafe fn pqdownheap(s: *mut DeflateState, tree: *const CtData, k: usize) {
    // SAFETY: class B (boundary), the caller's contract. Held for the
    // whole function: `smaller` never touches `*s`, so there is no
    // intervening reborrow to invalidate this one.
    let s = unsafe { &mut *s };
    let mut k = k;
    let v = s.heap[k];
    let mut j = k << 1;
    while j <= s.heap_len as usize {
        // SAFETY: class B (boundary), forwarded.
        if j < s.heap_len as usize && unsafe { smaller(tree, s.heap[j + 1] as usize, s.heap[j] as usize, s.depth.as_ptr()) } {
            j += 1;
        }
        // SAFETY: class B (boundary), forwarded.
        if unsafe { smaller(tree, v as usize, s.heap[j] as usize, s.depth.as_ptr()) } {
            break;
        }
        s.heap[k] = s.heap[j];
        k = j;
        j <<= 1;
    }
    s.heap[k] = v;
}

/// `gen_bitlen(s, desc)`, `deftree.c:353-431`.
///
/// # Safety
/// `s` must be valid for writes; `desc` valid for reads; `desc.dyn_tree`
/// (aliasing one of `s`'s own tree arrays at every real call site -- see
/// the module docs) valid for reads and writes at every index this
/// function's algorithm reaches (bounded by `s.heap`'s contents, the
/// caller's responsibility, same as the C).
unsafe fn gen_bitlen(s: *mut DeflateState, desc: *const TreeDesc) {
    // SAFETY: class B (boundary), the caller's contract. Read once, not
    // held across any call.
    let (tree, max_code, stat_desc) = unsafe { ((*desc).dyn_tree, (*desc).max_code, (*desc).stat_desc) };
    // SAFETY: class B (boundary), forwarded.
    let (stree, extra, base, max_length) =
        unsafe { ((*stat_desc).static_tree, (*stat_desc).extra_bits, (*stat_desc).extra_base, (*stat_desc).max_length) };

    // SAFETY: class B (boundary), the caller's contract. Held for a
    // stretch with no intervening call into another `s`-touching function.
    let s = unsafe { &mut *s };
    for bits in 0..=MAX_BITS {
        s.bl_count[bits] = 0;
    }

    let heap_max = s.heap_max as usize;
    // SAFETY: class B (boundary). `s.heap[s.heap_max]` is a valid tree
    // index by the caller's contract (same invariant the C relies on).
    unsafe { (*tree.add(s.heap[heap_max] as usize)).set_len(0) };

    let mut overflow: i32 = 0;
    let mut h = heap_max + 1;
    while h < HEAP_SIZE {
        let n = s.heap[h] as usize;
        // SAFETY: class B (boundary). `tree[n].Dad` was set by `build_tree`
        // before this function runs, for every `n` reachable through
        // `s.heap` here.
        let dad = unsafe { (*tree.add(n)).dad() as usize };
        // SAFETY: class B (boundary).
        let mut bits = unsafe { (*tree.add(dad)).len() as i32 } + 1;
        if bits > max_length {
            bits = max_length;
            overflow += 1;
        }
        // SAFETY: class B (boundary).
        unsafe { (*tree.add(n)).set_len(bits as u16) };
        if n > max_code as usize {
            h += 1;
            continue;
        }
        s.bl_count[bits as usize] += 1;
        let mut xbits = 0i32;
        if n as i32 >= base {
            // SAFETY: class B (boundary). `extra` has `elems` entries
            // (`(*stat_desc).elems`), and `n - base` is in range for every
            // tree this is called with -- the same invariant the C relies
            // on (`extra[n-base]`, no bounds check there either).
            xbits = unsafe { *extra.add((n as i32 - base) as usize) };
        }
        // SAFETY: class B (boundary).
        let f = unsafe { (*tree.add(n)).freq() };
        s.opt_len = s.opt_len.wrapping_add((f as Ulg).wrapping_mul((bits + xbits) as Ulg));
        if !stree.is_null() {
            // SAFETY: class B (boundary). `stree` (when non-null) has the
            // same shape as `tree` here.
            let slen = unsafe { (*stree.add(n)).len() };
            s.static_len = s.static_len.wrapping_add((f as Ulg).wrapping_mul((slen as i32 + xbits) as Ulg));
        }
        h += 1;
    }
    if overflow == 0 {
        return;
    }

    loop {
        let mut bits = (max_length - 1) as usize;
        while s.bl_count[bits] == 0 {
            bits -= 1;
        }
        s.bl_count[bits] -= 1;
        s.bl_count[bits + 1] += 2;
        s.bl_count[max_length as usize] -= 1;
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }

    let mut bits = max_length;
    while bits != 0 {
        let mut n = s.bl_count[bits as usize];
        while n != 0 {
            h -= 1;
            let m = s.heap[h] as usize;
            if m > max_code as usize {
                continue;
            }
            // SAFETY: class B (boundary).
            if unsafe { (*tree.add(m)).len() as i32 } != bits {
                // SAFETY: class B (boundary).
                let (old_len, freq) = unsafe { ((*tree.add(m)).len() as i64, (*tree.add(m)).freq() as i64) };
                let delta = (bits as i64 - old_len).wrapping_mul(freq);
                s.opt_len = (s.opt_len as i64).wrapping_add(delta) as Ulg;
                // SAFETY: class B (boundary).
                unsafe { (*tree.add(m)).set_len(bits as u16) };
            }
            n -= 1;
        }
        bits -= 1;
    }
}

/// `build_tree(s, desc)`, `deftree.c:484-566`.
///
/// # Safety
/// `s` must be valid for writes; `desc` valid for reads and writes;
/// `desc.dyn_tree` (aliasing one of `s`'s own tree arrays -- see the module
/// docs) valid for reads and writes at indices `0..elems` and, once
/// internal nodes are created, up to `2 * elems`.
unsafe fn build_tree(s: *mut DeflateState, desc: *mut TreeDesc) {
    // SAFETY: class B (boundary), the caller's contract. Read once.
    let (tree, stree, elems) = unsafe { ((*desc).dyn_tree, (*(*desc).stat_desc).static_tree, (*(*desc).stat_desc).elems) };

    // SAFETY: class B (boundary), the caller's contract.
    let s_ref = unsafe { &mut *s };
    s_ref.heap_len = 0;
    s_ref.heap_max = HEAP_SIZE as c_int;

    let mut max_code: i32 = -1;
    for n in 0..elems as usize {
        // SAFETY: class B (boundary), the caller's contract.
        if unsafe { (*tree.add(n)).freq() } != 0 {
            s_ref.heap_len += 1;
            let hl = s_ref.heap_len as usize;
            s_ref.heap[hl] = n as c_int;
            max_code = n as i32;
            s_ref.depth[n] = 0;
        } else {
            // SAFETY: class B (boundary).
            unsafe { (*tree.add(n)).set_len(0) };
        }
    }

    while s_ref.heap_len < 2 {
        let node = if max_code < 2 {
            max_code += 1;
            max_code
        } else {
            0
        };
        s_ref.heap_len += 1;
        let hl = s_ref.heap_len as usize;
        s_ref.heap[hl] = node;
        let node = node as usize;
        // SAFETY: class B (boundary).
        unsafe { (*tree.add(node)).set_freq(1) };
        s_ref.depth[node] = 0;
        s_ref.opt_len = s_ref.opt_len.wrapping_sub(1);
        if !stree.is_null() {
            // SAFETY: class B (boundary).
            let slen = unsafe { (*stree.add(node)).len() };
            s_ref.static_len = s_ref.static_len.wrapping_sub(slen as Ulg);
        }
    }
    // SAFETY: class B (boundary), the caller's contract.
    unsafe { (*desc).max_code = max_code };

    {
        let mut n = (s_ref.heap_len / 2) as usize;
        while n >= 1 {
            // SAFETY: class B (boundary), forwarded.
            unsafe { pqdownheap(s, tree, n) };
            n -= 1;
        }
    }

    let mut node = elems as usize;
    loop {
        // `pqremove(s, tree, n)`, `deftree.c:296-301`.
        // SAFETY: class B (boundary). Reborrowed fresh: `pqdownheap` just
        // reborrowed `*s` above (first iteration) or below (subsequent
        // ones).
        let s_ref = unsafe { &mut *s };
        let n = s_ref.heap[SMALLEST] as usize;
        let hl = s_ref.heap_len as usize;
        s_ref.heap[SMALLEST] = s_ref.heap[hl];
        s_ref.heap_len -= 1;
        // SAFETY: class B (boundary), forwarded.
        unsafe { pqdownheap(s, tree, SMALLEST) };

        // SAFETY: class B (boundary). Reborrowed fresh after `pqdownheap`.
        let s_ref = unsafe { &mut *s };
        let m = s_ref.heap[SMALLEST] as usize;

        s_ref.heap_max -= 1;
        let hm = s_ref.heap_max as usize;
        s_ref.heap[hm] = n as c_int;
        s_ref.heap_max -= 1;
        let hm = s_ref.heap_max as usize;
        s_ref.heap[hm] = m as c_int;

        // SAFETY: class B (boundary).
        let (fn_, fm) = unsafe { ((*tree.add(n)).freq(), (*tree.add(m)).freq()) };
        // SAFETY: class B (boundary).
        unsafe { (*tree.add(node)).set_freq(fn_.wrapping_add(fm)) };
        s_ref.depth[node] = core::cmp::max(s_ref.depth[n], s_ref.depth[m]) + 1;
        // SAFETY: class B (boundary).
        unsafe {
            (*tree.add(n)).set_dad(node as u16);
            (*tree.add(m)).set_dad(node as u16);
        }

        let s_ref = unsafe { &mut *s };
        s_ref.heap[SMALLEST] = node as c_int;
        node += 1;
        // SAFETY: class B (boundary), forwarded.
        unsafe { pqdownheap(s, tree, SMALLEST) };

        // SAFETY: class B (boundary). Reborrowed fresh after `pqdownheap`.
        let s_ref = unsafe { &mut *s };
        if s_ref.heap_len < 2 {
            break;
        }
    }

    // SAFETY: class B (boundary).
    let s_ref = unsafe { &mut *s };
    s_ref.heap_max -= 1;
    let hm = s_ref.heap_max as usize;
    s_ref.heap[hm] = s_ref.heap[SMALLEST];

    // SAFETY: class B (boundary), forwarded.
    unsafe { gen_bitlen(s, desc) };

    // SAFETY: class B (boundary), the caller's contract. `s.bl_count` was
    // just filled in by `gen_bitlen`.
    let s_ref = unsafe { &mut *s };
    // SAFETY: class B (boundary), forwarded.
    unsafe {
        let tree_slice = core::slice::from_raw_parts_mut(tree, 2 * elems as usize + 1);
        gen_codes(tree_slice, max_code, &s_ref.bl_count);
    }
}

/// `scan_tree(s, tree, max_code)`, `deftree.c:572-612`.
///
/// # Safety
/// `s` must be valid for writes; `tree` (aliasing one of `s`'s own tree
/// arrays at every real call site) valid for reads and writes at indices
/// `0..=max_code+1`.
unsafe fn scan_tree(s: *mut DeflateState, tree: *mut CtData, max_code: i32) {
    let mut prevlen: i32 = -1;
    // SAFETY: class B (boundary), the caller's contract.
    let mut nextlen = unsafe { (*tree).len() as i32 };
    let mut count: i32 = 0;
    let mut max_count: i32 = 7;
    let mut min_count: i32 = 4;
    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }
    // SAFETY: class B (boundary). `tree` has `max_code + 2` valid entries
    // at every real call site (the guard slot past the tree's own last
    // used index).
    unsafe { (*tree.add((max_code + 1) as usize)).set_len(0xffff) };

    let mut n: i32 = 0;
    while n <= max_code {
        let curlen = nextlen;
        // SAFETY: class B (boundary).
        nextlen = unsafe { (*tree.add((n + 1) as usize)).len() as i32 };
        count += 1;
        if count < max_count && curlen == nextlen {
            n += 1;
            continue;
        }
        // SAFETY: class B (boundary), the caller's contract.
        let s = unsafe { &mut *s };
        if count < min_count {
            s.bl_tree[curlen as usize].set_freq(s.bl_tree[curlen as usize].freq().wrapping_add(count as u16));
        } else if curlen != 0 {
            if curlen != prevlen {
                s.bl_tree[curlen as usize].set_freq(s.bl_tree[curlen as usize].freq().wrapping_add(1));
            }
            s.bl_tree[REP_3_6].set_freq(s.bl_tree[REP_3_6].freq().wrapping_add(1));
        } else if count <= 10 {
            s.bl_tree[REPZ_3_10].set_freq(s.bl_tree[REPZ_3_10].freq().wrapping_add(1));
        } else {
            s.bl_tree[REPZ_11_138].set_freq(s.bl_tree[REPZ_11_138].freq().wrapping_add(1));
        }
        count = 0;
        prevlen = curlen;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
        n += 1;
    }
}

/// `send_tree(s, tree, max_code)`, `deftree.c:618-664`.
///
/// # Safety
/// `s` must be valid for writes; `tree` (aliasing one of `s`'s own tree
/// arrays at every real call site) valid for reads at indices
/// `0..=max_code+1`; `s.bl_tree` must hold valid codes (set by
/// `build_bl_tree`, before this is ever called).
unsafe fn send_tree(s: *mut DeflateState, tree: *const CtData, max_code: i32) {
    let mut prevlen: i32 = -1;
    // SAFETY: class B (boundary), the caller's contract.
    let mut nextlen = unsafe { (*tree).len() as i32 };
    let mut count: i32 = 0;
    let mut max_count: i32 = 7;
    let mut min_count: i32 = 4;
    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }

    let mut n: i32 = 0;
    while n <= max_code {
        let curlen = nextlen;
        // SAFETY: class B (boundary).
        nextlen = unsafe { (*tree.add((n + 1) as usize)).len() as i32 };
        count += 1;
        if count < max_count && curlen == nextlen {
            n += 1;
            continue;
        }
        if count < min_count {
            loop {
                // SAFETY: class B (boundary), forwarded. `s.bl_tree` is
                // `2*BL_CODES+1` entries, `curlen <= MAX_BITS` (15), well
                // in range.
                unsafe { send_code(s, curlen as usize, s_bl_tree_ptr(s)) };
                count -= 1;
                if count == 0 {
                    break;
                }
            }
        } else if curlen != 0 {
            if curlen != prevlen {
                // SAFETY: class B (boundary), forwarded.
                unsafe { send_code(s, curlen as usize, s_bl_tree_ptr(s)) };
                count -= 1;
            }
            // SAFETY: class B (boundary), forwarded.
            unsafe {
                send_code(s, REP_3_6, s_bl_tree_ptr(s));
                send_bits(s, count - 3, 2);
            }
        } else if count <= 10 {
            // SAFETY: class B (boundary), forwarded.
            unsafe {
                send_code(s, REPZ_3_10, s_bl_tree_ptr(s));
                send_bits(s, count - 3, 3);
            }
        } else {
            // SAFETY: class B (boundary), forwarded.
            unsafe {
                send_code(s, REPZ_11_138, s_bl_tree_ptr(s));
                send_bits(s, count - 11, 7);
            }
        }
        count = 0;
        prevlen = curlen;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
        n += 1;
    }
}

/// `&s->bl_tree[0]` as a raw pointer, freshly re-derived at each call site
/// rather than cached in a local -- `send_code`/`send_bits` reborrow `*s`
/// internally, so a stale `*const CtData` computed before such a call and
/// reused after it would be exactly the aliasing hazard the module docs
/// flag; re-deriving it fresh from `s` every time sidesteps that.
///
/// # Safety
/// `s` must be valid for reads.
#[inline(always)]
unsafe fn s_bl_tree_ptr(s: *mut DeflateState) -> *const CtData {
    // SAFETY: class B (boundary), the caller's contract. This reborrow is
    // used only to compute an address (`.as_ptr()`), not held.
    unsafe { (*s).bl_tree.as_ptr() }
}

/// `build_bl_tree(s)`, `deftree.c:670-699`.
///
/// # Safety
/// `s` must be valid for writes.
unsafe fn build_bl_tree(s: *mut DeflateState) -> i32 {
    // SAFETY: class B (boundary), the caller's contract.
    let (ltree_ptr, l_max_code, dtree_ptr, d_max_code) = unsafe {
        let sr = &*s;
        (sr.dyn_ltree.as_ptr() as *mut CtData, sr.l_desc.max_code, sr.dyn_dtree.as_ptr() as *mut CtData, sr.d_desc.max_code)
    };
    // SAFETY: class B (boundary), forwarded.
    unsafe {
        scan_tree(s, ltree_ptr, l_max_code);
        scan_tree(s, dtree_ptr, d_max_code);
    }

    // SAFETY: class B (boundary), forwarded. `&mut (*s).bl_desc` -- taking
    // this address does not read/hold any other part of `*s`.
    unsafe { build_tree(s, &mut (*s).bl_desc as *mut TreeDesc) };

    let mut max_blindex: i32 = BL_CODES as i32 - 1;
    // SAFETY: class B (boundary), the caller's contract.
    let s_ref = unsafe { &mut *s };
    while max_blindex >= 3 {
        if s_ref.bl_tree[bl_order[max_blindex as usize] as usize].len() != 0 {
            break;
        }
        max_blindex -= 1;
    }
    s_ref.opt_len = s_ref
        .opt_len
        .wrapping_add((3 * (max_blindex + 1) + 5 + 5 + 4) as Ulg);

    max_blindex
}

/// `send_all_trees(s, lcodes, dcodes, blcodes)`, `deftree.c:706-733`.
///
/// # Safety
/// `s` must be valid for writes; `s.dyn_ltree`/`dyn_dtree` valid for reads
/// up to `lcodes`/`dcodes`; `s.bl_tree` holds valid codes (set by
/// `build_bl_tree`, always called first).
unsafe fn send_all_trees(s: *mut DeflateState, lcodes: i32, dcodes: i32, blcodes: i32) {
    // SAFETY: class B (boundary), forwarded.
    unsafe {
        send_bits(s, lcodes - 257, 5);
        send_bits(s, dcodes - 1, 5);
        send_bits(s, blcodes - 4, 4);
    }
    for rank in 0..blcodes {
        // SAFETY: class B (boundary). `s.bl_tree` reborrowed fresh each
        // iteration, not held across `send_bits`.
        let len = unsafe { (*s).bl_tree[bl_order[rank as usize] as usize].len() };
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_bits(s, len as c_int, 3) };
    }

    // SAFETY: class B (boundary).
    let (ltree_ptr, dtree_ptr) = unsafe { ((*s).dyn_ltree.as_ptr(), (*s).dyn_dtree.as_ptr()) };
    // SAFETY: class B (boundary), forwarded.
    unsafe {
        send_tree(s, ltree_ptr, lcodes - 1);
        send_tree(s, dtree_ptr, dcodes - 1);
    }
}

/// `d_code(dist)`, `deftree.c:159-160`.
#[inline(always)]
fn d_code(dist: u32) -> usize {
    if dist < 256 {
        dist_code[dist as usize] as usize
    } else {
        dist_code[256 + (dist >> 7) as usize] as usize
    }
}

/// `compress_block(s, ltree, dtree)`, `deftree.c:964-1010`.
///
/// # Safety
/// `s` must be valid for writes; `ltree`/`dtree` (aliasing one of `s`'s own
/// tree arrays, or the `static_ltree`/`static_dtree` consts, at every real
/// call site) valid for reads at every code this function looks up.
unsafe fn compress_block(s: *mut DeflateState, ltree: *const CtData, dtree: *const CtData) {
    // SAFETY: class B (boundary), the caller's contract.
    let last_lit = unsafe { (*s).last_lit };
    if last_lit != 0 {
        let mut lx: usize = 0;
        loop {
            // SAFETY: class B (boundary).
            let (dist, lc) = unsafe { ((*s).d_buf.add(lx).read() as u32, (*s).l_buf.add(lx).read() as i32) };
            lx += 1;
            if dist == 0 {
                // SAFETY: class B (boundary), forwarded.
                unsafe { send_code(s, lc as usize, ltree) };
            } else {
                let code = length_code[lc as usize] as usize;
                // SAFETY: class B (boundary), forwarded.
                unsafe { send_code(s, code + LITERALS + 1, ltree) };
                let extra = extra_lbits[code];
                let mut lc = lc;
                if extra != 0 {
                    lc -= base_length[code];
                    // SAFETY: class B (boundary), forwarded.
                    unsafe { send_bits(s, lc, extra) };
                }
                let dist = dist - 1;
                let code = d_code(dist);
                // SAFETY: class B (boundary), forwarded.
                unsafe { send_code(s, code, dtree) };
                let extra = extra_dbits[code];
                if extra != 0 {
                    let dist = dist - base_dist[code] as u32;
                    // SAFETY: class B (boundary), forwarded.
                    unsafe { send_bits(s, dist as c_int, extra) };
                }
            }
            if lx >= last_lit as usize {
                break;
            }
        }
    }
    // SAFETY: class B (boundary), forwarded.
    unsafe { send_code(s, END_BLOCK, ltree) };
    // SAFETY: class B (boundary).
    let eob_len = unsafe { (*ltree.add(END_BLOCK)).len() };
    // SAFETY: class B (boundary), the caller's contract.
    unsafe { (*s).last_eob_len = eob_len as c_int };
}

/// `set_data_type(s)`, `deftree.c:1018-1029`.
///
/// # Safety
/// `s` must be valid for writes.
unsafe fn set_data_type(s: *mut DeflateState) {
    // SAFETY: class B (boundary), the caller's contract. One continuous
    // reborrow: no intervening call into another `s`-touching function.
    let s = unsafe { &mut *s };
    let mut n = 0usize;
    let mut ascii_freq: u32 = 0;
    let mut bin_freq: u32 = 0;
    while n < 7 {
        bin_freq = bin_freq.wrapping_add(s.dyn_ltree[n].freq() as u32);
        n += 1;
    }
    while n < 128 {
        ascii_freq = ascii_freq.wrapping_add(s.dyn_ltree[n].freq() as u32);
        n += 1;
    }
    while n < LITERALS {
        bin_freq = bin_freq.wrapping_add(s.dyn_ltree[n].freq() as u32);
        n += 1;
    }
    s.data_type = if bin_freq > (ascii_freq >> 2) { Z_BINARY } else { Z_ASCII };
}

/// `copy_block(s, buf, len, header)`, `deftree.c:1035-1058`.
///
/// # Safety
/// `s` must be valid for writes; `buf` valid for reads for `len` bytes;
/// `s.pending_buf` valid for writes for `s.pending_buf_size` bytes (the
/// same invariant `put_byte` documents -- checked below, not assumed).
unsafe fn copy_block(s: *mut DeflateState, buf: *const c_char, len: c_uint, header: c_int) {
    // SAFETY: class B (boundary), forwarded.
    unsafe { bi_windup(s) };
    // SAFETY: class B (boundary). Reborrowed fresh after `bi_windup`.
    let s_ref = unsafe { &mut *s };
    s_ref.last_eob_len = 8;

    if header != 0 {
        // SAFETY: class B (boundary), forwarded, twice.
        unsafe {
            put_short(s, len as Ush);
            put_short(s, !(len as Ush));
        }
    }
    // SAFETY: class B (boundary). Reborrowed fresh after the `put_short`
    // calls (which reborrow `*s` internally).
    let s_ref = unsafe { &mut *s };
    // Real catch, not restated: same reasoning as `put_byte` -- the C's
    // `memcpy` here has no bounds check of its own either.
    assert!(
        (s_ref.pending as c_ulong).wrapping_add(len as c_ulong) <= s_ref.pending_buf_size,
        "pending_buf overflow"
    );
    // SAFETY: class C (construction). Just asserted the write stays within
    // `s_ref.pending_buf`'s `pending_buf_size` bytes; `buf` is `len` bytes
    // readable by the caller's contract.
    unsafe {
        core::ptr::copy_nonoverlapping(buf as *const u8, s_ref.pending_buf.add(s_ref.pending as usize), len as usize)
    };
    s_ref.pending += len as c_int;
}

// ---------------------------------------------------------------------------
// The six entry points, `deftree.c:241-267,738-959`. No `EXPORT_SYMBOL` of
// their own -- see the module docs -- so plain `#[no_mangle]`, no
// `kernel::kabi_export!`.
// ---------------------------------------------------------------------------

/// `zlib_tr_init(s)`, `deftree.c:241-267`. `tr_static_init()` is not
/// called -- there is nothing left for it to do, since every table it
/// built at runtime is a real `const`/`static` here (see the module docs).
///
/// # Safety
/// `s` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_init(s: *mut DeflateState) {
    // SAFETY: class B (boundary), the caller's contract.
    let s_ref = unsafe { &mut *s };
    s_ref.compressed_len = 0;

    s_ref.l_desc.dyn_tree = s_ref.dyn_ltree.as_mut_ptr();
    s_ref.l_desc.stat_desc = &static_l_desc;
    s_ref.d_desc.dyn_tree = s_ref.dyn_dtree.as_mut_ptr();
    s_ref.d_desc.stat_desc = &static_d_desc;
    s_ref.bl_desc.dyn_tree = s_ref.bl_tree.as_mut_ptr();
    s_ref.bl_desc.stat_desc = &static_bl_desc;

    s_ref.bi_buf = 0;
    s_ref.bi_valid = 0;
    s_ref.last_eob_len = 8;

    // SAFETY: class B (boundary), forwarded.
    unsafe { init_block(s) };
}

/// `zlib_tr_stored_block(s, buf, stored_len, eof)`, `deftree.c:738-750`.
///
/// # Safety
/// `s` must be valid for writes; `buf` valid for reads for `stored_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_stored_block(s: *mut DeflateState, buf: *const c_char, stored_len: Ulg, eof: c_int) {
    // SAFETY: class B (boundary), forwarded.
    unsafe { send_bits(s, (STORED_BLOCK << 1) + eof, 3) };
    // SAFETY: class B (boundary). Reborrowed fresh after `send_bits`.
    let s_ref = unsafe { &mut *s };
    s_ref.compressed_len = (s_ref.compressed_len.wrapping_add(3).wrapping_add(7)) & !7u64;
    s_ref.compressed_len = s_ref.compressed_len.wrapping_add((stored_len.wrapping_add(4)) << 3);
    // SAFETY: class B (boundary), forwarded.
    unsafe { copy_block(s, buf, stored_len as c_uint, 1) };
}

/// `zlib_tr_stored_type_only(s)`, `deftree.c:754-761`.
///
/// # Safety
/// `s` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_stored_type_only(s: *mut DeflateState) {
    // SAFETY: class B (boundary), forwarded.
    unsafe { send_bits(s, STORED_BLOCK << 1, 3) };
    // SAFETY: class B (boundary), forwarded.
    unsafe { bi_windup(s) };
    // SAFETY: class B (boundary). Reborrowed fresh after `bi_windup`.
    let s_ref = unsafe { &mut *s };
    s_ref.compressed_len = (s_ref.compressed_len.wrapping_add(3)) & !7u64;
}

/// `zlib_tr_align(s)`, `deftree.c:775-795`.
///
/// # Safety
/// `s` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_align(s: *mut DeflateState) {
    // SAFETY: class B (boundary), forwarded.
    unsafe { send_bits(s, STATIC_TREES << 1, 3) };
    // SAFETY: class B (boundary), forwarded. `static_ltree` is `'static`.
    unsafe { send_code(s, END_BLOCK, static_ltree.as_ptr()) };
    // SAFETY: class B (boundary). Reborrowed fresh after `send_code`.
    let s_ref = unsafe { &mut *s };
    s_ref.compressed_len = s_ref.compressed_len.wrapping_add(10);
    // SAFETY: class B (boundary), forwarded.
    unsafe { bi_flush(s) };

    // SAFETY: class B (boundary). Reborrowed fresh after `bi_flush`.
    let s_ref = unsafe { &mut *s };
    if 1 + s_ref.last_eob_len + 10 - s_ref.bi_valid < 9 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_bits(s, STATIC_TREES << 1, 3) };
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_code(s, END_BLOCK, static_ltree.as_ptr()) };
        // SAFETY: class B (boundary). Reborrowed fresh after `send_code`.
        let s_ref = unsafe { &mut *s };
        s_ref.compressed_len = s_ref.compressed_len.wrapping_add(10);
        // SAFETY: class B (boundary), forwarded.
        unsafe { bi_flush(s) };
    }
    // SAFETY: class B (boundary). Reborrowed fresh after the (possibly
    // skipped) second `bi_flush`.
    let s_ref = unsafe { &mut *s };
    s_ref.last_eob_len = 7;
}

/// `zlib_tr_tally(s, dist, lc)`, `deftree.c:915-959`.
///
/// # Safety
/// `s` must be valid for writes; `s.d_buf`/`s.l_buf` valid for writes at
/// index `s.last_lit`.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_tally(s: *mut DeflateState, dist: c_uint, lc: c_uint) -> c_int {
    // SAFETY: class B (boundary), the caller's contract. One continuous
    // reborrow: no intervening call into another `s`-touching function
    // (only raw `d_buf`/`l_buf` writes, which are separate allocations,
    // not aliasing `*s` itself).
    let s = unsafe { &mut *s };
    let last_lit = s.last_lit as usize;
    // SAFETY: class B (boundary). `s.d_buf`/`s.l_buf` are valid for writes
    // at `last_lit` by the caller's contract.
    unsafe {
        *s.d_buf.add(last_lit) = dist as Ush;
        *s.l_buf.add(last_lit) = lc as Uch;
    }
    s.last_lit += 1;

    if dist == 0 {
        s.dyn_ltree[lc as usize].set_freq(s.dyn_ltree[lc as usize].freq().wrapping_add(1));
    } else {
        s.matches += 1;
        let dist = dist - 1;
        s.dyn_ltree[length_code[lc as usize] as usize + LITERALS + 1]
            .set_freq(s.dyn_ltree[length_code[lc as usize] as usize + LITERALS + 1].freq().wrapping_add(1));
        let dc = d_code(dist);
        // `Assert((ush)dist < (ush)MAX_DIST(s) && (ush)d_code(dist) <
        // (ush)D_CODES, "zlib_tr_tally: bad match")`, deftree.c:930-932 --
        // a debug-only check in the C (compiled out at `!DEBUG_ZLIB`, same
        // as every other `Assert` in this file), reproduced the same way
        // this project already translates zlib's should-not-happen
        // checks (mpih_div_rs.rs). `dc < D_CODES` is also backstopped by
        // Rust's own array-bounds panic on the indexing right below --
        // same shape as the zlib_inflate MATCH-state case, where the
        // language's indexing already subsumes the dropped C guard for
        // release builds -- but the guard is kept explicit here too so
        // both halves of the C's invariant stay documented and checked
        // in exactly the builds that check anything else in this file.
        debug_assert!(
            dist < s.w_size.wrapping_sub(MIN_LOOKAHEAD) && dc < D_CODES,
            "zlib_tr_tally: bad match"
        );
        s.dyn_dtree[dc].set_freq(s.dyn_dtree[dc].freq().wrapping_add(1));
    }

    if (s.last_lit & 0xfff) == 0 && s.level > 2 {
        let mut out_length: u64 = (s.last_lit as u64).wrapping_mul(8);
        let in_length = (s.strstart as i64).wrapping_sub(s.block_start) as u64;
        for dcode in 0..D_CODES {
            out_length = out_length
                .wrapping_add((s.dyn_dtree[dcode].freq() as u64).wrapping_mul((5 + extra_dbits[dcode]) as u64));
        }
        out_length >>= 3;
        // Not adding an `in_length != 0` guard the C doesn't have: the C
        // divides by `in_length` unconditionally here too
        // (`out_length*100L/in_length` in the `Tracev`, dead at
        // `!DEBUG_ZLIB`, but this comparison has the same shape and no
        // guard either). If `in_length` can genuinely be zero at this
        // point, the C's behavior is already undefined (division by zero);
        // Rust's checked division panics instead, which is the correct
        // "leave checked" treatment for a case that was already a latent
        // problem in the reference, not a new one this port introduces.
        if (s.matches as u64) < (s.last_lit as u64) / 2 && out_length < in_length / 2 {
            return 1;
        }
    }
    (s.last_lit == s.lit_bufsize - 1) as c_int
}

/// `zlib_tr_flush_block(s, buf, stored_len, eof)`, `deftree.c:802-909`.
///
/// # Safety
/// `s` must be valid for writes; `buf`, if non-null, valid for reads for
/// `stored_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zlib_tr_flush_block(s: *mut DeflateState, buf: *const c_char, stored_len: Ulg, eof: c_int) -> Ulg {
    let mut opt_lenb: Ulg;
    let static_lenb: Ulg;
    let mut max_blindex: i32 = 0;

    // SAFETY: class B (boundary), the caller's contract.
    let level = unsafe { (*s).level };
    if level > 0 {
        // SAFETY: class B (boundary).
        if unsafe { (*s).data_type } == Z_UNKNOWN {
            // SAFETY: class B (boundary), forwarded.
            unsafe { set_data_type(s) };
        }

        // SAFETY: class B (boundary), forwarded. `&mut (*s).l_desc`/
        // `&mut (*s).d_desc` -- taking these addresses does not read/hold
        // any other part of `*s`.
        unsafe {
            build_tree(s, &mut (*s).l_desc as *mut TreeDesc);
            build_tree(s, &mut (*s).d_desc as *mut TreeDesc);
        }

        // SAFETY: class B (boundary), forwarded.
        max_blindex = unsafe { build_bl_tree(s) };

        // SAFETY: class B (boundary).
        let (opt_len, static_len) = unsafe { ((*s).opt_len, (*s).static_len) };
        opt_lenb = (opt_len.wrapping_add(3).wrapping_add(7)) >> 3;
        static_lenb = (static_len.wrapping_add(3).wrapping_add(7)) >> 3;

        if static_lenb <= opt_lenb {
            opt_lenb = static_lenb;
        }
    } else {
        debug_assert!(!buf.is_null());
        opt_lenb = stored_len.wrapping_add(5);
        static_lenb = stored_len.wrapping_add(5);
    }

    if stored_len.wrapping_add(4) <= opt_lenb && !buf.is_null() {
        // SAFETY: class B (boundary), forwarded.
        unsafe { zlib_tr_stored_block(s, buf, stored_len, eof) };
    } else if static_lenb == opt_lenb {
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_bits(s, (STATIC_TREES << 1) + eof, 3) };
        // SAFETY: class B (boundary), forwarded. `static_ltree`/
        // `static_dtree` are `'static`.
        unsafe { compress_block(s, static_ltree.as_ptr(), static_dtree.as_ptr()) };
        // SAFETY: class B (boundary). Reborrowed fresh after
        // `compress_block`.
        let s_ref = unsafe { &mut *s };
        s_ref.compressed_len = s_ref.compressed_len.wrapping_add(3).wrapping_add(s_ref.static_len);
    } else {
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_bits(s, (DYN_TREES << 1) + eof, 3) };
        // SAFETY: class B (boundary).
        let (l_max_code, d_max_code) = unsafe { ((*s).l_desc.max_code, (*s).d_desc.max_code) };
        // SAFETY: class B (boundary), forwarded.
        unsafe { send_all_trees(s, l_max_code + 1, d_max_code + 1, max_blindex + 1) };
        // SAFETY: class B (boundary).
        let (ltree_ptr, dtree_ptr) = unsafe { ((*s).dyn_ltree.as_ptr(), (*s).dyn_dtree.as_ptr()) };
        // SAFETY: class B (boundary), forwarded.
        unsafe { compress_block(s, ltree_ptr, dtree_ptr) };
        // SAFETY: class B (boundary). Reborrowed fresh after
        // `compress_block`.
        let s_ref = unsafe { &mut *s };
        s_ref.compressed_len = s_ref.compressed_len.wrapping_add(3).wrapping_add(s_ref.opt_len);
    }

    // SAFETY: class B (boundary), forwarded.
    unsafe { init_block(s) };

    if eof != 0 {
        // SAFETY: class B (boundary), forwarded.
        unsafe { bi_windup(s) };
        // SAFETY: class B (boundary). Reborrowed fresh after `bi_windup`.
        let s_ref = unsafe { &mut *s };
        s_ref.compressed_len = s_ref.compressed_len.wrapping_add(7);
    }

    // SAFETY: class B (boundary).
    unsafe { (*s).compressed_len >> 3 }
}

// ---------------------------------------------------------------------------
// ABI check -- offsets and sizes the harness compares against offsetof() on
// the real `defutil.h`. Not exercised by any caller in the kernel; exists so
// `port/test/deftree/` can prove the full-struct mirror stayed in step,
// same convention as `inffast_rs_abi`/`inftrees_rs_abi`/`inflate_rs_abi`.
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn deftree_rs_abi(out: *mut u64) {
    let vals: [u64; 22] = [
        core::mem::size_of::<DeflateState>() as u64,
        core::mem::offset_of!(DeflateState, strm) as u64,
        core::mem::offset_of!(DeflateState, status) as u64,
        core::mem::offset_of!(DeflateState, pending_buf) as u64,
        core::mem::offset_of!(DeflateState, pending) as u64,
        core::mem::offset_of!(DeflateState, data_type) as u64,
        core::mem::offset_of!(DeflateState, w_bits) as u64,
        core::mem::offset_of!(DeflateState, window) as u64,
        core::mem::offset_of!(DeflateState, block_start) as u64,
        core::mem::offset_of!(DeflateState, strstart) as u64,
        core::mem::offset_of!(DeflateState, level) as u64,
        core::mem::offset_of!(DeflateState, dyn_ltree) as u64,
        core::mem::offset_of!(DeflateState, dyn_dtree) as u64,
        core::mem::offset_of!(DeflateState, bl_tree) as u64,
        core::mem::offset_of!(DeflateState, l_desc) as u64,
        core::mem::offset_of!(DeflateState, bl_count) as u64,
        core::mem::offset_of!(DeflateState, heap) as u64,
        core::mem::offset_of!(DeflateState, l_buf) as u64,
        core::mem::offset_of!(DeflateState, d_buf) as u64,
        core::mem::offset_of!(DeflateState, opt_len) as u64,
        core::mem::offset_of!(DeflateState, compressed_len) as u64,
        core::mem::offset_of!(DeflateState, bi_buf) as u64,
    ];
    // SAFETY: class B (boundary), the caller's contract: `out` valid for
    // `vals.len()` writes.
    unsafe { core::ptr::copy_nonoverlapping(vals.as_ptr(), out, vals.len()) };
}

// Table-content accessors for `port/test/deftree/`, so the differential can
// compare the const-computed tables directly against the C's
// runtime-computed ones (same convention as `inffixed_rs_table`), not only
// indirectly through compressed-output bytes.
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_base_length_ptr() -> *const i32 { base_length.as_ptr() }
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_length_code_ptr() -> *const u8 { length_code.as_ptr() }
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_base_dist_ptr() -> *const i32 { base_dist.as_ptr() }
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_dist_code_ptr() -> *const u8 { dist_code.as_ptr() }
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_static_ltree_ptr() -> *const u16 { static_ltree.as_ptr() as *const u16 }
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn deftree_rs_static_dtree_ptr() -> *const u16 { static_dtree.as_ptr() as *const u16 }
