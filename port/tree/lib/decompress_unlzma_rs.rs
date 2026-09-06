// SPDX-License-Identifier: LGPL-2.1-or-later

//! The LZMA range-coder decompressor -- Rust behind `lib/decompress_unlzma.c`'s
//! `unlzma()` (the non-`PREBOOT` arm only).
//!
//! # `lib/decompress_unlzma.c` ITSELF STAYS PRISTINE -- like
//! # `decompress_inflate.c`, but for a different reason
//!
//! `CONFIG_KERNEL_LZMA` is off in both of this project's configs (verified
//! against the built `.config`, not the fragment: `grep CONFIG_KERNEL_LZMA
//! build-full/.config build-fast/.config` -> both `# ... is not set`), so
//! unlike `decompress_inflate.c`'s `CONFIG_KERNEL_GZIP` case, `arch/x86/
//! boot/compressed/misc.c`'s `#ifdef CONFIG_KERNEL_LZMA` guard around
//! textually including this file never fires here -- this file's preboot
//! arm really is dead code in this project's own builds, the same as
//! bunzip2/unlz4/unlzo(-the-wrapper)/unxz/unzstd's.
//!
//! But UNLIKE those five, this file's `#ifdef STATIC` body is not just a
//! thin wrapper -- it's the entire LZMA range-coder algorithm, in one
//! translation unit, with no separate `lib/lzma/` to delegate to the way
//! `decompress_unlzo.c` delegates to `lzo/lzo1x_decompress_safe.c`.
//! `logs/build-limits.md` already documents the precedent for exactly that
//! library file's own pre-boot body: kept byte-identical to upstream even
//! though neither build here exercises it, because `CONFIG_KERNEL_LZO` is
//! a real, supported kernel configuration this project simply doesn't
//! build -- "if it ever drifts from the Rust, nothing in this project will
//! notice" is a documented, accepted limit, not a silent one. Overwriting
//! `decompress_unlzma.c` the way the five thin-wrapper files overwrite
//! theirs would delete the ONLY copy of the algorithm the preboot path
//! needs, silently, for a configuration nothing here builds or tests --
//! the same class of mistake `decompress_inflate_rs.rs`'s module doc
//! records making once already this session, just without that mistake's
//! build-time forcing function to catch it here. So `decompress_unlzma.c`
//! stays pristine, and the two small allocator thunks live in a new,
//! separate file, `decompress_unlzma_alloc.c` -- same arrangement as
//! `decompress_inflate.c`/`decompress_inflate_alloc.c`, different
//! underlying reason (see `logs/build-limits.md`'s entry on this file for
//! the full account).
//!
//! `unlzma()` has no `EXPORT_SYMBOL`, so there's no MODVERSIONS CRC forcing
//! a C-entry/Rust-body thunk shape -- this file defines `unlzma()` directly
//! under its own name (the `lib/union_find` shape, same as `gunzip()`).
//! The Makefile's `CONFIG_RUST` arm does not compile `decompress_unlzma.o`
//! at all for the same reason it doesn't compile `decompress_inflate.o`:
//! `unlzma()` is the only definition of that symbol when `CONFIG_RUST=y`,
//! and compiling the pristine C alongside it would double-define it.
//!
//! # A self-contained algorithm, like bunzip2 -- not a thin wrapper
//!
//! Unlike unlz4/unlzo/unxz/unzstd (which wrap an already-ported or still-C
//! backend), this file IS the LZMA range-coder decoder itself, same shape
//! as `decompress_bunzip2_rs.rs`. No separate `lib/lzma/` to delegate to;
//! everything here is ported directly.
//!
//! # Structs and the probability-model array
//!
//! `struct rc` (the range coder), `struct writer` (the output ring buffer
//! + its callbacks) and `struct cstate` (the 4-register LZMA match-history
//! state) are all internal to this file -- no FFI layout constraint,
//! translated as plain Rust structs with the same fields. `struct
//! lzma_header` IS read via raw byte-at-a-time copy from the input stream
//! (`((unsigned char *)&header)[i] = *rc.ptr++`) and is `__attribute__
//! ((packed))` in C; rather than mirror that as a `#[repr(C, packed)]`
//! struct (unaligned-reference hazards for no benefit -- nothing outside
//! this translation needs the C layout), the header is read into a plain
//! `[u8; 13]` byte buffer (1 + 4 + 8, matching `pos: u8, dict_size: u32,
//! dst_size: u64`) and its two multi-byte fields are reconstructed
//! directly with the same little-endian byte order `read_int()`/
//! `ENDIAN_CONVERT` produce, rather than duplicating that macro's
//! C-generic-typeof trick (which Rust has no equivalent of) as two
//! separate, explicitly-typed calls.
//!
//! `p`, the probability-model array (`num_probs` × `u16`), is manipulated
//! throughout via raw pointer offsets (`p.add(OFFSET)`) matching the C's
//! own `prob = p + LZMA_SOME_OFFSET + ...` pointer arithmetic exactly,
//! rather than translating to slice indexing -- the C never bounds-checks
//! these offsets either (they're derived from the header's `lc`/`lp`
//! fields, which size the array in the first place), so an index-based
//! translation would silently add a bounds check the C does not have.
//!
//! # The alloc-failure cascade, translated as independent ownership checks
//!
//! `unlzma()`'s C is FOUR chained `goto`s into a shared cleanup tail
//! (`exit_3` falls into `exit_2` falls into `exit_1` falls into `exit_0`),
//! the same "staged/cascading" shape `decompress_unlz4_rs.rs`'s module doc
//! describes. Translated the way `decompress_unzstd_rs.rs`'s `__unzstd()`
//! translates its own multi-buffer cleanup: `p`'s null-ness after the
//! labelled block exactly captures whether `large_malloc()` for it ever
//! succeeded (every path that could skip its allocation returns before the
//! block's tail, matching `goto exit_2`/`exit_1`/`exit_0` never reaching
//! `large_free(p)`), and `wr_buffer_owned`/`inbuf_owned` exactly capture
//! the C's own `if (!output)`/`if (!buf)` ownership conditions -- so three
//! independent checks after one labelled block reproduce every `goto`
//! target's effective behavior.
//!
//! # The range coder's arithmetic is `wrapping_*` throughout, deliberately
//!
//! This kernel builds Rust with overflow checks on, unlike the five
//! wrapper files in this family: the range coder's `u32`/`i32` arithmetic
//! (`rc->range`/`rc->code`/`rc->bound`, the LZMA index/offset computations
//! built from `cst.rep0`/`pos_slot`/header-derived `lc`/`lp`/`pb`) relies
//! throughout on C's well-defined (on real hardware) unsigned/signed
//! wraparound, the same way a range coder or hash function always does --
//! and unlike the plain `int`/`uint32_t` arithmetic the C uses without a
//! second thought, a straight translation to Rust's checked-by-default
//! operators would PANIC on exactly the inputs (corrupt or adversarial
//! streams) this decoder exists to reject cleanly with an "LZMA data is
//! corrupt" error instead. Every arithmetic op reachable from corrupt or
//! boundary input is `wrapping_add`/`wrapping_sub`/`wrapping_mul`/
//! `wrapping_shl`/`wrapping_shr` here, each with an inline comment where
//! the reason isn't obvious from the surrounding C-mirroring translation
//! alone. This was not done by inspection alone: verified mechanically,
//! the way this file's own review comment suggested -- compile with `-O
//! -C overflow-checks=on --emit=obj` and read the object's undefined
//! symbols (`nm -u`). Before this pass: `panic_const_add_overflow`,
//! `_mul_overflow`, `_shl_overflow`, `_sub_overflow` all present. After:
//! none of the four remain: only `decompress_unlzma_alloc`,
//! `decompress_unlzma_large_alloc`, `kfree` and `vfree` are undefined,
//! exactly the real functions this file calls.
//!
//! # `large_malloc`/`large_free` vs `malloc`/`free`, and why BOTH are here
//!
//! Unlike every other file in this family, `decompress_unlzma.c` calls
//! its plain `malloc`/`free` (mapped to `kmalloc`/`kfree` by `mm.h`'s
//! non-`STATIC` arm) for the INPUT buffer only (`inbuf`, when the caller
//! doesn't supply one), and `large_malloc`/`large_free` (mapped to
//! `vmalloc`/`vfree`) for the OUTPUT buffer and the probability array.
//! Both allocator families are therefore needed here, unlike e.g.
//! `decompress_unxz.c` (kmalloc only) or `decompress_unlz4.c` (vmalloc
//! only) -- `decompress_unlzma.c`'s own C alloc shim has two functions for
//! exactly this reason.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

const LZMA_IOBUF_SIZE: c_long = 0x10000;

const RC_TOP_BITS: u32 = 24;
const RC_MOVE_BITS: u32 = 5;
const RC_MODEL_TOTAL_BITS: u32 = 11;

const LZMA_BASE_SIZE: usize = 1846;
const LZMA_LIT_SIZE: usize = 768;

const LZMA_NUM_POS_BITS_MAX: u32 = 4;

const LZMA_LEN_NUM_LOW_BITS: u32 = 3;
const LZMA_LEN_NUM_MID_BITS: u32 = 3;
const LZMA_LEN_NUM_HIGH_BITS: u32 = 8;

const LZMA_LEN_CHOICE: usize = 0;
const LZMA_LEN_CHOICE_2: usize = LZMA_LEN_CHOICE + 1;
const LZMA_LEN_LOW: usize = LZMA_LEN_CHOICE_2 + 1;
const LZMA_LEN_MID: usize = LZMA_LEN_LOW + (1 << (LZMA_NUM_POS_BITS_MAX + LZMA_LEN_NUM_LOW_BITS));
const LZMA_LEN_HIGH: usize = LZMA_LEN_MID + (1 << (LZMA_NUM_POS_BITS_MAX + LZMA_LEN_NUM_MID_BITS));
const LZMA_NUM_LEN_PROBS: usize = LZMA_LEN_HIGH + (1 << LZMA_LEN_NUM_HIGH_BITS);

const LZMA_NUM_STATES: usize = 12;
const LZMA_NUM_LIT_STATES: c_int = 7;

const LZMA_START_POS_MODEL_INDEX: c_int = 4;
const LZMA_END_POS_MODEL_INDEX: c_int = 14;
const LZMA_NUM_FULL_DISTANCES: usize = 1 << (LZMA_END_POS_MODEL_INDEX >> 1);

const LZMA_NUM_POS_SLOT_BITS: u32 = 6;
const LZMA_NUM_LEN_TO_POS_STATES: c_int = 4;

const LZMA_NUM_ALIGN_BITS: u32 = 4;

const LZMA_MATCH_MIN_LEN: c_int = 2;

const LZMA_IS_MATCH: usize = 0;
const LZMA_IS_REP: usize = LZMA_IS_MATCH + (LZMA_NUM_STATES << LZMA_NUM_POS_BITS_MAX);
const LZMA_IS_REP_G0: usize = LZMA_IS_REP + LZMA_NUM_STATES;
const LZMA_IS_REP_G1: usize = LZMA_IS_REP_G0 + LZMA_NUM_STATES;
const LZMA_IS_REP_G2: usize = LZMA_IS_REP_G1 + LZMA_NUM_STATES;
const LZMA_IS_REP_0_LONG: usize = LZMA_IS_REP_G2 + LZMA_NUM_STATES;
const LZMA_POS_SLOT: usize = LZMA_IS_REP_0_LONG + (LZMA_NUM_STATES << LZMA_NUM_POS_BITS_MAX);
const LZMA_SPEC_POS: usize =
    LZMA_POS_SLOT + ((LZMA_NUM_LEN_TO_POS_STATES as usize) << LZMA_NUM_POS_SLOT_BITS);
const LZMA_ALIGN: usize = LZMA_SPEC_POS + LZMA_NUM_FULL_DISTANCES - LZMA_END_POS_MODEL_INDEX as usize;
const LZMA_LEN_CODER: usize = LZMA_ALIGN + (1 << LZMA_NUM_ALIGN_BITS);
const LZMA_REP_LEN_CODER: usize = LZMA_LEN_CODER + LZMA_NUM_LEN_PROBS;
const LZMA_LITERAL: usize = LZMA_REP_LEN_CODER + LZMA_NUM_LEN_PROBS;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

extern "C" {
    /// `lib/decompress_unlzma_alloc.c`. Three lines: `return
    /// kmalloc(size, GFP_KERNEL);` -- `kmalloc` itself has no linkable
    /// symbol.
    fn decompress_unlzma_alloc(size: c_ulong) -> *mut c_void;
    /// `lib/decompress_unlzma_alloc.c`. Three lines: `return
    /// vmalloc(size);`.
    fn decompress_unlzma_large_alloc(size: c_ulong) -> *mut c_void;
    /// `mm/slub.c`, `EXPORT_SYMBOL(kfree)`. Real out-of-line function.
    fn kfree(objp: *const c_void);
    /// `mm/vmalloc.c`, `EXPORT_SYMBOL(vfree)`. Real out-of-line function.
    fn vfree(addr: *const c_void);
}

struct Rc {
    fill: FillFn,
    ptr: *mut u8,
    buffer: *mut u8,
    buffer_end: *mut u8,
    buffer_size: c_long,
    code: u32,
    range: u32,
    bound: u32,
    error: ErrorFn,
}

struct LzmaHeader {
    dict_size: u32,
    dst_size: u64,
}

struct Writer {
    buffer: *mut u8,
    previous_byte: u8,
    buffer_pos: usize,
    global_pos: usize,
    flush: Option<FlushFn>,
    header: *const LzmaHeader,
}

struct Cstate {
    state: c_int,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
}

/// `nofill()`, `lib/decompress_unlzma.c`.
unsafe extern "C" fn nofill(_buffer: *mut c_void, _len: c_ulong) -> c_long {
    -1
}

/// `rc_read()`. Called twice: once at startup and once in rc_normalize().
unsafe fn rc_read(rc: &mut Rc) {
    rc.buffer_size = unsafe { (rc.fill)(rc.buffer as *mut c_void, LZMA_IOBUF_SIZE as c_ulong) };
    if rc.buffer_size <= 0 {
        unsafe { (rc.error)(b"unexpected EOF\0".as_ptr() as *mut c_char) };
    }
    rc.ptr = rc.buffer;
    rc.buffer_end = unsafe { rc.buffer.offset(rc.buffer_size as isize) };
}

/// `rc_init()`. Called once.
unsafe fn rc_init(rc: &mut Rc, fill: Option<FillFn>, buffer: *mut u8, buffer_size: c_long) {
    rc.fill = fill.unwrap_or(nofill);
    rc.buffer = buffer;
    rc.buffer_size = buffer_size;
    rc.buffer_end = unsafe { rc.buffer.offset(buffer_size as isize) };
    rc.ptr = rc.buffer;
    rc.code = 0;
    rc.range = 0xFFFF_FFFF;
}

/// `rc_init_code()`. Called once.
unsafe fn rc_init_code(rc: &mut Rc) {
    for _ in 0..5 {
        if rc.ptr >= rc.buffer_end {
            unsafe { rc_read(rc) };
        }
        let b = unsafe { *rc.ptr };
        rc.ptr = unsafe { rc.ptr.add(1) };
        rc.code = (rc.code << 8) | b as u32;
    }
}

/// `rc_do_normalize()`. Called twice, one callsite inlined in C's
/// `rc_is_bit_0_helper()` -- here just called directly from
/// `rc_normalize()`, same observable effect.
unsafe fn rc_do_normalize(rc: &mut Rc) {
    if rc.ptr >= rc.buffer_end {
        unsafe { rc_read(rc) };
    }
    rc.range <<= 8;
    let b = unsafe { *rc.ptr };
    rc.ptr = unsafe { rc.ptr.add(1) };
    rc.code = (rc.code << 8) | b as u32;
}

unsafe fn rc_normalize(rc: &mut Rc) {
    if rc.range < (1 << RC_TOP_BITS) {
        unsafe { rc_do_normalize(rc) };
    }
}

/// `rc_is_bit_0_helper()`. Kept as its own function per the C's own
/// comment: exposes `rc->code < rc->bound` to the optimizer.
unsafe fn rc_is_bit_0_helper(rc: &mut Rc, p: *mut u16) -> u32 {
    unsafe { rc_normalize(rc) };
    rc.bound = (unsafe { *p as u32 }).wrapping_mul(rc.range >> RC_MODEL_TOTAL_BITS);
    rc.bound
}

unsafe fn rc_is_bit_0(rc: &mut Rc, p: *mut u16) -> bool {
    let t = unsafe { rc_is_bit_0_helper(rc, p) };
    rc.code < t
}

unsafe fn rc_update_bit_0(rc: &mut Rc, p: *mut u16) {
    rc.range = rc.bound;
    unsafe {
        *p = (*p).wrapping_add(((1u16 << RC_MODEL_TOTAL_BITS).wrapping_sub(*p)) >> RC_MOVE_BITS);
    }
}

unsafe fn rc_update_bit_1(rc: &mut Rc, p: *mut u16) {
    rc.range = rc.range.wrapping_sub(rc.bound);
    rc.code = rc.code.wrapping_sub(rc.bound);
    unsafe {
        *p = (*p).wrapping_sub(*p >> RC_MOVE_BITS);
    }
}

/// `rc_get_bit()`. Called 4 times in the main unlzma loop.
unsafe fn rc_get_bit(rc: &mut Rc, p: *mut u16, symbol: &mut c_int) -> c_int {
    // wrapping_*: rc_get_bit() has no local bound on how many times it can
    // be called against a given `symbol` (that bound lives in each
    // caller -- rc_bit_tree_decode()'s `num_levels`, or process_bit0's
    // literal match-byte loop, both small in practice), so the compiler
    // must assume the worst case here and would otherwise insert a
    // runtime overflow check that could panic instead of wrapping the way
    // C's plain `int` multiply/add does.
    if unsafe { rc_is_bit_0(rc, p) } {
        unsafe { rc_update_bit_0(rc, p) };
        *symbol = symbol.wrapping_mul(2);
        0
    } else {
        unsafe { rc_update_bit_1(rc, p) };
        *symbol = symbol.wrapping_mul(2).wrapping_add(1);
        1
    }
}

/// `rc_direct_bit()`. Called once.
unsafe fn rc_direct_bit(rc: &mut Rc) -> c_int {
    unsafe { rc_normalize(rc) };
    rc.range >>= 1;
    if rc.code >= rc.range {
        rc.code = rc.code.wrapping_sub(rc.range);
        1
    } else {
        0
    }
}

/// `rc_bit_tree_decode()`. Called twice.
unsafe fn rc_bit_tree_decode(rc: &mut Rc, p: *mut u16, num_levels: c_int, symbol: &mut c_int) {
    *symbol = 1;
    let mut i = num_levels;
    while i != 0 {
        i -= 1;
        let idx = *symbol as isize;
        unsafe { rc_get_bit(rc, p.offset(idx), symbol) };
    }
    *symbol = symbol.wrapping_sub(1i32.wrapping_shl(num_levels as u32));
}

unsafe fn get_pos(wr: &Writer) -> usize {
    wr.global_pos.wrapping_add(wr.buffer_pos)
}

/// `peek_old_byte()`. The buffer-mode (`wr->flush == NULL`) and streaming
/// (`wr->flush` set) branches use genuinely different wraparound
/// arithmetic in the C -- kept exactly as two separate branches, including
/// the buffer-mode branch's signed 32-bit intermediate (`int32_t pos` in
/// the C), not widened to a signed 64-bit or unsigned type, since that
/// intermediate's wraparound behavior on a large `offs` is part of the
/// faithfully-reproduced arithmetic (GOALS.md's C-is-a-reference boundary
/// -- this project's floor.md ruling is to reproduce, not to be safer).
unsafe fn peek_old_byte(wr: &Writer, mut offs: u32) -> u8 {
    let dict_size = unsafe { (*wr.header).dict_size };
    if wr.flush.is_none() {
        while offs > dict_size {
            offs -= dict_size;
        }
        // wrapping_sub: `offs` is a caller-supplied match distance
        // (ultimately cst.rep0, corrupt-input-influenced) that can
        // legitimately exceed `wr.buffer_pos` here -- C's plain `int32_t`
        // subtraction wraps silently (well-defined two's-complement on
        // real hardware); this must too, not panic, to reproduce the same
        // (out-of-bounds, but non-crashing) pointer this C already computes
        // with no bounds check of its own.
        let pos = (wr.buffer_pos as i32).wrapping_sub(offs as i32);
        unsafe { *wr.buffer.offset(pos as isize) }
    } else {
        let mut pos = (wr.buffer_pos as u32).wrapping_sub(offs);
        while pos >= dict_size {
            pos = pos.wrapping_add(dict_size);
        }
        unsafe { *wr.buffer.offset(pos as isize) }
    }
}

/// `write_byte()`.
unsafe fn write_byte(wr: &mut Writer, byte: u8) -> c_int {
    unsafe {
        *wr.buffer.add(wr.buffer_pos) = byte;
    }
    wr.buffer_pos = wr.buffer_pos.wrapping_add(1);
    wr.previous_byte = byte;
    let dict_size = unsafe { (*wr.header).dict_size } as usize;
    if let Some(f) = wr.flush {
        if wr.buffer_pos == dict_size {
            wr.buffer_pos = 0;
            wr.global_pos = wr.global_pos.wrapping_add(dict_size);
            if unsafe { f(wr.buffer as *mut c_void, dict_size as c_ulong) } != dict_size as c_long
            {
                return -1;
            }
        }
    }
    0
}

unsafe fn copy_byte(wr: &mut Writer, offs: u32) -> c_int {
    let b = unsafe { peek_old_byte(wr, offs) };
    unsafe { write_byte(wr, b) }
}

/// `copy_bytes()`.
unsafe fn copy_bytes(wr: &mut Writer, rep0: u32, mut len: c_int) -> c_int {
    let dst_size = unsafe { (*wr.header).dst_size };
    loop {
        if unsafe { copy_byte(wr, rep0) } != 0 {
            return -1;
        }
        len = len.wrapping_sub(1);
        if len == 0 || wr.buffer_pos as u64 >= dst_size {
            break;
        }
    }
    len
}

/// `process_bit0()`.
unsafe fn process_bit0(
    wr: &mut Writer,
    rc: &mut Rc,
    cst: &mut Cstate,
    p: *mut u16,
    _pos_state: c_int,
    prob_in: *mut u16,
    lc: c_int,
    literal_pos_mask: u32,
) -> c_int {
    let mut mi: c_int = 1;
    unsafe { rc_update_bit_0(rc, prob_in) };
    // wrapping_*: bounded in practice (lc<9, lp<5 per the header check in
    // unlzma(), so this whole index stays small), but not provably so to
    // the compiler across this function boundary -- same reasoning as
    // unlzma()'s own header-derived arithmetic.
    let literal_idx = (unsafe { get_pos(wr) } as u32 & literal_pos_mask)
        .wrapping_shl(lc as u32)
        .wrapping_add((wr.previous_byte as u32).wrapping_shr(8u32.wrapping_sub(lc as u32)));
    let prob = unsafe { p.add(LZMA_LITERAL.wrapping_add(LZMA_LIT_SIZE.wrapping_mul(literal_idx as usize))) };

    if cst.state >= LZMA_NUM_LIT_STATES {
        let mut match_byte = unsafe { peek_old_byte(wr, cst.rep0) } as c_int;
        loop {
            match_byte = match_byte.wrapping_shl(1);
            let bit = match_byte & 0x100;
            let prob_lit = unsafe { prob.offset((0x100 + bit).wrapping_add(mi) as isize) };
            let got = unsafe { rc_get_bit(rc, prob_lit, &mut mi) };
            if got != 0 {
                if bit == 0 {
                    break;
                }
            } else if bit != 0 {
                break;
            }
            if mi >= 0x100 {
                break;
            }
        }
    }
    while mi < 0x100 {
        let prob_lit = unsafe { prob.offset(mi as isize) };
        unsafe { rc_get_bit(rc, prob_lit, &mut mi) };
    }
    if cst.state < 4 {
        cst.state = 0;
    } else if cst.state < 10 {
        cst.state -= 3;
    } else {
        cst.state -= 6;
    }

    unsafe { write_byte(wr, mi as u8) }
}

/// `process_bit1()`.
unsafe fn process_bit1(
    wr: &mut Writer,
    rc: &mut Rc,
    cst: &mut Cstate,
    p: *mut u16,
    pos_state: c_int,
    prob_in: *mut u16,
) -> c_int {
    let offset;
    let num_bits;
    let mut len: c_int = 0;

    unsafe { rc_update_bit_1(rc, prob_in) };
    let mut prob = unsafe { p.add(LZMA_IS_REP.wrapping_add(cst.state as usize)) };
    if unsafe { rc_is_bit_0(rc, prob) } {
        unsafe { rc_update_bit_0(rc, prob) };
        cst.rep3 = cst.rep2;
        cst.rep2 = cst.rep1;
        cst.rep1 = cst.rep0;
        cst.state = if cst.state < LZMA_NUM_LIT_STATES { 0 } else { 3 };
        prob = unsafe { p.add(LZMA_LEN_CODER) };
    } else {
        unsafe { rc_update_bit_1(rc, prob) };
        prob = unsafe { p.add(LZMA_IS_REP_G0.wrapping_add(cst.state as usize)) };
        if unsafe { rc_is_bit_0(rc, prob) } {
            unsafe { rc_update_bit_0(rc, prob) };
            prob = unsafe {
                p.add(LZMA_IS_REP_0_LONG.wrapping_add((cst.state.wrapping_shl(LZMA_NUM_POS_BITS_MAX).wrapping_add(pos_state)) as usize))
            };
            if unsafe { rc_is_bit_0(rc, prob) } {
                unsafe { rc_update_bit_0(rc, prob) };
                cst.state = if cst.state < LZMA_NUM_LIT_STATES { 9 } else { 11 };
                return unsafe { copy_byte(wr, cst.rep0) };
            } else {
                unsafe { rc_update_bit_1(rc, prob) };
            }
        } else {
            let distance;
            unsafe { rc_update_bit_1(rc, prob) };
            prob = unsafe { p.add(LZMA_IS_REP_G1.wrapping_add(cst.state as usize)) };
            if unsafe { rc_is_bit_0(rc, prob) } {
                unsafe { rc_update_bit_0(rc, prob) };
                distance = cst.rep1;
            } else {
                unsafe { rc_update_bit_1(rc, prob) };
                prob = unsafe { p.add(LZMA_IS_REP_G2.wrapping_add(cst.state as usize)) };
                if unsafe { rc_is_bit_0(rc, prob) } {
                    unsafe { rc_update_bit_0(rc, prob) };
                    distance = cst.rep2;
                } else {
                    unsafe { rc_update_bit_1(rc, prob) };
                    distance = cst.rep3;
                    cst.rep3 = cst.rep2;
                }
                cst.rep2 = cst.rep1;
            }
            cst.rep1 = cst.rep0;
            cst.rep0 = distance;
        }
        cst.state = if cst.state < LZMA_NUM_LIT_STATES { 8 } else { 11 };
        prob = unsafe { p.add(LZMA_REP_LEN_CODER) };
    }

    let mut prob_len = unsafe { prob.add(LZMA_LEN_CHOICE) };
    if unsafe { rc_is_bit_0(rc, prob_len) } {
        unsafe { rc_update_bit_0(rc, prob_len) };
        prob_len = unsafe { prob.add(LZMA_LEN_LOW + ((pos_state as u32) << LZMA_LEN_NUM_LOW_BITS) as usize) };
        offset = 0;
        num_bits = LZMA_LEN_NUM_LOW_BITS as c_int;
    } else {
        unsafe { rc_update_bit_1(rc, prob_len) };
        prob_len = unsafe { prob.add(LZMA_LEN_CHOICE_2) };
        if unsafe { rc_is_bit_0(rc, prob_len) } {
            unsafe { rc_update_bit_0(rc, prob_len) };
            prob_len = unsafe {
                prob.add(LZMA_LEN_MID + ((pos_state as u32) << LZMA_LEN_NUM_MID_BITS) as usize)
            };
            offset = 1 << LZMA_LEN_NUM_LOW_BITS;
            num_bits = LZMA_LEN_NUM_MID_BITS as c_int;
        } else {
            unsafe { rc_update_bit_1(rc, prob_len) };
            prob_len = unsafe { prob.add(LZMA_LEN_HIGH) };
            offset = (1 << LZMA_LEN_NUM_LOW_BITS) + (1 << LZMA_LEN_NUM_MID_BITS);
            num_bits = LZMA_LEN_NUM_HIGH_BITS as c_int;
        }
    }

    unsafe { rc_bit_tree_decode(rc, prob_len, num_bits, &mut len) };
    len = len.wrapping_add(offset as c_int);

    if cst.state < 4 {
        let mut pos_slot: c_int = 0;

        cst.state = cst.state.wrapping_add(LZMA_NUM_LIT_STATES);
        let idx = if len < LZMA_NUM_LEN_TO_POS_STATES {
            len
        } else {
            LZMA_NUM_LEN_TO_POS_STATES - 1
        };
        prob = unsafe { p.add(LZMA_POS_SLOT.wrapping_add((idx as u32).wrapping_shl(LZMA_NUM_POS_SLOT_BITS) as usize)) };
        unsafe { rc_bit_tree_decode(rc, prob, LZMA_NUM_POS_SLOT_BITS as c_int, &mut pos_slot) };
        if pos_slot >= LZMA_START_POS_MODEL_INDEX {
            let mut i: c_int;
            let mut mi: c_int;
            let mut nb = (pos_slot >> 1) - 1;
            cst.rep0 = (2 | (pos_slot & 1)) as u32;
            if pos_slot < LZMA_END_POS_MODEL_INDEX {
                cst.rep0 = cst.rep0.wrapping_shl(nb as u32);
                // Wrapping i32 arithmetic: `cst.rep0 as c_int` can be
                // negative (rep0's high bit set, reinterpreted) and/or this
                // sum can exceed i32 range under corrupt input driving
                // rep0 to an unexpected value -- C's plain `int` arithmetic
                // here wraps silently (well-defined two's-complement
                // wraparound in practice), matching `.wrapping_*` rather
                // than leaving a plain operator that would panic under
                // this kernel's overflow-checks build instead of producing
                // C's same (wrong, but non-crashing) result.
                let off = (LZMA_SPEC_POS as c_int)
                    .wrapping_add(cst.rep0 as c_int)
                    .wrapping_sub(pos_slot)
                    .wrapping_sub(1);
                prob = unsafe { p.offset(off as isize) };
            } else {
                nb = nb.wrapping_sub(LZMA_NUM_ALIGN_BITS as c_int);
                while nb != 0 {
                    nb = nb.wrapping_sub(1);
                    cst.rep0 = (cst.rep0 << 1) | unsafe { rc_direct_bit(rc) as u32 };
                }
                prob = unsafe { p.add(LZMA_ALIGN) };
                cst.rep0 <<= LZMA_NUM_ALIGN_BITS;
                nb = LZMA_NUM_ALIGN_BITS as c_int;
            }
            i = 1;
            mi = 1;
            while nb != 0 {
                nb = nb.wrapping_sub(1);
                if unsafe { rc_get_bit(rc, prob.offset(mi as isize), &mut mi) } != 0 {
                    cst.rep0 |= i as u32;
                }
                i = i.wrapping_shl(1);
            }
        } else {
            cst.rep0 = pos_slot as u32;
        }
        cst.rep0 = cst.rep0.wrapping_add(1);
        if cst.rep0 == 0 {
            return 0;
        }
        let dict_size = unsafe { (*wr.header).dict_size };
        if cst.rep0 > dict_size || cst.rep0 as usize > unsafe { get_pos(wr) } {
            return -1;
        }
    }

    len = len.wrapping_add(LZMA_MATCH_MIN_LEN);

    unsafe { copy_bytes(wr, cst.rep0, len) }
}

/// `unlzma()`, `lib/decompress_unlzma.c`. The dispatcher's `.decompressor`
/// entry for the `"lzma"` magic (`\x5d\x00`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn unlzma(
    buf: *mut u8,
    in_len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    output: *mut u8,
    posp: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    let mut inbuf_owned: *mut c_void = core::ptr::null_mut();
    let mut wr_buffer_owned: *mut c_void = core::ptr::null_mut();
    let mut p: *mut u16 = core::ptr::null_mut();

    let ret: c_int = 'body: {
        let inbuf: *mut u8 = if !buf.is_null() {
            buf
        } else {
            inbuf_owned = unsafe { decompress_unlzma_alloc(LZMA_IOBUF_SIZE as c_ulong) };
            inbuf_owned as *mut u8
        };
        if inbuf.is_null() {
            call_error(b"Could not allocate input buffer\0");
            break 'body -1;
        }

        let mut cst = Cstate {
            state: 0,
            rep0: 1,
            rep1: 1,
            rep2: 1,
            rep3: 1,
        };

        let mut header = LzmaHeader {
            dict_size: 0,
            dst_size: 0,
        };
        let mut wr = Writer {
            buffer: core::ptr::null_mut(),
            previous_byte: 0,
            buffer_pos: 0,
            global_pos: 0,
            flush,
            header: &header,
        };

        // `rc.error` is called unconditionally by rc_read()/rc_init_code(),
        // matching the C's own `rc.error = error;` with no null check --
        // every real caller supplies one (same assumption this file
        // family's other `call_error` closures make defensively; here the
        // struct field itself needs a real fn pointer, so a genuine
        // no-op is substituted when `error` is None rather than a null
        // function pointer, which would be UB to call).
        unsafe extern "C" fn noop_error(_msg: *mut c_char) {}
        let mut rc = Rc {
            fill: fill.unwrap_or(nofill),
            ptr: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            buffer_end: core::ptr::null_mut(),
            buffer_size: 0,
            code: 0,
            range: 0,
            bound: 0,
            error: error.unwrap_or(noop_error),
        };
        unsafe { rc_init(&mut rc, fill, inbuf, in_len) };

        let mut hdr_bytes = [0u8; 13]; // pos(1) + dict_size(4) + dst_size(8)
        for b in hdr_bytes.iter_mut() {
            if rc.ptr >= rc.buffer_end {
                unsafe { rc_read(&mut rc) };
            }
            *b = unsafe { *rc.ptr };
            rc.ptr = unsafe { rc.ptr.add(1) };
        }
        let hdr_pos = hdr_bytes[0] as c_int;
        header.dict_size = u32::from_le_bytes(hdr_bytes[1..5].try_into().unwrap());
        header.dst_size = u64::from_le_bytes(hdr_bytes[5..13].try_into().unwrap());

        if hdr_pos >= 9 * 5 * 5 {
            call_error(b"bad header\0");
            break 'body -1;
        }

        // wrapping_*: `hdr_pos` is bounded < 225 by the check just above,
        // which bounds every value computed from it here too (lc<9, mi<25,
        // lp<5, pb<5) -- true by construction, but not something the
        // compiler can prove across this loop, so it inserts the same
        // runtime overflow checks it would for genuinely unbounded input.
        let mut mi: c_int = 0;
        let mut lc = hdr_pos;
        while lc >= 9 {
            mi = mi.wrapping_add(1);
            lc = lc.wrapping_sub(9);
        }
        let mut pb: c_int = 0;
        let mut lp = mi;
        while lp >= 5 {
            pb = pb.wrapping_add(1);
            lp = lp.wrapping_sub(5);
        }
        let pos_state_mask: u32 = 1u32.wrapping_shl(pb as u32).wrapping_sub(1);
        let literal_pos_mask: u32 = 1u32.wrapping_shl(lp as u32).wrapping_sub(1);

        if header.dict_size == 0 {
            header.dict_size = 1;
        }

        if !output.is_null() {
            wr.buffer = output;
        } else {
            let bufsize = core::cmp::min(header.dst_size, header.dict_size as u64) as c_ulong;
            wr_buffer_owned = unsafe { decompress_unlzma_large_alloc(bufsize) };
            wr.buffer = wr_buffer_owned as *mut u8;
        }
        if wr.buffer.is_null() {
            break 'body -1;
        }

        let mut num_probs =
            LZMA_BASE_SIZE.wrapping_add(LZMA_LIT_SIZE.wrapping_shl(lc.wrapping_add(lp) as u32));
        p = unsafe {
            decompress_unlzma_large_alloc(
                (num_probs.wrapping_mul(core::mem::size_of::<u16>())) as c_ulong,
            )
        } as *mut u16;
        if p.is_null() {
            break 'body -1;
        }
        num_probs = LZMA_LITERAL.wrapping_add(LZMA_LIT_SIZE.wrapping_shl(lc.wrapping_add(lp) as u32));
        for i in 0..num_probs {
            unsafe {
                *p.add(i) = ((1u32 << RC_MODEL_TOTAL_BITS) >> 1) as u16;
            }
        }

        unsafe { rc_init_code(&mut rc) };

        // Explicit break value per exit reason -- NOT re-derived from state
        // afterward. An earlier version of this translation tried to
        // distinguish "reached dst_size" / "rep0==0" (both -> ret=0, C falls
        // through to the *posp/flush code) from "corrupt data" / "ran out of
        // input" (both -> C's `goto exit_3`, skipping *posp/flush entirely,
        // ret stays -1) by re-checking `cst.rep0 == 0` and `get_pos(&wr) >=
        // dst_size` AFTER the loop -- but `cst.rep0` is persistent state from
        // a PRIOR iteration and could coincidentally be 0 on an error exit
        // too, misrouting a real corrupt-data failure into the success path
        // (writing *posp and calling flush() when the C never would have).
        // An explicit tag removes the inference entirely.
        let inner_ret: c_int = 'lzma_loop: loop {
            if (unsafe { get_pos(&wr) } as u64) >= header.dst_size {
                break 'lzma_loop 0;
            }
            let pos_state = (unsafe { get_pos(&wr) } as u32 & pos_state_mask) as c_int;
            let prob = unsafe {
                p.add(
                    LZMA_IS_MATCH
                        .wrapping_add(
                            ((cst.state << LZMA_NUM_POS_BITS_MAX).wrapping_add(pos_state)) as usize,
                        ),
                )
            };
            if unsafe { rc_is_bit_0(&mut rc, prob) } {
                if unsafe { process_bit0(&mut wr, &mut rc, &mut cst, p, pos_state, prob, lc, literal_pos_mask) }
                    != 0
                {
                    call_error(b"LZMA data is corrupt\0");
                    break 'lzma_loop -1;
                }
            } else {
                if unsafe { process_bit1(&mut wr, &mut rc, &mut cst, p, pos_state, prob) } != 0 {
                    call_error(b"LZMA data is corrupt\0");
                    break 'lzma_loop -1;
                }
                if cst.rep0 == 0 {
                    break 'lzma_loop 0;
                }
            }
            if rc.buffer_size <= 0 {
                break 'lzma_loop -1;
            }
        };

        if inner_ret == 0 {
            if !posp.is_null() {
                unsafe {
                    *posp = rc.ptr.offset_from(rc.buffer) as c_long;
                }
            }
            let flush_ok = match wr.flush {
                None => true,
                Some(f) => unsafe {
                    f(wr.buffer as *mut c_void, wr.buffer_pos as c_ulong) == wr.buffer_pos as c_long
                },
            };
            if flush_ok {
                0
            } else {
                -1
            }
        } else {
            -1
        }
    };

    if !p.is_null() {
        unsafe { vfree(p as *const c_void) };
    }
    if !wr_buffer_owned.is_null() {
        unsafe { vfree(wr_buffer_owned as *const c_void) };
    }
    if !inbuf_owned.is_null() {
        unsafe { kfree(inbuf_owned as *const c_void) };
    }
    ret
}
