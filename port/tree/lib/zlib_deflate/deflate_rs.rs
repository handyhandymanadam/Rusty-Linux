// SPDX-License-Identifier: GPL-2.0-only

//! The DEFLATE compressor proper: the sliding window, the hash chains, the
//! longest-match search and the three strategies (stored, fast, lazy). The
//! Huffman coding it feeds is `deftree_rs.rs`.
//!
//! Ported from `lib/zlib_deflate/deflate.c` (Copyright (C) 1995-1996
//! Jean-loup Gailly, zlib license).
//!
//! # Shape
//!
//! All six of `deflate.c`'s symbols are `EXPORT_SYMBOL`'d in `deflate_syms.c`,
//! so their MODVERSIONS fingerprints come from the DWARF of the definition
//! (GOALS.md section 2, criterion 4). They stay C, in `deflate_glue.c`:
//!
//! * `zlib_deflateReset`, `zlib_deflate`, `zlib_deflateEnd` -- one-line thunks
//!   into the `rust_zlib_*` functions below;
//! * `zlib_deflateInit2` -- argument guards, the workspace layout
//!   (`struct deflate_workspace` is a C type this crate does not mirror) and
//!   the carving of the four memory chunks; it hands the pointers to
//!   [`rust_zlib_deflate_init_state`];
//! * `zlib_deflate_workspacesize` -- a `BUG_ON` and `sizeof(deflate_workspace)`;
//! * `zlib_deflate_dfltcc_enabled` -- a constant.
//!
//! Everything else -- `read_buf`, `lm_init`, `longest_match`, `fill_window`,
//! `deflate_stored/fast/slow`, `flush_pending`, the bit-buffer flush -- is
//! here. `configuration_table`'s function pointer becomes a `match` on the
//! level.
//!
//! # Deliberate divergences
//!
//! * `zlib_adler32()` is a `static inline` in `include/linux/zutil.h` (no
//!   symbol to call), so it is reimplemented, the same way `inflate_rs.rs`
//!   does.
//! * `longest_match()` is the `!UNALIGNED_OK` arm; `UNALIGNED_OK` is never
//!   defined (grepped: not in the Makefile or any config).
//! * `DEBUG_ZLIB` (`check_match`, `bits_sent`) and `CONFIG_ZLIB_DFLTCC` (s390
//!   hardware deflate) are not built on x86; the latter is a `compile_error!`
//!   so a configuration that turns it on cannot silently skip the hooks.
//!
//! `struct deflate_state` is mirrored in full, as in `deftree_rs.rs` (this is
//! a second copy of the same layout; `port/test/deflate` asserts both against
//! the C `offsetof()`s).
//!
//! Replaces: lib/zlib_deflate/deflate.c

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

#[cfg(CONFIG_ZLIB_DFLTCC)]
compile_error!("deflate_rs.rs: CONFIG_ZLIB_DFLTCC (s390 hardware deflate) is not ported; keep the C file");

type Byte = u8;
type Uch = u8;
type Ush = u16;
type Ulg = c_ulong;
type UInt = c_uint;
type Pos = u16;
type IPos = c_uint;

const LENGTH_CODES: usize = 29;
const LITERALS: usize = 256;
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
const D_CODES: usize = 30;
const BL_CODES: usize = 19;
const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;

const INIT_STATE: c_int = 42;
const BUSY_STATE: c_int = 113;
const FINISH_STATE: c_int = 666;

const MIN_MATCH: UInt = 3;
const MAX_MATCH: UInt = 258;
/// `MIN_LOOKAHEAD`.
const MIN_LOOKAHEAD: UInt = MAX_MATCH + MIN_MATCH + 1;
/// Matches of length 3 are discarded if their distance exceeds this.
const TOO_FAR: UInt = 4096;
/// Tail of the hash chains.
const NIL: UInt = 0;

const Z_NO_FLUSH: c_int = 0;
const Z_PARTIAL_FLUSH: c_int = 1;
const Z_PACKET_FLUSH: c_int = 2;
const Z_FULL_FLUSH: c_int = 4;
const Z_FINISH: c_int = 5;
const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_STREAM_ERROR: c_int = -2;
const Z_DATA_ERROR: c_int = -3;
const Z_BUF_ERROR: c_int = -5;
const Z_FILTERED: c_int = 1;
const Z_HUFFMAN_ONLY: c_int = 2;
const Z_UNKNOWN: c_int = 2;
const Z_DEFLATED: UInt = 8;
/// `PRESET_DICT`, `zutil.h`.
const PRESET_DICT: UInt = 0x20;

/// `block_state`, `defutil.h`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockState {
    NeedMore,
    BlockDone,
    FinishStarted,
    FinishDone,
}

/// `ct_data`, `defutil.h` -- two `ush`s (each a union of two names for the same bits).
#[derive(Clone, Copy)]
#[repr(C)]
struct CtData {
    fc: Ush,
    dl: Ush,
}

/// `tree_desc_s`, `defutil.h`.
#[repr(C)]
struct TreeDesc {
    dyn_tree: *mut CtData,
    max_code: c_int,
    stat_desc: *const c_void,
}

/// `z_stream_s`, `include/linux/zlib.h`.
#[repr(C)]
pub struct ZStream {
    next_in: *const Byte,
    avail_in: c_ulong,
    total_in: c_ulong,
    next_out: *mut Byte,
    avail_out: c_ulong,
    total_out: c_ulong,
    msg: *mut c_char,
    state: *mut DeflateState,
    workspace: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

/// Mirrors `struct deflate_state`, `defutil.h`, field for field.
#[repr(C)]
pub struct DeflateState {
    strm: *mut ZStream,
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

    bi_buf: Ush,
    bi_valid: c_int,
}

// The Huffman coder (deftree_rs.rs); it keeps its C names.
extern "C" {
    fn zlib_tr_init(s: *mut DeflateState);
    fn zlib_tr_tally(s: *mut DeflateState, dist: c_uint, lc: c_uint) -> c_int;
    fn zlib_tr_flush_block(s: *mut DeflateState, buf: *mut c_char, stored_len: Ulg, eof: c_int) -> Ulg;
    fn zlib_tr_align(s: *mut DeflateState);
    fn zlib_tr_stored_block(s: *mut DeflateState, buf: *mut c_char, stored_len: Ulg, eof: c_int);
    fn zlib_tr_stored_type_only(s: *mut DeflateState);
}

/// `config_s`, `deflate.c`.
struct Config {
    good_length: Ush,
    max_lazy: Ush,
    nice_length: Ush,
    max_chain: Ush,
}

/// `configuration_table[10]`; the C's `func` column is the `match` in [`zlib_deflate_impl`]:
/// level 0 stored, 1..=3 fast, 4..=9 slow.
static CONFIGURATION_TABLE: [Config; 10] = [
    Config { good_length: 0, max_lazy: 0, nice_length: 0, max_chain: 0 },
    Config { good_length: 4, max_lazy: 4, nice_length: 8, max_chain: 4 },
    Config { good_length: 4, max_lazy: 5, nice_length: 16, max_chain: 8 },
    Config { good_length: 4, max_lazy: 6, nice_length: 32, max_chain: 32 },
    Config { good_length: 4, max_lazy: 4, nice_length: 16, max_chain: 16 },
    Config { good_length: 8, max_lazy: 16, nice_length: 32, max_chain: 32 },
    Config { good_length: 8, max_lazy: 16, nice_length: 128, max_chain: 128 },
    Config { good_length: 8, max_lazy: 32, nice_length: 128, max_chain: 256 },
    Config { good_length: 32, max_lazy: 128, nice_length: 258, max_chain: 1024 },
    Config { good_length: 32, max_lazy: 258, nice_length: 258, max_chain: 4096 },
];

// ---------------------------------------------------------------------------
// defutil.h / zutil.h helpers (macros and `static inline`: no symbol in the C).
// ---------------------------------------------------------------------------

/// `put_byte(s, c)`.
#[inline(always)]
unsafe fn put_byte(s: *mut DeflateState, c: Byte) {
    // SAFETY: the C's own precondition -- there is room in pending_buf.
    unsafe {
        *(*s).pending_buf.add((*s).pending as usize) = c;
        (*s).pending += 1;
    }
}

/// `put_short(s, w)`: LSB first.
#[inline(always)]
unsafe fn put_short(s: *mut DeflateState, w: Ush) {
    // SAFETY: as `put_byte`.
    unsafe {
        put_byte(s, (w & 0xff) as Byte);
        put_byte(s, (w >> 8) as Byte);
    }
}

/// `putShortMSB()`.
unsafe fn putShortMSB(s: *mut DeflateState, b: UInt) {
    // SAFETY: as `put_byte`.
    unsafe {
        put_byte(s, (b >> 8) as Byte);
        put_byte(s, (b & 0xff) as Byte);
    }
}

/// `bi_flush()`: flush the bit buffer, keeping at most 7 bits in it.
unsafe fn bi_flush(s: *mut DeflateState) {
    // SAFETY: as `put_byte`.
    unsafe {
        if (*s).bi_valid == 16 {
            put_short(s, (*s).bi_buf);
            (*s).bi_buf = 0;
            (*s).bi_valid = 0;
        } else if (*s).bi_valid >= 8 {
            put_byte(s, (*s).bi_buf as Byte);
            (*s).bi_buf >>= 8;
            (*s).bi_valid -= 8;
        }
    }
}

/// `MAX_DIST(s)`.
#[inline(always)]
unsafe fn max_dist(s: *const DeflateState) -> UInt {
    // SAFETY: `s` is valid (caller).
    unsafe { (*s).w_size.wrapping_sub(MIN_LOOKAHEAD) }
}

/// `UPDATE_HASH(s, s->ins_h, c)`.
#[inline(always)]
unsafe fn update_hash(s: *mut DeflateState, c: Byte) {
    // SAFETY: `s` is valid (caller).
    unsafe { (*s).ins_h = (((*s).ins_h << (*s).hash_shift) ^ c as UInt) & (*s).hash_mask };
}

/// `INSERT_STRING(s, str, match_head)`: returns the previous head of the hash chain.
#[inline(always)]
unsafe fn insert_string(s: *mut DeflateState, str_: UInt) -> IPos {
    // SAFETY: the C's own precondition -- the first MIN_MATCH bytes at `str_` are in the window,
    // `prev` has w_size entries and `head` has hash_size entries.
    unsafe {
        update_hash(s, *(*s).window.add(str_ as usize + (MIN_MATCH as usize - 1)));
        let match_head = *(*s).head.add((*s).ins_h as usize) as IPos;
        *(*s).prev.add((str_ & (*s).w_mask) as usize) = match_head as Pos;
        *(*s).head.add((*s).ins_h as usize) = str_ as Pos;
        match_head
    }
}

/// `CLEAR_HASH(s)`.
#[inline(always)]
unsafe fn clear_hash(s: *mut DeflateState) {
    // SAFETY: `head` has hash_size entries.
    unsafe {
        *(*s).head.add((*s).hash_size as usize - 1) = NIL as Pos;
        core::ptr::write_bytes((*s).head, 0, (*s).hash_size.wrapping_sub(1) as usize);
    }
}

/// `zlib_adler32()` (`static inline` in `include/linux/zutil.h`).
unsafe fn adler32(adler: c_ulong, buf: *const Byte, len: UInt) -> c_ulong {
    const BASE: c_ulong = 65521;
    const NMAX: UInt = 5552;
    if buf.is_null() {
        return 1;
    }
    let mut s1 = adler & 0xffff;
    let mut s2 = (adler >> 16) & 0xffff;
    let mut p = buf;
    let mut len = len;
    while len > 0 {
        let k = if len < NMAX { len } else { NMAX };
        len -= k;
        for i in 0..k as usize {
            // SAFETY: caller guarantees `len` readable bytes.
            s1 = s1.wrapping_add(unsafe { *p.add(i) } as c_ulong);
            s2 = s2.wrapping_add(s1);
        }
        // SAFETY: stays within the caller's buffer.
        p = unsafe { p.add(k as usize) };
        s1 %= BASE;
        s2 %= BASE;
    }
    (s2 << 16) | s1
}

/// `flush_pending()`: flush as much pending output as possible.
unsafe fn flush_pending(strm: *mut ZStream) {
    // SAFETY: `strm->state` is the live deflate_state of this stream, as in the C.
    unsafe {
        let s = (*strm).state;
        bi_flush(s);
        let mut len: UInt = (*s).pending as UInt;
        if len as c_ulong > (*strm).avail_out {
            len = (*strm).avail_out as UInt;
        }
        if len == 0 {
            return;
        }
        if !(*strm).next_out.is_null() {
            core::ptr::copy_nonoverlapping((*s).pending_out as *const Byte, (*strm).next_out, len as usize);
            (*strm).next_out = (*strm).next_out.add(len as usize);
        }
        (*s).pending_out = (*s).pending_out.add(len as usize);
        (*strm).total_out = (*strm).total_out.wrapping_add(len as c_ulong);
        (*strm).avail_out = (*strm).avail_out.wrapping_sub(len as c_ulong);
        (*s).pending -= len as c_int;
        if (*s).pending == 0 {
            (*s).pending_out = (*s).pending_buf;
        }
    }
}

/// `read_buf()`: read a new buffer from the input stream, update the adler32 and the totals.
unsafe fn read_buf(strm: *mut ZStream, buf: *mut Byte, size: UInt) -> c_int {
    // SAFETY: as `flush_pending`; `buf` has room for `size` bytes (caller's contract).
    unsafe {
        let mut len: UInt = (*strm).avail_in as UInt;
        if len > size {
            len = size;
        }
        if len == 0 {
            return 0;
        }
        (*strm).avail_in = (*strm).avail_in.wrapping_sub(len as c_ulong);
        if (*(*strm).state).noheader == 0 {
            (*strm).adler = adler32((*strm).adler, (*strm).next_in, len);
        }
        core::ptr::copy_nonoverlapping((*strm).next_in, buf, len as usize);
        (*strm).next_in = (*strm).next_in.add(len as usize);
        (*strm).total_in = (*strm).total_in.wrapping_add(len as c_ulong);
        len as c_int
    }
}

/// `lm_init()`: initialize the "longest match" routines for a new stream.
unsafe fn lm_init(s: *mut DeflateState) {
    // SAFETY: `s` is valid and `head` has hash_size entries (caller).
    unsafe {
        (*s).window_size = 2 * (*s).w_size as Ulg;
        clear_hash(s);

        let cfg = &CONFIGURATION_TABLE[(*s).level as usize];
        (*s).max_lazy_match = cfg.max_lazy as UInt;
        (*s).good_match = cfg.good_length as UInt;
        (*s).nice_match = cfg.nice_length as c_int;
        (*s).max_chain_length = cfg.max_chain as UInt;

        (*s).strstart = 0;
        (*s).block_start = 0;
        (*s).lookahead = 0;
        (*s).match_length = MIN_MATCH - 1;
        (*s).prev_length = MIN_MATCH - 1;
        (*s).match_available = 0;
        (*s).ins_h = 0;
    }
}

/// `longest_match()`: set `match_start` to the longest match starting at the given string and return its length.
/// Matches shorter than or equal to `prev_length` are discarded, in which case the result equals `prev_length`.
unsafe fn longest_match(s: *mut DeflateState, mut cur_match: IPos) -> UInt {
    // SAFETY: the C's own preconditions -- `cur_match` is the head of the chain for the string at `strstart`,
    // its distance is <= MAX_DIST, and the window holds at least MIN_LOOKAHEAD bytes beyond `strstart`.
    unsafe {
        let mut chain_length = (*s).max_chain_length;
        let mut scan = (*s).window.add((*s).strstart as usize);
        let mut best_len = (*s).prev_length as c_int;
        let mut nice_match = (*s).nice_match;
        let limit: IPos = if (*s).strstart > max_dist(s) { (*s).strstart - max_dist(s) } else { NIL };
        let prev = (*s).prev;
        let wmask = (*s).w_mask;
        let strend = (*s).window.add((*s).strstart as usize + MAX_MATCH as usize);
        let mut scan_end1: Byte = *scan.offset(best_len as isize - 1);
        let mut scan_end: Byte = *scan.offset(best_len as isize);

        if (*s).prev_length >= (*s).good_match {
            chain_length >>= 2;
        }
        if nice_match as UInt > (*s).lookahead {
            nice_match = (*s).lookahead as c_int;
        }

        'chain: loop {
            'next: {
                let mut mtch = (*s).window.add(cur_match as usize);

                if *mtch.offset(best_len as isize) != scan_end || *mtch.offset(best_len as isize - 1) != scan_end1 || *mtch != *scan {
                    break 'next;
                }
                mtch = mtch.add(1);
                if *mtch != *scan.add(1) {
                    break 'next;
                }
                scan = scan.add(2);
                mtch = mtch.add(1);

                // eight comparisons per lookahead check
                loop {
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    scan = scan.add(1);
                    mtch = mtch.add(1);
                    if *scan != *mtch {
                        break;
                    }
                    if scan >= strend {
                        break;
                    }
                }

                let len = MAX_MATCH as c_int - strend.offset_from(scan) as c_int;
                scan = strend.sub(MAX_MATCH as usize);

                if len > best_len {
                    (*s).match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break 'chain;
                    }
                    scan_end1 = *scan.offset(best_len as isize - 1);
                    scan_end = *scan.offset(best_len as isize);
                }
            }
            cur_match = *prev.add((cur_match & wmask) as usize) as IPos;
            if cur_match <= limit {
                break;
            }
            chain_length = chain_length.wrapping_sub(1);
            if chain_length == 0 {
                break;
            }
        }

        if best_len as UInt <= (*s).lookahead {
            return best_len as UInt;
        }
        (*s).lookahead
    }
}

/// `fill_window()`: fill the window when the lookahead becomes insufficient. Updates `strstart` and `lookahead`.
unsafe fn fill_window(s: *mut DeflateState) {
    // SAFETY: the C's own preconditions -- the window, `prev` and `head` are the sizes `zlib_deflateInit2` gave them.
    unsafe {
        let wsize = (*s).w_size;
        loop {
            let mut more: UInt =
                (*s).window_size.wrapping_sub((*s).lookahead as Ulg).wrapping_sub((*s).strstart as Ulg) as UInt;

            if more == 0 && (*s).strstart == 0 && (*s).lookahead == 0 {
                more = wsize;
            } else if more == UInt::MAX {
                more -= 1;
            } else if (*s).strstart >= wsize.wrapping_add(max_dist(s)) {
                core::ptr::copy_nonoverlapping((*s).window.add(wsize as usize) as *const Byte, (*s).window, wsize as usize);
                (*s).match_start = (*s).match_start.wrapping_sub(wsize);
                (*s).strstart = (*s).strstart.wrapping_sub(wsize);
                (*s).block_start -= wsize as c_long;

                let mut n = (*s).hash_size;
                let mut p = (*s).head.add(n as usize);
                loop {
                    p = p.sub(1);
                    let m = *p as UInt;
                    *p = if m >= wsize { m - wsize } else { NIL } as Pos;
                    n -= 1;
                    if n == 0 {
                        break;
                    }
                }

                n = wsize;
                p = (*s).prev.add(n as usize);
                loop {
                    p = p.sub(1);
                    let m = *p as UInt;
                    *p = if m >= wsize { m - wsize } else { NIL } as Pos;
                    n -= 1;
                    if n == 0 {
                        break;
                    }
                }
                more = more.wrapping_add(wsize);
            }
            if (*(*s).strm).avail_in == 0 {
                return;
            }

            let n = read_buf((*s).strm, (*s).window.add((*s).strstart as usize + (*s).lookahead as usize), more);
            (*s).lookahead = (*s).lookahead.wrapping_add(n as UInt);

            if (*s).lookahead >= MIN_MATCH {
                (*s).ins_h = *(*s).window.add((*s).strstart as usize) as UInt;
                update_hash(s, *(*s).window.add((*s).strstart as usize + 1));
            }

            if !((*s).lookahead < MIN_LOOKAHEAD && (*(*s).strm).avail_in != 0) {
                break;
            }
        }
    }
}

/// `FLUSH_BLOCK_ONLY(s, eof)`.
#[inline(always)]
unsafe fn flush_block_only(s: *mut DeflateState, eof: c_int) {
    // SAFETY: as the C macro.
    unsafe {
        let buf = if (*s).block_start >= 0 { (*s).window.add((*s).block_start as usize) as *mut c_char } else { core::ptr::null_mut() };
        zlib_tr_flush_block(s, buf, ((*s).strstart as c_long).wrapping_sub((*s).block_start) as Ulg, eof);
        (*s).block_start = (*s).strstart as c_long;
        flush_pending((*s).strm);
    }
}

/// `deflate_stored()`: copy without compression as much as possible from the input stream (level 0).
unsafe fn deflate_stored(s: *mut DeflateState, flush: c_int) -> BlockState {
    // SAFETY: as `fill_window`.
    unsafe {
        let mut max_block_size: Ulg = 0xffff;
        if max_block_size > (*s).pending_buf_size.wrapping_sub(5) {
            max_block_size = (*s).pending_buf_size.wrapping_sub(5);
        }

        loop {
            if (*s).lookahead <= 1 {
                fill_window(s);
                if (*s).lookahead == 0 && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if (*s).lookahead == 0 {
                    break;
                }
            }

            (*s).strstart = (*s).strstart.wrapping_add((*s).lookahead);
            (*s).lookahead = 0;

            let max_start: Ulg = ((*s).block_start as Ulg).wrapping_add(max_block_size);
            if (*s).strstart == 0 || (*s).strstart as Ulg >= max_start {
                (*s).lookahead = ((*s).strstart as Ulg).wrapping_sub(max_start) as UInt;
                (*s).strstart = max_start as UInt;
                flush_block_only(s, 0);
                if (*(*s).strm).avail_out == 0 {
                    return BlockState::NeedMore;
                }
            }
            if (*s).strstart.wrapping_sub((*s).block_start as UInt) >= max_dist(s) {
                flush_block_only(s, 0);
                if (*(*s).strm).avail_out == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        flush_block_only(s, (flush == Z_FINISH) as c_int);
        if (*(*s).strm).avail_out == 0 {
            return if flush == Z_FINISH { BlockState::FinishStarted } else { BlockState::NeedMore };
        }
        if flush == Z_FINISH { BlockState::FinishDone } else { BlockState::BlockDone }
    }
}

/// `deflate_fast()`: compress as much as possible from the input stream, no lazy evaluation (levels 1..=3).
unsafe fn deflate_fast(s: *mut DeflateState, flush: c_int) -> BlockState {
    // SAFETY: as `fill_window`.
    unsafe {
        let mut hash_head: IPos = NIL;
        let mut bflush: c_int;

        loop {
            if (*s).lookahead < MIN_LOOKAHEAD {
                fill_window(s);
                if (*s).lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if (*s).lookahead == 0 {
                    break;
                }
            }

            if (*s).lookahead >= MIN_MATCH {
                hash_head = insert_string(s, (*s).strstart);
            }

            if hash_head != NIL && (*s).strstart.wrapping_sub(hash_head) <= max_dist(s) {
                if (*s).strategy != Z_HUFFMAN_ONLY {
                    (*s).match_length = longest_match(s, hash_head);
                }
            }
            if (*s).match_length >= MIN_MATCH {
                bflush = zlib_tr_tally(s, (*s).strstart.wrapping_sub((*s).match_start), (*s).match_length - MIN_MATCH);

                (*s).lookahead = (*s).lookahead.wrapping_sub((*s).match_length);

                if (*s).match_length <= (*s).max_lazy_match && (*s).lookahead >= MIN_MATCH {
                    (*s).match_length -= 1;
                    loop {
                        (*s).strstart = (*s).strstart.wrapping_add(1);
                        hash_head = insert_string(s, (*s).strstart);
                        (*s).match_length -= 1;
                        if (*s).match_length == 0 {
                            break;
                        }
                    }
                    (*s).strstart = (*s).strstart.wrapping_add(1);
                } else {
                    (*s).strstart = (*s).strstart.wrapping_add((*s).match_length);
                    (*s).match_length = 0;
                    (*s).ins_h = *(*s).window.add((*s).strstart as usize) as UInt;
                    update_hash(s, *(*s).window.add((*s).strstart as usize + 1));
                }
            } else {
                bflush = zlib_tr_tally(s, 0, *(*s).window.add((*s).strstart as usize) as c_uint);
                (*s).lookahead = (*s).lookahead.wrapping_sub(1);
                (*s).strstart = (*s).strstart.wrapping_add(1);
            }
            if bflush != 0 {
                flush_block_only(s, 0);
                if (*(*s).strm).avail_out == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        flush_block_only(s, (flush == Z_FINISH) as c_int);
        if (*(*s).strm).avail_out == 0 {
            return if flush == Z_FINISH { BlockState::FinishStarted } else { BlockState::NeedMore };
        }
        if flush == Z_FINISH { BlockState::FinishDone } else { BlockState::BlockDone }
    }
}

/// `deflate_slow()`: as `deflate_fast`, with lazy evaluation of matches (levels 4..=9).
unsafe fn deflate_slow(s: *mut DeflateState, flush: c_int) -> BlockState {
    // SAFETY: as `fill_window`.
    unsafe {
        let mut hash_head: IPos = NIL;
        let mut bflush: c_int;

        loop {
            if (*s).lookahead < MIN_LOOKAHEAD {
                fill_window(s);
                if (*s).lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                if (*s).lookahead == 0 {
                    break;
                }
            }

            if (*s).lookahead >= MIN_MATCH {
                hash_head = insert_string(s, (*s).strstart);
            }

            (*s).prev_length = (*s).match_length;
            (*s).prev_match = (*s).match_start;
            (*s).match_length = MIN_MATCH - 1;

            if hash_head != NIL && (*s).prev_length < (*s).max_lazy_match && (*s).strstart.wrapping_sub(hash_head) <= max_dist(s) {
                if (*s).strategy != Z_HUFFMAN_ONLY {
                    (*s).match_length = longest_match(s, hash_head);
                }

                if (*s).match_length <= 5
                    && ((*s).strategy == Z_FILTERED
                        || ((*s).match_length == MIN_MATCH && (*s).strstart.wrapping_sub((*s).match_start) > TOO_FAR))
                {
                    (*s).match_length = MIN_MATCH - 1;
                }
            }
            if (*s).prev_length >= MIN_MATCH && (*s).match_length <= (*s).prev_length {
                let max_insert: UInt = (*s).strstart.wrapping_add((*s).lookahead).wrapping_sub(MIN_MATCH);

                bflush = zlib_tr_tally(
                    s,
                    (*s).strstart.wrapping_sub(1).wrapping_sub((*s).prev_match),
                    (*s).prev_length - MIN_MATCH,
                );

                (*s).lookahead = (*s).lookahead.wrapping_sub((*s).prev_length - 1);
                (*s).prev_length -= 2;
                loop {
                    (*s).strstart = (*s).strstart.wrapping_add(1);
                    if (*s).strstart <= max_insert {
                        hash_head = insert_string(s, (*s).strstart);
                    }
                    (*s).prev_length -= 1;
                    if (*s).prev_length == 0 {
                        break;
                    }
                }
                (*s).match_available = 0;
                (*s).match_length = MIN_MATCH - 1;
                (*s).strstart = (*s).strstart.wrapping_add(1);

                if bflush != 0 {
                    flush_block_only(s, 0);
                    if (*(*s).strm).avail_out == 0 {
                        return BlockState::NeedMore;
                    }
                }
            } else if (*s).match_available != 0 {
                if zlib_tr_tally(s, 0, *(*s).window.add((*s).strstart as usize - 1) as c_uint) != 0 {
                    flush_block_only(s, 0);
                }
                (*s).strstart = (*s).strstart.wrapping_add(1);
                (*s).lookahead = (*s).lookahead.wrapping_sub(1);
                if (*(*s).strm).avail_out == 0 {
                    return BlockState::NeedMore;
                }
            } else {
                (*s).match_available = 1;
                (*s).strstart = (*s).strstart.wrapping_add(1);
                (*s).lookahead = (*s).lookahead.wrapping_sub(1);
            }
        }
        if (*s).match_available != 0 {
            zlib_tr_tally(s, 0, *(*s).window.add((*s).strstart as usize - 1) as c_uint);
            (*s).match_available = 0;
        }
        flush_block_only(s, (flush == Z_FINISH) as c_int);
        if (*(*s).strm).avail_out == 0 {
            return if flush == Z_FINISH { BlockState::FinishStarted } else { BlockState::NeedMore };
        }
        if flush == Z_FINISH { BlockState::FinishDone } else { BlockState::BlockDone }
    }
}

// ---------------------------------------------------------------------------
// The entry points `deflate_glue.c` calls.
// ---------------------------------------------------------------------------

/// The state-setting half of `zlib_deflateInit2()`, after the C glue has checked its arguments and carved the
/// workspace: `window` is `2 * w_size` bytes, `prev` is `w_size` entries, `head` is `1 << (memLevel + 7)` entries,
/// `overlay` is `(1 << (memLevel + 6)) * 4` bytes.
///
/// # Safety
/// `strm` and `s` are valid; the four memory chunks have the sizes above.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_deflate_init_state(
    strm: *mut ZStream,
    s: *mut DeflateState,
    noheader: c_int,
    window_bits: c_int,
    mem_level: c_int,
    level: c_int,
    strategy: c_int,
    method: c_int,
    window: *mut Byte,
    prev: *mut Pos,
    head: *mut Pos,
    overlay: *mut Ush,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        (*strm).state = s;
        (*s).strm = strm;

        (*s).noheader = noheader;
        (*s).w_bits = window_bits as UInt;
        (*s).w_size = 1 << (*s).w_bits;
        (*s).w_mask = (*s).w_size - 1;

        (*s).hash_bits = (mem_level + 7) as UInt;
        (*s).hash_size = 1 << (*s).hash_bits;
        (*s).hash_mask = (*s).hash_size - 1;
        (*s).hash_shift = ((*s).hash_bits + MIN_MATCH - 1) / MIN_MATCH;

        (*s).window = window;
        (*s).prev = prev;
        (*s).head = head;

        (*s).lit_bufsize = 1 << (mem_level + 6);

        (*s).pending_buf = overlay as *mut Uch;
        (*s).pending_buf_size = (*s).lit_bufsize as Ulg * (core::mem::size_of::<Ush>() as Ulg + 2);

        (*s).d_buf = overlay.add((*s).lit_bufsize as usize / core::mem::size_of::<Ush>());
        (*s).l_buf = (*s).pending_buf.add((1 + core::mem::size_of::<Ush>()) * (*s).lit_bufsize as usize);

        (*s).level = level;
        (*s).strategy = strategy;
        (*s).method = method as Byte;

        rust_zlib_deflateReset(strm)
    }
}

/// `zlib_deflateReset()`.
///
/// # Safety
/// `strm` is null or a valid stream.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_deflateReset(strm: *mut ZStream) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        if strm.is_null() || (*strm).state.is_null() {
            return Z_STREAM_ERROR;
        }

        (*strm).total_in = 0;
        (*strm).total_out = 0;
        (*strm).msg = core::ptr::null_mut();
        (*strm).data_type = Z_UNKNOWN;

        let s = (*strm).state;
        (*s).pending = 0;
        (*s).pending_out = (*s).pending_buf;

        if (*s).noheader < 0 {
            (*s).noheader = 0;
        }
        (*s).status = if (*s).noheader != 0 { BUSY_STATE } else { INIT_STATE };
        (*strm).adler = 1;
        (*s).last_flush = Z_NO_FLUSH;

        zlib_tr_init(s);
        lm_init(s);

        Z_OK
    }
}

/// `zlib_deflate()`.
///
/// # Safety
/// `strm` is null or a valid stream with valid in/out buffers.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_deflate(strm: *mut ZStream, flush: c_int) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        if strm.is_null() || (*strm).state.is_null() || flush > Z_FINISH || flush < 0 {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state;

        if ((*strm).next_in.is_null() && (*strm).avail_in != 0) || ((*s).status == FINISH_STATE && flush != Z_FINISH) {
            return Z_STREAM_ERROR;
        }
        if (*strm).avail_out == 0 {
            return Z_BUF_ERROR;
        }

        (*s).strm = strm;
        let old_flush = (*s).last_flush;
        (*s).last_flush = flush;

        if (*s).status == INIT_STATE {
            let mut header: UInt = (Z_DEFLATED + (((*s).w_bits - 8) << 4)) << 8;
            let mut level_flags: UInt = (((*s).level - 1) >> 1) as UInt;

            if level_flags > 3 {
                level_flags = 3;
            }
            header |= level_flags << 6;
            if (*s).strstart != 0 {
                header |= PRESET_DICT;
            }
            header += 31 - (header % 31);

            (*s).status = BUSY_STATE;
            putShortMSB(s, header);

            if (*s).strstart != 0 {
                putShortMSB(s, ((*strm).adler >> 16) as UInt);
                putShortMSB(s, ((*strm).adler & 0xffff) as UInt);
            }
            (*strm).adler = 1;
        }

        if (*s).pending != 0 {
            flush_pending(strm);
            if (*strm).avail_out == 0 {
                (*s).last_flush = -1;
                return Z_OK;
            }
        } else if (*strm).avail_in == 0 && flush <= old_flush && flush != Z_FINISH {
            return Z_BUF_ERROR;
        }

        if (*s).status == FINISH_STATE && (*strm).avail_in != 0 {
            return Z_BUF_ERROR;
        }

        if (*strm).avail_in != 0 || (*s).lookahead != 0 || (flush != Z_NO_FLUSH && (*s).status != FINISH_STATE) {
            let bstate = match (*s).level {
                0 => deflate_stored(s, flush),
                1..=3 => deflate_fast(s, flush),
                _ => deflate_slow(s, flush),
            };

            if bstate == BlockState::FinishStarted || bstate == BlockState::FinishDone {
                (*s).status = FINISH_STATE;
            }
            if bstate == BlockState::NeedMore || bstate == BlockState::FinishStarted {
                if (*strm).avail_out == 0 {
                    (*s).last_flush = -1;
                }
                return Z_OK;
            }
            if bstate == BlockState::BlockDone {
                if flush == Z_PARTIAL_FLUSH {
                    zlib_tr_align(s);
                } else if flush == Z_PACKET_FLUSH {
                    zlib_tr_stored_type_only(s);
                } else {
                    zlib_tr_stored_block(s, core::ptr::null_mut(), 0, 0);
                    if flush == Z_FULL_FLUSH {
                        clear_hash(s);
                    }
                }
                flush_pending(strm);
                if (*strm).avail_out == 0 {
                    (*s).last_flush = -1;
                    return Z_OK;
                }
            }
        }

        if flush != Z_FINISH {
            return Z_OK;
        }

        if (*s).noheader == 0 {
            putShortMSB(s, ((*strm).adler >> 16) as UInt);
            putShortMSB(s, ((*strm).adler & 0xffff) as UInt);
        }
        flush_pending(strm);
        if (*s).noheader == 0 {
            (*s).noheader = -1;
        }
        if (*s).pending == 0 {
            return Z_STREAM_END;
        }
        Z_OK
    }
}

/// `zlib_deflateEnd()`.
///
/// # Safety
/// `strm` is null or a valid stream.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_deflateEnd(strm: *mut ZStream) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        if strm.is_null() || (*strm).state.is_null() {
            return Z_STREAM_ERROR;
        }
        let status = (*(*strm).state).status;
        if status != INIT_STATE && status != BUSY_STATE && status != FINISH_STATE {
            return Z_STREAM_ERROR;
        }

        (*strm).state = core::ptr::null_mut();

        if status == BUSY_STATE {
            Z_DATA_ERROR
        } else {
            Z_OK
        }
    }
}

// Layout report for `port/test/deflate/`: sizes and every field offset of both mirrored structs, compared there
// against `offsetof()` on the real headers (same convention as `deftree_rs_abi`).
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn deflate_rs_abi(out: *mut u64) {
    let vals: [u64; 72] = [
        core::mem::size_of::<DeflateState>() as u64,
        core::mem::offset_of!(DeflateState, strm) as u64,
        core::mem::offset_of!(DeflateState, status) as u64,
        core::mem::offset_of!(DeflateState, pending_buf) as u64,
        core::mem::offset_of!(DeflateState, pending_buf_size) as u64,
        core::mem::offset_of!(DeflateState, pending_out) as u64,
        core::mem::offset_of!(DeflateState, pending) as u64,
        core::mem::offset_of!(DeflateState, noheader) as u64,
        core::mem::offset_of!(DeflateState, data_type) as u64,
        core::mem::offset_of!(DeflateState, method) as u64,
        core::mem::offset_of!(DeflateState, last_flush) as u64,
        core::mem::offset_of!(DeflateState, w_size) as u64,
        core::mem::offset_of!(DeflateState, w_bits) as u64,
        core::mem::offset_of!(DeflateState, w_mask) as u64,
        core::mem::offset_of!(DeflateState, window) as u64,
        core::mem::offset_of!(DeflateState, window_size) as u64,
        core::mem::offset_of!(DeflateState, prev) as u64,
        core::mem::offset_of!(DeflateState, head) as u64,
        core::mem::offset_of!(DeflateState, ins_h) as u64,
        core::mem::offset_of!(DeflateState, hash_size) as u64,
        core::mem::offset_of!(DeflateState, hash_bits) as u64,
        core::mem::offset_of!(DeflateState, hash_mask) as u64,
        core::mem::offset_of!(DeflateState, hash_shift) as u64,
        core::mem::offset_of!(DeflateState, block_start) as u64,
        core::mem::offset_of!(DeflateState, match_length) as u64,
        core::mem::offset_of!(DeflateState, prev_match) as u64,
        core::mem::offset_of!(DeflateState, match_available) as u64,
        core::mem::offset_of!(DeflateState, strstart) as u64,
        core::mem::offset_of!(DeflateState, match_start) as u64,
        core::mem::offset_of!(DeflateState, lookahead) as u64,
        core::mem::offset_of!(DeflateState, prev_length) as u64,
        core::mem::offset_of!(DeflateState, max_chain_length) as u64,
        core::mem::offset_of!(DeflateState, max_lazy_match) as u64,
        core::mem::offset_of!(DeflateState, level) as u64,
        core::mem::offset_of!(DeflateState, strategy) as u64,
        core::mem::offset_of!(DeflateState, good_match) as u64,
        core::mem::offset_of!(DeflateState, nice_match) as u64,
        core::mem::offset_of!(DeflateState, dyn_ltree) as u64,
        core::mem::offset_of!(DeflateState, dyn_dtree) as u64,
        core::mem::offset_of!(DeflateState, bl_tree) as u64,
        core::mem::offset_of!(DeflateState, l_desc) as u64,
        core::mem::offset_of!(DeflateState, d_desc) as u64,
        core::mem::offset_of!(DeflateState, bl_desc) as u64,
        core::mem::offset_of!(DeflateState, bl_count) as u64,
        core::mem::offset_of!(DeflateState, heap) as u64,
        core::mem::offset_of!(DeflateState, heap_len) as u64,
        core::mem::offset_of!(DeflateState, heap_max) as u64,
        core::mem::offset_of!(DeflateState, depth) as u64,
        core::mem::offset_of!(DeflateState, l_buf) as u64,
        core::mem::offset_of!(DeflateState, lit_bufsize) as u64,
        core::mem::offset_of!(DeflateState, last_lit) as u64,
        core::mem::offset_of!(DeflateState, d_buf) as u64,
        core::mem::offset_of!(DeflateState, opt_len) as u64,
        core::mem::offset_of!(DeflateState, static_len) as u64,
        core::mem::offset_of!(DeflateState, compressed_len) as u64,
        core::mem::offset_of!(DeflateState, matches) as u64,
        core::mem::offset_of!(DeflateState, last_eob_len) as u64,
        core::mem::offset_of!(DeflateState, bi_buf) as u64,
        core::mem::offset_of!(DeflateState, bi_valid) as u64,
        core::mem::size_of::<ZStream>() as u64,
        core::mem::offset_of!(ZStream, next_in) as u64,
        core::mem::offset_of!(ZStream, avail_in) as u64,
        core::mem::offset_of!(ZStream, total_in) as u64,
        core::mem::offset_of!(ZStream, next_out) as u64,
        core::mem::offset_of!(ZStream, avail_out) as u64,
        core::mem::offset_of!(ZStream, total_out) as u64,
        core::mem::offset_of!(ZStream, msg) as u64,
        core::mem::offset_of!(ZStream, state) as u64,
        core::mem::offset_of!(ZStream, workspace) as u64,
        core::mem::offset_of!(ZStream, data_type) as u64,
        core::mem::offset_of!(ZStream, adler) as u64,
        core::mem::offset_of!(ZStream, reserved) as u64,
    ];
    // SAFETY: the caller's contract: `out` valid for `vals.len()` writes.
    unsafe { core::ptr::copy_nonoverlapping(vals.as_ptr(), out, vals.len()) };
}
