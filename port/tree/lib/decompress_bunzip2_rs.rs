// SPDX-License-Identifier: GPL-2.0

//! The bzip2 decompressor -- Rust behind `lib/decompress_bunzip2.c`.
//!
//! Replaces: lib/decompress_bunzip2.c (the non-`PREBOOT` arm only -- see
//! below).
//!
//! `bunzip2()` is reached only through `lib/decompress.c`'s
//! `compress_formats[]` function-pointer table and is not `EXPORT_SYMBOL`'d,
//! so this is a full replacement (the `lib/union_find` shape), not a
//! C-entry-stays thunk: GOALS.md §1's MODVERSIONS constraint does not reach
//! a symbol with no CRC to hold.
//!
//! # `PREBOOT` is out of scope, same as `lzo1x_decompress_safe`'s pre-boot arm
//!
//! This file's `#ifdef STATIC` / `#define PREBOOT` arm and its `__decompress`
//! wrapper exist only when `arch/*/boot/compressed/` textually `#include`s
//! this file with `STATIC` predefined -- a separate, freestanding
//! translation unit neither of this project's builds compile, and which the
//! normal `lib/decompress_bunzip2.c` object (what this replaces) never
//! contains in the first place, since `STATIC` is undefined there. Nothing
//! is dropped by omitting it.
//!
//! # `kmalloc`/`vmalloc` stay in C
//!
//! Both are macros over `alloc_hooks(..._noprof(...))` since 6.10's
//! allocation profiling and have no linkable symbol -- `decompress_bunzip2.c`
//! (this port's C half) keeps two three-line wrappers,
//! `decompress_bunzip2_alloc` and `decompress_bunzip2_dict_alloc`. `kfree`
//! and `vfree` are real `EXPORT_SYMBOL`s and are called directly from here,
//! same split `xz_dec_lzma2_rs.rs` uses.
//!
//! # The two `goto`s, as state machines
//!
//! Both are the same shape the `lzo1x_decompress_safe` port already used:
//! a label that is jumped to both from a fall-through and from elsewhere,
//! turned into a loop with an explicit state enum rather than invented
//! control flow.
//!
//! * `get_next_block`'s inline Huffman-bit refill has one label
//!   (`got_huff_bits`) reached by fall-through *or* by a `goto` from inside
//!   its own refill loop when the input buffer runs dry. That one collapses
//!   into a labelled block (`'refill: { ... break 'refill value; ... }`),
//!   no state enum needed -- it is a single early-exit, not two entry points.
//!
//! * `read_bunzip`'s `decode_next_byte:` label sits inside the output `for
//!   (;;)`, is jumped to from a `goto` *inside itself* (a zero-length run),
//!   and is jumped to from *outside the loop entirely* at the bottom of the
//!   function (after refilling a block). [`ReadState`] names the two halves
//!   the C's single anonymous loop body is actually made of -- `Top` (the
//!   output-write / copy-count part) and `DecodeNext` (the BWT-walk /
//!   run-length part) -- and every `goto` becomes a state assignment plus
//!   `continue`.
//!
//! # `base`/`limit`'s `-1`-shifted pointers become `-1` on the index instead
//!
//! `struct group_data.base`/`.limit` are sized and used so that a Huffman
//! code length `i` (always >= 1) reads `base[i-1]`/`limit[i-1]` through a
//! pointer the C pre-decrements once (`base = hufGroup->base - 1;`) so the
//! *value* `i` can be used as the index. Rust has no pointer-before-the-array
//! trick to borrow-check, so every such access here is written
//! `base[i as usize - 1]` directly -- same bytes, no `unsafe` pointer offset
//! needed for it.
//!
//! # `write_count`'s negative-sentinel double duty is kept, not cleaned up
//!
//! The C stores a `RETVAL_*` error (always negative) into `bd->writeCount`
//! so the *next* call can return it immediately (`if (bd->writeCount < 0)
//! return bd->writeCount;`), reusing the same field that otherwise counts
//! remaining decoded bytes. Recording the divergence that was NOT made:
//! this stays a plain `i32` doing both jobs, exactly as upstream -- turning
//! it into an `enum`/`Option` would be more idiomatic but is extra surface
//! for a differential to disagree on for no behavioural gain.

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

const MAX_GROUPS: usize = 6;
const GROUP_SIZE: i32 = 50;
const MAX_HUFCODE_BITS: usize = 20;
const MAX_SYMBOLS: usize = 258;
const SYMBOL_RUNB: i32 = 1;

const RETVAL_OK: i32 = 0;
const RETVAL_LAST_BLOCK: i32 = -1;
const RETVAL_NOT_BZIP_DATA: i32 = -2;
const RETVAL_UNEXPECTED_INPUT_EOF: i32 = -3;
const RETVAL_UNEXPECTED_OUTPUT_EOF: i32 = -4;
const RETVAL_DATA_ERROR: i32 = -5;
const RETVAL_OUT_OF_MEMORY: i32 = -6;
const RETVAL_OBSOLETE_INPUT: i32 = -7;

const BZIP2_IOBUF_SIZE: usize = 4096;

/// `CRC32_POLY_BE`, `include/linux/crc32poly.h`.
const CRC32_POLY_BE: u32 = 0x04c1_1db7;

type FillFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type FlushFn = unsafe extern "C" fn(*mut c_void, c_ulong) -> c_long;
type ErrorFn = unsafe extern "C" fn(*mut c_char);

/// `struct group_data`, `lib/decompress_bunzip2.c`.
#[repr(C)]
#[derive(Clone, Copy)]
struct GroupData {
    /// `limit[MAX_HUFCODE_BITS+1]` -- the C's extra sentinel slot at the end.
    limit: [i32; MAX_HUFCODE_BITS + 1],
    base: [i32; MAX_HUFCODE_BITS],
    permute: [i32; MAX_SYMBOLS],
    min_len: i32,
    max_len: i32,
}

/// `struct bunzip_data`, `lib/decompress_bunzip2.c`.
///
/// Allocated as zeroed raw bytes by `start_bunzip` (mirroring the C's
/// `malloc` + `memset(0)`) and only ever reached through a pointer -- never
/// placed on the Rust stack -- both to match the C's allocation shape and
/// because `selectors` alone is 32 KiB. All-zero is a valid bit pattern for
/// every field, `fill: Option<FillFn>` included: `None` is the null pointer,
/// the same guaranteed FFI niche optimisation `decompress_rs.rs` documents
/// and relies on for its own function-pointer table.
#[repr(C)]
struct BunzipData {
    write_copies: i32,
    write_pos: i32,
    write_run_countdown: i32,
    write_count: i32,
    write_current: i32,
    fill: Option<FillFn>,
    inbuf_count: c_long,
    inbuf_pos: c_long,
    inbuf: *mut u8,
    inbuf_bit_count: u32,
    inbuf_bits: u32,
    crc32_table: [u32; 256],
    header_crc: u32,
    total_crc: u32,
    write_crc: u32,
    dbuf: *mut u32,
    dbuf_size: u32,
    selectors: [u8; 32768],
    groups: [GroupData; MAX_GROUPS],
    io_error: i32,
    byte_count: [i32; 256],
    sym_to_byte: [u8; 256],
    mtf_symbol: [u8; 256],
}

extern "C" {
    /// `lib/decompress_bunzip2.c`. Three lines: `return kmalloc(size,
    /// GFP_KERNEL);` -- `kmalloc` itself has no linkable symbol.
    fn decompress_bunzip2_alloc(size: c_uint) -> *mut c_void;
    /// `lib/decompress_bunzip2.c`. Three lines: `return vmalloc(size);`.
    fn decompress_bunzip2_dict_alloc(size: c_uint) -> *mut c_void;
    /// `mm/slub.c`, `EXPORT_SYMBOL(kfree)`. Real out-of-line function.
    fn kfree(objp: *const c_void);
    /// `mm/vmalloc.c`, `EXPORT_SYMBOL(vfree)`. Real out-of-line function.
    fn vfree(addr: *const c_void);
}

/// `get_bits()`, `lib/decompress_bunzip2.c`. All reads from the compressed
/// input go through this; all reads are big-endian.
#[link_section = ".init.text"]
unsafe fn get_bits(bd: &mut BunzipData, mut bits_wanted: u32) -> u32 {
    let mut bits: u32 = 0;

    while bd.inbuf_bit_count < bits_wanted {
        if bd.inbuf_pos == bd.inbuf_count {
            if bd.io_error != 0 {
                return 0;
            }
            bd.inbuf_count = match bd.fill {
                Some(f) => unsafe { f(bd.inbuf as *mut c_void, BZIP2_IOBUF_SIZE as c_ulong) },
                None => -1,
            };
            if bd.inbuf_count <= 0 {
                bd.io_error = RETVAL_UNEXPECTED_INPUT_EOF;
                return 0;
            }
            bd.inbuf_pos = 0;
        }
        // All arithmetic below is `unsigned int`/`unsigned long long` in the
        // C (unguarded there too), and every shift amount here stays well
        // under 32 by this function's own bit-accounting -- `.wrapping_shl`/
        // `.wrapping_shr` mask the amount mod the type width, which is
        // exact given that, not merely a fallback. wrapping_* throughout,
        // found by the CONFIG_RUST_OVERFLOW_CHECKS sweep, 2026-09-06.
        if bd.inbuf_bit_count >= 24 {
            bits = bd.inbuf_bits & (1u32.wrapping_shl(bd.inbuf_bit_count).wrapping_sub(1));
            bits_wanted = bits_wanted.wrapping_sub(bd.inbuf_bit_count);
            bits = bits.wrapping_shl(bits_wanted);
            bd.inbuf_bit_count = 0;
        }
        let byte = unsafe { *bd.inbuf.offset(bd.inbuf_pos as isize) };
        bd.inbuf_pos = bd.inbuf_pos.wrapping_add(1);
        bd.inbuf_bits = (bd.inbuf_bits.wrapping_shl(8)) | byte as u32;
        bd.inbuf_bit_count = bd.inbuf_bit_count.wrapping_add(8);
    }
    bd.inbuf_bit_count = bd.inbuf_bit_count.wrapping_sub(bits_wanted);
    bits |= (bd.inbuf_bits.wrapping_shr(bd.inbuf_bit_count)) & (1u32.wrapping_shl(bits_wanted).wrapping_sub(1));
    bits
}

/// `get_next_block()`, `lib/decompress_bunzip2.c`. Unpacks the next block
/// and sets up for the inverse Burrows-Wheeler step.
#[link_section = ".init.text"]
unsafe fn get_next_block(bd: &mut BunzipData) -> i32 {
    let dbuf_size = bd.dbuf_size as usize;
    let dbuf = unsafe { core::slice::from_raw_parts_mut(bd.dbuf, dbuf_size) };

    let i = unsafe { get_bits(bd, 24) };
    let j = unsafe { get_bits(bd, 24) };
    bd.header_crc = unsafe { get_bits(bd, 32) };
    if i == 0x177245 && j == 0x385090 {
        return RETVAL_LAST_BLOCK;
    }
    if i != 0x314159 || j != 0x265359 {
        return RETVAL_NOT_BZIP_DATA;
    }
    if unsafe { get_bits(bd, 1) } != 0 {
        return RETVAL_OBSOLETE_INPUT;
    }
    let orig_ptr = unsafe { get_bits(bd, 24) };
    if orig_ptr as usize >= dbuf_size {
        return RETVAL_DATA_ERROR;
    }

    // Symbol map: which of the 256 byte values actually occur. `sym_total`
    // is bounded by the two nested loops' own trip counts (16*16 = 256,
    // matching `sym_to_byte`'s size) -- format-structural, same class as
    // the array bounds already audited in the bounds_check investigation.
    // wrapping_* throughout this function, found by the
    // CONFIG_RUST_OVERFLOW_CHECKS sweep, 2026-09-06.
    let t = unsafe { get_bits(bd, 16) };
    let mut sym_total: usize = 0;
    for i in 0..16u32 {
        if t & (1u32.wrapping_shl(15u32.wrapping_sub(i))) != 0 {
            let k = unsafe { get_bits(bd, 16) };
            for j in 0..16u32 {
                if k & (1u32.wrapping_shl(15u32.wrapping_sub(j))) != 0 {
                    bd.sym_to_byte[sym_total] = (16u32.wrapping_mul(i).wrapping_add(j)) as u8;
                    sym_total = sym_total.wrapping_add(1);
                }
            }
        }
    }

    let group_count = unsafe { get_bits(bd, 3) } as i32;
    if !(2..=MAX_GROUPS as i32).contains(&group_count) {
        return RETVAL_DATA_ERROR;
    }
    let n_selectors = unsafe { get_bits(bd, 15) } as usize;
    if n_selectors == 0 {
        return RETVAL_DATA_ERROR;
    }
    for i in 0..group_count as usize {
        bd.mtf_symbol[i] = i as u8;
    }
    for i in 0..n_selectors {
        let mut j = 0usize;
        // Recorded divergence, found by adversarial review: C's `for (j = 0;
        // get_bits(bd, 1); j++) if (j >= groupCount) return
        // RETVAL_DATA_ERROR;` can, on malformed input, let j reach exactly
        // groupCount without tripping the bound check (the check and the
        // increment are staggered across loop iterations), going on to
        // read mtfSymbol[groupCount] -- one past the range this loop itself
        // just initialised, on a block past the first. This form checks the
        // bound every iteration before incrementing, rejecting that case
        // instead. Every valid stream (selectors are always < groupCount by
        // construction) decodes identically either way -- this only differs
        // on already-malformed input, and rejects it more safely.
        while unsafe { get_bits(bd, 1) } != 0 {
            j = j.wrapping_add(1);
            if j >= group_count as usize {
                return RETVAL_DATA_ERROR;
            }
        }
        let uc = bd.mtf_symbol[j];
        let mut j = j;
        while j != 0 {
            bd.mtf_symbol[j] = bd.mtf_symbol[j.wrapping_sub(1)];
            j = j.wrapping_sub(1);
        }
        bd.mtf_symbol[0] = uc;
        bd.selectors[i] = uc;
    }

    // Huffman tables: symTotal literals plus RUNA/RUNB. `sym_total <= 256`
    // (proven above), so this is nowhere near usize::MAX.
    let sym_count = sym_total.wrapping_add(2);
    for grp in 0..group_count as usize {
        let mut length = [0u8; MAX_SYMBOLS];
        let mut temp = [0u16; MAX_HUFCODE_BITS + 1];

        let mut t: i32 = (unsafe { get_bits(bd, 5) } as i32).wrapping_sub(1);
        for i in 0..sym_count {
            loop {
                if (t as u32) > (MAX_HUFCODE_BITS as u32).wrapping_sub(1) {
                    return RETVAL_DATA_ERROR;
                }
                let k = unsafe { get_bits(bd, 2) };
                if k < 2 {
                    bd.inbuf_bit_count = bd.inbuf_bit_count.wrapping_add(1);
                    break;
                }
                t = t.wrapping_add((k as i32).wrapping_add(1) & 2).wrapping_sub(1);
            }
            length[i] = (t.wrapping_add(1)) as u8;
        }

        let mut min_len = length[0];
        let mut max_len = length[0];
        for &l in &length[1..sym_count] {
            if l > max_len {
                max_len = l;
            } else if l < min_len {
                min_len = l;
            }
        }

        let g = &mut bd.groups[grp];
        g.min_len = min_len as i32;
        g.max_len = max_len as i32;

        // `min_len`/`max_len` are bounded 1..=MAX_HUFCODE_BITS (the loop
        // above rejects anything outside that range), so every `- 1` index
        // and `max_len - i` shift amount below is bounded by that same
        // format constant, matching the C's own unguarded equivalent.
        let mut pp: usize = 0;
        for i in min_len..=max_len {
            temp[(i as usize).wrapping_sub(1)] = 0;
            g.limit[(i as usize).wrapping_sub(1)] = 0;
            for t in 0..sym_count {
                if length[t] == i {
                    g.permute[pp] = t as i32;
                    pp = pp.wrapping_add(1);
                }
            }
        }
        for i in 0..sym_count {
            temp[(length[i] as usize).wrapping_sub(1)] =
                temp[(length[i] as usize).wrapping_sub(1)].wrapping_add(1);
        }
        let mut pp: i32 = 0;
        let mut t: i32 = 0;
        for i in min_len..max_len {
            pp = pp.wrapping_add(temp[(i as usize).wrapping_sub(1)] as i32);
            g.limit[(i as usize).wrapping_sub(1)] =
                (pp.wrapping_shl((max_len.wrapping_sub(i)) as u32)).wrapping_sub(1);
            pp = pp.wrapping_shl(1);
            t = t.wrapping_add(temp[(i as usize).wrapping_sub(1)] as i32);
            g.base[i as usize] = pp.wrapping_sub(t);
        }
        g.limit[max_len as usize] = i32::MAX;
        g.limit[(max_len as usize).wrapping_sub(1)] =
            pp.wrapping_add(temp[(max_len as usize).wrapping_sub(1)] as i32).wrapping_sub(1);
        g.base[(min_len as usize).wrapping_sub(1)] = 0;
    }

    for i in 0..256usize {
        bd.byte_count[i] = 0;
        bd.mtf_symbol[i] = i as u8;
    }

    // i64, not i32: C's `int runPos`/`int t` accumulate via `t +=
    // (runPos << nextSym); runPos <<= 1;` with no bound on consecutive
    // RUNA/RUNB symbols, so a malformed stream overflows a 32-bit
    // accumulator -- signed-overflow UB in C, a checked-arithmetic panic in
    // Rust. i64 plus the `>= dbuf_size` bound just below (a run this long
    // can never be valid; dbuf_size tops out at 900,000) makes the overflow
    // unreachable instead of relying on wraparound to match a UB path.
    let mut run_pos: i64 = 0;
    let mut dbuf_count: usize = 0;
    let mut sym_count_dn: i32 = 0;
    let mut selector: usize = 0;
    let mut group_idx: usize = 0;
    let mut t_accum: i64 = 0;

    loop {
        if sym_count_dn == 0 {
            sym_count_dn = GROUP_SIZE;
            if selector >= n_selectors {
                return RETVAL_DATA_ERROR;
            }
            group_idx = bd.selectors[selector] as usize;
            selector += 1;
        }
        sym_count_dn -= 1;

        // Bit-accounting, table indices and the RUNA/RUNB accumulators below
        // are all bounded by the same format-structural constants as the
        // Huffman table build above (MAX_HUFCODE_BITS/MAX_SYMBOLS,
        // dbuf_size), matching the C's own unguarded equivalent throughout.
        // wrapping_* found by the CONFIG_RUST_OVERFLOW_CHECKS sweep,
        // 2026-09-06.
        let max_len = bd.groups[group_idx].max_len;
        let j: u32 = 'refill: {
            while (bd.inbuf_bit_count as i32) < max_len {
                if bd.inbuf_pos == bd.inbuf_count {
                    break 'refill unsafe { get_bits(bd, max_len as u32) };
                }
                let byte = unsafe { *bd.inbuf.offset(bd.inbuf_pos as isize) };
                bd.inbuf_pos = bd.inbuf_pos.wrapping_add(1);
                bd.inbuf_bits = (bd.inbuf_bits.wrapping_shl(8)) | byte as u32;
                bd.inbuf_bit_count = bd.inbuf_bit_count.wrapping_add(8);
            }
            bd.inbuf_bit_count = bd.inbuf_bit_count.wrapping_sub(max_len as u32);
            (bd.inbuf_bits.wrapping_shr(bd.inbuf_bit_count))
                & (1u32.wrapping_shl(max_len as u32).wrapping_sub(1))
        };

        let min_len = bd.groups[group_idx].min_len;
        let mut i = min_len;
        while (j as i32) > bd.groups[group_idx].limit[(i as usize).wrapping_sub(1)] {
            i = i.wrapping_add(1);
        }
        bd.inbuf_bit_count = ((bd.inbuf_bit_count as i32).wrapping_add(max_len.wrapping_sub(i))) as u32;

        if i > max_len {
            return RETVAL_DATA_ERROR;
        }
        let sym = (j.wrapping_shr((max_len.wrapping_sub(i)) as u32) as i32)
            .wrapping_sub(bd.groups[group_idx].base[(i as usize).wrapping_sub(1)]);
        if (sym as u32) >= MAX_SYMBOLS as u32 {
            return RETVAL_DATA_ERROR;
        }
        let next_sym = bd.groups[group_idx].permute[sym as usize];

        if (next_sym as u32) <= SYMBOL_RUNB as u32 {
            if run_pos == 0 {
                run_pos = 1;
                t_accum = 0;
            }
            t_accum = t_accum.wrapping_add(run_pos.wrapping_shl(next_sym as u32));
            run_pos = run_pos.wrapping_shl(1);
            // No valid stream ever runs a byte anywhere near dbuf_size
            // times; a run this long is malformed input, not a bigger
            // valid run. Catching it here keeps both variables far below
            // where i64 arithmetic could ever overflow.
            if t_accum >= dbuf_size as i64 || run_pos >= dbuf_size as i64 {
                return RETVAL_DATA_ERROR;
            }
            continue;
        }

        if run_pos != 0 {
            run_pos = 0;
            if (dbuf_count as i64).wrapping_add(t_accum) >= dbuf_size as i64 {
                return RETVAL_DATA_ERROR;
            }
            let uc = bd.sym_to_byte[bd.mtf_symbol[0] as usize];
            bd.byte_count[uc as usize] = bd.byte_count[uc as usize].wrapping_add(t_accum as i32);
            while t_accum > 0 {
                t_accum = t_accum.wrapping_sub(1);
                dbuf[dbuf_count] = uc as u32;
                dbuf_count = dbuf_count.wrapping_add(1);
            }
        }
        if next_sym as usize > sym_total {
            break;
        }
        if dbuf_count >= dbuf_size {
            return RETVAL_DATA_ERROR;
        }
        let mut i = (next_sym as usize).wrapping_sub(1);
        let uc = bd.mtf_symbol[i];
        while i != 0 {
            bd.mtf_symbol[i] = bd.mtf_symbol[i.wrapping_sub(1)];
            i = i.wrapping_sub(1);
        }
        bd.mtf_symbol[0] = uc;
        let uc = bd.sym_to_byte[uc as usize];
        bd.byte_count[uc as usize] = bd.byte_count[uc as usize].wrapping_add(1);
        dbuf[dbuf_count] = uc as u32;
        dbuf_count = dbuf_count.wrapping_add(1);
    }

    // Undo the Burrows-Wheeler transform. `byte_count[]` is a running
    // cumulative histogram of `dbuf`'s own contents, in range by
    // construction (the same counting-sort invariant the bounds_check
    // investigation already verified for this exact loop).
    let mut j: i32 = 0;
    for i in 0..256usize {
        let k = j.wrapping_add(bd.byte_count[i]);
        bd.byte_count[i] = j;
        j = k;
    }
    for i in 0..dbuf_count {
        let uc = (dbuf[i] & 0xff) as usize;
        dbuf[bd.byte_count[uc] as usize] |= (i as u32).wrapping_shl(8);
        bd.byte_count[uc] = bd.byte_count[uc].wrapping_add(1);
    }

    if dbuf_count != 0 {
        if orig_ptr as usize >= dbuf_count {
            return RETVAL_DATA_ERROR;
        }
        bd.write_pos = dbuf[orig_ptr as usize] as i32;
        bd.write_current = bd.write_pos & 0xff;
        bd.write_pos >>= 8;
        bd.write_run_countdown = 5;
    }
    bd.write_count = dbuf_count as i32;

    RETVAL_OK
}

enum ReadState {
    Top,
    DecodeNext,
}

/// `read_bunzip()`, `lib/decompress_bunzip2.c`. Undoes the Burrows-Wheeler
/// transform on the intermediate buffer to produce output.
#[link_section = ".init.text"]
unsafe fn read_bunzip(bd: &mut BunzipData, outbuf: *mut u8, len: i32) -> i32 {
    if bd.write_count < 0 {
        return bd.write_count;
    }

    let mut gotcount: i32 = 0;
    let dbuf = unsafe { core::slice::from_raw_parts(bd.dbuf, bd.dbuf_size as usize) };
    let mut pos = bd.write_pos;
    let mut xcurrent = bd.write_current;

    if bd.write_copies != 0 {
        bd.write_copies = bd.write_copies.wrapping_sub(1);
        let mut state = ReadState::Top;
        let broke_by_count = 'outer: loop {
            match state {
                ReadState::Top => loop {
                    if gotcount >= len {
                        bd.write_pos = pos;
                        bd.write_current = xcurrent;
                        bd.write_copies = bd.write_copies.wrapping_add(1);
                        return gotcount;
                    }
                    unsafe { *outbuf.offset(gotcount as isize) = xcurrent as u8 };
                    gotcount = gotcount.wrapping_add(1);
                    bd.write_crc = (bd.write_crc.wrapping_shl(8))
                        ^ bd.crc32_table[((bd.write_crc.wrapping_shr(24)) ^ xcurrent as u32) as usize & 0xff];
                    if bd.write_copies != 0 {
                        bd.write_copies = bd.write_copies.wrapping_sub(1);
                        continue;
                    }
                    state = ReadState::DecodeNext;
                    break;
                },
                ReadState::DecodeNext => {
                    if bd.write_count == 0 {
                        bd.write_count = -1;
                        break 'outer true;
                    }
                    bd.write_count = bd.write_count.wrapping_sub(1);
                    let previous = xcurrent;
                    pos = dbuf[pos as usize] as i32;
                    xcurrent = pos & 0xff;
                    pos >>= 8;
                    bd.write_run_countdown = bd.write_run_countdown.wrapping_sub(1);
                    if bd.write_run_countdown != 0 {
                        if xcurrent != previous {
                            bd.write_run_countdown = 4;
                        }
                    } else {
                        bd.write_copies = xcurrent;
                        xcurrent = previous;
                        bd.write_run_countdown = 5;
                        if bd.write_copies == 0 {
                            continue 'outer;
                        }
                        bd.write_copies = bd.write_copies.wrapping_sub(1);
                    }
                    state = ReadState::Top;
                }
            }
        };
        let _ = broke_by_count;

        bd.write_crc = !bd.write_crc;
        bd.total_crc = ((bd.total_crc.wrapping_shl(1)) | (bd.total_crc.wrapping_shr(31))) ^ bd.write_crc;
        if bd.write_crc != bd.header_crc {
            // header_crc is 32 attacker-controlled bits off the wire; C's
            // `+1` relies on unsigned wraparound (0xffffffff -> 0), which a
            // checked `+` does not give under CONFIG_RUST_OVERFLOW_CHECKS=y.
            bd.total_crc = bd.header_crc.wrapping_add(1);
            return RETVAL_LAST_BLOCK;
        }
    }

    let block = unsafe { get_next_block(bd) };
    if block != 0 {
        bd.write_count = block;
        return if block != RETVAL_LAST_BLOCK { block } else { gotcount };
    }
    bd.write_crc = 0xffff_ffff;
    pos = bd.write_pos;
    xcurrent = bd.write_current;

    // `goto decode_next_byte` from outside the loop above: resume directly
    // in the decode half, sharing its body via the same state machine.
    let mut state = ReadState::DecodeNext;
    loop {
        match state {
            ReadState::Top => loop {
                if gotcount >= len {
                    bd.write_pos = pos;
                    bd.write_current = xcurrent;
                    bd.write_copies = bd.write_copies.wrapping_add(1);
                    return gotcount;
                }
                unsafe { *outbuf.offset(gotcount as isize) = xcurrent as u8 };
                gotcount = gotcount.wrapping_add(1);
                bd.write_crc = (bd.write_crc.wrapping_shl(8))
                    ^ bd.crc32_table[((bd.write_crc.wrapping_shr(24)) ^ xcurrent as u32) as usize & 0xff];
                if bd.write_copies != 0 {
                    bd.write_copies = bd.write_copies.wrapping_sub(1);
                    continue;
                }
                state = ReadState::DecodeNext;
                break;
            },
            ReadState::DecodeNext => {
                if bd.write_count == 0 {
                    bd.write_count = -1;
                    bd.write_crc = !bd.write_crc;
                    bd.total_crc = ((bd.total_crc.wrapping_shl(1)) | (bd.total_crc.wrapping_shr(31))) ^ bd.write_crc;
                    if bd.write_crc != bd.header_crc {
                        // header_crc is 32 attacker-controlled bits off the wire; C's
            // `+1` relies on unsigned wraparound (0xffffffff -> 0), which a
            // checked `+` does not give under CONFIG_RUST_OVERFLOW_CHECKS=y.
            bd.total_crc = bd.header_crc.wrapping_add(1);
                        return RETVAL_LAST_BLOCK;
                    }
                    let block = unsafe { get_next_block(bd) };
                    if block != 0 {
                        bd.write_count = block;
                        return if block != RETVAL_LAST_BLOCK { block } else { gotcount };
                    }
                    bd.write_crc = 0xffff_ffff;
                    pos = bd.write_pos;
                    xcurrent = bd.write_current;
                    state = ReadState::DecodeNext;
                    continue;
                }
                bd.write_count = bd.write_count.wrapping_sub(1);
                let previous = xcurrent;
                let dbuf = unsafe { core::slice::from_raw_parts(bd.dbuf, bd.dbuf_size as usize) };
                pos = dbuf[pos as usize] as i32;
                xcurrent = pos & 0xff;
                pos >>= 8;
                bd.write_run_countdown = bd.write_run_countdown.wrapping_sub(1);
                if bd.write_run_countdown != 0 {
                    if xcurrent != previous {
                        bd.write_run_countdown = 4;
                    }
                } else {
                    bd.write_copies = xcurrent;
                    xcurrent = previous;
                    bd.write_run_countdown = 5;
                    if bd.write_copies == 0 {
                        continue;
                    }
                    bd.write_copies = bd.write_copies.wrapping_sub(1);
                }
                state = ReadState::Top;
            }
        }
    }
}

#[link_section = ".init.text"]
unsafe extern "C" fn nofill(_buf: *mut c_void, _len: c_ulong) -> c_long {
    -1
}

/// `start_bunzip()`, `lib/decompress_bunzip2.c`.
///
/// Returns the allocated `bd` alongside the status, mirroring the C's
/// `struct bunzip_data **bdp` out-parameter: `*bdp` (here, the returned
/// pointer) is set as soon as the first allocation succeeds and stays set
/// on every later error path too (bad magic, dbuf allocation failure) --
/// C's `start_bunzip` never frees it itself on those paths, leaving that to
/// `bunzip2`'s own cleanup, which is also where `*pos` gets written from
/// `bd->inbufPos`. Freeing here instead (an earlier version of this port
/// did) is not a leak or a double-free, but it silently drops `*pos` on
/// those paths since the caller never gets the pointer back to read it from.
/// Only a failure of the FIRST allocation returns a null pointer.
#[link_section = ".init.text"]
unsafe fn start_bunzip(
    inbuf: *mut u8,
    len: c_long,
    fill: Option<FillFn>,
) -> (*mut BunzipData, i32) {
    const BZH0: u32 = (b'B' as u32) << 24 | (b'Z' as u32) << 16 | (b'h' as u32) << 8 | b'0' as u32;

    let size = core::mem::size_of::<BunzipData>();
    let raw = unsafe { decompress_bunzip2_alloc(size as c_uint) } as *mut u8;
    if raw.is_null() {
        return (ptr::null_mut(), RETVAL_OUT_OF_MEMORY);
    }
    unsafe { ptr::write_bytes(raw, 0, size) };
    let bd_ptr = raw as *mut BunzipData;
    let bd = unsafe { &mut *bd_ptr };

    bd.inbuf = inbuf;
    bd.inbuf_count = len;
    bd.fill = Some(fill.unwrap_or(nofill));

    for i in 0..256u32 {
        let mut c = i << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ CRC32_POLY_BE
            } else {
                c << 1
            };
        }
        bd.crc32_table[i as usize] = c;
    }

    let i = unsafe { get_bits(bd, 32) };
    if i.wrapping_sub(BZH0).wrapping_sub(1) >= 9 {
        return (bd_ptr, RETVAL_NOT_BZIP_DATA);
    }

    bd.dbuf_size = 100_000 * (i - BZH0);
    let dict = unsafe { decompress_bunzip2_dict_alloc(bd.dbuf_size * 4) } as *mut u32;
    if dict.is_null() {
        return (bd_ptr, RETVAL_OUT_OF_MEMORY);
    }
    bd.dbuf = dict;

    (bd_ptr, RETVAL_OK)
}

/// `bunzip2()`, `lib/decompress_bunzip2.c`. The dispatcher's `.decompressor`
/// entry for the `"bzip2"` magic (`BZh`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn bunzip2(
    buf: *mut u8,
    len: c_long,
    fill: Option<FillFn>,
    flush: Option<FlushFn>,
    mut outbuf: *mut u8,
    pos: *mut c_long,
    error: Option<ErrorFn>,
) -> c_int {
    // Recorded divergence, same as decompress_unlz4_rs.rs and
    // decompress_unlzo_rs.rs: C calls `error(...)` unconditionally, a
    // crash if the caller passed NULL. This closure tolerates
    // `error == NULL` instead of reproducing that contract violation.
    let call_error = |msg: &[u8]| {
        if let Some(e) = error {
            unsafe { e(msg.as_ptr() as *mut c_char) };
        }
    };

    if flush.is_some() {
        outbuf = unsafe { decompress_bunzip2_alloc(BZIP2_IOBUF_SIZE as c_uint) } as *mut u8;
    }
    if outbuf.is_null() {
        call_error(b"Could not allocate output buffer\0");
        return RETVAL_OUT_OF_MEMORY;
    }

    let inbuf = if !buf.is_null() {
        buf
    } else {
        unsafe { decompress_bunzip2_alloc(BZIP2_IOBUF_SIZE as c_uint) as *mut u8 }
    };
    if inbuf.is_null() {
        call_error(b"Could not allocate input buffer\0");
        if flush.is_some() {
            unsafe { kfree(outbuf as *const c_void) };
        }
        return RETVAL_OUT_OF_MEMORY;
    }

    let (bd_ptr, started_status) = unsafe { start_bunzip(inbuf, len, fill) };
    let mut i: i32;
    if started_status == RETVAL_OK {
        let bd = unsafe { &mut *bd_ptr };
        loop {
            let n = unsafe { read_bunzip(bd, outbuf, BZIP2_IOBUF_SIZE as i32) };
            i = n;
            if n <= 0 {
                break;
            }
            match flush {
                None => outbuf = unsafe { outbuf.offset(n as isize) },
                Some(f) => {
                    if n as c_long != unsafe { f(outbuf as *mut c_void, n as c_ulong) } {
                        i = RETVAL_UNEXPECTED_OUTPUT_EOF;
                        break;
                    }
                }
            }
        }
    } else {
        i = started_status;
    }

    if i == RETVAL_LAST_BLOCK {
        let bd = unsafe { &*bd_ptr };
        if bd.header_crc != bd.total_crc {
            call_error(b"Data integrity error when decompressing.\0");
        } else {
            i = RETVAL_OK;
        }
    } else if i == RETVAL_UNEXPECTED_OUTPUT_EOF {
        call_error(b"Compressed file ends unexpectedly\0");
    }

    if !bd_ptr.is_null() {
        let bd = unsafe { &*bd_ptr };
        if !bd.dbuf.is_null() {
            unsafe { vfree(bd.dbuf as *const c_void) };
        }
        if !pos.is_null() {
            unsafe { *pos = bd.inbuf_pos };
        }
        unsafe { kfree(bd_ptr as *const c_void) };
    }
    if buf.is_null() {
        unsafe { kfree(inbuf as *const c_void) };
    }
    if flush.is_some() {
        unsafe { kfree(outbuf as *const c_void) };
    }
    i
}
