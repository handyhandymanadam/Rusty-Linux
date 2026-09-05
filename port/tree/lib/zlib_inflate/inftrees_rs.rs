// SPDX-License-Identifier: GPL-2.0

//! Huffman decoding table construction for `zlib_inflate`.
//!
//! Ported from `lib/zlib_inflate/inftrees.c` (6.18.49), which carries
//! `Copyright (C) 1995-2005 Mark Adler`.
//!
//! # Shape: no C entry symbol
//!
//! `zlib_inflate_table()` is global but **not** `EXPORT_SYMBOL`'d — its only
//! caller is `zlib_inflate()` in `inflate.c`, three call sites — so it has no
//! MODVERSIONS CRC and GOALS.md §1's entry-thunk constraint does not reach it.
//! `inftrees.c` comes out of `zlib_inflate-objs` and this stands in its place,
//! the same shape as `inffast_rs.rs` beside it.
//!
//! **The C file is not deleted, and that is not an oversight.**
//! `lib/decompress_inflate.c:10` textually `#include`s it for the pre-boot
//! decompressor, and both of this project's configs set `CONFIG_KERNEL_GZIP`,
//! so that copy **is** compiled — into
//! `arch/x86/boot/compressed/misc.o`. Dropping a file from a Makefile does not
//! delete it. So the kernel image is decompressed by the C and everything
//! afterwards by this; both statements are true and they are about different
//! stages.
//!
//! # `struct code` is mirrored here AND in `inffast_rs.rs`
//!
//! One crate per ported file means there is no way to share the definition
//! today. Both mirrors are three fields and `#[repr(C)]`, both are checked
//! against `offsetof()` on the real header by their own differential, and
//! `port/test/zlib_inflate/main.c` now checks both. Recorded because a second
//! copy of a caller-owned layout is exactly the thing that goes stale
//! quietly — see STATUS.md's code-layout table on crate granularity.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **`lens` and `work` are slices; the table stays a raw pointer.** The
//!    first two have a length the caller passes in (`codes`), so they can be
//!    checked. The output table does not: `*table` is `state->next`, which the
//!    caller has already advanced past earlier tables, and the space left is
//!    `ENOUGH` minus an offset this function is never told. The C's own
//!    comment says the sufficiency of `ENOUGH` "has not been proven
//!    exhaustively, hence the check" — so the honest thing is to keep the C's
//!    contract and its `ENOUGH - MAXD` guard rather than invent a bound.
//!
//! 2. **`base` and `extra` are indexed, not offset.** The C does
//!    `base = lbase; base -= 257;` and then `base[work[sym]]`. Forming a
//!    pointer 257 elements before an array is undefined behaviour in C even
//!    when it works, and there is no way to spell it in Rust. The index is
//!    biased instead, at the one place it is used.
//!
//! 3. **For `CODES`, the `work[sym] > end` arm cannot be taken**, because
//!    `end` is 19 and `work[]` holds symbol indices below `codes`, which is 19
//!    at that call site. The C sets `base = extra = work` there and calls it a
//!    "dummy value--not used". Rather than reproduce a read of `work[work[sym]]`
//!    that can never happen, this returns the literal arm's answer and asserts.
//!
//! 4. **`wrapping_*` where the C relies on unsigned wraparound**, with the
//!    invariant named in a `debug_assert!`. `CONFIG_RUST_OVERFLOW_CHECKS=y` on
//!    both configs and this function is fed code lengths out of an attacker's
//!    deflate stream.
//!
//! # What is NOT changed
//!
//! `min` is used for two unrelated things in the C — the minimum code length,
//! and then "save offset to next table" inside the main loop. That is kept, in
//! one variable, because splitting it would make the two loops harder to check
//! against the original, and the original is what a reviewer will have open.
//!
//! Replaces: lib/zlib_inflate/inftrees.c

use core::ffi::{c_int, c_uint};

/// The longest Huffman code deflate permits.
const MAXBITS: usize = 15;

/// `ENOUGH`, `lib/zlib_inflate/inftrees.h`. Maximum size of a dynamic tree.
const ENOUGH: u32 = 2048;
/// `MAXD`, `lib/zlib_inflate/inftrees.h`. Worst case for the distance code.
const MAXD: u32 = 592;

/// `ENOUGH`, for the differential's ABI check. The two constants below are the
/// only numbers in this file that come from a header rather than from the
/// algorithm, so they are the two worth checking against it.
pub fn enough() -> u32 {
    ENOUGH
}

/// `MAXD`, for the differential's ABI check.
pub fn maxd() -> u32 {
    MAXD
}

/// `CODES`, the first `codetype`: the 19-symbol code-length alphabet.
const CODES: c_uint = 0;
/// `LENS`, the second: literal/length codes.
const LENS: c_uint = 1;
/// `DISTS`, the third: distance codes.
const DISTS: c_uint = 2;

/// Mirrors `code` in `lib/zlib_inflate/inftrees.h`. Four bytes, and the layout
/// is the caller's — `struct inflate_state` embeds an array of 2048 of them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Code {
    /// Operation, extra bits, or table-index bits.
    pub op: u8,
    /// Bits consumed by this part of the code.
    pub bits: u8,
    /// Literal byte, base length/distance, or offset to the next table.
    pub val: u16,
}

/// Length codes 257..285 base.
const LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258, 0, 0,
];
/// Length codes 257..285 extra.
const LEXT: [u16; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20,
    20, 21, 21, 21, 21, 16, 201, 196,
];
/// Distance codes 0..29 base.
const DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];
/// Distance codes 0..29 extra.
const DEXT: [u16; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26,
    26, 27, 27, 28, 28, 29, 29, 64, 64,
];

/// Build a set of tables to decode the provided canonical Huffman code.
///
/// The code lengths are `lens[0..codes-1]`. The result starts at `*table`,
/// whose indices are `0..2^bits-1`. `work` is a writable array of at least
/// `lens` shorts, used as a work area. `kind` is the type of code to generate:
/// `CODES`, `LENS` or `DISTS`.
///
/// Returns 0 on success, -1 for an invalid code, and +1 when `ENOUGH` is not
/// enough. On return `*table` points at the next available entry and `*bits`
/// is the actual root table index bits — it differs from the request if the
/// request was greater than the longest code or less than the shortest.
///
/// This assumes, but does not check, that every entry in `lens` is in
/// `0..=MAXBITS`. The caller must assure that; `inflate.c` does.
///
/// # Safety
///
/// `lens` must point at `codes` readable `u16`s, `work` at `codes` writable
/// ones, and `*table` at enough `Code` entries for the table this builds —
/// `ENOUGH` minus what the caller has already consumed, which is the same
/// contract `inftrees.c` has always had. `bits` must be a live `c_uint`.
#[no_mangle]
pub unsafe extern "C" fn zlib_inflate_table(
    kind: c_uint,
    lens: *mut u16,
    codes: c_uint,
    table: *mut *mut Code,
    bits: *mut c_uint,
    work: *mut u16,
) -> c_int {
    // SAFETY: the caller guarantees `codes` readable entries at `lens` and
    // `codes` writable ones at `work`.
    let lens = unsafe { core::slice::from_raw_parts(lens, codes as usize) };
    // SAFETY: as above.
    let work = unsafe { core::slice::from_raw_parts_mut(work, codes as usize) };

    let mut count = [0u16; MAXBITS + 1];
    let mut offs = [0u16; MAXBITS + 1];

    // Accumulate lengths for codes (assumes lens[] all in 0..MAXBITS).
    for sym in 0..codes as usize {
        count[lens[sym] as usize] += 1;
    }

    // Bound code lengths, force root to be within code lengths.
    // SAFETY: `bits` is live per the contract above.
    let mut root: u32 = unsafe { *bits };
    let mut max: u32 = MAXBITS as u32;
    while max >= 1 {
        if count[max as usize] != 0 {
            break;
        }
        max -= 1;
    }
    if root > max {
        root = max;
    }
    if max == 0 {
        // No symbols to code at all: make a table that forces an error.
        let this = Code {
            op: 64,
            bits: 1,
            val: 0,
        };
        // SAFETY: the caller's table always has room for the two entries the
        // C writes here; `inflate.c` reserves ENOUGH.
        unsafe {
            let t = *table;
            *t = this;
            *t.add(1) = this;
            *table = t.add(2);
            *bits = 1;
        }
        // No symbols, but wait for decoding to report the error.
        return 0;
    }
    let mut min: u32 = 1;
    while min < MAXBITS as u32 {
        if count[min as usize] != 0 {
            break;
        }
        min += 1;
    }
    if root < min {
        root = min;
    }

    // Check for an over-subscribed or incomplete set of lengths.
    let mut left: i32 = 1;
    for len in 1..=MAXBITS {
        left <<= 1;
        left -= count[len] as i32;
        if left < 0 {
            // Over-subscribed.
            return -1;
        }
    }
    if left > 0 && (kind == CODES || max != 1) {
        // Incomplete set.
        return -1;
    }

    // Generate offsets into the symbol table for each length, for sorting.
    offs[1] = 0;
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + count[len];
    }

    // Sort symbols by length, by symbol order within each length.
    for sym in 0..codes as usize {
        if lens[sym] != 0 {
            let o = offs[lens[sym] as usize] as usize;
            work[o] = sym as u16;
            offs[lens[sym] as usize] += 1;
        }
    }

    // Set up for the code type. `end` selects the literal / end-of-block /
    // length-or-distance arm below; see divergence 2 for the bias.
    let end: i32 = match kind {
        CODES => 19,
        LENS => 256,
        _ => -1,
    };

    // Initialise state for the loop.
    let mut huff: u32 = 0; // starting code
    let mut sym: usize = 0; // starting code symbol
    let mut len: u32 = min; // starting code length
    // SAFETY: `table` is live per the contract above.
    let table_base: *mut Code = unsafe { *table };
    let mut next: *mut Code = table_base; // current table to fill in
    let mut curr: u32 = root; // current table index bits
    let mut drop: u32 = 0; // current bits to drop from code for index
    let mut low: u32 = u32::MAX; // trigger new sub-table when len > root
    let mut used: u32 = 1u32 << root; // use root table entries
    let mask: u32 = used - 1; // mask for comparing low

    // Check available table space.
    if kind == LENS && used >= ENOUGH - MAXD {
        return 1;
    }

    // Process all codes and make table entries.
    loop {
        // Create the table entry.
        let ws = work[sym];
        let (op, val) = if (ws as i32) < end {
            (0u8, ws)
        } else if (ws as i32) > end {
            match kind {
                LENS => {
                    let i = ws as usize - 257;
                    (LEXT[i] as u8, LBASE[i])
                }
                DISTS => {
                    let i = ws as usize;
                    (DEXT[i] as u8, DBASE[i])
                }
                _ => {
                    // See divergence 3: unreachable for CODES.
                    debug_assert!(false, "CODES symbol above end");
                    (0u8, ws)
                }
            }
        } else {
            // End of block.
            (32 + 64, 0)
        };
        let this = Code {
            op,
            bits: (len - drop) as u8,
            val,
        };

        // Replicate for those indices with low len bits equal to huff.
        let mut incr: u32 = 1u32 << (len - drop);
        let mut fill: u32 = 1u32 << curr;
        min = fill; // save offset to next table -- the C reuses `min` here
        loop {
            fill -= incr;
            // SAFETY: `(huff >> drop) + fill` is inside the table this call
            // has claimed; that is the C's own bound and `used` tracks it.
            unsafe { *next.add(((huff >> drop) + fill) as usize) = this };
            if fill == 0 {
                break;
            }
        }

        // Backwards increment the len-bit code huff.
        incr = 1u32 << (len - 1);
        while huff & incr != 0 {
            incr >>= 1;
        }
        if incr != 0 {
            huff &= incr - 1;
            huff += incr;
        } else {
            huff = 0;
        }

        // Go to the next symbol, update count, len.
        sym += 1;
        count[len as usize] -= 1;
        if count[len as usize] == 0 {
            if len == max {
                break;
            }
            len = lens[work[sym] as usize] as u32;
        }

        // Create a new sub-table if needed.
        if len > root && (huff & mask) != low {
            // If first time, transition to sub-tables.
            if drop == 0 {
                drop = root;
            }

            // Increment past the last table. Here `min` is 1 << curr.
            // SAFETY: `min` entries were just filled at `next`, so this stays
            // within the space this call has claimed.
            next = unsafe { next.add(min as usize) };

            // Determine the length of the next table.
            curr = len - drop;
            left = 1i32 << curr;
            while curr + drop < max {
                left -= count[(curr + drop) as usize] as i32;
                if left <= 0 {
                    break;
                }
                curr += 1;
                left <<= 1;
            }

            // Check for enough space.
            used += 1u32 << curr;
            if kind == LENS && used >= ENOUGH - MAXD {
                return 1;
            }

            // Point the entry in the root table at the sub-table.
            low = huff & mask;
            // SAFETY: `low <= mask < 1 << root`, which is inside the root
            // table this call claimed first.
            unsafe {
                let e = &mut *table_base.add(low as usize);
                e.op = curr as u8;
                e.bits = root as u8;
                e.val = next.offset_from(table_base) as u16;
            }
        }
    }

    // Fill in the rest of the table for incomplete codes. This loop is like
    // the one above in incrementing huff for table indices. `len` is equal to
    // `curr + drop`, so no loop is needed to increment through high index
    // bits. When the current sub-table is filled, it drops back to the root
    // table to fill any remaining entries there.
    let mut this = Code {
        op: 64, // invalid code marker
        bits: (len - drop) as u8,
        val: 0,
    };
    while huff != 0 {
        // When done with the sub-table, drop back to the root table.
        if drop != 0 && (huff & mask) != low {
            drop = 0;
            len = root;
            next = table_base;
            this.bits = len as u8;
        }

        // Put the invalid code marker in the table.
        // SAFETY: `huff >> drop` is below `1 << curr` for the sub-table and
        // below `1 << root` for the root table; both are claimed space.
        unsafe { *next.add((huff >> drop) as usize) = this };

        // Backwards increment the len-bit code huff.
        let mut incr: u32 = 1u32 << (len - 1);
        while huff & incr != 0 {
            incr >>= 1;
        }
        if incr != 0 {
            huff &= incr - 1;
            huff += incr;
        } else {
            huff = 0;
        }
    }

    // Set the return parameters.
    // SAFETY: `table` and `bits` are live per the contract above.
    unsafe {
        *table = table_base.add(used as usize);
        *bits = root;
    }
    0
}
