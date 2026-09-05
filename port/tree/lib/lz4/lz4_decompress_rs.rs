// SPDX-License-Identifier: GPL-2.0
// (dual BSD-2-Clause, as the file it is ported from)

//! The LZ4 block decompressor.
//!
//! Ported from `lib/lz4/lz4_decompress.c` (6.18.49), which carries
//! `Copyright (C) 2011 - 2016, Yann Collet` under BSD-2-Clause, with kernel
//! changes by Sven Schmidt.
//!
//! # This one keeps its C entry symbols
//!
//! Eight of them are `EXPORT_SYMBOL`'d, so they carry MODVERSIONS CRCs and
//! GOALS.md §1's hard constraint binds. `lz4_decompress.c` keeps the entry
//! symbols and its `#ifdef STATIC` body; the bodies are here.
//!
//! # One function, eight instantiations, and const generics are the right tool
//!
//! `LZ4_decompress_generic()` is `FORCE_INLINE` with six parameters that are
//! always compile-time constants, so the C gets a specialised copy per caller
//! and the compiler folds the branches away. That is a template, and Rust
//! spells it `const` generics. [`decompress_generic`] takes `END_ON_INPUT`,
//! `PARTIAL` and `DICT` as const parameters and monomorphises exactly as the C
//! does — same code, same specialisation, without `__always_inline`.
//!
//! # WHY THIS ONE IS RAW POINTERS AND NOT SLICES
//!
//! `xz_dec_bcj_rs.rs` and `inflate_rs.rs` use slices wherever a length is
//! known. Here three separate things make that a *different program* rather
//! than a safer spelling of the same one:
//!
//! 1. **`LZ4_decompress_fast()` has no input length.** It passes `srcSize = 0`
//!    with `endOnInput` false; every input bound is compiled out and the
//!    decoder trusts the stream to end. There is no slice to build.
//!    `lib/decompress_unlz4.c:160` is a caller.
//! 2. **`lowPrefix` is legally outside any object.**
//!    `LZ4_decompress_fast()` passes `(BYTE *)dest - 64 * KB`. It is only ever
//!    *compared*, never dereferenced — but a Rust slice cannot describe it, and
//!    even the pointer arithmetic is undefined in C. Every such computation
//!    here is `wrapping_sub`/`wrapping_add`, which is defined in Rust; only a
//!    dereference would not be, and the checks prevent that.
//! 3. **`LZ4_wildCopy()` overruns on purpose**, by up to 7 bytes past its end,
//!    and the format's `MFLIMIT`/`LASTLITERALS` slack is what makes that safe.
//!    Expressing it as a checked slice copy means proving that slack at each of
//!    five sites, in a decoder where getting the proof wrong is a wild write.
//!
//! This is the `inffast_rs.rs` shape, for the same reason: the C is pointer
//! arithmetic over the caller's buffers and the honest port says so.
//!
//! **What is added instead: a `debug_assert!` at every site that reads or
//! writes past what it strictly needs, naming the slack it relies on.** They
//! compile out in the kernel and are live in `port/test/lz4/`, which is where
//! millions of streams go through them.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **All pointer arithmetic is `wrapping_*`.** `op - offset` with an
//!    attacker-controlled `offset` leaves the object routinely, and that is
//!    undefined behaviour in C and in Rust's `offset`. `wrapping_offset` is
//!    defined; the comparisons that follow are what keep it in bounds.
//!
//! 2. **`(uptrval)(op) + length < (uptrval)(op)` becomes
//!    `(op as usize).wrapping_add(length) < op as usize`.** Same overflow
//!    detection, spelled without integer overflow.
//!
//! # What is NOT changed
//!
//! The two-stage shortcut reads 16 bytes for a literal run of 0..14 and 18 for
//! a match of 4..18, and the `shortiend`/`shortoend` limits are what make that
//! safe. It is transcribed exactly, including the `&` rather than `&&` that
//! the C's comment says is deliberate.
//!
//! Replaces: lib/lz4/lz4_decompress.c

use core::ffi::{c_char, c_int, c_void};

/// `MINMATCH`, `lib/lz4/lz4defs.h`.
const MINMATCH: usize = 4;
/// `WILDCOPYLENGTH`.
const WILDCOPYLENGTH: isize = 8;
/// `LASTLITERALS`.
const LASTLITERALS: isize = 5;
/// `MFLIMIT` = `WILDCOPYLENGTH + MINMATCH`.
const MFLIMIT: isize = WILDCOPYLENGTH + MINMATCH as isize;
/// `MATCH_SAFEGUARD_DISTANCE` = `2 * WILDCOPYLENGTH - MINMATCH`.
const MATCH_SAFEGUARD_DISTANCE: isize = 2 * WILDCOPYLENGTH - MINMATCH as isize;
/// `ML_BITS`.
const ML_BITS: u32 = 4;
/// `ML_MASK`.
const ML_MASK: usize = (1usize << ML_BITS) - 1;
/// `RUN_MASK`, over `RUN_BITS = 8 - ML_BITS`.
const RUN_MASK: usize = (1usize << (8 - ML_BITS)) - 1;
/// 64 KiB, the largest LZ4 prefix.
const KB64: isize = 64 * 1024;

/// `noDict`, `lib/lz4/lz4defs.h`'s `dict_directive`.
const NO_DICT: u8 = 0;
/// `withPrefix64k`.
const WITH_PREFIX_64K: u8 = 1;
/// `usingExtDict`.
const USING_EXT_DICT: u8 = 2;

/// `inc32table[8]`.
const INC32TABLE: [usize; 8] = [0, 1, 2, 1, 0, 4, 4, 4];
/// `dec64table[8]`.
const DEC64TABLE: [isize; 8] = [0, 0, 0, -1, -4, 1, 2, 3];

/// Mirrors `LZ4_streamDecode_t_internal` in `include/linux/lz4.h`. Caller
/// owned — zram embeds it — so GOALS.md §5's layout rule applies.
#[repr(C)]
pub struct Lz4StreamDecode {
    /// The external dictionary, or null.
    pub external_dict: *const u8,
    /// Its size.
    pub ext_dict_size: usize,
    /// One past the end of the prefix decoded so far.
    pub prefix_end: *const u8,
    /// The prefix's size.
    pub prefix_size: usize,
}

/// `LZ4_readLE16()`.
///
/// # Safety
/// `p` must have two readable bytes.
#[inline]
unsafe fn read_le16(p: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { u16::from_le_bytes([*p, *p.add(1)]) as usize }
}

/// `LZ4_write32()`.
///
/// # Safety
/// `p` must have four writable bytes.
#[inline]
unsafe fn write32(p: *mut u8, v: u32) {
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 4) }
}

/// `LZ4_copy8()`: eight bytes, unaligned, source and destination may overlap
/// only in the way the caller has already accounted for.
///
/// # Safety
/// `src` must have eight readable bytes and `dst` eight writable ones.
#[inline]
unsafe fn copy8(dst: *mut u8, src: *const u8) {
    // SAFETY: the caller's contract. `copy` rather than `copy_nonoverlapping`
    // because the LZ4 match copies deliberately overlap; the C's `LZ4_copy8`
    // is a single unaligned load followed by a store, which has memmove
    // semantics for an 8-byte window.
    unsafe { core::ptr::copy(src, dst, 8) }
}

/// `LZ4_wildCopy()`: copies in eight-byte steps until it has passed `dst_end`,
/// so it may write up to seven bytes beyond it.
///
/// # Safety
///
/// `dst` must be writable to `dst_end` **rounded up to the next multiple of 8
/// from `dst`**, and `src` readable for the same length. That slack is the
/// LZ4 format's `MFLIMIT`/`LASTLITERALS` reserve, and every call site here
/// carries a `debug_assert!` naming the check that establishes it.
#[inline]
unsafe fn wild_copy(dst: *mut u8, src: *const u8, dst_end: *mut u8) {
    let mut d = dst;
    let mut s = src;
    loop {
        // SAFETY: the caller's contract.
        unsafe { copy8(d, s) };
        d = d.wrapping_add(8);
        s = s.wrapping_add(8);
        if d >= dst_end {
            break;
        }
    }
}

/// The one decoder, instantiated eight ways.
///
/// `END_ON_INPUT` is the C's `endOnInput` (`endOnInputSize` vs
/// `endOnOutputSize`), `PARTIAL` its `partialDecoding`, and `DICT` one of
/// [`NO_DICT`], [`WITH_PREFIX_64K`], [`USING_EXT_DICT`].
///
/// Returns the number of output bytes written when `END_ON_INPUT`, the number
/// of input bytes read otherwise, and a negative value on error.
///
/// # Safety
///
/// `src` must be readable for `src_size` bytes when `END_ON_INPUT`, and for as
/// far as a well-formed stream reaches otherwise. `dst` must be writable for
/// `output_size` bytes. `low_prefix` and `dict_start` are the caller's, and
/// `low_prefix` may point before `dst` — it is compared, never dereferenced,
/// except where `DICT == USING_EXT_DICT` makes it a real prefix.
///
/// This is `LZ4_decompress_generic()`'s contract unchanged. It is not a safe
/// interface and the C's is not either; the exported wrappers below are what
/// callers use.
#[allow(clippy::too_many_arguments)]
unsafe fn decompress_generic<const END_ON_INPUT: bool, const PARTIAL: bool, const DICT: u8>(
    src: *const u8,
    src_size: isize,
    dst: *mut u8,
    output_size: isize,
    low_prefix: *const u8,
    dict_start: *const u8,
    dict_size: usize,
) -> c_int {
    let mut ip: *const u8 = src;
    let iend: *const u8 = ip.wrapping_offset(src_size);

    let mut op: *mut u8 = dst;
    let oend: *mut u8 = op.wrapping_offset(output_size);
    let mut cpy: *mut u8;

    let dict_end: *const u8 = dict_start.wrapping_add(dict_size);

    let safe_decode = END_ON_INPUT;
    let check_offset = safe_decode && dict_size < KB64 as usize;

    /* Set up the "end" pointers for the shortcut. */
    let maxll: isize = if END_ON_INPUT { 14 } else { 8 };
    let shortiend: *const u8 = iend.wrapping_offset(-maxll).wrapping_offset(-2);
    let shortoend: *mut u8 = oend.wrapping_offset(-maxll).wrapping_offset(-18);

    /* Empty output buffer */
    if END_ON_INPUT && output_size == 0 {
        // SAFETY: `src_size >= 1` is what makes `*ip` readable here; when it
        // is not 1 the `&&` short-circuits before the read.
        return if src_size == 1 && unsafe { *ip } == 0 { 0 } else { -1 };
    }
    if !END_ON_INPUT && output_size == 0 {
        // SAFETY: the caller's stream has at least one byte.
        return if unsafe { *ip } == 0 { 1 } else { -1 };
    }
    if END_ON_INPUT && src_size == 0 {
        return -1;
    }

    /* Main Loop : decode sequences */
    'main: loop {
        let mut length: usize;
        let mut m: *const u8;
        let offset: usize;

        // SAFETY: on the first pass `src_size != 0`; afterwards the checks
        // below leave at least one readable byte, which is what
        // `ip < iend - RUN_MASK` and `ip >= iend - 2` are for.
        let token = unsafe { *ip } as usize;
        ip = ip.wrapping_add(1);
        length = token >> ML_BITS;

        // The `&` below is intentionally not `&&`; the C's comment says some
        // compilers parallelise the two comparisons better that way, and this
        // keeps the transcription exact.
        let stage1 = if END_ON_INPUT {
            length != RUN_MASK
        } else {
            length <= 8
        };
        let room = (if END_ON_INPUT { ip < shortiend } else { true }) & (op <= shortoend);

        if stage1 && room {
            /* Copy the literals */
            debug_assert!(op <= shortoend, "shortcut needs 18 bytes of output slack");
            // SAFETY: `op <= shortoend` leaves `maxll + 18` writable bytes and
            // `ip < shortiend` leaves `maxll + 2` readable ones, which covers
            // the 16 (or 8) copied here.
            unsafe { core::ptr::copy_nonoverlapping(ip, op, if END_ON_INPUT { 16 } else { 8 }) };
            op = op.wrapping_add(length);
            ip = ip.wrapping_add(length);

            /*
             * The second stage: prepare for match copying, decode full info.
             * If it doesn't work out, the info won't be wasted.
             */
            length = token & ML_MASK;
            // SAFETY: as above -- the two offset bytes are inside the slack.
            offset = unsafe { read_le16(ip) };
            ip = ip.wrapping_add(2);
            m = op.wrapping_sub(offset);

            /* Do not deal with overlapping matches. */
            if length != ML_MASK
                && offset >= 8
                && (DICT == WITH_PREFIX_64K || m >= low_prefix)
            {
                /* Copy the match. */
                // `op` has already advanced by `length`, which the stage-1
                // test bounds by `maxll`; `op <= shortoend` on entry therefore
                // leaves exactly 18 bytes here. Assert the invariant that is
                // actually true rather than the one that was true a moment ago
                // -- the first spelling of this fired on a valid stream.
                debug_assert!(
                    op <= oend.wrapping_offset(-18),
                    "the 18-byte match copy needs 18 bytes of output slack"
                );
                // SAFETY: `offset >= 8` makes the three copies
                // non-overlapping, and `m >= low_prefix` (or the 64k prefix)
                // makes them readable.
                unsafe {
                    core::ptr::copy_nonoverlapping(m, op, 8);
                    core::ptr::copy_nonoverlapping(m.add(8), op.add(8), 8);
                    core::ptr::copy_nonoverlapping(m.add(16), op.add(16), 2);
                }
                op = op.wrapping_add(length + MINMATCH);
                /* Both stages worked, load the next token. */
                continue 'main;
            }

            /*
             * The second stage didn't work out, but the info is ready. Propel
             * it right to the point of match copying.
             */
        } else {
            /* decode literal length */
            if length == RUN_MASK {
                let mut s: usize;

                if END_ON_INPUT && ip >= iend.wrapping_offset(-(RUN_MASK as isize)) {
                    /* overflow detection */
                    return output_error(ip, src);
                }
                loop {
                    // SAFETY: the bound just checked, and re-checked by the
                    // loop condition, leaves this byte readable.
                    s = unsafe { *ip } as usize;
                    ip = ip.wrapping_add(1);
                    length += s;
                    let more = (if END_ON_INPUT {
                        ip < iend.wrapping_offset(-(RUN_MASK as isize))
                    } else {
                        true
                    }) & (s == 255);
                    if !more {
                        break;
                    }
                }

                if safe_decode && (op as usize).wrapping_add(length) < op as usize {
                    /* overflow detection */
                    return output_error(ip, src);
                }
                if safe_decode && (ip as usize).wrapping_add(length) < ip as usize {
                    /* overflow detection */
                    return output_error(ip, src);
                }
            }

            /* copy literals */
            cpy = op.wrapping_add(length);
            const _: () = assert!(MFLIMIT >= WILDCOPYLENGTH);

            let tight = if END_ON_INPUT {
                cpy > oend.wrapping_offset(-MFLIMIT)
                    || ip.wrapping_add(length) > iend.wrapping_offset(-(2 + 1 + LASTLITERALS))
            } else {
                cpy > oend.wrapping_offset(-WILDCOPYLENGTH)
            };

            if tight {
                if PARTIAL {
                    if cpy > oend {
                        /* stop in the middle of a literal segment */
                        cpy = oend;
                        length = oend as usize - op as usize;
                    }
                    if END_ON_INPUT && ip.wrapping_add(length) > iend {
                        /* read attempt beyond end of input buffer */
                        return output_error(ip, src);
                    }
                } else {
                    if !END_ON_INPUT && cpy != oend {
                        /* block decoding must stop exactly there */
                        return output_error(ip, src);
                    }
                    if END_ON_INPUT && (ip.wrapping_add(length) != iend || cpy > oend) {
                        /* input must be consumed */
                        return output_error(ip, src);
                    }
                }

                /*
                 * supports overlapping memory regions; only matters for
                 * in-place decompression scenarios
                 */
                // SAFETY: the branch above established that `length` bytes are
                // readable at `ip` and writable at `op`.
                unsafe { core::ptr::copy(ip, op, length) };
                ip = ip.wrapping_add(length);
                op = op.wrapping_add(length);

                /*
                 * Necessarily EOF when !partialDecoding. When partialDecoding,
                 * it is EOF if we've either filled the output buffer or can't
                 * proceed with reading an offset for the following match.
                 */
                if !PARTIAL || cpy == oend || ip >= iend.wrapping_offset(-2) {
                    break 'main;
                }
            } else {
                debug_assert!(
                    cpy <= oend.wrapping_offset(-WILDCOPYLENGTH),
                    "wildCopy needs WILDCOPYLENGTH bytes of slack past cpy"
                );
                /* may overwrite up to WILDCOPYLENGTH beyond cpy */
                // SAFETY: the `tight` test that brought us here is exactly the
                // slack proof: `cpy <= oend - MFLIMIT` (or `- WILDCOPYLENGTH`)
                // on the output, and `ip + length <= iend - 8` on the input.
                unsafe { wild_copy(op, ip, cpy) };
                ip = ip.wrapping_add(length);
                op = cpy;
            }

            /* get offset */
            // SAFETY: the checks above leave at least `2 + 1 + LASTLITERALS`
            // readable bytes when END_ON_INPUT.
            offset = unsafe { read_le16(ip) };
            ip = ip.wrapping_add(2);
            m = op.wrapping_sub(offset);

            /* get matchlength */
            length = token & ML_MASK;
        }

        /* _copy_match: */
        if check_offset && m.wrapping_add(dict_size) < low_prefix {
            /* Error : offset outside buffers */
            return output_error(ip, src);
        }

        /*
         * costs ~1%; silences an msan warning when offset == 0. Note: when
         * partialDecoding, there is no guarantee that at least 4 bytes remain
         * available in the output buffer.
         */
        if !PARTIAL {
            debug_assert!(oend > op);
            debug_assert!(oend as usize - op as usize >= 4);
            // SAFETY: the assertions above, which the format's LASTLITERALS
            // reserve guarantees on a well-formed stream.
            unsafe { write32(op, offset as u32) };
        }

        if length == ML_MASK {
            let mut s: usize;

            loop {
                // SAFETY: the bound checked immediately after the read is the
                // C's own, in the same order.
                s = unsafe { *ip } as usize;
                ip = ip.wrapping_add(1);

                if END_ON_INPUT && ip > iend.wrapping_offset(-LASTLITERALS) {
                    return output_error(ip, src);
                }

                length += s;
                if s != 255 {
                    break;
                }
            }

            if safe_decode && (op as usize).wrapping_add(length) < op as usize {
                /* overflow detection */
                return output_error(ip, src);
            }
        }

        length += MINMATCH;

        /* match starting within external dictionary */
        if DICT == USING_EXT_DICT && m < low_prefix {
            if op.wrapping_add(length) > oend.wrapping_offset(-LASTLITERALS) {
                /* doesn't respect parsing restriction */
                if !PARTIAL {
                    return output_error(ip, src);
                }
                length = core::cmp::min(length, oend as usize - op as usize);
            }

            let from_prefix = low_prefix as usize - m as usize;
            if length <= from_prefix {
                /* match fits entirely within the external dictionary */
                // SAFETY: `dict_end - from_prefix` is inside the dictionary,
                // which the caller supplied with `dict_size` bytes.
                unsafe { core::ptr::copy(dict_end.wrapping_sub(from_prefix), op, length) };
                op = op.wrapping_add(length);
            } else {
                /* match stretches into both the dictionary and this block */
                let copy_size = from_prefix;
                let rest_size = length - copy_size;

                // SAFETY: as above.
                unsafe {
                    core::ptr::copy_nonoverlapping(dict_end.wrapping_sub(copy_size), op, copy_size)
                };
                op = op.wrapping_add(copy_size);
                if rest_size > op as usize - low_prefix as usize {
                    /* overlap copy */
                    let end_of_match = op.wrapping_add(rest_size);
                    let mut copy_from = low_prefix;

                    while op < end_of_match {
                        // SAFETY: the loop is bounded by `end_of_match`, which
                        // the length checks above put inside the output.
                        unsafe { *op = *copy_from };
                        op = op.wrapping_add(1);
                        copy_from = copy_from.wrapping_add(1);
                    }
                } else {
                    // SAFETY: `rest_size <= op - low_prefix`, so the source is
                    // inside the prefix already written.
                    unsafe { core::ptr::copy_nonoverlapping(low_prefix, op, rest_size) };
                    op = op.wrapping_add(rest_size);
                }
            }
            continue 'main;
        }

        /* copy match within block */
        cpy = op.wrapping_add(length);

        /* partialDecoding may not respect endBlock parsing restrictions */
        debug_assert!(op <= oend);
        if PARTIAL && cpy > oend.wrapping_offset(-MATCH_SAFEGUARD_DISTANCE) {
            let mlen = core::cmp::min(length, oend as usize - op as usize);
            let match_end = m.wrapping_add(mlen);
            let copy_end = op.wrapping_add(mlen);

            if match_end > op {
                /* overlap copy */
                while op < copy_end {
                    // SAFETY: bounded by `copy_end <= oend`.
                    unsafe { *op = *m };
                    op = op.wrapping_add(1);
                    m = m.wrapping_add(1);
                }
            } else {
                // SAFETY: `mlen` bytes fit before `oend` and the regions do
                // not overlap in this branch.
                unsafe { core::ptr::copy_nonoverlapping(m, op, mlen) };
            }
            op = copy_end;
            if op == oend {
                break 'main;
            }
            continue 'main;
        }

        if offset < 8 {
            // SAFETY: the offset checks above put `m` inside the prefix or the
            // block; four bytes plus the table-driven step stay there.
            unsafe {
                *op = *m;
                *op.add(1) = *m.add(1);
                *op.add(2) = *m.add(2);
                *op.add(3) = *m.add(3);
            }
            m = m.wrapping_add(INC32TABLE[offset]);
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(m, op.add(4), 4) };
            m = m.wrapping_offset(-DEC64TABLE[offset]);
        } else {
            // SAFETY: `offset >= 8` and the offset checks put eight readable
            // bytes at `m`.
            unsafe { copy8(op, m) };
            m = m.wrapping_add(8);
        }

        op = op.wrapping_add(8);

        if cpy > oend.wrapping_offset(-MATCH_SAFEGUARD_DISTANCE) {
            let o_copy_limit: *mut u8 = oend.wrapping_offset(-(WILDCOPYLENGTH - 1));

            if cpy > oend.wrapping_offset(-LASTLITERALS) {
                /* the last LASTLITERALS bytes must be literals */
                return output_error(ip, src);
            }

            if op < o_copy_limit {
                debug_assert!(
                    o_copy_limit <= oend.wrapping_offset(-(WILDCOPYLENGTH - 1)),
                    "wildCopy to oCopyLimit stays WILDCOPYLENGTH-1 short of oend"
                );
                // SAFETY: `o_copy_limit` is `WILDCOPYLENGTH - 1` short of
                // `oend`, which is exactly the overrun `wild_copy` may make.
                unsafe { wild_copy(op, m, o_copy_limit) };
                m = m.wrapping_offset(o_copy_limit as isize - op as isize);
                op = o_copy_limit;
            }
            while op < cpy {
                // SAFETY: bounded by `cpy <= oend - LASTLITERALS`.
                unsafe { *op = *m };
                op = op.wrapping_add(1);
                m = m.wrapping_add(1);
            }
        } else {
            // SAFETY: `cpy <= oend - MATCH_SAFEGUARD_DISTANCE`, which is
            // 2*WILDCOPYLENGTH - MINMATCH of slack.
            unsafe { copy8(op, m) };
            if length > 16 {
                // SAFETY: as above.
                unsafe { wild_copy(op.add(8), m.add(8), cpy) };
            }
        }
        /* wildcopy correction */
        op = cpy;
    }

    /* end of decoding */
    if END_ON_INPUT {
        /* Nb of output bytes decoded */
        (op as isize - dst as isize) as c_int
    } else {
        /* Nb of input bytes read */
        (ip as isize - src as isize) as c_int
    }
}

/// `goto _output_error`: `-(ip - src) - 1`.
#[inline]
fn output_error(ip: *const u8, src: *const u8) -> c_int {
    (-(ip as isize - src as isize)) as c_int - 1
}

// ---------------------------------------------------------------------------
// The eight instantiations. Every one of these is a call the C makes with all
// six directives constant; here they are const generic arguments and the
// monomorphisation is the same specialisation `FORCE_INLINE` produced.
// ---------------------------------------------------------------------------

// The C types these contracts name. A Rust object has
// no C type graph to resolve them against, so they are
// not duplicates of anything -- omit one and the build
// stops naming the reference it could not resolve.
// Generated by rig/kabi-migrate.py; do not hand-edit.
kernel::kabi_rule!("type_string", "t#LZ4_streamDecode_t",
    "typedef_type LZ4_streamDecode_t { union_type { member array_type[4] { base_type unsigned long long byte_size(8) encoding(7) } table data_member_location(0) , member t#LZ4_streamDecode_t_internal internal_donotuse data_member_location(0) } byte_size(32) }");
kernel::kabi_rule!("type_string", "t#LZ4_streamDecode_t_internal",
    "typedef_type LZ4_streamDecode_t_internal { structure_type { member pointer_type { const_type { t#uint8_t } } externalDict data_member_location(0) , member t#size_t extDictSize data_member_location(8) , member pointer_type { const_type { t#uint8_t } } prefixEnd data_member_location(16) , member t#size_t prefixSize data_member_location(24) } byte_size(32) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#uint8_t",
    "typedef_type uint8_t { t#u8 }");

kernel::kabi_export! {
    LZ4_decompress_safe,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) compressedSize , formal_parameter base_type int byte_size(4) encoding(5) maxDecompressedSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_safe()`.
///
/// # Safety
/// `source` must have `compressed_size` readable bytes and `dest`
/// `max_decompressed_size` writable ones.
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_safe(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_decompressed_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract, which is LZ4_decompress_safe()'s own.
    unsafe {
        decompress_generic::<true, false, NO_DICT>(
            source as *const u8,
            compressed_size as isize,
            dest as *mut u8,
            max_decompressed_size as isize,
            dest as *const u8,
            core::ptr::null(),
            0,
        )
    }
}

kernel::kabi_export! {
    LZ4_decompress_safe_partial,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dst , formal_parameter base_type int byte_size(4) encoding(5) compressedSize , formal_parameter base_type int byte_size(4) encoding(5) targetOutputSize , formal_parameter base_type int byte_size(4) encoding(5) dstCapacity ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_safe_partial()`.
///
/// # Safety
/// As [`LZ4_decompress_safe`], with `dst_capacity` bytes at `dst`.
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_safe_partial(
    src: *const c_char,
    dst: *mut c_char,
    compressed_size: c_int,
    target_output_size: c_int,
    dst_capacity: c_int,
) -> c_int {
    let cap = core::cmp::min(target_output_size, dst_capacity);
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<true, true, NO_DICT>(
            src as *const u8,
            compressed_size as isize,
            dst as *mut u8,
            cap as isize,
            dst as *const u8,
            core::ptr::null(),
            0,
        )
    }
}

kernel::kabi_export! {
    LZ4_decompress_fast,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) originalSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_fast()`.
///
/// **No input bound.** The stream is trusted to end within itself; a corrupt
/// one reads past `source`. That is the C's contract and the reason
/// `lib/decompress_unlz4.c` is the only in-tree caller.
///
/// # Safety
/// `dest` must have `original_size` writable bytes, `source` must hold a
/// well-formed stream, and the 64 KiB before `dest` must be a prefix the
/// stream may reference (it is only read when the stream says so).
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_fast(
    source: *const c_char,
    dest: *mut c_char,
    original_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<false, false, WITH_PREFIX_64K>(
            source as *const u8,
            0,
            dest as *mut u8,
            original_size as isize,
            (dest as *const u8).wrapping_offset(-KB64),
            core::ptr::null(),
            0,
        )
    }
}

/// `LZ4_decompress_safe_withPrefix64k()`.
///
/// # Safety
/// As the C's, with a 64 KiB prefix immediately before `dest`.
unsafe fn safe_with_prefix64k(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<true, false, WITH_PREFIX_64K>(
            source as *const u8,
            compressed_size as isize,
            dest as *mut u8,
            max_output_size as isize,
            (dest as *const u8).wrapping_offset(-KB64),
            core::ptr::null(),
            0,
        )
    }
}

/// `LZ4_decompress_safe_withSmallPrefix()`.
///
/// # Safety
/// As the C's, with `prefix_size` bytes immediately before `dest`.
unsafe fn safe_with_small_prefix(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
    prefix_size: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<true, false, NO_DICT>(
            source as *const u8,
            compressed_size as isize,
            dest as *mut u8,
            max_output_size as isize,
            (dest as *const u8).wrapping_sub(prefix_size),
            core::ptr::null(),
            0,
        )
    }
}

/// `LZ4_decompress_safe_forceExtDict()`.
///
/// # Safety
/// As the C's; `dict_start` must have `dict_size` readable bytes.
unsafe fn safe_force_ext_dict(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
    dict_start: *const c_void,
    dict_size: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<true, false, USING_EXT_DICT>(
            source as *const u8,
            compressed_size as isize,
            dest as *mut u8,
            max_output_size as isize,
            dest as *const u8,
            dict_start as *const u8,
            dict_size,
        )
    }
}

/// `LZ4_decompress_fast_extDict()`.
///
/// # Safety
/// As the C's.
unsafe fn fast_ext_dict(
    source: *const c_char,
    dest: *mut c_char,
    original_size: c_int,
    dict_start: *const c_void,
    dict_size: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<false, false, USING_EXT_DICT>(
            source as *const u8,
            0,
            dest as *mut u8,
            original_size as isize,
            dest as *const u8,
            dict_start as *const u8,
            dict_size,
        )
    }
}

/// `LZ4_decompress_safe_doubleDict()` — the ring-buffer case, where the first
/// part of the dictionary is the prefix and the second is external.
///
/// # Safety
/// As the C's.
unsafe fn safe_double_dict(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
    prefix_size: usize,
    dict_start: *const c_void,
    dict_size: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<true, false, USING_EXT_DICT>(
            source as *const u8,
            compressed_size as isize,
            dest as *mut u8,
            max_output_size as isize,
            (dest as *const u8).wrapping_sub(prefix_size),
            dict_start as *const u8,
            dict_size,
        )
    }
}

/// `LZ4_decompress_fast_doubleDict()`.
///
/// # Safety
/// As the C's.
unsafe fn fast_double_dict(
    source: *const c_char,
    dest: *mut c_char,
    original_size: c_int,
    prefix_size: usize,
    dict_start: *const c_void,
    dict_size: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        decompress_generic::<false, false, USING_EXT_DICT>(
            source as *const u8,
            0,
            dest as *mut u8,
            original_size as isize,
            (dest as *const u8).wrapping_sub(prefix_size),
            dict_start as *const u8,
            dict_size,
        )
    }
}

// ---------------------------------------------------------------------------
// Streaming. LZ4_streamDecode_t is the caller's, so its layout is out of
// bounds (GOALS.md §5) and port/test/lz4/ checks every offset against
// offsetof() on include/linux/lz4.h.
// ---------------------------------------------------------------------------

kernel::kabi_export! {
    LZ4_setStreamDecode,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#LZ4_streamDecode_t } LZ4_streamDecode , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } dictionary , formal_parameter base_type int byte_size(4) encoding(5) dictSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_setStreamDecode()`.
///
/// # Safety
/// `sd` must be a live `LZ4_streamDecode_t`; `dictionary` must have
/// `dict_size` readable bytes, or be null with `dict_size == 0`.
#[no_mangle]
pub unsafe extern "C" fn LZ4_setStreamDecode(
    sd: *mut Lz4StreamDecode,
    dictionary: *const c_char,
    dict_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    let sd = unsafe { &mut *sd };

    sd.prefix_size = dict_size as usize;
    sd.prefix_end = (dictionary as *const u8).wrapping_add(dict_size as usize);
    sd.external_dict = core::ptr::null();
    sd.ext_dict_size = 0;
    1
}

kernel::kabi_export! {
    LZ4_decompress_safe_continue,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#LZ4_streamDecode_t } LZ4_streamDecode , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) compressedSize , formal_parameter base_type int byte_size(4) encoding(5) maxOutputSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_safe_continue()`.
///
/// # Safety
/// As the C's: previously decoded blocks must still be where they were
/// decoded, or registered with [`LZ4_setStreamDecode`].
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_safe_continue(
    sd: *mut Lz4StreamDecode,
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    let lz4sd = unsafe { &mut *sd };
    let result;

    if lz4sd.prefix_size == 0 {
        /* The first call, no dictionary yet. */
        debug_assert!(lz4sd.ext_dict_size == 0);
        // SAFETY: as above.
        result = unsafe {
            LZ4_decompress_safe(source, dest, compressed_size, max_output_size)
        };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size = result as usize;
        lz4sd.prefix_end = (dest as *const u8).wrapping_add(result as usize);
    } else if lz4sd.prefix_end == dest as *const u8 {
        /* They're rolling the current segment. */
        // SAFETY: as above.
        result = unsafe {
            if lz4sd.prefix_size >= KB64 as usize - 1 {
                safe_with_prefix64k(source, dest, compressed_size, max_output_size)
            } else if lz4sd.ext_dict_size == 0 {
                safe_with_small_prefix(
                    source,
                    dest,
                    compressed_size,
                    max_output_size,
                    lz4sd.prefix_size,
                )
            } else {
                safe_double_dict(
                    source,
                    dest,
                    compressed_size,
                    max_output_size,
                    lz4sd.prefix_size,
                    lz4sd.external_dict as *const c_void,
                    lz4sd.ext_dict_size,
                )
            }
        };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size += result as usize;
        lz4sd.prefix_end = lz4sd.prefix_end.wrapping_add(result as usize);
    } else {
        /* The buffer wraps around, or they're switching to another buffer. */
        lz4sd.ext_dict_size = lz4sd.prefix_size;
        lz4sd.external_dict = lz4sd.prefix_end.wrapping_sub(lz4sd.ext_dict_size);
        // SAFETY: as above.
        result = unsafe {
            safe_force_ext_dict(
                source,
                dest,
                compressed_size,
                max_output_size,
                lz4sd.external_dict as *const c_void,
                lz4sd.ext_dict_size,
            )
        };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size = result as usize;
        lz4sd.prefix_end = (dest as *const u8).wrapping_add(result as usize);
    }

    result
}

kernel::kabi_export! {
    LZ4_decompress_fast_continue,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#LZ4_streamDecode_t } LZ4_streamDecode , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) originalSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_fast_continue()`.
///
/// # Safety
/// As [`LZ4_decompress_fast`] and the C's.
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_fast_continue(
    sd: *mut Lz4StreamDecode,
    source: *const c_char,
    dest: *mut c_char,
    original_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    let lz4sd = unsafe { &mut *sd };
    let result;

    if lz4sd.prefix_size == 0 {
        debug_assert!(lz4sd.ext_dict_size == 0);
        // SAFETY: as above.
        result = unsafe { LZ4_decompress_fast(source, dest, original_size) };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size = original_size as usize;
        lz4sd.prefix_end = (dest as *const u8).wrapping_add(original_size as usize);
    } else if lz4sd.prefix_end == dest as *const u8 {
        // SAFETY: as above.
        result = unsafe {
            if lz4sd.prefix_size >= KB64 as usize - 1 || lz4sd.ext_dict_size == 0 {
                LZ4_decompress_fast(source, dest, original_size)
            } else {
                fast_double_dict(
                    source,
                    dest,
                    original_size,
                    lz4sd.prefix_size,
                    lz4sd.external_dict as *const c_void,
                    lz4sd.ext_dict_size,
                )
            }
        };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size += original_size as usize;
        lz4sd.prefix_end = lz4sd.prefix_end.wrapping_add(original_size as usize);
    } else {
        lz4sd.ext_dict_size = lz4sd.prefix_size;
        lz4sd.external_dict = lz4sd.prefix_end.wrapping_sub(lz4sd.ext_dict_size);
        // SAFETY: as above.
        result = unsafe {
            fast_ext_dict(
                source,
                dest,
                original_size,
                lz4sd.external_dict as *const c_void,
                lz4sd.ext_dict_size,
            )
        };
        if result <= 0 {
            return result;
        }
        lz4sd.prefix_size = original_size as usize;
        lz4sd.prefix_end = (dest as *const u8).wrapping_add(original_size as usize);
    }

    result
}

kernel::kabi_export! {
    LZ4_decompress_safe_usingDict,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) compressedSize , formal_parameter base_type int byte_size(4) encoding(5) maxOutputSize , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } dictStart , formal_parameter base_type int byte_size(4) encoding(5) dictSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_safe_usingDict()`.
///
/// # Safety
/// As the C's.
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_safe_usingDict(
    source: *const c_char,
    dest: *mut c_char,
    compressed_size: c_int,
    max_output_size: c_int,
    dict_start: *const c_char,
    dict_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dict_size == 0 {
            return LZ4_decompress_safe(source, dest, compressed_size, max_output_size);
        }
        if dict_start.wrapping_add(dict_size as usize) == dest as *const c_char {
            if dict_size >= KB64 as c_int - 1 {
                return safe_with_prefix64k(source, dest, compressed_size, max_output_size);
            }
            return safe_with_small_prefix(
                source,
                dest,
                compressed_size,
                max_output_size,
                dict_size as usize,
            );
        }
        safe_force_ext_dict(
            source,
            dest,
            compressed_size,
            max_output_size,
            dict_start as *const c_void,
            dict_size as usize,
        )
    }
}

kernel::kabi_export! {
    LZ4_decompress_fast_usingDict,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } source , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter base_type int byte_size(4) encoding(5) originalSize , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } dictStart , formal_parameter base_type int byte_size(4) encoding(5) dictSize ) -> base_type int byte_size(4) encoding(5)",
}

/// `LZ4_decompress_fast_usingDict()`.
///
/// # Safety
/// As [`LZ4_decompress_fast`] and the C's.
#[no_mangle]
pub unsafe extern "C" fn LZ4_decompress_fast_usingDict(
    source: *const c_char,
    dest: *mut c_char,
    original_size: c_int,
    dict_start: *const c_char,
    dict_size: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dict_size == 0 || dict_start.wrapping_add(dict_size as usize) == dest as *const c_char {
            return LZ4_decompress_fast(source, dest, original_size);
        }
        fast_ext_dict(
            source,
            dest,
            original_size,
            dict_start as *const c_void,
            dict_size as usize,
        )
    }
}
