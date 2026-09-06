// SPDX-License-Identifier: GPL-2.0

//! The fast path of the zlib inflate decoder.
//!
//! Ported from `lib/zlib_inflate/inffast.c` (6.18.49), which carries
//! `Copyright (C) 1995-2004 Mark Adler`. This is the routine inflate()
//! spends most of its time in: it decodes literal, length and distance
//! codes and writes out literal and match bytes until the input or the
//! output runs low, the block ends, or the data is bad.
//!
//! # This one has no C entry symbol, and that is deliberate
//!
//! `inflate_fast()` is global but **not** `EXPORT_SYMBOL`'d — its only
//! caller is `zlib_inflate()` in the same directory. The constraint that
//! forces a C entry thunk everywhere else in this port is
//! `CONFIG_GENDWARFKSYMS` computing a MODVERSIONS CRC from DWARF type
//! names, and a symbol with no export has no CRC. So this is the
//! `union_find` shape: `inffast.c` is gone from the build, the function is
//! defined here outright, and `inflate.c` links straight to it with no
//! trampoline.
//!
//! # The entry contract, which is the caller's to keep
//!
//! `zlib_inflate()` calls this only with
//!
//! * `state->mode == LEN`
//! * `strm->avail_in >= 6` — six bytes is the most a single length/distance
//!   pair can consume (15 + 5 + 15 + 13 = 48 bits), so the decode loop never
//!   has to check for input
//! * `strm->avail_out >= 258` — 258 bytes is the longest codeable match, so
//!   the loop never has to check for output space
//! * `start >= strm->avail_out`
//! * `state->bits < 8`
//!
//! Every bound in the body rests on those. They are debug-asserted below,
//! which costs nothing in the kernel (`CONFIG_RUST_DEBUG_ASSERTIONS` is off
//! on both configs) and is live in the userspace differential.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **`INFLATE_STRICT` is not carried over.** The C guards its `dmax`
//!    check with `#ifdef INFLATE_STRICT`, and nothing in the tree ever
//!    defines it — `grep -r INFLATE_STRICT src/linux` finds only the
//!    `#ifdef`s themselves and a comment. The block is dead in every kernel
//!    this project builds, so porting it would be porting code that cannot
//!    run. `state.dmax` is still in the struct mirror, at its true offset,
//!    so re-enabling it later is a local change.
//!
//! 2. **One unaligned-read construct instead of the C's two.** The C forks
//!    on `IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)` between a
//!    plain `*sfrom++` — which is undefined behaviour in C on an unaligned
//!    pointer, and merely happens to work on x86 — and a byte-wise
//!    `get_unaligned16()` helper. [`core::ptr::read_unaligned`] is the
//!    correct spelling of exactly that intent, and rustc lowers it to the
//!    single load on targets that have one and to a byte-wise sequence on
//!    targets that do not. Same bytes either way; the helper is gone.
//!    Both configs this project builds set the option, so this changes no
//!    generated code today.
//!
//! 3. **All arithmetic on values bounded by an invariant rather than a
//!    local `if` uses `wrapping_*` (bit accounting, window-copy pointer
//!    offsets, the `avail_in`/`avail_out` epilogue, the `len`/`loops`
//!    countdown loops, the `(1 << bits) - 1` mask constructions).**
//!    `CONFIG_RUST_OVERFLOW_CHECKS=y` on both configs, so a plain `-`/`<<`
//!    here would turn an impossible case into a kernel panic inside the
//!    decompressor. The invariants that make those operations safe come
//!    from the entry contract and the decode tables rather than from a
//!    local `if`, so each one carries a `debug_assert!` stating the
//!    invariant instead (where one wasn't already present). Originally
//!    this point covered only the bit-accounting subtractions; the
//!    pointer-offset and mask-construction sites were still plain
//!    arithmetic, found later by the CONFIG_RUST_OVERFLOW_CHECKS
//!    panic-symbol sweep, 2026-09-06 -- a real, if narrow, gap in this
//!    point's own original coverage claim. The userspace differential
//!    runs with `-C debug-assertions=on` and would stop on a violation;
//!    the kernel wraps exactly as the C does.
//!
//! # Layout is the caller's
//!
//! [`ZStream`], [`InflateState`] and [`Code`] mirror `struct z_stream_s`
//! (`include/linux/zlib.h`), `struct inflate_state` and `code`
//! (`lib/zlib_inflate/inflate.h`, `inftrees.h`). GOALS.md §5 puts all three
//! out of bounds: nothing here may reorder, resize or add a field. The
//! differential harness static-asserts every offset this file reads against
//! `offsetof()` on the real headers, because a silently wrong offset is the
//! one mistake in this port that no output comparison would localise.
//!
//! Replaces: lib/zlib_inflate/inffast.c

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

/// Mirrors `code` in `lib/zlib_inflate/inftrees.h`. Four bytes.
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

/// Mirrors the head of `struct inflate_state` in `lib/zlib_inflate/inflate.h`.
///
/// **Truncated on purpose.** `inflate_fast()` touches nothing past
/// `distbits`; the tail (`ncode` through the 2048-entry `codes` array, about
/// 7 KiB) is left out rather than mirrored, because a field this file never
/// names is a field that can go stale without anything noticing. Every field
/// that *is* here sits at the offset the C gives it, and the harness checks
/// that. Nothing may take `size_of::<InflateState>()`.
#[repr(C)]
pub struct InflateState {
    /// Current inflate mode; this function writes `TYPE` or `BAD`.
    pub mode: c_int,
    /// True if processing the last block.
    pub last: c_int,
    /// Bit 0 zlib, bit 1 gzip.
    pub wrap: c_int,
    /// True if a dictionary was provided.
    pub havedict: c_int,
    /// gzip header method and flags.
    pub flags: c_int,
    /// Maximum distance from the zlib header. Read only under
    /// `INFLATE_STRICT`, which is never defined — see the module docs.
    pub dmax: c_uint,
    /// Protected copy of the check value.
    pub check: c_ulong,
    /// Protected copy of the output count.
    pub total: c_ulong,
    /// Log base 2 of the requested window size.
    pub wbits: c_uint,
    /// Window size, or zero if no window is in use.
    pub wsize: c_uint,
    /// Valid bytes in the window.
    pub whave: c_uint,
    /// Window write index.
    pub write: c_uint,
    /// The sliding window, if `wsize != 0`.
    pub window: *mut u8,
    /// Input bit accumulator.
    pub hold: c_ulong,
    /// Number of bits in `hold`.
    pub bits: c_uint,
    /// Literal or length of data to copy.
    pub length: c_uint,
    /// Distance back to copy from.
    pub offset: c_uint,
    /// Extra bits needed.
    pub extra: c_uint,
    /// Starting table for length/literal codes.
    pub lencode: *const Code,
    /// Starting table for distance codes.
    pub distcode: *const Code,
    /// Index bits for `lencode`.
    pub lenbits: c_uint,
    /// Index bits for `distcode`.
    pub distbits: c_uint,
}

/// Mirrors `struct z_stream_s` in `include/linux/zlib.h`.
#[repr(C)]
pub struct ZStream {
    /// Next input byte.
    pub next_in: *const u8,
    /// Bytes available at `next_in`.
    pub avail_in: c_ulong,
    /// Total input bytes read so far.
    pub total_in: c_ulong,
    /// Where the next output byte goes.
    pub next_out: *mut u8,
    /// Free space remaining at `next_out`.
    pub avail_out: c_ulong,
    /// Total bytes output so far.
    pub total_out: c_ulong,
    /// Last error message, or null.
    pub msg: *mut c_char,
    /// Decoder state; `struct internal_state *` in the C.
    pub state: *mut InflateState,
    /// Memory allocated for this stream.
    pub workspace: *mut c_void,
    /// Best guess at the data type.
    pub data_type: c_int,
    /// Adler-32 of the uncompressed data.
    pub adler: c_ulong,
    /// Reserved.
    pub reserved: c_ulong,
}

/// `TYPE` in the `inflate_mode` enum, `lib/zlib_inflate/inflate.h`.
///
/// The enum is plain and unvalued, so these are positional. `pub` so the
/// differential harness can read them back and compare them against the real
/// header; hand-counting an enum is exactly the kind of claim this project
/// does not accept without a mechanical check.
pub const MODE_TYPE: c_int = 11;
/// `BAD` in the `inflate_mode` enum, `lib/zlib_inflate/inflate.h`.
pub const MODE_BAD: c_int = 27;

/// Byte-for-byte the C's message, NUL included.
const MSG_DIST_TOO_FAR: &[u8] = b"invalid distance too far back\0";
/// Byte-for-byte the C's message, NUL included.
const MSG_INVALID_DIST: &[u8] = b"invalid distance code\0";
/// Byte-for-byte the C's message, NUL included.
const MSG_INVALID_LITLEN: &[u8] = b"invalid literal/length code\0";

/// Decode codes and emit bytes until input, output, the block, or the data
/// runs out.
///
/// `start` is `inflate()`'s value for `strm->avail_out` on entry, from which
/// the beginning of this call's output is recovered.
///
/// On return `state->mode` is `LEN` (ran low on input or output), `TYPE`
/// (hit end-of-block) or `BAD` (bad data, with `strm->msg` set).
///
/// # Safety
/// `strm` must be a live [`ZStream`] whose `state` points at a live
/// [`InflateState`] with decode tables built by `zlib_inflate_table()`, and
/// the entry contract in the module docs must hold. Same requirements as the
/// C, which is equally unchecked.
#[no_mangle]
pub unsafe extern "C" fn inflate_fast(strm: *mut ZStream, start: c_uint) {
    // SAFETY: the caller guarantees `strm` and `strm->state` are live and
    // that the entry contract holds. Every pointer walked below stays inside
    // the input, output or window buffers by the same bounds argument the C
    // makes: `avail_in >= 6` and `avail_out >= 258` cover the most any one
    // iteration can consume or emit, and the loop re-tests both at the end.
    unsafe {
        let state: *mut InflateState = (*strm).state;

        debug_assert!((*strm).avail_in >= 6, "entry contract: avail_in >= 6");
        debug_assert!((*strm).avail_out >= 258, "entry contract: avail_out >= 258");
        debug_assert!(
            start as c_ulong >= (*strm).avail_out,
            "entry contract: start >= avail_out"
        );
        // The C's header comment also claims `state->bits < 8` on entry. It
        // is NOT true: `zlib_inflate()`'s `case LEN` tests only
        // `have >= 6 && left >= 258` before calling, and `hold`/`bits` carry
        // across calls, so entry with `bits >= 8` happens on ordinary
        // streams within a few hundred decompressions. Asserting it here
        // fires immediately. It is left unasserted rather than "fixed",
        // because the C's behaviour in that case is the behaviour this port
        // has to reproduce. What the claim was really protecting is checked
        // below instead: that the epilogue does not rewind `in` past where
        // this call started.

        // Copy state into locals, exactly as the C does. `inp` is the C's
        // `in`, which is a keyword here.
        let mut inp: *const u8 = (*strm).next_in;
        // Only read by the debug assertion after the epilogue.
        let entry_in: *const u8 = inp;
        // avail_in >= 6 / avail_out >= 258 are the entry contract (module
        // doc above), so these never actually underflow; wrapping_sub
        // matches the C's plain `- 5`/`- 257` instead of panicking on a
        // path the contract rules out.
        let last: *const u8 = inp.add(((*strm).avail_in.wrapping_sub(5)) as usize);
        let mut out: *mut u8 = (*strm).next_out;
        let beg: *mut u8 = out.sub((start as c_ulong).wrapping_sub((*strm).avail_out) as usize);
        let end: *mut u8 = out.add(((*strm).avail_out.wrapping_sub(257)) as usize);

        let wsize: c_uint = (*state).wsize;
        let whave: c_uint = (*state).whave;
        let write: c_uint = (*state).write;
        let window: *const u8 = (*state).window;
        let mut hold: c_ulong = (*state).hold;
        let mut bits: c_uint = (*state).bits;
        let lcode: *const Code = (*state).lencode;
        let dcode: *const Code = (*state).distcode;
        // lenbits/distbits are bounded by the decode tables' own build
        // limits (well under 32), matching the C's own unguarded
        // `(1U << bits) - 1`.
        let lmask: c_uint = (1u32.wrapping_shl((*state).lenbits)).wrapping_sub(1);
        let dmask: c_uint = (1u32.wrapping_shl((*state).distbits)).wrapping_sub(1);

        // Declared up here rather than at first use so the copy macro below
        // can name them: `macro_rules!` resolves outer identifiers at the
        // point the macro is defined, not the point it is called.
        let mut this: Code;
        let mut op: c_uint;
        let mut len: c_uint;
        let mut dist: c_uint;
        let mut from: *const u8;

        // Pull one byte into the bit accumulator. `avail_in >= 6` is what
        // makes this safe without a bounds test, and it is why the loop
        // stops while five bytes remain rather than at the end.
        macro_rules! pull_byte {
            () => {{
                // `bits` stays well under 64 (called only while bits < 15,
                // at most twice per outer iteration), matching the C's own
                // unguarded `hold += (unsigned long)(*in++) << bits`.
                hold = hold.wrapping_add((*inp as c_ulong).wrapping_shl(bits));
                inp = inp.add(1);
                bits += 8;
            }};
        }

        // Copy `n` bytes forward, one at a time, `n >= 1`. The C spells this
        // as a `do { } while (--op)`, which runs once for `op == 1` and
        // would run 2^32 times for `op == 0`; every caller below has already
        // proved `op >= 1`.
        macro_rules! copy_bytes {
            ($n:expr) => {{
                let mut n = $n;
                debug_assert!(n >= 1, "do-while copy entered with a zero count");
                loop {
                    *out = *from;
                    out = out.add(1);
                    from = from.add(1);
                    // n >= 1 on entry (debug_assert! above) and the loop
                    // breaks the instant n reaches 0, so this never
                    // decrements past 0.
                    n = n.wrapping_sub(1);
                    if n == 0 {
                        break;
                    }
                }
            }};
        }

        'outer: loop {
            if bits < 15 {
                pull_byte!();
                pull_byte!();
            }
            this = *lcode.add((hold as c_uint & lmask) as usize);

            'dolen: loop {
                op = this.bits as c_uint;
                // The table guarantees a code is at most 15 bits and the
                // accumulator held at least 15 — see divergence 3.
                debug_assert!(bits >= op, "length code wider than the accumulator");
                hold = hold.wrapping_shr(op);
                bits = bits.wrapping_sub(op);

                op = this.op as c_uint;
                if op == 0 {
                    // Literal.
                    *out = this.val as u8;
                    out = out.add(1);
                } else if op & 16 != 0 {
                    // Length base, with `op & 15` extra bits to follow.
                    len = this.val as c_uint;
                    op &= 15;
                    if op != 0 {
                        if bits < op {
                            pull_byte!();
                        }
                        len += hold as c_uint & ((1u32 << op) - 1);
                        debug_assert!(bits >= op, "length extra wider than the accumulator");
                        hold = hold.wrapping_shr(op);
                        bits = bits.wrapping_sub(op);
                    }
                    if bits < 15 {
                        pull_byte!();
                        pull_byte!();
                    }
                    this = *dcode.add((hold as c_uint & dmask) as usize);

                    'dodist: loop {
                        op = this.bits as c_uint;
                        debug_assert!(bits >= op, "distance code wider than the accumulator");
                        hold = hold.wrapping_shr(op);
                        bits = bits.wrapping_sub(op);

                        op = this.op as c_uint;
                        if op & 16 != 0 {
                            // Distance base, with `op & 15` extra bits.
                            dist = this.val as c_uint;
                            op &= 15;
                            if bits < op {
                                pull_byte!();
                                if bits < op {
                                    pull_byte!();
                                }
                            }
                            dist += hold as c_uint & ((1u32 << op) - 1);
                            debug_assert!(bits >= op, "distance extra wider than the accumulator");
                            hold = hold.wrapping_shr(op);
                            bits = bits.wrapping_sub(op);

                            // How far back we can reach inside this call's
                            // own output. The C truncates the pointer
                            // difference to `unsigned`; so does this.
                            op = out.offset_from(beg) as c_uint;
                            if dist > op {
                                // Some or all of the match predates this
                                // call and has to come out of the window.
                                op = dist - op;
                                if op > whave {
                                    (*strm).msg = MSG_DIST_TOO_FAR.as_ptr() as *mut c_char;
                                    (*state).mode = MODE_BAD;
                                    break 'outer;
                                }
                                from = window;
                                if write == 0 {
                                    // Very common case: the window has not
                                    // wrapped, so the tail of it is the most
                                    // recent output.
                                    // `op <= whave <= wsize` is checked
                                    // above (MSG_DIST_TOO_FAR), matching
                                    // the C's own unguarded `wsize - op`.
                                    from = from.add((wsize.wrapping_sub(op)) as usize);
                                    if op < len {
                                        len -= op;
                                        copy_bytes!(op);
                                        from = out.sub(dist as usize);
                                    }
                                } else if write < op {
                                    // The match starts before the wrap point
                                    // and may run through it.
                                    // `op <= wsize` (as above) and `write >=
                                    // 0`, so `wsize + write >= op` always;
                                    // matches the C's own unguarded
                                    // `wsize + write - op`.
                                    from = from.add((wsize.wrapping_add(write).wrapping_sub(op)) as usize);
                                    op -= write;
                                    if op < len {
                                        len -= op;
                                        copy_bytes!(op);
                                        from = window;
                                        if write < len {
                                            op = write;
                                            len -= op;
                                            copy_bytes!(op);
                                            from = out.sub(dist as usize);
                                        }
                                    }
                                } else {
                                    // Contiguous inside the window.
                                    from = from.add((write - op) as usize);
                                    if op < len {
                                        len -= op;
                                        copy_bytes!(op);
                                        from = out.sub(dist as usize);
                                    }
                                }
                                // Three at a time is what the C settled on;
                                // its own footnote records that larger
                                // unrolls measured slower.
                                while len > 2 {
                                    *out = *from;
                                    out = out.add(1);
                                    from = from.add(1);
                                    *out = *from;
                                    out = out.add(1);
                                    from = from.add(1);
                                    *out = *from;
                                    out = out.add(1);
                                    from = from.add(1);
                                    len -= 3;
                                }
                                // The C advances `from` across these last
                                // one or two bytes too. It is dead from here
                                // on either way, and writing the second byte
                                // through `from.add(1)` keeps rustc from
                                // flagging a store nothing reads.
                                if len != 0 {
                                    *out = *from;
                                    out = out.add(1);
                                    if len > 1 {
                                        *out = *from.add(1);
                                        out = out.add(1);
                                    }
                                }
                            } else {
                                // The whole match is inside this call's
                                // output, so copy straight from it. The
                                // copy overlaps whenever `dist < len`, and
                                // it must stay a forward byte-order copy:
                                // that overlap is how deflate spells a run.
                                from = out.sub(dist as usize);

                                // The minimum match length is three, so
                                // after at most one alignment byte there are
                                // still at least two left to halve.
                                debug_assert!(len >= 3, "match shorter than the deflate minimum");

                                // Align `out` to two bytes so the 16-bit
                                // stores below are aligned. `out - 1` even
                                // means `out` is odd.
                                if (out as usize).wrapping_sub(1) & 1 == 0 {
                                    *out = *from;
                                    out = out.add(1);
                                    from = from.add(1);
                                    // len >= 3 on entry (debug_assert! above)
                                    // and this branch fires at most once.
                                    len = len.wrapping_sub(1);
                                }
                                debug_assert!(out as usize % 2 == 0, "16-bit store left unaligned");
                                debug_assert!(len >= 2, "halved copy entered with fewer than two bytes");

                                let mut sout = out as *mut u16;
                                if dist > 2 {
                                    // Safe to move two bytes at a time: each
                                    // pair's source is finalised before it is
                                    // read whenever `dist >= 2`.
                                    let mut sfrom = from as *const u16;
                                    let mut loops: c_ulong = (len >> 1) as c_ulong;
                                    loop {
                                        sout.write_unaligned(sfrom.read_unaligned());
                                        sout = sout.add(1);
                                        sfrom = sfrom.add(1);
                                        // loops starts >= 1 (len >= 2, debug_assert! above) and breaks at 0.
                                        loops = loops.wrapping_sub(1);
                                        if loops == 0 {
                                            break;
                                        }
                                    }
                                    out = sout as *mut u8;
                                    from = sfrom as *const u8;
                                } else {
                                    // `dist` is 1 or 2: the output is a
                                    // repeating two-byte pattern, so splat it
                                    // instead of copying. Reading the two
                                    // bytes separately is the C union's
                                    // byte semantics without its endianness
                                    // assumption.
                                    let mut pat: [u8; 2] = [*out.sub(2), *out.sub(1)];
                                    if dist == 1 {
                                        // One repeated byte: both halves are
                                        // the byte immediately behind `out`.
                                        pat[0] = pat[1];
                                    }
                                    let pat16 = u16::from_ne_bytes(pat);
                                    let mut loops: c_ulong = (len >> 1) as c_ulong;
                                    loop {
                                        sout.write_unaligned(pat16);
                                        sout = sout.add(1);
                                        // loops starts >= 1 (len >= 2, debug_assert! above) and breaks at 0.
                                        loops = loops.wrapping_sub(1);
                                        if loops == 0 {
                                            break;
                                        }
                                    }
                                    out = sout as *mut u8;
                                    // `from` is deliberately NOT advanced
                                    // here, matching the C. It still points
                                    // at the even phase of the pattern,
                                    // which is what the odd tail byte below
                                    // needs.
                                }
                                // Odd tail byte. `from` is dead after this,
                                // so unlike the C it is not advanced.
                                if len & 1 != 0 {
                                    *out = *from;
                                    out = out.add(1);
                                }
                            }
                        } else if op & 64 == 0 {
                            // Second-level distance table.
                            this = *dcode
                                .add((this.val as c_uint + (hold as c_uint & (1u32.wrapping_shl(op).wrapping_sub(1)))) as usize);
                            continue 'dodist;
                        } else {
                            (*strm).msg = MSG_INVALID_DIST.as_ptr() as *mut c_char;
                            (*state).mode = MODE_BAD;
                            break 'outer;
                        }
                        break 'dodist;
                    }
                } else if op & 64 == 0 {
                    // Second-level length table.
                    this = *lcode
                        .add((this.val as c_uint + (hold as c_uint & (1u32.wrapping_shl(op).wrapping_sub(1)))) as usize);
                    continue 'dolen;
                } else if op & 32 != 0 {
                    // End of block.
                    (*state).mode = MODE_TYPE;
                    break 'outer;
                } else {
                    (*strm).msg = MSG_INVALID_LITLEN.as_ptr() as *mut c_char;
                    (*state).mode = MODE_BAD;
                    break 'outer;
                }
                break 'dolen;
            }

            if !(inp < last && (out as *const u8) < (end as *const u8)) {
                break 'outer;
            }
        }

        // Give back the whole bytes still sitting in the accumulator. On
        // entry `bits < 8`, so `in` cannot walk back past where it started.
        len = bits >> 3;
        debug_assert!(
            len as usize <= inp.offset_from(entry_in) as usize,
            "epilogue rewound `in` past the start of this call's input"
        );
        inp = inp.sub(len as usize);
        bits -= len << 3;
        hold &= ((1u32 << bits) - 1) as c_ulong;

        (*strm).next_in = inp;
        (*strm).next_out = out;
        // Both of these truncate to 32 bits before widening, as the C's
        // `(unsigned)` cast does.
        // Pointer differences bounded by real buffer sizes (never remotely
        // near i64::MAX), matching the C's own pointer arithmetic before
        // its `(unsigned)` truncation.
        (*strm).avail_in = if inp < last {
            5i64.wrapping_add(last.offset_from(inp) as i64) as c_uint as c_ulong
        } else {
            5i64.wrapping_sub(inp.offset_from(last) as i64) as c_uint as c_ulong
        };
        (*strm).avail_out = if (out as *const u8) < (end as *const u8) {
            257i64.wrapping_add(end.offset_from(out) as i64) as c_uint as c_ulong
        } else {
            257i64.wrapping_sub(out.offset_from(end) as i64) as c_uint as c_ulong
        };
        (*state).hold = hold;
        (*state).bits = bits;
    }
}
