// SPDX-License-Identifier: GPL-2.0

//! The LZO1X decompressor.
//!
//! Ported from `lib/lzo/lzo1x_decompress_safe.c` (6.18.49), which carries
//! `Copyright (C) 1996-2012 Markus F.X.J. Oberhumer` and kernel changes by
//! Nitin Gupta and Richard Purdie.
//!
//! # This one keeps its C entry symbol
//!
//! `lzo1x_decompress_safe()` is `EXPORT_SYMBOL_GPL`'d, so it has a
//! MODVERSIONS CRC and GOALS.md §1's hard constraint binds: the C entry
//! symbol stays in `lzo1x_decompress_safe.c` and this is the body behind it.
//! That is the `bcd` shape, not the `union_find` shape `inffast_rs.rs` was
//! able to use. Nine callers reach it — `crypto/lzo{,-rle}.c`, zram's two
//! backends, btrfs, f2fs, jffs2, squashfs, and `lib/decompress_unlzo.c`.
//!
//! # The gotos, and why this is a four-state loop
//!
//! The C is a `for(;;)` with two labels **inside** its body that are also
//! jumped to from **outside** it:
//!
//! ```text
//!     if (*ip > 17) {
//!         t = *ip++ - 17;
//!         if (t < 4) { next = t; goto match_next; }   <-- into the loop
//!         goto copy_literal_run;                      <-- into the loop
//!     }
//!     for (;;) { ... copy_literal_run: ... match_next: ... }
//! ```
//!
//! Rust has no jump into a loop body, so the body is split at its labels
//! into the four states of [`Entry`] and the prologue picks the one to start
//! in. Every `goto` becomes an assignment plus `continue`, and the C's
//! fall-through order is preserved by which state each arm hands on to.
//! **The states are the C's labels, not an invention:** `Top` is the head of
//! the `for(;;)`, `CopyLiteralRun` and `MatchNext` are its two labels, and
//! `MatchCopy` is the unlabelled block between them that three arms fall
//! into.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **Only the `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` variant is
//!    ported, and it is compiled unconditionally.** The C has four
//!    `#if defined(...)` fast paths that read and write eight bytes at a
//!    time, each guarded by `HAVE_IP(t + 15)` / `HAVE_OP(t + 15)` so it can
//!    only run when those bytes exist. [`core::ptr::read_unaligned`] is
//!    correct on every architecture — it lowers to a wide load where one
//!    exists and to a byte sequence where it does not — so taking the fast
//!    path everywhere produces identical output everywhere. What changes on
//!    an unaligned-hostile target is speed, not behaviour, and the guards
//!    mean it never reads or writes further than the C would have.
//!
//!    **This is measured, not asserted.** The differential runs a third arm:
//!    the same pristine C compiled with the option OFF, taking its
//!    byte-at-a-time paths. All three arms are compared on every case.
//!
//! 2. **`wrapping_*` where the C relies on unsigned wraparound**, with a
//!    `debug_assert!` naming the invariant instead.
//!    `CONFIG_RUST_OVERFLOW_CHECKS=y` on both configs, so a plain `-` would
//!    turn an impossible case into a kernel panic inside a decompressor that
//!    is fed untrusted data by nine callers. The assertions are live in the
//!    userspace differential and compiled out in the kernel.
//!
//! # What is NOT changed
//!
//! The bounds checks are transcribed one for one, including where the C
//! reads a byte *before* testing that it may. `while (*ip == 0) { ip++;
//! NEED_IP(1); }` tests the byte it has already read, and both zero-run
//! extensions do it. That is the C's behaviour on a corrupt stream and this
//! reproduces it exactly rather than tidying it — a decompressor that
//! rejects one byte earlier than the original is a different decompressor.
//!
//! Replaces: lib/lzo/lzo1x_decompress_safe.c

use core::ffi::{c_int, c_uchar};

/// `LZO_E_OK`, `include/linux/lzo.h`.
const LZO_E_OK: c_int = 0;
/// `LZO_E_ERROR`, `include/linux/lzo.h`.
const LZO_E_ERROR: c_int = -1;
/// `LZO_E_INPUT_OVERRUN`, `include/linux/lzo.h`.
const LZO_E_INPUT_OVERRUN: c_int = -4;
/// `LZO_E_OUTPUT_OVERRUN`, `include/linux/lzo.h`.
const LZO_E_OUTPUT_OVERRUN: c_int = -5;
/// `LZO_E_LOOKBEHIND_OVERRUN`, `include/linux/lzo.h`.
const LZO_E_LOOKBEHIND_OVERRUN: c_int = -6;
/// `LZO_E_INPUT_NOT_CONSUMED`, `include/linux/lzo.h`.
const LZO_E_INPUT_NOT_CONSUMED: c_int = -8;

/// `M2_MAX_OFFSET`, `lib/lzo/lzodefs.h`.
const M2_MAX_OFFSET: usize = 0x0800;
/// `MIN_ZERO_RUN_LENGTH`, `lib/lzo/lzodefs.h`.
const MIN_ZERO_RUN_LENGTH: usize = 4;

/// The C's `MAX_255_COUNT`: how many 255 steps a length extension may take
/// before the running total could overflow. See `Documentation/staging/lzo.rst`.
const MAX_255_COUNT: usize = (usize::MAX / 255) - 2;

/// Where in the C's `for(;;)` body to resume.
///
/// These are the C's own labels, not a restructuring: `Top` is the head of
/// the loop, `CopyLiteralRun` and `MatchNext` are the two labels inside it
/// that outside code jumps to, and `MatchCopy` is the unlabelled block
/// between them that three arms fall into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// Head of the `for(;;)`: read the next instruction byte.
    Top,
    /// The C's `copy_literal_run:` label.
    CopyLiteralRun,
    /// The unlabelled match copy, reached by falling out of the dispatch.
    MatchCopy,
    /// The C's `match_next:` label.
    MatchNext,
}

/// Decompress an LZO1X stream.
///
/// Returns `LZO_E_OK` or one of the negative `LZO_E_*` codes, and writes the
/// number of bytes produced through `out_len` on **every** path including
/// the error ones, exactly as the C does.
///
/// # Safety
/// `inp` must be valid for `in_len` bytes, `out` for `*out_len` bytes, and
/// `out_len` must be a live `usize`. The buffers must not overlap. Same
/// contract as the C, which is equally unchecked.
#[no_mangle]
pub unsafe extern "C" fn lzo1x_decompress_safe(
    inp: *const c_uchar,
    in_len: usize,
    out: *mut c_uchar,
    out_len: *mut usize,
) -> c_int {
    // SAFETY: the caller guarantees both buffers are live for the lengths
    // given. Every pointer walked below is kept inside them by the same
    // HAVE_IP/HAVE_OP/TEST_LB checks the C uses, transcribed one for one.
    unsafe {
        let mut op: *mut c_uchar = out;
        let mut ip: *const c_uchar = inp;
        let ip_end: *const c_uchar = inp.add(in_len);
        let op_end: *mut c_uchar = out.add(*out_len);

        let mut t: usize;
        let mut next: usize = 0;
        let mut state: usize = 0;
        let mut m_pos: *const c_uchar = core::ptr::null();

        // `(size_t)(ip_end - ip) >= (size_t)(x)`
        macro_rules! have_ip {
            ($x:expr) => {
                (ip_end as usize).wrapping_sub(ip as usize) >= ($x) as usize
            };
        }
        macro_rules! have_op {
            ($x:expr) => {
                (op_end as usize).wrapping_sub(op as usize) >= ($x) as usize
            };
        }
        // The C's four exits all write *out_len before returning.
        macro_rules! bail {
            ($code:expr) => {{
                *out_len = op.offset_from(out) as usize;
                return $code;
            }};
        }
        macro_rules! need_ip {
            ($x:expr) => {
                if !have_ip!($x) {
                    bail!(LZO_E_INPUT_OVERRUN);
                }
            };
        }
        macro_rules! need_op {
            ($x:expr) => {
                if !have_op!($x) {
                    bail!(LZO_E_OUTPUT_OVERRUN);
                }
            };
        }
        macro_rules! test_lb {
            ($m:expr) => {
                if ($m) < (out as *const c_uchar) {
                    bail!(LZO_E_LOOKBEHIND_OVERRUN);
                }
            };
        }
        /// Read one byte and advance, the C's `*ip++`.
        macro_rules! next_byte {
            () => {{
                let b = *ip;
                ip = ip.add(1);
                b as usize
            }};
        }
        // The C's zero-run length extension, which appears three times with
        // different bases. Reads the byte before testing it may, as the C
        // does -- see the module docs.
        macro_rules! extend_length {
            ($base:expr) => {{
                let ip_last = ip;
                while *ip == 0 {
                    ip = ip.add(1);
                    need_ip!(1);
                }
                let mut offset = ip.offset_from(ip_last) as usize;
                if offset > MAX_255_COUNT {
                    bail!(LZO_E_ERROR);
                }
                offset = (offset << 8) - offset;
                t += offset + $base + next_byte!();
            }};
        }

        if in_len < 3 {
            bail!(LZO_E_INPUT_OVERRUN);
        }

        let bitstream_version: u8;
        if in_len >= 5 && *ip == 17 {
            bitstream_version = *ip.add(1);
            ip = ip.add(2);
        } else {
            bitstream_version = 0;
        }

        // The prologue picks which of the C's labels to enter the loop at.
        let mut entry;
        if *ip > 17 {
            t = next_byte!() - 17;
            if t < 4 {
                next = t;
                entry = Entry::MatchNext;
            } else {
                entry = Entry::CopyLiteralRun;
            }
        } else {
            t = 0;
            entry = Entry::Top;
        }

        loop {
            match entry {
                Entry::Top => {
                    t = next_byte!();
                    if t < 16 {
                        if state == 0 {
                            if t == 0 {
                                extend_length!(15);
                            }
                            t += 3;
                            entry = Entry::CopyLiteralRun;
                            continue;
                        } else if state != 4 {
                            next = t & 3;
                            m_pos = op.sub(1);
                            m_pos = m_pos.sub(t >> 2);
                            m_pos = m_pos.sub(next_byte!() << 2);
                            test_lb!(m_pos);
                            need_op!(2);
                            *op = *m_pos;
                            *op.add(1) = *m_pos.add(1);
                            op = op.add(2);
                            entry = Entry::MatchNext;
                            continue;
                        } else {
                            next = t & 3;
                            m_pos = op.sub(1 + M2_MAX_OFFSET);
                            m_pos = m_pos.sub(t >> 2);
                            m_pos = m_pos.sub(next_byte!() << 2);
                            t = 3;
                        }
                    } else if t >= 64 {
                        next = t & 3;
                        m_pos = op.sub(1);
                        m_pos = m_pos.sub((t >> 2) & 7);
                        m_pos = m_pos.sub(next_byte!() << 3);
                        // t >= 64 so t >> 5 >= 2; the C's `- 1 + (3 - 1)`
                        // cannot underflow here.
                        debug_assert!(t >> 5 >= 1, "M3 length underflow");
                        t = (t >> 5) - 1 + (3 - 1);
                    } else if t >= 32 {
                        t = (t & 31) + (3 - 1);
                        if t == 2 {
                            extend_length!(31);
                            need_ip!(2);
                        }
                        m_pos = op.sub(1);
                        next = u16::from_le_bytes([*ip, *ip.add(1)]) as usize;
                        ip = ip.add(2);
                        m_pos = m_pos.sub(next >> 2);
                        next &= 3;
                    } else {
                        need_ip!(2);
                        next = u16::from_le_bytes([*ip, *ip.add(1)]) as usize;
                        if (next & 0xfffc) == 0xfffc
                            && (t & 0xf8) == 0x18
                            && bitstream_version != 0
                        {
                            // Zero-run, lzo-rle's bitstream version 1.
                            need_ip!(3);
                            t &= 7;
                            t |= (*ip.add(2) as usize) << 3;
                            t += MIN_ZERO_RUN_LENGTH;
                            need_op!(t);
                            core::ptr::write_bytes(op, 0, t);
                            op = op.add(t);
                            next &= 3;
                            ip = ip.add(3);
                            entry = Entry::MatchNext;
                            continue;
                        }
                        m_pos = op;
                        m_pos = m_pos.sub((t & 8) << 11);
                        t = (t & 7) + (3 - 1);
                        if t == 2 {
                            extend_length!(7);
                            need_ip!(2);
                            next = u16::from_le_bytes([*ip, *ip.add(1)]) as usize;
                        }
                        ip = ip.add(2);
                        m_pos = m_pos.sub(next >> 2);
                        next &= 3;
                        if m_pos == (op as *const c_uchar) {
                            // End of stream.
                            *out_len = op.offset_from(out) as usize;
                            return if t != 3 {
                                LZO_E_ERROR
                            } else if ip == ip_end {
                                LZO_E_OK
                            } else if ip < ip_end {
                                LZO_E_INPUT_NOT_CONSUMED
                            } else {
                                LZO_E_INPUT_OVERRUN
                            };
                        }
                        m_pos = m_pos.sub(0x4000);
                    }
                    entry = Entry::MatchCopy;
                }

                Entry::CopyLiteralRun => {
                    if have_ip!(t + 15) && have_op!(t + 15) {
                        // Eight bytes at a time; the guard above is what
                        // makes the overshoot safe.
                        let ie = ip.add(t);
                        let oe = op.add(t);
                        loop {
                            (op as *mut u64).write_unaligned((ip as *const u64).read_unaligned());
                            op = op.add(8);
                            ip = ip.add(8);
                            (op as *mut u64).write_unaligned((ip as *const u64).read_unaligned());
                            op = op.add(8);
                            ip = ip.add(8);
                            if ip >= ie {
                                break;
                            }
                        }
                        ip = ie;
                        op = oe;
                    } else {
                        need_op!(t);
                        need_ip!(t + 3);
                        debug_assert!(t > 0, "literal run of zero length");
                        loop {
                            *op = *ip;
                            op = op.add(1);
                            ip = ip.add(1);
                            t -= 1;
                            if t == 0 {
                                break;
                            }
                        }
                    }
                    state = 4;
                    entry = Entry::Top;
                }

                Entry::MatchCopy => {
                    test_lb!(m_pos);
                    if op.offset_from(m_pos) >= 8 {
                        let oe = op.add(t);
                        if have_op!(t + 15) {
                            loop {
                                (op as *mut u64)
                                    .write_unaligned((m_pos as *const u64).read_unaligned());
                                op = op.add(8);
                                m_pos = m_pos.add(8);
                                (op as *mut u64)
                                    .write_unaligned((m_pos as *const u64).read_unaligned());
                                op = op.add(8);
                                m_pos = m_pos.add(8);
                                if op >= oe {
                                    break;
                                }
                            }
                            op = oe;
                            if have_ip!(6) {
                                // The C `continue`s the outer loop here,
                                // skipping match_next entirely.
                                state = next;
                                (op as *mut u32)
                                    .write_unaligned((ip as *const u32).read_unaligned());
                                op = op.add(next);
                                ip = ip.add(next);
                                entry = Entry::Top;
                                continue;
                            }
                        } else {
                            need_op!(t);
                            loop {
                                *op = *m_pos;
                                op = op.add(1);
                                m_pos = m_pos.add(1);
                                if op >= oe {
                                    break;
                                }
                            }
                        }
                    } else {
                        let oe = op.add(t);
                        need_op!(t);
                        *op = *m_pos;
                        *op.add(1) = *m_pos.add(1);
                        op = op.add(2);
                        m_pos = m_pos.add(2);
                        loop {
                            *op = *m_pos;
                            op = op.add(1);
                            m_pos = m_pos.add(1);
                            if op >= oe {
                                break;
                            }
                        }
                    }
                    entry = Entry::MatchNext;
                }

                Entry::MatchNext => {
                    state = next;
                    t = next;
                    if have_ip!(6) && have_op!(4) {
                        (op as *mut u32).write_unaligned((ip as *const u32).read_unaligned());
                        op = op.add(t);
                        ip = ip.add(t);
                    } else {
                        need_ip!(t + 3);
                        need_op!(t);
                        while t > 0 {
                            *op = *ip;
                            op = op.add(1);
                            ip = ip.add(1);
                            t -= 1;
                        }
                    }
                    entry = Entry::Top;
                }
            }
        }
    }
}
