// SPDX-License-Identifier: GPL-2.0

//! The two command-line scanners of `arch/x86/lib/cmdline.c`.
//!
//! Ported from `arch/x86/lib/cmdline.c` (6.18.49): "Misc librarized functions
//! for cmdline poking". The C file's two `static` workers,
//! `__cmdline_find_option_bool()` and `__cmdline_find_option()`, are the
//! parsing; they are here. What stays in `arch/x86/lib/cmdline.c` is the two
//! public entry points `cmdline_find_option_bool()` and
//! `cmdline_find_option()`: they pass `COMMAND_LINE_SIZE` and, under
//! `CONFIG_CMDLINE_BOOL`, retry on `builtin_cmdline` (a Kconfig-gated
//! `IS_ENABLED()`, a variable and a macro that a Rust body cannot express
//! without mirroring them). Neither entry is `EXPORT_SYMBOL`ed, so there is no
//! MODVERSIONS contract.
//!
//! This is NOT the boot stub's copy (`arch/x86/boot/compressed/cmdline_rs.rs`,
//! a different algorithm over real-mode far pointers) and NOT
//! `lib/cmdline_rs.rs` (`get_option` and friends). Replaces the two workers of
//! `arch/x86/lib/cmdline.c`.
//!
//! # Contract of both workers (same as the C)
//!
//! * `cmdline` may be NULL (returns -1) or NOT NUL-terminated: no more than
//!   `max_cmdline_size` bytes are read, and none after the first NUL.
//! * `option` must be NUL-terminated. It is read only up to its terminator.
//! * `__cmdline_find_option_rs` writes at most `bufsize - 1` argument bytes
//!   plus a NUL, i.e. never more than `bufsize` bytes, and ONLY when
//!   `bufsize != 0`. Quirk kept from the C: when `bufsize != 0` it writes the
//!   NUL at `buffer[0]` even if the option was not found at all.
//! * `len` and `pos` use the C's `int` arithmetic; counters that the C would
//!   overflow (2^31 characters) wrap here instead of trapping (the kernel
//!   builds Rust with overflow checks on).
//!
//! No message text is produced by this file.

use core::ffi::{c_char, c_int};

#[inline(always)]
fn myisspace(c: u8) -> bool {
    c <= b' ' // "Close enough approximation", as the C says
}

#[derive(PartialEq, Clone, Copy)]
enum State {
    WordStart, // start of word / after whitespace
    WordCmp,   // comparing this word
    WordSkip,  // miscompare, skip
    BufCpy,    // copying this to buffer
}

/// `__cmdline_find_option_bool()` of the C file.
///
/// Returns the position (counting from 1) of `option` as an entire word of
/// `cmdline`, 0 when not found or on buffer overrun, -1 for a NULL `cmdline`.
///
/// # Safety
/// `cmdline` is NULL or points to `max_cmdline_size` readable bytes, or to a
/// NUL-terminated string (reads stop at the NUL); `option` is a NUL-terminated
/// string.
#[no_mangle]
pub unsafe extern "C" fn __cmdline_find_option_bool_rs(
    cmdline: *const c_char,
    max_cmdline_size: c_int,
    option: *const c_char,
) -> c_int {
    let mut pos: c_int = 0;
    let mut wstart: c_int = 0;
    let mut opptr: *const u8 = core::ptr::null();
    let mut state = State::WordStart;
    let mut cur = cmdline as *const u8;

    if cmdline.is_null() {
        return -1; // No command line
    }

    // This 'pos' check ensures we do not overrun a non-NULL-terminated 'cmdline'.
    while pos < max_cmdline_size {
        // SAFETY: pos < max_cmdline_size, so this byte is within the caller's
        // buffer; no byte after a NUL is ever read (every NUL path returns).
        let c = unsafe { *cur };
        // SAFETY: stays within, or one past the end of, the same buffer.
        cur = unsafe { cur.add(1) };
        pos += 1;

        let mut st = state;
        if st == State::WordStart {
            if c == 0 {
                return 0;
            } else if myisspace(c) {
                continue;
            }
            state = State::WordCmp;
            opptr = option as *const u8;
            wstart = pos;
            st = State::WordCmp; // fallthrough
        }
        if st == State::WordCmp {
            // SAFETY: opptr points into the NUL-terminated `option` and is
            // only advanced past a byte that was not the NUL.
            let oc = unsafe { *opptr };
            if oc == 0 {
                // Matched all the way to the end of the option: a space or the
                // end of the command line means we matched.
                if c == 0 || myisspace(c) {
                    return wstart;
                }
                // End of option but not the end of a word: not a match.
            } else if c == 0 {
                return 0; // hit the NUL terminator of cmdline
            } else {
                // SAFETY: oc != 0, so opptr + 1 is within `option`'s terminator.
                opptr = unsafe { opptr.add(1) };
                if c == oc {
                    continue; // still matching
                }
            }
            state = State::WordSkip;
            st = State::WordSkip; // fallthrough
        }
        if st == State::WordSkip {
            if c == 0 {
                return 0;
            } else if myisspace(c) {
                state = State::WordStart;
            }
        }
    }

    0 // Buffer overrun
}

/// `__cmdline_find_option()` of the C file.
///
/// Returns the length of the argument of the LAST `option=argument` word
/// (whether or not it was truncated to fit `buffer`), or -1 when not found
/// or `cmdline` is NULL.
///
/// # Safety
/// As [`__cmdline_find_option_bool_rs`]; and `buffer` is writable for
/// `bufsize` bytes when `bufsize != 0` (it may be NULL when `bufsize == 0`).
#[no_mangle]
pub unsafe extern "C" fn __cmdline_find_option_rs(
    cmdline: *const c_char,
    max_cmdline_size: c_int,
    option: *const c_char,
    buffer: *mut c_char,
    bufsize: c_int,
) -> c_int {
    let mut pos: c_int = 0;
    let mut len: c_int = -1;
    let mut opptr: *const u8 = core::ptr::null();
    let mut bufptr = buffer as *mut u8;
    let mut state = State::WordStart;
    let mut cur = cmdline as *const u8;

    if cmdline.is_null() {
        return -1; // No command line
    }

    // The C's `while (pos++ < max_cmdline_size)`: compare, then increment.
    loop {
        let before = pos;
        pos = pos.wrapping_add(1);
        if before >= max_cmdline_size {
            break;
        }
        // SAFETY: before < max_cmdline_size, so this byte is within the buffer.
        let c = unsafe { *cur };
        // SAFETY: stays within, or one past the end of, the same buffer.
        cur = unsafe { cur.add(1) };
        if c == 0 {
            break;
        }

        let mut st = state;
        if st == State::WordStart {
            if myisspace(c) {
                continue;
            }
            state = State::WordCmp;
            opptr = option as *const u8;
            st = State::WordCmp; // fallthrough
        }
        if st == State::WordCmp {
            // SAFETY: opptr points into the NUL-terminated `option`.
            let oc = unsafe { *opptr };
            if c == b'=' && oc == 0 {
                // Matched all the way to the end of the option: prepare to
                // copy the argument.
                len = 0;
                bufptr = buffer as *mut u8;
                state = State::BufCpy;
                continue;
            }
            // The C's `c == *opptr++`: opptr advances on a mismatch too, but
            // the state then becomes WordSkip and opptr is reset at the next
            // word start, so it is never read past `option`'s terminator.
            // SAFETY: when oc == 0 the pointer is not read again before reset;
            // wrapping_add keeps the (unread) value well-defined.
            opptr = opptr.wrapping_add(1);
            if c == oc {
                continue;
            }
            state = State::WordSkip;
            st = State::WordSkip; // fallthrough
        }
        if st == State::WordSkip {
            if myisspace(c) {
                state = State::WordStart;
            }
            continue;
        }
        // State::BufCpy
        if myisspace(c) {
            state = State::WordStart;
        } else {
            // Increment len, but don't overrun the supplied buffer and leave
            // room for the NUL terminator.
            len = len.wrapping_add(1);
            if len < bufsize {
                // SAFETY: 1 <= len < bufsize, and bufptr has advanced
                // len - 1 < bufsize - 1 times since it was reset to `buffer`.
                unsafe {
                    *bufptr = c;
                    bufptr = bufptr.add(1);
                }
            }
        }
    }

    if bufsize != 0 {
        // SAFETY: bufptr - buffer <= bufsize - 1 (see above), inside the buffer.
        unsafe { *bufptr = 0 };
    }

    len
}

/// Kani proofs (`cd rig/x86-cmdline-kani && cargo kani`; inert in the kernel build). They prove,
/// for EVERY content of the buffers within the stated sizes (not a sample): no read outside
/// `cmdline[0..max]` or past `option`'s NUL, no write outside `buffer[0..bufsize]`, the result
/// range, and that a positive `bool` answer is a genuine whole-word match. Bounded: cmdline up to
/// 6 bytes, option up to 3 characters, bufsize up to 5. The kernel's COMMAND_LINE_SIZE (2048) is
/// not covered by the proof; the loops are the same at any size, and the randomised/small-scope
/// differential against the C (`port/test/x86_cmdline/run.sh`) covers the C behaviour.
#[cfg(kani)]
mod proofs {
    use super::*;

    const N: usize = 6;

    #[kani::proof]
    #[kani::unwind(10)]
    fn bool_scan_is_in_bounds_and_sound() {
        let cmd: [u8; N] = kani::any();
        let opt: [u8; 4] = kani::any();
        kani::assume(opt[3] == 0); // NUL-terminated option, at most 3 characters
        let max: c_int = kani::any();
        kani::assume(max >= 0 && max <= N as c_int);
        let l = opt.iter().position(|&b| b == 0).unwrap();

        // `cmd` is exactly N bytes (no terminator is promised): any read at index >= max, or
        // beyond N, is an out-of-bounds failure Kani reports.
        let r = unsafe { __cmdline_find_option_bool_rs(cmd.as_ptr() as *const c_char, max, opt.as_ptr() as *const c_char) };

        assert!(r >= 0 && r <= max);
        if r > 0 {
            let s = (r - 1) as usize;
            // starts a word: line start or a blank before it
            assert!(s == 0 || cmd[s - 1] <= b' ');
            // the option text is there...
            let mut i = 0;
            while i < l {
                assert!(cmd[s + i] == opt[i]);
                i += 1;
            }
            // ...and the byte after it was read (so it is inside max) and ends the word
            assert!(s + l < max as usize);
            assert!(cmd[s + l] <= b' ');
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn bool_scan_null_cmdline() {
        let opt: [u8; 2] = [b'a', 0];
        let max: c_int = kani::any();
        let r = unsafe { __cmdline_find_option_bool_rs(core::ptr::null(), max, opt.as_ptr() as *const c_char) };
        assert!(r == -1);
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn opt_scan_is_in_bounds_and_bounded_writes() {
        let cmd: [u8; N] = kani::any();
        let opt: [u8; 4] = kani::any();
        kani::assume(opt[3] == 0);
        let max: c_int = kani::any();
        kani::assume(max >= 0 && max <= N as c_int);
        let mut buf: [u8; 5] = kani::any();
        let orig = buf;
        let bufsize: c_int = kani::any();
        kani::assume(bufsize >= 1 && bufsize <= 5);

        let r = unsafe {
            __cmdline_find_option_rs(
                cmd.as_ptr() as *const c_char,
                max,
                opt.as_ptr() as *const c_char,
                buf.as_mut_ptr() as *mut c_char,
                bufsize,
            )
        };

        // length of the argument: -1 (not found) or 0..=max
        assert!(r >= -1 && r <= max);
        // nothing at or after buffer[bufsize] was touched
        let mut i = bufsize as usize;
        while i < 5 {
            assert!(buf[i] == orig[i]);
            i += 1;
        }
        // the argument copied is terminated inside the buffer: a NUL at index min(r, bufsize-1)
        // when an argument was found, and at index 0 when not (the C's quirk)
        if r >= 0 {
            let at = if (r as usize) < (bufsize as usize) { r as usize } else { bufsize as usize - 1 };
            assert!(buf[at] == 0);
        } else {
            assert!(buf[0] == 0);
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn opt_scan_bufsize_zero_writes_nothing() {
        let cmd: [u8; N] = kani::any();
        let opt: [u8; 4] = kani::any();
        kani::assume(opt[3] == 0);
        let max: c_int = kani::any();
        kani::assume(max >= 0 && max <= N as c_int);
        // bufsize 0: the C never writes, and the caller may pass NULL
        let r = unsafe {
            __cmdline_find_option_rs(cmd.as_ptr() as *const c_char, max, opt.as_ptr() as *const c_char, core::ptr::null_mut(), 0)
        };
        assert!(r >= -1 && r <= max);
    }
}
