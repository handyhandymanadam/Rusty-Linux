// SPDX-License-Identifier: GPL-2.0

//! glob(7) matching -- the Rust body behind `lib/glob.c`'s C entry symbols.
//!
//! Ported from `lib/glob.c` (6.18.49). The C remains the reference, not the
//! specification: see DIVERGENCES at the foot of this file for what was
//! deliberately done differently and why.
//!
//! The exported C entry points `glob_match()` and `glob_match_len()` stay in
//! `lib/glob.c` and call straight into [`rust_glob_match_str()`]. That keeps
//! the exported symbols, their signatures and their CRCs exactly as they
//! were, while the whole of the actual matching logic lives here.
//!
//! Replaces: lib/glob.c

use core::ffi::c_char;

/// Byte at `i`, or NUL past the end.
///
/// This is the whole of the port's safety argument. The C walks two raw
/// pointers and relies on a NUL terminator (and, for the length-bounded
/// entry point, on a `str >= str_end` test) to stop. Here both inputs are
/// bounded slices before the matcher starts, so every read is in range and
/// an out-of-range index yields NUL -- which is precisely what the C's two
/// termination tests produce.
#[inline]
fn at(b: &[u8], i: usize) -> u8 {
    if i < b.len() { b[i] } else { 0 }
}

/// Outcome of scanning one `[...]` character class.
enum Class {
    /// Well-formed. `.0` is whether the class matched (inversion applied);
    /// `.1` is the pattern index just past the closing `]`.
    Formed(bool, usize),
    /// Unterminated or truncated -- the C matches the `[` literally.
    Malformed,
}

/// Scan the character class starting at `p` (just past the `[`) against `c`.
fn class_scan(pat: &[u8], p: usize, c: u8) -> Class {
    let inverted = at(pat, p) == b'!';
    let mut class = p.wrapping_add(inverted as usize);
    let mut a = at(pat, class);
    class = class.wrapping_add(1);
    let mut matched = false;

    // Each iteration consumes one span: a single character `a`, or a range
    // `a-b`. The first span may begin with ']', which is why this is a
    // do-while in the C and a `loop` with the test at the bottom here.
    loop {
        if a == 0 {
            return Class::Malformed;
        }
        let mut b = a;

        if at(pat, class) == b'-' && at(pat, class.wrapping_add(1)) != b']' {
            b = at(pat, class.wrapping_add(1));
            if b == 0 {
                return Class::Malformed;
            }
            class = class.wrapping_add(2);
            // A range with a > b matches nothing, as in the C.
        }
        matched |= a <= c && c <= b;

        a = at(pat, class);
        class = class.wrapping_add(1);
        if a == b']' {
            break;
        }
    }

    Class::Formed(matched != inverted, class)
}

/// The matcher. `pat` and `s` are the readable regions; an index past the
/// end reads as NUL, exactly as the C's terminator tests behave.
fn glob_match_bytes(pat: &[u8], s: &[u8]) -> bool {
    // Backtrack to the previous `*` on mismatch and retry one character
    // later in the string. Because `*` matches every character, one level
    // of backtracking is provably enough.
    let mut back_pat: Option<usize> = None;
    let mut back_str: usize = 0;

    let mut p: usize = 0;
    let mut i: usize = 0;

    loop {
        let c = at(s, i);
        let d = at(pat, p);
        p = p.wrapping_add(1);
        i = i.wrapping_add(1);

        // Set when control reaches the C's `literal:` label, carrying the
        // byte to compare against. Set to `[` when a class is malformed.
        let mut literal: Option<u8> = None;
        let mut backtrack = false;

        match d {
            // Wildcard: anything but NUL.
            b'?' => {
                if c == 0 {
                    return false;
                }
            }
            // Any-length wildcard.
            b'*' => {
                if at(pat, p) == 0 {
                    return true; // trailing `*` matches the rest
                }
                back_pat = Some(p);
                i = i.wrapping_sub(1); // allow a zero-length match
                back_str = i;
            }
            // Character class.
            b'[' => {
                if c == 0 {
                    return false; // no possible match
                }
                match class_scan(pat, p, c) {
                    Class::Formed(true, end) => p = end,
                    Class::Formed(false, _) => backtrack = true,
                    Class::Malformed => literal = Some(b'['),
                }
            }
            // Escape, then fall through to the literal comparison.
            _ => {
                let d = if d == b'\\' {
                    let e = at(pat, p);
                    p = p.wrapping_add(1);
                    e
                } else {
                    d
                };
                literal = Some(d);
            }
        }

        if let Some(d) = literal {
            if c == d {
                if d == 0 {
                    return true; // both ran out together
                }
            } else {
                backtrack = true;
            }
        }

        if backtrack {
            if c == 0 {
                return false; // no point continuing
            }
            match back_pat {
                None => return false,
                Some(bp) => {
                    p = bp;
                    back_str = back_str.wrapping_add(1);
                    i = back_str;
                }
            }
        }
    }
}

/// Length of the NUL-terminated string at `p`.
///
/// # Safety
/// `p` must be non-null and point at a NUL-terminated byte string.
unsafe fn strlen(p: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: the caller guarantees a NUL-terminated string at `p`, so every
    // byte up to and including the terminator is readable.
    while unsafe { *p.add(n) } != 0 {
        n = n.wrapping_add(1);
    }
    n
}

/// Length of the string at `p`, reading at most `max` bytes.
///
/// # Safety
/// `p` must be non-null and `max` bytes must be readable from it.
unsafe fn strnlen(p: *const u8, max: usize) -> usize {
    let mut n = 0usize;
    // SAFETY: `n < max` is tested first and the caller guarantees `max` bytes
    // are readable from `p`, so the read is in range.
    while n < max && unsafe { *p.add(n) } != 0 {
        n = n.wrapping_add(1);
    }
    n
}

/// The C body of lib/glob.c's `glob_match_str()`.
///
/// `str_end` is NULL for the NUL-terminated entry point, or one past the
/// last readable byte for the length-bounded one.
///
/// # Safety
/// `pat` must be a NUL-terminated string. `str` must be NUL-terminated when
/// `str_end` is NULL, and otherwise readable up to `str_end`. This is the
/// same contract the C had; the callers are lib/glob.c's two wrappers.
#[no_mangle]
pub unsafe extern "C" fn rust_glob_match_str(
    pat: *const c_char,
    str: *const c_char,
    str_end: *const c_char,
) -> bool {
    let pat = pat as *const u8;
    let s = str as *const u8;

    // SAFETY: the caller guarantees `pat` is NUL-terminated.
    let pat_len = unsafe { strlen(pat) };
    let s_len = if str_end.is_null() {
        // SAFETY: with a NULL `str_end` the caller guarantees `str` is
        // NUL-terminated.
        unsafe { strlen(s) }
    } else {
        // SAFETY: the caller guarantees every byte in [str, str_end) is
        // readable, and that is exactly the range strnlen is bounded to.
        unsafe { strnlen(s, (str_end as usize).wrapping_sub(s as usize)) }
    };

    // SAFETY: both lengths were just measured within the caller's guaranteed
    // readable regions, so both slices are in bounds. Neither is written to
    // and neither outlives this call, so no aliasing rule is at stake.
    let (pat, s) = unsafe {
        (
            core::slice::from_raw_parts(pat, pat_len),
            core::slice::from_raw_parts(s, s_len),
        )
    };

    glob_match_bytes(pat, s)
}

// DIVERGENCES from lib/glob.c, per GOALS.md §5.
//
// 1. Both inputs are measured (strlen / strnlen) before matching, rather
//    than walked one byte at a time with a terminator test in the loop.
//
//    Q1 can anything outside observe it?  No. Every byte read is inside the
//       region the C was already permitted to read: for the NUL-terminated
//       entry point the C walks to the NUL itself, and for the bounded one
//       strnlen stops at str_end. No value, no memory and no write ordering
//       changes -- the function has no writes at all.
//    Q2 does it change a layout or an interface?  No. Same symbols, same
//       signatures, same C wrappers, same CRCs.
//    Q3 does it force a change anywhere else?  No.
//
//    Cost: one extra O(n+m) pass in front of an O(n*m) matcher, and only
//    when the match would have exited early. Bought: the matcher body has
//    no unsafe in it at all, and no pointer can leave its buffer, which is
//    the entire reason to do this in Rust.
//
// 2. NOT DONE, deliberately, and recorded so it is not mistaken for an
//    oversight: the C does not collapse runs of `*`, so "***a" re-enters
//    the backtracking machinery three times. Collapsing them is externally
//    unobservable and strictly faster. It is left out of the first port to
//    keep this change one thing rather than two; it is a wishlist item.
