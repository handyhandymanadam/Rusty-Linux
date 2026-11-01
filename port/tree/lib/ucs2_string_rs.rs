// SPDX-License-Identifier: GPL-2.0

//! UCS-2 string handling -- the Rust bodies behind `lib/ucs2_string.c`.
//!
//! Ported from `lib/ucs2_string.c` (6.18.49). These operate on the UTF-16
//! strings EFI variables are named with, so "UCS-2" here means "an array of
//! `u16`, NUL-terminated", and surrogate pairs are not decoded by the C
//! either — `ucs2_as_utf8()` emits three bytes for anything at or above
//! 0x800, surrogate or not. That is preserved.
//!
//! Replaces: lib/ucs2_string.c

use core::ffi::c_int;

/// `ucs2_char_t` from `include/linux/ucs2_string.h`.
type Ucs2Char = u16;

/// Body of `ucs2_strnlen()`.
///
/// # Safety
/// `s` must be readable for `maxlength` `u16`s, or up to a NUL within them.
///
/// See `include/linux/ucs2_string.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn ucs2_strnlen(s: *const Ucs2Char, maxlength: usize) -> usize {
    let mut length = 0usize;

    // SAFETY: every read is at an index strictly below `maxlength`, which
    // the caller guarantees is readable -- see the divergence note below.
    unsafe {
        while length < maxlength && *s.add(length) != 0 {
            length = length.wrapping_add(1);
        }
    }
    length
}

/// Body of `ucs2_strlen()`.
///
/// # Safety
/// `s` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ucs2_strlen(s: *const Ucs2Char) -> usize {
    // SAFETY: `usize::MAX` is the C's `~0UL`; the NUL is what stops it.
    unsafe { ucs2_strnlen(s, usize::MAX) }
}

/// Body of `ucs2_strsize()`: the length in BYTES, not characters.
///
/// # Safety
/// As [`ucs2_strnlen`], with `maxlength` in bytes.
#[no_mangle]
pub unsafe extern "C" fn ucs2_strsize(data: *const Ucs2Char, maxlength: usize) -> usize {
    // SAFETY: the caller's contract.
    unsafe { (ucs2_strnlen(data, maxlength / 2)).wrapping_mul(2) }
}

/// Body of `ucs2_strscpy()`, minus the argument checks.
///
/// `lib/ucs2_string.c` has already rejected `count == 0` and an absurd
/// `count` with its `WARN_ON_ONCE` before this is reached.
///
/// # Safety
/// `dst` must be writable for `count` `u16`s and `src` readable until a NUL
/// or `count` `u16`s, whichever comes first.
#[no_mangle]
pub unsafe extern "C" fn rust_ucs2_strscpy(
    dst: *mut Ucs2Char,
    src: *const Ucs2Char,
    count: usize,
) -> isize {
    // 7 is E2BIG. There is no errno header to reach from here and the value
    // is fixed by the uapi.
    const E2BIG: isize = 7;

    // SAFETY: `res` is strictly below `count` at every read and write, and
    // the caller guarantees that many elements on both sides.
    unsafe {
        for res in 0..count {
            let c = *src.add(res);

            *dst.add(res) = c;
            if c == 0 {
                return res as isize;
            }
        }

        // Ran out of room: truncate, terminate, and say so.
        *dst.add(count.wrapping_sub(1)) = 0;
    }
    -E2BIG
}

/// Body of `ucs2_strncmp()`.
///
/// # Safety
/// `a` and `b` must each be readable until a NUL or `len` `u16`s.
#[no_mangle]
pub unsafe extern "C" fn rust_ucs2_strncmp(
    a: *const Ucs2Char,
    b: *const Ucs2Char,
    len: usize,
) -> c_int {
    // SAFETY: every read is at an index below `len`.
    unsafe {
        for i in 0..len {
            let (x, y) = (*a.add(i), *b.add(i));

            if x < y {
                return -1;
            }
            if x > y {
                return 1;
            }
            if x == 0 {
                // x == y == 0: both ended together.
                return 0;
            }
        }
    }
    0
}

/// Body of `ucs2_utf8size()`: how many bytes the UTF-8 form would take.
///
/// # Safety
/// `src` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ucs2_utf8size(src: *const Ucs2Char) -> usize {
    let mut i = 0usize;
    let mut j = 0usize;

    // SAFETY: the caller guarantees a NUL terminator, which stops the walk.
    unsafe {
        loop {
            let c = *src.add(i);

            if c == 0 {
                break;
            }
            j = j.wrapping_add(if c >= 0x800 {
                3
            } else if c >= 0x80 {
                2
            } else {
                1
            });
            i = i.wrapping_add(1);
        }
    }
    j
}

/// Body of `ucs2_as_utf8()`: convert to UTF-8, up to `maxlength` bytes.
///
/// Returns the number of bytes written, not counting a NUL. Note that the C
/// only writes a terminating NUL when there was room left over — a full
/// buffer comes back unterminated, and callers know that.
///
/// # Safety
/// `dest` must be writable for `maxlength` bytes, plus one more when the
/// conversion stops short. `src` must be readable per
/// [`ucs2_strnlen`].
#[no_mangle]
pub unsafe extern "C" fn ucs2_as_utf8(
    dest: *mut u8,
    src: *const Ucs2Char,
    maxlength: usize,
) -> usize {
    let mut maxlength = maxlength;
    let mut j = 0usize;

    // SAFETY: the caller's contract. `limit` bounds the reads and every
    // write is preceded by a check that `maxlength` bytes remain.
    unsafe {
        let limit = ucs2_strnlen(src, maxlength);
        let mut i = 0usize;

        while maxlength != 0 && i < limit {
            let c = *src.add(i);

            if c >= 0x800 {
                if maxlength < 3 {
                    break;
                }
                maxlength = maxlength.wrapping_sub(3);
                *dest.add(j) = 0xe0 | ((c & 0xf000) >> 12) as u8;
                *dest.add(j.wrapping_add(1)) = 0x80 | ((c & 0x0fc0) >> 6) as u8;
                *dest.add(j.wrapping_add(2)) = 0x80 | (c & 0x003f) as u8;
                j = j.wrapping_add(3);
            } else if c >= 0x80 {
                if maxlength < 2 {
                    break;
                }
                maxlength = maxlength.wrapping_sub(2);
                *dest.add(j) = 0xc0 | ((c & 0x7c0) >> 6) as u8;
                *dest.add(j.wrapping_add(1)) = 0x80 | (c & 0x03f) as u8;
                j = j.wrapping_add(2);
            } else {
                maxlength = maxlength.wrapping_sub(1);
                *dest.add(j) = (c & 0x7f) as u8;
                j = j.wrapping_add(1);
            }
            i = i.wrapping_add(1);
        }

        // Only terminated when there was room left. A full buffer comes
        // back unterminated -- the C's behaviour, and callers rely on the
        // returned length rather than on a NUL.
        if maxlength != 0 {
            *dest.add(j) = 0;
        }
    }
    j
}

// DIVERGENCE from lib/ucs2_string.c, per GOALS.md §5.
//
// ucs2_strnlen() reads ONE ELEMENT FEWER than the C.
//
// The C is
//
//     while (*s++ != 0 && length < maxlength)
//             length++;
//
// which evaluates `*s++` BEFORE testing `length < maxlength`. So when the
// first `maxlength` elements are all non-zero it reads `s[maxlength]` --
// one past the region the caller said was there -- and then returns
// `maxlength` regardless of what that element held.
//
// Q1 can anything outside observe the difference?  The RETURN VALUE cannot
//    differ: the extra element is read and then discarded on both branches.
//    What differs is a read of memory the caller never promised existed,
//    which is undefined behaviour rather than behaviour.
// Q2 does it change a layout or an interface?  No.
// Q3 does it force a change anywhere else?  No.
//
// So this removes a one-element over-read and changes no answer. The
// differential test checks every length against the C to make sure of the
// first half of that claim.
