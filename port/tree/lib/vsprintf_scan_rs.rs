// SPDX-License-Identifier: GPL-2.0-only

//! The buffer-scanning half of `lib/vsprintf.c` -- the Rust behind
//! `vsscanf()`'s format-string walk and its `va_arg`-free consumption
//! logic.
//!
//! Follow-up to `vsprintf_rs.rs` (the formatting side), coordinated
//! directly with that file's author before starting: new file (that one
//! is independently owned and already large), `vsprintf_scan_rs_*`
//! naming to match their `vsprintf_rs_*` convention, and
//! `simple_strntoll`/`simple_strntoull` (vsscanf's own number parsers)
//! stay C-to-C, unchanged -- confirmed as an independent, low-risk
//! follow-up if ever wanted, not required for this split.
//!
//! # Why this isn't the same shape as `format_decode`'s split
//!
//! `vsnprintf`'s split works because `format_decode()` returns a
//! descriptor and a LATER, separate step (`get_arg`) does the `va_arg`
//! extraction. `vsscanf()` doesn't have that shape: every specifier case
//! calls its own `va_arg` immediately, interleaved with the buffer-side
//! parsing. So this is a round trip, once per specifier, not a single
//! decode-then-extract pass:
//!
//! 1. The retained C `vsscanf()` loop calls [`vsprintf_scan_rs_next`],
//!    which owns everything that needs no `va_arg` at all: skipping
//!    whitespace, literal-text matching, `%*...` skip-conversions,
//!    field-width/qualifier parsing, deciding which specifier this is,
//!    and (for numeric specifiers) the leading-digit validity check --
//!    all of it pure `fmt`/`str` inspection.
//! 2. Based on the returned [`ScanKind`], C calls `va_arg` with the
//!    right type (an ordinary switch, unchanged in shape from upstream)
//!    to get the destination pointer or, for numeric specifiers, to
//!    finish the job itself (it already owns `simple_strntoll`/
//!    `simple_strntoull`, so there is nothing left for Rust to do there
//!    beyond having already validated the leading digit and confirmed
//!    the specifier is numeric).
//! 3. For `%c`/`%s`/`%[`, C calls back into
//!    [`vsprintf_scan_rs_consume_c`]/[`vsprintf_scan_rs_consume_s`]/
//!    [`vsprintf_scan_rs_consume_bracket`] with the now-extracted
//!    pointer, and Rust does the actual character-copying.
//!
//! # The one place `va_arg`-consumption ORDER matters
//!
//! Upstream's `%[` case calls `va_arg(args, char *)` BEFORE checking
//! `field_width == -1`, before checking for a closing `]`, and before
//! checking the first character actually matches the set -- on every
//! one of those failure paths it still `return`s having consumed the
//! `va_arg` slot, because a caller's subsequent `va_arg` calls in the
//! same `vsscanf()` invocation must land on the right stack/register
//! slot regardless of whether THIS specifier matched. So
//! `vsprintf_scan_rs_next()` runs the ENTIRE `%[` validity chain (all of
//! it `va_arg`-independent: parsing the set, checking for `]`, checking
//! the first character) and reports the outcome via
//! [`ScanSpec::stop`], but always classifies `%[` as
//! [`ScanKind::NeedBracket`] so the C thunk still calls `va_arg` even
//! when `stop` is true -- the extracted pointer is then simply unused,
//! exactly matching upstream.
//!
//! # Character classification
//!
//! `isdigit`/`isspace`/`isxdigit` are `_ctype[]`-table macros
//! (`include/linux/ctype.h`); `isodigit`/`_tolower` (the fast qualifier-
//! char lowercasing, not the `_ctype`-based `tolower`) are plain range/
//! bit checks with no table at all. Same `_ctype` extern and bitmask
//! convention `vsprintf_rs.rs` already uses.

#![allow(non_snake_case)]

use core::ffi::c_char;

unsafe extern "C" {
    static _ctype: [u8; 256];
}

fn ctype_byte(c: u8, mask: u8) -> bool {
    // SAFETY: `_ctype` is a fixed 256-entry table, `c as usize < 256`.
    (unsafe { _ctype[c as usize] } & mask) != 0
}

/// `isspace(c)`, `include/linux/ctype.h` (`_S == 0x20`).
fn isspace_byte(c: u8) -> bool {
    ctype_byte(c, 0x20)
}
/// `isdigit(c)` (the `_ctype`-table form; this build's `__builtin_isdigit`
/// fast path is behaviourally identical for the ASCII range vsscanf ever
/// sees). `include/linux/ctype.h` (`_D == 0x04`).
fn isdigit_byte(c: u8) -> bool {
    ctype_byte(c, 0x04)
}
/// `isxdigit(c)`, `include/linux/ctype.h` (`_D|_X == 0x04|0x40`).
fn isxdigit_byte(c: u8) -> bool {
    ctype_byte(c, 0x44)
}
/// `isodigit(c)`, `include/linux/ctype.h` -- a plain range check, no
/// `_ctype` table at all: `c >= '0' && c <= '7'`.
fn isodigit_byte(c: u8) -> bool {
    c.is_ascii() && (b'0'..=b'7').contains(&c)
}
/// `_tolower(c)`, `include/linux/ctype.h` -- the FAST qualifier-char
/// lowercasing (`c | 0x20`), not the `_ctype`-table `tolower()`.
fn tolower_fast(c: u8) -> u8 {
    c | 0x20
}

// `skip_spaces()` (`lib/string_helpers.c`, already ported and exported
// by `string_helpers_rs.rs`) -- reused via `extern "C"` rather than
// reimplemented.
unsafe extern "C" {
    fn skip_spaces(str_: *const c_char) -> *mut c_char;
}

unsafe fn deref_u8(p: *const c_char) -> u8 {
    // SAFETY: caller's contract -- `p` valid for at least one byte read
    // (every call site here reads from a NUL-terminated C string, so
    // the read is always in-bounds).
    unsafe { *p as u8 }
}

/// What [`vsprintf_scan_rs_next`] found, and what the retained C
/// `vsscanf()` loop must do about it.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// Stop; return `num` unchanged. Covers: format string exhausted,
    /// a literal-text mismatch, an invalid/unsupported specifier
    /// character, `%*[` (unsupported), and a numeric specifier whose
    /// leading character isn't a valid digit for its base.
    Done = 0,
    /// No `va_arg` needed this iteration; `fmt`/`str` are already
    /// advanced as needed. Covers a matched literal character, a
    /// matched `%%`, and a fully-consumed `%*...` skip-conversion.
    Continue = 1,
    /// `%n`: caller must do `*va_arg(args, int *) = str - buf;` itself
    /// (trivial enough that no Rust call-back is worth it).
    NeedN = 2,
    /// `%c`: caller extracts `va_arg(args, char *)` and passes it to
    /// [`vsprintf_scan_rs_consume_c`].
    NeedC = 3,
    /// `%s`: caller extracts `va_arg(args, char *)` and passes it to
    /// [`vsprintf_scan_rs_consume_s`].
    NeedS = 4,
    /// `%[...]`: caller extracts `va_arg(args, char *)` UNCONDITIONALLY
    /// (see the module doc on `va_arg`-consumption order) -- if
    /// `stop` is set, discard it and return `num` unchanged; otherwise
    /// pass it to [`vsprintf_scan_rs_consume_bracket`].
    NeedBracket = 5,
    /// A numeric conversion (`%d`/`%i`/`%u`/`%o`/`%x`/`%X`) whose
    /// leading digit has already been validated. Caller runs its own
    /// unchanged `simple_strntoll`/`simple_strntoull` + qualifier-based
    /// `va_arg` switch, exactly as upstream.
    NeedNumeric = 6,
}

/// Returned by [`vsprintf_scan_rs_next`]. Fields are only meaningful for
/// the [`ScanKind`] variant that uses them, documented per field.
#[repr(C)]
pub struct ScanSpec {
    /// What the caller (the retained C `vsscanf()` loop) must do next.
    pub kind: ScanKind,
    /// [`ScanKind::NeedBracket`] only: `true` means the caller must
    /// still consume `va_arg` (see module doc) but discard the result
    /// and return `num` unchanged, matching upstream's `return num;`
    /// after an already-consumed `va_arg`.
    pub stop: bool,
    /// [`ScanKind::NeedNumeric`] only: `'H'`/`'h'`/`'l'`/`'L'`/`'z'`, or
    /// `0xff` for "no qualifier" (upstream's `qualifier = -1` as a
    /// `u8`).
    pub qualifier: u8,
    /// [`ScanKind::NeedNumeric`] only.
    pub is_sign: bool,
    /// [`ScanKind::NeedNumeric`] only: 8/10/16, or 0 (`%i`, radix
    /// auto-detected by `simple_strntoll`/`simple_strntoull` from a
    /// `0`/`0x` prefix).
    pub base: u32,
    /// [`ScanKind::NeedC`]/[`ScanKind::NeedS`]/[`ScanKind::NeedBracket`]
    /// only: already resolved from upstream's `-1` sentinel to the
    /// real default (1 for `%c`, `SHRT_MAX` for `%s`; never `-1` for
    /// `%[`, since that's one of the `stop` conditions).
    pub field_width: i16,
    /// [`ScanKind::NeedBracket`] only, and only meaningful if `!stop`:
    /// the 256-bit character set (`DECLARE_BITMAP(set, 256)` upstream),
    /// already complemented and with bit 0 cleared if `%[^...]` was
    /// negated -- `consume_bracket` uses it as-is.
    pub set: [u64; 4],
}

const SHRT_MAX: i16 = i16::MAX;

fn set_bit(set: &mut [u64; 4], bit: u8) {
    set[(bit >> 6) as usize] |= 1u64 << (bit & 63);
}
fn clear_bit(set: &mut [u64; 4], bit: u8) {
    set[(bit >> 6) as usize] &= !(1u64 << (bit & 63));
}
fn test_bit(set: &[u64; 4], bit: u8) -> bool {
    (set[(bit >> 6) as usize] & (1u64 << (bit & 63))) != 0
}
fn complement(set: &mut [u64; 4]) {
    for word in set.iter_mut() {
        *word = !*word;
    }
}

/// `skip_atoi()`'s own field-width-parsing use in `vsscanf()`
/// (`static inline int skip_atoi(const char **s)`, `lib/vsprintf.c`) --
/// re-derived here rather than called cross-file, since the format-
/// string walk that needs it moves here entirely. `i*10 + digit` uses
/// wrapping arithmetic: upstream's `int` accumulation is unchecked
/// (silently wraps on real compilers for a format string with an
/// absurd number of width digits), and the result gets truncated to
/// `s16` on assignment regardless -- faithfully reproducing that rather
/// than panicking on a pathological but real input is the point,
/// exactly the same reasoning as every wraparound fix in xarray_rs.rs.
///
/// # Safety
/// `*fmt` must point at a NUL-terminated C string whose current byte is
/// an ASCII digit (caller's contract, matching every real call site).
unsafe fn skip_atoi(fmt: &mut *const c_char) -> i32 {
    let mut i: i32 = 0;
    loop {
        let c = unsafe { deref_u8(*fmt) };
        i = i.wrapping_mul(10).wrapping_add((c - b'0') as i32);
        *fmt = unsafe { fmt.add(1) };
        if !isdigit_byte(unsafe { deref_u8(*fmt) }) {
            break;
        }
    }
    i
}

/// `vsscanf()`'s per-specifier classification -- everything in the
/// upstream `while (*fmt)` loop body that needs no `va_arg` at all. See
/// the module doc for the full design and the `%[` ordering subtlety.
///
/// # Safety
/// `fmt`/`str_` must each point at a valid `*mut *const c_char`/
/// `*const *const c_char` referring to a NUL-terminated C string;
/// `buf` must be the same buffer `*str_` points into (used only for
/// pointer-difference arithmetic, never dereferenced through `buf`
/// itself).
#[no_mangle]
pub unsafe extern "C" fn vsprintf_scan_rs_next(
    fmt: *mut *const c_char,
    str_: *mut *const c_char,
    _buf: *const c_char,
) -> ScanSpec {
    let done = ScanSpec {
        kind: ScanKind::Done,
        stop: false,
        qualifier: 0xff,
        is_sign: false,
        base: 0,
        field_width: 0,
        set: [0; 4],
    };
    let cont = ScanSpec { kind: ScanKind::Continue, ..done };

    unsafe {
        // "skip any white space in format" -- matches any amount
        // (including none) of white space in the input.
        if isspace_byte(deref_u8(*fmt)) {
            *fmt = (*fmt).add(1);
            *fmt = skip_spaces(*fmt);
            *str_ = skip_spaces(*str_);
        }

        // "anything that is not a conversion must match exactly"
        if deref_u8(*fmt) != b'%' && deref_u8(*fmt) != 0 {
            let fc = deref_u8(*fmt);
            *fmt = (*fmt).add(1);
            let sc = deref_u8(*str_);
            *str_ = (*str_).add(1);
            if fc != sc {
                return done;
            }
            return cont;
        }

        if deref_u8(*fmt) == 0 {
            return done;
        }
        *fmt = (*fmt).add(1);

        // "skip this conversion. advance both strings to next white
        // space" -- '%*...'
        if deref_u8(*fmt) == b'*' {
            if deref_u8(*str_) == 0 {
                return done;
            }
            while !isspace_byte(deref_u8(*fmt)) && deref_u8(*fmt) != b'%' && deref_u8(*fmt) != 0 {
                if deref_u8(*fmt) == b'[' {
                    // '%*[' not yet supported, invalid format
                    return done;
                }
                *fmt = (*fmt).add(1);
            }
            while !isspace_byte(deref_u8(*str_)) && deref_u8(*str_) != 0 {
                *str_ = (*str_).add(1);
            }
            return cont;
        }

        // "get field width"
        let mut field_width: i32 = -1;
        if isdigit_byte(deref_u8(*fmt)) {
            field_width = skip_atoi(&mut *fmt);
            if field_width <= 0 {
                return done;
            }
        }

        // "get conversion qualifier"
        let mut qualifier: u8 = 0xff;
        let fc = deref_u8(*fmt);
        if fc == b'h' || tolower_fast(fc) == b'l' || fc == b'z' {
            qualifier = fc;
            *fmt = (*fmt).add(1);
            if qualifier == deref_u8(*fmt) {
                if qualifier == b'h' {
                    qualifier = b'H';
                    *fmt = (*fmt).add(1);
                } else if qualifier == b'l' {
                    qualifier = b'L';
                    *fmt = (*fmt).add(1);
                }
            }
        }

        if deref_u8(*fmt) == 0 {
            return done;
        }

        if deref_u8(*fmt) == b'n' {
            *fmt = (*fmt).add(1);
            return ScanSpec { kind: ScanKind::NeedN, ..done };
        }

        if deref_u8(*str_) == 0 {
            return done;
        }

        let spec_char = deref_u8(*fmt);
        *fmt = (*fmt).add(1);

        if spec_char == b'c' {
            return ScanSpec {
                kind: ScanKind::NeedC,
                field_width: if field_width == -1 { 1 } else { field_width as i16 },
                ..done
            };
        }
        if spec_char == b's' {
            return ScanSpec {
                kind: ScanKind::NeedS,
                field_width: if field_width == -1 { SHRT_MAX } else { field_width as i16 },
                ..done
            };
        }
        if spec_char == b'[' {
            // va_arg is ALWAYS consumed for '%[' upstream, even on
            // every failure path below -- see module doc. `stop` on
            // any of these paths reports that without touching `fmt`
            // any further than upstream does (upstream also stops
            // advancing `fmt` past the point of failure on the
            // `field_width == -1` path specifically -- the negate/set
            // parsing below still runs on that path in Rust for
            // simplicity, but its only observable effect is CPU work,
            // not behaviour, since `stop` discards everything).
            let mut set = [0u64; 4];
            let mut len: u32 = 0;
            let negate = deref_u8(*fmt) == b'^';
            let width_bad = field_width == -1;
            if negate {
                *fmt = (*fmt).add(1);
            }
            while deref_u8(*fmt) != 0 && deref_u8(*fmt) != b']' {
                set_bit(&mut set, deref_u8(*fmt));
                *fmt = (*fmt).add(1);
                len += 1;
            }
            let no_close_or_empty = deref_u8(*fmt) == 0 || len == 0;
            if !no_close_or_empty {
                *fmt = (*fmt).add(1);
            }
            if negate {
                complement(&mut set);
                clear_bit(&mut set, 0);
            }
            let first_mismatch = !no_close_or_empty && !test_bit(&set, deref_u8(*str_));
            let stop = width_bad || no_close_or_empty || first_mismatch;
            return ScanSpec {
                kind: ScanKind::NeedBracket,
                stop,
                field_width: if stop { 0 } else { field_width as i16 },
                set,
                ..done
            };
        }

        let (base, is_sign): (u32, bool) = match spec_char {
            b'o' => (8, false),
            b'x' | b'X' => (16, false),
            b'i' => (0, true),
            b'd' => (10, true),
            b'u' => (10, false),
            b'%' => {
                // "looking for '%' in str"
                let sc = deref_u8(*str_);
                *str_ = (*str_).add(1);
                if sc != b'%' {
                    return done;
                }
                return cont;
            }
            _ => return done, // invalid format; stop here
        };

        // "have some sort of integer conversion. first, skip white
        // space in buffer."
        *str_ = skip_spaces(*str_);

        let mut digit = deref_u8(*str_);
        if is_sign && digit == b'-' {
            if field_width == 1 {
                return done;
            }
            digit = deref_u8((*str_).add(1));
        }

        let digit_ok = digit != 0
            && !(base == 16 && !isxdigit_byte(digit))
            && !(base == 10 && !isdigit_byte(digit))
            && !(base == 8 && !isodigit_byte(digit))
            && !(base == 0 && !isdigit_byte(digit));
        if !digit_ok {
            return done;
        }

        ScanSpec {
            kind: ScanKind::NeedNumeric,
            qualifier,
            is_sign,
            base,
            field_width: if field_width == -1 { -1 } else { field_width as i16 },
            ..done
        }
    }
}

/// `%c`'s copy loop, given the already-`va_arg`-extracted destination.
/// `spec.field_width` is already resolved (never -1).
///
/// # Safety
/// `str_`/`dst` must be valid for the reads/writes this performs:
/// `*str_` a NUL-terminated C string, `dst` writable for at least
/// `field_width` bytes (upstream's own contract -- the caller's
/// `va_arg(args, char *)` destination, unchecked, exactly as upstream).
#[no_mangle]
pub unsafe extern "C" fn vsprintf_scan_rs_consume_c(
    str_: *mut *const c_char,
    field_width: i16,
    dst: *mut c_char,
) {
    let mut field_width = field_width;
    let mut s = dst as *mut u8;
    unsafe {
        loop {
            let c = deref_u8(*str_);
            *s = c;
            s = s.add(1);
            *str_ = (*str_).add(1);
            field_width -= 1;
            if !(field_width > 0 && deref_u8(*str_) != 0) {
                break;
            }
        }
    }
}

/// `%s`'s copy loop (skip leading whitespace, copy until next
/// whitespace or `field_width` runs out, NUL-terminate).
///
/// # Safety
/// Same contract as [`vsprintf_scan_rs_consume_c`].
#[no_mangle]
pub unsafe extern "C" fn vsprintf_scan_rs_consume_s(
    str_: *mut *const c_char,
    field_width: i16,
    dst: *mut c_char,
) {
    let mut field_width = field_width;
    let mut s = dst as *mut u8;
    unsafe {
        *str_ = skip_spaces(*str_);
        while deref_u8(*str_) != 0 && !isspace_byte(deref_u8(*str_)) && field_width > 0 {
            field_width -= 1;
            *s = deref_u8(*str_);
            s = s.add(1);
            *str_ = (*str_).add(1);
        }
        *s = 0;
    }
}

/// `%[...]`'s copy loop, given the already-validated set (see
/// [`ScanSpec::set`]) and the already-`va_arg`-extracted destination.
/// Only called when [`ScanSpec::stop`] was `false`.
///
/// `set` points at the first of [`ScanSpec::set`]'s 4 `u64` words (a
/// plain pointer rather than a reference so the C side declares it as
/// the natural `const unsigned long long *`, matching how `spec.set`
/// -- a struct member of array type -- decays when passed).
///
/// # Safety
/// Same contract as [`vsprintf_scan_rs_consume_c`], plus: `set` valid
/// for reads of 4 `u64`s.
#[no_mangle]
pub unsafe extern "C" fn vsprintf_scan_rs_consume_bracket(
    str_: *mut *const c_char,
    field_width: i16,
    set: *const u64,
    dst: *mut c_char,
) {
    let mut field_width = field_width;
    let mut s = dst as *mut u8;
    // SAFETY: caller's contract, 4 `u64`s.
    let set: [u64; 4] = unsafe { [*set, *set.add(1), *set.add(2), *set.add(3)] };
    unsafe {
        while test_bit(&set, deref_u8(*str_)) && field_width > 0 {
            field_width -= 1;
            *s = deref_u8(*str_);
            s = s.add(1);
            *str_ = (*str_).add(1);
        }
        *s = 0;
    }
}
