// SPDX-License-Identifier: GPL-2.0

//! String-to-integer conversion -- the Rust behind `lib/kstrtox.c`.
//!
//! Ported from `lib/kstrtox.c` (6.18.49).
//!
//! Replaces: lib/kstrtox.c
//!
//! # Three of these symbols are not exported, and still have to be Rust
//!
//! `_parse_integer_fixup_radix`, `_parse_integer_limit` and `_parse_integer`
//! carry no `EXPORT_SYMBOL` -- so no MODVERSIONS fingerprint, no
//! `kernel::kabi_export!()` -- but `lib/vsprintf.c` and `lib/bitmap-str.c`
//! (both still C, both un-ported: `vsprintf.c` is the highest fan-in file in
//! the tree and goes last per SCOPE.md §1) call them directly across the
//! object boundary via `lib/kstrtox.h`. Deleting the C body without keeping
//! these three linkable under their exact C names would break two files this
//! port never touches. `#[no_mangle] pub unsafe extern "C" fn` is sufficient:
//! kbuild links every object into one `vmlinux` regardless of source
//! language, so an ordinary global symbol resolves the reference just as the
//! old `.o` did.
//!
//! # `copy_from_user` is called through the extern, not the inline wrapper
//!
//! `include/linux/uaccess.h`'s `copy_from_user()` is a `static inline` --
//! unreachable from Rust, which cannot link against a header-only C
//! function -- that dispatches to either `_inline_copy_from_user()` or the
//! `extern` `_copy_from_user()` depending on `INLINE_COPY_FROM_USER`, after
//! a `check_copy_size()` hardening check. The header says outright: *"Rust
//! code always uses the extern definition."* `lib/usercopy.c` (also
//! un-ported) defines that extern as nothing but a call to
//! `_inline_copy_from_user()` -- so `access_ok()`, `might_fault()`, the
//! actual `raw_copy_from_user()` and the short-copy zero-fill on failure are
//! all still performed; only `check_copy_size()`'s object-size hardening is
//! skipped. Every call site here first clamps `count` to `sizeof(buf) - 1`,
//! so the size that check would validate is already guaranteed safe before
//! the call -- skipping it changes nothing observable and matches the
//! convention the C header itself documents for Rust callers.
//!
//! # Byte comparisons are done as `u8`, not as promoted `int`
//!
//! The C reads `unsigned int c = *s;` on a (signed, on x86-64) `char`, so a
//! byte with the high bit set promotes to a large value before any range
//! check runs. Every comparison here is either an exact match against an
//! ASCII byte or a range check against an ASCII range (`'0'..='9'`,
//! `'a'..='f'`), and a `u8` in `0x80..=0xFF` fails every one of those checks
//! exactly as the promoted-and-widened C value does -- both reject the byte
//! as "not a digit" / "not x". Reading it as plain `u8` reaches the same
//! answer without reproducing char-promotion, and was checked against the
//! two places it could matter: the digit-value loop and the `x`-detection in
//! `_parse_integer_fixup_radix`.
//!
//! # `div_u64` is plain division here, and that is not a shortcut
//!
//! `include/linux/math64.h` defines `div_u64(u64, u32)` as `dividend /
//! divisor` whenever `BITS_PER_LONG == 64`, which is unconditionally true on
//! the only architecture either config builds. There is no 64-bit-divide
//! symbol to call.

use core::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, c_void};

/// `-EINVAL`.
const EINVAL: c_int = 22;
/// `-EFAULT`.
const EFAULT: c_int = 14;
/// `-ERANGE`.
const ERANGE: c_int = 34;

/// `KSTRTOX_OVERFLOW` -- `lib/kstrtox.h`.
const KSTRTOX_OVERFLOW: c_uint = 1 << 31;

extern "C" {
    /// `lib/usercopy.c`'s `_copy_from_user()`. Returns the number of bytes
    /// NOT copied -- zero is success. See the module doc comment.
    fn _copy_from_user(to: *mut c_void, from: *const c_void, n: c_ulong) -> c_ulong;
}

/// `s[i]` as `_parse_integer_limit` and friends read it: an unsigned byte,
/// not a promoted `int`. See the module doc comment.
#[inline]
unsafe fn byte_at(s: *const c_char, i: usize) -> u8 {
    // SAFETY: the caller guarantees `s` is NUL-terminated and `i` does not
    // read past that terminator -- the same guarantee every C caller here
    // relies on.
    unsafe { *s.add(i) as u8 }
}

/// `_tolower()` from `include/linux/ctype.h`: `c | 0x20`, nothing more.
#[inline]
const fn ascii_tolower(c: u8) -> u8 {
    c | 0x20
}

/// `isxdigit(c)` from `include/linux/ctype.h`, restated directly: `'0'..='9'`
/// or `'a'..='f'` after `_tolower`. Equivalent to `_ctype[c] & (_D|_X)` for
/// every byte this parser ever indexes with, and does not need `lib/ctype.c`
/// linked in to be read.
#[inline]
fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&ascii_tolower(c))
}

/// Body of `_parse_integer_fixup_radix()`: detect `0x`/`0` prefixes when
/// `*base == 0`, and skip a `0x`/`0X` prefix once `base` is 16.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `base` at a valid `u32`.
#[no_mangle]
pub unsafe extern "C" fn _parse_integer_fixup_radix(
    s: *const c_char,
    base: *mut c_uint,
) -> *const c_char {
    // SAFETY: caller guarantees `base` is valid.
    let mut b = unsafe { *base };
    // SAFETY: caller guarantees `s` is NUL-terminated; reading s[0] is
    // always in bounds of that guarantee.
    let s0 = unsafe { byte_at(s, 0) };

    if b == 0 {
        if s0 == b'0' {
            // SAFETY: s0 == '0' means s[0] is not NUL, so s[1] is in bounds.
            let s1 = unsafe { byte_at(s, 1) };
            // Short-circuit: s[2] is only read once s[1] == 'x', which
            // guarantees s[1] was not the NUL terminator, so a byte at s[2]
            // exists (the terminator itself, at worst).
            let is_x_prefix =
                ascii_tolower(s1) == b'x' && is_hex_digit(unsafe { byte_at(s, 2) });
            b = if is_x_prefix { 16 } else { 8 };
        } else {
            b = 10;
        }
    }

    let mut s = s;
    if b == 16 && s0 == b'0' {
        // SAFETY: as above -- s0 == '0' guarantees s[1] is in bounds.
        if ascii_tolower(unsafe { byte_at(s, 1) }) == b'x' {
            // SAFETY: advancing past two bytes just read as in-bounds.
            s = unsafe { s.add(2) };
        }
    }

    // SAFETY: caller guarantees `base` is valid.
    unsafe { *base = b };
    s
}

/// Body of `_parse_integer_limit()`: consume up to `max_chars` digits of
/// `base`, returning the digit count OR-ed with [`KSTRTOX_OVERFLOW`].
///
/// "Don't you dare use this function" -- same caveat as the C: it does not
/// stop at the string's end on its own, relying on the NUL terminator (or
/// any other non-digit byte) failing the digit check and breaking the loop.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `p` at a valid `u64`.
#[no_mangle]
pub unsafe extern "C" fn _parse_integer_limit(
    s: *const c_char,
    base: c_uint,
    p: *mut c_ulonglong,
    max_chars: usize,
) -> c_uint {
    let mut res: u64 = 0;
    let mut rv: c_uint = 0;
    let mut max_chars = max_chars;
    let mut i = 0usize;

    while max_chars > 0 {
        max_chars = max_chars.wrapping_sub(1);
        // SAFETY: the loop only continues past a byte that was itself a
        // valid digit, which guarantees it was not the NUL terminator, so
        // the next byte is in bounds of the caller's NUL-terminated string.
        let c = unsafe { byte_at(s, i) };
        let lc = ascii_tolower(c);

        let val: u32 = if c.is_ascii_digit() {
            (c.wrapping_sub(b'0')) as u32
        } else if (b'a'..=b'f').contains(&lc) {
            ((lc.wrapping_sub(b'a')) as u32).wrapping_add(10)
        } else {
            break;
        };

        if val >= base {
            break;
        }

        if res & (!0u64 << 60) != 0 {
            // div_u64(u64, u32) is plain division at BITS_PER_LONG == 64;
            // see the module doc comment.
            if res > (u64::MAX.wrapping_sub(val as u64)) / base as u64 {
                rv |= KSTRTOX_OVERFLOW;
            }
        }
        res = res.wrapping_mul(base as u64).wrapping_add(val as u64);
        rv = rv.wrapping_add(1);
        i = i.wrapping_add(1);
    }

    // SAFETY: caller guarantees `p` is valid.
    unsafe { *p = res };
    rv
}

/// Body of `_parse_integer()`: [`_parse_integer_limit`] with `max_chars ==
/// INT_MAX`.
///
/// # Safety
/// Same as [`_parse_integer_limit`].
#[no_mangle]
pub unsafe extern "C" fn _parse_integer(
    s: *const c_char,
    base: c_uint,
    p: *mut c_ulonglong,
) -> c_uint {
    // SAFETY: forwarding the caller's guarantee.
    unsafe { _parse_integer_limit(s, base, p, c_int::MAX as usize) }
}

/// `_kstrtoull()`: shared body behind [`kstrtoull`] and (via negation)
/// [`kstrtoll`]. Not exported in the C (`static`), so this stays a plain
/// Rust function rather than an `extern "C"` symbol.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u64`.
unsafe fn kstrtoull_body(s: *const c_char, base: c_uint, res: *mut c_ulonglong) -> c_int {
    let mut tmp: u64 = 0;
    let mut base = base;
    // SAFETY: forwarding the caller's guarantee.
    let s = unsafe { _parse_integer_fixup_radix(s, &mut base) };
    // SAFETY: `s` and `&mut tmp` are valid for `_parse_integer`.
    let rv = unsafe { _parse_integer(s, base, &mut tmp) };

    if rv & KSTRTOX_OVERFLOW != 0 {
        return -ERANGE;
    }
    if rv == 0 {
        return -EINVAL;
    }
    // SAFETY: `rv` digits were consumed from `s`, which stays in bounds of
    // the caller's NUL-terminated string; the byte after them is either the
    // terminator or a real character, both safe to read.
    let mut s = unsafe { s.add(rv as usize) };
    // SAFETY: as above.
    if unsafe { byte_at(s, 0) } == b'\n' {
        s = unsafe { s.add(1) };
    }
    // SAFETY: as above.
    if unsafe { byte_at(s, 0) } != 0 {
        return -EINVAL;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp };
    0
}

// The C types these contracts name. Generated by `rig/kabi-pin.sh
// --capture`; do not hand-edit -- see logs/pins/kstrtox.pins.
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#__s16",
    "typedef_type __s16 { base_type short byte_size(2) encoding(5) }");
kernel::kabi_rule!("type_string", "t#s16",
    "typedef_type s16 { t#__s16 }");
kernel::kabi_rule!("type_string", "t#__s8",
    "typedef_type __s8 { base_type signed char byte_size(1) encoding(6) }");
kernel::kabi_rule!("type_string", "t#s8",
    "typedef_type s8 { t#__s8 }");
kernel::kabi_rule!("type_string", "t#__u16",
    "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u16",
    "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    kstrtoull,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned long long byte_size(8) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtoull()`: convert a string to an `unsigned long long`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u64`.
#[no_mangle]
pub unsafe extern "C" fn kstrtoull(
    s: *const c_char,
    base: c_uint,
    res: *mut c_ulonglong,
) -> c_int {
    // SAFETY: caller guarantees `s` is NUL-terminated.
    let s = if unsafe { byte_at(s, 0) } == b'+' {
        unsafe { s.add(1) }
    } else {
        s
    };
    // SAFETY: forwarding the caller's guarantees.
    unsafe { kstrtoull_body(s, base, res) }
}

kernel::kabi_export! {
    kstrtoll,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type long long byte_size(8) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtoll()`: convert a string to a `long long`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `i64`.
#[no_mangle]
pub unsafe extern "C" fn kstrtoll(s: *const c_char, base: c_uint, res: *mut c_longlong) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: caller guarantees `s` is NUL-terminated.
    if unsafe { byte_at(s, 0) } == b'-' {
        // SAFETY: s[0] == '-' means s[0] is not NUL, so s+1 is in bounds.
        let rv = unsafe { kstrtoull_body(s.add(1), base, &mut tmp) };
        if rv < 0 {
            return rv;
        }
        let neg = (tmp as i64).wrapping_neg();
        if neg > 0 {
            return -ERANGE;
        }
        // SAFETY: caller guarantees `res` is valid.
        unsafe { *res = neg };
    } else {
        // SAFETY: forwarding the caller's guarantees.
        let rv = unsafe { kstrtoull(s, base, &mut tmp) };
        if rv < 0 {
            return rv;
        }
        if (tmp as i64) < 0 {
            return -ERANGE;
        }
        // SAFETY: caller guarantees `res` is valid.
        unsafe { *res = tmp as i64 };
    }
    0
}

kernel::kabi_export! {
    _kstrtoul,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `_kstrtoul()`. Internal per the C's own comment -- callers want
/// `kstrtoul()`, the header inline that (on this, 64-bit-`long`,
/// architecture) always calls [`kstrtoull`] directly instead.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u64`.
#[no_mangle]
pub unsafe extern "C" fn _kstrtoul(s: *const c_char, base: c_uint, res: *mut c_ulong) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as c_ulong as u64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as c_ulong };
    0
}

kernel::kabi_export! {
    _kstrtol,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type long byte_size(8) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `_kstrtol()`. Internal per the C's own comment; see [`_kstrtoul`].
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `i64`.
#[no_mangle]
pub unsafe extern "C" fn _kstrtol(s: *const c_char, base: c_uint, res: *mut c_long) -> c_int {
    let mut tmp: i64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as c_long as i64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as c_long };
    0
}

kernel::kabi_export! {
    kstrtouint,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtouint()`: convert a string to an `unsigned int`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u32`.
#[no_mangle]
pub unsafe extern "C" fn kstrtouint(s: *const c_char, base: c_uint, res: *mut c_uint) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as c_uint as u64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as c_uint };
    0
}

kernel::kabi_export! {
    kstrtoint,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtoint()`: convert a string to an `int`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `i32`.
#[no_mangle]
pub unsafe extern "C" fn kstrtoint(s: *const c_char, base: c_uint, res: *mut c_int) -> c_int {
    let mut tmp: i64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as c_int as i64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as c_int };
    0
}

kernel::kabi_export! {
    kstrtou16,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#u16 } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtou16()`: convert a string to a `u16`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u16`.
#[no_mangle]
pub unsafe extern "C" fn kstrtou16(s: *const c_char, base: c_uint, res: *mut u16) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as u16 as u64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as u16 };
    0
}

kernel::kabi_export! {
    kstrtos16,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#s16 } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtos16()`: convert a string to an `s16`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `i16`.
#[no_mangle]
pub unsafe extern "C" fn kstrtos16(s: *const c_char, base: c_uint, res: *mut i16) -> c_int {
    let mut tmp: i64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as i16 as i64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as i16 };
    0
}

kernel::kabi_export! {
    kstrtou8,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#u8 } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtou8()`: convert a string to a `u8`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `u8`.
#[no_mangle]
pub unsafe extern "C" fn kstrtou8(s: *const c_char, base: c_uint, res: *mut u8) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as u8 as u64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as u8 };
    0
}

kernel::kabi_export! {
    kstrtos8,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#s8 } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtos8()`: convert a string to an `s8`.
///
/// # Safety
/// `s` must point at a NUL-terminated string and `res` at a valid `i8`.
#[no_mangle]
pub unsafe extern "C" fn kstrtos8(s: *const c_char, base: c_uint, res: *mut i8) -> c_int {
    let mut tmp: i64 = 0;
    // SAFETY: forwarding the caller's guarantees.
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as i8 as i64 {
        return -ERANGE;
    }
    // SAFETY: caller guarantees `res` is valid.
    unsafe { *res = tmp as i8 };
    0
}

kernel::kabi_export! {
    kstrtobool,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter pointer_type { t#bool } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtobool()`: convert common user inputs into boolean values.
///
/// Returns 0 iff the first character is one of `EeYyTt1DdNnFf0`, or
/// `[oO][NnFf]` for "on"/"off".
///
/// # Safety
/// `s`, if non-null, must point at a NUL-terminated string; `res` must be a
/// valid `bool`.
#[no_mangle]
pub unsafe extern "C" fn kstrtobool(s: *const c_char, res: *mut bool) -> c_int {
    if s.is_null() {
        return -EINVAL;
    }
    // SAFETY: caller guarantees `s` is NUL-terminated.
    let s0 = unsafe { byte_at(s, 0) };
    let val = match s0 {
        b'e' | b'E' | b'y' | b'Y' | b't' | b'T' | b'1' => Some(true),
        b'd' | b'D' | b'n' | b'N' | b'f' | b'F' | b'0' => Some(false),
        b'o' | b'O' => {
            // SAFETY: s0 is one of 'o'/'O', not NUL, so s[1] is in bounds.
            match unsafe { byte_at(s, 1) } {
                b'n' | b'N' => Some(true),
                b'f' | b'F' => Some(false),
                _ => None,
            }
        }
        _ => None,
    };
    match val {
        Some(v) => {
            // SAFETY: caller guarantees `res` is valid.
            unsafe { *res = v };
            0
        }
        None => -EINVAL,
    }
}

kernel::kabi_export! {
    kstrtobool_from_user,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter pointer_type { t#bool } res ) -> base_type int byte_size(4) encoding(5)",
}

/// `kstrtobool_from_user()`: [`kstrtobool`] on a `__user` buffer.
///
/// "Longest string needed to differentiate, newline, terminator" -- 4 bytes,
/// same as the C.
///
/// # Safety
/// `s` must be a `__user` pointer valid for `count` bytes; `res` must be a
/// valid `bool`.
#[no_mangle]
pub unsafe extern "C" fn kstrtobool_from_user(
    s: *const c_char,
    count: c_ulong,
    res: *mut bool,
) -> c_int {
    let mut buf = [0u8; 4];
    let count = (count as usize).min(buf.len() - 1);
    // SAFETY: `s` is the caller's `__user` pointer, valid for `count` bytes
    // by the caller's guarantee; `buf` has room for `count` bytes plus the
    // NUL this function adds below.
    let missing = unsafe {
        _copy_from_user(
            buf.as_mut_ptr() as *mut c_void,
            s as *const c_void,
            count as c_ulong,
        )
    };
    if missing != 0 {
        return -EFAULT;
    }
    buf[count] = 0;
    // SAFETY: `buf` is NUL-terminated at `count`, within its bounds.
    unsafe { kstrtobool(buf.as_ptr() as *const c_char, res) }
}

/// The shared shape of every `kstrto<T>_from_user()`: copy at most
/// `sizeof(buf) - 1` bytes out of a `__user` string, NUL-terminate, and
/// delegate to the non-`_from_user` conversion. Mirrors the C's
/// `kstrto_from_user()` macro in `lib/kstrtox.c`.
///
/// `$buflen` is `1 (sign) + bits(&type) (binary digits) + 1 (newline) + 1
/// (terminator)`, exactly as the C sizes it.
macro_rules! kstrto_from_user {
    ($name:ident, $ty:ty, $buflen:literal, $inner:expr, contract = $contract:literal $(,)?) => {
        kernel::kabi_export! {
            $name,
            license = "",
            namespace = "",
            contract = $contract,
        }

        #[doc = concat!("`", stringify!($name), "()`: the `_from_user` form of the matching conversion.")]
        ///
        /// # Safety
        /// `s` must be a `__user` pointer valid for `count` bytes; `res`
        /// must be a valid destination.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            s: *const c_char,
            count: c_ulong,
            base: c_uint,
            res: *mut $ty,
        ) -> c_int {
            let mut buf = [0u8; $buflen];
            let count = (count as usize).min(buf.len() - 1);
            // SAFETY: `s` is the caller's `__user` pointer, valid for
            // `count` bytes by the caller's guarantee; `buf` has room for
            // `count` bytes plus the NUL this function adds below.
            let missing = unsafe {
                _copy_from_user(
                    buf.as_mut_ptr() as *mut c_void,
                    s as *const c_void,
                    count as c_ulong,
                )
            };
            if missing != 0 {
                return -EFAULT;
            }
            buf[count] = 0;
            let g: unsafe extern "C" fn(*const c_char, c_uint, *mut $ty) -> c_int = $inner;
            // SAFETY: `buf` is NUL-terminated at `count`, within its bounds.
            unsafe { g(buf.as_ptr() as *const c_char, base, res) }
        }
    };
}

kstrto_from_user! {
    kstrtoull_from_user, c_ulonglong, 67, kstrtoull,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned long long byte_size(8) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtoll_from_user, c_longlong, 67, kstrtoll,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type long long byte_size(8) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtoul_from_user, c_ulong, 67, _kstrtoul,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtol_from_user, c_long, 67, _kstrtol,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type long byte_size(8) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtouint_from_user, c_uint, 34, kstrtouint,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtoint_from_user, c_int, 34, kstrtoint,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtou16_from_user, u16, 19, kstrtou16,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#u16 } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtos16_from_user, i16, 19, kstrtos16,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#s16 } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtou8_from_user, u8, 11, kstrtou8,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#u8 } res ) -> base_type int byte_size(4) encoding(5)",
}

kstrto_from_user! {
    kstrtos8_from_user, i8, 11, kstrtos8,
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type unsigned int byte_size(4) encoding(7) base , formal_parameter pointer_type { t#s8 } res ) -> base_type int byte_size(4) encoding(5)",
}
