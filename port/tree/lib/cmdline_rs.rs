// SPDX-License-Identifier: GPL-2.0-only

//! Kernel command-line parsing -- the Rust behind `lib/cmdline.c`.
//!
//! Ported from `lib/cmdline.c` (6.18.49), whose code and copyrights come from
//! `init/main.c` and `arch/i386/kernel/setup.c`.
//!
//! Replaces: lib/cmdline.c
//!
//! # Every function here is the "contract without a length" shape
//!
//! Not one of these signatures carries a bound. `get_option()` takes a
//! `char **`, `next_arg()` takes a `char *` and WRITES NULs into it, and both
//! walk until they find a terminator. The previous attempt at this port named
//! that class -- *"the C's contract provides no length"* -- and concluded it
//! cannot be eliminated at the FFI boundary without changing the callers'
//! signatures, which would be a different change from porting the file.
//!
//! So the `unsafe` here is not an artefact of translation; it is the contract
//! upstream published, restated. What Rust adds is that the reasoning is
//! written down at each site rather than assumed.
//!
//! # `next_arg()` writes into its argument
//!
//! It is a tokeniser that terminates each field **in place**, so the buffer
//! must be writable and the `param`/`val` pointers it hands back are interior
//! pointers into it. That is why its argument is `char *` and not
//! `const char *`, and it is the reason `parse_args()` copies the command
//! line before parsing it.
//!
//! # `simple_strtoull` and friends stay in C
//!
//! They live in `lib/vsprintf.c`, which has the highest fan-in in the tree
//! and is ported last (SCOPE.md §1). Calling them is a C crossing this port
//! deliberately keeps.

use core::ffi::{c_char, c_int, c_ulonglong};

extern "C" {
    /// `lib/vsprintf.c`.
    fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> c_ulonglong;
    /// `lib/vsprintf.c`.
    fn simple_strtol(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> core::ffi::c_long;
    /// `lib/string.c`. Advances past leading whitespace.
    fn skip_spaces(str_: *const c_char) -> *mut c_char;
    /// `lib/string.c`.
    fn strlen(s: *const c_char) -> usize;
    /// `lib/string.c`.
    fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int;
    /// `lib/ctype.c`, now `lib/ctype_rs.rs`.
    static _ctype: [u8; 256];
}

/// `_S` -- the white-space bit `isspace()` tests.
const CTYPE_S: u8 = 0x20;

/// `isspace()` from `include/linux/ctype.h`.
#[inline]
fn is_space(c: c_char) -> bool {
    // SAFETY: `_ctype` is a 256-entry table and the index is a byte, which is
    // exactly what `__ismask()` does.
    (unsafe { _ctype[c as u8 as usize] } & CTYPE_S) != 0
}

// The C types these contracts name -- there are none; every parameter is a
// built-in type or a pointer to one.

kernel::kabi_export! {
    get_option,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { pointer_type { base_type char byte_size(1) encoding(8) } } str , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } pint ) -> base_type int byte_size(4) encoding(5)",
}

/// Body of `get_option()`. Returns 0 for no integer, 1 for one, 2 if a comma
/// followed, 3 if a hyphen did.
///
/// **The value is parsed as `unsigned long long` and then narrowed to `int`,
/// including in the negative case**, where the C writes
/// `-simple_strtoull(++cur, str, 0)`. Reproducing the narrowing exactly is the
/// point: `get_option("4294967296", &v)` gives 0, not saturation, and callers
/// have depended on that for a long time. `-Coverflow-checks=y` makes the
/// obvious Rust panic there, so the casts are explicit and wrapping.
///
/// # Safety
/// `*str` must be NUL-terminated; `pint` may be null, which the C documents as
/// "use as a validator".
#[no_mangle]
pub unsafe extern "C" fn get_option(str_: *mut *mut c_char, pint: *mut c_int) -> c_int {
    // SAFETY: the caller guarantees a valid `char **`.
    let cur = unsafe { *str_ };

    // SAFETY: `cur` is NUL-terminated or null, both of which this tests.
    if cur.is_null() || unsafe { *cur } == 0 {
        return 0;
    }

    // `++cur` IS A SIDE EFFECT AND IT IS LOAD-BEARING. The C writes
    // `value = -simple_strtoull(++cur, str, 0)`, so after the negative branch
    // `cur` points PAST the hyphen -- and the `cur == *str` test below is
    // what turns "a hyphen with no digits after it" into "no integer here".
    // Leaving `cur` on the hyphen makes get_option("-,") return 2 instead of
    // 0, and its documented contract says a leading hyphen without an integer
    // is the no-integer case. Found by upstream's own
    // lib/tests/cmdline_kunit.c, which failed on the patterns `-,`, `-`, `--`
    // and `-""` before this line existed.
    let mut cur = cur;
    // SAFETY: `cur` points at a readable character, and simple_strtoull walks
    // a NUL-terminated string and writes the end back through `str_`.
    let value = unsafe {
        if *cur == b'-' as c_char {
            cur = cur.add(1);
            (simple_strtoull(cur, str_, 0) as i64).wrapping_neg() as c_int
        } else {
            simple_strtoull(cur, str_, 0) as c_int
        }
    };

    if !pint.is_null() {
        // SAFETY: the caller guarantees `pint` is writable when non-null.
        unsafe { *pint = value };
    }

    // SAFETY: simple_strtoull has just written a valid pointer through `str_`.
    let end = unsafe { *str_ };
    if core::ptr::eq(cur, end) {
        return 0;
    }
    // SAFETY: `end` points inside the same NUL-terminated string.
    match unsafe { *end } as u8 {
        b',' => {
            // SAFETY: as above.
            unsafe { *str_ = end.add(1) };
            2
        }
        b'-' => 3,
        _ => 1,
    }
}

/// `get_range()`: expand `M-N` into the caller's array, returning `N - M`.
///
/// **It returns the span even when it wrote nothing**, which is what lets
/// `get_options()` keep counting while `nints` is 0 (validation mode).
///
/// # Safety
/// `*str` must be NUL-terminated, and `pint` must be writable for `n`
/// elements.
#[inline]
unsafe fn get_range(str_: *mut *mut c_char, pint: *mut c_int, n: c_int) -> c_int {
    // `(*str)++` IN THE C MUTATES THE CALLER'S POINTER, and this line has to
    // as well. Computing the advanced pointer into a local and leaving `*str`
    // on the hyphen makes the NEXT get_option() see that hyphen and parse the
    // upper bound as a negative number -- so `1-3` yields 1, 2, -3. Upstream's
    // lib/tests/cmdline_kunit.c cmdline_test_range found it.
    //
    // Note that `simple_strtol` is then given a NULL endptr, so `*str` stays
    // pointing at the upper bound's first digit on purpose: the C's comment
    // says "the next iteration will handle the upper number in the range".
    // SAFETY: the caller guarantees a valid `char **` pointing at '-'.
    unsafe { *str_ = (*str_).add(1) };
    // SAFETY: `*str_` is inside the NUL-terminated string.
    let upper = unsafe { simple_strtol(*str_, core::ptr::null_mut(), 0) } as c_int;
    // SAFETY: the caller guarantees `pint` is readable.
    let start = unsafe { *pint };
    let inc = upper.wrapping_sub(start);

    let mut p = pint;
    let mut x = start;
    let mut n = n;
    while n != 0 && x < upper {
        // SAFETY: fewer than `n` writes have happened, and the caller
        // guarantees `n` writable elements.
        unsafe {
            *p = x;
            p = p.add(1);
        }
        x += 1;
        n -= 1;
    }
    inc
}

kernel::kabi_export! {
    get_options,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } str , formal_parameter base_type int byte_size(4) encoding(5) nints , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } ints ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}

/// Body of `get_options()`: a comma-separated list, possibly with `M-N`
/// ranges, into `ints[1..]`, with the count in `ints[0]`.
///
/// **`nints == 0` is validation mode**: nothing past `ints[0]` is written and
/// the return is the count that would have been produced. The C expresses
/// that by aiming every write at `ints` itself, which is why `pint` is
/// `ints` rather than `ints + i` in that mode -- a detail that looks like a
/// bug and is not.
///
/// # Safety
/// `str` must be NUL-terminated. `ints` must be writable for `nints`
/// elements, or for one element when `nints` is 0.
#[no_mangle]
pub unsafe extern "C" fn get_options(str_: *const c_char, nints: c_int, ints: *mut c_int) -> *mut c_char {
    let validate = nints == 0;
    let mut s = str_ as *mut c_char;
    let mut i: c_int = 1;

    while i < nints || validate {
        // SAFETY: in validation mode every write goes to ints[0]; otherwise
        // `i < nints` and the caller guarantees `nints` elements.
        let pint = if validate { ints } else { unsafe { ints.add(i as usize) } };

        // SAFETY: `s` is NUL-terminated and `pint` is writable.
        let res = unsafe { get_option(&mut s, pint) };
        if res == 0 {
            break;
        }
        if res == 3 {
            let n = if validate { 0 } else { nints - i };
            // SAFETY: as above; `n` is the room actually left.
            let range_nums = unsafe { get_range(&mut s, pint, n) };
            if range_nums < 0 {
                break;
            }
            // One less than the span: the next iteration handles the upper
            // number in the range.
            i += range_nums - 1;
        }
        i += 1;
        if res == 1 {
            break;
        }
    }
    // SAFETY: the caller guarantees at least one writable element.
    unsafe { *ints = i - 1 };
    s
}

kernel::kabi_export! {
    memparse,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } ptr , formal_parameter pointer_type { pointer_type { base_type char byte_size(1) encoding(8) } } retptr ) -> base_type unsigned long long byte_size(8) encoding(7)",
}

/// Body of `memparse()`: a number with an optional `K`/`M`/`G`/`T`/`P`/`E`
/// suffix, either case.
///
/// **The suffix is consumed and the higher ones are not.** The C's switch
/// falls through from `E` down to `K`, and only the `K` case does `endptr++`
/// -- so every suffix shifts by the right amount and every suffix advances
/// the pointer by exactly one. Getting that wrong gives `1E` a `retptr` that
/// still points at the `E`.
///
/// The shifts are `wrapping_shl` because the C's `<<=` on `unsigned long
/// long` wraps: `memparse("64E")` overflows 64 bits, upstream lets it, and
/// `-Coverflow-checks=y` would make the obvious Rust panic instead.
///
/// # Safety
/// `ptr` must be NUL-terminated; `retptr` may be null.
#[no_mangle]
pub unsafe extern "C" fn memparse(ptr: *const c_char, retptr: *mut *mut c_char) -> c_ulonglong {
    let mut endptr: *mut c_char = core::ptr::null_mut();
    // SAFETY: `ptr` is NUL-terminated and `endptr` is a valid local.
    let mut ret = unsafe { simple_strtoull(ptr, &mut endptr, 0) };

    // SAFETY: simple_strtoull leaves `endptr` inside the same string.
    let shift = match unsafe { *endptr } as u8 {
        b'E' | b'e' => 60,
        b'P' | b'p' => 50,
        b'T' | b't' => 40,
        b'G' | b'g' => 30,
        b'M' | b'm' => 20,
        b'K' | b'k' => 10,
        _ => 0,
    };
    if shift != 0 {
        ret = ret.wrapping_shl(shift);
        // The C advances by one for ANY suffix -- the fallthrough chain
        // reaches the `endptr++` in the 'K' case from every other case.
        // SAFETY: `endptr` points at the suffix character, which is not the
        // NUL, so one past it is still inside the string.
        endptr = unsafe { endptr.add(1) };
    }

    if !retptr.is_null() {
        // SAFETY: the caller guarantees `retptr` is writable when non-null.
        unsafe { *retptr = endptr };
    }
    ret
}

/// Body of `parse_option_str()`: is `option` one of the comma-separated
/// entries in `str`?
///
/// Not `EXPORT_SYMBOL` in the C and not exported here, but it is a global
/// symbol and stays one.
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn parse_option_str(str_: *const c_char, option: *const c_char) -> bool {
    let mut s = str_;
    // SAFETY: `option` is NUL-terminated.
    let optlen = unsafe { strlen(option) };

    // SAFETY: `s` is NUL-terminated and every advance below stops at the NUL.
    while unsafe { *s } != 0 {
        // SAFETY: strncmp stops at `optlen` or at either string's NUL.
        if unsafe { strncmp(s, option, optlen) } == 0 {
            // SAFETY: the prefix matched, so `optlen` characters are readable.
            s = unsafe { s.add(optlen) };
            // SAFETY: `s` still points inside the string, at worst at its NUL.
            let c = unsafe { *s } as u8;
            if c == 0 || c == b',' {
                return true;
            }
        }
        // SAFETY: as above.
        while unsafe { *s } != 0 && unsafe { *s } as u8 != b',' {
            // SAFETY: as above.
            s = unsafe { s.add(1) };
        }
        // SAFETY: as above.
        if unsafe { *s } as u8 == b',' {
            // SAFETY: as above.
            s = unsafe { s.add(1) };
        }
    }
    false
}

kernel::kabi_export! {
    next_arg,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } args , formal_parameter pointer_type { pointer_type { base_type char byte_size(1) encoding(8) } } param , formal_parameter pointer_type { pointer_type { base_type char byte_size(1) encoding(8) } } val ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}

/// Body of `next_arg()`: one `param=val` pair out of a command line,
/// terminated in place.
///
/// **`equals == 0` means "no `=` found", not "`=` at index 0".** The C uses
/// the index itself as the flag, so an argument that begins with `=` is
/// treated as having no value at all. That is upstream's behaviour, it is
/// reachable, and it is reproduced rather than tidied -- `logs/floor.md`,
/// "a port may NOT be safer than the C, yet".
///
/// # Safety
/// `args` must be a NUL-terminated, **writable** buffer -- this function
/// writes NULs into it -- and `param` and `val` must be writable. The
/// pointers written back are interior pointers into `args` and live as long
/// as it does.
#[no_mangle]
pub unsafe extern "C" fn next_arg(
    args: *mut c_char,
    param: *mut *mut c_char,
    val: *mut *mut c_char,
) -> *mut c_char {
    let mut args = args;
    let mut equals: usize = 0;
    let mut in_quote = false;
    let mut quoted = false;

    // SAFETY: `args` is NUL-terminated and readable.
    if unsafe { *args } as u8 == b'"' {
        // SAFETY: the first character is not the NUL, so one past it is
        // still inside the buffer.
        args = unsafe { args.add(1) };
        in_quote = true;
        quoted = true;
    }

    let mut i: usize = 0;
    loop {
        // SAFETY: the loop stops at the NUL, so `i` never passes it.
        let c = unsafe { *args.add(i) } as u8;
        if c == 0 {
            break;
        }
        if is_space(c as c_char) && !in_quote {
            break;
        }
        if equals == 0 && c == b'=' {
            equals = i;
        }
        if c == b'"' {
            in_quote = !in_quote;
        }
        i += 1;
    }

    // SAFETY: the caller guarantees `param` and `val` are writable.
    unsafe { *param = args };
    if equals == 0 {
        // SAFETY: as above.
        unsafe { *val = core::ptr::null_mut() };
    } else {
        // SAFETY: `equals < i` and every index below `i` is inside the
        // buffer; the buffer is writable by the caller's contract.
        unsafe {
            *args.add(equals) = 0;
            *val = args.add(equals + 1);

            // Don't include quotes in value.
            if **val as u8 == b'"' {
                *val = (*val).add(1);
                if *args.add(i - 1) as u8 == b'"' {
                    *args.add(i - 1) = 0;
                }
            }
        }
    }
    if quoted && i > 0 {
        // SAFETY: `i - 1` is inside the buffer.
        unsafe {
            if *args.add(i - 1) as u8 == b'"' {
                *args.add(i - 1) = 0;
            }
        }
    }

    // SAFETY: `i` indexes the terminator or the separator, both inside the
    // buffer; one past a non-NUL separator is still inside it.
    unsafe {
        if *args.add(i) != 0 {
            *args.add(i) = 0;
            args = args.add(i + 1);
        } else {
            args = args.add(i);
        }
        // Chew up trailing spaces.
        skip_spaces(args)
    }
}
