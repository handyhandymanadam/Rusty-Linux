// SPDX-License-Identifier: GPL-2.0-only

//! Mount-option style token parser -- the Rust behind part of `lib/parser.c`.
//!
//! Ported from `lib/parser.c` (6.18.49): `match_token()` (pattern tables like `"size=%d"`, `"name=%s"`,
//! `"mode=%o"`, `"%%"`, with an optional field width), the numeric extractors `match_int`, `match_uint`,
//! `match_u64`, `match_octal`, `match_hex`, `match_wildcard` (`*` and `?` globbing) and `match_strlcpy`. In C
//! (`parser_glue.c`): `match_strdup()` (`kmemdup_nul`). `match_one`, `match_number` and `match_u64int` are the C's
//! static helpers.
//!
//! The kernel's `strchr`, `strcmp`, `strncmp`, `strlen`, `simple_strtol/ul` and `kstrtoull/kstrtouint` are called through
//! their C symbols; `isdigit()` reads the `_ctype` table as the header does. Quirks kept: a `%<width>` of 2^32-1 or more
//! becomes an `int` (so `%4294967295s` means "no width"), a `%s` width is compared as `size_t` after sign extension.
//! None of the exports has a guard, WARN or static key, so no C entry stays: `kernel::kabi_export!` carries each export and
//! its contract (C fingerprints taken from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: lib/parser.c (all but match_strdup)

use core::ffi::{c_char, c_int, c_long, c_ulong};

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const NUMBER_BUF_LEN: usize = 24;
/// `MAX_OPT_ARGS` (`include/linux/parser.h`).
const MAX_OPT_ARGS: c_int = 3;
/// `_D` in `include/linux/ctype.h`.
const CTYPE_D: u8 = 0x04;

extern "C" {
    static _ctype: [u8; 256];
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    fn simple_strtol(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> c_long;
    fn simple_strtoul(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> c_ulong;
    fn kstrtoull(s: *const c_char, base: u32, res: *mut u64) -> c_int;
    fn kstrtouint(s: *const c_char, base: u32, res: *mut u32) -> c_int;
}

/// `substring_t`.
#[repr(C)]
pub struct Substring {
    from: *mut c_char,
    to: *mut c_char,
}

/// `struct match_token`.
#[repr(C)]
pub struct MatchToken {
    token: c_int,
    pattern: *const c_char,
}

#[inline(always)]
fn isdigit(c: c_char) -> bool {
    (unsafe { _ctype[c as u8 as usize] }) & CTYPE_D != 0
}

/// `match_one()`: does `s` match pattern `p`? Fills `args`.
unsafe fn match_one(s: *mut c_char, p: *const c_char, args: *mut Substring) -> c_int {
    let mut s = s;
    let mut p = p;
    let mut argc: c_int = 0;

    if p.is_null() {
        return 1;
    }

    loop {
        let mut len: c_int = -1;
        let meta = unsafe { strchr(p, b'%' as c_int) } as *const c_char;
        if meta.is_null() {
            return (unsafe { strcmp(p, s) } == 0) as c_int;
        }

        if unsafe { strncmp(p, s, meta.offset_from(p) as usize) } != 0 {
            return 0;
        }

        s = unsafe { s.offset(meta.offset_from(p)) };
        p = unsafe { meta.add(1) };

        if isdigit(unsafe { *p }) {
            let mut endp: *mut c_char = p as *mut c_char;
            len = unsafe { simple_strtoul(p, &mut endp, 10) } as c_int;
            p = endp;
        } else if unsafe { *p } == b'%' as c_char {
            let c = unsafe { *s };
            s = unsafe { s.add(1) };
            if c != b'%' as c_char {
                return 0;
            }
            p = unsafe { p.add(1) };
            continue;
        }

        if argc >= MAX_OPT_ARGS {
            return 0;
        }

        let arg = unsafe { &mut *args.add(argc as usize) };
        arg.from = s;
        let conv = unsafe { *p } as u8;
        p = unsafe { p.add(1) };
        match conv {
            b's' => {
                let str_len = unsafe { strlen(s) };

                if str_len == 0 {
                    return 0;
                }
                if len == -1 || (len as isize as usize) > str_len {
                    len = str_len as c_int;
                }
                arg.to = unsafe { s.offset(len as isize) };
            }
            b'd' | b'u' | b'o' | b'x' => {
                let mut to: *mut c_char = arg.to;
                unsafe {
                    match conv {
                        b'd' => {
                            simple_strtol(s, &mut to, 0);
                        }
                        b'u' => {
                            simple_strtoul(s, &mut to, 0);
                        }
                        b'o' => {
                            simple_strtoul(s, &mut to, 8);
                        }
                        _ => {
                            simple_strtoul(s, &mut to, 16);
                        }
                    }
                }
                arg.to = to;
                if arg.to == arg.from {
                    return 0;
                }
            }
            _ => return 0,
        }
        s = arg.to;
        argc += 1;
    }
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#match_token",
    "structure_type match_token { member base_type int byte_size(4) encoding(5) token data_member_location(0) , member pointer_type { const_type { base_type char byte_size(1) encoding(8) } } pattern data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#bool",
    "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#substring_t",
    "typedef_type substring_t { structure_type { member pointer_type { base_type char byte_size(1) encoding(8) } from data_member_location(0) , member pointer_type { base_type char byte_size(1) encoding(8) } to data_member_location(8) } byte_size(16) }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");

kernel::kabi_export! {
    match_token,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } s , formal_parameter pointer_type { const_type { s#match_token } } table , formal_parameter pointer_type { t#substring_t } args ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_token()`: index of the first pattern in `table` that `s` matches (the table ends with a NULL pattern).
///
/// # Safety
/// `s` a NUL-terminated string; `table` ends with a `pattern == NULL` entry; `args` has `MAX_OPT_ARGS` entries.
#[no_mangle]
pub unsafe extern "C" fn match_token(s: *mut c_char, table: *const MatchToken, args: *mut Substring) -> c_int {
    let mut p = table;

    while unsafe { match_one(s, (*p).pattern, args) } == 0 {
        p = unsafe { p.add(1) };
    }

    unsafe { (*p).token }
}

kernel::kabi_export! {
    match_strlcpy,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter pointer_type { const_type { t#substring_t } } src , formal_parameter t#size_t size ) -> t#size_t",
}
/// `match_strlcpy()`: copy a substring into `dest`, NUL-terminated and truncated to `size`; returns its full length.
///
/// # Safety
/// `dest` writable for `size` bytes; `src` a valid substring.
#[no_mangle]
pub unsafe extern "C" fn match_strlcpy(dest: *mut c_char, src: *const Substring, size: usize) -> usize {
    let ret = unsafe { ((*src).to as usize).wrapping_sub((*src).from as usize) };

    if size != 0 {
        let len = if ret >= size { size - 1 } else { ret };
        unsafe {
            core::ptr::copy_nonoverlapping((*src).from as *const c_char, dest, len);
            *dest.add(len) = 0;
        }
    }
    ret
}

/// `match_number()`.
unsafe fn match_number(s: *const Substring, result: *mut c_int, base: u32) -> c_int {
    let mut endp: *mut c_char = core::ptr::null_mut();
    let mut buf = [0 as c_char; NUMBER_BUF_LEN];

    if unsafe { match_strlcpy(buf.as_mut_ptr(), s, NUMBER_BUF_LEN) } >= NUMBER_BUF_LEN {
        return -ERANGE;
    }
    let mut ret = 0;
    let val = unsafe { simple_strtol(buf.as_ptr(), &mut endp, base) };
    if endp as *const c_char == buf.as_ptr() {
        ret = -EINVAL;
    } else if val < c_int::MIN as c_long || val > c_int::MAX as c_long {
        ret = -ERANGE;
    } else {
        unsafe { *result = val as c_int };
    }
    ret
}

/// `match_u64int()`.
unsafe fn match_u64int(s: *const Substring, result: *mut u64, base: u32) -> c_int {
    let mut buf = [0 as c_char; NUMBER_BUF_LEN];
    let mut val: u64 = 0;

    if unsafe { match_strlcpy(buf.as_mut_ptr(), s, NUMBER_BUF_LEN) } >= NUMBER_BUF_LEN {
        return -ERANGE;
    }
    let ret = unsafe { kstrtoull(buf.as_ptr(), base, &mut val) };
    if ret == 0 {
        unsafe { *result = val };
    }
    ret
}

kernel::kabi_export! {
    match_int,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#substring_t } s , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } result ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_int()`: signed number with C prefixes (0x, 0) from a substring.
///
/// # Safety
/// `s` a valid substring; `result` writable.
#[no_mangle]
pub unsafe extern "C" fn match_int(s: *const Substring, result: *mut c_int) -> c_int {
    unsafe { match_number(s, result, 0) }
}

kernel::kabi_export! {
    match_uint,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#substring_t } s , formal_parameter pointer_type { base_type unsigned int byte_size(4) encoding(7) } result ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_uint()`: unsigned decimal number from a substring.
///
/// # Safety
/// `s` a valid substring; `result` writable.
#[no_mangle]
pub unsafe extern "C" fn match_uint(s: *const Substring, result: *mut u32) -> c_int {
    let mut buf = [0 as c_char; NUMBER_BUF_LEN];

    if unsafe { match_strlcpy(buf.as_mut_ptr(), s, NUMBER_BUF_LEN) } >= NUMBER_BUF_LEN {
        return -ERANGE;
    }

    unsafe { kstrtouint(buf.as_ptr(), 10, result) }
}

kernel::kabi_export! {
    match_u64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#substring_t } s , formal_parameter pointer_type { t#u64 } result ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_u64()`: unsigned 64-bit number with C prefixes from a substring.
///
/// # Safety
/// `s` a valid substring; `result` writable.
#[no_mangle]
pub unsafe extern "C" fn match_u64(s: *const Substring, result: *mut u64) -> c_int {
    unsafe { match_u64int(s, result, 0) }
}

kernel::kabi_export! {
    match_octal,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#substring_t } s , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } result ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_octal()`.
///
/// # Safety
/// `s` a valid substring; `result` writable.
#[no_mangle]
pub unsafe extern "C" fn match_octal(s: *const Substring, result: *mut c_int) -> c_int {
    unsafe { match_number(s, result, 8) }
}

kernel::kabi_export! {
    match_hex,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { t#substring_t } s , formal_parameter pointer_type { base_type int byte_size(4) encoding(5) } result ) -> base_type int byte_size(4) encoding(5)",
}
/// `match_hex()`.
///
/// # Safety
/// `s` a valid substring; `result` writable.
#[no_mangle]
pub unsafe extern "C" fn match_hex(s: *const Substring, result: *mut c_int) -> c_int {
    unsafe { match_number(s, result, 16) }
}

kernel::kabi_export! {
    match_wildcard,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } pattern , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } str ) -> t#bool",
}
/// `match_wildcard()`: glob match with `*` (any run) and `?` (any one character).
///
/// # Safety
/// Both strings NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn match_wildcard(pattern: *const c_char, str: *const c_char) -> bool {
    let mut s = str;
    let mut p = pattern;
    let mut str = str;
    let mut pattern = pattern;
    let mut star = false;

    while unsafe { *s } != 0 {
        match unsafe { *p } as u8 {
            b'?' => {
                s = unsafe { s.add(1) };
                p = unsafe { p.add(1) };
            }
            b'*' => {
                star = true;
                str = s;
                p = unsafe { p.add(1) };
                if unsafe { *p } == 0 {
                    return true;
                }
                pattern = p;
            }
            _ => {
                if unsafe { *s != *p } {
                    if !star {
                        return false;
                    }
                    str = unsafe { str.add(1) };
                    s = str;
                    p = pattern;
                } else {
                    s = unsafe { s.add(1) };
                    p = unsafe { p.add(1) };
                }
            }
        }
    }

    if unsafe { *p } == b'*' as c_char {
        p = unsafe { p.add(1) };
    }
    (unsafe { *p }) == 0
}
