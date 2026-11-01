// SPDX-License-Identifier: GPL-2.0

//! UTF-8 comparison, case folding and hashing -- the Rust behind `fs/unicode/utf8-core.c`.
//!
//! Ported from `fs/unicode/utf8-core.c` (6.18.49): validating a string, comparing two strings after normalization (`utf8_strncmp`) or after case folding (`utf8_strncasecmp`,
//! `utf8_strncasecmp_folded`), producing the normalized or case-folded form into a buffer (`utf8_normalize`, `utf8_casefold`) and hashing the folded form (`utf8_casefold_hash`). Each
//! walks a `struct utf8cursor` byte by byte through `utf8ncursor()` / `utf8byte()` of `utf8_norm_rs.rs`. In C (`utf8-core_glue.c`): the exported symbols as thunks that unpack `struct
//! qstr` (the MODVERSIONS fingerprint comes from the DWARF of the C definition), `utf8_load` / `utf8_unload` (module symbol request, allocation) and `utf8_parse_version`
//! (`match_token`), plus a wrapper for `end_name_hash()`.
//!
//! Replaces: fs/unicode/utf8-core.c (the comparison, folding and hashing functions)

use core::ffi::{c_int, c_void};

const EINVAL: c_int = 22;

/// `enum utf8_normalization`.
const UTF8_NFDI: c_int = 0;
const UTF8_NFDICF: c_int = 1;

/// `sizeof(struct utf8cursor)`, kept as an 8-byte-aligned buffer (checked by `utf8_norm_glue.c`).
#[repr(C, align(8))]
struct Cursor([u8; 72]);

extern "C" {
    fn utf8nlen(um: *const c_void, n: c_int, s: *const u8, len: usize) -> isize;
    fn utf8ncursor(u8c: *mut Cursor, um: *const c_void, n: c_int, s: *const u8, len: usize) -> c_int;
    fn utf8byte(u8c: *mut Cursor) -> c_int;
    /// `end_name_hash(hash)`
    fn rust_u8c_end_name_hash(hash: usize) -> u32;
}

impl Cursor {
    fn new() -> Cursor {
        Cursor([0; 72])
    }
}

/// `utf8_validate()`.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_validate(um: *const c_void, name: *const u8, len: u32) -> c_int {
    unsafe {
        if utf8nlen(um, UTF8_NFDI, name, len as usize) < 0 {
            return -1;
        }
        0
    }
}

/// The comparison loop of `utf8_strncmp()` / `utf8_strncasecmp()`.
unsafe fn compare(um: *const c_void, n: c_int, name1: *const u8, len1: u32, name2: *const u8, len2: u32) -> c_int {
    unsafe {
        let mut cur1 = Cursor::new();
        let mut cur2 = Cursor::new();

        if utf8ncursor(&mut cur1, um, n, name1, len1 as usize) < 0 {
            return -EINVAL;
        }

        if utf8ncursor(&mut cur2, um, n, name2, len2 as usize) < 0 {
            return -EINVAL;
        }

        loop {
            let c1 = utf8byte(&mut cur1);
            let c2 = utf8byte(&mut cur2);

            if c1 < 0 || c2 < 0 {
                return -EINVAL;
            }
            if c1 != c2 {
                return 1;
            }
            if c1 == 0 {
                break;
            }
        }

        0
    }
}

/// `utf8_strncmp()`.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_strncmp(um: *const c_void, name1: *const u8, len1: u32, name2: *const u8, len2: u32) -> c_int {
    unsafe { compare(um, UTF8_NFDI, name1, len1, name2, len2) }
}

/// `utf8_strncasecmp()`.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_strncasecmp(um: *const c_void, name1: *const u8, len1: u32, name2: *const u8, len2: u32) -> c_int {
    unsafe { compare(um, UTF8_NFDICF, name1, len1, name2, len2) }
}

/// `utf8_strncasecmp_folded()`: `cf` is expected to be a valid UTF-8 casefolded string.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_strncasecmp_folded(um: *const c_void, cf: *const u8, name: *const u8, len: u32) -> c_int {
    unsafe {
        let mut cur1 = Cursor::new();
        let mut i = 0usize;

        if utf8ncursor(&mut cur1, um, UTF8_NFDICF, name, len as usize) < 0 {
            return -EINVAL;
        }

        loop {
            let c1 = utf8byte(&mut cur1);
            let c2 = *cf.add(i) as c_int;
            i += 1;
            if c1 < 0 {
                return -EINVAL;
            }
            if c1 != c2 {
                return 1;
            }
            if c1 == 0 {
                break;
            }
        }

        0
    }
}

/// The copy loop of `utf8_casefold()` / `utf8_normalize()`: the normalized (`n`) string with its terminating NUL into `dest`, its length, or -EINVAL.
unsafe fn emit(um: *const c_void, n: c_int, name: *const u8, len: u32, dest: *mut u8, dlen: usize) -> c_int {
    unsafe {
        let mut cur = Cursor::new();

        if utf8ncursor(&mut cur, um, n, name, len as usize) < 0 {
            return -EINVAL;
        }

        let mut nlen = 0usize;
        while nlen < dlen {
            let c = utf8byte(&mut cur);

            *dest.add(nlen) = c as u8;
            if c == 0 {
                return nlen as c_int;
            }
            if c == -1 {
                break;
            }
            nlen += 1;
        }
        -EINVAL
    }
}

/// `utf8_casefold()`.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_casefold(um: *const c_void, name: *const u8, len: u32, dest: *mut u8, dlen: usize) -> c_int {
    unsafe { emit(um, UTF8_NFDICF, name, len, dest, dlen) }
}

/// `utf8_normalize()`.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_normalize(um: *const c_void, name: *const u8, len: u32, dest: *mut u8, dlen: usize) -> c_int {
    unsafe { emit(um, UTF8_NFDI, name, len, dest, dlen) }
}

/// `utf8_casefold_hash()`: the name hash of the case-folded string, stored through `*hash` on success.
#[no_mangle]
pub unsafe extern "C" fn rust_utf8_casefold_hash(um: *const c_void, salt: *const c_void, name: *const u8, len: u32, hash: *mut u32) -> c_int {
    unsafe {
        let mut cur = Cursor::new();
        // init_name_hash(salt)
        let mut h: usize = salt as usize;

        if utf8ncursor(&mut cur, um, UTF8_NFDICF, name, len as usize) < 0 {
            return -EINVAL;
        }

        loop {
            let c = utf8byte(&mut cur);
            if c == 0 {
                break;
            }
            if c < 0 {
                return -EINVAL;
            }
            // partial_name_hash((unsigned char)c, hash)
            let ch = c as u8 as usize;
            h = h.wrapping_add(ch << 4).wrapping_add(ch >> 4).wrapping_mul(11);
        }
        *hash = rust_u8c_end_name_hash(h);
        0
    }
}
