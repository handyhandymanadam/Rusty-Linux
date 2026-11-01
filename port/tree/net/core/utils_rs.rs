// SPDX-License-Identifier: GPL-2.0-or-later

//! IPv4 / IPv6 address literal parsing -- the Rust behind part of `net/core/utils.c`.
//!
//! Ported from `net/core/utils.c` (6.18.49): `in_aton()`, `in4_pton()`, `in6_pton()` and the helper
//! `xdigit2bin()` with its `IN6PTON_*` state bits. In C (`utils_glue.c`): the net rate limiter,
//! `inet_pton_with_scope()` (device lookups), `inet_addr_is_any()` and the checksum-replace helpers
//! that read `sk_buff`.
//!
//! `in6_pton()` is a byte-at-a-time state machine over a 16-byte scratch buffer; the C's pointer
//! arithmetic on `d`, `dc` and `dbuf` is index arithmetic here. One quirk is kept on purpose: when a
//! dotted-quad tail is met before any colon (`tok` is NULL) the C still computes
//! `srclen + (int)(s - tok)`, a pointer minus NULL truncated to `int`; here the same value is
//! computed with wrapping arithmetic (`in4_pton()` then fails on the leading '.' either way).
//! `hex_to_bin()` stays the kernel's (`lib/hexdump.c`). Neither export has a guard, WARN or static
//! key, so no C entry stays: `kernel::kabi_export!` carries each export and its contract (C
//! fingerprints 0xaf56058e, 0x18d79f80, 0x18d79f80, from the C object before it was removed,
//! `rig/kabi-symtypes.sh`).
//!
//! Replaces: net/core/utils.c (the address-parsing half)

use core::ffi::{c_char, c_int};

extern "C" {
    fn hex_to_bin(ch: u8) -> c_int;
}

const IN6PTON_XDIGIT: c_int = 0x0001_0000;
const IN6PTON_DIGIT: c_int = 0x0002_0000;
const IN6PTON_COLON_MASK: c_int = 0x0070_0000;
const IN6PTON_COLON_1: c_int = 0x0010_0000; /* single : requested */
const IN6PTON_COLON_2: c_int = 0x0020_0000; /* second : requested */
const IN6PTON_COLON_1_2: c_int = 0x0040_0000; /* :: requested */
const IN6PTON_DOT: c_int = 0x0080_0000; /* . */
const IN6PTON_DELIM: c_int = 0x1000_0000;
const IN6PTON_NULL: c_int = 0x2000_0000; /* first/tail */
const IN6PTON_UNKNOWN: c_int = 0x4000_0000;

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "t#__be32",
    "typedef_type __be32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#__u8",
    "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8",
    "typedef_type u8 { t#__u8 }");

kernel::kabi_export! {
    in_aton,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } str ) -> t#__be32",
}

/// `in_aton()`: convert an ASCII dotted quad to a big-endian address (no validation).
///
/// # Safety
/// `str` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn in_aton(str: *const c_char) -> u32 {
    let mut s = str as *const u8;
    let mut l: u32 = 0;

    for _ in 0..4 {
        l <<= 8;
        if unsafe { *s } != b'\0' {
            let mut val: u32 = 0;
            while unsafe { *s } != b'\0' && unsafe { *s } != b'.' && unsafe { *s } != b'\n' {
                val = val.wrapping_mul(10);
                val = val.wrapping_add((unsafe { *s } as i8 as i32).wrapping_sub(b'0' as i32) as u32);
                s = unsafe { s.add(1) };
            }
            l |= val;
            if unsafe { *s } != b'\0' {
                s = unsafe { s.add(1) };
            }
        }
    }
    l.to_be()
}

/// `xdigit2bin()`.
#[inline(always)]
fn xdigit2bin(c: u8, delim: c_int) -> c_int {
    if c as i8 as c_int == delim || c == b'\0' {
        return IN6PTON_DELIM;
    }
    if c == b':' {
        return IN6PTON_COLON_MASK;
    }
    if c == b'.' {
        return IN6PTON_DOT;
    }

    let val = unsafe { hex_to_bin(c) };
    if val >= 0 {
        return val | IN6PTON_XDIGIT | if val < 10 { IN6PTON_DIGIT } else { 0 };
    }

    if delim == -1 {
        return IN6PTON_DELIM;
    }
    IN6PTON_UNKNOWN
}

/// `strlen()` for a NUL-terminated string.
unsafe fn strlen(s: *const u8) -> c_int {
    let mut n: usize = 0;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n as c_int
}

kernel::kabi_export! {
    in4_pton,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src , formal_parameter base_type int byte_size(4) encoding(5) srclen , formal_parameter pointer_type { t#u8 } dst , formal_parameter base_type int byte_size(4) encoding(5) delim , formal_parameter pointer_type { pointer_type { const_type { base_type char byte_size(1) encoding(8) } } } end ) -> base_type int byte_size(4) encoding(5)",
}

/// `in4_pton()`: convert an IPv4 literal to 4 bytes. Returns 1 on success, 0 on any error; `*end`
/// (if not NULL) points at the end of the parsed text.
///
/// # Safety
/// `src` readable for `srclen` bytes (or up to its NUL when `srclen < 0`), `dst` writable for 4
/// bytes, `end` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn in4_pton(
    src: *const c_char,
    srclen: c_int,
    dst: *mut u8,
    delim: c_int,
    end: *mut *const c_char,
) -> c_int {
    let mut srclen = srclen;
    let mut dbuf = [0u8; 4];
    let mut ret: c_int = 0;
    let mut w: c_int = 0;

    if srclen < 0 {
        srclen = unsafe { strlen(src as *const u8) };
    }
    let mut s = src as *const u8;
    let mut d: usize = 0;
    let mut i: c_int = 0;
    'out: {
        loop {
            let c = xdigit2bin(if srclen > 0 { unsafe { *s } } else { b'\0' }, delim);
            if c & (IN6PTON_DIGIT | IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK) == 0 {
                break 'out;
            }
            if c & (IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK) != 0 {
                if w == 0 {
                    break 'out;
                }
                dbuf[d] = (w & 0xff) as u8;
                d += 1;
                w = 0;
                i += 1;
                if c & (IN6PTON_DELIM | IN6PTON_COLON_MASK) != 0 {
                    if i != 4 {
                        break 'out;
                    }
                    break;
                }
            } else {
                w = w.wrapping_mul(10).wrapping_add(c);
                if (w & 0xffff) > 255 {
                    break 'out;
                }
            }
            /* cont: */
            if i >= 4 {
                break 'out;
            }
            s = unsafe { s.add(1) };
            srclen -= 1;
        }
        ret = 1;
        unsafe { core::ptr::copy_nonoverlapping(dbuf.as_ptr(), dst, 4) };
    }
    if !end.is_null() {
        unsafe { *end = s as *const c_char };
    }
    ret
}

kernel::kabi_export! {
    in6_pton,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src , formal_parameter base_type int byte_size(4) encoding(5) srclen , formal_parameter pointer_type { t#u8 } dst , formal_parameter base_type int byte_size(4) encoding(5) delim , formal_parameter pointer_type { pointer_type { const_type { base_type char byte_size(1) encoding(8) } } } end ) -> base_type int byte_size(4) encoding(5)",
}

/// `in6_pton()`: convert an IPv6 literal to 16 bytes. Returns 1 on success, 0 on any error; `*end`
/// (if not NULL) points at the end of the parsed text.
///
/// # Safety
/// `src` readable for `srclen` bytes (or up to its NUL when `srclen < 0`), `dst` writable for 16
/// bytes, `end` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn in6_pton(
    src: *const c_char,
    srclen: c_int,
    dst: *mut u8,
    delim: c_int,
    end: *mut *const c_char,
) -> c_int {
    let mut tok: *const u8 = core::ptr::null();
    let mut dc: Option<isize> = None;
    let mut dbuf = [0u8; 16];
    let mut ret: c_int = 0;
    let mut state: c_int = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT | IN6PTON_NULL;
    let mut w: c_int = 0;
    let mut srclen = srclen;

    let mut s = src as *const u8;
    let mut d: isize = 0;
    if srclen < 0 {
        srclen = unsafe { strlen(s) };
    }

    'out: {
        loop {
            let c = xdigit2bin(if srclen > 0 { unsafe { *s } } else { b'\0' }, delim);
            if c & state == 0 {
                break 'out;
            }
            let mut skip_to_cont = false;
            if c & (IN6PTON_DELIM | IN6PTON_COLON_MASK) != 0 {
                /* process one 16-bit word */
                if state & IN6PTON_NULL == 0 {
                    dbuf[d as usize] = ((w >> 8) & 0xff) as u8;
                    d += 1;
                    dbuf[d as usize] = (w & 0xff) as u8;
                    d += 1;
                }
                w = 0;
                if c & IN6PTON_DELIM != 0 {
                    /* We've processed last word */
                    break;
                }
                /*
                 * COLON_1 => XDIGIT
                 * COLON_2 => XDIGIT|DELIM
                 * COLON_1_2 => COLON_2
                 */
                match state & IN6PTON_COLON_MASK {
                    IN6PTON_COLON_2 => {
                        dc = Some(d);
                        state = IN6PTON_XDIGIT | IN6PTON_DELIM;
                        if d >= 16 {
                            state |= IN6PTON_NULL;
                        }
                    }
                    x if x == (IN6PTON_COLON_1 | IN6PTON_COLON_1_2) => {
                        state = IN6PTON_XDIGIT | IN6PTON_COLON_2;
                    }
                    IN6PTON_COLON_1 => {
                        state = IN6PTON_XDIGIT;
                    }
                    IN6PTON_COLON_1_2 => {
                        state = IN6PTON_COLON_2;
                    }
                    _ => {
                        state = 0;
                    }
                }
                tok = unsafe { s.add(1) };
                skip_to_cont = true;
            }

            if !skip_to_cont {
                if c & IN6PTON_DOT != 0 {
                    let from = if tok.is_null() { s } else { tok };
                    let adj = srclen.wrapping_add((s as isize).wrapping_sub(tok as isize) as c_int);
                    let mut s2: *const c_char = s as *const c_char;
                    ret = unsafe {
                        in4_pton(from as *const c_char, adj, dbuf.as_mut_ptr().offset(d), delim, &mut s2)
                    };
                    s = s2 as *const u8;
                    if ret > 0 {
                        d += 4;
                        break;
                    }
                    break 'out;
                }

                w = (w << 4) | (0xff & c);
                state = IN6PTON_COLON_1 | IN6PTON_DELIM;
                if w & 0xf000 == 0 {
                    state |= IN6PTON_XDIGIT;
                }
                if dc.is_none() && d + 2 < 16 {
                    state |= IN6PTON_COLON_1_2;
                    state &= !IN6PTON_DELIM;
                }
                if d + 2 >= 16 {
                    state &= !(IN6PTON_COLON_1 | IN6PTON_COLON_1_2);
                }
            }
            /* cont: */
            if (dc.is_some() && d + 4 < 16) || d + 4 == 16 {
                state |= IN6PTON_DOT;
            }
            if d >= 16 {
                state &= !(IN6PTON_XDIGIT | IN6PTON_COLON_MASK);
            }
            s = unsafe { s.add(1) };
            srclen -= 1;
        }

        let mut i: isize = 15;
        d -= 1;
        let rd = |idx: isize| -> u8 { if (0..16).contains(&idx) { dbuf[idx as usize] } else { 0 } };

        if let Some(dc) = dc {
            while d >= dc {
                unsafe { *dst.offset(i) = rd(d) };
                i -= 1;
                d -= 1;
            }
            while i >= dc {
                unsafe { *dst.offset(i) = 0 };
                i -= 1;
            }
            while i >= 0 {
                unsafe { *dst.offset(i) = rd(d) };
                i -= 1;
                d -= 1;
            }
        } else {
            unsafe { core::ptr::copy_nonoverlapping(dbuf.as_ptr(), dst, 16) };
        }

        ret = 1;
    }
    if !end.is_null() {
        unsafe { *end = s as *const c_char };
    }
    ret
}
