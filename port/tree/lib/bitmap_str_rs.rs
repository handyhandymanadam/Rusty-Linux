// SPDX-License-Identifier: GPL-2.0-only

//! Bitmap string parsing -- the Rust behind part of `lib/bitmap-str.c`.
//!
//! Ported from `lib/bitmap-str.c` (6.18.49): `bitmap_parselist()` ("0-3,8,16-31:4/8", "all", "N", the
//! `start-end:used/group` pattern) and `bitmap_parse()` (hex mask, 32-bit chunks, comma-separated, right to
//! left) with their helpers (`struct region`, `bitmap_getnum`, region scanning, `bitmap_get_x32_reverse`).
//! In C (`bitmap_str_glue.c`): the `_user` variants (`memdup_user_nul`), `bitmap_print_to_pagebuf` and the
//! `bitmap_print_*_to_buf` functions (`scnprintf`, `kasprintf`, `memory_read_from_buffer`).
//!
//! `_parse_integer`, `strncasecmp`, `strnchrnul`, `hex_to_bin` and `bitmap_set/clear` (`__bitmap_set/clear`, bitmap_rs.rs)
//! are the kernel's own, called through their C symbols; `isspace()` reads the `_ctype` table like the header does.
//! The 64-bit big-endian arm of `bitmap_parse` (`bitmap[chunk ^ 1]`) is not built here. Errors are the C's
//! (-EINVAL, -ERANGE, -EOVERFLOW as `ERR_PTR` inside the parser). The upstream test `lib/test_bitmap.c` (CONFIG_TEST_BITMAP)
//! exercises both functions at boot. Neither export has a guard, WARN or static key, so no C entry stays:
//! `kernel::kabi_export!` carries each export and its contract (C fingerprints taken from the C object before it was
//! removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: lib/bitmap-str.c (the parsers)

use core::ffi::{c_char, c_int, c_ulong, c_void};

#[cfg(target_endian = "big")]
compile_error!("bitmap_str_rs.rs: little-endian only (bitmap_parse's 64-bit big-endian arm is not ported)");

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const EOVERFLOW: c_int = 75;
const KSTRTOX_OVERFLOW: u32 = 1 << 31;
/// `_S` in `include/linux/ctype.h`.
const CTYPE_S: u8 = 0x20;

extern "C" {
    static _ctype: [u8; 256];
    fn _parse_integer(s: *const c_char, base: u32, p: *mut u64) -> u32;
    fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int;
    fn strnchrnul(s: *const c_char, count: usize, c: c_int) -> *mut c_char;
    fn hex_to_bin(ch: u8) -> c_int;
    fn __bitmap_set(map: *mut c_ulong, start: u32, len: c_int);
    fn __bitmap_clear(map: *mut c_ulong, start: u32, len: c_int);
    fn _find_next_bit(addr: *const c_ulong, nbits: c_ulong, start: c_ulong) -> c_ulong;
}

type Cp = *const c_char;

/// `ERR_PTR(err)`.
#[inline(always)]
fn err_ptr(e: c_int) -> Cp {
    e as isize as Cp
}

/// `IS_ERR(p)`: the last 4095 addresses.
#[inline(always)]
fn is_err(p: Cp) -> bool {
    (p as usize) >= (-4095isize) as usize
}

/// `PTR_ERR(p)`.
#[inline(always)]
fn ptr_err(p: Cp) -> c_int {
    p as isize as c_int
}

/// `struct region`.
struct Region {
    start: u32,
    off: u32,
    group_len: u32,
    end: u32,
    nbits: u32,
}

#[inline(always)]
unsafe fn ch(p: Cp) -> u8 {
    unsafe { *(p as *const u8) }
}

/// `isspace()`.
#[inline(always)]
fn isspace(c: u8) -> bool {
    (unsafe { _ctype[c as usize] }) & CTYPE_S != 0
}

/// `bitmap_set_region()`.
unsafe fn bitmap_set_region(r: &Region, bitmap: *mut c_ulong) {
    let mut start = r.start;
    while start <= r.end {
        let n = core::cmp::min(r.end.wrapping_sub(start).wrapping_add(1), r.off);
        unsafe { __bitmap_set(bitmap, start, n as c_int) };
        /* `unsigned int`: wraps like the C (a huge group_len can bring start back below end) */
        start = start.wrapping_add(r.group_len);
    }
}

/// `bitmap_check_region()`.
fn bitmap_check_region(r: &Region) -> c_int {
    if r.start > r.end || r.group_len == 0 || r.off > r.group_len {
        return -EINVAL;
    }

    if r.end >= r.nbits {
        return -ERANGE;
    }

    0
}

/// `bitmap_getnum()`: a decimal number or `N` (the last bit).
unsafe fn bitmap_getnum(str: Cp, num: &mut u32, lastbit: u32) -> Cp {
    let mut n: u64 = 0;

    if unsafe { ch(str) } == b'N' {
        *num = lastbit;
        return unsafe { str.add(1) };
    }

    let len = unsafe { _parse_integer(str, 10, &mut n) };
    if len == 0 {
        return err_ptr(-EINVAL);
    }
    if len & KSTRTOX_OVERFLOW != 0 || n != (n as u32) as u64 {
        return err_ptr(-EOVERFLOW);
    }

    *num = n as u32;
    unsafe { str.add(len as usize) }
}

#[inline(always)]
fn end_of_str(c: u8) -> bool {
    c == b'\0' || c == b'\n'
}

#[inline(always)]
fn __end_of_region(c: u8) -> bool {
    isspace(c) || c == b','
}

#[inline(always)]
fn end_of_region(c: u8) -> bool {
    __end_of_region(c) || end_of_str(c)
}

/// `bitmap_find_region()`: next region, or NULL at the end of the string.
unsafe fn bitmap_find_region(str: Cp) -> Cp {
    let mut str = str;
    while __end_of_region(unsafe { ch(str) }) {
        str = unsafe { str.add(1) };
    }

    if end_of_str(unsafe { ch(str) }) {
        core::ptr::null()
    } else {
        str
    }
}

/// `bitmap_find_region_reverse()`.
unsafe fn bitmap_find_region_reverse(start: Cp, end: Cp) -> Cp {
    let mut end = end;
    while start <= end && __end_of_region(unsafe { ch(end) }) {
        end = unsafe { end.sub(1) };
    }

    end
}

/// `bitmap_parse_region()`.
unsafe fn bitmap_parse_region(str: Cp, r: &mut Region) -> Cp {
    let lastbit = r.nbits.wrapping_sub(1);
    let mut str = str;

    'check_pattern: {
        if unsafe { strncasecmp(str, c"all".as_ptr(), 3) } == 0 {
            r.start = 0;
            r.end = lastbit;
            str = unsafe { str.add(3) };

            break 'check_pattern;
        }

        str = unsafe { bitmap_getnum(str, &mut r.start, lastbit) };
        if is_err(str) {
            return str;
        }

        if end_of_region(unsafe { ch(str) }) {
            /* no_end: */
            r.end = r.start;
            return unsafe { no_pattern(str, r) };
        }

        if unsafe { ch(str) } != b'-' {
            return err_ptr(-EINVAL);
        }

        str = unsafe { bitmap_getnum(str.add(1), &mut r.end, lastbit) };
        if is_err(str) {
            return str;
        }
    }

    /* check_pattern: */
    if end_of_region(unsafe { ch(str) }) {
        return unsafe { no_pattern(str, r) };
    }

    if unsafe { ch(str) } != b':' {
        return err_ptr(-EINVAL);
    }

    str = unsafe { bitmap_getnum(str.add(1), &mut r.off, lastbit) };
    if is_err(str) {
        return str;
    }

    if unsafe { ch(str) } != b'/' {
        return err_ptr(-EINVAL);
    }

    unsafe { bitmap_getnum(str.add(1), &mut r.group_len, lastbit) }
}

/// The C's `no_pattern:` label.
unsafe fn no_pattern(str: Cp, r: &mut Region) -> Cp {
    r.off = r.end.wrapping_add(1);
    r.group_len = r.end.wrapping_add(1);

    if end_of_str(unsafe { ch(str) }) {
        core::ptr::null()
    } else {
        str
    }
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):


kernel::kabi_export! {
    bitmap_parselist,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } buf , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } maskp , formal_parameter base_type int byte_size(4) encoding(5) nmaskbits ) -> base_type int byte_size(4) encoding(5)",
}
/// `bitmap_parselist()`: parse "0-3,8,16-31:4/8" style lists into `maskp` (`nmaskbits` bits). Returns 0 or -errno.
///
/// # Safety
/// `buf` a NUL-terminated string; `maskp` writable for `nmaskbits` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_parselist(buf: Cp, maskp: *mut c_ulong, nmaskbits: c_int) -> c_int {
    let mut buf = buf;
    let mut r = Region { start: 0, off: 0, group_len: 0, end: 0, nbits: nmaskbits as u32 };

    /* bitmap_zero() */
    unsafe { core::ptr::write_bytes(maskp, 0, ((r.nbits as u64 + 63) / 64) as usize) };

    while !buf.is_null() {
        buf = unsafe { bitmap_find_region(buf) };
        if buf.is_null() {
            return 0;
        }

        buf = unsafe { bitmap_parse_region(buf, &mut r) };
        if is_err(buf) {
            return ptr_err(buf);
        }

        let ret = bitmap_check_region(&r);
        if ret != 0 {
            return ret;
        }

        unsafe { bitmap_set_region(&r, maskp) };
    }

    0
}

/// `bitmap_get_x32_reverse()`: one 32-bit hex chunk ending at `end`, scanning left.
unsafe fn bitmap_get_x32_reverse(start: Cp, end: Cp, num: *mut u32) -> Cp {
    let mut ret: u32 = 0;
    let mut end = end;

    let mut i: u32 = 0;
    while i < 32 {
        let c = unsafe { hex_to_bin(ch(end)) };
        end = unsafe { end.sub(1) };
        if c < 0 {
            return err_ptr(-EINVAL);
        }

        ret |= (c as u32) << i;

        if start > end || __end_of_region(unsafe { ch(end) }) {
            unsafe { *num = ret };
            return end;
        }
        i += 4;
    }

    let c = unsafe { hex_to_bin(ch(end)) };
    end = unsafe { end.sub(1) };
    if c >= 0 {
        return err_ptr(-EOVERFLOW);
    }
    unsafe { *num = ret };
    end
}

kernel::kabi_export! {
    bitmap_parse,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } start , formal_parameter base_type unsigned int byte_size(4) encoding(7) buflen , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } maskp , formal_parameter base_type int byte_size(4) encoding(5) nmaskbits ) -> base_type int byte_size(4) encoding(5)",
}
/// `bitmap_parse()`: parse a comma-separated hex mask (32-bit chunks, most significant first). Returns 0 or -errno.
///
/// # Safety
/// `start` readable for `buflen` bytes or up to its NUL/newline; `maskp` writable for `nmaskbits` bits.
#[no_mangle]
pub unsafe extern "C" fn bitmap_parse(start: Cp, buflen: u32, maskp: *mut c_ulong, nmaskbits: c_int) -> c_int {
    let mut end: Cp = unsafe { strnchrnul(start, buflen as usize, b'\n' as c_int) as Cp }.wrapping_sub(1);
    let mut chunks: c_int = ((nmaskbits as u32).wrapping_add(31) / 32) as c_int;
    let bitmap = maskp as *mut u32;

    let mut chunk: c_int = 0;
    loop {
        end = unsafe { bitmap_find_region_reverse(start, end) };
        if start > end {
            break;
        }

        let had = chunks;
        chunks = chunks.wrapping_sub(1);
        if had == 0 {
            return -EOVERFLOW;
        }

        end = unsafe { bitmap_get_x32_reverse(start, end, bitmap.offset(chunk as isize)) };
        if is_err(end) {
            return ptr_err(end);
        }
        chunk += 1;
    }

    let unset_bit: c_int = ((((nmaskbits as u32).wrapping_add(31) / 32) as c_int).wrapping_sub(chunks)).wrapping_mul(32);
    if unset_bit < nmaskbits {
        unsafe { __bitmap_clear(maskp, unset_bit as u32, nmaskbits - unset_bit) };
        return 0;
    }

    if unsafe { _find_next_bit(maskp, unset_bit as c_ulong, nmaskbits as c_ulong) } != unset_bit as c_ulong {
        return -EOVERFLOW;
    }

    0
}

#[allow(dead_code)]
type Unused = *const c_void;
