// SPDX-License-Identifier: GPL-2.0

//! UTF-8 / UTF-16 / UTF-32 conversion -- the Rust behind part of `fs/nls/nls_base.c`.
//!
//! Ported from `fs/nls/nls_base.c` (6.18.49), "Native language support -- charsets
//! and unicode translations", by Gordon Chaffee 1996, 1997 (UTF-8 table from the
//! Unicode home page's FSS-UTF sample). Here: [`utf8_to_utf32`], [`utf32_to_utf8`],
//! [`utf8s_to_utf16s`] and [`utf16s_to_utf8s`]. In C (`nls_base_glue.c`): the
//! charset registry (`nls_lock`, `tables`, `__register_nls`, `load_nls`, ...).
//!
//! The four `EXPORT_SYMBOL`s and their MODVERSIONS contracts are carried here by
//! `kernel::kabi_export!`; none of the four has a guard, static key or bug-table
//! entry, so no C entry stays (`logs/c-entry-rule.md`). The contract texts are
//! the C definitions' gendwarfksyms output, taken before the C was removed
//! (CRCs 0x51b16d3a, 0xa92ed79d, 0xf8388831, 0xc6a1746d).
//!
//! Behaviour kept exactly, including the oddities: `utf32_to_utf8` returns 0
//! for a NULL output pointer before it validates `u`; its loop runs while
//! `maxout` is non-zero, so a NEGATIVE `maxout` is treated as "plenty"; the
//! 5- and 6-byte table rows exist but can never succeed (> UNICODE_MAX);
//! `utf8_to_utf32` reads the first byte with no length check (the caller's
//! duty). No message text is produced by this file.
//!
//! Replaces: fs/nls/nls_base.c (the conversion half; the registry stays C)

use core::ffi::c_int;

const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;
const EILSEQ: c_int = 84;

const UNICODE_MAX: u64 = 0x0010_ffff;
const PLANE_SIZE: u32 = 0x0001_0000;
const SURROGATE_MASK: u64 = 0xffff_f800;
const SURROGATE_PAIR: u64 = 0x0000_d800;
const SURROGATE_LOW: u64 = 0x0000_0400;
const SURROGATE_BITS: u64 = 0x0000_03ff;

/// `enum utf16_endian` (`include/linux/nls.h`).
const UTF16_LITTLE_ENDIAN: c_int = 1;
const UTF16_BIG_ENDIAN: c_int = 2;

/// `struct utf8_table`: cmask, cval, shift, lmask, lval.
struct Utf8Row {
    cmask: i32,
    cval: i32,
    shift: i32,
    lmask: u64,
    lval: u64,
}

/// The table's last row (`cmask == 0`) is the terminator and is not stored.
static UTF8_TABLE: [Utf8Row; 6] = [
    Utf8Row { cmask: 0x80, cval: 0x00, shift: 0 * 6, lmask: 0x7F, lval: 0 },
    Utf8Row { cmask: 0xE0, cval: 0xC0, shift: 6, lmask: 0x7FF, lval: 0x80 },
    Utf8Row { cmask: 0xF0, cval: 0xE0, shift: 2 * 6, lmask: 0xFFFF, lval: 0x800 },
    Utf8Row { cmask: 0xF8, cval: 0xF0, shift: 3 * 6, lmask: 0x1F_FFFF, lval: 0x10000 },
    Utf8Row { cmask: 0xFC, cval: 0xF8, shift: 4 * 6, lmask: 0x3FF_FFFF, lval: 0x20_0000 },
    Utf8Row { cmask: 0xFE, cval: 0xFC, shift: 5 * 6, lmask: 0x7FFF_FFFF, lval: 0x400_0000 },
];

kernel::kabi_export! {
    utf8_to_utf32,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { typedef_type u8 { typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) } } } } s , formal_parameter base_type int byte_size(4) encoding(5) inlen , formal_parameter pointer_type { typedef_type unicode_t { typedef_type u32 { typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) } } } } pu ) -> base_type int byte_size(4) encoding(5)",
}

/// Decode one UTF-8 sequence at `s` (at most `inlen` bytes) into `*pu`;
/// returns the sequence length or `-EILSEQ` / `-EOVERFLOW`.
///
/// # Safety
/// `s` must be readable for the sequence (first byte always; further bytes
/// only while `inlen` allows), and `pu` writable.
#[no_mangle]
pub unsafe extern "C" fn utf8_to_utf32(s: *const u8, inlen: c_int, pu: *mut u32) -> c_int {
    let mut s = s;
    let c0 = unsafe { *s } as i32;
    let mut l = c0 as u64;
    let mut nc: c_int = 0;

    for t in UTF8_TABLE.iter() {
        nc += 1;
        if (c0 & t.cmask) == t.cval {
            l &= t.lmask;
            if l < t.lval || l > UNICODE_MAX || (l & SURROGATE_MASK) == SURROGATE_PAIR {
                return -EILSEQ;
            }
            unsafe { *pu = l as u32 };
            return nc;
        }
        if inlen <= nc {
            return -EOVERFLOW;
        }

        s = unsafe { s.add(1) };
        let c = ((unsafe { *s } as u32 ^ 0x80) & 0xFF) as u64;
        if c & 0xC0 != 0 {
            return -EILSEQ;
        }

        l = (l << 6) | c;
    }
    -EILSEQ
}

kernel::kabi_export! {
    utf32_to_utf8,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter typedef_type unicode_t { typedef_type u32 { typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) } } } u , formal_parameter pointer_type { typedef_type u8 { typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) } } } s , formal_parameter base_type int byte_size(4) encoding(5) maxout ) -> base_type int byte_size(4) encoding(5)",
}

/// Encode code point `u` as UTF-8 at `s` (at most `maxout` bytes); returns the
/// byte count or `-EILSEQ` / `-EOVERFLOW`.
///
/// # Safety
/// `s` is NULL or writable for the encoded length (<= `maxout`, <= 4 bytes
/// for any value that can succeed).
#[no_mangle]
pub unsafe extern "C" fn utf32_to_utf8(u: u32, s: *mut u8, maxout: c_int) -> c_int {
    if s.is_null() {
        return 0;
    }

    let l = u as u64;
    if l > UNICODE_MAX || (l & SURROGATE_MASK) == SURROGATE_PAIR {
        return -EILSEQ;
    }

    let mut s = s;
    let mut maxout = maxout;
    let mut nc: c_int = 0;
    for t in UTF8_TABLE.iter() {
        if maxout == 0 {
            break;
        }
        nc += 1;
        if l <= t.lmask {
            let mut c = t.shift;
            unsafe { *s = (t.cval as u64 | (l >> c)) as u8 };
            while c > 0 {
                c -= 6;
                s = unsafe { s.add(1) };
                unsafe { *s = (0x80 | ((l >> c) & 0x3F)) as u8 };
            }
            return nc;
        }
        maxout = maxout.wrapping_sub(1);
    }
    -EOVERFLOW
}

/// `put_utf16()`: store `c` (truncated to 16 bits) in the requested byte order.
#[inline(always)]
unsafe fn put_utf16(s: *mut u16, c: u32, endian: c_int) {
    let c = c as u16;
    unsafe {
        *s = match endian {
            UTF16_LITTLE_ENDIAN => c.to_le(),
            UTF16_BIG_ENDIAN => c.to_be(),
            _ => c,
        }
    };
}

/// `get_utf16()`: load one 16-bit unit in the stated byte order.
#[inline(always)]
unsafe fn get_utf16(p: *const u16, endian: c_int) -> u64 {
    let c = unsafe { *p };
    (match endian {
        UTF16_LITTLE_ENDIAN => u16::from_le(c),
        UTF16_BIG_ENDIAN => u16::from_be(c),
        _ => c,
    }) as u64
}

kernel::kabi_export! {
    utf8s_to_utf16s,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { typedef_type u8 { typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) } } } } s , formal_parameter base_type int byte_size(4) encoding(5) inlen , formal_parameter enumeration_type utf16_endian { enumerator UTF16_HOST_ENDIAN = 0 , enumerator UTF16_LITTLE_ENDIAN = 1 , enumerator UTF16_BIG_ENDIAN = 2 } byte_size(4) endian , formal_parameter pointer_type { typedef_type wchar_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } pwcs , formal_parameter base_type int byte_size(4) encoding(5) maxout ) -> base_type int byte_size(4) encoding(5)",
}

/// Convert a NUL- or length-terminated UTF-8 string to UTF-16; returns the
/// number of 16-bit units written, or `-EINVAL` on a bad sequence.
///
/// # Safety
/// `s` readable for `inlen` bytes (or up to the NUL), `pwcs` writable for
/// `maxout` units.
#[no_mangle]
pub unsafe extern "C" fn utf8s_to_utf16s(
    s: *const u8,
    inlen: c_int,
    endian: c_int,
    pwcs: *mut u16,
    maxout: c_int,
) -> c_int {
    let mut s = s;
    let mut inlen = inlen;
    let mut maxout = maxout;
    let mut op = pwcs;

    while inlen > 0 && maxout > 0 && unsafe { *s } != 0 {
        if unsafe { *s } & 0x80 != 0 {
            let mut u: u32 = 0;
            let size = unsafe { utf8_to_utf32(s, inlen, &mut u) };
            if size < 0 {
                return -EINVAL;
            }
            s = unsafe { s.add(size as usize) };
            inlen -= size;

            if u >= PLANE_SIZE {
                if maxout < 2 {
                    break;
                }
                u -= PLANE_SIZE;
                unsafe {
                    put_utf16(op, (SURROGATE_PAIR as u32) | ((u >> 10) & SURROGATE_BITS as u32), endian);
                    op = op.add(1);
                    put_utf16(
                        op,
                        (SURROGATE_PAIR | SURROGATE_LOW) as u32 | (u & SURROGATE_BITS as u32),
                        endian,
                    );
                    op = op.add(1);
                }
                maxout -= 2;
            } else {
                unsafe {
                    put_utf16(op, u, endian);
                    op = op.add(1);
                }
                maxout -= 1;
            }
        } else {
            unsafe {
                put_utf16(op, *s as u32, endian);
                op = op.add(1);
                s = s.add(1);
            }
            inlen -= 1;
            maxout -= 1;
        }
    }
    (unsafe { op.offset_from(pwcs) }) as c_int
}

kernel::kabi_export! {
    utf16s_to_utf8s,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { typedef_type wchar_t { typedef_type u16 { typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) } } } } } pwcs , formal_parameter base_type int byte_size(4) encoding(5) inlen , formal_parameter enumeration_type utf16_endian { enumerator UTF16_HOST_ENDIAN = 0 , enumerator UTF16_LITTLE_ENDIAN = 1 , enumerator UTF16_BIG_ENDIAN = 2 } byte_size(4) endian , formal_parameter pointer_type { typedef_type u8 { typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) } } } s , formal_parameter base_type int byte_size(4) encoding(5) maxout ) -> base_type int byte_size(4) encoding(5)",
}

/// Convert UTF-16 to UTF-8; unpaired surrogates and unencodable units are
/// skipped; stops at a NUL unit, when input runs out, or when the next
/// character no longer fits. Returns bytes written.
///
/// # Safety
/// `pwcs` readable for `inlen` units, `s` writable for `maxout` bytes.
#[no_mangle]
pub unsafe extern "C" fn utf16s_to_utf8s(
    pwcs: *const u16,
    inlen: c_int,
    endian: c_int,
    s: *mut u8,
    maxout: c_int,
) -> c_int {
    let mut pwcs = pwcs;
    let mut inlen = inlen;
    let mut maxout = maxout;
    let mut op = s;

    while inlen > 0 && maxout > 0 {
        let mut u = unsafe { get_utf16(pwcs, endian) };
        if u == 0 {
            break;
        }
        pwcs = unsafe { pwcs.add(1) };
        inlen -= 1;
        if u > 0x7f {
            if (u & SURROGATE_MASK) == SURROGATE_PAIR {
                if u & SURROGATE_LOW != 0 {
                    /* Ignore character and move on */
                    continue;
                }
                if inlen <= 0 {
                    break;
                }
                let v = unsafe { get_utf16(pwcs, endian) };
                if (v & SURROGATE_MASK) != SURROGATE_PAIR || (v & SURROGATE_LOW) == 0 {
                    /* Ignore character and move on */
                    continue;
                }
                u = PLANE_SIZE as u64 + ((u & SURROGATE_BITS) << 10) + (v & SURROGATE_BITS);
                pwcs = unsafe { pwcs.add(1) };
                inlen -= 1;
            }
            let size = unsafe { utf32_to_utf8(u as u32, op, maxout) };
            if size < 0 {
                if size == -EILSEQ {
                    /* Ignore character and move on */
                    continue;
                }
                /*
                 * Stop filling the buffer with data once a character
                 * does not fit anymore.
                 */
                break;
            } else {
                op = unsafe { op.add(size as usize) };
                maxout -= size;
            }
        } else {
            unsafe { *op = u as u8 };
            op = unsafe { op.add(1) };
            maxout -= 1;
        }
    }
    (unsafe { op.offset_from(s) }) as c_int
}
