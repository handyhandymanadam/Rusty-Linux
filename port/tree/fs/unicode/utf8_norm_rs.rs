// SPDX-License-Identifier: GPL-2.0-only

//! UTF-8 normalization -- the Rust behind `fs/unicode/utf8-norm.c`.
//!
//! Ported from `fs/unicode/utf8-norm.c` (6.18.49, SGI): walking the packed normalization tries (`utf8nlookup`), the algorithmic Hangul decomposition (`utf8hangul`), the length of a
//! normalized string (`utf8nlen`), and the byte-at-a-time cursor that emits a normalized (NFD, optionally case-folded) string with canonical reordering (`utf8ncursor`, `utf8byte`),
//! plus `utf8version_is_supported`. The whole file is here; `utf8_norm_glue.c` only checks the structure layouts this code hard-codes and keeps upstream's `EXPORT_SYMBOL_GPL`
//! block for the KUnit-as-module configuration.
//!
//! Replaces: fs/unicode/utf8-norm.c

use core::ffi::{c_char, c_int};
use core::ptr::null;

/// `struct utf8data` (checked by the glue).
#[repr(C)]
pub struct Utf8Data {
    maxage: u32,
    offset: u32,
}

/// `struct utf8data_table`.
#[repr(C)]
pub struct Utf8DataTable {
    utf8agetab: *const u32,
    utf8agetab_size: c_int,
    utf8nfdicfdata: *const Utf8Data,
    utf8nfdicfdata_size: c_int,
    utf8nfdidata: *const Utf8Data,
    utf8nfdidata_size: c_int,
    utf8data: *const u8,
}

/// `struct unicode_map`.
#[repr(C)]
pub struct UnicodeMap {
    version: u32,
    ntab: [*const Utf8Data; 2],
    tables: *const Utf8DataTable,
}

/// `struct utf8cursor`.
#[repr(C)]
pub struct Utf8Cursor {
    um: *const UnicodeMap,
    n: c_int,
    s: *const u8,
    p: *const u8,
    ss: *const u8,
    sp: *const u8,
    len: u32,
    slen: u32,
    ccc: i16,
    nccc: i16,
    hangul: [u8; UTF8HANGULLEAF],
}

const UTF8HANGULLEAF: usize = 12;

const BITNUM: u8 = 0x07;
const NEXTBYTE: u8 = 0x08;
const OFFLEN: u8 = 0x30;
const OFFLEN_SHIFT: u8 = 4;
const RIGHTPATH: u8 = 0x40;
const TRIENODE: u8 = 0x80;
const RIGHTNODE: u8 = 0x40;
const LEFTNODE: u8 = 0x80;

const MINCCC: i16 = 0;
const MAXCCC: i16 = 254;
const STOPPER: i16 = 0;
const DECOMPOSE: i16 = 255;

const HANGUL: u8 = 255;

const SB: u32 = 0xAC00;
const LB: u32 = 0x1100;
const VB: u32 = 0x1161;
const TB: u32 = 0x11A7;
const VC: u32 = 21;
const TC: u32 = 28;
const NC: u32 = VC * TC;

/// `utf8version_is_supported()`.
#[no_mangle]
pub unsafe extern "C" fn utf8version_is_supported(um: *const UnicodeMap, version: u32) -> c_int {
    unsafe {
        let t = (*um).tables;
        let mut i = (*t).utf8agetab_size - 1;

        while i >= 0 && *(*t).utf8agetab.add(i as usize) != 0 {
            if version == *(*t).utf8agetab.add(i as usize) {
                return 1;
            }
            i -= 1;
        }
        0
    }
}

/// `utf8clen()`.
unsafe fn utf8clen(s: *const u8) -> usize {
    unsafe {
        let c = *s;
        1 + (c >= 0xC0) as usize + (c >= 0xE0) as usize + (c >= 0xF0) as usize
    }
}

/// `utf8decode3()`.
unsafe fn utf8decode3(str: *const u8) -> u32 {
    unsafe {
        let mut uc = (*str & 0x0F) as u32;
        uc <<= 6;
        uc |= (*str.add(1) & 0x3F) as u32;
        uc <<= 6;
        uc |= (*str.add(2) & 0x3F) as u32;
        uc
    }
}

/// `utf8encode3()`.
unsafe fn utf8encode3(str: *mut u8, mut val: u32) -> usize {
    unsafe {
        *str.add(2) = ((val & 0x3F) | 0x80) as u8;
        val >>= 6;
        *str.add(1) = ((val & 0x3F) | 0x80) as u8;
        val >>= 6;
        *str = (val | 0xE0) as u8;
        3
    }
}

/// `utf8hangul()`: decompose the Hangul syllable at `str` into `hangul` and return that leaf.
unsafe fn utf8hangul(str: *const u8, hangul: *mut u8) -> *const u8 {
    unsafe {
        // Calculate the SI, LI, VI, and TI values.
        let si = utf8decode3(str).wrapping_sub(SB);
        let li = si / NC;
        let vi = (si % NC) / TC;
        let ti = si % TC;

        // Fill in base of leaf.
        let mut h = hangul;
        *h = 2;
        *h.add(1) = DECOMPOSE as u8;
        h = h.add(2);

        // Add LPart, a 3-byte UTF-8 sequence.
        h = h.add(utf8encode3(h, li.wrapping_add(LB)));

        // Add VPart, a 3-byte UTF-8 sequence.
        h = h.add(utf8encode3(h, vi.wrapping_add(VB)));

        // Add TPart if required, also a 3-byte UTF-8 sequence.
        if ti != 0 {
            h = h.add(utf8encode3(h, ti.wrapping_add(TB)));
        }

        // Terminate string.
        *h = 0;

        hangul
    }
}

/// `utf8nlookup()`: the leaf of the normalization trie for the character at `s`, or null.
unsafe fn utf8nlookup(um: *const UnicodeMap, n: c_int, hangul: *mut u8, mut s: *const u8, mut len: usize) -> *const u8 {
    unsafe {
        let mut trie = (*(*um).tables).utf8data.add((*(*um).ntab[n as usize]).offset as usize);

        if len == 0 {
            return null();
        }

        let mut node = 1;
        while node != 0 {
            let mut offlen = ((*trie & OFFLEN) >> OFFLEN_SHIFT) as i32;
            if *trie & NEXTBYTE != 0 {
                len = len.wrapping_sub(1);
                if len == 0 {
                    return null();
                }
                s = s.add(1);
            }
            let mask = 1u8 << (*trie & BITNUM);
            if *s & mask != 0 {
                // Right leg
                if offlen != 0 {
                    // Right node at offset of trie
                    node = (*trie & RIGHTNODE) as i32;
                    let mut offset = *trie.add(offlen as usize) as i32;
                    offlen -= 1;
                    while offlen != 0 {
                        offset <<= 8;
                        offset |= *trie.add(offlen as usize) as i32;
                        offlen -= 1;
                    }
                    trie = trie.offset(offset as isize);
                } else if *trie & RIGHTPATH != 0 {
                    // Right node after this node
                    node = (*trie & TRIENODE) as i32;
                    trie = trie.add(1);
                } else {
                    // No right node.
                    return null();
                }
            } else {
                // Left leg
                if offlen != 0 {
                    // Left node after this node.
                    node = (*trie & LEFTNODE) as i32;
                    trie = trie.add(offlen as usize + 1);
                } else if *trie & RIGHTPATH != 0 {
                    // No left node.
                    return null();
                } else {
                    // Left node after this node
                    node = (*trie & TRIENODE) as i32;
                    trie = trie.add(1);
                }
            }
        }
        // Hangul decomposition is done algorithmically. These are the codepoints >= 0xAC00 and <= 0xD7A3. Their UTF-8 encoding is always 3 bytes long, so s has been advanced
        // twice, and the start of the sequence is at s-2.
        if *trie.add(1) as i16 == DECOMPOSE && *trie.add(2) == HANGUL {
            trie = utf8hangul(s.sub(2), hangul);
        }
        trie
    }
}

/// `utf8lookup()`.
unsafe fn utf8lookup(um: *const UnicodeMap, n: c_int, hangul: *mut u8, s: *const u8) -> *const u8 {
    unsafe { utf8nlookup(um, n, hangul, s, usize::MAX) }
}

/// `strlen(LEAF_STR(leaf))`.
unsafe fn leaf_strlen(leaf: *const u8) -> usize {
    unsafe {
        let mut n = 0;
        while *leaf.add(2 + n) != 0 {
            n += 1;
        }
        n
    }
}

/// `utf8nlen()`.
#[no_mangle]
pub unsafe extern "C" fn utf8nlen(um: *const UnicodeMap, n: c_int, s: *const c_char, mut len: usize) -> isize {
    unsafe {
        let mut s = s as *const u8;
        let mut ret: usize = 0;
        let mut hangul = [0u8; UTF8HANGULLEAF];
        let t = (*um).tables;

        while len != 0 && *s != 0 {
            let leaf = utf8nlookup(um, n, hangul.as_mut_ptr(), s, len);
            if leaf.is_null() {
                return -1;
            }
            if *(*t).utf8agetab.add(*leaf as usize) > (*(*um).ntab[n as usize]).maxage {
                ret = ret.wrapping_add(utf8clen(s));
            } else if *leaf.add(1) as i16 == DECOMPOSE {
                ret = ret.wrapping_add(leaf_strlen(leaf));
            } else {
                ret = ret.wrapping_add(utf8clen(s));
            }
            let c = utf8clen(s);
            len = len.wrapping_sub(c);
            s = s.add(c);
        }
        ret as isize
    }
}

/// `utf8ncursor()`.
#[no_mangle]
pub unsafe extern "C" fn utf8ncursor(u8c: *mut Utf8Cursor, um: *const UnicodeMap, n: c_int, s: *const c_char, len: usize) -> c_int {
    unsafe {
        if s.is_null() {
            return -1;
        }
        (*u8c).um = um;
        (*u8c).n = n;
        (*u8c).s = s as *const u8;
        (*u8c).p = null();
        (*u8c).ss = null();
        (*u8c).sp = null();
        (*u8c).len = len as u32;
        (*u8c).slen = 0;
        (*u8c).ccc = STOPPER;
        (*u8c).nccc = STOPPER;
        // Check we didn't clobber the maximum length.
        if (*u8c).len as usize != len {
            return -1;
        }
        // The first byte of s may not be an utf8 continuation.
        if len > 0 && (*(s as *const u8) & 0xC0) == 0x80 {
            return -1;
        }
        0
    }
}

/// `utf8byte()`: the next byte of the normalized string, 0 at its end, -1 for a binary blob.
#[no_mangle]
pub unsafe extern "C" fn utf8byte(u8c: *mut Utf8Cursor) -> c_int {
    unsafe {
        let c = &mut *u8c;
        let mut ccc: i16;

        'outer: loop {
            // Check for the end of a decomposed character.
            if !c.p.is_null() && *c.s == 0 {
                c.s = c.p;
                c.p = null();
            }

            'mismatch: {
                // Check for end-of-string.
                if c.p.is_null() && (c.len == 0 || *c.s == 0) {
                    // There is no next byte.
                    if c.ccc == STOPPER {
                        return 0;
                    }
                    // End-of-string during a scan counts as a stopper.
                    ccc = STOPPER;
                    break 'mismatch;
                } else if (*c.s & 0xC0) == 0x80 {
                    // This is a continuation of the current character.
                    if c.p.is_null() {
                        c.len = c.len.wrapping_sub(1);
                    }
                    let b = *c.s;
                    c.s = c.s.add(1);
                    return b as c_int;
                }

                // Look up the data for the current character.
                let mut leaf = if !c.p.is_null() {
                    utf8lookup(c.um, c.n, c.hangul.as_mut_ptr(), c.s)
                } else {
                    utf8nlookup(c.um, c.n, c.hangul.as_mut_ptr(), c.s, c.len as usize)
                };

                // No leaf found implies that the input is a binary blob.
                if leaf.is_null() {
                    return -1;
                }

                ccc = *leaf.add(1) as i16;
                // Characters that are too new have CCC 0.
                if *(*(*c.um).tables).utf8agetab.add(*leaf as usize) > (*(*c.um).ntab[c.n as usize]).maxage {
                    ccc = STOPPER;
                } else if ccc == DECOMPOSE {
                    c.len = c.len.wrapping_sub(utf8clen(c.s) as u32);
                    c.p = c.s.add(utf8clen(c.s));
                    c.s = leaf.add(2);
                    // Empty decomposition implies CCC 0.
                    if *c.s == 0 {
                        if c.ccc == STOPPER {
                            continue 'outer;
                        }
                        ccc = STOPPER;
                        break 'mismatch;
                    }

                    leaf = utf8lookup(c.um, c.n, c.hangul.as_mut_ptr(), c.s);
                    if leaf.is_null() {
                        return -1;
                    }
                    ccc = *leaf.add(1) as i16;
                }

                // If this is not a stopper, then see if it updates the next canonical class to be emitted.
                if ccc != STOPPER && c.ccc < ccc && ccc < c.nccc {
                    c.nccc = ccc;
                }

                // Return the current byte if this is the current combining class.
                if ccc == c.ccc {
                    if c.p.is_null() {
                        c.len = c.len.wrapping_sub(1);
                    }
                    let b = *c.s;
                    c.s = c.s.add(1);
                    return b as c_int;
                }
            }

            // Current combining class mismatch. (ccc_mismatch:)
            if c.nccc == STOPPER {
                // Scan forward for the first canonical class to be emitted. Save the position from which to restart.
                c.ccc = MINCCC - 1;
                c.nccc = ccc;
                c.sp = c.p;
                c.ss = c.s;
                c.slen = c.len;
                if c.p.is_null() {
                    c.len = c.len.wrapping_sub(utf8clen(c.s) as u32);
                }
                c.s = c.s.add(utf8clen(c.s));
            } else if ccc != STOPPER {
                // Not a stopper, and not the ccc we're emitting.
                if c.p.is_null() {
                    c.len = c.len.wrapping_sub(utf8clen(c.s) as u32);
                }
                c.s = c.s.add(utf8clen(c.s));
            } else if c.nccc != MAXCCC + 1 {
                // At a stopper, restart for next ccc.
                c.ccc = c.nccc;
                c.nccc = MAXCCC + 1;
                c.s = c.ss;
                c.p = c.sp;
                c.len = c.slen;
            } else {
                // All done, proceed from here.
                c.ccc = STOPPER;
                c.nccc = STOPPER;
                c.sp = null();
                c.ss = null();
                c.slen = 0;
            }
        }
    }
}
