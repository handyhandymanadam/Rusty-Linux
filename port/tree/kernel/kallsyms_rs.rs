// SPDX-License-Identifier: GPL-2.0-only

//! The symbol-table walkers of `kernel/kallsyms.c` -- the Rust behind them.
//!
//! Ported from `kernel/kallsyms.c` (6.18.49): `kallsyms_expand_symbol()` (decompress one name from the token stream), `kallsyms_get_symbol_type()`, `get_symbol_offset()` (marker plus
//! sequential scan to the n-th symbol), `kallsyms_sym_address()`, `get_symbol_seq()`, `kallsyms_lookup_names()` (binary search by name over the sorted sequence, then the run of equal
//! names) and the address binary search with alias handling of `get_symbol_pos()`. The tables (`kallsyms_names`, `_markers`, `_token_table`, `_token_index`, `_offsets`,
//! `_seqs_of_names`, `_num_syms`, `_relative_base`) are generated at link time; the glue passes their addresses and values in a [`Ksyms`], so these functions work on any consistent
//! set of tables (the userspace test builds its own). In C (`kallsyms_glue.c`): the exports and callers, module / ftrace / bpf / kprobe symbols, the section-end fallback of
//! `get_symbol_pos()`, the seq_file iterator, `sprint_symbol` and the rest.
//!
//! These run from oops, panic and NMI printing: no allocation, no panic paths other than the C's own failures. Arithmetic wraps as in C.
//!
//! Replaces: kernel/kallsyms.c (the table walkers)

use core::ffi::{c_char, c_int, c_uint, c_ulong};

const KSYM_NAME_LEN: usize = 512;
const ESRCH: c_int = 3;

/// The kallsyms tables as the link produced them.
#[repr(C)]
pub struct Ksyms {
    names: *const u8,
    markers: *const c_uint,
    token_table: *const c_char,
    token_index: *const u16,
    offsets: *const c_int,
    seqs: *const u8,
    num_syms: c_uint,
    relative_base: c_ulong,
}

/// `kallsyms_expand_symbol()`: expand the symbol at stream offset `off` into `result` (at most `maxlen` bytes, NUL included, truncated); returns the offset of the next symbol.
///
/// # Safety
/// `result` must be valid for `maxlen` bytes; the tables must be consistent.
unsafe fn expand(t: &Ksyms, off: c_uint, result: *mut c_char, maxlen: usize) -> c_uint {
    // SAFETY: the tables are consistent and `result` has room for `maxlen` bytes.
    unsafe {
        let mut off = off;
        let mut result = result;
        let mut maxlen = maxlen;
        let mut skipped_first = false;

        // the compressed symbol length from the first symbol byte
        let mut data = t.names.add(off as usize);
        let mut len: c_int = *data as c_int;
        data = data.add(1);
        off = off.wrapping_add(1);

        // MSB set: a "big" symbol, one more length byte
        if (len & 0x80) != 0 {
            len = (len & 0x7F) | ((*data as c_int) << 7);
            data = data.add(1);
            off = off.wrapping_add(1);
        }

        // the offset of the next symbol on the compressed stream
        off = off.wrapping_add(len as c_uint);

        // for every byte of the compressed data, copy the table entry for that byte
        'outer: while len != 0 {
            let mut tptr = t.token_table.add(*t.token_index.add(*data as usize) as usize);
            data = data.add(1);
            len -= 1;

            while *tptr != 0 {
                if skipped_first {
                    if maxlen <= 1 {
                        break 'outer;
                    }
                    *result = *tptr;
                    result = result.add(1);
                    maxlen -= 1;
                } else {
                    skipped_first = true;
                }
                tptr = tptr.add(1);
            }
        }

        if maxlen != 0 {
            *result = 0;
        }
        off
    }
}

/// `get_symbol_offset()`: the stream offset of symbol number `pos`.
///
/// # Safety
/// The tables must be consistent and `pos` below `num_syms`.
unsafe fn symbol_offset(t: &Ksyms, pos: c_ulong) -> c_uint {
    // SAFETY: the tables are consistent.
    unsafe {
        // the closest marker (one every 256 positions), then skip symbol by symbol
        let mut name = t.names.add(*t.markers.add((pos >> 8) as usize) as usize);

        let mut i: c_int = 0;
        while (i as c_ulong) < (pos & 0xFF) {
            let mut len: c_int = *name as c_int;

            // MSB set: a "big" symbol, look into the next byte (and skip it, too)
            if (len & 0x80) != 0 {
                len = ((len & 0x7F) | ((*name.add(1) as c_int) << 7)) + 1;
            }

            name = name.add((len + 1) as usize);
            i += 1;
        }

        name.offset_from(t.names) as c_uint
    }
}

/// `kallsyms_sym_address()`.
///
/// # Safety
/// `idx` is below `num_syms`.
unsafe fn sym_address(t: &Ksyms, idx: c_ulong) -> c_ulong {
    // SAFETY: the tables are consistent.
    unsafe { t.relative_base.wrapping_add(*t.offsets.add(idx as usize) as c_uint as c_ulong) }
}

/// `get_symbol_seq()`: the 3-byte sequence number of the `index`-th symbol in name order.
///
/// # Safety
/// `index` is below `num_syms`.
unsafe fn symbol_seq(t: &Ksyms, index: c_int) -> c_uint {
    // SAFETY: the tables are consistent.
    unsafe {
        let mut seq: c_uint = 0;
        for i in 0..3 {
            seq = (seq << 8) | *t.seqs.add((3 * index + i) as usize) as c_uint;
        }
        seq
    }
}

/// `strcmp()` sign on NUL-terminated strings, bytes compared as unsigned.
unsafe fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: both are NUL-terminated.
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i) as u8, *b.add(i) as u8);
            if x != y {
                return x as c_int - y as c_int;
            }
            if x == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// `kallsyms_expand_symbol()` for C.
///
/// # Safety
/// As [`expand`].
#[no_mangle]
pub unsafe extern "C" fn rust_ks_expand_symbol(t: *const Ksyms, off: c_uint, result: *mut c_char, maxlen: usize) -> c_uint {
    // SAFETY: the caller passes valid tables and buffer.
    unsafe { expand(&*t, off, result, maxlen) }
}

/// `kallsyms_get_symbol_type()`.
///
/// # Safety
/// The tables are consistent and `off` is a symbol offset.
#[no_mangle]
pub unsafe extern "C" fn rust_ks_symbol_type(t: *const Ksyms, off: c_uint) -> c_char {
    // SAFETY: the caller passes valid tables.
    unsafe {
        let t = &*t;
        let mut off = off as usize;
        if (*t.names.add(off) & 0x80) != 0 {
            off += 1;
        }
        *t.token_table.add(*t.token_index.add(*t.names.add(off + 1) as usize) as usize)
    }
}

/// `get_symbol_offset()` for C.
///
/// # Safety
/// As [`symbol_offset`].
#[no_mangle]
pub unsafe extern "C" fn rust_ks_symbol_offset(t: *const Ksyms, pos: c_ulong) -> c_uint {
    // SAFETY: the caller passes valid tables.
    unsafe { symbol_offset(&*t, pos) }
}

/// `kallsyms_sym_address()` for C.
///
/// # Safety
/// As [`sym_address`].
#[no_mangle]
pub unsafe extern "C" fn rust_ks_sym_address(t: *const Ksyms, idx: c_int) -> c_ulong {
    // SAFETY: the caller passes valid tables.
    unsafe { sym_address(&*t, idx as c_ulong) }
}

/// `get_symbol_seq()` for C.
///
/// # Safety
/// As [`symbol_seq`].
#[no_mangle]
pub unsafe extern "C" fn rust_ks_symbol_seq(t: *const Ksyms, index: c_int) -> c_uint {
    // SAFETY: the caller passes valid tables.
    unsafe { symbol_seq(&*t, index) }
}

/// `kallsyms_lookup_names()`: the range `[start, end]` (positions in name order) of the symbols called `name`; `end` may be NULL. 0 or `-ESRCH`.
///
/// # Safety
/// `name` is a NUL-terminated string; `start` is valid for writes, `end` is NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn rust_ks_lookup_names(t: *const Ksyms, name: *const c_char, start: *mut c_uint, end: *mut c_uint) -> c_int {
    // SAFETY: the caller passes valid tables, string and pointers.
    unsafe {
        let t = &*t;
        let mut namebuf = [0 as c_char; KSYM_NAME_LEN];
        let mut low: c_int = 0;
        let mut high: c_int = t.num_syms.wrapping_sub(1) as c_int;
        let mut mid: c_int = 0;

        while low <= high {
            mid = low + (high - low) / 2;
            let seq = symbol_seq(t, mid);
            let off = symbol_offset(t, seq as c_ulong);
            expand(t, off, namebuf.as_mut_ptr(), KSYM_NAME_LEN);
            let ret = strcmp(name, namebuf.as_ptr());
            if ret > 0 {
                low = mid + 1;
            } else if ret < 0 {
                high = mid - 1;
            } else {
                break;
            }
        }

        if low > high {
            return -ESRCH;
        }

        low = mid;
        while low != 0 {
            let seq = symbol_seq(t, low - 1);
            let off = symbol_offset(t, seq as c_ulong);
            expand(t, off, namebuf.as_mut_ptr(), KSYM_NAME_LEN);
            if strcmp(name, namebuf.as_ptr()) != 0 {
                break;
            }
            low -= 1;
        }
        *start = low as c_uint;

        if !end.is_null() {
            high = mid;
            while (high as c_uint) < t.num_syms.wrapping_sub(1) {
                let seq = symbol_seq(t, high + 1);
                let off = symbol_offset(t, seq as c_ulong);
                expand(t, off, namebuf.as_mut_ptr(), KSYM_NAME_LEN);
                if strcmp(name, namebuf.as_ptr()) != 0 {
                    break;
                }
                high += 1;
            }
            *end = high as c_uint;
        }

        0
    }
}

/// The address search of `get_symbol_pos()`: the index of the first symbol of the alias group containing `addr`, its start address and the address of the next non-aliased symbol
/// (0 when there is none; the C glue then uses the end of the section).
///
/// # Safety
/// The tables are consistent; the out pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_ks_symbol_pos(t: *const Ksyms, addr: c_ulong, symbol_start: *mut c_ulong, symbol_end: *mut c_ulong) -> c_ulong {
    // SAFETY: the caller passes valid tables and pointers.
    unsafe {
        let t = &*t;
        let mut end: c_ulong = 0;

        // binary search on the sorted kallsyms_offsets array
        let mut low: c_ulong = 0;
        let mut high: c_ulong = t.num_syms as c_ulong;

        while high.wrapping_sub(low) > 1 {
            let mid = low + high.wrapping_sub(low) / 2;
            if sym_address(t, mid) <= addr {
                low = mid;
            } else {
                high = mid;
            }
        }

        // the first aliased symbol: symbols with the same address
        while low != 0 && sym_address(t, low - 1) == sym_address(t, low) {
            low -= 1;
        }

        let start = sym_address(t, low);

        // the next non-aliased symbol
        let mut i = low + 1;
        while i < t.num_syms as c_ulong {
            if sym_address(t, i) > start {
                end = sym_address(t, i);
                break;
            }
            i += 1;
        }

        *symbol_start = start;
        *symbol_end = end;
        low
    }
}
