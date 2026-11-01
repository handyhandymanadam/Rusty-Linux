#!/usr/bin/env python3
"""Mechanically translate a fs/nls/nls_<cs>.c table file into nls_<cs>_rs.rs.

usage: gen.py <pristine nls_X.c> <out _rs.rs> <Ident> <sym> <charset> <file-tag>

Only the DATA is translated (charset2uni, pageNN, page_uni2charset,
charset2lower/upper); the logic is the same 20 lines in every file and lives
in the template below. The generated tables are NOT trusted: run.sh compares
every entry against the C compiled from the same pristine file.
"""
import re, sys

src, out, ident, sym, charset, tag = sys.argv[1:7]
text = open(src).read()

def body(name, ctype_re):
    m = re.search(r'static const ' + ctype_re + r'\s+' + re.escape(name) + r'\[256\]\s*=\s*\{(.*?)\};', text, re.S)
    assert m, name
    s = re.sub(r'/\*.*?\*/', '', m.group(1), flags=re.S)
    vals = [int(x, 16) for x in re.findall(r'0x[0-9a-fA-F]+', s)]
    assert len(vals) <= 256, (name, len(vals))
    return vals + [0] * (256 - len(vals))          # C zero-fills a short initialiser

def fmt(vals, w, ty):
    per = 8 if ty == 'u8' else 4
    rows = []
    for i in range(0, 256, per):
        rows.append('    ' + ', '.join('0x%0*x' % (w, v) for v in vals[i:i+per]) + ',')
    return '\n'.join(rows)

c2u = body('charset2uni', r'wchar_t')
lower = body('charset2lower', r'unsigned char')
upper = body('charset2upper', r'unsigned char')
pages = sorted(set(re.findall(r'static const unsigned char (page[0-9a-f]{2})\[256\]', text)))
pagevals = {p: body(p, r'unsigned char') for p in pages}
m = re.search(r'page_uni2charset\[256\]\s*=\s*\{(.*?)\};', text, re.S)
used = re.findall(r'page[0-9a-f]{2}', m.group(1))
assert sorted(used) == pages and 'page_uni2charset' in text
# C initialiser form is positional: page00, page01, ... or designated [0x03] = page03
idx = {}
entries = [e.strip() for e in re.sub(r'/\*.*?\*/', '', m.group(1), flags=re.S).split(',') if e.strip()]
pos = 0
for e in entries:
    d = re.match(r'\[(0x[0-9a-fA-F]+|\d+)\]\s*=\s*(page[0-9a-f]{2})$', e)
    if d:
        pos = int(d.group(1), 0); idx[pos] = d.group(2)
    elif e == 'NULL':
        pass                                    # absent page: None
    else:
        assert re.match(r'page[0-9a-f]{2}$', e), e
        idx[pos] = e
    pos += 1

o = []
o.append('''// SPDX-License-Identifier: GPL-2.0

//! NLS charset "%(cs)s" -- the Rust behind `fs/nls/nls_%(tag)s.c`.
//!
//! Ported from `fs/nls/nls_%(tag)s.c` (6.18.49), which is "Generated automatically
//! from the Unicode and charset tables from the Unicode Organization
//! (www.unicode.org). The Unicode to charset table has only exact mappings."
//!
//! # What is here and what stayed in C (`nls_%(u)s_glue.c`)
//!
//! Here: the data tables (`charset2uni`, the `pageNN` Unicode-to-charset pages
//! and the page index, `charset2lower`, `charset2upper`), `uni2char`,
//! `char2uni`, and the `struct nls_table` itself (`%(sym)s`). In C:
//! `module_init`/`module_exit`, `MODULE_*`, and the `register_nls()` call, a
//! macro that expands to `__register_nls(nls, THIS_MODULE)`.
//!
//! The tables were generated from the C initialisers by
//! `port/test/nls_tables/gen.py` and are verified entry by entry against the C
//! (compiled unmodified from `port/pristine/fs/nls/`) by
//! `port/test/nls_tables/run.sh`: `uni2char` for all 65536 code points x
//! boundlen -2..8, `char2uni` for all 256 bytes, both case tables byte-equal.
//! A short C initialiser zero-fills the rest of the array; so do these.
//!
//! `__register_nls()` WRITES this table (`nls->owner`, `nls->next`), so it is
//! mutable shared state behind an `UnsafeCell`, laid out exactly as the C
//! struct (`rig/layout-check.sh` compares the geometry against vmlinux DWARF).
//!
//! Error values are the C's: `-ENAMETOOLONG` for `boundlen <= 0`, `-EINVAL`
//! for a code point or byte with no mapping. No message text is produced.
//!
//! Replaces: fs/nls/nls_%(tag)s.c

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};

const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;

/// Mirrors `struct nls_table` in `include/linux/nls.h`.
#[repr(C)]
pub struct %(id)s {
    charset: *const c_char,
    alias: *const c_char,
    uni2char: Option<unsafe extern "C" fn(u16, *mut u8, c_int) -> c_int>,
    char2uni: Option<unsafe extern "C" fn(*const u8, c_int, *mut u16) -> c_int>,
    charset2lower: *const u8,
    charset2upper: *const u8,
    owner: *mut c_void,
    next: *mut %(id)s,
}

/// The table is written by `__register_nls()` under `nls_lock`; Rust never
/// touches it after construction.
#[repr(transparent)]
pub struct SharedTable%(id)s(UnsafeCell<%(id)s>);

// SAFETY: all mutation is by the C registry, serialised by its spinlock.
unsafe impl Sync for SharedTable%(id)s {}
''' % dict(cs=charset, tag=tag, u=tag.replace('-', '_'), sym=sym, id=ident))

o.append('/// `charset2uni[]` of the C file (a zero entry means "no mapping").\nstatic CHARSET2UNI: [u16; 256] = [\n' + fmt(c2u, 4, 'u16') + '\n];\n')
for p in pages:
    o.append('/// `%s[]` of the C file: low byte of the code point -> charset byte.\nstatic %s: [u8; 256] = [\n' % (p, p.upper()) + fmt(pagevals[p], 2, 'u8') + '\n];\n')
o.append('/// `page_uni2charset[]` of the C file, indexed by the high byte of the code point.\nstatic PAGE_UNI2CHARSET: [Option<&\'static [u8; 256]>; 256] = {\n    let mut t: [Option<&\'static [u8; 256]>; 256] = [None; 256];\n' +
         ''.join('    t[0x%02x] = Some(&%s);\n' % (i, p.upper()) for i, p in sorted(idx.items())) + '    t\n};\n')
o.append('/// `charset2lower[]` of the C file.\nstatic CHARSET2LOWER: [u8; 256] = [\n' + fmt(lower, 2, 'u8') + '\n];\n')
o.append('/// `charset2upper[]` of the C file.\nstatic CHARSET2UPPER: [u8; 256] = [\n' + fmt(upper, 2, 'u8') + '\n];\n')
o.append('''/// `uni2char()` of the C file.
unsafe extern "C" fn uni2char(uni: u16, out: *mut u8, boundlen: c_int) -> c_int {
    let cl = (uni & 0x00ff) as usize;
    let ch = ((uni & 0xff00) >> 8) as usize;

    if boundlen <= 0 {
        return -ENAMETOOLONG;
    }

    match PAGE_UNI2CHARSET[ch] {
        Some(page) if page[cl] != 0 => {
            // SAFETY: boundlen >= 1, so out[0] is writable (the nls_table contract).
            unsafe { *out = page[cl] };
            1
        }
        _ => -EINVAL,
    }
}

/// `char2uni()` of the C file.
unsafe extern "C" fn char2uni(rawstring: *const u8, _boundlen: c_int, uni: *mut u16) -> c_int {
    // SAFETY: the caller passes at least one readable byte and a valid
    // wchar_t out-parameter (the nls_table contract); the C reads one byte
    // regardless of boundlen, and so does this.
    let u = CHARSET2UNI[unsafe { *rawstring } as usize];
    unsafe { *uni = u };
    if u == 0x0000 {
        return -EINVAL;
    }
    1
}

/// `static struct nls_table table` of the C file, given a symbol so the glue
/// can pass it to `register_nls()`.
#[no_mangle]
pub static %(sym)s: SharedTable%(id)s = SharedTable%(id)s(UnsafeCell::new(%(id)s {
    charset: b"%(cs)s\\0".as_ptr() as *const c_char,
    alias: core::ptr::null(),
    uni2char: Some(uni2char),
    char2uni: Some(char2uni),
    charset2lower: CHARSET2LOWER.as_ptr(),
    charset2upper: CHARSET2UPPER.as_ptr(),
    owner: core::ptr::null_mut(),
    next: core::ptr::null_mut(),
}));
''' % dict(sym=sym, id=ident, cs=charset))
open(out, 'w').write('\n'.join(o))
