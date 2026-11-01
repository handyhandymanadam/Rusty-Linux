// SPDX-License-Identifier: GPL-2.0

//! SELinux multi-level security -- the Rust behind `security/selinux/ss/mls.c`.
//!
//! Ported from `security/selinux/ss/mls.c` (6.18.49, Stephen Smalley / Trusted Computer Solutions): the length and the text of the MLS part of a security context
//! (`mls_compute_context_len`, `mls_sid_to_context`), the validity checks (`mls_level_isvalid`, `mls_range_isvalid`, `mls_context_isvalid`), the text parser
//! (`mls_context_to_sid`), `mls_range_set`, `mls_setup_user_range`, `mls_convert_context` and the range-transition decision of `mls_compute_sid`. The `struct policydb`,
//! `struct context` and datum fields it touches are read at fixed offsets that `mls_glue.c` asserts. Category bitmaps are walked with the same rule as
//! `ebitmap_for_each_positive_bit`; every change to one goes through the C `ebitmap_*` functions. In C (`mls_glue.c`): the layout checks, `mls_from_string` (kstrdup) and
//! the NetLabel conversions (CONFIG_NETLABEL), plus `rust_ml_sidtab_search`.
//!
//! Replaces: security/selinux/ss/mls.c (all but mls_from_string and the NetLabel functions)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

const EINVAL: c_int = 22;

// Offsets in `struct policydb` (asserted by the glue).
const P_MLS_ENABLED: usize = 0;
const P_SYMTAB: usize = 8; // symtab[8], 24 bytes each: table (16) + nprim
const SYMTAB_SIZE: usize = 24;
const SYMTAB_NPRIM: usize = 16;
const SYM_USERS: usize = 4;
const SYM_LEVELS: usize = 6;
const SYM_CATS: usize = 7;
const P_SYM_VAL_TO_NAME: usize = 200; // char **sym_val_to_name[8]
const P_CLASS_VAL_TO_STRUCT: usize = 264;
const P_USER_VAL_TO_STRUCT: usize = 280;
const P_PROCESS_CLASS: usize = 598; // u16

// `struct context`.
const C_USER: usize = 0;
const C_ROLE: usize = 4;
const C_RANGE: usize = 16;
// `struct mls_range` is two `struct mls_level`: sens (u32) + cat (struct ebitmap, 16 bytes).
const LEVEL_SIZE: usize = 24;
const L_SENS: usize = 0;
const L_CAT: usize = 8;

// `struct ebitmap` / `struct ebitmap_node` (64-bit).
const EB_NODE: usize = 0;
const EB_HIGHBIT: usize = 8;
const EBN_NEXT: usize = 0;
const EBN_MAPS: usize = 8;
const EBN_STARTBIT: usize = 56;
const EBITMAP_UNIT_NUMS: usize = 6;
const EBITMAP_SIZE: u32 = (EBITMAP_UNIT_NUMS as u32) * 64;

// `struct user_datum`, `struct level_datum`, `struct cat_datum`, `struct class_datum`.
const UD_RANGE: usize = 24;
const UD_DFLTLEVEL: usize = 72;
const LD_LEVEL: usize = 0; // struct level_datum: struct mls_level level
const CD_VALUE: usize = 0;
const CLD_DEFAULT_RANGE: usize = 67;

const OBJECT_R_VAL: u32 = 1;
const SECSID_NULL: u32 = 0;
const AVTAB_TRANSITION: u32 = 0x0010;
const AVTAB_MEMBER: u32 = 0x0020;
const AVTAB_CHANGE: u32 = 0x0040;
const DEFAULT_SOURCE_LOW: i8 = 1;
const DEFAULT_SOURCE_HIGH: i8 = 2;
const DEFAULT_SOURCE_LOW_HIGH: i8 = 3;
const DEFAULT_TARGET_LOW: i8 = 4;
const DEFAULT_TARGET_HIGH: i8 = 5;
const DEFAULT_TARGET_LOW_HIGH: i8 = 6;
const DEFAULT_GLBLUB: i8 = 7;

/// `struct range_trans`.
#[repr(C)]
struct RangeTrans {
    source_type: u32,
    target_type: u32,
    target_class: u16,
}

extern "C" {
    fn symtab_search(s: *mut c_void, name: *const c_char) -> *mut c_void;
    fn ebitmap_equal(e1: *const c_void, e2: *const c_void) -> bool;
    fn ebitmap_cpy(dst: *mut c_void, src: *const c_void) -> c_int;
    fn ebitmap_and(dst: *mut c_void, e1: *const c_void, e2: *const c_void) -> c_int;
    fn ebitmap_contains(e1: *const c_void, e2: *const c_void, last_e2bit: u32) -> c_int;
    fn ebitmap_set_bit(e: *mut c_void, bit: u32, value: c_int) -> c_int;
    fn ebitmap_destroy(e: *mut c_void);
    fn policydb_rangetr_search(p: *mut c_void, key: *mut RangeTrans) -> *mut c_void;
    /// `sidtab_search()`: the context of a SID, or NULL.
    fn rust_ml_sidtab_search(s: *mut c_void, sid: u32) -> *mut c_void;
}

#[inline]
unsafe fn rd32(base: *const c_void, off: usize) -> u32 {
    unsafe {
        base.cast::<u8>().add(off).cast::<u32>().read_unaligned()
    }
}
#[inline]
unsafe fn wr32(base: *mut c_void, off: usize, v: u32) {
    unsafe {
        base.cast::<u8>().add(off).cast::<u32>().write_unaligned(v)
    }
}
#[inline]
unsafe fn rdp(base: *const c_void, off: usize) -> *mut c_void {
    unsafe {
        base.cast::<u8>().add(off).cast::<*mut c_void>().read_unaligned()
    }
}

#[inline]
unsafe fn mls_enabled(p: *const c_void) -> bool {
    unsafe {
        rd32(p, P_MLS_ENABLED) as c_int != 0
    }
}
/// `&p->symtab[which]`
#[inline]
unsafe fn symtab(p: *mut c_void, which: usize) -> *mut c_void {
    unsafe {
        p.cast::<u8>().add(P_SYMTAB + which * SYMTAB_SIZE).cast()
    }
}
#[inline]
unsafe fn nprim(p: *mut c_void, which: usize) -> u32 {
    unsafe {
        rd32(symtab(p, which), SYMTAB_NPRIM)
    }
}
/// `sym_name(p, which, nr)`
#[inline]
unsafe fn sym_name(p: *const c_void, which: usize, nr: u32) -> *const c_char {
    unsafe {
        let tab = rdp(p, P_SYM_VAL_TO_NAME + which * 8).cast::<*const c_char>();
        tab.add(nr as usize).read()
    }
}
#[inline]
unsafe fn level(c: *mut c_void, base: usize, l: usize) -> *mut c_void {
    unsafe {
        c.cast::<u8>().add(base + l * LEVEL_SIZE).cast()
    }
}
#[inline]
unsafe fn cat(lv: *mut c_void) -> *mut c_void {
    unsafe {
        lv.cast::<u8>().add(L_CAT).cast()
    }
}
#[inline]
unsafe fn sens(lv: *const c_void) -> u32 {
    unsafe {
        rd32(lv, L_SENS)
    }
}

unsafe fn strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}
/// `strchr(s, c)` for a non-NUL `c`.
unsafe fn strchr(s: *mut c_char, c: u8) -> *mut c_char {
    unsafe {
        let mut p = s;
        loop {
            let b = *p as u8;
            if b == c {
                return p;
            }
            if b == 0 {
                return null_mut();
            }
            p = p.add(1);
        }
    }
}
/// `strcpy(dst, src)`; returns the length copied.
unsafe fn strcpy(dst: *mut c_char, src: *const c_char) -> usize {
    unsafe {
        let n = strlen(src);
        core::ptr::copy_nonoverlapping(src, dst, n + 1);
        n
    }
}

/// `mls_level_dom(l1, l2)`.
unsafe fn level_dom(l1: *mut c_void, l2: *mut c_void) -> bool {
    unsafe {
        sens(l1) >= sens(l2) && ebitmap_contains(cat(l1), cat(l2), 0) != 0
    }
}
/// `mls_level_eq(l1, l2)`.
unsafe fn level_eq(l1: *mut c_void, l2: *mut c_void) -> bool {
    unsafe {
        sens(l1) == sens(l2) && ebitmap_equal(cat(l1), cat(l2))
    }
}
/// `mls_level_between(l1, l2, l3)`.
unsafe fn level_between(l1: *mut c_void, l2: *mut c_void, l3: *mut c_void) -> bool {
    unsafe {
        level_dom(l1, l2) && level_dom(l3, l1)
    }
}

/// `ebitmap_for_each_positive_bit(e, n, bit)`: the next set bit after `bit` (or the first for `None`), `highbit` when there is none. `node` is the cursor.
struct Bits {
    e: *const c_void,
    node: *const c_void,
}
impl Bits {
    unsafe fn new(e: *const c_void) -> Bits {
        unsafe {
            Bits { e, node: rdp(e, EB_NODE) }
        }
    }
    unsafe fn highbit(&self) -> u32 {
        unsafe {
            rd32(self.e, EB_HIGHBIT)
        }
    }
    /// First set bit at or after offset `from` (relative to the node) in the current node, or EBITMAP_SIZE.
    unsafe fn find_in_node(&self, from: u32) -> u32 {
        unsafe {
            let maps = self.node.cast::<u8>().add(EBN_MAPS).cast::<u64>();
            let mut ofs = from;
            while ofs < EBITMAP_SIZE {
                let w = maps.add((ofs / 64) as usize).read_unaligned() >> (ofs % 64);
                if w != 0 {
                    return ofs + w.trailing_zeros();
                }
                ofs = (ofs / 64 + 1) * 64;
            }
            EBITMAP_SIZE
        }
    }
    unsafe fn first_from_nodes(&mut self) -> u32 {
        unsafe {
            while !self.node.is_null() {
                let ofs = self.find_in_node(0);
                if ofs < EBITMAP_SIZE {
                    return rd32(self.node, EBN_STARTBIT) + ofs;
                }
                self.node = rdp(self.node, EBN_NEXT);
            }
            self.highbit()
        }
    }
    unsafe fn start(&mut self) -> u32 {
        unsafe {
            self.node = rdp(self.e, EB_NODE);
            self.first_from_nodes()
        }
    }
    unsafe fn next(&mut self, bit: u32) -> u32 {
        unsafe {
            let start = rd32(self.node, EBN_STARTBIT);
            let ofs = self.find_in_node(bit.wrapping_sub(start).wrapping_add(1));
            if ofs < EBITMAP_SIZE {
                return ofs + start;
            }
            self.node = rdp(self.node, EBN_NEXT);
            self.first_from_nodes()
        }
    }
}

/// `mls_compute_context_len()`.
#[no_mangle]
pub unsafe extern "C" fn mls_compute_context_len(p: *mut c_void, context: *mut c_void) -> c_int {
    unsafe {
        if !mls_enabled(p) {
            return 0;
        }
        let mut len: c_int = 1; // for the beginning ":"
        for l in 0..2usize {
            let lv = level(context, C_RANGE, l);
            len = len.wrapping_add(strlen(sym_name(p, SYM_LEVELS, sens(lv).wrapping_sub(1))) as c_int);

            // categories
            let mut head: c_int = -2;
            let mut prev: c_int = -2;
            let e = cat(lv);
            let mut it = Bits::new(e);
            let hb = it.highbit();
            let mut i = it.start();
            while i < hb {
                if (i as c_int).wrapping_sub(prev) > 1 {
                    // one or more negative bits are skipped
                    if head != prev {
                        len = len.wrapping_add(strlen(sym_name(p, SYM_CATS, prev as u32)) as c_int + 1);
                    }
                    len = len.wrapping_add(strlen(sym_name(p, SYM_CATS, i)) as c_int + 1);
                    head = i as c_int;
                }
                prev = i as c_int;
                i = it.next(i);
            }
            if prev != head {
                len = len.wrapping_add(strlen(sym_name(p, SYM_CATS, prev as u32)) as c_int + 1);
            }
            if l == 0 {
                if level_eq(level(context, C_RANGE, 0), level(context, C_RANGE, 1)) {
                    break;
                } else {
                    len = len.wrapping_add(1);
                }
            }
        }
        len
    }
}

/// `mls_sid_to_context()`.
#[no_mangle]
pub unsafe extern "C" fn mls_sid_to_context(p: *mut c_void, context: *mut c_void, scontext: *mut *mut c_char) {
    unsafe {
        if !mls_enabled(p) {
            return;
        }
        let mut sp = *scontext;
        *sp = b':' as c_char;
        sp = sp.add(1);

        for l in 0..2usize {
            let lv = level(context, C_RANGE, l);
            sp = sp.add(strcpy(sp, sym_name(p, SYM_LEVELS, sens(lv).wrapping_sub(1))));

            // categories
            let mut head: c_int = -2;
            let mut prev: c_int = -2;
            let mut it = Bits::new(cat(lv));
            let hb = it.highbit();
            let mut i = it.start();
            while i < hb {
                if (i as c_int).wrapping_sub(prev) > 1 {
                    // one or more negative bits are skipped
                    if prev != head {
                        *sp = if prev.wrapping_sub(head) > 1 { b'.' } else { b',' } as c_char;
                        sp = sp.add(1);
                        sp = sp.add(strcpy(sp, sym_name(p, SYM_CATS, prev as u32)));
                    }
                    *sp = if prev < 0 { b':' } else { b',' } as c_char;
                    sp = sp.add(1);
                    sp = sp.add(strcpy(sp, sym_name(p, SYM_CATS, i)));
                    head = i as c_int;
                }
                prev = i as c_int;
                i = it.next(i);
            }

            if prev != head {
                *sp = if prev.wrapping_sub(head) > 1 { b'.' } else { b',' } as c_char;
                sp = sp.add(1);
                sp = sp.add(strcpy(sp, sym_name(p, SYM_CATS, prev as u32)));
            }

            if l == 0 {
                if level_eq(level(context, C_RANGE, 0), level(context, C_RANGE, 1)) {
                    break;
                } else {
                    *sp = b'-' as c_char;
                    sp = sp.add(1);
                }
            }
        }
        *scontext = sp;
    }
}

/// `mls_level_isvalid()`.
#[no_mangle]
pub unsafe extern "C" fn mls_level_isvalid(p: *mut c_void, l: *mut c_void) -> c_int {
    unsafe {
        let s = sens(l);
        if s == 0 || s > nprim(p, SYM_LEVELS) {
            return 0;
        }
        let levdatum = symtab_search(symtab(p, SYM_LEVELS), sym_name(p, SYM_LEVELS, s - 1));
        if levdatum.is_null() {
            return 0;
        }
        // Return 1 iff all the bits set in l->cat are also set in levdatum->level.cat and no bit in l->cat is larger than p->p_cats.nprim.
        ebitmap_contains(cat(levdatum.cast::<u8>().add(LD_LEVEL).cast()), cat(l), nprim(p, SYM_CATS))
    }
}

/// `mls_range_isvalid()`.
#[no_mangle]
pub unsafe extern "C" fn mls_range_isvalid(p: *mut c_void, r: *mut c_void) -> c_int {
    unsafe {
        let lo = r.cast::<u8>().cast::<c_void>();
        let hi = r.cast::<u8>().add(LEVEL_SIZE).cast::<c_void>();
        (mls_level_isvalid(p, lo) != 0 && mls_level_isvalid(p, hi) != 0 && level_dom(hi, lo)) as c_int
    }
}

/// `mls_context_isvalid()`.
#[no_mangle]
pub unsafe extern "C" fn mls_context_isvalid(p: *mut c_void, c: *mut c_void) -> c_int {
    unsafe {
        if !mls_enabled(p) {
            return 1;
        }
        if mls_range_isvalid(p, c.cast::<u8>().add(C_RANGE).cast()) == 0 {
            return 0;
        }
        if rd32(c, C_ROLE) == OBJECT_R_VAL {
            return 1;
        }
        // User must be authorized for the MLS range.
        let user = rd32(c, C_USER);
        if user == 0 || user > nprim(p, SYM_USERS) {
            return 0;
        }
        let usrdatum = rdp(p, P_USER_VAL_TO_STRUCT).cast::<*mut c_void>().add((user - 1) as usize).read();
        let ur = usrdatum.cast::<u8>().add(UD_RANGE);
        // mls_range_contains(usrdatum->range, c->range)
        if !(level_dom(level(c, C_RANGE, 0), ur.cast()) && level_dom(ur.add(LEVEL_SIZE).cast(), level(c, C_RANGE, 1))) {
            return 0; // user may not be associated with range
        }
        1
    }
}

/// `mls_context_to_sid()`.
#[no_mangle]
pub unsafe extern "C" fn mls_context_to_sid(
    pol: *mut c_void,
    oldc: c_char,
    scontext: *mut c_char,
    context: *mut c_void,
    s: *mut c_void,
    def_sid: u32,
) -> c_int {
    unsafe {
        if !mls_enabled(pol) {
            // With no MLS, only return -EINVAL if there is a MLS field and it did not come from an xattr.
            if oldc != 0 && def_sid == SECSID_NULL {
                return -EINVAL;
            }
            return 0;
        }

        // No MLS component to the security context, try and map to default if provided.
        if oldc == 0 {
            if def_sid == SECSID_NULL {
                return -EINVAL;
            }
            let defcon = rust_ml_sidtab_search(s, def_sid);
            if defcon.is_null() {
                return -EINVAL;
            }
            return mls_context_cpy(context, defcon);
        }

        // If we're dealing with a range, figure out where the two parts of the range begin.
        let mut rangep: [*mut c_char; 2] = [scontext, strchr(scontext, b'-')];
        if !rangep[1].is_null() {
            *rangep[1] = 0;
            rangep[1] = rangep[1].add(1);
        }

        // For each part of the range:
        for l in 0..2usize {
            // Split sensitivity and category set.
            let sensitivity = rangep[l];
            if sensitivity.is_null() {
                break;
            }
            let mut next_cat = strchr(sensitivity, b':');
            if !next_cat.is_null() {
                *next_cat = 0;
                next_cat = next_cat.add(1);
            }

            // Parse sensitivity.
            let levdatum = symtab_search(symtab(pol, SYM_LEVELS), sensitivity);
            if levdatum.is_null() {
                return -EINVAL;
            }
            let lv = level(context, C_RANGE, l);
            wr32(lv, L_SENS, sens(levdatum.cast::<u8>().add(LD_LEVEL).cast()));

            // Extract category set.
            while !next_cat.is_null() {
                let cur_cat = next_cat;
                next_cat = strchr(next_cat, b',');
                if !next_cat.is_null() {
                    *next_cat = 0;
                    next_cat = next_cat.add(1);
                }

                // Separate into range if exists
                let mut rngptr = strchr(cur_cat, b'.');
                if !rngptr.is_null() {
                    // Remove '.'
                    *rngptr = 0;
                    rngptr = rngptr.add(1);
                }

                let catdatum = symtab_search(symtab(pol, SYM_CATS), cur_cat);
                if catdatum.is_null() {
                    return -EINVAL;
                }
                let cvalue = rd32(catdatum, CD_VALUE);

                let rc = ebitmap_set_bit(cat(lv), cvalue.wrapping_sub(1), 1);
                if rc != 0 {
                    return rc;
                }

                // If range, set all categories in range
                if rngptr.is_null() {
                    continue;
                }

                let rngdatum = symtab_search(symtab(pol, SYM_CATS), rngptr);
                if rngdatum.is_null() {
                    return -EINVAL;
                }
                let rvalue = rd32(rngdatum, CD_VALUE);
                if cvalue >= rvalue {
                    return -EINVAL;
                }

                let mut i = cvalue;
                while i < rvalue {
                    let rc = ebitmap_set_bit(cat(lv), i, 1);
                    if rc != 0 {
                        return rc;
                    }
                    i += 1;
                }
            }
        }

        // If we didn't see a '-', the range start is also the range end.
        if rangep[1].is_null() {
            let (lo, hi) = (level(context, C_RANGE, 0), level(context, C_RANGE, 1));
            wr32(hi, L_SENS, sens(lo));
            let rc = ebitmap_cpy(cat(hi), cat(lo));
            if rc != 0 {
                return rc;
            }
        }

        0
    }
}

/// `mls_range_set()`: copy the MLS range `range` into `context`.
#[no_mangle]
pub unsafe extern "C" fn mls_range_set(context: *mut c_void, range: *mut c_void) -> c_int {
    unsafe {
        let mut rc = 0;
        for l in 0..2usize {
            let dst = level(context, C_RANGE, l);
            let src = range.cast::<u8>().add(l * LEVEL_SIZE).cast::<c_void>();
            wr32(dst, L_SENS, sens(src));
            rc = ebitmap_cpy(cat(dst), cat(src));
            if rc != 0 {
                break;
            }
        }
        rc
    }
}

/// `mls_setup_user_range()`.
#[no_mangle]
pub unsafe extern "C" fn mls_setup_user_range(p: *mut c_void, fromcon: *mut c_void, user: *mut c_void, usercon: *mut c_void) -> c_int {
    unsafe {
        if mls_enabled(p) {
            let fromcon_sen = level(fromcon, C_RANGE, 0);
            let fromcon_clr = level(fromcon, C_RANGE, 1);
            let user_low = level(user, UD_RANGE, 0);
            let user_clr = level(user, UD_RANGE, 1);
            let user_def = user.cast::<u8>().add(UD_DFLTLEVEL).cast::<c_void>();
            let usercon_sen = level(usercon, C_RANGE, 0);
            let usercon_clr = level(usercon, C_RANGE, 1);

            // Honor the user's default level if we can
            if level_between(user_def, fromcon_sen, fromcon_clr) {
                core::ptr::copy_nonoverlapping(user_def.cast::<u8>(), usercon_sen.cast::<u8>(), LEVEL_SIZE);
            } else if level_between(fromcon_sen, user_def, user_clr) {
                core::ptr::copy_nonoverlapping(fromcon_sen.cast::<u8>(), usercon_sen.cast::<u8>(), LEVEL_SIZE);
            } else if level_between(fromcon_clr, user_low, user_def) {
                core::ptr::copy_nonoverlapping(user_low.cast::<u8>(), usercon_sen.cast::<u8>(), LEVEL_SIZE);
            } else {
                return -EINVAL;
            }

            // Lower the clearance of available contexts if the clearance of "fromcon" is lower than that of the user's default clearance (but only if the "fromcon" clearance
            // dominates the user's computed sensitivity level)
            if level_dom(user_clr, fromcon_clr) {
                core::ptr::copy_nonoverlapping(fromcon_clr.cast::<u8>(), usercon_clr.cast::<u8>(), LEVEL_SIZE);
            } else if level_dom(fromcon_clr, user_clr) {
                core::ptr::copy_nonoverlapping(user_clr.cast::<u8>(), usercon_clr.cast::<u8>(), LEVEL_SIZE);
            } else {
                return -EINVAL;
            }
        }
        0
    }
}

/// `mls_convert_context()`.
#[no_mangle]
pub unsafe extern "C" fn mls_convert_context(oldp: *mut c_void, newp: *mut c_void, oldc: *mut c_void, newc: *mut c_void) -> c_int {
    unsafe {
        if !mls_enabled(oldp) || !mls_enabled(newp) {
            return 0;
        }
        for l in 0..2usize {
            let name = sym_name(oldp, SYM_LEVELS, sens(level(oldc, C_RANGE, l)).wrapping_sub(1));
            let levdatum = symtab_search(symtab(newp, SYM_LEVELS), name);
            if levdatum.is_null() {
                return -EINVAL;
            }
            wr32(level(newc, C_RANGE, l), L_SENS, sens(levdatum.cast::<u8>().add(LD_LEVEL).cast()));

            let mut it = Bits::new(cat(level(oldc, C_RANGE, l)));
            let hb = it.highbit();
            let mut i = it.start();
            while i < hb {
                let catdatum = symtab_search(symtab(newp, SYM_CATS), sym_name(oldp, SYM_CATS, i));
                if catdatum.is_null() {
                    return -EINVAL;
                }
                let rc = ebitmap_set_bit(cat(level(newc, C_RANGE, l)), rd32(catdatum, CD_VALUE).wrapping_sub(1), 1);
                if rc != 0 {
                    return rc;
                }
                i = it.next(i);
            }
        }
        0
    }
}

// The mls_context_cpy* / glblub helpers of context.h.
unsafe fn cpy_levels(dst: *mut c_void, src: *const c_void, src0: usize, src1: usize) -> c_int {
    unsafe {
        // dst level 0 <- src level src0, dst level 1 <- src level src1; on failure of the second copy level 0's categories are destroyed.
        let d0 = level(dst, C_RANGE, 0);
        let d1 = level(dst, C_RANGE, 1);
        let s0 = level(src as *mut c_void, C_RANGE, src0);
        let s1 = level(src as *mut c_void, C_RANGE, src1);
        wr32(d0, L_SENS, sens(s0));
        let rc = ebitmap_cpy(cat(d0), cat(s0));
        if rc != 0 {
            return rc;
        }
        wr32(d1, L_SENS, sens(s1));
        let rc = ebitmap_cpy(cat(d1), cat(s1));
        if rc != 0 {
            ebitmap_destroy(cat(d0));
        }
        rc
    }
}
unsafe fn mls_context_cpy(dst: *mut c_void, src: *const c_void) -> c_int {
    unsafe {
        cpy_levels(dst, src, 0, 1)
    }
}
unsafe fn mls_context_cpy_low(dst: *mut c_void, src: *const c_void) -> c_int {
    unsafe {
        cpy_levels(dst, src, 0, 0)
    }
}
unsafe fn mls_context_cpy_high(dst: *mut c_void, src: *const c_void) -> c_int {
    unsafe {
        cpy_levels(dst, src, 1, 1)
    }
}
unsafe fn mls_context_glblub(dst: *mut c_void, c1: *const c_void, c2: *const c_void) -> c_int {
    unsafe {
        let r1 = |l| level(c1 as *mut c_void, C_RANGE, l);
        let r2 = |l| level(c2 as *mut c_void, C_RANGE, l);
        if sens(r1(1)) < sens(r2(0)) || sens(r2(1)) < sens(r1(0)) {
            // These ranges have no common sensitivities
            return -EINVAL;
        }
        // Take the greatest of the low
        wr32(level(dst, C_RANGE, 0), L_SENS, sens(r1(0)).max(sens(r2(0))));
        // Take the least of the high
        wr32(level(dst, C_RANGE, 1), L_SENS, sens(r1(1)).min(sens(r2(1))));
        let rc = ebitmap_and(cat(level(dst, C_RANGE, 0)), cat(r1(0)), cat(r2(0)));
        if rc != 0 {
            return rc;
        }
        ebitmap_and(cat(level(dst, C_RANGE, 1)), cat(r1(1)), cat(r2(1)))
    }
}

/// `mls_compute_sid()`.
#[no_mangle]
pub unsafe extern "C" fn mls_compute_sid(
    p: *mut c_void,
    scontext: *mut c_void,
    tcontext: *mut c_void,
    tclass: u16,
    specified: u32,
    newcontext: *mut c_void,
    sock: bool,
) -> c_int {
    unsafe {
        if !mls_enabled(p) {
            return 0;
        }
        // `case AVTAB_TRANSITION` falls through into `case AVTAB_CHANGE`.
        let mut change = specified == AVTAB_CHANGE;
        if specified == AVTAB_TRANSITION {
            // Look for a range transition rule.
            let mut rtr = RangeTrans { source_type: rd32(scontext, 8), target_type: rd32(tcontext, 8), target_class: tclass };
            let r = policydb_rangetr_search(p, &mut rtr);
            if !r.is_null() {
                return mls_range_set(newcontext, r);
            }

            let mut default_range: i8 = 0;
            if tclass != 0 && (tclass as u32) <= nprim(p, 1) {
                let cladatum = rdp(p, P_CLASS_VAL_TO_STRUCT).cast::<*mut c_void>().add(tclass as usize - 1).read();
                if !cladatum.is_null() {
                    default_range = cladatum.cast::<u8>().add(CLD_DEFAULT_RANGE).cast::<i8>().read();
                }
            }

            match default_range {
                DEFAULT_SOURCE_LOW => return mls_context_cpy_low(newcontext, scontext),
                DEFAULT_SOURCE_HIGH => return mls_context_cpy_high(newcontext, scontext),
                DEFAULT_SOURCE_LOW_HIGH => return mls_context_cpy(newcontext, scontext),
                DEFAULT_TARGET_LOW => return mls_context_cpy_low(newcontext, tcontext),
                DEFAULT_TARGET_HIGH => return mls_context_cpy_high(newcontext, tcontext),
                DEFAULT_TARGET_LOW_HIGH => return mls_context_cpy(newcontext, tcontext),
                DEFAULT_GLBLUB => return mls_context_glblub(newcontext, scontext, tcontext),
                _ => {}
            }
            change = true;
        }
        if change {
            let process_class = p.cast::<u8>().add(P_PROCESS_CLASS).cast::<u16>().read_unaligned();
            return if tclass == process_class || sock {
                // Use the process MLS attributes.
                mls_context_cpy(newcontext, scontext)
            } else {
                // Use the process effective MLS attributes.
                mls_context_cpy_low(newcontext, scontext)
            };
        }
        if specified == AVTAB_MEMBER {
            // Use the process effective MLS attributes.
            return mls_context_cpy_low(newcontext, scontext);
        }
        -EINVAL
    }
}
