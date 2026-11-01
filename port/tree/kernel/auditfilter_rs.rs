// SPDX-License-Identifier: GPL-2.0-or-later

//! The pure checks of `kernel/auditfilter.c` -- the Rust behind them.
//!
//! Ported from `kernel/auditfilter.c` (6.18.49, `CONFIG_AUDIT`): `audit_comparator()` and the uid / gid comparators (one function over the numeric ids), `audit_to_op()`,
//! `audit_field_valid()` (which field types are allowed on which filter list, with which operators and values), `parent_len()` and `audit_compare_dname_path()`. In C
//! (`auditfilter_glue.c`): everything with rule structures, lists, locks, strings from user space and the LSM -- the exports and the `kuid_t` / `kgid_t` / `qstr` wrappers that hand over
//! the numbers. Every `AUDIT_*`, `Audit_*`, `S_IFMT` and `AF_MAX` constant used here is checked against the headers by `static_assert`s in the glue.
//!
//! Replaces: kernel/auditfilter.c (the comparators, field validation and path helpers)

use core::ffi::{c_char, c_int, c_void};

const EINVAL: c_int = 22;

const AUDIT_EQUAL_: u32 = 0; // Audit_equal
const AUDIT_NOT_EQUAL_: u32 = 1;
const AUDIT_BITMASK_: u32 = 2;
const AUDIT_BITTEST_: u32 = 3;
const AUDIT_LT_: u32 = 4;
const AUDIT_GT_: u32 = 5;
const AUDIT_LE_: u32 = 6;
const AUDIT_GE_: u32 = 7;
const AUDIT_BAD_: u32 = 8;

const FILTER_USER: u32 = 0x00;
const FILTER_EXCLUDE: u32 = 0x05;
const FILTER_FS: u32 = 0x06;
const FILTER_URING_EXIT: u32 = 0x07;

const MSGTYPE: u32 = 12;
const FSTYPE: u32 = 26;
const PERM: u32 = 106;
const FILTERKEY: u32 = 210;
const ARG0: u32 = 200;
const ARG1: u32 = 201;
const ARG2: u32 = 202;
const ARG3: u32 = 203;
const PERS: u32 = 10;
const DEVMINOR: u32 = 101;
const UID: u32 = 1;
const EUID: u32 = 2;
const SUID: u32 = 3;
const FSUID: u32 = 4;
const LOGINUID: u32 = 9;
const OBJ_UID: u32 = 109;
const GID: u32 = 5;
const EGID: u32 = 6;
const SGID: u32 = 7;
const FSGID: u32 = 8;
const OBJ_GID: u32 = 110;
const PID: u32 = 0;
const PPID: u32 = 18;
const DEVMAJOR: u32 = 100;
const EXIT: u32 = 103;
const SUCCESS: u32 = 104;
const INODE: u32 = 102;
const SESSIONID: u32 = 25;
const SUBJ_SEN: u32 = 16;
const SUBJ_CLR: u32 = 17;
const OBJ_LEV_LOW: u32 = 22;
const OBJ_LEV_HIGH: u32 = 23;
const SADDR_FAM: u32 = 113;
const SUBJ_USER: u32 = 13;
const SUBJ_ROLE: u32 = 14;
const SUBJ_TYPE: u32 = 15;
const OBJ_USER: u32 = 19;
const OBJ_ROLE: u32 = 20;
const OBJ_TYPE: u32 = 21;
const WATCH: u32 = 105;
const DIR: u32 = 107;
const LOGINUID_SET: u32 = 24;
const ARCH: u32 = 11;
const FILETYPE: u32 = 108;
const FIELD_COMPARE: u32 = 111;
const EXE: u32 = 112;
const MAX_FIELD_COMPARE: u32 = 25;
const S_IFMT: u32 = 0o170000;
const AF_MAX: u32 = 46;
const AUDIT_NAME_FULL: c_int = -1;

extern "C" {
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
}

/// `audit_comparator()`: the 32-bit values compared by the rule's operator; the bit operators give the masked value (non-zero) or a test.
#[no_mangle]
pub extern "C" fn rust_audit_comparator(left: u32, op: u32, right: u32) -> c_int {
    match op {
        AUDIT_EQUAL_ => (left == right) as c_int,
        AUDIT_NOT_EQUAL_ => (left != right) as c_int,
        AUDIT_LT_ => (left < right) as c_int,
        AUDIT_LE_ => (left <= right) as c_int,
        AUDIT_GT_ => (left > right) as c_int,
        AUDIT_GE_ => (left >= right) as c_int,
        AUDIT_BITMASK_ => (left & right) as c_int,
        AUDIT_BITTEST_ => ((left & right) == right) as c_int,
        _ => 0,
    }
}

/// `audit_uid_comparator()` / `audit_gid_comparator()` on the numeric ids: no bit operators.
#[no_mangle]
pub extern "C" fn rust_audit_id_comparator(left: u32, op: u32, right: u32) -> c_int {
    match op {
        AUDIT_EQUAL_ => (left == right) as c_int,
        AUDIT_NOT_EQUAL_ => (left != right) as c_int,
        AUDIT_LT_ => (left < right) as c_int,
        AUDIT_LE_ => (left <= right) as c_int,
        AUDIT_GT_ => (left > right) as c_int,
        AUDIT_GE_ => (left >= right) as c_int,
        _ => 0,
    }
}

/// `audit_to_op()`: the index of `op` in the operator table (`Audit_bad` when absent); `ops` has `Audit_bad` entries.
///
/// # Safety
/// `ops` is valid for `Audit_bad` reads.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_to_op(op: u32, ops: *const u32) -> u32 {
    let mut n = AUDIT_EQUAL_;
    // SAFETY: the table has `Audit_bad` entries and `n` stays below that.
    while n < AUDIT_BAD_ && unsafe { *ops.add(n as usize) } != op {
        n += 1;
    }
    n
}

/// `audit_field_valid()`: is this field type allowed on the filter list `listnr`, with this operator and value. 0 or `-EINVAL`.
#[no_mangle]
pub extern "C" fn rust_audit_field_valid(listnr: u32, ftype: u32, op: u32, val: u32) -> c_int {
    match ftype {
        MSGTYPE => {
            if listnr != FILTER_EXCLUDE && listnr != FILTER_USER {
                return -EINVAL;
            }
        }
        FSTYPE => {
            if listnr != FILTER_FS {
                return -EINVAL;
            }
        }
        PERM => {
            if listnr == FILTER_URING_EXIT {
                return -EINVAL;
            }
        }
        _ => {}
    }

    if listnr == FILTER_FS {
        match ftype {
            FSTYPE | FILTERKEY => {}
            _ => return -EINVAL,
        }
    }

    // Check for valid field type and op
    match ftype {
        // all ops are valid
        ARG0 | ARG1 | ARG2 | ARG3 | PERS | DEVMINOR => {}
        // bit ops are only useful on syscall args
        UID | EUID | SUID | FSUID | LOGINUID | OBJ_UID | GID | EGID | SGID | FSGID | OBJ_GID | PID | MSGTYPE | PPID | DEVMAJOR | EXIT | SUCCESS | INODE | SESSIONID | SUBJ_SEN
        | SUBJ_CLR | OBJ_LEV_LOW | OBJ_LEV_HIGH | SADDR_FAM => {
            if op == AUDIT_BITMASK_ || op == AUDIT_BITTEST_ {
                return -EINVAL;
            }
        }
        // only equal and not equal valid ops
        SUBJ_USER | SUBJ_ROLE | SUBJ_TYPE | OBJ_USER | OBJ_ROLE | OBJ_TYPE | WATCH | DIR | FILTERKEY | LOGINUID_SET | ARCH | FSTYPE | PERM | FILETYPE | FIELD_COMPARE | EXE => {
            if op != AUDIT_NOT_EQUAL_ && op != AUDIT_EQUAL_ {
                return -EINVAL;
            }
        }
        // field not recognized
        _ => return -EINVAL,
    }

    // Check for select valid field values
    match ftype {
        LOGINUID_SET => {
            if val != 0 && val != 1 {
                return -EINVAL;
            }
        }
        PERM => {
            if val & !15 != 0 {
                return -EINVAL;
            }
        }
        FILETYPE => {
            if val & !S_IFMT != 0 {
                return -EINVAL;
            }
        }
        FIELD_COMPARE => {
            if val > MAX_FIELD_COMPARE {
                return -EINVAL;
            }
        }
        SADDR_FAM => {
            if val >= AF_MAX {
                return -EINVAL;
            }
        }
        _ => {}
    }

    0
}

/// `parent_len()`: the length of the parent portion of a path (the slash that ends it included).
///
/// # Safety
/// `path` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_parent_len(path: *const c_char) -> c_int {
    // SAFETY: `path` is NUL-terminated; `p` stays within `[path, path + plen)`.
    unsafe {
        let mut plen = 0usize;
        while *path.add(plen) != 0 {
            plen += 1;
        }

        if plen == 0 {
            return plen as c_int;
        }

        // disregard trailing slashes
        let mut p = path.add(plen - 1);
        while *p == b'/' as c_char && p > path {
            p = p.sub(1);
        }

        // walk backward until we find the next slash or hit beginning
        while *p != b'/' as c_char && p > path {
            p = p.sub(1);
        }

        // did we find a slash? Then increment to include it in path
        if *p == b'/' as c_char {
            p = p.add(1);
        }

        p.offset_from(path) as c_int
    }
}

/// `audit_compare_dname_path()`: compare a dentry name (`dlen` bytes at `dname`) with the last component of `path`; 0 is a match. `parentlen` is `AUDIT_NAME_FULL` (-1) to compute it.
///
/// # Safety
/// `dname` is valid for `dlen` bytes; `path` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_compare_dname_path(dlen: c_int, dname: *const u8, path: *const c_char, parentlen: c_int) -> c_int {
    // SAFETY: as the contract says.
    unsafe {
        let mut n = 0usize;
        while *path.add(n) != 0 {
            n += 1;
        }
        let mut pathlen = n as c_int;
        if pathlen < dlen {
            return 1;
        }

        let parentlen = if parentlen == AUDIT_NAME_FULL { rust_audit_parent_len(path) } else { parentlen };

        let p = path.offset(parentlen as isize);

        // handle trailing slashes
        pathlen -= parentlen;
        while pathlen > 0 && *p.offset((pathlen - 1) as isize) == b'/' as c_char {
            pathlen -= 1;
        }

        if pathlen != dlen {
            return 1;
        }

        memcmp(p as *const c_void, dname as *const c_void, dlen as usize)
    }
}
