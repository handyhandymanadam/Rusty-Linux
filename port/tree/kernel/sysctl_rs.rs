// SPDX-License-Identifier: GPL-2.0

//! The text engine of `kernel/sysctl.c` (the `/proc/sys` integer handlers) -- the Rust behind it.
//!
//! Ported from `kernel/sysctl.c` (6.18.49, `CONFIG_PROC_SYSCTL`): the buffer primitives (`proc_skip_spaces`, `proc_skip_char`, `strtoul_lenient`, `proc_get_long`, `proc_put_long`,
//! `proc_put_char`), the read/write loops of `__do_proc_dointvec`, `do_proc_douintvec_w`, `do_proc_douintvec_r` and `__do_proc_doulongvec_minmax`, and the conversion callbacks
//! `do_proc_dointvec_conv`, `do_proc_douintvec_conv`, the two min/max ones and the jiffies one. In C (`sysctl_glue.c`): every exported handler, the `ctl_table` plumbing, the string,
//! bitmap and `ms`/`USER_HZ` handlers, the sysctl registration tree, and wrappers for what needs kernel macros (`isspace()` from the `_ctype` table, the first-position policy with its
//! `pr_warn_once`). The conversion callbacks are also handed to other C code as function pointers; the glue keeps `static` entry points that call these.
//!
//! The numbers are the C's: unsigned long arithmetic wraps; `int` conversions truncate; `-*lvalp` is the unsigned negation. Values are read and written with volatile accesses where C
//! uses `READ_ONCE` / `WRITE_ONCE`.
//!
//! Replaces: kernel/sysctl.c (the integer-handler text engine)

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_ulonglong, c_void};
use core::ptr::{null, null_mut, read_volatile, write_volatile};

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const TMPBUFLEN: usize = 22;
const KSTRTOX_OVERFLOW: c_uint = 1 << 31;
const INT_MAX: c_ulong = i32::MAX as c_ulong;

extern "C" {
    fn _parse_integer_fixup_radix(s: *const c_char, base: *mut c_uint) -> *const c_char;
    fn _parse_integer(s: *const c_char, base: c_uint, p: *mut c_ulonglong) -> c_uint;
    fn rust_sysctl_isspace(c: c_int) -> bool;
    fn rust_sysctl_first_pos(ppos: *mut i64, table: *const c_void) -> bool;
}

/// The whitespace separators `proc_wspace_sep`.
static WSPACE_SEP: [c_char; 3] = [b' ' as c_char, b'\t' as c_char, b'\n' as c_char];

/// `proc_skip_spaces()`.
///
/// # Safety
/// `buf` points to a pointer to at least `*size` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_skip_spaces(buf: *mut *mut c_char, size: *mut usize) {
    // SAFETY: the caller's buffer is valid for `*size` bytes.
    unsafe {
        while *size != 0 {
            if !rust_sysctl_isspace(**buf as u8 as c_int) {
                break;
            }
            *size -= 1;
            *buf = (*buf).add(1);
        }
    }
}

/// `proc_skip_char()`.
///
/// # Safety
/// As [`rust_sysctl_skip_spaces`].
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_skip_char(buf: *mut *mut c_char, size: *mut usize, v: c_char) {
    // SAFETY: the caller's buffer is valid for `*size` bytes.
    unsafe {
        while *size != 0 {
            if **buf != v {
                break;
            }
            *size -= 1;
            *buf = (*buf).add(1);
        }
    }
}

/// `strtoul_lenient()`: parse an integer, fail only on overflow.
///
/// # Safety
/// `cp` is a NUL-terminated string; `endp` may be NULL; `res` is valid for writes.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_strtoul_lenient(cp: *const c_char, endp: *mut *mut c_char, base: c_uint, res: *mut c_ulong) -> c_int {
    // SAFETY: the caller passes a NUL-terminated string and valid pointers.
    unsafe {
        let mut base = base;
        let mut result: c_ulonglong = 0;
        let cp = _parse_integer_fixup_radix(cp, &mut base);
        let rv = _parse_integer(cp, base, &mut result);
        if (rv & KSTRTOX_OVERFLOW) != 0 || result != (result as c_ulong) as c_ulonglong {
            return -ERANGE;
        }

        let cp = cp.add(rv as usize);
        if !endp.is_null() {
            *endp = cp as *mut c_char;
        }
        *res = result as c_ulong;
        0
    }
}

/// `proc_get_long()`: read an integer from a kernel buffer; `perm_tr` lists the allowed trailing characters, `tr` receives the trailer.
///
/// # Safety
/// `buf` points to a pointer to `*size` readable bytes; `perm_tr` to `perm_tr_len` bytes; the out pointers are valid (`tr` may be NULL).
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_get_long(
    buf: *mut *mut c_char,
    size: *mut usize,
    val: *mut c_ulong,
    neg: *mut bool,
    perm_tr: *const c_char,
    perm_tr_len: c_uint,
    tr: *mut c_char,
) -> c_int {
    // SAFETY: as the safety contract says; `tmp` is a local array and `p` stays inside it.
    unsafe {
        let mut tmp = [0 as c_char; TMPBUFLEN];
        let mut len = *size as isize;

        if len <= 0 {
            return -EINVAL;
        }
        if len > (TMPBUFLEN - 1) as isize {
            len = (TMPBUFLEN - 1) as isize;
        }

        core::ptr::copy_nonoverlapping(*buf, tmp.as_mut_ptr(), len as usize);
        tmp[len as usize] = 0;

        let mut p: *mut c_char = tmp.as_mut_ptr();
        if *p == b'-' as c_char && *size > 1 {
            *neg = true;
            p = p.add(1);
        } else {
            *neg = false;
        }
        if !(b'0' as c_char <= *p && *p <= b'9' as c_char) {
            return -EINVAL;
        }

        if rust_sysctl_strtoul_lenient(p, &mut p, 0, val) != 0 {
            return -EINVAL;
        }

        let len = p.offset_from(tmp.as_ptr());

        // We don't know if the next char is whitespace thus we may accept invalid integers (e.g. 1234...a) or two integers instead of one (e.g. 123...1): do not allow such
        // large numbers.
        if len == (TMPBUFLEN - 1) as isize {
            return -EINVAL;
        }

        let len = len as usize;
        if len < *size && perm_tr_len != 0 {
            let c = *p as u8;
            let mut found = false;
            let mut k = 0;
            while k < perm_tr_len as usize {
                if *perm_tr.add(k) as u8 == c {
                    found = true;
                    break;
                }
                k += 1;
            }
            if !found {
                return -EINVAL;
            }
        }

        if !tr.is_null() && len < *size {
            *tr = *p;
        }

        *buf = (*buf).add(len);
        *size -= len;
        0
    }
}

/// `proc_put_long()`: write a decimal integer into a buffer, truncated to what is left.
///
/// # Safety
/// `buf` points to a pointer to `*size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_put_long(buf: *mut *mut c_void, size: *mut usize, val: c_ulong, neg: bool) {
    // SAFETY: the caller's buffer is valid for `*size` bytes; at most `*size` are written.
    unsafe {
        let mut tmp = [0u8; TMPBUFLEN];
        let mut digits = [0u8; 20];
        let mut nd = 0;
        let mut v = val;
        loop {
            digits[nd] = b'0' + (v % 10) as u8;
            nd += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut len = 0;
        if neg {
            tmp[len] = b'-';
            len += 1;
        }
        while nd > 0 {
            nd -= 1;
            tmp[len] = digits[nd];
            len += 1;
        }
        if len > *size {
            len = *size;
        }
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), *buf as *mut u8, len);
        *size -= len;
        *buf = (*buf as *mut u8).add(len) as *mut c_void;
    }
}

/// `proc_put_char()`.
///
/// # Safety
/// `buf` points to a pointer to `*size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_put_char(buf: *mut *mut c_void, size: *mut usize, c: c_char) {
    // SAFETY: the caller's buffer is valid for `*size` bytes.
    unsafe {
        if *size != 0 {
            let b = *buf as *mut c_char;
            *b = c;
            *size -= 1;
            *buf = b.add(1) as *mut c_void;
        }
    }
}

/// `do_proc_dointvec_conv()`.
///
/// # Safety
/// The pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_dointvec_conv(negp: *mut bool, lvalp: *mut c_ulong, valp: *mut c_int, write: c_int, _data: *mut c_void) -> c_int {
    // SAFETY: the caller passes valid pointers.
    unsafe {
        if write != 0 {
            if *negp {
                if *lvalp > INT_MAX + 1 {
                    return -EINVAL;
                }
                write_volatile(valp, (*lvalp).wrapping_neg() as c_int);
            } else {
                if *lvalp > INT_MAX {
                    return -EINVAL;
                }
                write_volatile(valp, *lvalp as c_int);
            }
        } else {
            let val = read_volatile(valp);
            if val < 0 {
                *negp = true;
                *lvalp = (val as c_long as c_ulong).wrapping_neg();
            } else {
                *negp = false;
                *lvalp = val as c_ulong;
            }
        }
        0
    }
}

/// `do_proc_douintvec_conv()`.
///
/// # Safety
/// The pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_douintvec_conv(lvalp: *mut c_ulong, valp: *mut c_uint, write: c_int, _data: *mut c_void) -> c_int {
    // SAFETY: the caller passes valid pointers.
    unsafe {
        if write != 0 {
            if *lvalp > c_uint::MAX as c_ulong {
                return -EINVAL;
            }
            write_volatile(valp, *lvalp as c_uint);
        } else {
            *lvalp = read_volatile(valp) as c_ulong;
        }
        0
    }
}

/// The `{ int *min; int *max; }` of `do_proc_dointvec_minmax_conv_param` and the unsigned twin.
#[repr(C)]
pub struct MinMax<T> {
    min: *const T,
    max: *const T,
}

/// `do_proc_dointvec_minmax_conv()`.
///
/// # Safety
/// The pointers are valid; `data` points to a [`MinMax<c_int>`].
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_dointvec_minmax_conv(negp: *mut bool, lvalp: *mut c_ulong, valp: *mut c_int, write: c_int, data: *mut c_void) -> c_int {
    // SAFETY: the caller passes valid pointers.
    unsafe {
        let param = data as *const MinMax<c_int>;
        let mut tmp: c_int = 0;
        let ip = if write != 0 { &mut tmp as *mut c_int } else { valp };

        let ret = rust_sysctl_dointvec_conv(negp, lvalp, ip, write, data);
        if ret != 0 {
            return ret;
        }

        if write != 0 {
            if (!(*param).min.is_null() && *(*param).min > tmp) || (!(*param).max.is_null() && *(*param).max < tmp) {
                return -EINVAL;
            }
            write_volatile(valp, tmp);
        }
        0
    }
}

/// `do_proc_douintvec_minmax_conv()`.
///
/// # Safety
/// The pointers are valid; `data` points to a [`MinMax<c_uint>`].
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_douintvec_minmax_conv(lvalp: *mut c_ulong, valp: *mut c_uint, write: c_int, data: *mut c_void) -> c_int {
    // SAFETY: the caller passes valid pointers.
    unsafe {
        let param = data as *const MinMax<c_uint>;
        let mut tmp: c_uint = 0;
        let up = if write != 0 { &mut tmp as *mut c_uint } else { valp };

        let ret = rust_sysctl_douintvec_conv(lvalp, up, write, data);
        if ret != 0 {
            return ret;
        }

        if write != 0 {
            if (!(*param).min.is_null() && *(*param).min > tmp) || (!(*param).max.is_null() && *(*param).max < tmp) {
                return -ERANGE;
            }
            write_volatile(valp, tmp);
        }
        0
    }
}

/// `do_proc_dointvec_jiffies_conv()`; `hz` is `HZ`.
///
/// # Safety
/// The pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_dointvec_jiffies_conv(negp: *mut bool, lvalp: *mut c_ulong, valp: *mut c_int, write: c_int, hz: c_int) -> c_int {
    // SAFETY: the caller passes valid pointers.
    unsafe {
        let hz_ul = hz as c_ulong;
        if write != 0 {
            if *lvalp > (i32::MAX / hz) as c_ulong {
                return 1;
            }
            if *negp {
                write_volatile(valp, (*lvalp).wrapping_neg().wrapping_mul(hz_ul) as c_int);
            } else {
                write_volatile(valp, (*lvalp).wrapping_mul(hz_ul) as c_int);
            }
        } else {
            let val = read_volatile(valp);
            let lval: c_ulong;
            if val < 0 {
                *negp = true;
                lval = (val as c_long as c_ulong).wrapping_neg();
            } else {
                *negp = false;
                lval = val as c_ulong;
            }
            *lvalp = lval / hz_ul;
        }
        0
    }
}

type ConvInt = unsafe extern "C" fn(*mut bool, *mut c_ulong, *mut c_int, c_int, *mut c_void) -> c_int;
type ConvUint = unsafe extern "C" fn(*mut c_ulong, *mut c_uint, c_int, *mut c_void) -> c_int;

/// `__do_proc_dointvec()`; `conv` is not NULL (the glue substitutes the default), `table` is passed through to the first-position policy.
///
/// # Safety
/// As the C function's contract: `buffer` is a kernel buffer of `*lenp` bytes, `tbl_data` holds `maxlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_do_dointvec(
    tbl_data: *mut c_void,
    maxlen: c_int,
    table: *const c_void,
    write: c_int,
    buffer: *mut c_void,
    lenp: *mut usize,
    ppos: *mut i64,
    conv: ConvInt,
    data: *mut c_void,
    page_size: usize,
) -> c_int {
    // SAFETY: as the safety contract says.
    unsafe {
        let mut err: c_int = 0;
        let mut first = true;
        let mut buffer = buffer;
        let mut p: *mut c_char = null_mut();

        if tbl_data.is_null() || maxlen == 0 || *lenp == 0 || (*ppos != 0 && write == 0) {
            *lenp = 0;
            return 0;
        }

        let mut i = tbl_data as *mut c_int;
        let mut vleft: c_int = maxlen / 4;
        let mut left: usize = *lenp;

        let mut out = false;
        if write != 0 {
            if rust_sysctl_first_pos(ppos, table) {
                out = true;
            } else {
                if left > page_size - 1 {
                    left = page_size - 1;
                }
                p = buffer as *mut c_char;
            }
        }

        if !out {
            while left != 0 && {
                let c = vleft != 0;
                vleft -= 1;
                c
            } {
                let mut lval: c_ulong = 0;
                let mut neg: bool = false;

                if write != 0 {
                    rust_sysctl_skip_spaces(&mut p, &mut left);

                    if left == 0 {
                        break;
                    }
                    err = rust_sysctl_get_long(&mut p, &mut left, &mut lval, &mut neg, WSPACE_SEP.as_ptr(), WSPACE_SEP.len() as c_uint, null_mut());
                    if err != 0 {
                        break;
                    }
                    if conv(&mut neg, &mut lval, i, 1, data) != 0 {
                        err = -EINVAL;
                        break;
                    }
                } else {
                    if conv(&mut neg, &mut lval, i, 0, data) != 0 {
                        err = -EINVAL;
                        break;
                    }
                    if !first {
                        rust_sysctl_put_char(&mut buffer, &mut left, b'\t' as c_char);
                    }
                    rust_sysctl_put_long(&mut buffer, &mut left, lval, neg);
                }
                i = i.add(1);
                first = false;
            }

            if write == 0 && !first && left != 0 && err == 0 {
                rust_sysctl_put_char(&mut buffer, &mut left, b'\n' as c_char);
            }
            if write != 0 && err == 0 && left != 0 {
                rust_sysctl_skip_spaces(&mut p, &mut left);
            }
            if write != 0 && first {
                return if err != 0 { err } else { -EINVAL };
            }
            *lenp -= left;
        }
        *ppos += *lenp as i64;
        err
    }
}

/// `do_proc_douintvec_w()`.
///
/// # Safety
/// As the C function's contract.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_do_douintvec_w(
    tbl_data: *mut c_uint,
    table: *const c_void,
    buffer: *mut c_void,
    lenp: *mut usize,
    ppos: *mut i64,
    conv: ConvUint,
    data: *mut c_void,
    page_size: usize,
) -> c_int {
    // SAFETY: as the safety contract says.
    unsafe {
        let mut lval: c_ulong = 0;
        let mut neg: bool = false;
        let mut p = buffer as *mut c_char;
        let mut left = *lenp;

        if rust_sysctl_first_pos(ppos, table) {
            // This is in keeping with old __do_proc_dointvec()
            *ppos += *lenp as i64;
            return 0;
        }

        if left > page_size - 1 {
            left = page_size - 1;
        }

        rust_sysctl_skip_spaces(&mut p, &mut left);
        if left == 0 {
            return -EINVAL;
        }

        let err = rust_sysctl_get_long(&mut p, &mut left, &mut lval, &mut neg, WSPACE_SEP.as_ptr(), WSPACE_SEP.len() as c_uint, null_mut());
        if err != 0 || neg {
            return -EINVAL;
        }

        if conv(&mut lval, tbl_data, 1, data) != 0 {
            return -EINVAL;
        }

        if left != 0 {
            rust_sysctl_skip_spaces(&mut p, &mut left);
        }
        0
    }
}

/// `do_proc_douintvec_r()`.
///
/// # Safety
/// As the C function's contract.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_do_douintvec_r(tbl_data: *mut c_uint, buffer: *mut c_void, lenp: *mut usize, ppos: *mut i64, conv: ConvUint, data: *mut c_void) -> c_int {
    // SAFETY: as the safety contract says.
    unsafe {
        let mut lval: c_ulong = 0;
        let mut err: c_int = 0;
        let mut buffer = buffer;
        let mut left = *lenp;

        if conv(&mut lval, tbl_data, 0, data) != 0 {
            err = -EINVAL;
        } else {
            rust_sysctl_put_long(&mut buffer, &mut left, lval, false);
            if left != 0 {
                rust_sysctl_put_char(&mut buffer, &mut left, b'\n' as c_char);
            }
        }

        *lenp -= left;
        *ppos += *lenp as i64;
        err
    }
}

/// `__do_proc_doulongvec_minmax()`; `table_min` / `table_max` are `extra1` / `extra2`.
///
/// # Safety
/// As the C function's contract.
#[no_mangle]
pub unsafe extern "C" fn rust_sysctl_do_doulongvec(
    data: *mut c_void,
    maxlen: c_int,
    table: *const c_void,
    table_min: *const c_ulong,
    table_max: *const c_ulong,
    write: c_int,
    buffer: *mut c_void,
    lenp: *mut usize,
    ppos: *mut i64,
    convmul: c_ulong,
    convdiv: c_ulong,
    page_size: usize,
) -> c_int {
    // SAFETY: as the safety contract says.
    unsafe {
        let mut err: c_int = 0;
        let mut first = true;
        let mut buffer = buffer;
        let mut p: *mut c_char = null_mut();

        if data.is_null() || maxlen == 0 || *lenp == 0 || (*ppos != 0 && write == 0) {
            *lenp = 0;
            return 0;
        }

        let mut i = data as *mut c_ulong;
        let min = table_min;
        let max = table_max;
        let mut vleft: c_int = maxlen / core::mem::size_of::<c_ulong>() as c_int;
        let mut left = *lenp;

        if write != 0 {
            if rust_sysctl_first_pos(ppos, table) {
                *ppos += *lenp as i64;
                return err;
            }
            if left > page_size - 1 {
                left = page_size - 1;
            }
            p = buffer as *mut c_char;
        }

        while left != 0 && {
            let c = vleft != 0;
            vleft -= 1;
            c
        } {
            let mut val: c_ulong;

            if write != 0 {
                let mut neg = false;

                rust_sysctl_skip_spaces(&mut p, &mut left);
                if left == 0 {
                    break;
                }

                val = 0;
                err = rust_sysctl_get_long(&mut p, &mut left, &mut val, &mut neg, WSPACE_SEP.as_ptr(), WSPACE_SEP.len() as c_uint, null_mut());
                if err != 0 || neg {
                    err = -EINVAL;
                    break;
                }

                val = convmul.wrapping_mul(val) / convdiv;
                if (min != null() && val < *min) || (max != null() && val > *max) {
                    err = -EINVAL;
                    break;
                }
                write_volatile(i, val);
            } else {
                val = convdiv.wrapping_mul(read_volatile(i)) / convmul;
                if !first {
                    rust_sysctl_put_char(&mut buffer, &mut left, b'\t' as c_char);
                }
                rust_sysctl_put_long(&mut buffer, &mut left, val, false);
            }
            i = i.add(1);
            first = false;
        }

        if write == 0 && !first && left != 0 && err == 0 {
            rust_sysctl_put_char(&mut buffer, &mut left, b'\n' as c_char);
        }
        if write != 0 && err == 0 {
            rust_sysctl_skip_spaces(&mut p, &mut left);
        }
        if write != 0 && first {
            return if err != 0 { err } else { -EINVAL };
        }
        *lenp -= left;
        *ppos += *lenp as i64;
        err
    }
}
