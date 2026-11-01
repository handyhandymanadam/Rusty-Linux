// SPDX-License-Identifier: GPL-2.0-or-later

//! The filesystem mount-parameter parser -- the Rust behind `fs/fs_parser.c`.
//!
//! Ported from `fs/fs_parser.c` (6.18.49, David Howells): looking up a constant by name (`lookup_constant`), matching a parameter against a specification table with the `noxxx`
//! negation rule (`fs_lookup_key`), `__fs_parse()` itself, and the converters that turn a string value into a boolean, 32/64-bit integer (in a given base), enum, file descriptor,
//! uid or gid (`fs_param_is_*`). In C (`fs_parser_glue.c`): every exported symbol as a thunk (so the MODVERSIONS fingerprints keep coming from the C definitions), `bool_names`,
//! `fs_lookup_param` (path lookup), and the `rust_fp_*` wrappers -- reading the bit-field `fs_parameter.type`, the `pr_err`-like `inval_plog` / `warn_plog` message texts (printf-style, so
//! they stay in C), `make_kuid` / `make_kgid` with `current_user_ns()`.
//!
//! Replaces: fs/fs_parser.c (everything except bool_names, fs_lookup_param and fs_validate_description)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null;

const ENOPARAM: c_int = 519;
const INT_MAX: u32 = i32::MAX as u32;

/// `enum fs_value_type`.
const FS_VALUE_IS_FLAG: c_int = 1;
const FS_VALUE_IS_STRING: c_int = 2;
const FS_VALUE_IS_BLOB: c_int = 3;
const FS_VALUE_IS_FILE: c_int = 5;

/// `fs_param_neg_with_no`, `fs_param_can_be_empty`, `fs_param_deprecated`.
const FS_PARAM_NEG_WITH_NO: u16 = 0x0002;
const FS_PARAM_CAN_BE_EMPTY: u16 = 0x0004;
const FS_PARAM_DEPRECATED: u16 = 0x0008;

/// `struct constant_table`.
#[repr(C)]
pub struct ConstantTable {
    name: *const c_char,
    value: c_int,
}

type ParamType = Option<unsafe extern "C" fn(*mut c_void, *const ParameterSpec, *mut c_void, *mut ParseResult) -> c_int>;

/// `struct fs_parameter_spec` (offsets checked by the glue).
#[repr(C)]
pub struct ParameterSpec {
    name: *const c_char,
    type_: ParamType,
    opt: u8,
    flags: u16,
    data: *const c_void,
}

/// `struct fs_parse_result`: the value union is read as 64 bits, as two 32-bit halves.
#[repr(C)]
pub struct ParseResult {
    negated: bool,
    u: u64,
}

impl ParseResult {
    fn set_u32(&mut self, v: u32) {
        // the 32-bit members overlay the low half of the union; the high half keeps what was there
        self.u = (self.u & !0xffff_ffff) | v as u64;
    }
}

extern "C" {
    fn rust_fp_type(param: *const c_void) -> c_int;
    fn rust_fp_key(param: *const c_void) -> *const c_char;
    fn rust_fp_string(param: *const c_void) -> *const c_char;
    fn rust_fp_dirfd(param: *const c_void) -> c_int;
    /// `inval_plog(log, "Bad value for '%s'", key)` and its siblings, by number; returns -EINVAL.
    fn rust_fp_inval(log: *mut c_void, which: c_int, key: *const c_char) -> c_int;
    /// `warn_plog(log, "Deprecated parameter '%s'", key)`
    fn rust_fp_warn_deprecated(log: *mut c_void, key: *const c_char);
    /// `make_kuid(current_user_ns(), v)` / `make_kgid(...)`: 1 and the kernel id in `*out` if valid, else 0.
    fn rust_fp_make_kuid(v: u32, out: *mut u32) -> c_int;
    fn rust_fp_make_kgid(v: u32, out: *mut u32) -> c_int;
    fn kstrtouint(s: *const c_char, base: u32, res: *mut u32) -> c_int;
    fn kstrtoint(s: *const c_char, base: u32, res: *mut i32) -> c_int;
    fn kstrtoull(s: *const c_char, base: u32, res: *mut u64) -> c_int;
}

const INVAL_UNEXPECTED: c_int = 0;
const INVAL_BAD_VALUE: c_int = 1;
const INVAL_UID: c_int = 2;
const INVAL_GID: c_int = 3;

/// `strcmp(a, b) == 0`.
unsafe fn streq(mut a: *const c_char, mut b: *const c_char) -> bool {
    unsafe {
        loop {
            if *a != *b {
                return false;
            }
            if *a == 0 {
                return true;
            }
            a = a.add(1);
            b = b.add(1);
        }
    }
}

/// `__lookup_constant()`.
unsafe fn lookup_constant_node(mut tbl: *const ConstantTable, name: *const c_char) -> *const ConstantTable {
    unsafe {
        while !(*tbl).name.is_null() {
            if streq(name, (*tbl).name) {
                return tbl;
            }
            tbl = tbl.add(1);
        }
        null()
    }
}

/// `lookup_constant()`: the value of `name` in a table, or `not_found`.
#[no_mangle]
pub unsafe extern "C" fn rust_lookup_constant(tbl: *const ConstantTable, name: *const c_char, not_found: c_int) -> c_int {
    unsafe {
        let p = lookup_constant_node(tbl, name);

        if p.is_null() {
            not_found
        } else {
            (*p).value
        }
    }
}

/// `is_flag()`.
unsafe fn is_flag(p: *const ParameterSpec) -> bool {
    unsafe { (*p).type_.is_none() }
}

/// `fs_lookup_key()`: the specification matching the parameter (a flag with `noxxx` negation if allowed), `*negated` set for the negated form.
unsafe fn fs_lookup_key(desc: *const ParameterSpec, param: *const c_void, negated: *mut bool) -> *const ParameterSpec {
    unsafe {
        let mut other: *const ParameterSpec = null();
        let name = rust_fp_key(param);
        let want_flag = rust_fp_type(param) == FS_VALUE_IS_FLAG;

        *negated = false;
        let mut p = desc;
        while !(*p).name.is_null() {
            if streq((*p).name, name) {
                if is_flag(p) == want_flag {
                    return p;
                }
                other = p;
            }
            p = p.add(1);
        }
        if want_flag && *name == b'n' as c_char && *name.add(1) == b'o' as c_char && *name.add(2) != 0 {
            let mut p = desc;
            while !(*p).name.is_null() {
                if streq((*p).name, name.add(2)) && (*p).flags & FS_PARAM_NEG_WITH_NO != 0 {
                    *negated = true;
                    return p;
                }
                p = p.add(1);
            }
        }
        other
    }
}

/// `__fs_parse()`: parse a mount parameter against a specification table; the option number, -ENOPARAM or -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust___fs_parse(log: *mut c_void, desc: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        (*result).u = 0;

        let p = fs_lookup_key(desc, param, &mut (*result).negated);
        if p.is_null() {
            return -ENOPARAM;
        }

        if (*p).flags & FS_PARAM_DEPRECATED != 0 {
            rust_fp_warn_deprecated(log, rust_fp_key(param));
        }

        // Try to turn the type we were given into the type desired by the parameter and give an error if we can't.
        if is_flag(p) {
            if rust_fp_type(param) != FS_VALUE_IS_FLAG {
                return rust_fp_inval(log, INVAL_UNEXPECTED, rust_fp_key(param));
            }
            (*result).u = (!(*result).negated) as u64;
        } else {
            let ret = ((*p).type_.unwrap())(log, p, param, result);
            if ret != 0 {
                return ret;
            }
        }
        (*p).opt as c_int
    }
}

/// `fs_param_bad_value()`.
unsafe fn bad_value(log: *mut c_void, param: *const c_void) -> c_int {
    unsafe { rust_fp_inval(log, INVAL_BAD_VALUE, rust_fp_key(param)) }
}

/// `*param->string == 0 && (p->flags & fs_param_can_be_empty)`.
unsafe fn empty_ok(p: *const ParameterSpec, param: *const c_void) -> bool {
    unsafe { *rust_fp_string(param) == 0 && (*p).flags & FS_PARAM_CAN_BE_EMPTY != 0 }
}

/// `fs_param_is_bool()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_bool(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult, bool_names: *const ConstantTable) -> c_int {
    unsafe {
        if rust_fp_type(param) != FS_VALUE_IS_STRING {
            return bad_value(log, param);
        }
        if empty_ok(p, param) {
            return 0;
        }
        let b = rust_lookup_constant(bool_names, rust_fp_string(param), -1);
        if b == -1 {
            return bad_value(log, param);
        }
        (*result).u = (*result).u & !0xff | (b as u8 as u64);
        0
    }
}

/// `fs_param_is_u32()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_u32(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        let base = (*p).data as usize as u32;
        let mut v: u32 = (*result).u as u32;
        if rust_fp_type(param) != FS_VALUE_IS_STRING {
            return bad_value(log, param);
        }
        if empty_ok(p, param) {
            return 0;
        }
        let rc = kstrtouint(rust_fp_string(param), base, &mut v);
        if rc < 0 {
            return bad_value(log, param);
        }
        (*result).set_u32(v);
        0
    }
}

/// `fs_param_is_s32()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_s32(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        let mut v: i32 = (*result).u as u32 as i32;
        if rust_fp_type(param) != FS_VALUE_IS_STRING {
            return bad_value(log, param);
        }
        if empty_ok(p, param) {
            return 0;
        }
        if kstrtoint(rust_fp_string(param), 0, &mut v) < 0 {
            return bad_value(log, param);
        }
        (*result).set_u32(v as u32);
        0
    }
}

/// `fs_param_is_u64()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_u64(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        let mut v: u64 = (*result).u;
        if rust_fp_type(param) != FS_VALUE_IS_STRING {
            return bad_value(log, param);
        }
        if empty_ok(p, param) {
            return 0;
        }
        if kstrtoull(rust_fp_string(param), 0, &mut v) < 0 {
            return bad_value(log, param);
        }
        (*result).u = v;
        0
    }
}

/// `fs_param_is_enum()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_enum(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        if rust_fp_type(param) != FS_VALUE_IS_STRING {
            return bad_value(log, param);
        }
        if empty_ok(p, param) {
            return 0;
        }
        let c = lookup_constant_node((*p).data as *const ConstantTable, rust_fp_string(param));
        if c.is_null() {
            return bad_value(log, param);
        }
        (*result).set_u32((*c).value as u32);
        0
    }
}

/// `fs_param_is_string()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_string(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void) -> c_int {
    unsafe {
        if rust_fp_type(param) != FS_VALUE_IS_STRING || (*rust_fp_string(param) == 0 && (*p).flags & FS_PARAM_CAN_BE_EMPTY == 0) {
            return bad_value(log, param);
        }
        0
    }
}

/// `fs_param_is_blob()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_blob(log: *mut c_void, param: *mut c_void) -> c_int {
    unsafe {
        if rust_fp_type(param) != FS_VALUE_IS_BLOB {
            return bad_value(log, param);
        }
        0
    }
}

/// `fs_param_is_fd()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_fd(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        match rust_fp_type(param) {
            FS_VALUE_IS_STRING => 'string: {
                let mut v: u32 = (*result).u as u32;
                if (*rust_fp_string(param) == 0 && (*p).flags & FS_PARAM_CAN_BE_EMPTY == 0) || kstrtouint(rust_fp_string(param), 0, &mut v) < 0 {
                    break 'string;
                }
                (*result).set_u32(v);
                if v <= INT_MAX {
                    return 0;
                }
            }
            FS_VALUE_IS_FILE => {
                let v = rust_fp_dirfd(param) as u32;
                (*result).set_u32(v);
                if v <= INT_MAX {
                    return 0;
                }
            }
            _ => {}
        }
        bad_value(log, param)
    }
}

/// `fs_param_is_file_or_string()`.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_file_or_string(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        match rust_fp_type(param) {
            FS_VALUE_IS_STRING => return rust_fs_param_is_string(log, p, param),
            FS_VALUE_IS_FILE => {
                let v = rust_fp_dirfd(param) as u32;
                (*result).set_u32(v);
                if v <= INT_MAX {
                    return 0;
                }
            }
            _ => {}
        }
        bad_value(log, param)
    }
}

/// `fs_param_is_uid()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_uid(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        if rust_fs_param_is_u32(log, p, param, result) != 0 {
            return bad_value(log, param);
        }

        let mut id: u32 = 0;
        if rust_fp_make_kuid((*result).u as u32, &mut id) == 0 {
            return rust_fp_inval(log, INVAL_UID, rust_fp_string(param));
        }

        (*result).set_u32(id);
        0
    }
}

/// `fs_param_is_gid()`: convert the value of a mount parameter of that kind into `result`, or log and return -EINVAL.
#[no_mangle]
pub unsafe extern "C" fn rust_fs_param_is_gid(log: *mut c_void, p: *const ParameterSpec, param: *mut c_void, result: *mut ParseResult) -> c_int {
    unsafe {
        if rust_fs_param_is_u32(log, p, param, result) != 0 {
            return bad_value(log, param);
        }

        let mut id: u32 = 0;
        if rust_fp_make_kgid((*result).u as u32, &mut id) == 0 {
            return rust_fp_inval(log, INVAL_GID, rust_fp_string(param));
        }

        (*result).set_u32(id);
        0
    }
}
