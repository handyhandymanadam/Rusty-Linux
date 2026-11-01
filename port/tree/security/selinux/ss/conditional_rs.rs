// SPDX-License-Identifier: GPL-2.0-only

//! SELinux conditional policy -- the Rust behind `security/selinux/ss/conditional.c`.
//!
//! Ported from `security/selinux/ss/conditional.c` (6.18.49, Tresys): boolean values and the reverse-Polish conditional expressions over them (`cond_evaluate_expr`,
//! `evaluate_cond_nodes`), enabling and disabling the rules of the true and false lists, reading and writing booleans and the conditional list of a policy file (including the
//! type-rule conflict checks of `cond_insertf`), the conditional part of the access decision (`cond_compute_av`, `cond_compute_xperms`), and duplicating / destroying the
//! conditional state of a `policydb` for a policy reload. The `struct policydb` fields it touches are read at fixed offsets that `conditional_glue.c` asserts. In C
//! (`conditional_glue.c`): those layout checks and `rust_cd_*` wrappers for `kfree` / `kcalloc` / `kzalloc` / `kmemdup`, `str_read`, `avtab_hash_eval` and the `pr_err` texts.
//!
//! Replaces: security/selinux/ss/conditional.c (everything)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

// Offsets in `struct policydb` (asserted by the glue).
const OFF_BOOLS_TABLE: usize = 128; // p_bools.table (symtab[SYM_BOOLS])
const OFF_BOOLS_NPRIM: usize = 144; // p_bools.nprim
const OFF_SYM_VAL_TO_NAME_BOOLS: usize = 240; // sym_val_to_name[SYM_BOOLS]
const OFF_TE_AVTAB: usize = 296;
const OFF_BOOL_VAL_TO_STRUCT: usize = 376;
const OFF_TE_COND_AVTAB: usize = 384;
const OFF_COND_LIST: usize = 408;
const OFF_COND_LIST_LEN: usize = 416;

const AVTAB_ALLOWED: u16 = 0x0001;
const AVTAB_AUDITALLOW: u16 = 0x0002;
const AVTAB_AUDITDENY: u16 = 0x0004;
const AVTAB_TYPE: u16 = 0x0070;
const AVTAB_XPERMS: u16 = 0x0700;
const AVTAB_ENABLED: u16 = 0x8000;

const COND_EXPR_MAXDEPTH: usize = 10;
const COND_BOOL: u32 = 1;
const COND_NOT: u32 = 2;
const COND_OR: u32 = 3;
const COND_AND: u32 = 4;
const COND_XOR: u32 = 5;
const COND_EQ: u32 = 6;
const COND_NEQ: u32 = 7;
const COND_LAST: u32 = COND_NEQ;

/// `struct avtab_key`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvKey {
    source_type: u16,
    target_type: u16,
    target_class: u16,
    specified: u16,
}

/// `struct avtab_node` (its datum is an 8-byte union).
#[repr(C)]
pub struct AvNode {
    key: AvKey,
    datum: u64,
    next: *mut AvNode,
}

/// `struct cond_bool_datum`.
#[repr(C)]
pub struct BoolDatum {
    value: u32,
    state: c_int,
}

/// `struct cond_expr_node`.
#[repr(C)]
pub struct ExprNode {
    expr_type: u32,
    boolean: u32,
}

/// `struct cond_expr`.
#[repr(C)]
pub struct Expr {
    nodes: *mut ExprNode,
    len: u32,
}

/// `struct cond_av_list`.
#[repr(C)]
pub struct AvList {
    nodes: *mut *mut AvNode,
    len: u32,
}

/// `struct cond_node`.
#[repr(C)]
pub struct CondNode {
    cur_state: c_int,
    expr: Expr,
    true_list: AvList,
    false_list: AvList,
}

/// `struct policy_file`.
#[repr(C)]
pub struct PolicyFile {
    data: *mut u8,
    len: usize,
}

/// `struct policy_data`.
#[repr(C)]
pub struct PolicyData {
    p: *mut c_void,
    fp: *mut PolicyFile,
}

/// `struct cond_insertf_data`.
#[repr(C)]
struct InsertData {
    p: *mut c_void,
    dst: *mut *mut AvNode,
    other: *mut AvList,
}

/// `struct av_decision` (the first three words).
#[repr(C)]
pub struct AvDecision {
    allowed: u32,
    auditallow: u32,
    auditdeny: u32,
}

/// `struct hashtab_node`.
#[repr(C)]
pub struct HtNode {
    key: *mut c_void,
    datum: *mut c_void,
    next: *mut HtNode,
}

const _: () = assert!(core::mem::size_of::<AvNode>() == 24 && core::mem::size_of::<CondNode>() == 56 && core::mem::size_of::<BoolDatum>() == 8);

extern "C" {
    fn rust_cd_kfree(p: *mut c_void);
    fn rust_cd_kcalloc(n: u32, size: usize) -> *mut c_void;
    fn rust_cd_kzalloc(size: usize) -> *mut c_void;
    fn rust_cd_kmemdup(src: *const c_void, size: usize) -> *mut c_void;
    fn rust_cd_str_read(strp: *mut *mut c_char, fp: *mut PolicyFile, len: u32) -> c_int;
    fn rust_cd_hash_eval(h: *mut c_void);
    fn rust_cd_err(which: c_int);
    fn services_compute_xperms_decision(xpermd: *mut c_void, node: *mut AvNode);
    fn services_compute_xperms_drivers(xperms: *mut c_void, node: *mut AvNode);

    fn avtab_init(h: *mut c_void);
    fn avtab_destroy(h: *mut c_void);
    fn avtab_alloc(h: *mut c_void, nrules: u32) -> c_int;
    fn avtab_alloc_dup(new: *mut c_void, orig: *const c_void) -> c_int;
    fn avtab_search_node(h: *mut c_void, key: *const AvKey) -> *mut AvNode;
    fn avtab_search_node_next(node: *mut AvNode, specified: u16) -> *mut AvNode;
    fn avtab_insert_nonunique(h: *mut c_void, key: *const AvKey, datum: *const u64) -> *mut AvNode;
    fn avtab_read_item(
        a: *mut c_void,
        fp: *mut PolicyFile,
        pol: *const c_void,
        insertf: unsafe extern "C" fn(*mut c_void, *const AvKey, *const u64, *mut c_void) -> c_int,
        p: *mut c_void,
        conditional: bool,
    ) -> c_int;
    fn avtab_write_item(p: *const c_void, cur: *const AvNode, fp: *mut PolicyFile) -> c_int;
    fn hashtab_duplicate(
        new: *mut c_void,
        orig: *const c_void,
        copy: unsafe extern "C" fn(*mut HtNode, *const HtNode, *mut c_void) -> c_int,
        destroy: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int,
        args: *mut c_void,
    ) -> c_int;
    fn hashtab_map(h: *mut c_void, apply: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int, args: *mut c_void) -> c_int;
    fn hashtab_destroy(h: *mut c_void);
    fn symtab_insert(s: *mut c_void, name: *mut c_char, datum: *mut c_void) -> c_int;
}

const E_UNDEFINED: c_int = 0;
const E_READ_BOOL: c_int = 1;
const E_TYPE_EXISTS: c_int = 2;
const E_TOO_MANY: c_int = 3;
const E_CONFLICT: c_int = 4;
const E_CONFLICT_TRUE: c_int = 5;
const E_INSERT: c_int = 6;
const E_UNKNOWN_OP: c_int = 7;
const E_UNKNOWN_BOOL: c_int = 8;

#[inline(always)]
unsafe fn field<T>(p: *const c_void, off: usize) -> *mut T {
    unsafe { (p as *mut u8).add(off) as *mut T }
}

/// `next_entry()` of policydb.h.
unsafe fn next_entry(buf: *mut u8, fp: *mut PolicyFile, bytes: usize) -> c_int {
    unsafe {
        if bytes > (*fp).len {
            return -EINVAL;
        }
        core::ptr::copy_nonoverlapping((*fp).data, buf, bytes);
        (*fp).data = (*fp).data.add(bytes);
        (*fp).len -= bytes;
        0
    }
}

/// `put_entry()` of policydb.h.
unsafe fn put_entry(buf: *const u8, bytes: usize, num: usize, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let len = match bytes.checked_mul(num) {
            Some(l) => l,
            None => return -EINVAL,
        };
        if len > (*fp).len {
            return -EINVAL;
        }
        core::ptr::copy_nonoverlapping(buf, (*fp).data, len);
        (*fp).data = (*fp).data.add(len);
        (*fp).len -= len;
        0
    }
}

/// `cond_evaluate_expr()`: true (1), false (0) or undefined (-1; the stack is too deep or the expression malformed).
unsafe fn cond_evaluate_expr(p: *mut c_void, expr: *mut Expr) -> c_int {
    unsafe {
        let mut s = [0 as c_int; COND_EXPR_MAXDEPTH];
        let mut sp: isize = -1;

        if (*expr).len == 0 {
            return -1;
        }

        let mut i = 0;
        while i < (*expr).len {
            let node = (*expr).nodes.add(i as usize);

            match (*node).expr_type {
                COND_BOOL => {
                    if sp == COND_EXPR_MAXDEPTH as isize - 1 {
                        return -1;
                    }
                    sp += 1;
                    let arr = *field::<*mut *mut BoolDatum>(p, OFF_BOOL_VAL_TO_STRUCT);
                    s[sp as usize] = (**arr.add((*node).boolean.wrapping_sub(1) as usize)).state;
                }
                COND_NOT => {
                    if sp < 0 {
                        return -1;
                    }
                    s[sp as usize] = (s[sp as usize] == 0) as c_int;
                }
                COND_OR => {
                    if sp < 1 {
                        return -1;
                    }
                    sp -= 1;
                    s[sp as usize] |= s[sp as usize + 1];
                }
                COND_AND => {
                    if sp < 1 {
                        return -1;
                    }
                    sp -= 1;
                    s[sp as usize] &= s[sp as usize + 1];
                }
                COND_XOR => {
                    if sp < 1 {
                        return -1;
                    }
                    sp -= 1;
                    s[sp as usize] ^= s[sp as usize + 1];
                }
                COND_EQ => {
                    if sp < 1 {
                        return -1;
                    }
                    sp -= 1;
                    s[sp as usize] = (s[sp as usize] == s[sp as usize + 1]) as c_int;
                }
                COND_NEQ => {
                    if sp < 1 {
                        return -1;
                    }
                    sp -= 1;
                    s[sp as usize] = (s[sp as usize] != s[sp as usize + 1]) as c_int;
                }
                _ => return -1,
            }
            i += 1;
        }
        s[0]
    }
}

/// `evaluate_cond_node()`.
unsafe fn evaluate_cond_node(p: *mut c_void, node: *mut CondNode) {
    unsafe {
        let new_state = cond_evaluate_expr(p, &mut (*node).expr);
        if new_state != (*node).cur_state {
            (*node).cur_state = new_state;
            if new_state == -1 {
                rust_cd_err(E_UNDEFINED);
            }
            // turn the rules on or off
            let mut i = 0;
            while i < (*node).true_list.len {
                let avnode = *(*node).true_list.nodes.add(i as usize);
                if new_state <= 0 {
                    (*avnode).key.specified &= !AVTAB_ENABLED;
                } else {
                    (*avnode).key.specified |= AVTAB_ENABLED;
                }
                i += 1;
            }

            i = 0;
            while i < (*node).false_list.len {
                let avnode = *(*node).false_list.nodes.add(i as usize);
                // -1 or 1
                if new_state != 0 {
                    (*avnode).key.specified &= !AVTAB_ENABLED;
                } else {
                    (*avnode).key.specified |= AVTAB_ENABLED;
                }
                i += 1;
            }
        }
    }
}

/// `evaluate_cond_nodes()`.
#[no_mangle]
pub unsafe extern "C" fn evaluate_cond_nodes(p: *mut c_void) {
    unsafe {
        let list = *field::<*mut CondNode>(p, OFF_COND_LIST);
        let mut i = 0;
        while i < *field::<u32>(p, OFF_COND_LIST_LEN) {
            evaluate_cond_node(p, list.add(i as usize));
            i += 1;
        }
    }
}

/// `cond_policydb_init()`.
#[no_mangle]
pub unsafe extern "C" fn cond_policydb_init(p: *mut c_void) {
    unsafe {
        *field::<*mut c_void>(p, OFF_BOOL_VAL_TO_STRUCT) = null_mut();
        *field::<*mut c_void>(p, OFF_COND_LIST) = null_mut();
        *field::<u32>(p, OFF_COND_LIST_LEN) = 0;

        avtab_init(field::<c_void>(p, OFF_TE_COND_AVTAB));
    }
}

/// `cond_node_destroy()`.
unsafe fn cond_node_destroy(node: *mut CondNode) {
    unsafe {
        rust_cd_kfree((*node).expr.nodes as *mut c_void);
        // the avtab_ptr_t nodes are destroyed by the avtab
        rust_cd_kfree((*node).true_list.nodes as *mut c_void);
        rust_cd_kfree((*node).false_list.nodes as *mut c_void);
    }
}

/// `cond_list_destroy()`.
unsafe fn cond_list_destroy(p: *mut c_void) {
    unsafe {
        let list = *field::<*mut CondNode>(p, OFF_COND_LIST);
        let mut i = 0;
        while i < *field::<u32>(p, OFF_COND_LIST_LEN) {
            cond_node_destroy(list.add(i as usize));
            i += 1;
        }
        rust_cd_kfree(list as *mut c_void);
        *field::<*mut c_void>(p, OFF_COND_LIST) = null_mut();
        *field::<u32>(p, OFF_COND_LIST_LEN) = 0;
    }
}

/// `cond_policydb_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn cond_policydb_destroy(p: *mut c_void) {
    unsafe {
        rust_cd_kfree(*field::<*mut c_void>(p, OFF_BOOL_VAL_TO_STRUCT));
        avtab_destroy(field::<c_void>(p, OFF_TE_COND_AVTAB));
        cond_list_destroy(p);
    }
}

/// `cond_init_bool_indexes()`.
#[no_mangle]
pub unsafe extern "C" fn cond_init_bool_indexes(p: *mut c_void) -> c_int {
    unsafe {
        rust_cd_kfree(*field::<*mut c_void>(p, OFF_BOOL_VAL_TO_STRUCT));
        let arr = rust_cd_kcalloc(*field::<u32>(p, OFF_BOOLS_NPRIM), core::mem::size_of::<*mut c_void>());
        *field::<*mut c_void>(p, OFF_BOOL_VAL_TO_STRUCT) = arr;
        if arr.is_null() {
            return -ENOMEM;
        }

        rust_cd_hash_eval(field::<c_void>(p, OFF_TE_COND_AVTAB));

        0
    }
}

/// `cond_destroy_bool()`.
#[no_mangle]
pub unsafe extern "C" fn cond_destroy_bool(key: *mut c_void, datum: *mut c_void, _p: *mut c_void) -> c_int {
    unsafe {
        rust_cd_kfree(key);
        rust_cd_kfree(datum);
        0
    }
}

/// `cond_index_bool()`.
#[no_mangle]
pub unsafe extern "C" fn cond_index_bool(key: *mut c_void, datum: *mut c_void, datap: *mut c_void) -> c_int {
    unsafe {
        let booldatum = datum as *mut BoolDatum;
        let p = datap;

        if (*booldatum).value == 0 || (*booldatum).value > *field::<u32>(p, OFF_BOOLS_NPRIM) {
            return -EINVAL;
        }

        let names = *field::<*mut *mut c_void>(p, OFF_SYM_VAL_TO_NAME_BOOLS);
        *names.add((*booldatum).value as usize - 1) = key;
        let arr = *field::<*mut *mut BoolDatum>(p, OFF_BOOL_VAL_TO_STRUCT);
        *arr.add((*booldatum).value as usize - 1) = booldatum;

        0
    }
}

/// `cond_read_bool()`.
#[no_mangle]
pub unsafe extern "C" fn cond_read_bool(_p: *mut c_void, s: *mut c_void, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut key: *mut c_char = null_mut();
        let mut buf = [0u32; 3];
        let mut rc;

        let booldatum = rust_cd_kzalloc(core::mem::size_of::<BoolDatum>()) as *mut BoolDatum;
        if booldatum.is_null() {
            return -ENOMEM;
        }

        'err: {
            rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 12);
            if rc != 0 {
                break 'err;
            }

            (*booldatum).value = u32::from_le(buf[0]);
            let val = u32::from_le(buf[1]);

            rc = -EINVAL;
            if val > 1 {
                // !val_is_boolean(val)
                break 'err;
            }
            (*booldatum).state = val as c_int;

            let len = u32::from_le(buf[2]);

            rc = rust_cd_str_read(&mut key, fp, len);
            if rc != 0 {
                break 'err;
            }

            rc = symtab_insert(s, key, booldatum as *mut c_void);
            if rc != 0 {
                break 'err;
            }

            return 0;
        }
        rust_cd_err(E_READ_BOOL);
        cond_destroy_bool(key as *mut c_void, booldatum as *mut c_void, null_mut());
        rc
    }
}

/// `cond_insertf()`: the callback `avtab_read_item()` calls for every rule of a conditional list.
unsafe extern "C" fn cond_insertf(_a: *mut c_void, k: *const AvKey, d: *const u64, ptr: *mut c_void) -> c_int {
    unsafe {
        let data = ptr as *mut InsertData;
        let p = (*data).p;
        let other = (*data).other;

        // For type rules we have to make certain there aren't any conflicting rules by searching the te_avtab and the cond_te_avtab.
        if (*k).specified & AVTAB_TYPE != 0 {
            if !avtab_search_node(field::<c_void>(p, OFF_TE_AVTAB), k).is_null() {
                rust_cd_err(E_TYPE_EXISTS);
                return -EINVAL;
            }
            // If we are reading the false list other will be a pointer to the true list. We can have duplicate entries if there is only 1 other entry and it is in our true list.
            // If we are reading the true list (other == NULL) there shouldn't be any other entries.
            if !other.is_null() {
                let node_ptr = avtab_search_node(field::<c_void>(p, OFF_TE_COND_AVTAB), k);
                if !node_ptr.is_null() {
                    if !avtab_search_node_next(node_ptr, (*k).specified).is_null() {
                        rust_cd_err(E_TOO_MANY);
                        return -EINVAL;
                    }
                    let mut found = false;
                    let mut i = 0;
                    while i < (*other).len {
                        if *(*other).nodes.add(i as usize) == node_ptr {
                            found = true;
                            break;
                        }
                        i += 1;
                    }
                    if !found {
                        rust_cd_err(E_CONFLICT);
                        return -EINVAL;
                    }
                }
            } else if !avtab_search_node(field::<c_void>(p, OFF_TE_COND_AVTAB), k).is_null() {
                rust_cd_err(E_CONFLICT_TRUE);
                return -EINVAL;
            }
        }

        let node_ptr = avtab_insert_nonunique(field::<c_void>(p, OFF_TE_COND_AVTAB), k, d);
        if node_ptr.is_null() {
            rust_cd_err(E_INSERT);
            return -ENOMEM;
        }

        *(*data).dst = node_ptr;
        0
    }
}

/// `cond_read_av_list()`.
unsafe fn cond_read_av_list(p: *mut c_void, fp: *mut PolicyFile, list: *mut AvList, other: *mut AvList) -> c_int {
    unsafe {
        let mut buf = [0u32; 1];

        let mut rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 4);
        if rc != 0 {
            return rc;
        }

        let len = u32::from_le(buf[0]);
        if len == 0 {
            return 0;
        }

        (*list).nodes = rust_cd_kcalloc(len, core::mem::size_of::<*mut AvNode>()) as *mut *mut AvNode;
        if (*list).nodes.is_null() {
            return -ENOMEM;
        }

        let mut data = InsertData { p, dst: null_mut(), other };
        let mut i = 0;
        while i < len {
            data.dst = (*list).nodes.add(i as usize);
            rc = avtab_read_item(field::<c_void>(p, OFF_TE_COND_AVTAB), fp, p, cond_insertf, &mut data as *mut InsertData as *mut c_void, true);
            if rc != 0 {
                rust_cd_kfree((*list).nodes as *mut c_void);
                (*list).nodes = null_mut();
                return rc;
            }
            i += 1;
        }

        (*list).len = len;
        0
    }
}

/// `expr_node_isvalid()`.
unsafe fn expr_node_isvalid(p: *mut c_void, expr: *const ExprNode) -> bool {
    unsafe {
        if (*expr).expr_type == 0 || (*expr).expr_type > COND_LAST {
            rust_cd_err(E_UNKNOWN_OP);
            return false;
        }

        if (*expr).expr_type == COND_BOOL && ((*expr).boolean == 0 || (*expr).boolean > *field::<u32>(p, OFF_BOOLS_NPRIM)) {
            rust_cd_err(E_UNKNOWN_BOOL);
            return false;
        }
        true
    }
}

/// `cond_read_node()`.
unsafe fn cond_read_node(p: *mut c_void, node: *mut CondNode, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut buf = [0u32; 2];

        let mut rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 8);
        if rc != 0 {
            return rc;
        }

        (*node).cur_state = u32::from_le(buf[0]) as c_int;

        // expr
        let len = u32::from_le(buf[1]);
        (*node).expr.nodes = rust_cd_kcalloc(len, core::mem::size_of::<ExprNode>()) as *mut ExprNode;
        if (*node).expr.nodes.is_null() {
            return -ENOMEM;
        }

        (*node).expr.len = len;

        let mut i = 0;
        while i < len {
            let expr = (*node).expr.nodes.add(i as usize);

            rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 8);
            if rc != 0 {
                return rc;
            }

            (*expr).expr_type = u32::from_le(buf[0]);
            (*expr).boolean = u32::from_le(buf[1]);

            if !expr_node_isvalid(p, expr) {
                return -EINVAL;
            }
            i += 1;
        }

        rc = cond_read_av_list(p, fp, &mut (*node).true_list, null_mut());
        if rc != 0 {
            return rc;
        }
        cond_read_av_list(p, fp, &mut (*node).false_list, &mut (*node).true_list)
    }
}

/// `cond_read_list()`.
#[no_mangle]
pub unsafe extern "C" fn cond_read_list(p: *mut c_void, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut buf = [0u32; 1];

        let mut rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 4);
        if rc != 0 {
            return rc;
        }

        let len = u32::from_le(buf[0]);

        let list = rust_cd_kcalloc(len, core::mem::size_of::<CondNode>()) as *mut CondNode;
        *field::<*mut CondNode>(p, OFF_COND_LIST) = list;
        if list.is_null() {
            return -ENOMEM;
        }

        'err: {
            rc = avtab_alloc(field::<c_void>(p, OFF_TE_COND_AVTAB), *field::<u32>(field::<c_void>(p, OFF_TE_AVTAB), 8));
            if rc != 0 {
                break 'err;
            }

            *field::<u32>(p, OFF_COND_LIST_LEN) = len;

            let mut i = 0;
            while i < len {
                rc = cond_read_node(p, list.add(i as usize), fp);
                if rc != 0 {
                    break 'err;
                }
                i += 1;
            }
            return 0;
        }
        cond_list_destroy(p);
        rc
    }
}

/// `strlen()`.
unsafe fn strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

/// `cond_write_bool()`.
#[no_mangle]
pub unsafe extern "C" fn cond_write_bool(vkey: *mut c_void, datum: *mut c_void, ptr: *mut c_void) -> c_int {
    unsafe {
        let key = vkey as *const c_char;
        let booldatum = datum as *const BoolDatum;
        let pd = ptr as *const PolicyData;
        let fp = (*pd).fp;

        let len = strlen(key);
        let buf: [u32; 3] = [(*booldatum).value.to_le(), ((*booldatum).state as u32).to_le(), (len as u32).to_le()];
        let mut rc = put_entry(buf.as_ptr() as *const u8, 4, 3, fp);
        if rc != 0 {
            return rc;
        }
        rc = put_entry(key as *const u8, 1, len, fp);
        if rc != 0 {
            return rc;
        }
        0
    }
}

/// `cond_write_av_list()`: writes the key/value pairs from the avtab, not the list nodes.
unsafe fn cond_write_av_list(p: *mut c_void, list: *mut AvList, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let buf = [(*list).len.to_le()];
        let mut rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
        if rc != 0 {
            return rc;
        }

        let mut i = 0;
        while i < (*list).len {
            rc = avtab_write_item(p, *(*list).nodes.add(i as usize), fp);
            if rc != 0 {
                return rc;
            }
            i += 1;
        }

        0
    }
}

/// `cond_write_node()`.
unsafe fn cond_write_node(p: *mut c_void, node: *mut CondNode, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut buf = [(((*node).cur_state) as u32).to_le()];
        let mut rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
        if rc != 0 {
            return rc;
        }

        buf[0] = (*node).expr.len.to_le();
        rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
        if rc != 0 {
            return rc;
        }

        let mut i = 0;
        while i < (*node).expr.len {
            let b2: [u32; 2] = [(*(*node).expr.nodes.add(i as usize)).expr_type.to_le(), (*(*node).expr.nodes.add(i as usize)).boolean.to_le()];
            rc = put_entry(b2.as_ptr() as *const u8, 4, 2, fp);
            if rc != 0 {
                return rc;
            }
            i += 1;
        }

        rc = cond_write_av_list(p, &mut (*node).true_list, fp);
        if rc != 0 {
            return rc;
        }
        rc = cond_write_av_list(p, &mut (*node).false_list, fp);
        if rc != 0 {
            return rc;
        }

        0
    }
}

/// `cond_write_list()`.
#[no_mangle]
pub unsafe extern "C" fn cond_write_list(p: *mut c_void, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let buf = [(*field::<u32>(p, OFF_COND_LIST_LEN)).to_le()];
        let mut rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
        if rc != 0 {
            return rc;
        }

        let list = *field::<*mut CondNode>(p, OFF_COND_LIST);
        let mut i = 0;
        while i < *field::<u32>(p, OFF_COND_LIST_LEN) {
            rc = cond_write_node(p, list.add(i as usize), fp);
            if rc != 0 {
                return rc;
            }
            i += 1;
        }

        0
    }
}

/// `cond_compute_xperms()`.
#[no_mangle]
pub unsafe extern "C" fn cond_compute_xperms(ctab: *mut c_void, key: *mut AvKey, xpermd: *mut c_void) {
    unsafe {
        if ctab.is_null() || key.is_null() || xpermd.is_null() {
            return;
        }

        let mut node = avtab_search_node(ctab, key);
        while !node.is_null() {
            if (*node).key.specified & AVTAB_ENABLED != 0 {
                services_compute_xperms_decision(xpermd, node);
            }
            node = avtab_search_node_next(node, (*key).specified);
        }
    }
}

/// `cond_compute_av()`: add what the enabled conditional rules allow to the decision.
#[no_mangle]
pub unsafe extern "C" fn cond_compute_av(ctab: *mut c_void, key: *mut AvKey, avd: *mut AvDecision, xperms: *mut c_void) {
    unsafe {
        if ctab.is_null() || key.is_null() || avd.is_null() {
            return;
        }

        let mut node = avtab_search_node(ctab, key);
        while !node.is_null() {
            let sp = (*node).key.specified;
            let datum = (*node).datum as u32;
            if AVTAB_ALLOWED | AVTAB_ENABLED == sp & (AVTAB_ALLOWED | AVTAB_ENABLED) {
                (*avd).allowed |= datum;
            }
            if AVTAB_AUDITDENY | AVTAB_ENABLED == sp & (AVTAB_AUDITDENY | AVTAB_ENABLED) {
                // Since a '0' in an auditdeny mask represents a permission we do NOT want to audit (dontaudit), we use the '&' operand to ensure that all '0's in the mask are
                // retained (much unlike the allow and auditallow cases).
                (*avd).auditdeny &= datum;
            }
            if AVTAB_AUDITALLOW | AVTAB_ENABLED == sp & (AVTAB_AUDITALLOW | AVTAB_ENABLED) {
                (*avd).auditallow |= datum;
            }
            if !xperms.is_null() && sp & AVTAB_ENABLED != 0 && sp & AVTAB_XPERMS != 0 {
                services_compute_xperms_drivers(xperms, node);
            }
            node = avtab_search_node_next(node, (*key).specified);
        }
    }
}

/// `cond_dup_av_list()`.
unsafe fn cond_dup_av_list(new: *mut AvList, orig: *const AvList, avtab: *mut c_void) -> c_int {
    unsafe {
        core::ptr::write_bytes(new as *mut u8, 0, core::mem::size_of::<AvList>());

        (*new).nodes = rust_cd_kcalloc((*orig).len, core::mem::size_of::<*mut AvNode>()) as *mut *mut AvNode;
        if (*new).nodes.is_null() {
            return -ENOMEM;
        }

        let mut i = 0;
        while i < (*orig).len {
            let o = *(*orig).nodes.add(i as usize);
            let n = avtab_insert_nonunique(avtab, &(*o).key, &(*o).datum);
            *(*new).nodes.add(i as usize) = n;
            if n.is_null() {
                return -ENOMEM;
            }
            (*new).len += 1;
            i += 1;
        }

        0
    }
}

/// `duplicate_policydb_cond_list()`.
unsafe fn duplicate_policydb_cond_list(newp: *mut c_void, origp: *const c_void) -> c_int {
    unsafe {
        let rc = avtab_alloc_dup(field::<c_void>(newp, OFF_TE_COND_AVTAB), field::<c_void>(origp, OFF_TE_COND_AVTAB));
        if rc != 0 {
            return rc;
        }

        *field::<u32>(newp, OFF_COND_LIST_LEN) = 0;
        let olen = *field::<u32>(origp, OFF_COND_LIST_LEN);
        let nlist = rust_cd_kcalloc(olen, core::mem::size_of::<CondNode>()) as *mut CondNode;
        *field::<*mut CondNode>(newp, OFF_COND_LIST) = nlist;

        'error: {
            if nlist.is_null() {
                break 'error;
            }

            let olist = *field::<*mut CondNode>(origp, OFF_COND_LIST);
            let mut i = 0;
            while i < olen {
                let newn = nlist.add(i as usize);
                let orign = olist.add(i as usize);

                *field::<u32>(newp, OFF_COND_LIST_LEN) += 1;

                (*newn).cur_state = (*orign).cur_state;
                (*newn).expr.nodes = rust_cd_kmemdup((*orign).expr.nodes as *const c_void, (*orign).expr.len as usize * core::mem::size_of::<ExprNode>()) as *mut ExprNode;
                if (*newn).expr.nodes.is_null() {
                    break 'error;
                }

                (*newn).expr.len = (*orign).expr.len;

                let mut rc = cond_dup_av_list(&mut (*newn).true_list, &(*orign).true_list, field::<c_void>(newp, OFF_TE_COND_AVTAB));
                if rc != 0 {
                    break 'error;
                }

                rc = cond_dup_av_list(&mut (*newn).false_list, &(*orign).false_list, field::<c_void>(newp, OFF_TE_COND_AVTAB));
                if rc != 0 {
                    break 'error;
                }
                i += 1;
            }

            return 0;
        }

        avtab_destroy(field::<c_void>(newp, OFF_TE_COND_AVTAB));
        cond_list_destroy(newp);
        -ENOMEM
    }
}

/// `cond_bools_destroy()`.
unsafe extern "C" fn cond_bools_destroy(_key: *mut c_void, datum: *mut c_void, _args: *mut c_void) -> c_int {
    unsafe {
        // key was not copied so no need to free here
        rust_cd_kfree(datum);
        0
    }
}

/// `cond_bools_copy()`.
unsafe extern "C" fn cond_bools_copy(new: *mut HtNode, orig: *const HtNode, _args: *mut c_void) -> c_int {
    unsafe {
        let datum = rust_cd_kmemdup((*orig).datum, core::mem::size_of::<BoolDatum>());
        if datum.is_null() {
            return -ENOMEM;
        }

        (*new).key = (*orig).key; // No need to copy, never modified
        (*new).datum = datum;
        0
    }
}

/// `cond_bools_index()`.
unsafe extern "C" fn cond_bools_index(_key: *mut c_void, datum: *mut c_void, args: *mut c_void) -> c_int {
    unsafe {
        let booldatum = datum as *mut BoolDatum;
        let cond_bool_array = args as *mut *mut BoolDatum;

        *cond_bool_array.add((*booldatum).value.wrapping_sub(1) as usize) = booldatum;

        0
    }
}

/// `duplicate_policydb_bools()`.
unsafe fn duplicate_policydb_bools(newdb: *mut c_void, orig: *const c_void) -> c_int {
    unsafe {
        let nprim = *field::<u32>(orig, OFF_BOOLS_NPRIM);
        let cond_bool_array = rust_cd_kcalloc(nprim, core::mem::size_of::<*mut BoolDatum>()) as *mut *mut BoolDatum;
        if cond_bool_array.is_null() {
            return -ENOMEM;
        }

        let rc = hashtab_duplicate(field::<c_void>(newdb, OFF_BOOLS_TABLE), field::<c_void>(orig, OFF_BOOLS_TABLE), cond_bools_copy, cond_bools_destroy, null_mut());
        if rc != 0 {
            rust_cd_kfree(cond_bool_array as *mut c_void);
            return -ENOMEM;
        }

        hashtab_map(field::<c_void>(newdb, OFF_BOOLS_TABLE), cond_bools_index, cond_bool_array as *mut c_void);
        *field::<*mut *mut BoolDatum>(newdb, OFF_BOOL_VAL_TO_STRUCT) = cond_bool_array;

        *field::<u32>(newdb, OFF_BOOLS_NPRIM) = nprim;

        0
    }
}

/// `cond_policydb_destroy_dup()`.
#[no_mangle]
pub unsafe extern "C" fn cond_policydb_destroy_dup(p: *mut c_void) {
    unsafe {
        hashtab_map(field::<c_void>(p, OFF_BOOLS_TABLE), cond_bools_destroy, null_mut());
        hashtab_destroy(field::<c_void>(p, OFF_BOOLS_TABLE));
        cond_policydb_destroy(p);
    }
}

/// `cond_policydb_dup()`.
#[no_mangle]
pub unsafe extern "C" fn cond_policydb_dup(new: *mut c_void, orig: *const c_void) -> c_int {
    unsafe {
        cond_policydb_init(new);

        if duplicate_policydb_bools(new, orig) != 0 {
            return -ENOMEM;
        }

        if duplicate_policydb_cond_list(new, orig) != 0 {
            cond_policydb_destroy_dup(new);
            return -ENOMEM;
        }

        0
    }
}
