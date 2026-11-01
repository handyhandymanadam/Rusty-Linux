// SPDX-License-Identifier: GPL-2.0

//! The extra boot config (XBC) parser and tree -- the Rust behind `lib/bootconfig.c`.
//!
//! Ported from `lib/bootconfig.c` (6.18.49), "Extra Boot Config" (Masami Hiramatsu). The boot config is tree-structured ASCII text of key-value pairs.
//! `xbc_init()` copies it into memory, `xbc_parse_tree()` splits it into delimiters, keys and values (`=`, `:=`, `+=`, `{`, `}`, `;`, newline, `#` comments,
//! quotes) and builds the tree in an array of 8-byte nodes (`next`, `child`, `parent`, `data` offset with a value flag); `xbc_verify_tree()` checks brace
//! balance and key length / depth limits. The accessors and finders (`xbc_node_find_subkey`, `find_value`, `find_next_leaf`, ...) walk that array.
//!
//! # Shape
//! * **In Rust**: everything except two functions: the parser, the tree builder, the verifier, `xbc_init` / `_xbc_exit`, and every accessor and finder. All of
//!   it is `__init` code upstream; here each function is placed in `.init.text` (`#[link_section = ".init.text"]`), as the earlier `__init` ports do, so it is
//!   freed with the rest of the init text and never references an `__init` symbol from non-init text.
//! * **In C** (`bootconfig_glue.c`): the file's state (`xbc_nodes`, `xbc_data`, ..., all `__initdata`, handed to the Rust as pointers by `rust_xbc_state()`), the
//!   memblock allocation, the exports as one-line `__init` thunks, the embedded-config accessor, and the two functions that format with the variadic
//!   `snprintf` (`xbc_node_compose_key_after`, `xbc_snprint_cmdline`) together with their name buffer. Every `WARN_ON` site is a one-line wrapper (the warning
//!   now names the glue file: recorded divergence).
//!
//! `<linux/ctype.h>` is reproduced through the kernel's own `_ctype` table (Latin-1 aware, not ASCII), and the string helpers (`strlen`, `strcmp`, `strchr`,
//! `strpbrk`, `skip_spaces`, `strim`) are the kernel's out-of-line functions, so behaviour on bytes >= 0x80 is exactly the C's.
//!
//! Single CPU, early boot (`setup_boot_config()` before the allocator is up); no concurrency.
//!
//! Replaces: lib/bootconfig.c (all but the two `snprintf` users, the state, the allocation and the exports)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("bootconfig_rs.rs: x86-64 little-endian only (packed 8-byte nodes, 64-bit size_t)");

const XBC_VALUE: u32 = 1 << 15;
const XBC_DATA_MAX: u64 = (XBC_VALUE - 1) as u64;
const XBC_NODE_MAX: i32 = 8192;
const XBC_KEYLEN_MAX: i32 = 256;
const XBC_DEPTH_MAX: i32 = 16;

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const ENOENT: c_int = 2;
const EBUSY: c_int = 16;
const ERANGE: c_int = 34;
const ENODEV: c_int = 19;

// <linux/ctype.h>
const CT_U: u8 = 0x01;
const CT_L: u8 = 0x02;
const CT_D: u8 = 0x04;
const CT_P: u8 = 0x10;
const CT_S: u8 = 0x20;
const CT_SP: u8 = 0x80;

/// `struct xbc_node` (packed, 8 bytes).
#[repr(C, packed)]
pub struct XbcNode {
    next: u16,
    child: u16,
    parent: u16,
    data: u16,
}

/// Pointers to the C file's `__initdata` state.
#[repr(C)]
pub struct XbcState {
    nodes: *mut *mut XbcNode,
    node_num: *mut c_int,
    data: *mut *mut c_char,
    data_size: *mut usize,
    last_parent: *mut *mut XbcNode,
    err_msg: *mut *const c_char,
    err_pos: *mut c_int,
    open_brace: *mut c_int,
    brace_index: *mut c_int,
}

extern "C" {
    static _ctype: [u8; 256];

    fn rust_xbc_state() -> *const XbcState;
    fn rust_xbcw_alloc(size: usize) -> *mut c_void;
    fn rust_xbcw_free(addr: *mut c_void, size: usize, early: bool);
    fn rust_xbcw_warn_data(cond: bool) -> bool;
    fn rust_xbcw_warn_leaf(cond: bool) -> bool;
    fn rust_xbcw_warn_kv(cond: bool) -> bool;
    fn rust_xbcw_warn_init_node(cond: bool) -> bool;

    fn strlen(s: *const c_char) -> usize;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char;
    fn skip_spaces(s: *const c_char) -> *mut c_char;
    fn strim(s: *mut c_char) -> *mut c_char;
}

#[inline(always)]
unsafe fn st() -> &'static XbcState {
    unsafe { &*rust_xbc_state() }
}

#[inline(always)]
unsafe fn ct(c: c_int) -> u8 {
    unsafe { _ctype[(c as u8) as usize] }
}

#[inline(always)]
unsafe fn isalnum(c: c_int) -> bool {
    unsafe { ct(c) & (CT_U | CT_L | CT_D) != 0 }
}

#[inline(always)]
unsafe fn isprint(c: c_int) -> bool {
    unsafe { ct(c) & (CT_P | CT_U | CT_L | CT_D | CT_SP) != 0 }
}

#[inline(always)]
unsafe fn isspace(c: c_int) -> bool {
    unsafe { ct(c) & CT_S != 0 }
}

macro_rules! cstr {
    ($s:literal) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

#[inline(always)]
unsafe fn nodes(s: &XbcState) -> *mut XbcNode {
    unsafe { *s.nodes }
}

#[inline(always)]
unsafe fn last_parent(s: &XbcState) -> *mut XbcNode {
    unsafe { *s.last_parent }
}

/// `xbc_node_index()`: a pointer difference, as in C (a NULL node gives a negative number).
#[inline(always)]
unsafe fn node_index(s: &XbcState, node: *const XbcNode) -> c_int {
    unsafe { ((node as isize).wrapping_sub(nodes(s) as isize) / 8) as c_int }
}

#[inline(always)]
unsafe fn node_at(s: &XbcState, idx: usize) -> *mut XbcNode {
    unsafe { nodes(s).add(idx) }
}

/// `xbc_get_info()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_get_info(node_size: *mut c_int, data_size: *mut usize) -> c_int {
    unsafe {
        let s = st();
        if (*s.data).is_null() {
            return -ENODEV;
        }

        if !node_size.is_null() {
            *node_size = *s.node_num;
        }
        if !data_size.is_null() {
            *data_size = *s.data_size;
        }
        0
    }
}

/// `xbc_parse_error()`.
#[link_section = ".init.text"]
unsafe fn xbc_parse_error(msg: *const c_char, p: *const c_char) -> c_int {
    unsafe {
        let s = st();
        *s.err_msg = msg;
        *s.err_pos = (p as isize).wrapping_sub(*s.data as isize) as c_int;

        -EINVAL
    }
}

/// `xbc_root_node()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_root_node() -> *mut XbcNode {
    unsafe {
        let s = st();
        if (*s.data).is_null() {
            return null_mut();
        }

        nodes(s)
    }
}

/// `xbc_node_index()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_index(node: *mut XbcNode) -> c_int {
    unsafe { node_index(st(), node) }
}

/// `xbc_node_get_parent()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_get_parent(node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        let s = st();
        let parent = (*node).parent;
        if parent as i32 == XBC_NODE_MAX {
            null_mut()
        } else {
            node_at(s, parent as usize)
        }
    }
}

/// `xbc_node_get_child()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_get_child(node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        let child = (*node).child;
        if child != 0 {
            node_at(st(), child as usize)
        } else {
            null_mut()
        }
    }
}

/// `xbc_node_get_next()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_get_next(node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        let next = (*node).next;
        if next != 0 {
            node_at(st(), next as usize)
        } else {
            null_mut()
        }
    }
}

/// `xbc_node_get_data()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_get_data(node: *mut XbcNode) -> *const c_char {
    unsafe {
        let s = st();
        let offset = ((*node).data as u32 & !XBC_VALUE) as c_int;

        if rust_xbcw_warn_data(offset as usize >= *s.data_size) {
            return null();
        }

        (*s.data).add(offset as usize)
    }
}

#[inline(always)]
unsafe fn is_value(node: *const XbcNode) -> bool {
    unsafe { (*node).data as u32 & XBC_VALUE != 0 }
}

#[inline(always)]
unsafe fn is_key(node: *const XbcNode) -> bool {
    unsafe { !is_value(node) }
}

#[inline(always)]
unsafe fn is_leaf(node: *mut XbcNode) -> bool {
    unsafe { is_key(node) && ((*node).child == 0 || is_value(rust_xbc_node_get_child(node))) }
}

/// `xbc_node_get_subkey()` (header inline).
#[inline(always)]
unsafe fn get_subkey(node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        let child = rust_xbc_node_get_child(node);

        if !child.is_null() && is_value(child) {
            rust_xbc_node_get_next(child)
        } else {
            child
        }
    }
}

/// `xbc_node_match_prefix()`.
#[link_section = ".init.text"]
unsafe fn xbc_node_match_prefix(node: *mut XbcNode, prefix: *mut *const c_char) -> bool {
    unsafe {
        let mut p = rust_xbc_node_get_data(node);
        let len = strlen(p);

        if strncmp(*prefix, p, len) != 0 {
            return false;
        }

        p = (*prefix).add(len);
        if *p == b'.' as c_char {
            p = p.add(1);
        } else if *p != 0 {
            return false;
        }
        *prefix = p;

        true
    }
}

/// `xbc_node_find_subkey()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_find_subkey(parent: *mut XbcNode, mut key: *const c_char) -> *mut XbcNode {
    unsafe {
        let mut node = if !parent.is_null() { get_subkey(parent) } else { rust_xbc_root_node() };

        while !node.is_null() && is_key(node) {
            if !xbc_node_match_prefix(node, &mut key) {
                node = rust_xbc_node_get_next(node);
            } else if *key != 0 {
                node = get_subkey(node);
            } else {
                break;
            }
        }

        node
    }
}

/// `xbc_node_find_value()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_find_value(parent: *mut XbcNode, key: *const c_char, vnode: *mut *mut XbcNode) -> *const c_char {
    unsafe {
        let mut node = rust_xbc_node_find_subkey(parent, key);

        if node.is_null() || !is_key(node) {
            return null();
        }

        node = rust_xbc_node_get_child(node);
        if !node.is_null() && !is_value(node) {
            return null();
        }

        if !vnode.is_null() {
            *vnode = node;
        }

        if !node.is_null() {
            rust_xbc_node_get_data(node)
        } else {
            cstr!("")
        }
    }
}

/// `xbc_node_find_next_leaf()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_find_next_leaf(root: *mut XbcNode, node_in: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        let s = st();
        let mut node: *mut XbcNode;

        if (*s.data).is_null() {
            return null_mut();
        }

        if node_in.is_null() {
            // First try
            node = root;
            if node.is_null() {
                node = nodes(s);
            }
        } else {
            // Leaf node may have a subkey
            let next = get_subkey(node_in);
            if !next.is_null() {
                node = next;
            } else {
                if node_in == root {
                    // @root was a leaf, no child node.
                    return null_mut();
                }

                node = node_in;
                while (*node).next == 0 {
                    node = rust_xbc_node_get_parent(node);
                    if node == root {
                        return null_mut();
                    }
                    // User passed a node which is not uder parent
                    if rust_xbcw_warn_leaf(node.is_null()) {
                        return null_mut();
                    }
                }
                node = rust_xbc_node_get_next(node);
            }
        }

        while !node.is_null() && !is_leaf(node) {
            node = rust_xbc_node_get_child(node);
        }

        node
    }
}

/// `xbc_node_find_next_key_value()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_node_find_next_key_value(root: *mut XbcNode, leaf: *mut *mut XbcNode) -> *const c_char {
    unsafe {
        // tip must be passed
        if rust_xbcw_warn_kv(leaf.is_null()) {
            return null();
        }

        *leaf = rust_xbc_node_find_next_leaf(root, *leaf);
        if (*leaf).is_null() {
            return null();
        }
        if (**leaf).child != 0 {
            rust_xbc_node_get_data(rust_xbc_node_get_child(*leaf))
        } else {
            cstr!("") // No value key
        }
    }
}

// ---- XBC parse and tree build ----

/// `xbc_init_node()`.
#[link_section = ".init.text"]
unsafe fn xbc_init_node(node: *mut XbcNode, data: *mut c_char, flag: u32) -> c_int {
    unsafe {
        let s = st();
        let offset = (data as usize).wrapping_sub(*s.data as usize);

        if rust_xbcw_warn_init_node(offset as u64 >= XBC_DATA_MAX) {
            return -EINVAL;
        }

        (*node).data = ((offset as u16) as u32 | flag) as u16;
        (*node).child = 0;
        (*node).next = 0;

        0
    }
}

/// `xbc_add_node()`.
#[link_section = ".init.text"]
unsafe fn xbc_add_node(data: *mut c_char, flag: u32) -> *mut XbcNode {
    unsafe {
        let s = st();

        if *s.node_num == XBC_NODE_MAX {
            return null_mut();
        }

        let node = nodes(s).add(*s.node_num as usize);
        *s.node_num += 1;
        if xbc_init_node(node, data, flag) < 0 {
            return null_mut();
        }

        node
    }
}

#[inline(always)]
unsafe fn xbc_last_sibling(mut node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        while (*node).next != 0 {
            node = rust_xbc_node_get_next(node);
        }

        node
    }
}

#[inline(always)]
unsafe fn xbc_last_child(mut node: *mut XbcNode) -> *mut XbcNode {
    unsafe {
        while (*node).child != 0 {
            node = rust_xbc_node_get_child(node);
        }

        node
    }
}

/// `__xbc_add_sibling()`.
#[link_section = ".init.text"]
unsafe fn __xbc_add_sibling(data: *mut c_char, flag: u32, head: bool) -> *mut XbcNode {
    unsafe {
        let s = st();
        let node = xbc_add_node(data, flag);

        if !node.is_null() {
            let lp = last_parent(s);
            if lp.is_null() {
                // Ignore @head in this case
                (*node).parent = XBC_NODE_MAX as u16;
                let sib = xbc_last_sibling(nodes(s));
                (*sib).next = node_index(s, node) as u16;
            } else {
                (*node).parent = node_index(s, lp) as u16;
                if (*lp).child == 0 || head {
                    (*node).next = (*lp).child;
                    (*lp).child = node_index(s, node) as u16;
                } else {
                    let mut sib = rust_xbc_node_get_child(lp);
                    sib = xbc_last_sibling(sib);
                    (*sib).next = node_index(s, node) as u16;
                }
            }
        } else {
            xbc_parse_error(cstr!("Too many nodes"), data);
        }

        node
    }
}

#[inline(always)]
unsafe fn xbc_add_sibling(data: *mut c_char, flag: u32) -> *mut XbcNode {
    unsafe { __xbc_add_sibling(data, flag, false) }
}

#[inline(always)]
unsafe fn xbc_add_head_sibling(data: *mut c_char, flag: u32) -> *mut XbcNode {
    unsafe { __xbc_add_sibling(data, flag, true) }
}

#[inline(always)]
unsafe fn xbc_add_child(data: *mut c_char, flag: u32) -> *mut XbcNode {
    unsafe {
        let node = xbc_add_sibling(data, flag);

        if !node.is_null() {
            *st().last_parent = node;
        }

        node
    }
}

/// `xbc_valid_keyword()`.
#[inline(always)]
unsafe fn xbc_valid_keyword(mut key: *const c_char) -> bool {
    unsafe {
        if *key == 0 {
            return false;
        }

        while isalnum(*key as c_int) || *key == b'-' as c_char || *key == b'_' as c_char {
            key = key.add(1);
        }

        *key == 0
    }
}

/// `skip_comment()`.
#[inline(always)]
unsafe fn skip_comment(p: *mut c_char) -> *mut c_char {
    unsafe {
        let ret = strchr(p, b'\n' as c_int);
        if ret.is_null() {
            p.add(strlen(p))
        } else {
            ret.add(1)
        }
    }
}

/// `skip_spaces_until_newline()`.
#[inline(always)]
unsafe fn skip_spaces_until_newline(mut p: *mut c_char) -> *mut c_char {
    unsafe {
        while isspace(*p as c_int) && *p != b'\n' as c_char {
            p = p.add(1);
        }
        p
    }
}

/// `__xbc_open_brace()`.
#[link_section = ".init.text"]
unsafe fn __xbc_open_brace(p: *mut c_char) -> c_int {
    unsafe {
        let s = st();
        // Push the last key as open brace
        if *s.brace_index >= XBC_DEPTH_MAX {
            return xbc_parse_error(cstr!("Exceed max depth of braces"), p);
        }
        *s.open_brace.add(*s.brace_index as usize) = node_index(s, last_parent(s));
        *s.brace_index += 1;

        0
    }
}

/// `__xbc_close_brace()`.
#[link_section = ".init.text"]
unsafe fn __xbc_close_brace(p: *mut c_char) -> c_int {
    unsafe {
        let s = st();
        *s.brace_index -= 1;
        if last_parent(s).is_null()
            || *s.brace_index < 0
            || *s.open_brace.add(*s.brace_index as usize) != node_index(s, last_parent(s))
        {
            return xbc_parse_error(cstr!("Unexpected closing brace"), p);
        }

        if *s.brace_index == 0 {
            *s.last_parent = null_mut();
        } else {
            *s.last_parent = node_at(s, *s.open_brace.add(*s.brace_index as usize - 1) as usize);
        }

        0
    }
}

/// `__xbc_parse_value()`: returns the delimiter or an error, no node added. As in lib/cmdline.c you can use " around spaces, but can't escape " for value.
#[link_section = ".init.text"]
unsafe fn __xbc_parse_value(__v: *mut *mut c_char, __n: *mut *mut c_char) -> c_int {
    unsafe {
        let mut v = *__v;
        let mut quotes: c_int = 0;

        v = skip_spaces(v);
        while *v == b'#' as c_char {
            v = skip_comment(v);
            v = skip_spaces(v);
        }
        if *v == b'"' as c_char || *v == b'\'' as c_char {
            quotes = *v as c_int;
            v = v.add(1);
        }
        let mut p = v.offset(-1);
        let mut c: c_int;
        loop {
            p = p.add(1);
            c = *p as c_int;
            if c == 0 {
                break;
            }
            if !isprint(c) && !isspace(c) {
                return xbc_parse_error(cstr!("Non printable value"), p);
            }
            if quotes != 0 {
                if c != quotes {
                    continue;
                }
                quotes = 0;
                *p = 0;
                p = p.add(1);
                p = skip_spaces_until_newline(p);
                c = *p as c_int;
                if c != 0 && strchr(cstr!(",;\n#}"), c).is_null() {
                    return xbc_parse_error(cstr!("No value delimiter"), p);
                }
                if *p != 0 {
                    p = p.add(1);
                }
                break;
            }
            if !strchr(cstr!(",;\n#}"), c).is_null() {
                *p = 0;
                p = p.add(1);
                v = strim(v);
                break;
            }
        }
        if quotes != 0 {
            return xbc_parse_error(cstr!("No closing quotes"), p);
        }
        if c == b'#' as c_int {
            p = skip_comment(p);
            c = b'\n' as c_int; // A comment must be treated as a newline
        }
        *__n = p;
        *__v = v;

        c
    }
}

/// `xbc_parse_array()`.
#[link_section = ".init.text"]
unsafe fn xbc_parse_array(__v: *mut *mut c_char) -> c_int {
    unsafe {
        let s = st();
        let mut next: *mut c_char = null_mut();
        let mut node: *mut XbcNode;
        let mut c: c_int;

        if (*last_parent(s)).child != 0 {
            *s.last_parent = rust_xbc_node_get_child(last_parent(s));
        }

        loop {
            c = __xbc_parse_value(__v, &mut next);
            if c < 0 {
                return c;
            }

            node = xbc_add_child(*__v, XBC_VALUE);
            if node.is_null() {
                return -ENOMEM;
            }
            *__v = next;
            if c != b',' as c_int {
                break;
            }
        }
        (*node).child = 0;

        c
    }
}

/// `find_match_node()`.
#[link_section = ".init.text"]
unsafe fn find_match_node(mut node: *mut XbcNode, k: *const c_char) -> *mut XbcNode {
    unsafe {
        while !node.is_null() {
            if strcmp(rust_xbc_node_get_data(node), k) == 0 {
                break;
            }
            node = rust_xbc_node_get_next(node);
        }
        node
    }
}

/// `__xbc_add_key()`.
#[link_section = ".init.text"]
unsafe fn __xbc_add_key(k: *mut c_char) -> c_int {
    unsafe {
        let s = st();
        let mut node: *mut XbcNode;

        if !xbc_valid_keyword(k) {
            return xbc_parse_error(cstr!("Invalid keyword"), k);
        }

        let add_node = *s.node_num == 0;
        if !add_node {
            if last_parent(s).is_null() {
                // the first level
                node = find_match_node(nodes(s), k);
            } else {
                let mut child = rust_xbc_node_get_child(last_parent(s));
                // Since the value node is the first child, skip it.
                if !child.is_null() && is_value(child) {
                    child = rust_xbc_node_get_next(child);
                }
                node = find_match_node(child, k);
            }

            if !node.is_null() {
                *s.last_parent = node;
                return 0;
            }
        }

        node = xbc_add_child(k, 0);
        if node.is_null() {
            return -ENOMEM;
        }
        0
    }
}

/// `__xbc_parse_keys()`.
#[link_section = ".init.text"]
unsafe fn __xbc_parse_keys(mut k: *mut c_char) -> c_int {
    unsafe {
        k = strim(k);
        loop {
            let p = strchr(k, b'.' as c_int);
            if p.is_null() {
                break;
            }
            *p = 0;
            let ret = __xbc_add_key(k);
            if ret != 0 {
                return ret;
            }
            k = p.add(1);
        }

        __xbc_add_key(k)
    }
}

/// `xbc_parse_kv()`.
#[link_section = ".init.text"]
unsafe fn xbc_parse_kv(k: *mut *mut c_char, mut v: *mut c_char, op: c_int) -> c_int {
    unsafe {
        let s = st();
        let prev_parent = last_parent(s);
        let mut next: *mut c_char = null_mut();

        let mut ret = __xbc_parse_keys(*k);
        if ret != 0 {
            return ret;
        }

        let mut c = __xbc_parse_value(&mut v, &mut next);
        if c < 0 {
            return c;
        }

        let child = rust_xbc_node_get_child(last_parent(s));
        let mut skip_head = false;
        if !child.is_null() && is_value(child) {
            if op == b'=' as c_int {
                return xbc_parse_error(cstr!("Value is redefined"), v);
            }
            if op == b':' as c_int {
                let nidx = (*child).next;

                if xbc_init_node(child, v, XBC_VALUE) < 0 {
                    return xbc_parse_error(cstr!("Failed to override value"), v);
                }
                (*child).next = nidx; // keep subkeys
                skip_head = true;
            } else {
                // op must be '+'
                *s.last_parent = xbc_last_child(child);
            }
        }
        if !skip_head {
            // The value node should always be the first child
            if xbc_add_head_sibling(v, XBC_VALUE).is_null() {
                return -ENOMEM;
            }
        }

        // array:
        if c == b',' as c_int {
            // Array
            c = xbc_parse_array(&mut next);
            if c < 0 {
                return c;
            }
        }

        *s.last_parent = prev_parent;

        if c == b'}' as c_int {
            ret = __xbc_close_brace(next.offset(-1));
            if ret < 0 {
                return ret;
            }
        }

        *k = next;

        0
    }
}

/// `xbc_parse_key()`.
#[link_section = ".init.text"]
unsafe fn xbc_parse_key(k: *mut *mut c_char, n: *mut c_char) -> c_int {
    unsafe {
        let s = st();
        let prev_parent = last_parent(s);

        *k = strim(*k);
        if **k != 0 {
            let ret = __xbc_parse_keys(*k);
            if ret != 0 {
                return ret;
            }
            *s.last_parent = prev_parent;
        }
        *k = n;

        0
    }
}

/// `xbc_open_brace()`.
#[link_section = ".init.text"]
unsafe fn xbc_open_brace(k: *mut *mut c_char, n: *mut c_char) -> c_int {
    unsafe {
        let ret = __xbc_parse_keys(*k);
        if ret != 0 {
            return ret;
        }
        *k = n;

        __xbc_open_brace(n.offset(-1))
    }
}

/// `xbc_close_brace()`.
#[link_section = ".init.text"]
unsafe fn xbc_close_brace(k: *mut *mut c_char, n: *mut c_char) -> c_int {
    unsafe {
        let ret = xbc_parse_key(k, n);
        if ret != 0 {
            return ret;
        }
        // k is updated in xbc_parse_key()

        __xbc_close_brace(n.offset(-1))
    }
}

/// `xbc_verify_tree()`.
#[link_section = ".init.text"]
unsafe fn xbc_verify_tree() -> c_int {
    unsafe {
        let s = st();

        // Brace closing
        if *s.brace_index != 0 {
            let n = node_at(s, *s.open_brace.add(*s.brace_index as usize - 1) as usize);
            return xbc_parse_error(cstr!("Brace is not closed"), rust_xbc_node_get_data(n));
        }

        // Empty tree
        if *s.node_num == 0 {
            xbc_parse_error(cstr!("Empty config"), *s.data);
            return -ENOENT;
        }

        for i in 0..*s.node_num as usize {
            if (*nodes(s).add(i)).next as c_int > *s.node_num {
                return xbc_parse_error(cstr!("No closing brace"), rust_xbc_node_get_data(nodes(s).add(i)));
            }
        }

        // Key tree limitation check
        let mut n = nodes(s);
        let mut depth: c_int = 1;
        let mut len: c_int = 0;

        while !n.is_null() {
            let wlen = strlen(rust_xbc_node_get_data(n)) as c_int + 1;
            len += wlen;
            if len > XBC_KEYLEN_MAX {
                return xbc_parse_error(cstr!("Too long key length"), rust_xbc_node_get_data(n));
            }

            let mut m = rust_xbc_node_get_child(n);
            if !m.is_null() && is_key(m) {
                n = m;
                depth += 1;
                if depth > XBC_DEPTH_MAX {
                    return xbc_parse_error(cstr!("Too many key words"), rust_xbc_node_get_data(n));
                }
                continue;
            }
            len -= wlen;
            m = rust_xbc_node_get_next(n);
            while m.is_null() {
                n = rust_xbc_node_get_parent(n);
                if n.is_null() {
                    break;
                }
                len -= strlen(rust_xbc_node_get_data(n)) as c_int + 1;
                depth -= 1;
                m = rust_xbc_node_get_next(n);
            }
            n = m;
        }

        0
    }
}

/// `xbc_parse_tree()`: need to set up xbc_data and xbc_nodes before calling this.
#[link_section = ".init.text"]
unsafe fn xbc_parse_tree() -> c_int {
    unsafe {
        let s = st();
        let mut ret: c_int = 0;

        *s.last_parent = null_mut();
        let mut p = *s.data;
        loop {
            let mut q = strpbrk(p, cstr!("{}=+;:\n#"));
            if q.is_null() {
                p = skip_spaces(p);
                if *p != 0 {
                    ret = xbc_parse_error(cstr!("No delimiter"), p);
                }
                break;
            }

            let c = *q as c_int;
            *q = 0;
            q = q.add(1);
            match c as u8 {
                b':' | b'+' => {
                    let eq = *q;
                    q = q.add(1);
                    if eq != b'=' as c_char {
                        ret = xbc_parse_error(
                            if c == b'+' as c_int { cstr!("Wrong '+' operator") } else { cstr!("Wrong ':' operator") },
                            q.offset(-2),
                        );
                    } else {
                        ret = xbc_parse_kv(&mut p, q, c);
                    }
                }
                b'=' => ret = xbc_parse_kv(&mut p, q, c),
                b'{' => ret = xbc_open_brace(&mut p, q),
                b'#' => {
                    q = skip_comment(q);
                    ret = xbc_parse_key(&mut p, q);
                }
                b';' | b'\n' => ret = xbc_parse_key(&mut p, q),
                b'}' => ret = xbc_close_brace(&mut p, q),
                _ => {}
            }
            if ret != 0 {
                break;
            }
        }

        ret
    }
}

/// `_xbc_exit()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_exit(early: bool) {
    unsafe {
        let s = st();
        rust_xbcw_free(*s.data as *mut c_void, *s.data_size, early);
        *s.data = null_mut();
        *s.data_size = 0;
        *s.node_num = 0;
        rust_xbcw_free(nodes(s) as *mut c_void, 8 * XBC_NODE_MAX as usize, early);
        *s.nodes = null_mut();
        *s.brace_index = 0;
    }
}

/// `xbc_init()`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn rust_xbc_init(data: *const c_char, size: usize, emsg: *mut *const c_char, epos: *mut c_int) -> c_int {
    unsafe {
        let s = st();

        if !epos.is_null() {
            *epos = -1;
        }

        if !(*s.data).is_null() {
            if !emsg.is_null() {
                *emsg = cstr!("Bootconfig is already initialized");
            }
            return -EBUSY;
        }
        if size as u64 > XBC_DATA_MAX || size == 0 {
            if !emsg.is_null() {
                *emsg = if size != 0 { cstr!("Config data is too big") } else { cstr!("Config data is empty") };
            }
            return -ERANGE;
        }

        *s.data = rust_xbcw_alloc(size + 1) as *mut c_char;
        if (*s.data).is_null() {
            if !emsg.is_null() {
                *emsg = cstr!("Failed to allocate bootconfig data");
            }
            return -ENOMEM;
        }
        core::ptr::copy_nonoverlapping(data, *s.data, size);
        *(*s.data).add(size) = 0;
        *s.data_size = size + 1;

        *s.nodes = rust_xbcw_alloc(8 * XBC_NODE_MAX as usize) as *mut XbcNode;
        if (*s.nodes).is_null() {
            if !emsg.is_null() {
                *emsg = cstr!("Failed to allocate bootconfig nodes");
            }
            rust_xbc_exit(true);
            return -ENOMEM;
        }
        core::ptr::write_bytes(*s.nodes as *mut u8, 0, 8 * XBC_NODE_MAX as usize);

        let mut ret = xbc_parse_tree();
        if ret == 0 {
            ret = xbc_verify_tree();
        }

        if ret < 0 {
            if !epos.is_null() {
                *epos = *s.err_pos;
            }
            if !emsg.is_null() {
                *emsg = *s.err_msg;
            }
            rust_xbc_exit(true);
        } else {
            ret = *s.node_num;
        }

        ret
    }
}
