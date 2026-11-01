// SPDX-License-Identifier: GPL-2.0-or-later

//! Rust part of `kernel/params.c`: the command-line walker. `parse_args()` (the loop that splits a
//! string like "foo=bar,bar2 baz=fuz wiz" into parameters, stops at `--`, dispatches each one and reports
//! the failures), `parse_one()` (the table lookup and the call of the parameter's `set`), `parameq()`,
//! `parameqn()` and `dash2underscore()`. Everything else in the file (the typed `param_set_*` / `param_get_*`
//! families and their exports, the sysfs attributes, `kernel_param_lock()`, `param_check_unsafe()`, the kmalloc'ed
//! parameter bookkeeping) stays C in `params_glue.c`.
//!
//! Reached from `start_kernel()` (`parse_args("Booting kernel", ...)`, `parse_early_options()` via
//! `parse_early_param()`) and, at run time, from the module loader (`load_module()`). The function keeps no state of
//! its own; the only shared things it touches are the parameter's mutex, taken through the C `kernel_param_lock()`
//! (a mutex, so it may sleep: this code runs in process context, exactly like the C), and the
//! parameter callbacks it is handed.
//!
//! Error messages are the C's, byte for byte (`logs/hooks.md`, params record); `pr_debug` is a no-op in a kernel without
//! `CONFIG_DYNAMIC_DEBUG` (both configs here), and with it the C would plant `struct _ddebug` entries naming
//! `kernel/params.c` that Rust cannot, so that configuration is a `compile_error!`.
//!
//! No panic path: pointer arithmetic is raw, counters wrap; `rig/uaccess-panic-check.sh` and the `nm` check in
//! logs/hooks.md confirm the object has no `panic*` undefined symbol.
//!
//! Replaces (x86-64 only): dash2underscore, parameqn, parameq, parse_one, parse_args in kernel/params.c

use core::ffi::{c_char, c_void};

#[cfg(CONFIG_DYNAMIC_DEBUG)]
compile_error!("kernel/params_rs.rs: pr_debug() sites of parse_one()/parse_args() would plant _ddebug entries; port them to C first");
#[cfg(not(CONFIG_SYSFS))]
compile_error!("kernel/params_rs.rs: without CONFIG_SYSFS kernel_param_lock() is an empty inline, not a symbol");
#[cfg(CONFIG_PARAVIRT_XXL)]
compile_error!("kernel/params_rs.rs: irqs_disabled() reads EFLAGS directly");

// C-HEADERS: linux/types.h linux/moduleparam.h linux/errno.h asm/processor-flags.h
/// `ENOENT`.
const ENOENT: i32 = 2; // C: ENOENT
/// `EPERM`.
const EPERM: i32 = 1; // C: EPERM
/// `EINVAL`.
const EINVAL: i32 = 22; // C: EINVAL
/// `ENOSPC`.
const ENOSPC: i32 = 28; // C: ENOSPC
/// `KERNEL_PARAM_OPS_FL_NOARG`.
const KERNEL_PARAM_OPS_FL_NOARG: u32 = 1; // C: KERNEL_PARAM_OPS_FL_NOARG
/// `sizeof(struct kernel_param)`.
const KP_SIZE: usize = 40; // C: sizeof(struct kernel_param)
/// `offsetof(struct kernel_param, name)`.
const KP_NAME: usize = 0; // C: offsetof(struct kernel_param, name)
/// `offsetof(struct kernel_param, mod)`.
const KP_MOD: usize = 8; // C: offsetof(struct kernel_param, mod)
/// `offsetof(struct kernel_param, ops)`.
const KP_OPS: usize = 16; // C: offsetof(struct kernel_param, ops)
/// `offsetof(struct kernel_param, level)`.
const KP_LEVEL: usize = 26; // C: offsetof(struct kernel_param, level)
/// `offsetof(struct kernel_param_ops, flags)`.
const OPS_FLAGS: usize = 0; // C: offsetof(struct kernel_param_ops, flags)
/// `offsetof(struct kernel_param_ops, set)`.
const OPS_SET: usize = 8; // C: offsetof(struct kernel_param_ops, set)
/// `X86_EFLAGS_IF`.
const X86_EFLAGS_IF: u64 = 0x200; // C: X86_EFLAGS_IF

/// The `set` callback of `struct kernel_param_ops`.
type SetFn = unsafe extern "C" fn(*const c_char, *const KernelParam) -> i32;
/// `parse_unknown_fn`.
pub type UnknownFn = unsafe extern "C" fn(*mut c_char, *mut c_char, *const c_char, *mut c_void) -> i32;

/// The first fields of `struct kernel_param` (the rest, `perm`, `flags` and the union, is not read here).
/// Layout of `struct kernel_param` (size and offsets checked by consts_check.py; not annotated `Mirrors`: rig/layout-check.sh flattens the C anonymous union into extra members and reports a geometry difference that is only that).
#[repr(C)]
pub struct KernelParam {
    /// `name`.
    pub name: *const c_char,
    /// `mod` (a `struct module *`).
    pub module: *mut c_void,
    /// `ops`.
    pub ops: *const KernelParamOps,
    /// `perm`.
    pub perm: u16,
    /// `level`.
    pub level: i8,
    /// `flags`.
    pub flags: u8,
    /// the union (`arg` / `str` / `arr`).
    pub arg: *mut c_void,
}

/// `struct kernel_param_ops`.
/// Mirrors `struct kernel_param_ops`.
#[repr(C)]
pub struct KernelParamOps {
    /// `flags`.
    pub flags: u32,
    /// `set`.
    pub set: SetFn,
    /// `get` (unused here).
    pub get: *const c_void,
    /// `free` (unused here).
    pub free: *const c_void,
}

const _: () = assert!(core::mem::size_of::<KernelParam>() == KP_SIZE);
const _: () = assert!(core::mem::offset_of!(KernelParam, name) == KP_NAME);
const _: () = assert!(core::mem::offset_of!(KernelParam, module) == KP_MOD);
const _: () = assert!(core::mem::offset_of!(KernelParam, ops) == KP_OPS);
const _: () = assert!(core::mem::offset_of!(KernelParam, level) == KP_LEVEL);
const _: () = assert!(core::mem::offset_of!(KernelParamOps, flags) == OPS_FLAGS);
const _: () = assert!(core::mem::offset_of!(KernelParamOps, set) == OPS_SET);

// What the C file provides or the kernel exports; in the userspace test the harness supplies them.
extern "C" {
    fn next_arg(args: *mut c_char, param: *mut *mut c_char, val: *mut *mut c_char) -> *mut c_char;
    fn skip_spaces(s: *const c_char) -> *mut c_char;
    fn kernel_param_lock(m: *mut c_void);
    fn kernel_param_unlock(m: *mut c_void);
    /// `static bool param_check_unsafe(const struct kernel_param *kp)` in `params_glue.c` (made non-static there).
    fn param_check_unsafe(kp: *const KernelParam) -> bool;
    fn _printk(fmt: *const c_char, ...) -> i32;
}

// `parse_one()` was `static` in the C: hidden, so that after the final link it is local again (`/proc/kallsyms`
// letter `t`). `param_check_unsafe()` lost its `static` in the glue; hidden for the same reason.
#[cfg(not(userspace_test))]
core::arch::global_asm!(".hidden parse_one", ".hidden param_check_unsafe");

/// `dash2underscore()`.
#[inline(always)]
fn dash2underscore(c: u8) -> u8 {
    if c == b'-' {
        b'_'
    } else {
        c
    }
}

/// `parameqn()`: equal for the first `n` characters, a dash counting as an underscore.
///
/// # Safety
/// `a` and `b` are readable up to the first difference or `n` bytes, as in the C.
#[no_mangle]
pub unsafe extern "C" fn parameqn(a: *const c_char, b: *const c_char, n: usize) -> bool {
    let mut i: usize = 0;
    while i < n {
        // SAFETY: caller contract (the C reads the same bytes in the same order and stops at the first difference).
        let (x, y) = unsafe { (*a.add(i) as u8, *b.add(i) as u8) };
        if dash2underscore(x) != dash2underscore(y) {
            return false;
        }
        i = i.wrapping_add(1);
    }
    true
}

/// `parameq()`: `parameqn(a, b, strlen(a) + 1)`.
///
/// # Safety
/// `a` and `b` are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn parameq(a: *const c_char, b: *const c_char) -> bool {
    let mut len: usize = 0;
    // SAFETY: `a` is NUL-terminated.
    while unsafe { *a.add(len) } != 0 {
        len = len.wrapping_add(1);
    }
    // SAFETY: as parameqn.
    unsafe { parameqn(a, b, len.wrapping_add(1)) }
}

/// `irqs_disabled()` (x86: `native_save_fl()` and the `IF` bit).
#[cfg(not(userspace_test))]
#[inline(always)]
fn irqs_disabled() -> bool {
    let flags: u64;
    // SAFETY: the C was `pushf; pop`.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
    flags & X86_EFLAGS_IF == 0
}
/// Userspace test: the harness owns the flag.
#[cfg(userspace_test)]
fn irqs_disabled() -> bool {
    extern "C" {
        fn test_irqs_disabled() -> bool;
    }
    // SAFETY: harness.
    unsafe { test_irqs_disabled() }
}

/// `parse_one()`.
///
/// # Safety
/// As `parse_args`.
#[no_mangle]
pub unsafe extern "C" fn parse_one(
    param: *mut c_char,
    val: *mut c_char,
    doing: *const c_char,
    params: *const KernelParam,
    num_params: u32,
    min_level: i16,
    max_level: i16,
    arg: *mut c_void,
    handle_unknown: Option<UnknownFn>,
) -> i32 {
    let mut i: u32 = 0;
    /* Find parameter */
    while i < num_params {
        // SAFETY: `params` has `num_params` entries.
        let p = unsafe { params.add(i as usize) };
        // SAFETY: `name` is a NUL-terminated string; `param` too.
        if unsafe { parameq(param, (*p).name) } {
            // SAFETY: a registered parameter has ops.
            let ops = unsafe { &*(*p).ops };
            let level = unsafe { (*p).level } as i16;
            if level < min_level || level > max_level {
                return 0;
            }
            /* No one handled NULL, so do it here. */
            if val.is_null() && ops.flags & KERNEL_PARAM_OPS_FL_NOARG == 0 {
                return -EINVAL;
            }
            // SAFETY: the C calls these with the same arguments in the same order.
            unsafe {
                kernel_param_lock((*p).module);
                let err = if param_check_unsafe(p) { (ops.set)(val, p) } else { -EPERM };
                kernel_param_unlock((*p).module);
                return err;
            }
        }
        i = i.wrapping_add(1);
    }

    if let Some(f) = handle_unknown {
        // SAFETY: the callback the caller supplied.
        return unsafe { f(param, val, doing, arg) };
    }

    -ENOENT
}

/// `val ?: ""`.
const EMPTY: &[u8; 1] = b"\0";

/// `parse_args()`: "Args looks like "foo=bar,bar2 baz=fuz wiz"."
///
/// # Safety
/// `args` is a writable NUL-terminated string (`next_arg()` writes into it); `params` has `num` entries;
/// `doing` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn parse_args(
    doing: *const c_char,
    args: *mut c_char,
    params: *const KernelParam,
    num: u32,
    min_level: i16,
    max_level: i16,
    arg: *mut c_void,
    unknown: Option<UnknownFn>,
) -> *mut c_char {
    let mut param: *mut c_char = core::ptr::null_mut();
    let mut val: *mut c_char = core::ptr::null_mut();
    let mut err: *mut c_char = core::ptr::null_mut();

    /* Chew leading spaces */
    // SAFETY: `args` is a string.
    let mut args = unsafe { skip_spaces(args) };

    // SAFETY: as above, every `*args` read is of a NUL-terminated string `next_arg` advanced.
    while unsafe { *args } != 0 {
        // SAFETY: `args` is writable and NUL-terminated.
        args = unsafe { next_arg(args, &mut param, &mut val) };
        /* Stop at -- */
        // SAFETY: `param` was set by `next_arg` to a NUL-terminated string.
        if val.is_null() && unsafe { is_dashdash(param) } {
            return if !err.is_null() { err } else { args };
        }
        let irq_was_disabled = irqs_disabled();
        // SAFETY: as parse_one.
        let ret = unsafe { parse_one(param, val, doing, params, num, min_level, max_level, arg, unknown) };
        if irq_was_disabled && !irqs_disabled() {
            // SAFETY: printk with the C's format and arguments (KERN_WARNING).
            unsafe { _printk(c"\x014%s: option '%s' enabled irq's!\n".as_ptr(), doing, param) };
        }

        match ret {
            0 => continue,
            x if x == -ENOENT => {
                // SAFETY: KERN_ERR.
                unsafe { _printk(c"\x013%s: Unknown parameter `%s'\n".as_ptr(), doing, param) };
            }
            x if x == -ENOSPC => {
                let v = if val.is_null() { EMPTY.as_ptr() as *const c_char } else { val as *const c_char };
                // SAFETY: KERN_ERR.
                unsafe { _printk(c"\x013%s: `%s' too large for parameter `%s'\n".as_ptr(), doing, v, param) };
            }
            _ => {
                let v = if val.is_null() { EMPTY.as_ptr() as *const c_char } else { val as *const c_char };
                // SAFETY: KERN_ERR.
                unsafe { _printk(c"\x013%s: `%s' invalid for parameter `%s'\n".as_ptr(), doing, v, param) };
            }
        }

        err = ret as isize as *mut c_char; // ERR_PTR(ret)
    }

    err
}

/// `strcmp(param, "--") == 0`.
///
/// # Safety
/// `s` is NUL-terminated.
#[inline(always)]
unsafe fn is_dashdash(s: *const c_char) -> bool {
    // SAFETY: stops at the first NUL, so no read beyond the terminator.
    unsafe { *s as u8 == b'-' && *s.add(1) as u8 == b'-' && *s.add(2) == 0 }
}
