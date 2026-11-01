// SPDX-License-Identifier: GPL-2.0-only

//! Rust part of `init/main.c`: the early command-line pass. `parse_early_param()` (once: copy `boot_command_line` into a
//! private buffer and parse it), `parse_early_options()` (a `parse_args()` call with `do_early_param` as the unknown-parameter
//! handler) and `do_early_param()` (for every entry of the `__setup` table that is `early` and whose name `parameq`s the
//! parameter, call its `setup_func`; a non-zero result prints "Malformed early option"). Everything else in the file (start_kernel
//! and the rest of the 1,500 lines) stays C in `main_glue.c`.
//!
//! Runs once on the boot CPU from `setup_arch()` (x86) or just before `parse_args("Booting kernel", ...)`, interrupts off,
//! before the allocator; the buffer and the `done` flag are private `__initdata`. The callbacks it runs are the kernel's `early_param()`
//! handlers (arbitrary code). No panic path.
//!
//! The message is the C's, byte for byte (`rig/phase-e/msgs_check.py`).
//!
//! Replaces (x86-64 only): do_early_param, parse_early_options, parse_early_param in init/main.c

use core::ffi::{c_char, c_void};

#[cfg(CONFIG_FORTIFY_SOURCE)]
compile_error!("init/main_rs.rs: strscpy() under FORTIFY_SOURCE is a checked inline; port it before enabling");

// C-HEADERS: linux/types.h asm/setup.h linux/init.h
/// `COMMAND_LINE_SIZE` (x86: asm/setup.h).
const COMMAND_LINE_SIZE: usize = 2048; // C: COMMAND_LINE_SIZE
/// `sizeof(struct obs_kernel_param)`.
const OBS_SIZE: usize = 24; // C: sizeof(struct obs_kernel_param)
/// `offsetof(struct obs_kernel_param, setup_func)`.
const OBS_SETUP_FUNC: usize = 8; // C: offsetof(struct obs_kernel_param, setup_func)
/// `offsetof(struct obs_kernel_param, early)`.
const OBS_EARLY: usize = 16; // C: offsetof(struct obs_kernel_param, early)

/// `struct obs_kernel_param` (linux/init.h): one `__setup()` / `early_param()` registration.
/// Mirrors `struct obs_kernel_param`.
#[repr(C)]
pub struct ObsKernelParam {
    /// `str`: the parameter name (with `=` for `__setup`).
    pub name: *const c_char,
    /// `setup_func`.
    pub setup_func: unsafe extern "C" fn(*mut c_char) -> i32,
    /// `early`.
    pub early: i32,
}
const _: () = assert!(core::mem::size_of::<ObsKernelParam>() == OBS_SIZE);
const _: () = assert!(core::mem::offset_of!(ObsKernelParam, setup_func) == OBS_SETUP_FUNC);
const _: () = assert!(core::mem::offset_of!(ObsKernelParam, early) == OBS_EARLY);

type UnknownFn = unsafe extern "C" fn(*mut c_char, *mut c_char, *const c_char, *mut c_void) -> i32;

extern "C" {
    /// `__setup_start[]`, `__setup_end[]` (the `.init.setup` section bounds, vmlinux.lds).
    static __setup_start: [ObsKernelParam; 0];
    static __setup_end: [ObsKernelParam; 0];
    static boot_command_line: [c_char; COMMAND_LINE_SIZE];
    fn parameq(a: *const c_char, b: *const c_char) -> bool;
    fn parse_args(doing: *const c_char, args: *mut c_char, params: *const c_void, num: u32, min_level: i16, max_level: i16, arg: *mut c_void, unknown: Option<UnknownFn>) -> *mut c_char;
    fn sized_strscpy(dst: *mut c_char, src: *const c_char, count: usize) -> isize;
    fn _printk(fmt: *const c_char, ...) -> i32;
}

/// `static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata` (function-local in the C).
#[link_section = ".init.data"]
static mut TMP_CMDLINE: [c_char; COMMAND_LINE_SIZE] = [0; COMMAND_LINE_SIZE];
/// `static int done __initdata`.
#[link_section = ".init.data"]
static mut DONE: i32 = 0;

/// `do_early_param()`: "Check for early params."
///
/// # Safety
/// Called by `parse_args` with NUL-terminated `param` (and `val` or NULL).
#[link_section = ".init.text"]
unsafe extern "C" fn do_early_param(param: *mut c_char, val: *mut c_char, _unused: *const c_char, _arg: *mut c_void) -> i32 {
    // the linker-provided table bounds (taking the address of an extern static is safe)
    let (mut p, end) = ((&raw const __setup_start) as *const ObsKernelParam, (&raw const __setup_end) as *const ObsKernelParam);
    while p < end {
        // SAFETY: p is inside the table.
        unsafe {
            if (*p).early != 0 && parameq(param, (*p).name) && ((*p).setup_func)(val) != 0 {
                _printk(c"\x014Malformed early option '%s'\n".as_ptr(), param);
            }
            p = p.add(1);
        }
    }
    /* We accept everything at this stage. */
    0
}

/// `parse_early_options()`.
///
/// # Safety
/// `cmdline` is a writable NUL-terminated string.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn parse_early_options(cmdline: *mut c_char) {
    // SAFETY: as parse_args.
    unsafe { parse_args(c"early options".as_ptr(), cmdline, core::ptr::null(), 0, 0, 0, core::ptr::null_mut(), Some(do_early_param)) };
}

/// `parse_early_param()`: "Arch code calls this early on, or if not, just before other parsing."
///
/// # Safety
/// Boot CPU, early boot; `boot_command_line` is set.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn parse_early_param() {
    // SAFETY: single CPU, private `__initdata`.
    unsafe {
        if DONE != 0 {
            return;
        }

        /* All fall through to do_early_param. */
        let tmp = (&raw mut TMP_CMDLINE) as *mut c_char;
        sized_strscpy(tmp, (&raw const boot_command_line) as *const c_char, COMMAND_LINE_SIZE);
        parse_early_options(tmp);
        DONE = 1;
    }
}

/// Userspace test only: forget that `parse_early_param()` already ran.
///
/// # Safety
/// Single-threaded test harness.
#[cfg(userspace_test)]
pub unsafe fn test_reset_done() {
    // SAFETY: harness.
    unsafe { DONE = 0 };
}
