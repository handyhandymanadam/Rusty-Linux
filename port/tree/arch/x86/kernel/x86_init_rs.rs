// SPDX-License-Identifier: GPL-2.0

//! Rust part of `arch/x86/kernel/x86_init.c`: the six global no-op callbacks. The rest of the file (the
//! `x86_init`, `x86_cpuinit`, `x86_platform` and `x86_apic_ops` tables of function pointers, the `static` no-op
//! callbacks the tables point at, `x86_wallclock_init()`, the `EXPORT_SYMBOL_GPL(x86_platform)`) stays C in
//! `x86_init_glue.c`: it is data whose initialisers name functions of a dozen other files and
//! whose structure layouts the headers own; the `static` no-ops are only reachable through those tables (a Rust
//! definition would have to become a global symbol, changing `/proc/kallsyms`, for no logic).
//!
//! These six are pure: each returns a constant or does nothing. They are installed as indirect-call targets
//! (`x86_init.*`, `x86_platform.get_wallclock`, ...) and `x86_init_noop` is also compared by address by some
//! callers, so each is a real, separate symbol (no merging with identical code: kbuild passes no
//! `-C llvm-args=-enable-mergefunc`; checked in the object, see logs/hooks.md).
//!
//! No panic path (nothing to compute).
//!
//! Replaces (x86-64 only): the six functions named above in arch/x86/kernel/x86_init.c

use core::ffi::c_void;

// C-HEADERS: linux/types.h linux/errno.h
/// `EINVAL` (uapi/asm-generic/errno-base.h).
const EINVAL: i32 = 22; // C: EINVAL

/// `void x86_init_noop(void) { }`.
#[no_mangle]
pub extern "C" fn x86_init_noop() {}

/// `void __init x86_init_uint_noop(unsigned int unused) { }`.
#[no_mangle]
#[link_section = ".init.text"]
pub extern "C" fn x86_init_uint_noop(_unused: u32) {}

/// `bool __init bool_x86_init_noop(void) { return false; }`.
#[no_mangle]
#[link_section = ".init.text"]
pub extern "C" fn bool_x86_init_noop() -> bool {
    false
}

/// `void x86_op_int_noop(int cpu) { }`.
#[no_mangle]
pub extern "C" fn x86_op_int_noop(_cpu: i32) {}

/// `int set_rtc_noop(const struct timespec64 *now) { return -EINVAL; }`.
#[no_mangle]
pub extern "C" fn set_rtc_noop(_now: *const c_void) -> i32 {
    -EINVAL
}

/// `void get_rtc_noop(struct timespec64 *now) { }`.
#[no_mangle]
pub extern "C" fn get_rtc_noop(_now: *mut c_void) {}
