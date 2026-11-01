// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/error.c (warn() and error()).
//!
//! The boot stub's fatal-error path. Text and call order are those of the C:
//! warn() prints "\n\n", the message, "\n\n"; error() is warn() then
//! " -- System halted" and a hlt loop. The *_putstr() functions stay in
//! misc.c (it defines them as `error_putstr(x) == __putstr(x)`).
//! Built only for the 64-bit stub with CONFIG_RUST (see the Makefile).

#![cfg_attr(efi_stub, feature(c_variadic))]

use core::arch::asm;
use core::ffi::c_char;

extern "C" {
    /// misc.c: writes to the early serial port and/or VGA.
    fn __putstr(s: *const c_char);
}

/// `void warn(const char *m)`
///
/// # Safety
/// `m` must point to a NUL-terminated string (as for the C).
#[no_mangle]
pub unsafe extern "C" fn warn(m: *const c_char) {
    // SAFETY: __putstr() takes NUL-terminated strings; the literals are, and `m` is by contract.
    unsafe {
        __putstr(c"\n\n".as_ptr());
        __putstr(m);
        __putstr(c"\n\n".as_ptr());
    }
}

/// `void error(char *m) __noreturn`
///
/// # Safety
/// `m` must point to a NUL-terminated string (as for the C).
#[no_mangle]
pub unsafe extern "C" fn error(m: *mut c_char) -> ! {
    // SAFETY: same contract as warn(); the literal is NUL-terminated.
    unsafe {
        warn(m);
        __putstr(c" -- System halted".as_ptr());
    }
    loop {
        // SAFETY: `hlt` has no operands; the C did `asm("hlt")` in the same loop.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

/// `void panic(const char *fmt, ...) __noreturn` -- CONFIG_EFI_STUB only (the EFI libstub
/// provides vsnprintf()). Formats into a 1024-byte buffer, drops one trailing '\n', error().
#[cfg(efi_stub)]
mod panic_efi {
    use core::ffi::{c_char, c_int, VaList};

    extern "C" {
        /// drivers/firmware/efi/libstub/vsprintf.c
        fn vsnprintf(buf: *mut c_char, size: usize, fmt: *const c_char, args: VaList) -> c_int;
    }

    static mut BUF: [c_char; 1024] = [0; 1024];

    /// # Safety
    /// `fmt` and the variadic arguments must match, as for the C.
    #[no_mangle]
    pub unsafe extern "C" fn panic(fmt: *const c_char, args: ...) -> ! {
        let buf = (&raw mut BUF) as *mut c_char;
        // SAFETY: buf is a live 1024-byte static; fmt/args per the contract.
        let len = unsafe { vsnprintf(buf, 1024, fmt, args) };
        // SAFETY: len - 1 is inside buf as long as vsnprintf returns what fits (as in the C).
        unsafe {
            if len != 0 && *buf.offset((len - 1) as isize) == b'\n' as c_char {
                *buf.offset((len - 1) as isize) = 0;
            }
            super::error(buf)
        }
    }
}
