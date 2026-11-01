// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/tty.c (16-bit real-mode setup; very simple screen,
//! serial and keyboard I/O through the BIOS). Same exported symbols as the C:
//! early_serial_base, putchar, puts, getchar, kbd_flush, getchar_timeout.
//!
//! putchar/puts and their helpers stay in `.inittext` (the C's `__section(".inittext")`),
//! because they are used to signal errors during initialization.
#![allow(dead_code)]

#[path = "rm_common.rs"]
mod rm;

use core::ffi::{c_char, c_int};
use rm::*;

const XMTRDY: u8 = 0x20;
const TXR: u16 = 0; // transmit register (WRITE)
const LSR: u16 = 5; // line status

/// `int early_serial_base;` (zero-initialised; placed in plain `.bss`, which is what
/// setup.ld collects -- it does not match `.bss.<name>`).
#[no_mangle]
#[link_section = ".bss"]
pub static mut early_serial_base: c_int = 0;

#[link_section = ".inittext"]
unsafe fn serial_putchar(ch: c_int) {
    let mut timeout: u32 = 0xffff; // `unsigned`
    // SAFETY: early_serial_base is a plain global in single-threaded real mode.
    let base = unsafe { early_serial_base } as u16;
    loop {
        // SAFETY: port I/O on the UART the user asked for with earlyprintk=.
        let lsr = unsafe { inb(base.wrapping_add(LSR)) };
        if lsr & XMTRDY != 0 {
            break;
        }
        timeout -= 1;
        if timeout == 0 {
            break;
        }
        cpu_relax();
    }
    // SAFETY: as above.
    unsafe { outb(ch as u8, base.wrapping_add(TXR)) };
}

#[link_section = ".inittext"]
unsafe fn bios_putchar(ch: c_int) {
    // SAFETY: BIOS INT 10h/AH=0Eh teletype output.
    unsafe {
        let mut ireg = new_regs();
        ireg.ebx = 0x0007;
        ireg.ecx = 0x0001;
        ireg.eax = (ireg.eax & !0xffff) | 0x0e00 | (ch as u32 & 0xff);
        intcall(0x10, &ireg, core::ptr::null_mut());
    }
}

#[no_mangle]
#[link_section = ".inittext"]
pub unsafe extern "C" fn putchar(ch: c_int) {
    // SAFETY: see helpers.
    unsafe {
        if ch == b'\n' as c_int {
            putchar(b'\r' as c_int); // \n -> \r\n
        }
        bios_putchar(ch);
        if early_serial_base != 0 {
            serial_putchar(ch);
        }
    }
}

#[no_mangle]
#[link_section = ".inittext"]
pub unsafe extern "C" fn puts(str: *const c_char) {
    let mut p = str;
    // SAFETY: `str` is NUL-terminated, as for the C.
    unsafe {
        while *p != 0 {
            putchar(*p as c_int);
            p = p.add(1);
        }
    }
}

/// Read the CMOS clock through the BIOS and return the seconds in BCD.
unsafe fn gettime() -> u8 {
    // SAFETY: BIOS INT 1Ah/AH=02h.
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        ireg.eax = (ireg.eax & !0xff00) | 0x0200;
        intcall(0x1a, &ireg, oreg.as_mut_ptr());
        (oreg.assume_init().edx >> 8) as u8 // oreg.dh
    }
}

/// Read from the keyboard.
#[no_mangle]
pub unsafe extern "C" fn getchar() -> c_int {
    // SAFETY: BIOS INT 16h/AH=00h.
    unsafe {
        let ireg = new_regs();
        let mut oreg = out_regs();
        intcall(0x16, &ireg, oreg.as_mut_ptr());
        (oreg.assume_init().eax & 0xff) as c_int // oreg.al
    }
}

unsafe fn kbd_pending() -> bool {
    // SAFETY: BIOS INT 16h/AH=01h.
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        ireg.eax = (ireg.eax & !0xff00) | 0x0100;
        intcall(0x16, &ireg, oreg.as_mut_ptr());
        oreg.assume_init().eflags & X86_EFLAGS_ZF == 0
    }
}

#[no_mangle]
pub unsafe extern "C" fn kbd_flush() {
    // SAFETY: see helpers.
    unsafe {
        loop {
            if !kbd_pending() {
                break;
            }
            getchar();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn getchar_timeout() -> c_int {
    let mut cnt: c_int = 30;
    // SAFETY: see helpers.
    unsafe {
        let mut t0 = gettime() as c_int;
        while cnt != 0 {
            if kbd_pending() {
                return getchar();
            }
            let t1 = gettime() as c_int;
            if t0 != t1 {
                cnt -= 1;
                t0 = t1;
            }
        }
    }
    0 // Timeout!
}
