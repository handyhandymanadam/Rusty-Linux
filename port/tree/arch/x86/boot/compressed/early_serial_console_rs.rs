// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/early_serial_console.c, which
//! #includes ../early_serial_console.c (also used by the regular-kernel boot
//! code; that file stays C, untouched). Built only with CONFIG_EARLY_PRINTK.
//!
//! Port I/O goes through `pio_ops` (io.h: TDX guests replace the callbacks),
//! exactly as the C's `inb`/`outb` macros do. strncmp() and simple_strtoull()
//! are the stub's own C (string.c) and are called, not re-implemented.

use core::ffi::{c_char, c_int, c_uint};

const DEFAULT_SERIAL_PORT: c_int = 0x3f8; // ttyS0
const DLAB: u8 = 0x80;
const IER: c_int = 1; // interrupt enable
const FCR: c_int = 2; // FIFO control
const LCR: c_int = 3; // line control
const MCR: c_int = 4; // modem control
const DLL: c_int = 0; // divisor latch low
const DLH: c_int = 1; // divisor latch high
const DEFAULT_BAUD: c_int = 9600;
const BASE_BAUD: c_uint = 1843200 / 16;

/// `struct port_io_ops` of arch/x86/boot/io.h.
#[repr(C)]
struct PortIoOps {
    f_inb: Option<unsafe extern "C" fn(u16) -> u8>,
    f_outb: Option<unsafe extern "C" fn(u8, u16)>,
    f_outw: Option<unsafe extern "C" fn(u16, u16)>,
}

extern "C" {
    static pio_ops: PortIoOps;
    fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int;
    fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> u64;
    fn cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
}

/// This might be accessed before .bss is cleared, so use .data instead.
#[no_mangle]
#[link_section = ".data"]
pub static mut early_serial_base: c_int = 0;

#[inline(always)]
unsafe fn inb(port: c_int) -> u8 {
    // SAFETY: init_default_io_ops() (misc.c) has set f_inb before any console code runs; the C called it unconditionally.
    unsafe { (pio_ops.f_inb.unwrap_unchecked())(port as u16) }
}

#[inline(always)]
unsafe fn outb(v: u8, port: c_int) {
    // SAFETY: as inb(), for f_outb.
    unsafe { (pio_ops.f_outb.unwrap_unchecked())(v, port as u16) }
}

unsafe fn early_serial_init(port: c_int, baud: c_int) {
    // SAFETY (whole body): port I/O to the UART the caller chose, via pio_ops, as the C.
    unsafe {
        outb(0x3, port + LCR); // 8n1
        outb(0, port + IER); // no interrupt
        outb(0, port + FCR); // no fifo
        outb(0x3, port + MCR); // DTR + RTS

        let divisor: u32 = (115200 / baud) as u32;
        let c = inb(port + LCR);
        outb(c | DLAB, port + LCR);
        outb((divisor & 0xff) as u8, port + DLL);
        outb(((divisor >> 8) & 0xff) as u8, port + DLH);
        outb(c & !DLAB, port + LCR);

        early_serial_base = port;
    }
}

unsafe fn parse_earlyprintk() {
    let mut baud: c_int = DEFAULT_BAUD;
    let mut arg = [0 as c_char; 32];
    let a = arg.as_mut_ptr();
    let mut pos: isize = 0;
    let mut port: c_int = 0;

    // SAFETY (whole body): `arg` is a live 32-byte buffer, NUL-terminated by cmdline_find_option()
    // when it returns > 0; pos never passes the terminator (as in the C); the extern fns are the stub's C.
    unsafe {
        if cmdline_find_option(c"earlyprintk".as_ptr(), a, 32) > 0 {
            let mut e: *mut c_char = core::ptr::null_mut();

            if strncmp(a, c"serial".as_ptr(), 6) == 0 {
                port = DEFAULT_SERIAL_PORT;
                pos += 6;
            }

            if *a.offset(pos) == b',' as c_char {
                pos += 1;
            }

            // make sure we have
            //   "serial,0x3f8,115200"
            //   "serial,ttyS0,115200"
            //   "ttyS0,115200"
            if pos == 7 && strncmp(a.offset(pos), c"0x".as_ptr(), 2) == 0 {
                port = simple_strtoull(a.offset(pos), &mut e, 16) as c_int;
                if port == 0 || a.offset(pos) == e {
                    port = DEFAULT_SERIAL_PORT;
                } else {
                    pos = e.offset_from(a);
                }
            } else if strncmp(a.offset(pos), c"ttyS".as_ptr(), 4) == 0 {
                const BASES: [c_int; 2] = [0x3f8, 0x2f8];
                let mut idx = 0;

                // += strlen("ttyS");
                pos += 4;

                let ch = *a.offset(pos);
                pos += 1;
                if ch == b'1' as c_char {
                    idx = 1;
                }

                port = BASES[idx];
            }

            if *a.offset(pos) == b',' as c_char {
                pos += 1;
            }

            baud = simple_strtoull(a.offset(pos), &mut e, 0) as c_int;
            if baud == 0 || a.offset(pos) == e {
                baud = DEFAULT_BAUD;
            }
        }

        if port != 0 {
            early_serial_init(port, baud);
        }
    }
}

unsafe fn probe_baud(port: c_int) -> c_uint {
    // SAFETY (whole body): port I/O to the UART the caller chose, via pio_ops, as the C.
    unsafe {
        let lcr = inb(port + LCR);
        outb(lcr | DLAB, port + LCR);
        let dll = inb(port + DLL);
        let dlh = inb(port + DLH);
        outb(lcr, port + LCR);
        let quot: c_uint = ((dlh as c_uint) << 8) | dll as c_uint;

        BASE_BAUD / quot
    }
}

unsafe fn parse_console_uart8250() {
    let mut optstr = [0 as c_char; 64];
    let mut options: *mut c_char;
    let baud: c_int;
    let mut port: c_int = 0;

    // console=uart8250,io,0x3f8,115200n8
    // need to make sure it is last one console !
    // SAFETY (whole body): `optstr` is a live 64-byte buffer, NUL-terminated by cmdline_find_option()
    // when it returns > 0; the prefix lengths 12/8 are within the matched prefix; extern fns are the stub's C.
    unsafe {
        if cmdline_find_option(c"console".as_ptr(), optstr.as_mut_ptr(), 64) <= 0 {
            return;
        }

        options = optstr.as_mut_ptr();

        if strncmp(options, c"uart8250,io,".as_ptr(), 12) == 0 {
            port = simple_strtoull(options.add(12), &mut options, 0) as c_int;
        } else if strncmp(options, c"uart,io,".as_ptr(), 8) == 0 {
            port = simple_strtoull(options.add(8), &mut options, 0) as c_int;
        } else {
            return;
        }

        if !options.is_null() && *options == b',' as c_char {
            let mut b = simple_strtoull(options.add(1), core::ptr::null_mut(), 0) as c_int;
            if b == 0 {
                b = DEFAULT_BAUD;
            }
            baud = b;
        } else {
            baud = probe_baud(port) as c_int;
        }

        if port != 0 {
            early_serial_init(port, baud);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn console_init() {
    // SAFETY: stub-time single-threaded; early_serial_base is a plain int written only above.
    unsafe {
        parse_earlyprintk();

        if early_serial_base == 0 {
            parse_console_uart8250();
        }
    }
}
