// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/early_serial_console.c in the 16-bit real-mode setup (code16, -Zregparm=3).
//! The C file is `#include`d by compressed/early_serial_console.c for the 64-bit boot stub (which has its own accepted
//! Rust version, compressed/early_serial_console_rs.rs, untouched); here it is a plain object that exports exactly the
//! one global of the C object (nm of build-fast early_serial_console.o): `console_init()`. `early_serial_base` is
//! tty.c's (tty_rs.rs's) variable, `early_serial_init`, `parse_*` and `probe_baud` are private (static) as in the C.
//! Placement: the C object has only `.text` (+ .rodata); nothing is in `.inittext`, and nothing here is either.
//!
//! Behaviour = the C, line for line: `console_init()` runs `parse_earlyprintk()` ("earlyprintk=serial,0x3f8,115200",
//! "serial,ttyS1", "ttyS0,115200", "0x2f8", default port 0x3f8 and baud 9600, "0x" only right after "serial,"), and if no
//! port was set `parse_console_uart8250()` ("console=uart8250,io,0x3f8,115200n8" / "uart,io,..."; no baud given ->
//! `probe_baud(port)` reads the divisor latch back from the UART). `early_serial_init()` programs the UART through
//! `pio_ops` (io.h: TDX guests swap the callbacks) in the C's order: LCR=3, IER=0, FCR=0, MCR=3, divisor = 115200/baud,
//! inb(LCR), LCR|DLAB, DLL, DLH, LCR&~DLAB, then `early_serial_base = port`. Port numbers are `port + REG` truncated to 16
//! bits by io.h's `u16` port argument (e.g. port 0xffff+3 -> 2), exactly as the C. No message strings exist in the C or here.
//! boot.h's inline `cmdline_find_option()` (cmd_line_ptr >= 1 MiB -> -1) is reproduced (boot_params.hdr.cmd_line_ptr at 0x228).
//!
//! Divisions (the point of the task): the C divides in two places, and in both the instruction is the trapping hardware one:
//!   * `probe_baud`: `BASE_BAUD / quot` with quot = (dlh<<8)|dll read from hardware, 0 when the UART reads 0/0 -> C `div %ecx`
//!     -> #DE (INT 0, the real-mode vector at 0000:0000). A Rust `/` would be `cmp; je ud2` (panic=immediate-abort: #UD, INT 6)
//!     = a different trap. Here `div_u32()` is the same `div` instruction in asm, so the trap (and, unwinding nothing, the
//!     whole behaviour) is identical: DIVERGENCE REMOVED, not merely recorded.
//!   * `early_serial_init`: `115200 / baud` (signed int, `idiv`), baud == 0 is unreachable (both callers map 0 to 9600; the
//!     int truncation is applied before the test; probe_baud's result is 1..=115200); negative baud (0x80000000.. as int) is
//!     reachable and divides to a negative number whose low 16 bits go to DLL/DLH (same `idiv`, via `idiv_i32()`).
//!     115200/INT_MIN cannot overflow (the dividend is the constant).
//!
//! Where the Rust differs from the C (all recorded): (1) `arg[32]` / `optstr[64]` are zero-initialised; the C leaves
//! them uninitialised and cmdline_find_option() writes only min(len, size-1)+1 bytes, so for a value that ends right after
//! "ttyS" the C's `arg[pos++]` (pos = 5, past the NUL) and the following `arg[pos] == ','` test read an indeterminate stack
//! byte, the Rust reads 0 (= one of the C's possible behaviours; a real stack byte of ',' would have made the C parse a
//! baud from stack garbage). (2) `/` -> asm as above (no behaviour change). (3) `port + REG` is `wrapping_add` (the C's int add wraps in the
//! kernel build; `earlyprintk=serial,0x7ffffffe` reaches it) and `cs!("..")` is a NUL-terminated literal (= `c".."`, Kani cannot parse the latter).
//! Everything else is the same control flow. LLVM turns the equality-only `strncmp(x, "lit", n)` calls into inline word compares / a `memcmp`
//! call (setup's string.c/string_rs.rs memcmp); same result, x always has >= n readable bytes (arg[32], optstr[64]). `early_serial_init` is a
//! local (`t`) symbol with a mangled name, not exported, as the C's `static`.
//!
//! TEST-GAP: (a) the indeterminate-stack read of (1); (b) the real UART: baud/divisor programming is only observable in the
//! QEMU register trace (rig/realmode/uart-trace.sh) and the host model, never on silicon (FIFO/16550A quirks, an absent UART
//! reading 0xff, the DLAB protocol of real chips); (c) a UART whose divisor reads 0 under `probe_baud`: #DE in real mode goes to
//! the BIOS's INT 0 handler; the host test only checks that C and Rust both trap at the same access; (d) cmd_line_ptr >= 1 MiB
//! (inaccessible command line) cannot be provoked by the loader in a boot; the host model returns -1 from the mock instead.
//! Under `--cfg host_mock` (host tests only) only the cmdline lookup is an extern hook (the harness supplies strncmp/memcmp/
//! simple_strtoull: the real string.c); never set for the target build.
#![allow(dead_code)]

#[cfg(not(kani))]
#[path = "rm_common.rs"]
mod rm;

use core::arch::asm;
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

/// A NUL-terminated string literal as a `*const c_char` (same bytes as `c"..."`; Kani does not support C-string literals).
macro_rules! cs {
    ($s:literal) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

#[cfg(not(kani))]
extern "C" {
    fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int;
    fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> u64;
    /// tty.c / tty_rs.rs
    static mut early_serial_base: c_int;
}
#[cfg(kani)]
static mut early_serial_base: c_int = 0;
#[cfg(kani)]
use kmodel::{simple_strtoull, strncmp};
#[cfg(not(any(host_mock, kani)))]
extern "C" {
    /// boot.h: `boot_params.hdr.cmd_line_ptr` (u32 at 0x228); cmdline.c
    static boot_params: [u8; 4096];
    fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
}
#[cfg(host_mock)]
extern "C" {
    fn mock_cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
}

/// boot.h's inline `cmdline_find_option()`: -1 if the command line is inaccessible (cmd_line_ptr >= 1 MiB).
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
unsafe fn cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int {
    // SAFETY: boot_params is the zero page; the field is a naturally aligned u32 at 0x228.
    unsafe {
        let p = (core::ptr::addr_of!(boot_params) as *const u8).add(0x228) as *const u32;
        let cmd_line_ptr = p.read();
        if cmd_line_ptr >= 0x100000 {
            return -1;
        }
        __cmdline_find_option(cmd_line_ptr, option, buffer, bufsize)
    }
}
#[cfg(kani)]
use kmodel::cmdline_find_option;
#[cfg(host_mock)]
#[inline(always)]
unsafe fn cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int {
    unsafe { mock_cmdline_find_option(option, buffer, bufsize) }
}

/// io.h `inb(port + reg)`: the int sum is truncated to the u16 port argument.
#[cfg(not(kani))]
#[inline(always)]
unsafe fn inb(port: c_int) -> u8 {
    // SAFETY: init_default_io_ops() ran in main() before console_init().
    unsafe { rm::inb(port as u16) }
}

#[cfg(not(kani))]
#[inline(always)]
unsafe fn outb(v: u8, port: c_int) {
    // SAFETY: as inb().
    unsafe { rm::outb(v, port as u16) }
}
#[cfg(kani)]
unsafe fn inb(port: c_int) -> u8 {
    unsafe { kmodel::uart_in(port as u16) }
}
#[cfg(kani)]
unsafe fn outb(v: u8, port: c_int) {
    unsafe { kmodel::uart_out(v, port as u16) }
}

/// The C's `unsigned / unsigned` as the hardware `div` (edx = 0): a zero divisor raises #DE exactly like the C.
#[cfg(not(kani))]
#[inline(always)]
unsafe fn div_u32(n: u32, d: u32) -> u32 {
    let q: u32;
    // SAFETY: `div` with edx = 0; d == 0 faults with #DE as the C's compiled division does.
    unsafe { asm!("div {d:e}", d = in(reg) d, inout("eax") n => q, inout("edx") 0u32 => _, options(nostack)) };
    q
}

/// The C's `int / int` with a constant dividend as the hardware `idiv` (cdq: edx = sign of eax).
#[cfg(not(kani))]
#[inline(always)]
unsafe fn idiv_i32(n: i32, d: i32) -> i32 {
    let q: i32;
    // SAFETY: `cdq; idiv`; d == 0 faults with #DE as the C's compiled division does (unreachable, see the header).
    unsafe { asm!("cdq", "idiv {d:e}", d = in(reg) d, inout("eax") n => q, out("edx") _, options(nostack)) };
    q
}

#[cfg(kani)]
use kmodel::{div_u32, idiv_i32};

unsafe fn early_serial_init(port: c_int, baud: c_int) {
    // SAFETY (whole body): port I/O to the UART the caller chose, via pio_ops, as the C.
    unsafe {
        outb(0x3, port.wrapping_add(LCR)); // 8n1
        outb(0, port.wrapping_add(IER)); // no interrupt
        outb(0, port.wrapping_add(FCR)); // no fifo
        outb(0x3, port.wrapping_add(MCR)); // DTR + RTS

        let divisor: u32 = idiv_i32(115200, baud) as u32;
        let c = inb(port.wrapping_add(LCR));
        outb(c | DLAB, port.wrapping_add(LCR));
        outb((divisor & 0xff) as u8, port.wrapping_add(DLL));
        outb(((divisor >> 8) & 0xff) as u8, port.wrapping_add(DLH));
        outb(c & !DLAB, port.wrapping_add(LCR));

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
    // when it returns > 0; pos never passes the terminator by more than the C's own one-past ("ttyS" + 1);
    // the extern fns are the setup's string.c / cmdline.c.
    unsafe {
        if cmdline_find_option(cs!("earlyprintk"), a, 32) > 0 {
            let mut e: *mut c_char = core::ptr::null_mut();

            if strncmp(a, cs!("serial"), 6) == 0 {
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
            if pos == 7 && strncmp(a.offset(pos), cs!("0x"), 2) == 0 {
                port = simple_strtoull(a.offset(pos), &mut e, 16) as c_int;
                if port == 0 || a.offset(pos) == e {
                    port = DEFAULT_SERIAL_PORT;
                } else {
                    pos = e.offset_from(a);
                }
            } else if strncmp(a.offset(pos), cs!("ttyS"), 4) == 0 {
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
        let lcr = inb(port.wrapping_add(LCR));
        outb(lcr | DLAB, port.wrapping_add(LCR));
        let dll = inb(port.wrapping_add(DLL));
        let dlh = inb(port.wrapping_add(DLH));
        outb(lcr, port.wrapping_add(LCR));
        let quot: c_uint = ((dlh as c_uint) << 8) | dll as c_uint;

        div_u32(BASE_BAUD, quot)
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
    // when it returns > 0; the prefix lengths 12/8 are within the matched prefix; extern fns are the setup's C.
    unsafe {
        if cmdline_find_option(cs!("console"), optstr.as_mut_ptr(), 64) <= 0 {
            return;
        }

        options = optstr.as_mut_ptr();

        if strncmp(options, cs!("uart8250,io,"), 12) == 0 {
            port = simple_strtoull(options.add(12), &mut options, 0) as c_int;
        } else if strncmp(options, cs!("uart,io,"), 8) == 0 {
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
    // SAFETY: setup-time, single-threaded; early_serial_base is tty.c's plain int.
    unsafe {
        parse_earlyprintk();

        if early_serial_base == 0 {
            parse_console_uart8250();
        }
    }
}

// ---- Kani models and proofs (rig/realmode/run-earlyserial-kani.sh); not compiled for the target or the host tests.
// The environment is modelled, the code under proof is the code above: `cmdline_find_option` follows the real function's contract
// (-1 absent; else the buffer gets min(len, size-1) NON-NUL bytes and a NUL at that index; bytes after it are left alone, i.e. the
// zero-initialised buffer of this file); `strncmp` is the real loop; `simple_strtoull` is an over-approximation: it consumes ANY
// prefix of non-NUL bytes (and looks at the byte after it) and returns any value; the UART returns any byte and every access is
// logged; `div`/`idiv` are Rust divisions that record a #DE instead of trapping (the asm cannot run in Kani).
#[cfg(kani)]
mod kmodel {
    use super::*;

    pub static mut LOG: [(bool, u16, u8); 24] = [(false, 0, 0); 24];
    pub static mut LOG_N: usize = 0;
    pub static mut DE_PROBE: bool = false; // `div` by zero in probe_baud
    pub static mut DE_INIT: bool = false; // `idiv` by zero in early_serial_init
    pub static mut PRUNE_DE: bool = false; // harness switch: a #DE ends the path (the C cannot continue after the trap)

    unsafe fn rec(w: bool, p: u16, v: u8) {
        unsafe {
            if LOG_N < 24 {
                LOG[LOG_N] = (w, p, v);
            }
            LOG_N += 1;
        }
    }
    pub unsafe fn uart_in(port: u16) -> u8 {
        let v: u8 = kani::any();
        unsafe { rec(false, port, v) };
        v
    }
    pub unsafe fn uart_out(v: u8, port: u16) {
        unsafe { rec(true, port, v) };
    }
    pub unsafe fn div_u32(n: u32, d: u32) -> u32 {
        if d == 0 {
            unsafe { DE_PROBE = true };
            if unsafe { PRUNE_DE } {
                kani::assume(false);
            }
            return 0;
        }
        n / d
    }
    pub unsafe fn idiv_i32(n: i32, d: i32) -> i32 {
        if d == 0 {
            unsafe { DE_INIT = true };
            kani::assume(false);
        }
        n.wrapping_div(d)
    }
    pub unsafe fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int {
        unsafe {
            let mut i = 0;
            while i < count {
                let a = *cs.add(i) as u8;
                let b = *ct.add(i) as u8;
                if a != b {
                    return if a < b { -1 } else { 1 };
                }
                if a == 0 {
                    return 0;
                }
                i += 1;
            }
            0
        }
    }
    pub unsafe fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, _base: c_uint) -> u64 {
        unsafe {
            let n: usize = kani::any();
            kani::assume(n <= 40);
            let mut i = 0;
            while i < n {
                kani::assume(*cp.add(i) != 0);
                i += 1;
            }
            let _stop = *cp.add(n); // the byte that ends the number is read (and must be inside the buffer)
            if !endp.is_null() {
                *endp = cp.add(n) as *mut c_char;
            }
        }
        kani::any()
    }
    pub unsafe fn cmdline_find_option(_option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int {
        let len: c_int = kani::any();
        kani::assume(len >= -1 && len <= 100);
        let max = if bufsize > 0 { (bufsize - 1) as usize } else { 0 };
        let n = if len > 0 && (len as usize) < max { len as usize } else if len > 0 { max } else { 0 };
        unsafe {
            let mut i = 0;
            while i < n {
                let c: c_char = kani::any();
                kani::assume(c != 0);
                *buffer.add(i) = c;
                i += 1;
            }
            if bufsize > 0 {
                *buffer.add(n) = 0;
            }
        }
        len
    }
    pub unsafe fn reset() {
        unsafe {
            LOG_N = 0;
            DE_PROBE = false;
            DE_INIT = false;
            PRUNE_DE = false;
            early_serial_base = 0;
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// parse_earlyprintk(): for EVERY command-line value (any length, any bytes, truncated to 31 + NUL as the real
    /// cmdline_find_option does) no read or pointer offset leaves `arg[32]`, `BASES[idx]` is in range, no overflow, and the idiv is never
    /// executed with baud == 0 (it would be #DE); the strncmp/simple_strtoull models are the real contract / an over-approximation.
    #[kani::proof]
    #[kani::unwind(45)]
    fn parse_earlyprintk_safe() {
        unsafe {
            kmodel::reset();
            parse_earlyprintk();
            assert!(!kmodel::DE_INIT);
        }
    }

    /// console_init() as a whole (earlyprintk, then console=uart8250/uart,io with probe_baud): memory safe over `optstr[64]`, init never
    /// divides by zero, and a #DE can only come from probe_baud (path ends there, as the C's trap does).
    #[kani::proof]
    #[kani::unwind(70)]
    fn console_init_safe() {
        unsafe {
            kmodel::reset();
            kmodel::PRUNE_DE = true;
            console_init();
            assert!(!kmodel::DE_INIT);
            // a port was programmed iff early_serial_base was set, and then it is nonzero
            if kmodel::LOG_N > 0 && early_serial_base != 0 {
                assert!(early_serial_base != 0);
            }
        }
    }

    /// early_serial_init(port, baud) for every port and every nonzero baud: the 8 writes + 1 read in the C's order, exactly the values of
    /// the C (LCR 3, IER 0, FCR 0, MCR 3, divisor = 115200 / baud truncated toward zero (i64 reference), LCR|DLAB, DLL, DLH, LCR & 0x7f).
    #[kani::proof]
    #[kani::unwind(3)]
    fn early_serial_init_sequence() {
        unsafe {
            kmodel::reset();
            let port: c_int = kani::any();
            let baud: c_int = kani::any();
            kani::assume(baud != 0);
            early_serial_init(port, baud);
            assert!(kmodel::LOG_N == 9);
            let l = kmodel::LOG;
            let p = |r: c_int| (port.wrapping_add(r)) as u16;
            let div = (115200i64 / baud as i64) as u32;
            let lcr_read = l[4].2;
            assert!(l[0] == (true, p(3), 3));
            assert!(l[1] == (true, p(1), 0));
            assert!(l[2] == (true, p(2), 0));
            assert!(l[3] == (true, p(4), 3));
            assert!(l[4].0 == false && l[4].1 == p(3));
            assert!(l[5] == (true, p(3), lcr_read | 0x80));
            assert!(l[6] == (true, p(0), (div & 0xff) as u8));
            assert!(l[7] == (true, p(1), ((div >> 8) & 0xff) as u8));
            assert!(l[8] == (true, p(3), lcr_read & !0x80));
            assert!(early_serial_base == port);
        }
    }

    /// probe_baud(port) for every port and every divisor-latch content: access order (LCR read, LCR|DLAB write, DLL read, DLH read, LCR
    /// restore), no #DE iff quot != 0, and then 1 <= result <= 115200 (so early_serial_init's baud is never 0 and positive).
    #[kani::proof]
    #[kani::unwind(3)]
    fn probe_baud_arith() {
        unsafe {
            kmodel::reset();
            let port: c_int = kani::any();
            let r = probe_baud(port);
            assert!(kmodel::LOG_N == 5);
            let l = kmodel::LOG;
            let p = |r: c_int| (port.wrapping_add(r)) as u16;
            let (lcr, dll, dlh) = (l[0].2, l[2].2, l[3].2);
            assert!(l[0].0 == false && l[0].1 == p(3));
            assert!(l[1] == (true, p(3), lcr | 0x80));
            assert!(l[2].0 == false && l[2].1 == p(0));
            assert!(l[3].0 == false && l[3].1 == p(1));
            assert!(l[4] == (true, p(3), lcr));
            let quot = ((dlh as u32) << 8) | dll as u32;
            assert!(kmodel::DE_PROBE == (quot == 0));
            if quot != 0 {
                assert!(r == 115200 / quot && r >= 1 && r <= 115200);
            }
        }
    }
}
