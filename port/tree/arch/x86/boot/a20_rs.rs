// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/a20.c (16-bit real-mode setup): enable the A20 gate.
//! Exports `enable_a20()` (0 = on, -1 = failed) like the C; every other function is private.
//!
//! Order of attempts per round (255 rounds, as `A20_ENABLE_LOOPS`): short test (32 tries) ->
//! BIOS INT 15h AX=2401 -> short test -> `empty_8042()` -> short test -> if the KBC answered,
//! 8042 command sequence (0xd1 / 0xdf / 0xff) + long test (2^21 tries) -> fast gate (port 0x92)
//! + long test. No message is printed anywhere in this file (none in the C either).
//!
//! The test is "write a counter at 0000:0200 (the INT 80h vector), read FFFF:0210": equal
//! (xor == 0 for all tries) means the address wrapped at 1 MiB, i.e. A20 is off. The fs/gs
//! accesses are `mov fs/gs, r16` and `mov r32, fs/gs:[imm]` exactly as boot.h's
//! set_fs/set_gs/rdfs32/wrfs32/rdgs32 (asm volatile, memory-clobbering). `io_delay()` is
//! `outb(0, 0x80)` through `pio_ops.f_outb` (so TDX-style overrides apply), as in io.h.
//!
//! Deliberate divergences from the C: none in behaviour (same port-access / BIOS-call sequence,
//! checked by the lockstep host differential rig/realmode/run-a20-diff.sh). `++ctr` is a
//! `wrapping_add` (the C's signed overflow is UB; the kernel is built -fwrapv-equivalent).
//! Under `--cfg host_mock` (host test build only) the segment accesses are routed to extern
//! hooks so a simulated memory can stand in for fs:/gs: -- never set for the target build.
//!
//! TEST-GAP: real hardware is not covered -- real KBC timing/quirks (status values, IBF/OBF
//! behaviour), a real BIOS INT 15h/2401 or HIMEM, the real 1 MiB address wrap (QEMU/SeaBIOS boots
//! with A20 already on, so only the "already on" path runs in the boot compare). The other paths
//! run only against the simulated PC of rig/realmode/a20-diff.c (logs/test-gaps.md).
#![allow(dead_code)]

#[path = "rm_common.rs"]
mod rm;

use rm::*;

const MAX_8042_LOOPS: i32 = 100000;
const MAX_8042_FF: i32 = 32;

const A20_TEST_ADDR: u32 = 4 * 0x80;
const A20_TEST_SHORT: i32 = 32;
const A20_TEST_LONG: i32 = 2097152; // 2^21
const A20_ENABLE_LOOPS: i32 = 255;

#[cfg(not(host_mock))]
mod seg {
    use core::arch::asm;
    // 4*0x80 and +0x10 are literal below (asm const operands in a memory operand).
    #[inline(always)]
    pub unsafe fn set_fs(seg: u16) {
        unsafe { asm!("mov fs, {0:x}", in(reg_abcd) seg, options(nostack, preserves_flags)) };
    }
    #[inline(always)]
    pub unsafe fn set_gs(seg: u16) {
        unsafe { asm!("mov gs, {0:x}", in(reg_abcd) seg, options(nostack, preserves_flags)) };
    }
    #[inline(always)]
    pub unsafe fn rdfs32_a20() -> u32 {
        let v: u32;
        unsafe { asm!("mov {0:e}, dword ptr fs:[{1}]", out(reg) v, const super::A20_TEST_ADDR, options(nostack, preserves_flags)) };
        v
    }
    #[inline(always)]
    pub unsafe fn wrfs32_a20(v: u32) {
        unsafe { asm!("mov dword ptr fs:[{1}], {0:e}", in(reg) v, const super::A20_TEST_ADDR, options(nostack, preserves_flags)) };
    }
    #[inline(always)]
    pub unsafe fn rdgs32_a20_plus16() -> u32 {
        let v: u32;
        unsafe { asm!("mov {0:e}, dword ptr gs:[{1}]", out(reg) v, const super::A20_TEST_ADDR + 0x10, options(nostack, preserves_flags)) };
        v
    }
}

#[cfg(host_mock)]
mod seg {
    extern "C" {
        fn mock_set_fs(s: u16);
        fn mock_set_gs(s: u16);
        fn mock_rdfs32(a: u32) -> u32;
        fn mock_wrfs32(v: u32, a: u32);
        fn mock_rdgs32(a: u32) -> u32;
    }
    pub unsafe fn set_fs(s: u16) { unsafe { mock_set_fs(s) } }
    pub unsafe fn set_gs(s: u16) { unsafe { mock_set_gs(s) } }
    pub unsafe fn rdfs32_a20() -> u32 { unsafe { mock_rdfs32(super::A20_TEST_ADDR) } }
    pub unsafe fn wrfs32_a20(v: u32) { unsafe { mock_wrfs32(v, super::A20_TEST_ADDR) } }
    pub unsafe fn rdgs32_a20_plus16() -> u32 { unsafe { mock_rdgs32(super::A20_TEST_ADDR + 0x10) } }
}

#[inline(always)]
unsafe fn io_delay() {
    // SAFETY: port 0x80 is the conventional delay port; pio_ops set up in main().
    unsafe { outb(0, 0x80) }
}

unsafe fn empty_8042() -> i32 {
    let mut loops = MAX_8042_LOOPS;
    let mut ffs = MAX_8042_FF;
    // `while (loops--)`: test, then decrement.
    while loops != 0 {
        loops -= 1;
        unsafe {
            io_delay();
            let status = inb(0x64);
            if status == 0xff {
                // FF is a plausible, but very unlikely status
                ffs -= 1;
                if ffs == 0 {
                    return -1; // Assume no KBC present
                }
            }
            if status & 1 != 0 {
                // Read and discard input data
                io_delay();
                let _ = inb(0x60);
            } else if status & 2 == 0 {
                // Buffers empty, finished!
                return 0;
            }
        }
    }
    -1
}

/// Returns nonzero if the A20 line is enabled. The test address is the int $0x80 vector.
unsafe fn a20_test(mut loops: i32) -> i32 {
    let mut ok: u32 = 0;
    unsafe {
        seg::set_fs(0x0000);
        seg::set_gs(0xffff);

        let saved = seg::rdfs32_a20();
        let mut ctr = saved;

        while loops != 0 {
            loops -= 1;
            ctr = ctr.wrapping_add(1);
            seg::wrfs32_a20(ctr);
            io_delay(); // Serialize and make delay constant
            ok = seg::rdgs32_a20_plus16() ^ ctr;
            if ok != 0 {
                break;
            }
        }

        seg::wrfs32_a20(saved);
    }
    ok as i32
}

unsafe fn a20_test_short() -> i32 {
    unsafe { a20_test(A20_TEST_SHORT) }
}

unsafe fn a20_test_long() -> i32 {
    unsafe { a20_test(A20_TEST_LONG) }
}

unsafe fn enable_a20_bios() {
    unsafe {
        let mut ireg = new_regs();
        ireg.eax = (ireg.eax & 0xffff_0000) | 0x2401;
        intcall(0x15, &ireg, core::ptr::null_mut());
    }
}

unsafe fn enable_a20_kbc() {
    unsafe {
        empty_8042();
        outb(0xd1, 0x64); // Command write
        empty_8042();
        outb(0xdf, 0x60); // A20 on
        empty_8042();
        outb(0xff, 0x64); // Null command, but UHCI wants it
        empty_8042();
    }
}

unsafe fn enable_a20_fast() {
    unsafe {
        let mut port_a = inb(0x92); // Configuration port A
        port_a |= 0x02; // Enable A20
        port_a &= !0x01; // Do not reset machine
        outb(port_a, 0x92);
    }
}

/// Actual routine to enable A20; return 0 on ok, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn enable_a20() -> i32 {
    let mut loops = A20_ENABLE_LOOPS;
    unsafe {
        while loops != 0 {
            loops -= 1;
            // First, check to see if A20 is already enabled (legacy free, etc.)
            if a20_test_short() != 0 {
                return 0;
            }
            // Next, try the BIOS (INT 0x15, AX=0x2401)
            enable_a20_bios();
            if a20_test_short() != 0 {
                return 0;
            }
            // Try enabling A20 through the keyboard controller
            let kbc_err = empty_8042();
            if a20_test_short() != 0 {
                return 0; // BIOS worked, but with delayed reaction
            }
            if kbc_err == 0 {
                enable_a20_kbc();
                if a20_test_long() != 0 {
                    return 0;
                }
            }
            // Finally, try enabling the "fast A20 gate"
            enable_a20_fast();
            if a20_test_long() != 0 {
                return 0;
            }
        }
    }
    -1
}
