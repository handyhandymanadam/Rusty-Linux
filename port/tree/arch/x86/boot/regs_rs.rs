// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/regs.c (16-bit real-mode setup code, PHASE D pilot).
//!
//! Compiled for realmode_target.json (llvm-target i386-unknown-none-code16, `-Zregparm=3` =
//! the C's `-mregparm=3`), so `reg` arrives in %eax exactly as for the C `initregs()`.
//!
//! The C: memset the register set to 0, set EFLAGS_CF (so a BIOS call that does nothing but
//! forgets to set CF is noticed), and load the four data segment registers from the live ones.

#![allow(dead_code)]

use core::arch::asm;

/// `struct biosregs` (boot.h), the 32-bit view with the segment halves split out:
/// `_fsgs` = {gs, fs} and `_dses` = {es, ds} (little endian), 44 bytes.
#[repr(C)]
pub struct BiosRegs {
    edi: u32,
    esi: u32,
    ebp: u32,
    _esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    gs: u16,
    fs: u16,
    es: u16,
    ds: u16,
    eflags: u32,
}

const X86_EFLAGS_CF: u32 = 0x0001;

#[inline(always)]
fn ds() -> u16 {
    let seg: u16;
    // SAFETY: reads a segment register; no memory, no stack.
    unsafe { asm!("mov {0:x}, ds", out(reg_abcd) seg, options(nomem, nostack, preserves_flags)) };
    seg
}

#[inline(always)]
fn fs() -> u16 {
    let seg: u16;
    // SAFETY: as ds().
    unsafe { asm!("mov {0:x}, fs", out(reg_abcd) seg, options(nomem, nostack, preserves_flags)) };
    seg
}

#[inline(always)]
fn gs() -> u16 {
    let seg: u16;
    // SAFETY: as ds().
    unsafe { asm!("mov {0:x}, gs", out(reg_abcd) seg, options(nomem, nostack, preserves_flags)) };
    seg
}

/// `void initregs(struct biosregs *reg)`.
///
/// # Safety
/// `reg` must point to a writable `struct biosregs` (44 bytes), as for the C.
#[no_mangle]
pub unsafe extern "C" fn initregs(reg: *mut BiosRegs) {
    // SAFETY: caller contract above.
    unsafe {
        core::ptr::write_bytes(reg, 0, 1);
        (*reg).eflags |= X86_EFLAGS_CF;
        (*reg).ds = ds();
        (*reg).es = ds();
        (*reg).fs = fs();
        (*reg).gs = gs();
    }
}
