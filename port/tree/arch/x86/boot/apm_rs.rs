// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/apm.c (16-bit real-mode setup, code16, -Zregparm=3): the APM BIOS information probe,
//! `int query_apm_bios(void)`. Built only where the C is: the Makefile has `setup-$(CONFIG_X86_APM_BOOT) += apm.o` (APM is a 32-bit-only
//! option; this tree configures x86-64, so neither the C nor this file is part of setup.elf here: see TEST-GAP).
//!
//! Sequence (INT 15h AH=53h, same calls and register values as the C, partial-register stores keep the other bits of `ireg`):
//! installation check (AL=00h; CF set -> -1; BX != 'PM' (0x504d) -> -1; CX bit 1 (32-bit interface) clear -> -1); disconnect (AL=04h, oreg NULL);
//! 32-bit connect (AL=03h): boot_params.apm_bios_info.{cseg=AX, offset=EBX, cseg_16=CX, dseg=DX, cseg_len=SI, cseg_16_len=high word of ESI, dseg_len=DI}
//! are stored BEFORE the CF test (a failed connect still leaves them stored); CF set -> -1; installation check again (AL=00h): CF or BX != 'PM' ->
//! disconnect (AL=04h, NULL) and -1; else version=AX, flags=CX, return 0. No message strings. Offsets (checked against the real header by
//! rig/realmode/run-apm-diff.sh): apm_bios_info at 0x40 (version +0, cseg +2, offset +4, cseg_16 +8, dseg +10, flags +12, cseg_len +14, cseg_16_len +16, dseg_len +18).
//!
//! TEST-GAP: logs/realmode-apm.md (not built in any configuration here; the object is compared with the C object built from the same flags; behaviour is
//! the host differential against mocked BIOS; no APM BIOS exists in QEMU/SeaBIOS and no 32-bit kernel is built or booted here).
#![allow(dead_code, static_mut_refs)]

#[path = "rm_common.rs"]
mod rm;

use core::ffi::c_int;
use core::ptr::addr_of_mut;
use rm::*;

const OFF_APM: usize = 0x40; // C: offsetof(struct boot_params, apm_bios_info)
const APM_VERSION: usize = OFF_APM;
const APM_CSEG: usize = OFF_APM + 2;
const APM_OFFSET: usize = OFF_APM + 4;
const APM_CSEG_16: usize = OFF_APM + 8;
const APM_DSEG: usize = OFF_APM + 10;
const APM_FLAGS: usize = OFF_APM + 12;
const APM_CSEG_LEN: usize = OFF_APM + 14;
const APM_CSEG_16_LEN: usize = OFF_APM + 16;
const APM_DSEG_LEN: usize = OFF_APM + 18;

extern "C" {
    static mut boot_params: [u8; 4096];
}

#[inline(always)]
unsafe fn wr16(off: usize, v: u16) {
    unsafe { (addr_of_mut!(boot_params) as *mut u8).add(off).cast::<u16>().write_unaligned(v) }
}
#[inline(always)]
unsafe fn wr32(off: usize, v: u32) {
    unsafe { (addr_of_mut!(boot_params) as *mut u8).add(off).cast::<u32>().write_unaligned(v) }
}

#[no_mangle]
pub unsafe extern "C" fn query_apm_bios() -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();

        // APM BIOS installation check
        ireg.set_ah(0x53);
        intcall(0x15, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        if o.eflags & X86_EFLAGS_CF != 0 {
            return -1; // No APM BIOS
        }
        if o.bx() != 0x504d {
            return -1; // "PM" signature
        }
        if o.cx() & 0x02 == 0 {
            return -1; // 32 bits supported?
        }

        // Disconnect first, just in case
        ireg.set_al(0x04);
        intcall(0x15, &ireg, core::ptr::null_mut());

        // 32-bit connect
        ireg.set_al(0x03);
        intcall(0x15, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        wr16(APM_CSEG, o.ax());
        wr32(APM_OFFSET, o.ebx);
        wr16(APM_CSEG_16, o.cx());
        wr16(APM_DSEG, o.dx());
        wr16(APM_CSEG_LEN, o.si());
        wr16(APM_CSEG_16_LEN, o.hsi());
        wr16(APM_DSEG_LEN, o.di());

        if o.eflags & X86_EFLAGS_CF != 0 {
            return -1;
        }

        // Redo the installation check as the 32-bit connect; some BIOSes return different flags this way...
        ireg.set_al(0x00);
        intcall(0x15, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        if (o.eflags & X86_EFLAGS_CF != 0) || o.bx() != 0x504d {
            // Failure with 32-bit connect, try to disconnect and ignore
            ireg.set_al(0x04);
            intcall(0x15, &ireg, core::ptr::null_mut());
            return -1;
        }

        wr16(APM_VERSION, o.ax());
        wr16(APM_FLAGS, o.cx());
        0
    }
}
