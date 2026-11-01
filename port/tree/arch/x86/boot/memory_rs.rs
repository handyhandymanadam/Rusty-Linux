// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/memory.c (16-bit real-mode setup): memory detection
//! through BIOS INT 15h -- E820, E801, 88. Exports `detect_memory()` like the C.
//!
//! The results land in `boot_params` (the zero page): `e820_table[]`/`e820_entries`,
//! `alt_mem_k` and `screen_info.ext_mem_k`; the kernel log's "BIOS-e820:" lines come from them.
#![allow(dead_code)]

#[path = "rm_common.rs"]
mod rm;

use core::ptr::{addr_of, addr_of_mut};
use rm::*;

const SMAP: u32 = 0x534d_4150; // ASCII "SMAP"

// struct boot_params offsets (arch/x86/include/uapi/asm/bootparam.h, checked against the
// compiler: offsetof e820_table 720, e820_entries 488, alt_mem_k 480, screen_info.ext_mem_k 2,
// sizeof(struct boot_e820_entry) 20 (packed), E820_MAX_ENTRIES_ZEROPAGE 128).
const OFF_EXT_MEM_K: usize = 0x002;
const OFF_ALT_MEM_K: usize = 0x1e0;
const OFF_E820_ENTRIES: usize = 0x1e8;
const OFF_E820_TABLE: usize = 0x2d0;
const E820_ENTRY_SIZE: usize = 20;
const E820_MAX_ENTRIES_ZEROPAGE: usize = 128;

/// `struct boot_e820_entry` (packed).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BootE820Entry {
    addr: u64,
    size: u64,
    typ: u32,
}

extern "C" {
    /// `struct boot_params boot_params` (main.c), 4096 bytes.
    static mut boot_params: [u8; 4096];
}

#[inline(always)]
fn bp() -> *mut u8 {
    addr_of_mut!(boot_params) as *mut u8
}

/// `static struct boot_e820_entry buf;` -- static so it is zeroed (plain `.bss`).
#[link_section = ".bss"]
static mut BUF: BootE820Entry = BootE820Entry { addr: 0, size: 0, typ: 0 };

#[inline(always)]
fn set_lo16(r: &mut u32, v: u16) {
    *r = (*r & 0xffff_0000) | v as u32;
}

unsafe fn detect_memory_e820() {
    let mut count: usize = 0;
    // SAFETY: single-threaded real mode; boot_params is the zero page.
    unsafe {
        let mut desc = bp().add(OFF_E820_TABLE) as *mut BootE820Entry;

        let mut ireg = new_regs();
        let mut oreg = out_regs();
        set_lo16(&mut ireg.eax, 0xe820);
        set_lo16(&mut ireg.ecx, core::mem::size_of::<BootE820Entry>() as u16);
        ireg.edx = SMAP;
        set_lo16(&mut ireg.edi, addr_of!(BUF) as usize as u16);

        // Note: at least one BIOS assumes the buffer of one e820 call is the same as the
        // previous call's and only changes modified fields, so a temporary buffer is used and
        // the results are copied entry by entry. (Comment kept from the C.)
        loop {
            intcall(0x15, &ireg, oreg.as_mut_ptr());
            let o = oreg.assume_init_ref();
            ireg.ebx = o.ebx; // for next iteration...

            // BIOSes which terminate the chain with CF = 1 as opposed to %ebx = 0 don't always
            // report the SMAP signature on the final, failing, probe.
            if o.eflags & X86_EFLAGS_CF != 0 {
                break;
            }

            // Some BIOSes stop returning SMAP in the middle of the search loop. We don't know
            // how the BIOS screwed up the map at that point, so just return failure.
            if o.eax != SMAP {
                count = 0;
                break;
            }

            desc.write_unaligned(core::ptr::read_volatile(addr_of!(BUF)));
            desc = desc.add(1);
            count += 1;

            if !(ireg.ebx != 0 && count < E820_MAX_ENTRIES_ZEROPAGE) {
                break;
            }
        }

        *bp().add(OFF_E820_ENTRIES) = count as u8;
    }
}

unsafe fn detect_memory_e801() {
    // SAFETY: as above.
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        set_lo16(&mut ireg.eax, 0xe801);
        intcall(0x15, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_mut();

        if o.eflags & X86_EFLAGS_CF != 0 {
            return;
        }

        // Do we really need to do this?
        let (mut ax, mut bx) = (o.eax as u16, o.ebx as u16);
        let (cx, dx) = (o.ecx as u16, o.edx as u16);
        if cx != 0 || dx != 0 {
            ax = cx;
            bx = dx;
        }

        let alt = bp().add(OFF_ALT_MEM_K) as *mut u32;
        if ax as u32 > 15 * 1024 {
            // Bogus!
        } else if ax as u32 == 15 * 1024 {
            alt.write_unaligned(((bx as u32) << 6) + ax as u32);
        } else {
            // This ignores memory above 16MB if we have a memory hole there (see the C).
            alt.write_unaligned(ax as u32);
        }
    }
}

unsafe fn detect_memory_88() {
    // SAFETY: as above.
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        ireg.eax = (ireg.eax & !0xff00) | 0x8800; // ireg.ah = 0x88
        intcall(0x15, &ireg, oreg.as_mut_ptr());
        (bp().add(OFF_EXT_MEM_K) as *mut u16).write_unaligned(oreg.assume_init_ref().eax as u16);
    }
}

#[no_mangle]
pub unsafe extern "C" fn detect_memory() {
    // SAFETY: see helpers.
    unsafe {
        detect_memory_e820();
        detect_memory_e801();
        detect_memory_88();
    }
}
