// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/idt_64.c (the 64-bit stub's IDT setup).
//!
//! Same exported symbols as the C: `load_stage1_idt()`, `load_stage2_idt()` and
//! `cleanup_exception_handling()`. `boot_idt` / `boot_idt_desc` stay where they are
//! (head_64.S, `.data`); the handlers are the asm in idt_handlers_64.S. A wrong byte in
//! an IDT entry is a triple fault, so the entry encoding is a separate pure function
//! (`gate_entry`) that is compared with the C bitfield code in userspace (logs/stube-parity.md).
//! `--cfg=amd_mem_encrypt` mirrors CONFIG_AMD_MEM_ENCRYPT (the C's #ifdef / IS_ENABLED).

use core::arch::asm;

const BOOT_IDT_ENTRIES: usize = 32; // asm/desc_defs.h
const X86_TRAP_NMI: usize = 2; // asm/trapnr.h
const X86_TRAP_PF: usize = 14;
#[cfg(amd_mem_encrypt)]
const X86_TRAP_VC: usize = 29;
const KERNEL_CS: u64 = 0x10; // __KERNEL_CS = GDT_ENTRY_KERNEL_CS (2) * 8
const GATE_TRAP: u64 = 0xF; // enum desc_type

/// `gate_desc` (struct gate_struct, 16 bytes, packed): offset_low u16, segment u16,
/// struct idt_bits { ist:3, zero:5, type:5, dpl:2, p:1 } (u16), offset_middle u16,
/// offset_high u32, reserved u32. As two little-endian u64 words.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GateDesc {
    pub lo: u64,
    pub hi: u64,
}

/// `struct desc_ptr` (packed): `u16 size; unsigned long address`.
#[repr(C, packed)]
pub struct DescPtr {
    size: u16,
    address: u64,
}

const _: () = assert!(core::mem::size_of::<GateDesc>() == 16);
const _: () = assert!(core::mem::size_of::<DescPtr>() == 10);
const _: () = assert!(core::mem::offset_of!(DescPtr, address) == 2);

extern "C" {
    static mut boot_idt: [GateDesc; BOOT_IDT_ENTRIES];
    static mut boot_idt_desc: DescPtr;
    fn boot_page_fault();
    fn boot_nmi_trap();
    #[cfg(amd_mem_encrypt)]
    fn boot_stage1_vc();
    #[cfg(amd_mem_encrypt)]
    fn boot_stage2_vc();
    #[cfg(amd_mem_encrypt)]
    static sev_status: u64;
    #[cfg(amd_mem_encrypt)]
    fn sev_es_shutdown_ghcb();
}

/// The C's set_idt_entry() body: all-zero entry, then offset_low, segment = __KERNEL_CS,
/// type = GATE_TRAP, p = 1 (ist = dpl = 0), offset_middle, offset_high; reserved stays 0.
pub fn gate_entry(address: u64) -> GateDesc {
    let bits: u64 = (GATE_TRAP << 8) | (1 << 15); // type at bit 8 (after ist:3, zero:5), p at bit 15
    GateDesc {
        lo: (address & 0xffff) | (KERNEL_CS << 16) | (bits << 32) | (((address >> 16) & 0xffff) << 48),
        hi: address >> 32,
    }
}

/// # Safety
/// `vector` < BOOT_IDT_ENTRIES (the C does not check; callers pass constants).
unsafe fn set_idt_entry(vector: usize, handler: Option<unsafe extern "C" fn()>) {
    let address = match handler {
        Some(f) => f as usize as u64,
        None => 0,
    };
    // SAFETY: boot_idt has BOOT_IDT_ENTRIES entries; single CPU, interrupts not yet using it.
    unsafe { (&raw mut boot_idt).cast::<GateDesc>().add(vector).write(gate_entry(address)) };
}

/// # Safety
/// `dtr` must describe a valid IDT (ring 0).
unsafe fn load_boot_idt(dtr: *const DescPtr) {
    // SAFETY: the C was `asm volatile("lidt %0" :: "m" (*dtr))`.
    unsafe { asm!("lidt [{}]", in(reg) dtr, options(readonly, nostack, preserves_flags)) };
}

/// Setup IDT before kernel jumping to .Lrelocated
#[no_mangle]
pub unsafe extern "C" fn load_stage1_idt() {
    // SAFETY: boot-time single CPU; boot_idt_desc / boot_idt are the head_64.S objects.
    unsafe {
        (&raw mut boot_idt_desc.address).write_unaligned((&raw mut boot_idt) as usize as u64);

        #[cfg(amd_mem_encrypt)]
        set_idt_entry(X86_TRAP_VC, Some(boot_stage1_vc));

        load_boot_idt(&raw const boot_idt_desc);
    }
}

/// Setup IDT after kernel jumping to .Lrelocated (see the C for why #PF/#VC are set here).
#[no_mangle]
pub unsafe extern "C" fn load_stage2_idt() {
    // SAFETY: as load_stage1_idt().
    unsafe {
        (&raw mut boot_idt_desc.address).write_unaligned((&raw mut boot_idt) as usize as u64);

        set_idt_entry(X86_TRAP_PF, Some(boot_page_fault));
        set_idt_entry(X86_TRAP_NMI, Some(boot_nmi_trap));

        #[cfg(amd_mem_encrypt)]
        {
            // Clear the second stage #VC handler in case guest types needing #VC were not detected.
            if sev_status & (1 << 1) != 0 {
                set_idt_entry(X86_TRAP_VC, Some(boot_stage2_vc));
            } else {
                set_idt_entry(X86_TRAP_VC, None);
            }
        }

        load_boot_idt(&raw const boot_idt_desc);
    }
}

#[no_mangle]
pub unsafe extern "C" fn cleanup_exception_handling() {
    // SAFETY: as load_stage1_idt().
    unsafe {
        // Flush GHCB from cache and map it encrypted again when running as SEV-ES guest.
        #[cfg(amd_mem_encrypt)]
        sev_es_shutdown_ghcb();

        // Set a null-idt, disabling #PF and #VC handling
        (&raw mut boot_idt_desc.size).write_unaligned(0);
        (&raw mut boot_idt_desc.address).write_unaligned(0);
        load_boot_idt(&raw const boot_idt_desc);
    }
}
