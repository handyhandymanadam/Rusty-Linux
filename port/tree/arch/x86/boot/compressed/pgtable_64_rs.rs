// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/pgtable_64.c: the 4-/5-level paging switch of
//! the 64-bit stub. Exports what the C object did: `__pgtable_l5_enabled`, `pgdir_shift`,
//! `ptrs_per_p4d`, `trampoline_32bit` (all four in `.data`: they are written before `.bss` is
//! cleared) and `configure_5level_paging()`. The 32-bit trampoline itself is asm
//! (arch/x86/boot/startup/la57toggle.S, `trampoline_32bit_src`) and stays so.
//!
//! A mistake here triple-faults (the CR3/CR4 switch runs in compatibility mode with paging off), so
//! the arithmetic is split into pure functions (`find_trampoline_placement`, `sanitize_boot_params`)
//! that are compared with the C in userspace (rig/stube-parity/, logs/stube-parity.md).
//! `--cfg=amd_mem_encrypt` mirrors CONFIG_AMD_MEM_ENCRYPT: there `__PHYSICAL_MASK` is the variable
//! `physical_mask` (CONFIG_DYNAMIC_PHYSICAL_MASK) and CR3_ADDR_MASK also clears `sme_me_mask`.

use core::arch::asm;
use core::ffi::{c_char, c_int};
use core::ptr;

const PAGE_SIZE: u64 = 4096;
const TRAMPOLINE_32BIT_SIZE: usize = 2 * 4096; // asm/boot.h
const TRAMPOLINE_32BIT_CODE_OFFSET: usize = 4096;
const TRAMPOLINE_32BIT_CODE_SIZE: usize = 0xA0;
const BIOS_START_MIN: u64 = 0x20000; // 128K, less than this is insane
const BIOS_START_MAX: u64 = 0x9f000; // 640K, absolute maximum
const E820_TYPE_RAM: u32 = 1;
const X86_CR4_LA57: u64 = 1 << 12;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);
/// _PAGE_TABLE_NOENC = PRESENT | RW | USER | ACCESSED | DIRTY
const PAGE_TABLE_NOENC: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6);
const BOOT_PARAMS_SIZE: usize = 4096;

// struct boot_params offsets (arch/x86/include/uapi/asm/bootparam.h, 6.18.49; checked against the
// compiler by rig/stube-parity/layout-check.c)
const BP_EFI_LOADER_SIGNATURE: usize = 0x1c0;
const BP_E820_ENTRIES: usize = 0x1e8;
const BP_SENTINEL: usize = 0x1ef;
const BP_E820_TABLE: usize = 0x2d0;

/// `struct boot_e820_entry` (packed, 20 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub typ: u32,
}
const _: () = assert!(core::mem::size_of::<E820Entry>() == 20);

/// The `{ start, len }` pairs of sanitize_boot_params()'s `to_save[]`, in the C's order.
const TO_SAVE: [(usize, usize); 20] = [
    (0x000, 64),  // screen_info
    (0x040, 20),  // apm_bios_info
    (0x058, 8),   // tboot_addr
    (0x060, 16),  // ist_info
    (0x080, 16),  // hd0_info
    (0x090, 16),  // hd1_info
    (0x0a0, 16),  // sys_desc_table
    (0x0b0, 16),  // olpc_ofw_header
    (0x1c0, 32),  // efi_info
    (0x1e0, 4),   // alt_mem_k
    (0x1e4, 4),   // scratch
    (0x1e8, 1),   // e820_entries
    (0x1e9, 1),   // eddbuf_entries
    (0x1ea, 1),   // edd_mbr_sig_buf_entries
    (0x290, 64),  // edd_mbr_sig_buffer
    (0x1ec, 1),   // secure_boot
    (0x1f1, 123), // hdr
    (0x2d0, 2560), // e820_table
    (0xd00, 492), // eddbuf
    (0x13c, 4),   // cc_blob_address
];

extern "C" {
    static mut boot_params_ptr: *mut u8; // struct boot_params *
    fn cmdline_find_option_bool(option: *const c_char) -> c_int;
    fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int;
    /// la57toggle.S (a function, `.rodata`); only its address is used
    static trampoline_32bit_src: u8;
    static trampoline_ljmp_imm_offset: u16;
    #[cfg(amd_mem_encrypt)]
    static physical_mask: u64;
    #[cfg(amd_mem_encrypt)]
    static sme_me_mask: u64;
}

/// __pgtable_l5_enabled needs to be in .data to avoid being cleared along with .bss
#[no_mangle]
#[link_section = ".data"]
pub static mut __pgtable_l5_enabled: u32 = 0;
#[no_mangle]
#[link_section = ".data"]
pub static mut pgdir_shift: u32 = 39;
#[no_mangle]
#[link_section = ".data"]
pub static mut ptrs_per_p4d: u32 = 1;

/// Trampoline address, printed by extract_kernel(); kept out of .bss (cleared between
/// configure_5level_paging() and extract_kernel()).
#[no_mangle]
#[link_section = ".data"]
pub static mut trampoline_32bit: *mut u64 = ptr::null_mut();

/// Buffer to preserve trampoline memory
static mut TRAMPOLINE_SAVE: [u8; TRAMPOLINE_32BIT_SIZE] = [0; TRAMPOLINE_32BIT_SIZE];
/// sanitize_boot_params()'s `static struct boot_params scratch`
static mut SANITIZE_SCRATCH: [u8; BOOT_PARAMS_SIZE] = [0; BOOT_PARAMS_SIZE];

/// The part of find_trampoline_placement() that is arithmetic. `efi`: the loader signature is
/// "EL32" or "EL64" (then the BIOS data area is not consulted); `ebda_word` / `bios_word`: the
/// u16s at 0x40e / 0x413. `e820` is the table, in order; the C walks it from the last entry down.
pub fn trampoline_placement(efi: bool, ebda_word: u16, bios_word: u16, e820: &[E820Entry]) -> u64 {
    let mut bios_start: u64 = 0;
    let mut ebda_start: u64 = 0;

    if !efi {
        ebda_start = (ebda_word as u64) << 4;
        bios_start = (bios_word as u64) << 10;
    }

    if bios_start < BIOS_START_MIN || bios_start > BIOS_START_MAX {
        bios_start = BIOS_START_MAX;
    }

    if ebda_start > BIOS_START_MIN && ebda_start < bios_start {
        bios_start = ebda_start;
    }

    bios_start &= PAGE_MASK; // round_down

    // Find the first usable memory region under bios_start.
    for e in e820.iter().rev() {
        let (addr, size, typ) = (e.addr, e.size, e.typ);
        let mut new = bios_start;

        // Skip all entries above bios_start.
        if bios_start <= addr {
            continue;
        }
        // Skip non-RAM entries.
        if typ != E820_TYPE_RAM {
            continue;
        }
        // Adjust bios_start to the end of the entry if needed.
        if bios_start > addr.wrapping_add(size) {
            new = addr.wrapping_add(size);
        }
        // Keep bios_start page-aligned.
        new &= PAGE_MASK;
        // Skip the entry if it's too small.
        if new.wrapping_sub(TRAMPOLINE_32BIT_SIZE as u64) < addr {
            continue;
        }
        // Protect against underflow.
        if new.wrapping_sub(TRAMPOLINE_32BIT_SIZE as u64) > bios_start {
            break;
        }
        bios_start = new;
        break;
    }

    // Place the trampoline just below the end of low memory
    bios_start.wrapping_sub(TRAMPOLINE_32BIT_SIZE as u64)
}

/// # Safety
/// Boot-time, `boot_params_ptr` valid; reads the BIOS data area at 0x40e/0x413 for non-EFI.
unsafe fn find_trampoline_placement() -> u64 {
    // SAFETY: caller contract; the C dereferenced the same addresses.
    unsafe {
        let bp = boot_params_ptr;
        let sig = bp.add(BP_EFI_LOADER_SIGNATURE) as *const c_char;
        // strncmp(signature, EFI32_LOADER_SIGNATURE ("EL32"), 4) && strncmp(.., "EL64", 4)
        let efi = strncmp(sig, c"EL32".as_ptr(), 4) == 0 || strncmp(sig, c"EL64".as_ptr(), 4) == 0;
        let (ebda_word, bios_word) = if efi {
            (0, 0)
        } else {
            (ptr::read_volatile(0x40e as *const u16), ptr::read_volatile(0x413 as *const u16))
        };
        let n = *bp.add(BP_E820_ENTRIES) as usize;
        let table = core::slice::from_raw_parts(bp.add(BP_E820_TABLE) as *const E820Entry, n);
        trampoline_placement(efi, ebda_word, bios_word, table)
    }
}

/// asm/bootparam_utils.h sanitize_boot_params(): if `sentinel` is set, keep only the `to_save`
/// ranges of `bp` and zero the rest of the 4096 bytes (via `scratch`, as the C does).
///
/// # Safety
/// `bp` and `scratch` valid for BOOT_PARAMS_SIZE bytes and not overlapping.
pub unsafe fn sanitize_boot_params(bp: *mut u8, scratch: *mut u8) {
    // SAFETY: caller contract.
    unsafe {
        if *bp.add(BP_SENTINEL) != 0 {
            ptr::write_bytes(scratch, 0, BOOT_PARAMS_SIZE);
            for &(start, len) in TO_SAVE.iter() {
                ptr::copy_nonoverlapping(bp.add(start), scratch.add(start), len);
            }
            ptr::copy_nonoverlapping(scratch, bp, BOOT_PARAMS_SIZE);
        }
    }
}

/// sanitize_boot_params() for misc_rs.rs's extract_kernel() (the C had a second `static scratch` in misc.o; one scratch is shared
/// here: both users run once, single-threaded, one after the other).
///
/// # Safety
/// `bp` must point to the live boot_params (4096 bytes).
#[no_mangle]
pub unsafe extern "C" fn misc_sanitize_boot_params(bp: *mut u8) {
    // SAFETY: caller contract; SANITIZE_SCRATCH is a private 4096-byte static.
    unsafe { sanitize_boot_params(bp, (&raw mut SANITIZE_SCRATCH).cast::<u8>()) }
}

#[inline(always)]
fn physical_mask_value() -> u64 {
    #[cfg(amd_mem_encrypt)]
    // SAFETY: plain read of a stub global.
    return unsafe { ptr::read(&raw const physical_mask) };
    #[cfg(not(amd_mem_encrypt))]
    return (1u64 << 52) - 1;
}

/// PTE_PFN_MASK = (signed long)PAGE_MASK & __PHYSICAL_MASK
#[inline(always)]
fn pte_pfn_mask() -> u64 {
    PAGE_MASK & physical_mask_value()
}

/// native_read_cr3_pa() = read_cr3() & CR3_ADDR_MASK; CR3_ADDR_MASK = __sme_clr(PHYSICAL_PAGE_MASK)
#[inline(always)]
unsafe fn native_read_cr3_pa() -> u64 {
    let cr3: u64;
    // SAFETY: ring 0 (the C was `mov %cr3`).
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    #[cfg(amd_mem_encrypt)]
    // SAFETY: plain read of a stub global.
    return cr3 & pte_pfn_mask() & !unsafe { ptr::read(&raw const sme_me_mask) };
    #[cfg(not(amd_mem_encrypt))]
    return cr3 & pte_pfn_mask();
}

/// `void configure_5level_paging(struct boot_params *bp, void *pgtable)`
///
/// # Safety
/// Called once from head_64.S in 64-bit mode with the stub's identity-mapped low memory.
#[no_mangle]
pub unsafe extern "C" fn configure_5level_paging(bp: *mut u8, pgtable: *mut u8) {
    let mut l5_required = false;

    // SAFETY: boot-time, single CPU, ring 0, identity-mapped memory (the C's own assumptions).
    unsafe {
        // Initialize boot_params. Required for cmdline_find_option_bool().
        sanitize_boot_params(bp, (&raw mut SANITIZE_SCRATCH).cast::<u8>());
        boot_params_ptr = bp;

        // Check if LA57 is desired and supported: no `no5lvl` on the command line, CPUID leaf 7
        // exists and has the LA57 bit (leaf 7 ecx bit 16).
        if cmdline_find_option_bool(c"no5lvl".as_ptr()) == 0
            && core::arch::x86_64::__cpuid_count(0, 0).eax >= 7
            && (core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 16)) != 0
        {
            l5_required = true;

            // Initialize variables for 5-level paging
            __pgtable_l5_enabled = 1;
            pgdir_shift = 48;
            ptrs_per_p4d = 512;
        }

        // The trampoline will not be used if the paging mode is already set to the desired one.
        let cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if l5_required == ((cr4 & X86_CR4_LA57) != 0) {
            return;
        }

        trampoline_32bit = find_trampoline_placement() as *mut u64;
        let tramp = trampoline_32bit.cast::<u8>();

        // Preserve trampoline memory
        let save = (&raw mut TRAMPOLINE_SAVE).cast::<u8>();
        ptr::copy_nonoverlapping(tramp, save, TRAMPOLINE_32BIT_SIZE);

        // Clear trampoline memory first
        ptr::write_bytes(tramp, 0, TRAMPOLINE_32BIT_SIZE);

        // Copy trampoline code in place
        let toggle_la57 = tramp.add(TRAMPOLINE_32BIT_CODE_OFFSET);
        ptr::copy_nonoverlapping(&raw const trampoline_32bit_src, toggle_la57, TRAMPOLINE_32BIT_CODE_SIZE);

        // Avoid the need for a stack in the 32-bit trampoline code, by using LJMP rather than
        // LRET to return back to long mode. LJMP takes an immediate absolute address, which needs
        // to be adjusted based on the placement of the trampoline. (The immediate is unaligned.)
        let imm = toggle_la57.add(ptr::read(&raw const trampoline_ljmp_imm_offset) as usize).cast::<u32>();
        imm.write_unaligned(imm.read_unaligned().wrapping_add(toggle_la57 as usize as u32));

        // The code below prepares page table in trampoline memory: the new page table will be
        // used by trampoline code for switching from 4- to 5-level paging or vice versa.
        if l5_required {
            // For 4- to 5-level paging transition, set up current CR3 as the first and the only
            // entry in a new top-level page table.
            *trampoline_32bit = native_read_cr3_pa() | PAGE_TABLE_NOENC;
        } else {
            // For 5- to 4-level paging transition, copy page table pointed by first entry in the
            // current top-level page table as our new top-level page table. We cannot just point
            // to the page table from trampoline as it may be above 4G.
            let pgdp = native_read_cr3_pa() as *const u64;
            let new_cr3 = (*pgdp & pte_pfn_mask()) as *const u8;
            ptr::copy_nonoverlapping(new_cr3, tramp, PAGE_SIZE as usize);
        }

        // void (*toggle_la57)(void *cr3): called with the ordinary C calling convention.
        let toggle: unsafe extern "C" fn(*mut u64) = core::mem::transmute(toggle_la57);
        toggle(trampoline_32bit);

        // Move the top level page table out of trampoline memory.
        ptr::copy_nonoverlapping(tramp, pgtable, PAGE_SIZE as usize);
        asm!("mov cr3, {}", in(reg) pgtable as usize as u64, options(nostack, preserves_flags));

        // Restore trampoline memory
        ptr::copy_nonoverlapping(save, tramp, TRAMPOLINE_32BIT_SIZE);
    }
}
