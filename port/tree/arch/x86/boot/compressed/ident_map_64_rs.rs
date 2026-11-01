// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/ident_map_64.c (which `#include`s the kernel's
//! shared arch/x86/mm/ident_map.c, ported here too: that file stays C for the regular kernel).
//!
//! The stub's on-demand identity map: `initialize_identity_maps()` builds the first page tables
//! (kernel image, boot_params, command line, setup_data), `do_boot_page_fault()` (called from the
//! #PF gate in idt_64_rs.rs) maps the 2 MiB around any later fault, `set_page_*()` change one 4 KiB
//! page's flags for SEV. Exports everything the C object did (the file-local state stays local).
//!
//! A wrong flag or index here triple-faults. The page-table walk helpers below mirror the
//! kernel's inline functions as they expand in this stub (pgtable_l5_enabled() is the variable
//! `__pgtable_l5_enabled`, __pa/__va are the identity, p4d is folded at run time by returning
//! the pgd entry's address). They, and the whole build-up, are compared with the original C
//! (compiled for userspace from the same preprocessed source) in rig/stube-parity/ident_cmp.rs.
//! `--cfg=amd_mem_encrypt` / `--cfg=x86_verbose_bootup` mirror CONFIG_AMD_MEM_ENCRYPT /
//! CONFIG_X86_VERBOSE_BOOTUP.

#![allow(non_upper_case_globals)] // file-local state keeps the C names (pgt_data, top_level_pgt, mapping_info)

use core::arch::asm;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);
const PMD_SHIFT: u32 = 21;
const PMD_SIZE: u64 = 1 << PMD_SHIFT;
const PMD_MASK: u64 = !(PMD_SIZE - 1);
const PUD_SHIFT: u32 = 30;
const PUD_SIZE: u64 = 1 << PUD_SHIFT;
const PUD_MASK: u64 = !(PUD_SIZE - 1);
const P4D_SHIFT: u32 = 39;
const PTRS_PER_PGD: usize = 512;
const PTRS_PER_PUD: usize = 512;
const PTRS_PER_PMD: usize = 512;
const PTRS_PER_PTE: usize = 512;
const ENOMEM: c_int = 12;

// asm/pgtable_types.h
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_RW: u64 = 1 << 1;
const PAGE_ACCESSED: u64 = 1 << 5;
const PAGE_DIRTY: u64 = 1 << 6;
const PAGE_PSE: u64 = 1 << 7;
const PAGE_GLOBAL: u64 = 1 << 8; // == _PAGE_PROTNONE
const PAGE_NOPTISHADOW: u64 = 1 << 58;
const KERNPG_TABLE: u64 = PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY; // + _ENC
const PAGE_KERNEL_LARGE_EXEC: u64 = PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY | PAGE_PSE | PAGE_GLOBAL; // + _ENC
const PHYSICAL_MASK_SHIFT: u32 = 52;

// asm/boot.h (64-bit)
const BOOT_INIT_PGT_SIZE: u64 = 6 * 4096;
const BOOT_PGT_SIZE_WARN: u64 = 28 * 4096;
const BOOT_PGT_SIZE: u64 = 32 * 4096;
const COMMAND_LINE_SIZE: u64 = 2048;
// asm/trap_pf.h
const X86_PF_PROT: u64 = 1 << 0;
const X86_PF_USER: u64 = 1 << 2;
const X86_PF_RSVD: u64 = 1 << 3;
/// offsetof(struct pt_regs, ip); offsetof(struct boot_params, hdr.setup_data); sizeof(struct boot_params)
const PT_REGS_IP: usize = 128;
const BP_HDR_SETUP_DATA: usize = 0x250;
const BOOT_PARAMS_SIZE: usize = 4096;
/// struct setup_data { u64 next; u32 type; u32 len; u8 data[]; }
const SETUP_DATA_SIZE: u64 = 16;

/// `struct x86_mapping_info` (asm/init.h)
#[repr(C)]
pub struct MappingInfo {
    pub alloc_pgt_page: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    pub free_pgt_page: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub context: *mut c_void,
    pub page_flag: u64,
    pub offset: u64,
    pub direct_gbpages: bool,
    pub kernpg_flag: u64,
}
const _: () = assert!(core::mem::size_of::<MappingInfo>() == 56);
const _: () = assert!(core::mem::offset_of!(MappingInfo, kernpg_flag) == 48);

/// struct alloc_pgt_data
#[repr(C)]
pub struct AllocPgtData {
    pub pgt_buf: *mut u8,
    pub pgt_buf_size: u64,
    pub pgt_buf_offset: u64,
}

extern "C" {
    static mut __pgtable_l5_enabled: u32;
    static mut pgdir_shift: u32;
    static mut ptrs_per_p4d: u32;
    static mut boot_params_ptr: *mut u8;
    static mut spurious_nmi_count: c_int;
    static _head: u8;
    static _end: u8;
    static mut _pgtable: u8;
    fn error(m: *mut c_char) -> !;
    fn __putstr(s: *const c_char);
    fn __puthex(v: u64);
    fn get_cmd_line_ptr() -> u64;
    #[cfg(userspace_test)]
    static test_cr3: u64;
    #[cfg(amd_mem_encrypt)]
    static sme_me_mask: u64;
    #[cfg(amd_mem_encrypt)]
    fn sev_prep_identity_maps(top_level_pgt: u64);
    #[cfg(amd_mem_encrypt)]
    fn snp_check_features();
    #[cfg(amd_mem_encrypt)]
    fn sev_es_check_ghcb_fault(address: u64) -> bool;
    #[cfg(amd_mem_encrypt)]
    fn snp_set_page_private(paddr: u64);
    #[cfg(amd_mem_encrypt)]
    fn snp_set_page_shared(paddr: u64);
}

/// Used by PAGE_KERN* macros
#[no_mangle]
pub static mut __default_kernel_pte_mask: u64 = !0;

#[no_mangle]
pub static mut physical_mask: u64 = (1u64 << PHYSICAL_MASK_SHIFT) - 1;

/// Used to track our allocated page tables.
pub(crate) static mut pgt_data: AllocPgtData = AllocPgtData { pgt_buf: ptr::null_mut(), pgt_buf_size: 0, pgt_buf_offset: 0 };
/// The top level page table entry pointer.
pub(crate) static mut top_level_pgt: u64 = 0;
/// Mapping information passed to kernel_ident_mapping_init(); pointers are assigned at run time.
pub(crate) static mut mapping_info: MappingInfo = MappingInfo {
    alloc_pgt_page: None,
    free_pgt_page: None,
    context: ptr::null_mut(),
    page_flag: 0,
    offset: 0,
    direct_gbpages: false,
    kernpg_flag: 0,
};

// ---- SME / physical-mask plumbing: constants unless CONFIG_AMD_MEM_ENCRYPT ----
#[inline(always)]
fn sme_mask() -> u64 {
    #[cfg(amd_mem_encrypt)]
    // SAFETY: plain read of a stub global.
    return unsafe { ptr::read(&raw const sme_me_mask) };
    #[cfg(not(amd_mem_encrypt))]
    return 0;
}
/// __PHYSICAL_MASK: the variable `physical_mask` with CONFIG_DYNAMIC_PHYSICAL_MASK (SEV), else a constant.
#[inline(always)]
fn phys_mask() -> u64 {
    #[cfg(amd_mem_encrypt)]
    // SAFETY: plain read of this file's global.
    return unsafe { ptr::read(&raw const physical_mask) };
    #[cfg(not(amd_mem_encrypt))]
    return (1u64 << PHYSICAL_MASK_SHIFT) - 1;
}
#[inline(always)]
fn pte_pfn_mask() -> u64 {
    PAGE_MASK & phys_mask()
}
#[inline(always)]
fn pud_pfn_mask(pud: u64) -> u64 {
    if pud & PAGE_PSE != 0 { PUD_MASK & phys_mask() } else { pte_pfn_mask() }
}
#[inline(always)]
fn pmd_pfn_mask(pmd: u64) -> u64 {
    if pmd & PAGE_PSE != 0 { PMD_MASK & phys_mask() } else { pte_pfn_mask() }
}

// ---- the kernel's page-table inlines, as they expand in this stub ----
#[inline(always)]
unsafe fn l5() -> bool {
    // SAFETY: stub global written by configure_5level_paging().
    unsafe { ptr::read(&raw const __pgtable_l5_enabled) != 0 }
}
#[inline(always)]
unsafe fn pgd_present(pgd: u64) -> bool {
    // SAFETY: l5() contract.
    if unsafe { !l5() } { true } else { pgd & PAGE_PRESENT != 0 }
}
#[inline(always)]
fn p4d_present(p4d: u64) -> bool {
    p4d & PAGE_PRESENT != 0
}
#[inline(always)]
fn pud_present(pud: u64) -> bool {
    pud & PAGE_PRESENT != 0
}
#[inline(always)]
fn pud_leaf(pud: u64) -> bool {
    pud & PAGE_PSE != 0
}
/// pmd_present(): PRESENT | PROTNONE | PSE
#[inline(always)]
fn pmd_present(pmd: u64) -> bool {
    pmd & (PAGE_PRESENT | PAGE_GLOBAL | PAGE_PSE) != 0
}
#[inline(always)]
fn pmd_leaf(pmd: u64) -> bool {
    pmd & PAGE_PSE != 0
}
#[inline(always)]
unsafe fn p4d_index(addr: u64) -> u64 {
    // SAFETY: stub global.
    (addr >> P4D_SHIFT) & (unsafe { ptr::read(&raw const ptrs_per_p4d) }.wrapping_sub(1) as u64)
}
#[inline(always)]
fn pud_index(addr: u64) -> u64 {
    (addr >> PUD_SHIFT) & (PTRS_PER_PUD as u64 - 1)
}
#[inline(always)]
fn pmd_index(addr: u64) -> u64 {
    (addr >> PMD_SHIFT) & (PTRS_PER_PMD as u64 - 1)
}
#[inline(always)]
fn pte_index(addr: u64) -> u64 {
    (addr >> 12) & (PTRS_PER_PTE as u64 - 1)
}
#[inline(always)]
unsafe fn pgd_index(addr: u64) -> u64 {
    // SAFETY: stub global.
    (addr >> unsafe { ptr::read(&raw const pgdir_shift) }) & (PTRS_PER_PGD as u64 - 1)
}
/// p4d_offset(): the pgd entry itself when 5-level is off (p4d folded), else the p4d table + index
#[inline(always)]
unsafe fn p4d_offset(pgd: *mut u64, address: u64) -> *mut u64 {
    // SAFETY: l5()/page-table contract.
    unsafe {
        if !l5() {
            return pgd;
        }
        ((ptr::read(pgd) & pte_pfn_mask()) as *mut u64).add(p4d_index(address) as usize)
    }
}
#[inline(always)]
unsafe fn pud_offset(p4d: *mut u64, address: u64) -> *mut u64 {
    // SAFETY: page-table contract (p4d points at a present entry).
    unsafe { ((ptr::read(p4d) & pte_pfn_mask()) as *mut u64).add(pud_index(address) as usize) }
}
#[inline(always)]
unsafe fn pmd_offset(pud: *mut u64, address: u64) -> *mut u64 {
    // SAFETY: as above.
    unsafe {
        let v = ptr::read(pud);
        ((v & pud_pfn_mask(v)) as *mut u64).add(pmd_index(address) as usize)
    }
}
#[inline(always)]
unsafe fn pte_offset_kernel(pmd: *mut u64, address: u64) -> *mut u64 {
    // SAFETY: as above.
    unsafe {
        let v = ptr::read(pmd);
        ((v & pmd_pfn_mask(v)) as *mut u64).add(pte_index(address) as usize)
    }
}
/// WRITE_ONCE of a page-table entry (pti_set_user_pgtbl() is the identity: PTI is #undef'd here)
#[inline(always)]
unsafe fn set_entry(p: *mut u64, v: u64) {
    // SAFETY: caller contract.
    unsafe { ptr::write_volatile(p, v) };
}
/// `({ __boundary = (addr + SIZE) & MASK; (__boundary - 1 < end - 1) ? __boundary : end; })`
#[inline(always)]
fn addr_end(addr: u64, end: u64, shift: u32) -> u64 {
    let size = 1u64 << shift;
    let boundary = addr.wrapping_add(size) & !(size - 1);
    if boundary.wrapping_sub(1) < end.wrapping_sub(1) { boundary } else { end }
}

// ---- arch/x86/mm/ident_map.c ----
unsafe fn free_pgt(info: &MappingInfo, page: *mut u64) {
    match info.free_pgt_page {
        // SAFETY: caller contract; the page was handed out by alloc_pgt_page.
        Some(f) => unsafe { f(page.cast(), info.context) },
        // The C would call through NULL. Nothing in the stub calls the free functions
        // (free_pgt_page is never set); stop instead of jumping to 0.
        None => loop {
            // SAFETY: `hlt`.
            unsafe { asm!("hlt", options(nomem, nostack)) };
        },
    }
}

unsafe fn free_pte(info: &MappingInfo, pmd: *mut u64) {
    // SAFETY: page-table contract.
    unsafe { free_pgt(info, pte_offset_kernel(pmd, 0)) };
}

unsafe fn free_pmd(info: &MappingInfo, pud: *mut u64) {
    // SAFETY: page-table contract.
    unsafe {
        let pmd = pmd_offset(pud, 0);
        for i in 0..PTRS_PER_PMD {
            let e = ptr::read(pmd.add(i));
            if !pmd_present(e) {
                continue;
            }
            if pmd_leaf(e) {
                continue;
            }
            free_pte(info, pmd.add(i));
        }
        free_pgt(info, pmd);
    }
}

unsafe fn free_pud(info: &MappingInfo, p4d: *mut u64) {
    // SAFETY: page-table contract.
    unsafe {
        let pud = pud_offset(p4d, 0);
        for i in 0..PTRS_PER_PUD {
            let e = ptr::read(pud.add(i));
            if !pud_present(e) {
                continue;
            }
            if pud_leaf(e) {
                continue;
            }
            free_pmd(info, pud.add(i));
        }
        free_pgt(info, pud);
    }
}

unsafe fn free_p4d(info: &MappingInfo, pgd: *mut u64) {
    // SAFETY: page-table contract.
    unsafe {
        let p4d = p4d_offset(pgd, 0);
        let n = ptr::read(&raw const ptrs_per_p4d);
        let mut i: u32 = 0;
        while i < n {
            if p4d_present(ptr::read(p4d.add(i as usize))) {
                free_pud(info, p4d.add(i as usize));
            }
            i += 1;
        }
        if l5() {
            free_pgt(info, p4d);
        }
    }
}

/// # Safety
/// `info` and `pgd` valid, as for the C.
#[no_mangle]
pub unsafe extern "C" fn kernel_ident_mapping_free(info: *mut MappingInfo, pgd: *mut u64) {
    // SAFETY: caller contract.
    unsafe {
        for i in 0..PTRS_PER_PGD {
            if !pgd_present(ptr::read(pgd.add(i))) {
                continue;
            }
            free_p4d(&*info, pgd.add(i));
        }
        free_pgt(&*info, pgd);
    }
}

unsafe fn ident_pmd_init(info: &MappingInfo, pmd_page: *mut u64, addr: u64, end: u64) {
    let mut addr = addr & PMD_MASK;
    while addr < end {
        // SAFETY: page-table contract.
        unsafe {
            let pmd = pmd_page.add(pmd_index(addr) as usize);
            if !pmd_present(ptr::read(pmd)) {
                set_entry(pmd, addr.wrapping_sub(info.offset) | info.page_flag);
            }
        }
        addr = addr.wrapping_add(PMD_SIZE);
    }
}

unsafe fn ident_pud_init(info: &MappingInfo, pud_page: *mut u64, addr: u64, end: u64) -> c_int {
    let mut addr = addr;
    while addr < end {
        // SAFETY: page-table contract.
        unsafe {
            let pud = pud_page.add(pud_index(addr) as usize);
            let next = addr_end(addr, end, PUD_SHIFT);

            // if this is already a gbpage, this portion is already mapped
            if !pud_leaf(ptr::read(pud)) {
                // Is using a gbpage allowed? Not if it maps more than the requested region, at
                // the beginning or at the end, and never over an existing mapping.
                let use_gbpage = info.direct_gbpages
                    && (addr & !PUD_MASK) == 0
                    && (next & !PUD_MASK) == 0
                    && !pud_present(ptr::read(pud));

                if use_gbpage {
                    set_entry(pud, addr.wrapping_sub(info.offset) | info.page_flag);
                } else if pud_present(ptr::read(pud)) {
                    let pmd = pmd_offset(pud, 0);
                    ident_pmd_init(info, pmd, addr, next);
                } else {
                    let alloc = info.alloc_pgt_page.unwrap_unchecked();
                    let pmd = alloc(info.context) as *mut u64;
                    if pmd.is_null() {
                        return -ENOMEM;
                    }
                    ident_pmd_init(info, pmd, addr, next);
                    set_entry(pud, (pmd as u64) | info.kernpg_flag);
                }
            }
            addr = next;
        }
    }
    0
}

unsafe fn ident_p4d_init(info: &MappingInfo, p4d_page: *mut u64, addr: u64, end: u64) -> c_int {
    let mut addr = addr;
    while addr < end {
        // SAFETY: page-table contract.
        unsafe {
            let p4d = p4d_page.add(p4d_index(addr) as usize);
            let next = addr_end(addr, end, P4D_SHIFT);
            if p4d_present(ptr::read(p4d)) {
                let pud = pud_offset(p4d, 0);
                let result = ident_pud_init(info, pud, addr, next);
                if result != 0 {
                    return result;
                }
            } else {
                let alloc = info.alloc_pgt_page.unwrap_unchecked();
                let pud = alloc(info.context) as *mut u64;
                if pud.is_null() {
                    return -ENOMEM;
                }
                let result = ident_pud_init(info, pud, addr, next);
                if result != 0 {
                    return result;
                }
                set_entry(p4d, (pud as u64) | info.kernpg_flag | PAGE_NOPTISHADOW);
            }
            addr = next;
        }
    }
    0
}

/// # Safety
/// `info` (alloc_pgt_page set) and `pgd_page` valid, as for the C.
#[no_mangle]
pub unsafe extern "C" fn kernel_ident_mapping_init(info: *mut MappingInfo, pgd_page: *mut u64, pstart: u64, pend: u64) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let info = &mut *info;
        let mut addr = pstart.wrapping_add(info.offset);
        let end = pend.wrapping_add(info.offset);

        // Set the default pagetable flags if not supplied
        if info.kernpg_flag == 0 {
            info.kernpg_flag = KERNPG_TABLE | sme_mask();
        }
        // Filter out unsupported __PAGE_KERNEL_* bits:
        info.kernpg_flag &= ptr::read(&raw const __default_kernel_pte_mask);

        while addr < end {
            let pgd = pgd_page.add(pgd_index(addr) as usize);
            let next = addr_end(addr, end, ptr::read(&raw const pgdir_shift));
            if pgd_present(ptr::read(pgd)) {
                let p4d = p4d_offset(pgd, 0);
                let result = ident_p4d_init(info, p4d, addr, next);
                if result != 0 {
                    return result;
                }
            } else {
                let alloc = info.alloc_pgt_page.unwrap_unchecked();
                let p4d = alloc(info.context) as *mut u64;
                if p4d.is_null() {
                    return -ENOMEM;
                }
                let result = ident_p4d_init(info, p4d, addr, next);
                if result != 0 {
                    return result;
                }
                if l5() {
                    set_entry(pgd, (p4d as u64) | info.kernpg_flag | PAGE_NOPTISHADOW);
                } else {
                    // With p4d folded, pgd is equal to p4d. The pgd entry has to point to the
                    // pud page table in this case.
                    let pud = pud_offset(p4d, 0);
                    set_entry(pgd, (pud as u64) | info.kernpg_flag | PAGE_NOPTISHADOW);
                }
            }
            addr = next;
        }
    }
    0
}

// ---- arch/x86/boot/compressed/ident_map_64.c ----
#[cfg(x86_verbose_bootup)]
macro_rules! debug_putaddr {
    ($name:literal, $val:expr) => {{
        __putstr(concat!($name, ": 0x\0").as_ptr().cast());
        __puthex($val);
        __putstr(c"\n".as_ptr());
    }};
}

/// Allocates space for a page table entry; also the `alloc_pgt_page` callback of mapping_info.
unsafe extern "C" fn alloc_pgt_page(context: *mut c_void) -> *mut c_void {
    // SAFETY: `context` is &pgt_data (or a caller's AllocPgtData).
    unsafe {
        let pages = &mut *(context as *mut AllocPgtData);

        // Validate there is space available for a new page.
        if pages.pgt_buf_offset >= pages.pgt_buf_size {
            #[cfg(x86_verbose_bootup)]
            {
                __putstr(c"out of pgt_buf in arch/x86/boot/compressed/ident_map_64.c!?\n".as_ptr());
                debug_putaddr!("pages->pgt_buf_offset", pages.pgt_buf_offset);
                debug_putaddr!("pages->pgt_buf_size", pages.pgt_buf_size);
            }
            return ptr::null_mut();
        }

        // Consumed more tables than expected?
        if pages.pgt_buf_offset == BOOT_PGT_SIZE_WARN {
            #[cfg(x86_verbose_bootup)]
            {
                __putstr(c"pgt_buf running low in arch/x86/boot/compressed/ident_map_64.c\n".as_ptr());
                __putstr(c"Need to raise BOOT_PGT_SIZE?\n".as_ptr());
                debug_putaddr!("pages->pgt_buf_offset", pages.pgt_buf_offset);
                debug_putaddr!("pages->pgt_buf_size", pages.pgt_buf_size);
            }
        }

        let entry = pages.pgt_buf.add(pages.pgt_buf_offset as usize);
        pages.pgt_buf_offset += PAGE_SIZE;
        entry.cast()
    }
}

#[inline(always)]
fn round_down_pmd(x: u64) -> u64 {
    x & PMD_MASK
}
#[inline(always)]
fn round_up_pmd(x: u64) -> u64 {
    (x.wrapping_sub(1) | (PMD_SIZE - 1)).wrapping_add(1)
}

/// Adds the specified range to the identity mappings.
#[no_mangle]
pub unsafe extern "C" fn kernel_add_identity_map(start: u64, end: u64) {
    // Align boundary to 2M.
    let start = round_down_pmd(start);
    let end = round_up_pmd(end);
    if start >= end {
        return;
    }

    // Build the mapping.
    // SAFETY: single CPU, boot time; mapping_info/top_level_pgt set by initialize_identity_maps().
    let ret = unsafe { kernel_ident_mapping_init(&raw mut mapping_info, ptr::read(&raw const top_level_pgt) as *mut u64, start, end) };
    if ret != 0 {
        // SAFETY: error() takes a NUL-terminated string and never returns.
        unsafe { error(c"Error: kernel_ident_mapping_init() failed\n".as_ptr().cast_mut()) };
    }
}

#[inline(always)]
unsafe fn write_cr3(v: u64) {
    // SAFETY: ring 0; flushes the TLB, as the C's native_write_cr3().
    #[cfg(not(userspace_test))]
    unsafe {
        asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags))
    };
    // test seam: rig/stube-parity/ident_cmp.rs runs this file in userspace, where CR3 cannot be written
    // (the C twin has the same instruction elided); never set in a kernel build.
    #[cfg(userspace_test)]
    let _ = v;
}

/// Locates and clears a region for a new top level page table.
#[no_mangle]
pub unsafe extern "C" fn initialize_identity_maps(rmode: *mut u8) {
    // SAFETY: boot time, single CPU, identity-mapped memory; the C's own assumptions.
    unsafe {
        // Exclude the encryption mask from __PHYSICAL_MASK
        physical_mask &= !sme_mask();

        // Init mapping_info with run-time function/buffer pointers.
        mapping_info.alloc_pgt_page = Some(alloc_pgt_page);
        mapping_info.context = (&raw mut pgt_data).cast();
        // __PAGE_KERNEL_LARGE_EXEC (which carries _ENC = sme_me_mask) | sme_me_mask
        mapping_info.page_flag = PAGE_KERNEL_LARGE_EXEC | sme_mask();
        mapping_info.kernpg_flag = KERNPG_TABLE | sme_mask();

        // It should be impossible for this not to already be true, but since calling this a
        // second time would rewind the other counters, make sure this is reset too.
        pgt_data.pgt_buf_offset = 0;

        // If we came here via startup_32(), cr3 will be _pgtable already and we must append to the
        // existing area instead of entirely overwriting it. With 5-level paging, '_pgtable' is
        // used to allocate the p4d page table, the top-level page table is allocated separately.
        let cr3: u64;
        #[cfg(not(userspace_test))]
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        #[cfg(userspace_test)]
        {
            cr3 = ptr::read(&raw const test_cr3); // test seam, see write_cr3()
        }
        top_level_pgt = cr3 & pte_pfn_mask() & !sme_mask();
        let pgtable = (&raw mut _pgtable).cast::<u8>();
        if p4d_offset(top_level_pgt as *mut u64, 0) as *mut u8 == pgtable {
            pgt_data.pgt_buf = pgtable.add(BOOT_INIT_PGT_SIZE as usize);
            pgt_data.pgt_buf_size = BOOT_PGT_SIZE - BOOT_INIT_PGT_SIZE;
            ptr::write_bytes(pgt_data.pgt_buf, 0, pgt_data.pgt_buf_size as usize);
        } else {
            pgt_data.pgt_buf = pgtable;
            pgt_data.pgt_buf_size = BOOT_PGT_SIZE;
            ptr::write_bytes(pgt_data.pgt_buf, 0, pgt_data.pgt_buf_size as usize);
            top_level_pgt = alloc_pgt_page((&raw mut pgt_data).cast()) as u64;
        }

        // New page-table is set up - map the kernel image, boot_params and the command line. The
        // uncompressed kernel requires boot_params and the command line to be mapped in the
        // identity mapping. Map them explicitly here in case the compressed kernel does not touch
        // them, or does not touch all the pages covering them.
        kernel_add_identity_map((&raw const _head) as u64, (&raw const _end) as u64);
        boot_params_ptr = rmode;
        kernel_add_identity_map(boot_params_ptr as u64, boot_params_ptr as u64 + BOOT_PARAMS_SIZE as u64);
        let cmdline = get_cmd_line_ptr();
        kernel_add_identity_map(cmdline, cmdline + COMMAND_LINE_SIZE);

        // Also map the setup_data entries passed via boot_params in case they need to be accessed
        // by uncompressed kernel via the identity mapping.
        let mut sd = ptr::read_unaligned(boot_params_ptr.add(BP_HDR_SETUP_DATA) as *const u64) as *const u8;
        while !sd.is_null() {
            let sd_addr = sd as u64;
            let len = ptr::read_unaligned(sd.add(12) as *const u32) as u64; // sd->len
            kernel_add_identity_map(sd_addr, sd_addr + SETUP_DATA_SIZE + len);
            sd = ptr::read_unaligned(sd as *const u64) as *const u8; // sd->next
        }

        #[cfg(amd_mem_encrypt)]
        sev_prep_identity_maps(top_level_pgt);

        // Load the new page-table.
        write_cr3(top_level_pgt);

        // Now that the required page table mappings are established and a GHCB can be used,
        // check for SNP guest/HV feature compatibility.
        #[cfg(amd_mem_encrypt)]
        snp_check_features();
    }
}

unsafe fn split_large_pmd(info: &MappingInfo, pmdp: *mut u64, address: u64) -> *mut u64 {
    // SAFETY: page-table contract.
    unsafe {
        let pte = info.alloc_pgt_page.unwrap_unchecked()(info.context) as *mut u64;
        if pte.is_null() {
            return ptr::null_mut();
        }

        let mut a = address & PMD_MASK;
        // No large page - clear PSE flag
        let page_flags = info.page_flag & !PAGE_PSE;

        // Populate the PTEs
        for i in 0..PTRS_PER_PMD {
            set_entry(pte.add(i), a | page_flags);
            a += PAGE_SIZE;
        }

        // Ideally we need to clear the large PMD first and do a TLB flush before we write the new
        // PMD. But the 2M range of the PMD might contain the code we execute and/or the stack we
        // are on, so we can't do that. But that should be safe here because we are going from
        // large to small mappings and we are also the only user of the page-table, so there is no
        // chance of a TLB multihit.
        set_entry(pmdp, (pte as u64) | info.kernpg_flag);
        // Flush TLB to establish the new PMD
        write_cr3(ptr::read(&raw const top_level_pgt));

        pte.add(pte_index(address) as usize)
    }
}

#[cfg(amd_mem_encrypt)]
unsafe fn clflush_page(address: u64) {
    // Hardcode cl-size to 64 - CPUID can't be used here because that might cause another #VC
    // exception and the GHCB is not ready to use yet.
    let flush_size = 64usize;
    let start = (address & PAGE_MASK) as *const u8;
    // SAFETY: ring 0; first make sure there are no pending writes on the cache-lines to flush.
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
        let mut off = 0usize;
        while off != PAGE_SIZE as usize {
            asm!("clflush [{}]", in(reg) start.add(off), options(nostack, preserves_flags));
            off += flush_size;
        }
    }
}

unsafe fn set_clr_page_flags(info: &MappingInfo, address: u64, set: u64, clr: u64) -> c_int {
    // SAFETY: boot time, page-table contract.
    unsafe {
        let pgdp = ptr::read(&raw const top_level_pgt) as *mut u64;

        // First make sure there is a PMD mapping for 'address'. It should already exist, but keep
        // things generic. To map the page just read from it and fault it in if there is no
        // mapping yet. kernel_add_identity_map() can't be called here because that would
        // unconditionally map the address on PMD level, destroying any PTE-level mappings that
        // might already exist. Use assembly here so the access won't be optimized away.
        asm!("mov r9, {}", in(reg) ptr::read_volatile(address as *const u64), out("r9") _, options(nostack, preserves_flags));

        // The page is mapped at least with PMD size - so skip checks and walk directly to the PMD.
        let p4dp = p4d_offset(pgdp, address);
        let pudp = pud_offset(p4dp, address);
        let pmdp = pmd_offset(pudp, address);

        let ptep = if pmd_leaf(ptr::read(pmdp)) { split_large_pmd(info, pmdp, address) } else { pte_offset_kernel(pmdp, address) };

        if ptep.is_null() {
            return -ENOMEM;
        }

        // Changing encryption attributes of a page requires to flush it from the caches.
        #[cfg(amd_mem_encrypt)]
        if (set | clr) & sme_mask() != 0 {
            clflush_page(address);

            // If the encryption attribute is being cleared, change the page state to shared in
            // the RMP table.
            if clr != 0 {
                snp_set_page_shared(address & PAGE_MASK);
            }
        }

        // Update PTE
        let pte = (ptr::read(ptep) | set) & !clr;
        set_entry(ptep, pte);

        // If the encryption attribute is being set, then change the page state to private in the
        // RMP entry. The page state change must be done after the PTE is updated.
        #[cfg(amd_mem_encrypt)]
        if set & sme_mask() != 0 {
            snp_set_page_private(address & PAGE_MASK);
        }

        // Flush TLB after changing encryption attribute
        write_cr3(ptr::read(&raw const top_level_pgt));

        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_page_decrypted(address: u64) -> c_int {
    // SAFETY: boot-time; same contract as the C.
    unsafe { set_clr_page_flags(&*(&raw const mapping_info), address, 0, sme_mask()) }
}

#[no_mangle]
pub unsafe extern "C" fn set_page_encrypted(address: u64) -> c_int {
    // SAFETY: as above.
    unsafe { set_clr_page_flags(&*(&raw const mapping_info), address, sme_mask(), 0) }
}

#[no_mangle]
pub unsafe extern "C" fn set_page_non_present(address: u64) -> c_int {
    // SAFETY: as above.
    unsafe { set_clr_page_flags(&*(&raw const mapping_info), address, 0, PAGE_PRESENT) }
}

unsafe fn do_pf_error(msg: &core::ffi::CStr, error_code: u64, address: u64, ip: u64) -> ! {
    // SAFETY: error_putstr()/error_puthex() are __putstr()/__puthex(); NUL-terminated literals.
    unsafe {
        __putstr(msg.as_ptr());

        __putstr(c"\nError Code: ".as_ptr());
        __puthex(error_code);
        __putstr(c"\nCR2: 0x".as_ptr());
        __puthex(address);
        __putstr(c"\nRIP relative to _head: 0x".as_ptr());
        __puthex(ip.wrapping_sub((&raw const _head) as u64));
        __putstr(c"\n".as_ptr());

        error(c"Stopping.\n".as_ptr().cast_mut())
    }
}

/// `void do_boot_page_fault(struct pt_regs *regs, unsigned long error_code)`
#[no_mangle]
pub unsafe extern "C" fn do_boot_page_fault(regs: *const u8, error_code: u64) {
    // SAFETY: called from the boot_page_fault asm stub with a pt_regs on the stack, ring 0.
    unsafe {
        let cr2: u64;
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        let mut address = cr2;

        #[cfg(amd_mem_encrypt)]
        let ghcb_fault = sev_es_check_ghcb_fault(address);
        #[cfg(not(amd_mem_encrypt))]
        let ghcb_fault = false;

        address &= PMD_MASK;
        let end = address.wrapping_add(PMD_SIZE);

        // Check for unexpected error codes. Unexpected are:
        //  - Faults on present pages
        //  - User faults
        //  - Reserved bits set
        if error_code & (X86_PF_PROT | X86_PF_USER | X86_PF_RSVD) != 0 {
            do_pf_error(c"Unexpected page-fault:", error_code, address, ptr::read_unaligned(regs.add(PT_REGS_IP) as *const u64));
        } else if ghcb_fault {
            do_pf_error(c"Page-fault on GHCB page:", error_code, address, ptr::read_unaligned(regs.add(PT_REGS_IP) as *const u64));
        }

        // Error code is sane - now identity map the 2M region around the faulting address.
        kernel_add_identity_map(address, end);
    }
}

/// `void do_boot_nmi_trap(struct pt_regs *regs, unsigned long error_code)`
#[no_mangle]
pub unsafe extern "C" fn do_boot_nmi_trap(_regs: *const u8, _error_code: u64) {
    // SAFETY: stub global.
    unsafe { spurious_nmi_count = spurious_nmi_count.wrapping_add(1) };
}
