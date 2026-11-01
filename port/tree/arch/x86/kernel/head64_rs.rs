// SPDX-License-Identifier: GPL-2.0

//! Rust replacement for the logic of `arch/x86/kernel/head64.c`: the early page-fault handler
//! (`__early_make_pgtable`, `early_make_pgtable`, `do_early_exception`, `reset_early_page_tables`),
//! `clear_bss` and `x86_64_start_reservations`.
//!
//! WHAT STAYS C (`head64_glue.c`, upstream's file with exactly these functions removed): the variables
//! (`next_early_pgt`, `early_pmd_flags`, `__pgtable_l5_enabled`, `pgdir_shift`, `ptrs_per_p4d`,
//! `page_offset_base`, `vmalloc_base`, `vmemmap_base`, with their `EXPORT_SYMBOL`s and `SYM_PIC_ALIAS`es),
//! `early_setup_idt()` (not `__init`: the APs run it, and Rust code would be ftrace-patchable where the
//! C is built without `-pg`), `copy_bootdata()` (header inlines over `boot_params` and the SME/`sanitize_boot_params` stubs) and
//! `x86_64_start_kernel()` (the build-time `BUILD_BUG_ON`s, `cr4_init_shadow`, the `clear_page`
//! ALTERNATIVE, the per-CPU `cpu_tlbstate.cr4` read, the sme/kasan/tdx/ucode hooks: orchestration
//! over header inlines with no algorithm of its own). See logs/test-gaps.md.
//!
//! THIS RUNS BEFORE THE KERNEL HAS ANY FAULT HANDLING OF ITS OWN: `do_early_exception` is the early IDT's
//! handler (head_64.S `early_idt_handler_common`), `x86_64_start_kernel` calls the rest before the
//! panic machinery exists, and `clear_bss` runs before `.bss` is zero. So
//!   * there is no panic path: every `+ - << >>` that the C does on unsigned values with defined
//!     wrap-around is `wrapping_*`; indexing is by raw pointer, like the C (a `panic_const_*` here would
//!     be a call into code that cannot run yet; `rig/uaccess-panic-check.sh` checks the object);
//!   * no static of this file lives in `.bss` (there are none).
//!
//! Not `.pi.o`: this is ordinary kernel code on the kernel's virtual addresses (`-mcmodel=kernel`
//! equivalent), so symbol addresses are plain Rust references.
//!
//! Quirk kept bug for bug: with `USE_EARLY_PGTABLE_L5` the C reads `__pgtable_l5_enabled` (set by the
//! decompressor/`startup_64`), not the CPUID bit; `MAXMEM` is `1 << (l5 ? 52 : 46)`.
//!
//! TEST-GAP: an error here is a triple fault or a silent hang at the first early page fault. The boot
//! reaching userspace is the proof; the `reset_early_page_tables()` path inside `__early_make_pgtable`
//! (the 64 early page tables are used up) is not reached by any normal boot, and the AMD/TDX arms are
//! compile-checked and differential-tested against stubs only (logs/test-gaps.md).
//!
//! Replaces: arch/x86/kernel/head64.c (partly: see above)

use core::arch::asm;
use core::ffi::c_void;

#[cfg(CONFIG_PARAVIRT_XXL)]
compile_error!("head64_rs.rs reads/writes CR2/CR3 directly: CONFIG_PARAVIRT_XXL needs the pv ops");

// --- constants (checked against the kernel's headers by rig/phase-e/consts_check.py) -----------
// C-HEADERS: linux/types.h linux/pgtable.h asm/pgtable.h asm/page_types.h asm/pgtable_64_types.h asm/trapnr.h asm/bootparam.h asm/setup.h
const PMD_SHIFT: u32 = 21; // C: PMD_SHIFT
const PUD_SHIFT: u32 = 30; // C: PUD_SHIFT
const P4D_SHIFT: u32 = 39; // C: P4D_SHIFT
const PTRS_PER_PGD: usize = 512; // C: PTRS_PER_PGD
const PTRS_PER_PUD: usize = 512; // C: PTRS_PER_PUD
const PTRS_PER_PMD: usize = 512; // C: PTRS_PER_PMD
const PMD_MASK: u64 = !((1u64 << PMD_SHIFT) - 1); // C: PMD_MASK
const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_0000; // C: __START_KERNEL_map
const EARLY_DYNAMIC_PAGE_TABLES: u32 = 64; // C: EARLY_DYNAMIC_PAGE_TABLES
const KERNPG_TABLE_NOENC: u64 = 0x63; // C: _KERNPG_TABLE_NOENC
const PAGE_MASK: i64 = -4096; // C: (signed long)PAGE_MASK
const PHYSICAL_MASK_SHIFT: u32 = 52; // C: __PHYSICAL_MASK_SHIFT
const X86_TRAP_PF: i32 = 14; // C: X86_TRAP_PF
const X86_TRAP_VC: i32 = 29; // C: X86_TRAP_VC
const X86_TRAP_VE: i32 = 20; // C: X86_TRAP_VE
/// `PTE_PFN_MASK` as this file computes it (no DYNAMIC_PHYSICAL_MASK, no SME): checked against the header.
#[allow(dead_code)]
const PTE_PFN_MASK_CHECK: u64 = (PAGE_MASK as u64) & ((1u64 << PHYSICAL_MASK_SHIFT) - 1); // C: PTE_PFN_MASK
/// `CR3_ADDR_MASK` likewise.
#[allow(dead_code)]
const CR3_ADDR_MASK_CHECK: u64 = (PAGE_MASK as u64) & ((1u64 << PHYSICAL_MASK_SHIFT) - 1); // C: CR3_ADDR_MASK
const MAX_PHYSMEM_BITS_L4: u32 = 46; // C: 46
const MAX_PHYSMEM_BITS_L5: u32 = 52; // C: 52
/// `offsetof(struct boot_params, hdr.version)`.
const BP_HDR_VERSION: usize = 0x206; // C: offsetof(struct boot_params, hdr.version)
/// `offsetof(struct boot_params, hdr.hardware_subarch)`.
const BP_HDR_HARDWARE_SUBARCH: usize = 0x23c; // C: offsetof(struct boot_params, hdr.hardware_subarch)
/// `X86_SUBARCH_INTEL_MID`.
const X86_SUBARCH_INTEL_MID: u32 = 3; // C: X86_SUBARCH_INTEL_MID

extern "C" {
    static mut early_dynamic_pgts: u8;
    static mut early_top_pgt: u8;
    static mut next_early_pgt: u32;
    static early_pmd_flags: u64;
    static phys_base: u64;
    static __pgtable_l5_enabled: u32;
    static pgdir_shift: u32;
    static ptrs_per_p4d: u32;
    static page_offset_base: u64;
    #[cfg(CONFIG_DYNAMIC_PHYSICAL_MASK)]
    static physical_mask: u64;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    static sme_me_mask: u64;
    static mut boot_params: u8;
    static mut __bss_start: u8;
    static mut __bss_stop: u8;
    static mut __brk_base: u8;
    static mut __brk_limit: u8;

    fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
    fn early_fixup_exception(regs: *mut c_void, trapnr: i32);
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    fn handle_vc_boot_ghcb(regs: *mut c_void) -> bool;
    #[cfg(CONFIG_INTEL_TDX_GUEST)]
    fn tdx_early_handle_ve(regs: *mut c_void) -> bool;
    fn head64_copy_bootdata(real_mode_data: *mut u8);
    fn x86_early_init_platform_quirks();
    #[cfg(CONFIG_X86_INTEL_MID)]
    fn x86_intel_mid_early_setup();
    fn start_kernel() -> !;
}

// --- the machine, as a trait so the same algorithm runs in userspace against the real C ------------

/// What the early page-table code reads and writes outside the page tables themselves.
///
/// # Safety
/// The pointers are the kernel's own early page-table objects.
pub struct Env {
    /// `early_top_pgt` (512 entries, u64).
    pub early_top_pgt: *mut u64,
    /// `early_dynamic_pgts` (`EARLY_DYNAMIC_PAGE_TABLES` x 512 entries).
    pub early_dynamic_pgts: *mut u64,
    /// `next_early_pgt`.
    pub next_early_pgt: *mut u32,
    /// `early_pmd_flags`.
    pub early_pmd_flags: u64,
    /// `phys_base`.
    pub phys_base: u64,
    /// `__pgtable_l5_enabled != 0`.
    pub l5: bool,
    /// `pgdir_shift`.
    pub pgdir_shift: u32,
    /// `ptrs_per_p4d`.
    pub ptrs_per_p4d: u32,
    /// `page_offset_base` (`__PAGE_OFFSET`).
    pub page_offset: u64,
    /// `sme_me_mask` (0 when not built for AMD).
    pub me_mask: u64,
    /// `physical_mask` (`__PHYSICAL_MASK`).
    pub physical_mask: u64,
    /// CR3 as read (`read_cr3_pa()` is this & `CR3_ADDR_MASK`).
    pub cr3: u64,
}

impl Env {
    /// `PTE_PFN_MASK` = `(signed long)PAGE_MASK & __PHYSICAL_MASK`.
    #[inline(always)]
    fn pte_pfn_mask(&self) -> u64 {
        (PAGE_MASK as u64) & self.physical_mask
    }
    /// `read_cr3_pa()`: `CR3 & CR3_ADDR_MASK` where `CR3_ADDR_MASK = __sme_clr(PHYSICAL_PAGE_MASK)`.
    #[inline(always)]
    pub fn read_cr3_pa(&self) -> u64 {
        self.cr3 & self.pte_pfn_mask() & !self.me_mask
    }
    /// `__pa_nodebug(x)` = `__phys_addr_nodebug`: the carry-flag form of the C.
    #[inline(always)]
    pub fn pa_nodebug(&self, x: u64) -> u64 {
        let y = x.wrapping_sub(START_KERNEL_MAP);
        let add = if x > y { self.phys_base } else { START_KERNEL_MAP.wrapping_sub(self.page_offset) };
        y.wrapping_add(add)
    }
    /// `_KERNPG_TABLE` = `_KERNPG_TABLE_NOENC | _ENC`.
    #[inline(always)]
    fn kernpg_table(&self) -> u64 {
        KERNPG_TABLE_NOENC | self.me_mask
    }
    /// `PTRS_PER_P4D` (the variable).
    #[inline(always)]
    fn max_physmem_bits(&self) -> u32 {
        if self.l5 { MAX_PHYSMEM_BITS_L5 } else { MAX_PHYSMEM_BITS_L4 }
    }
}

/// Where the C calls `reset_early_page_tables()`: the Rust one is [`reset_tables`]; it writes `cr3`
/// through this hook so the userspace test can observe it.
pub trait Cr3 {
    /// `write_cr3(value)`.
    fn write_cr3(&mut self, v: u64);
}

/// `reset_early_page_tables()` over `Env`: wipe all early page tables except the kernel symbol map.
///
/// # Safety
/// `env` points at the kernel's early page tables.
#[inline(always)]
pub unsafe fn reset_tables<C: Cr3>(env: &Env, c: &mut C) {
    // SAFETY: early_top_pgt has PTRS_PER_PGD entries; the last (kernel map) is kept.
    unsafe {
        memset(env.early_top_pgt.cast(), 0, 8 * (PTRS_PER_PGD - 1));
        env.next_early_pgt.write(0);
    }
    c.write_cr3(env.pa_nodebug(env.early_top_pgt as usize as u64) | env.me_mask);
}

/// `__early_make_pgtable(address, pmd)`: create a new PMD entry.
///
/// # Safety
/// `env` points at the kernel's early page tables; `address` may be anything (a faulting address).
pub unsafe fn make_pgtable<C: Cr3>(env: &Env, c: &mut C, address: u64, pmd: u64) -> bool {
    let physaddr = address.wrapping_sub(env.page_offset);
    // Invalid address or early pgt is done?
    let maxmem: u64 = 1u64.wrapping_shl(env.max_physmem_bits());
    if physaddr >= maxmem || env.read_cr3_pa() != env.pa_nodebug(env.early_top_pgt as usize as u64) {
        return false;
    }
    let pfn_mask = env.pte_pfn_mask();
    let pgd_idx = (address.wrapping_shr(env.pgdir_shift) as usize) & (PTRS_PER_PGD - 1);
    // The three "allocate a page table" blocks of the C are the same shape.
    macro_rules! alloc_table {
        ($self_env:expr) => {{
            // SAFETY: next_early_pgt < EARLY_DYNAMIC_PAGE_TABLES was just checked.
            unsafe {
                let n = $self_env.next_early_pgt.read();
                $self_env.next_early_pgt.write(n.wrapping_add(1));
                $self_env.early_dynamic_pgts.add((n as usize).wrapping_mul(PTRS_PER_PMD))
            }
        }};
    }
    'again: loop {
        // SAFETY: pgd_idx < 512.
        let pgd_p = unsafe { env.early_top_pgt.add(pgd_idx) };
        // SAFETY: as above.
        let pgd = unsafe { pgd_p.read() };

        // The use of __START_KERNEL_map rather than __PAGE_OFFSET here is critical (the C comment).
        let mut p4d_p: *mut u64;
        if !env.l5 {
            p4d_p = pgd_p;
        } else if pgd != 0 {
            p4d_p = ((pgd & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base)) as usize as *mut u64;
        } else {
            // SAFETY: next_early_pgt is the kernel's counter.
            if unsafe { env.next_early_pgt.read() } >= EARLY_DYNAMIC_PAGE_TABLES {
                // SAFETY: as the function.
                unsafe { reset_tables(env, c) };
                continue 'again;
            }
            p4d_p = alloc_table!(env);
            // SAFETY: a fresh early page table of ptrs_per_p4d u64s inside early_dynamic_pgts.
            unsafe {
                memset(p4d_p.cast(), 0, 8usize.wrapping_mul(env.ptrs_per_p4d as usize));
                pgd_p.write((p4d_p as usize as u64).wrapping_sub(START_KERNEL_MAP).wrapping_add(env.phys_base).wrapping_add(env.kernpg_table()));
            }
        }
        let p4d_idx = (address.wrapping_shr(P4D_SHIFT) as usize) & (env.ptrs_per_p4d as usize).wrapping_sub(1);
        // SAFETY: the index is below ptrs_per_p4d.
        p4d_p = unsafe { p4d_p.add(p4d_idx) };
        // SAFETY: as above.
        let p4d = unsafe { p4d_p.read() };

        let mut pud_p: *mut u64;
        if p4d != 0 {
            pud_p = ((p4d & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base)) as usize as *mut u64;
        } else {
            // SAFETY: as above.
            if unsafe { env.next_early_pgt.read() } >= EARLY_DYNAMIC_PAGE_TABLES {
                // SAFETY: as the function.
                unsafe { reset_tables(env, c) };
                continue 'again;
            }
            pud_p = alloc_table!(env);
            // SAFETY: a fresh early page table of PTRS_PER_PUD u64s.
            unsafe {
                memset(pud_p.cast(), 0, 8 * PTRS_PER_PUD);
                p4d_p.write((pud_p as usize as u64).wrapping_sub(START_KERNEL_MAP).wrapping_add(env.phys_base).wrapping_add(env.kernpg_table()));
            }
        }
        // SAFETY: index below 512.
        pud_p = unsafe { pud_p.add((address.wrapping_shr(PUD_SHIFT) as usize) & (PTRS_PER_PUD - 1)) };
        // SAFETY: as above.
        let pud = unsafe { pud_p.read() };

        let pmd_p: *mut u64;
        if pud != 0 {
            pmd_p = ((pud & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base)) as usize as *mut u64;
        } else {
            // SAFETY: as above.
            if unsafe { env.next_early_pgt.read() } >= EARLY_DYNAMIC_PAGE_TABLES {
                // SAFETY: as the function.
                unsafe { reset_tables(env, c) };
                continue 'again;
            }
            let t = alloc_table!(env);
            // SAFETY: a fresh early page table of PTRS_PER_PMD u64s.
            unsafe {
                memset(t.cast(), 0, 8 * PTRS_PER_PMD);
                pud_p.write((t as usize as u64).wrapping_sub(START_KERNEL_MAP).wrapping_add(env.phys_base).wrapping_add(env.kernpg_table()));
            }
            pmd_p = t;
        }
        // SAFETY: index below 512.
        unsafe { pmd_p.add((address.wrapping_shr(PMD_SHIFT) as usize) & (PTRS_PER_PMD - 1)).write(pmd) };
        return true;
    }
}

/// `early_make_pgtable(address)`: the 2M identity of the direct map around `address`.
///
/// # Safety
/// As [`make_pgtable`].
pub unsafe fn early_make<C: Cr3>(env: &Env, c: &mut C, address: u64) -> bool {
    let physaddr = address.wrapping_sub(env.page_offset);
    let pmd = (physaddr & PMD_MASK).wrapping_add(env.early_pmd_flags);
    // SAFETY: as the function.
    unsafe { make_pgtable(env, c, address, pmd) }
}

/// Which of the hooks `do_early_exception` takes, for the userspace test.
pub trait Exc: Cr3 {
    /// `native_read_cr2()`.
    fn read_cr2(&mut self) -> u64;
    /// `handle_vc_boot_ghcb(regs)` (AMD arm).
    fn vc(&mut self, regs: *mut c_void) -> bool;
    /// `tdx_early_handle_ve(regs)`.
    fn ve(&mut self, regs: *mut c_void) -> bool;
    /// `early_fixup_exception(regs, trapnr)`.
    fn fixup(&mut self, regs: *mut c_void, trapnr: i32);
}

/// `do_early_exception()` over the hooks.
///
/// # Safety
/// As [`make_pgtable`].
pub unsafe fn early_exception<C: Exc>(env: &Env, c: &mut C, regs: *mut c_void, trapnr: i32, amd: bool, tdx: bool) {
    if trapnr == X86_TRAP_PF {
        let cr2 = c.read_cr2();
        // SAFETY: as the function.
        if unsafe { early_make(env, c, cr2) } {
            return;
        }
    }
    if amd && trapnr == X86_TRAP_VC && c.vc(regs) {
        return;
    }
    if tdx && trapnr == X86_TRAP_VE && c.ve(regs) {
        return;
    }
    c.fixup(regs, trapnr);
}

/// `x86_64_start_reservations()`'s decision: whether `copy_bootdata` runs, and the subarch switch.
/// Returns `(copy, intel_mid)`.
pub fn reservations_plan(hdr_version: u16, hardware_subarch: u32) -> (bool, bool) {
    (hdr_version == 0, hardware_subarch == X86_SUBARCH_INTEL_MID)
}

// --- the kernel-facing entry points ----------------------------------------------------------------

#[cfg(not(userspace_test))]
fn env() -> Env {
    Env {
        early_top_pgt: (&raw mut early_top_pgt).cast(),
        early_dynamic_pgts: (&raw mut early_dynamic_pgts).cast(),
        next_early_pgt: &raw mut next_early_pgt,
        // SAFETY: plain reads of kernel variables.
        early_pmd_flags: unsafe { early_pmd_flags },
        phys_base: unsafe { phys_base },
        l5: unsafe { __pgtable_l5_enabled } != 0,
        pgdir_shift: unsafe { pgdir_shift },
        ptrs_per_p4d: unsafe { ptrs_per_p4d },
        page_offset: unsafe { page_offset_base },
        #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
        me_mask: unsafe { sme_me_mask },
        #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
        me_mask: 0,
        #[cfg(CONFIG_DYNAMIC_PHYSICAL_MASK)]
        physical_mask: unsafe { physical_mask },
        #[cfg(not(CONFIG_DYNAMIC_PHYSICAL_MASK))]
        physical_mask: (1u64 << PHYSICAL_MASK_SHIFT) - 1,
        cr3: read_cr3(),
    }
}

#[cfg(not(userspace_test))]
#[inline(always)]
fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: ring 0.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// The real machine.
#[cfg(not(userspace_test))]
struct Hw;
#[cfg(not(userspace_test))]
impl Cr3 for Hw {
    #[inline(always)]
    fn write_cr3(&mut self, v: u64) {
        // SAFETY: `native_write_cr3()`: a memory clobber, the TLB is flushed.
        unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) };
    }
}
#[cfg(not(userspace_test))]
impl Exc for Hw {
    #[inline(always)]
    fn read_cr2(&mut self) -> u64 {
        let v: u64;
        // SAFETY: ring 0; `native_read_cr2()`.
        unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }
    #[inline(always)]
    fn vc(&mut self, _regs: *mut c_void) -> bool {
        #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
        // SAFETY: the C call.
        return unsafe { handle_vc_boot_ghcb(_regs) };
        #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
        false
    }
    #[inline(always)]
    fn ve(&mut self, _regs: *mut c_void) -> bool {
        #[cfg(CONFIG_INTEL_TDX_GUEST)]
        // SAFETY: the C call.
        return unsafe { tdx_early_handle_ve(_regs) };
        #[cfg(not(CONFIG_INTEL_TDX_GUEST))]
        false
    }
    #[inline(always)]
    fn fixup(&mut self, regs: *mut c_void, trapnr: i32) {
        // SAFETY: the C call.
        unsafe { early_fixup_exception(regs, trapnr) };
    }
}

/// `reset_early_page_tables()`: wipe all early page tables except for the kernel symbol map.
///
/// # Safety
/// Early boot, single CPU.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn reset_early_page_tables() {
    // SAFETY: as the function.
    unsafe { reset_tables(&env(), &mut Hw) };
}

/// `__early_make_pgtable()`: create a new PMD entry.
///
/// # Safety
/// Early boot, single CPU, early IDT.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn __early_make_pgtable(address: u64, pmd: u64) -> bool {
    // SAFETY: as the function.
    unsafe { make_pgtable(&env(), &mut Hw, address, pmd) }
}

/// `do_early_exception()`: called by `early_idt_handler_common` (head_64.S) with the saved registers.
///
/// # Safety
/// Early boot, single CPU, on the early IDT with `regs` the exception frame.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn do_early_exception(regs: *mut c_void, trapnr: i32) {
    // SAFETY: as the function.
    unsafe {
        early_exception(
            &env(),
            &mut Hw,
            regs,
            trapnr,
            cfg!(CONFIG_AMD_MEM_ENCRYPT),
            cfg!(CONFIG_INTEL_TDX_GUEST),
        )
    };
}

/// Don't add a printk in there. printk relies on the PDA which is not initialized yet.
///
/// # Safety
/// Early boot: `.bss` and the brk area are zeroed here.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn clear_bss() {
    let bss = &raw mut __bss_start;
    let bss_len = (&raw mut __bss_stop) as usize as u64;
    let brk = &raw mut __brk_base;
    let brk_len = (&raw mut __brk_limit) as usize as u64;
    // SAFETY: the linker-script ranges.
    unsafe {
        memset(bss.cast(), 0, bss_len.wrapping_sub(bss as usize as u64) as usize);
        memset(brk.cast(), 0, brk_len.wrapping_sub(brk as usize as u64) as usize);
    }
}

/// Called from `x86_64_start_kernel` (C) after the early setup.
///
/// # Safety
/// Early boot, single CPU; `real_mode_data` the physical address the boot stub passed.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn x86_64_start_reservations(real_mode_data: *mut u8) -> ! {
    // SAFETY: `boot_params` is a 4096-byte object; the offsets are checked by consts_check.py.
    let (version, subarch) = unsafe {
        let bp = &raw mut boot_params;
        (
            bp.add(BP_HDR_VERSION).cast::<u16>().read_unaligned(),
            bp.add(BP_HDR_HARDWARE_SUBARCH).cast::<u32>().read_unaligned(),
        )
    };
    let (copy, mid) = reservations_plan(version, subarch);
    // version is always not zero if it is copied
    if copy {
        // SAFETY: the C `copy_bootdata(__va(real_mode_data))` is done inside the C helper.
        unsafe { head64_copy_bootdata(real_mode_data) };
    }
    // SAFETY: the C calls, in the C's order.
    unsafe {
        x86_early_init_platform_quirks();
        if mid {
            #[cfg(CONFIG_X86_INTEL_MID)]
            x86_intel_mid_early_setup();
        }
        start_kernel()
    }
}
