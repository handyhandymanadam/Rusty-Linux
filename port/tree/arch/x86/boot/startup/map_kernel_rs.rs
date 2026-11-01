// SPDX-License-Identifier: GPL-2.0

//! Rust replacement for `arch/x86/boot/startup/map_kernel.c`: `__startup_64()`, which fixes up the
//! kernel's own page tables for the load address and builds the identity mapping used for the
//! switch to the kernel's virtual addresses (`head_64.S:114`, `call __pi___startup_64`).
//!
//! THIS IS A `.pi.o` OBJECT (see `logs/phase-e-pi.md`): it runs on the identity mapping, so
//!   * every address of a kernel symbol is taken with `lea reg, [rip + sym]` in inline asm (the C's
//!     `rip_rel_ptr()`), never with a Rust path expression (a static's address would go through the
//!     GOT or an absolute relocation, both forbidden);
//!   * there is no panic path: arithmetic that the C does on unsigned/`int` values with defined
//!     wrap-around is written with `wrapping_*`, shifts by a run-time amount with `wrapping_shr`,
//!     indexing with raw pointers (like the C, nothing is bounds checked).
//!
//! Layout: `startup_64_tables()` is the whole algorithm over plain pointers and values (so a
//! userspace differential can run it against the pristine C on synthetic tables, `rig/phase-e/`);
//! `__startup_64()` only resolves the symbol addresses and reads CR4, CONFIG_AMD_MEM_ENCRYPT's
//! `sme_me_mask` and the `boot_cpu_data` LA57 bit. The two `for (;;);` of the C (address too
//! large / not 2M aligned) are `Err(Hang)` from the core and `loop {}` in the wrapper.
//!
//! Quirk kept bug for bug: `MAX_PHYSMEM_BITS` is `pgtable_l5_enabled() ? 52 : 46`, and here
//! `pgtable_l5_enabled()` is the `boot_cpu_data` capability bit LA57 (`cpu_feature_enabled()`), not
//! `__pgtable_l5_enabled`: at this point `boot_cpu_data` is still all zero, so the limit is 46.
//!
//! TEST-GAP: an error here is a triple fault or a hang with no message. The boot reaching userspace
//! on both x86 configs shows the 4-level path ran; the 5-level path runs only under
//! `rig/stubh/la57boot.sh`-style TCG `-cpu max`; the CONFIG_AMD_MEM_ENCRYPT arm (SME mask,
//! `bss_decrypted` PMD edits) is exercised in userspace against the C with stub callees, never on
//! AMD hardware.
//!
//! Replaces: arch/x86/boot/startup/map_kernel.c

use core::arch::{asm, global_asm};
use core::ffi::c_void;

// The C is built `-include hidden.h`: every symbol it defines or references is hidden, so after the
// final link none is global (`nm`: `t`/`d`, as in build-*-base). Rust has no per-file default
// visibility, so the assembler is told the same, for the definition and every kernel symbol referenced
// (logs/phase-e-pi.md row 6).
global_asm!(
    ".hidden __startup_64",
    ".hidden early_dynamic_pgts",
    ".hidden early_top_pgt",
    ".hidden level4_kernel_pgt",
    ".hidden level3_kernel_pgt",
    ".hidden level2_fixmap_pgt",
    ".hidden level2_kernel_pgt",
    ".hidden next_early_pgt",
    ".hidden phys_base",
    ".hidden __pgtable_l5_enabled",
    ".hidden pgdir_shift",
    ".hidden ptrs_per_p4d",
    ".hidden _text",
    ".hidden _end",
    ".hidden boot_cpu_data",
);
#[cfg(CONFIG_AMD_MEM_ENCRYPT)]
global_asm!(
    ".hidden sme_me_mask",
    ".hidden __start_bss_decrypted",
    ".hidden __end_bss_decrypted",
    ".hidden sme_encrypt_kernel",
    ".hidden early_snp_set_memory_shared",
);

// --- constants (checked against the kernel's headers by rig/phase-e/consts_check.py) ----------
// C-HEADERS: linux/pgtable.h asm/pgtable.h asm/fixmap.h asm/pgtable_64_types.h asm/cpufeatures.h asm/processor.h
const PMD_SHIFT: u32 = 21; // C: PMD_SHIFT
const PUD_SHIFT: u32 = 30; // C: PUD_SHIFT
const P4D_SHIFT: u32 = 39; // C: P4D_SHIFT
const PTRS_PER_PGD: usize = 512; // C: PTRS_PER_PGD
const PTRS_PER_PUD: usize = 512; // C: PTRS_PER_PUD
const PTRS_PER_PMD: usize = 512; // C: PTRS_PER_PMD
const MAX_PTRS_PER_P4D: usize = 512; // C: MAX_PTRS_PER_P4D
const PMD_SIZE: u64 = 1 << PMD_SHIFT; // C: PMD_SIZE
const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_0000; // C: __START_KERNEL_map
const FIXMAP_PMD_TOP: usize = 507; // C: FIXMAP_PMD_TOP
const FIXMAP_PMD_NUM: usize = 2; // C: FIXMAP_PMD_NUM
const PAGE_PRESENT: u64 = 1 << 0; // C: _PAGE_PRESENT
const PAGE_GLOBAL: u64 = 1 << 8; // C: _PAGE_GLOBAL
/// `_PAGE_TABLE_NOENC` (the C's `_PAGE_TABLE` is this | `_ENC`, i.e. `| sme_me_mask`).
const PAGE_TABLE_NOENC: u64 = 0x67; // C: _PAGE_TABLE_NOENC
const KERNPG_TABLE_NOENC: u64 = 0x63; // C: _KERNPG_TABLE_NOENC
const PAGE_KERNEL_LARGE_EXEC: u64 = 0x1e3; // C: __PAGE_KERNEL_LARGE_EXEC
/// `X86_CR4_LA57` (bit 12).
const CR4_LA57: u64 = 1 << 12; // C: X86_CR4_LA57
/// `X86_FEATURE_LA57` = word 16, bit 16: the byte of `x86_capability` and the mask tested.
const FEATURE_LA57_BYTE: usize = 16 * 4 + 2; // C: (X86_FEATURE_LA57 / 8)
const FEATURE_LA57_MASK: u8 = 1 << 0; // C: (1 << (X86_FEATURE_LA57 % 8))
/// `offsetof(struct cpuinfo_x86, x86_capability)`.
const CPUINFO_CAP_OFFSET: usize = 0x30; // C: offsetof(struct cpuinfo_x86, x86_capability)
/// Index into `boot_cpu_data` of the byte holding `X86_FEATURE_LA57` (the userspace test sets it).
pub const CAP_BYTE_INDEX: usize = CPUINFO_CAP_OFFSET + FEATURE_LA57_BYTE;
const MAX_PHYSMEM_BITS_L4: u32 = 46; // C: 46
const MAX_PHYSMEM_BITS_L5: u32 = 52; // C: 52

/// Why the C spins forever (`for (;;);`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hang {
    /// `physaddr >> MAX_PHYSMEM_BITS != 0`.
    AddressTooLarge,
    /// `load_delta & ~PMD_MASK != 0`.
    NotPmdAligned,
}

/// The kernel objects `__startup_64()` edits, as raw pointers (all `u64` page-table entries or the
/// `unsigned int` / `unsigned long` variables).
pub struct Tables {
    /// `early_dynamic_pgts`, `EARLY_DYNAMIC_PAGE_TABLES` x 512 entries.
    pub early_dynamic_pgts: *mut u64,
    /// `early_top_pgt` (512 entries).
    pub early_top_pgt: *mut u64,
    /// `level4_kernel_pgt` (512 entries).
    pub level4_kernel_pgt: *mut u64,
    /// `level3_kernel_pgt` (512 entries).
    pub level3_kernel_pgt: *mut u64,
    /// `level2_fixmap_pgt` (512 entries).
    pub level2_fixmap_pgt: *mut u64,
    /// `level2_kernel_pgt` (512 entries).
    pub level2_kernel_pgt: *mut u64,
    /// `next_early_pgt`.
    pub next_early_pgt: *mut u32,
    /// `phys_base`.
    pub phys_base: *mut u64,
    /// `__pgtable_l5_enabled`.
    pub pgtable_l5_enabled: *mut u32,
    /// `pgdir_shift`.
    pub pgdir_shift: *mut u32,
    /// `ptrs_per_p4d`.
    pub ptrs_per_p4d: *mut u32,
}

/// Values the C reads from the machine.
pub struct Machine {
    /// `rip_rel_ptr(_text)`.
    pub physaddr: u64,
    /// `rip_rel_ptr(_end)`.
    pub end: u64,
    /// `native_read_cr4()`.
    pub cr4: u64,
    /// `boot_cpu_has(X86_FEATURE_LA57)`: selects `MAX_PHYSMEM_BITS`.
    pub cpu_has_la57: bool,
    /// `sme_get_me_mask()` (0 without CONFIG_AMD_MEM_ENCRYPT).
    pub me_mask: u64,
    /// `rip_rel_ptr(__start_bss_decrypted)` / `rip_rel_ptr(__end_bss_decrypted)`: used only with
    /// CONFIG_AMD_MEM_ENCRYPT (0 otherwise).
    pub bss_decrypted: (u64, u64),
}

#[cfg(CONFIG_AMD_MEM_ENCRYPT)]
extern "C" {
    /// arch/x86/boot/startup/sme.c.
    fn sme_encrypt_kernel(bp: *mut c_void);
    /// arch/x86/boot/startup/sev-startup.c.
    fn early_snp_set_memory_shared(vaddr: u64, paddr: u64, npages: u64);
}

/// `sme_postprocess_startup()`. Without CONFIG_AMD_MEM_ENCRYPT, `sme_encrypt_kernel()` is an empty
/// inline and `sme_get_me_mask()` is 0, so this is `return 0`.
///
/// # Safety
/// `pmd` is `level2_kernel_pgt` (512 entries).
#[allow(unused_variables)]
unsafe fn sme_postprocess(bp: *mut c_void, pmd: *mut u64, p2v_offset: u64, m: &Machine) -> u64 {
    let me_mask = m.me_mask;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    // SAFETY: as documented; the callees are the startup-code C functions.
    unsafe {
        // Encrypt the kernel and related (if SME is active).
        sme_encrypt_kernel(bp);

        // Clear the memory encryption mask from the .bss..decrypted section.
        if me_mask != 0 {
            let (mut paddr, paddr_end) = m.bss_decrypted;

            while paddr < paddr_end {
                // On SNP, transition the page to shared in the RMP table so that it is consistent
                // with the page table attribute change.
                early_snp_set_memory_shared(paddr, paddr, PTRS_PER_PMD as u64);

                let e = pmd.add(pmd_index(paddr.wrapping_sub(p2v_offset)));
                e.write(e.read().wrapping_sub(me_mask));
                paddr = paddr.wrapping_add(PMD_SIZE);
            }
        }
    }
    // Return the SME encryption mask (if SME is active) to be used as a modifier for the initial
    // pgdir entry programmed into CR3.
    me_mask
}

/// The body of `__startup_64()`. Returns the SME mask (0 without AMD), or why the C would hang.
///
/// # Safety
/// `t` must point at the kernel's page-table objects, valid for the accesses below (the C does no
/// checks); `m.physaddr` / `m.end` are the (identity-mapped) addresses of `_text` / `_end`.
pub unsafe fn startup_64_tables(t: &Tables, m: &Machine, p2v_offset: u64, bp: *mut c_void) -> Result<u64, Hang> {
    // SAFETY: see the function's contract; every access below is the C's access.
    unsafe {
        let physaddr = m.physaddr;
        let me_mask = m.me_mask;

        // check_la57_support(): 5-level paging is detected and enabled at kernel decompression
        // stage. Only check if it has been enabled there.
        let la57 = m.cr4 & CR4_LA57 != 0;
        if la57 {
            t.pgtable_l5_enabled.write(1);
            t.pgdir_shift.write(48);
            t.ptrs_per_p4d.write(512);
        }

        // Is the address too large?
        let max_bits = if m.cpu_has_la57 { MAX_PHYSMEM_BITS_L5 } else { MAX_PHYSMEM_BITS_L4 };
        if physaddr.wrapping_shr(max_bits) != 0 {
            return Err(Hang::AddressTooLarge);
        }

        // Compute the delta between the address I am compiled to run at and the address I am
        // actually running at.
        let mut load_delta = START_KERNEL_MAP.wrapping_add(p2v_offset);
        t.phys_base.write(load_delta);

        // Is the address not 2M aligned?
        if load_delta & (PMD_SIZE - 1) != 0 {
            return Err(Hang::NotPmdAligned);
        }

        let va_text = physaddr.wrapping_sub(p2v_offset);
        let va_end = m.end.wrapping_sub(p2v_offset);

        // Include the SME encryption mask in the fixup value.
        load_delta = load_delta.wrapping_add(me_mask);

        // Fixup the physical addresses in the page table.
        let pgd = t.early_top_pgt;
        let pgd_kernel = pgd.add(pgd_index(START_KERNEL_MAP, t.pgdir_shift.read()));
        pgd_kernel.write(pgd_kernel.read().wrapping_add(load_delta));

        if la57 {
            let p4d = t.level4_kernel_pgt;
            let e = p4d.add(MAX_PTRS_PER_P4D - 1);
            e.write(e.read().wrapping_add(load_delta));

            // `_PAGE_TABLE` includes `_ENC` (= the SME mask).
            pgd_kernel.write((p4d as u64) | (PAGE_TABLE_NOENC | me_mask));
        }

        let l3 = t.level3_kernel_pgt;
        let e = l3.add(PTRS_PER_PUD - 2);
        e.write(e.read().wrapping_add(load_delta));
        let e = l3.add(PTRS_PER_PUD - 1);
        e.write(e.read().wrapping_add(load_delta));

        let mut i = FIXMAP_PMD_TOP;
        while i > FIXMAP_PMD_TOP - FIXMAP_PMD_NUM {
            let e = t.level2_fixmap_pgt.add(i);
            e.write(e.read().wrapping_add(load_delta));
            i = i.wrapping_sub(1);
        }

        // Set up the identity mapping for the switchover. These entries should *NOT* have the
        // global bit set! This also creates a bunch of nonsense entries but that is fine -- it
        // avoids problems around wraparound.
        let pud = t.early_dynamic_pgts;
        let pmd = t.early_dynamic_pgts.add(PTRS_PER_PMD);
        t.next_early_pgt.write(2);

        let pgtable_flags = KERNPG_TABLE_NOENC.wrapping_add(me_mask);

        if la57 {
            let n = t.next_early_pgt.read();
            t.next_early_pgt.write(n.wrapping_add(1));
            let p4d = t.early_dynamic_pgts.add((n as usize).wrapping_mul(PTRS_PER_PMD));

            let i = (physaddr.wrapping_shr(t.pgdir_shift.read()) % PTRS_PER_PGD as u64) as usize;
            pgd.add(i).write((p4d as u64).wrapping_add(pgtable_flags));
            pgd.add(i.wrapping_add(1)).write((p4d as u64).wrapping_add(pgtable_flags));

            // `i` is an `int` in the C (`physaddr >> P4D_SHIFT`, truncated); PTRS_PER_P4D is
            // `ptrs_per_p4d`, which was just set to 512 above.
            let i = (physaddr >> P4D_SHIFT) as u32;
            p4d.add((i as usize) % 512).write((pud as u64).wrapping_add(pgtable_flags));
            p4d.add((i.wrapping_add(1) as usize) % 512).write((pud as u64).wrapping_add(pgtable_flags));
        } else {
            let i = (physaddr.wrapping_shr(t.pgdir_shift.read()) % PTRS_PER_PGD as u64) as usize;
            pgd.add(i).write((pud as u64).wrapping_add(pgtable_flags));
            pgd.add(i.wrapping_add(1)).write((pud as u64).wrapping_add(pgtable_flags));
        }

        let i = (physaddr >> PUD_SHIFT) as u32;
        pud.add((i as usize) % PTRS_PER_PUD).write((pmd as u64).wrapping_add(pgtable_flags));
        pud.add((i.wrapping_add(1) as usize) % PTRS_PER_PUD).write((pmd as u64).wrapping_add(pgtable_flags));

        let mut pmd_entry = PAGE_KERNEL_LARGE_EXEC & !PAGE_GLOBAL;
        pmd_entry = pmd_entry.wrapping_add(me_mask);
        pmd_entry = pmd_entry.wrapping_add(physaddr);

        // DIV_ROUND_UP(va_end - va_text, PMD_SIZE)
        let count = va_end.wrapping_sub(va_text).wrapping_add(PMD_SIZE - 1) / PMD_SIZE;
        let mut i: u64 = 0;
        while i < count {
            // `int idx = i + (physaddr >> PMD_SHIFT);`
            let idx = (i as i32).wrapping_add((physaddr >> PMD_SHIFT) as i32);
            pmd.offset((idx % PTRS_PER_PMD as i32) as isize)
                .write(pmd_entry.wrapping_add(i.wrapping_mul(PMD_SIZE)));
            i = i.wrapping_add(1);
        }

        // Fixup the kernel text+data virtual addresses. Note that we might write invalid pmds,
        // when the kernel is relocated cleanup_highmap() fixes this up along with the mappings
        // beyond _end.
        //
        // Only the region occupied by the kernel image has so far been checked against the table
        // of usable memory regions provided by the firmware, so invalidate pages outside that
        // region.
        let pmd = t.level2_kernel_pgt;
        let first = pmd_index(va_text);
        let last = pmd_index(va_end);

        // invalidate pages before the kernel image
        let mut i = 0usize;
        while i < first {
            let e = pmd.add(i);
            e.write(e.read() & !PAGE_PRESENT);
            i = i.wrapping_add(1);
        }

        // fixup pages that are part of the kernel image
        while i <= last {
            let e = pmd.add(i);
            let v = e.read();
            if v & PAGE_PRESENT != 0 {
                e.write(v.wrapping_add(load_delta));
            }
            i = i.wrapping_add(1);
        }

        // invalidate pages after the kernel image
        while i < PTRS_PER_PMD {
            let e = pmd.add(i);
            e.write(e.read() & !PAGE_PRESENT);
            i = i.wrapping_add(1);
        }

        Ok(sme_postprocess(bp, pmd, p2v_offset, m))
    }
}

/// `pgd_index(a)` = `(a >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)`, `PGDIR_SHIFT` being the variable.
#[inline(always)]
fn pgd_index(a: u64, shift: u32) -> usize {
    (a.wrapping_shr(shift) as usize) & (PTRS_PER_PGD - 1)
}

/// `pmd_index(a)` = `(a >> PMD_SHIFT) & (PTRS_PER_PMD - 1)`.
#[inline(always)]
fn pmd_index(a: u64) -> usize {
    ((a >> PMD_SHIFT) as usize) & (PTRS_PER_PMD - 1)
}

// --- symbol addresses: `rip_rel_ptr()` ----------------------------------------------------------

extern "C" {
    static mut early_dynamic_pgts: u8;
    static mut early_top_pgt: u8;
    static mut level4_kernel_pgt: u8;
    static mut level3_kernel_pgt: u8;
    static mut level2_fixmap_pgt: u8;
    static mut level2_kernel_pgt: u8;
    static mut next_early_pgt: u8;
    static mut phys_base: u8;
    static mut __pgtable_l5_enabled: u8;
    static mut pgdir_shift: u8;
    static mut ptrs_per_p4d: u8;
    static mut _text: u8;
    static mut _end: u8;
    static mut boot_cpu_data: u8;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    static mut sme_me_mask: u8;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    static mut __start_bss_decrypted: u8;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    static mut __end_bss_decrypted: u8;
}

/// `rip_rel_ptr(sym)`: `lea reg, [rip + sym]`, i.e. the address of `sym` as seen from the code that
/// is running (identity mapping), not the one the linker assigned.
macro_rules! rip_rel_ptr {
    ($sym:ident) => {{
        let p: *mut u8;
        // SAFETY: only takes the address of a symbol.
        unsafe {
            asm!("lea {}, [rip + {}]", out(reg) p, sym $sym,
                 options(pure, nomem, nostack, preserves_flags));
        }
        p
    }};
}

/// `native_read_cr4()`.
#[cfg(not(userspace_test))]
#[inline(always)]
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: ring 0.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}
/// Userspace test stand-in: CR4 is a variable the harness sets.
#[cfg(userspace_test)]
fn read_cr4() -> u64 {
    extern "C" {
        static g_cr4: u64;
    }
    // SAFETY: the test defines it.
    unsafe { g_cr4 }
}

/// The caller's (head_64.S) entry: `unsigned long __startup_64(unsigned long p2v_offset,
/// struct boot_params *bp)`.
///
/// This code is compiled PIC because it executes from the early 1:1 mapping of memory, which
/// deviates from the mapping expected by the linker. Kernel virtual addresses can be determined by
/// subtracting `p2v_offset` from the RIP-relative address.
///
/// # Safety
/// Called once from `head_64.S` on the boot CPU, on the identity mapping.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn __startup_64(p2v_offset: u64, bp: *mut c_void) -> u64 {
    let t = Tables {
        early_dynamic_pgts: rip_rel_ptr!(early_dynamic_pgts).cast(),
        early_top_pgt: rip_rel_ptr!(early_top_pgt).cast(),
        level4_kernel_pgt: rip_rel_ptr!(level4_kernel_pgt).cast(),
        level3_kernel_pgt: rip_rel_ptr!(level3_kernel_pgt).cast(),
        level2_fixmap_pgt: rip_rel_ptr!(level2_fixmap_pgt).cast(),
        level2_kernel_pgt: rip_rel_ptr!(level2_kernel_pgt).cast(),
        next_early_pgt: rip_rel_ptr!(next_early_pgt).cast(),
        phys_base: rip_rel_ptr!(phys_base).cast(),
        pgtable_l5_enabled: rip_rel_ptr!(__pgtable_l5_enabled).cast(),
        pgdir_shift: rip_rel_ptr!(pgdir_shift).cast(),
        ptrs_per_p4d: rip_rel_ptr!(ptrs_per_p4d).cast(),
    };
    let cap = rip_rel_ptr!(boot_cpu_data);
    // SAFETY: `boot_cpu_data.x86_capability` is a byte array of NCAPINTS words.
    let cap_byte = unsafe { cap.add(CAP_BYTE_INDEX).read() };
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    // SAFETY: `sme_me_mask` is a u64.
    let me_mask = unsafe { rip_rel_ptr!(sme_me_mask).cast::<u64>().read() };
    #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
    let me_mask = 0;
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    let bss_decrypted = (
        rip_rel_ptr!(__start_bss_decrypted) as usize as u64,
        rip_rel_ptr!(__end_bss_decrypted) as usize as u64,
    );
    #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
    let bss_decrypted = (0, 0);
    let m = Machine {
        physaddr: rip_rel_ptr!(_text) as usize as u64,
        end: rip_rel_ptr!(_end) as usize as u64,
        cr4: read_cr4(),
        cpu_has_la57: cap_byte & FEATURE_LA57_MASK != 0,
        me_mask,
        bss_decrypted,
    };

    // SAFETY: the pointers are the kernel's own page-table objects.
    match unsafe { startup_64_tables(&t, &m, p2v_offset, bp) } {
        Ok(v) => v,
        // `for (;;);`
        Err(_) => loop {},
    }
}
