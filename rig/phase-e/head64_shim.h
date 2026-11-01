/* Userspace stand-ins for what port/pristine/arch/x86/kernel/head64.c's early page-fault group needs from the
 * kernel. Every number is also a const in head64_rs.rs, checked against the kernel's headers by consts_check.py;
 * this file is not trusted: a wrong value here shows as a C != Rust mismatch. -DAMD=0|1 selects the arm. */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
typedef unsigned long pgdval_t, p4dval_t, pudval_t, pmdval_t, u64;
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pmdval_t pmd; } pmd_t;
struct pt_regs;
#define __init
#define PTRS_PER_PGD 512
#define PTRS_PER_PUD 512
#define PTRS_PER_PMD 512
#define PMD_SHIFT 21
#define PUD_SHIFT 30
#define P4D_SHIFT 39
#define PMD_MASK (~((1UL << PMD_SHIFT) - 1))
#define __START_KERNEL_map 0xffffffff80000000UL
#define EARLY_DYNAMIC_PAGE_TABLES 64
#define X86_TRAP_PF 14
#define X86_TRAP_VC 29
#define X86_TRAP_VE 20
#define CONFIG_AMD_MEM_ENCRYPT AMD
#define IS_ENABLED(x) (x)
extern unsigned int next_early_pgt, __pgtable_l5_enabled, pgdir_shift, ptrs_per_p4d;
extern unsigned long early_pmd_flags, phys_base, page_offset_base, sme_me_mask, g_cr3;
extern pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
extern pgd_t early_top_pgt[PTRS_PER_PGD];
#define pgtable_l5_enabled() (__pgtable_l5_enabled != 0)
#define __PAGE_OFFSET page_offset_base
#define MAX_PHYSMEM_BITS (pgtable_l5_enabled() ? 52 : 46)
#define MAXMEM (1UL << MAX_PHYSMEM_BITS)
#define PGDIR_SHIFT pgdir_shift
#define PTRS_PER_P4D ptrs_per_p4d
#define pgd_index(a) (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define p4d_index(a) (((a) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))
#define pud_index(a) (((a) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(a) (((a) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#if AMD
/* DYNAMIC_PHYSICAL_MASK: the SME bit is cleared from physical_mask */
#define __PHYSICAL_MASK (((1ULL << 52) - 1) & ~sme_me_mask)
#define _ENC sme_me_mask
#define __sme_clr(x) ((x) & ~sme_me_mask)
#else
#define __PHYSICAL_MASK ((1ULL << 52) - 1)
#define _ENC 0UL
#define sme_me_mask 0UL
#define __sme_clr(x) (x)
#endif
#define PHYSICAL_PAGE_MASK (((signed long)(~0xfffUL)) & __PHYSICAL_MASK)
#define PTE_PFN_MASK ((pmdval_t)PHYSICAL_PAGE_MASK)
#define CR3_ADDR_MASK __sme_clr(PHYSICAL_PAGE_MASK)
#define _KERNPG_TABLE (0x63UL | _ENC)
/* the kernel's __phys_addr_nodebug() (asm/page_64.h), verbatim */
static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - __PAGE_OFFSET));
	return x;
}
#define __pa_nodebug(x) __phys_addr_nodebug((unsigned long)(x))
#define __sme_pa_nodebug(x) (__pa_nodebug(x) | sme_me_mask)
#define read_cr3_pa() (g_cr3 & CR3_ADDR_MASK)
void sim_write_cr3(unsigned long v);
unsigned long sim_read_cr2(void);
bool sim_vc(struct pt_regs *r);
bool sim_ve(struct pt_regs *r);
void sim_fixup(struct pt_regs *r, int trapnr);
#define write_cr3(v) sim_write_cr3(v)
#define native_read_cr2() sim_read_cr2()
#define handle_vc_boot_ghcb(r) sim_vc(r)
#define tdx_early_handle_ve(r) sim_ve(r)
#define early_fixup_exception(r, t) sim_fixup(r, t)
