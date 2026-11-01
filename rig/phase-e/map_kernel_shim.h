/* Userspace stand-ins for what port/pristine/arch/x86/boot/startup/map_kernel.c needs from the kernel.
 * Every numeric macro here is checked against the kernel's own headers by rig/phase-e/consts_check.py
 * (same names compiled in the kernel tree) -- this file is not trusted. AMD=1 builds the
 * CONFIG_AMD_MEM_ENCRYPT arm (the SME mask is a variable and the callees are recording stubs). */
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t u64; typedef uint32_t u32;
typedef unsigned long pgdval_t, p4dval_t, pudval_t, pmdval_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pudval_t pud; } pud_t;
struct boot_params;
#define __init
#define PMD_SHIFT 21
#define PUD_SHIFT 30
#define P4D_SHIFT 39
#define PTRS_PER_PGD 512
#define PTRS_PER_PUD 512
#define PTRS_PER_PMD 512
#define MAX_PTRS_PER_P4D 512
#define PMD_SIZE (1UL << PMD_SHIFT)
#define PMD_MASK (~(PMD_SIZE - 1))
#define __START_KERNEL_map 0xffffffff80000000UL
#define FIXMAP_PMD_TOP 507
#define FIXMAP_PMD_NUM 2
#define EARLY_DYNAMIC_PAGE_TABLES 64
#define _PAGE_PRESENT 1UL
#define _PAGE_GLOBAL (1UL << 8)
#define X86_CR4_LA57 (1UL << 12)
#define __PAGE_KERNEL_LARGE_EXEC 0x1e3UL
#define _KERNPG_TABLE_NOENC 0x63UL
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
extern unsigned int pgdir_shift, ptrs_per_p4d, __pgtable_l5_enabled, next_early_pgt;
extern unsigned long phys_base;
extern unsigned long g_text, g_end, g_cr4; extern int g_cpu_la57;
#define PGDIR_SHIFT pgdir_shift
#define PTRS_PER_P4D ptrs_per_p4d
#define pgd_index(a) (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(a) (((a) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define MAX_PHYSMEM_BITS (g_cpu_la57 ? 52 : 46)
#define native_read_cr4() g_cr4
#define _text ((char *)g_text)
#define _end ((char *)g_end)
#define rip_rel_ptr(p) ((void *)(p))
extern pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
extern pgdval_t early_top_pgt[]; extern pgdval_t level4_kernel_pgt[];
extern pud_t level3_kernel_pgt[PTRS_PER_PUD]; extern pmd_t level2_fixmap_pgt[PTRS_PER_PMD];
extern pmd_t level2_kernel_pgt[PTRS_PER_PMD];
#if AMD
extern u64 sme_me_mask;
#define sme_get_me_mask() sme_me_mask
#define _ENC sme_me_mask
extern unsigned long g_bss_lo, g_bss_hi;
#define __start_bss_decrypted ((char *)g_bss_lo)
#define __end_bss_decrypted ((char *)g_bss_hi)
void sme_encrypt_kernel(struct boot_params *bp);
void early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr, unsigned long npages);
#else
#define sme_get_me_mask() 0ULL
#define _ENC 0ULL
#define sme_encrypt_kernel(bp) ((void)0)
extern char __start_bss_decrypted[], __end_bss_decrypted[];
static inline void early_snp_set_memory_shared(unsigned long v, unsigned long p, unsigned long n) {}
#endif
#define _PAGE_TABLE (0x67UL | _ENC)
