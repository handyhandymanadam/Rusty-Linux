/* Reference for arch/x86/boot/startup/map_kernel.c: the REAL C (map_kernel_gen.py extracts it from
 * port/pristine/), run over synthetic page-table objects. Build with -DAMD=0 or -DAMD=1. */
#include <string.h>
#include "map_kernel_shim.h"

unsigned int pgdir_shift = 39, ptrs_per_p4d = 1, __pgtable_l5_enabled, next_early_pgt;
unsigned long phys_base;
unsigned long g_text, g_end, g_cr4, g_bss_lo, g_bss_hi; int g_cpu_la57;
pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
/* 1024 entries: the C writes pgd[i + 1] with i up to 511 (one past the 512-entry table); the pad is compared too */
pgdval_t early_top_pgt[1024], level4_kernel_pgt[1024];
pud_t level3_kernel_pgt[PTRS_PER_PUD]; pmd_t level2_fixmap_pgt[PTRS_PER_PMD], level2_kernel_pgt[PTRS_PER_PMD];

#if AMD
u64 sme_me_mask;
#define LOGMAX 8192
unsigned long g_log[LOGMAX][3]; unsigned g_nlog; unsigned g_nenc; void *g_enc_bp;
void sme_encrypt_kernel(struct boot_params *bp) { g_nenc++; g_enc_bp = bp; }
void early_snp_set_memory_shared(unsigned long v, unsigned long p, unsigned long n)
{ if (g_nlog < LOGMAX) { g_log[g_nlog][0] = v; g_log[g_nlog][1] = p; g_log[g_nlog][2] = n; } g_nlog++; }
#endif

#include MKINC

/* ---- the harness interface ---- */
static struct { void *p; size_t n; } R[] = {
	{ early_dynamic_pgts, sizeof early_dynamic_pgts }, { early_top_pgt, sizeof early_top_pgt },
	{ level4_kernel_pgt, sizeof level4_kernel_pgt }, { level3_kernel_pgt, sizeof level3_kernel_pgt },
	{ level2_fixmap_pgt, sizeof level2_fixmap_pgt }, { level2_kernel_pgt, sizeof level2_kernel_pgt },
	{ &next_early_pgt, 4 }, { &phys_base, 8 }, { &__pgtable_l5_enabled, 4 }, { &pgdir_shift, 4 }, { &ptrs_per_p4d, 4 },
};
#define NR (sizeof R / sizeof R[0])
void *region_ptr(int i) { return R[i].p; }
size_t region_len(int i) { return R[i].n; }
size_t region_off(int i) { size_t o = 0; for (int k = 0; k < i; k++) o += R[k].n; return o; }
size_t snap_size(void) { return region_off(NR); }
void snap(unsigned char *out) { for (size_t i = 0; i < NR; i++) { memcpy(out, R[i].p, R[i].n); out += R[i].n; } }
void restore(const unsigned char *in) { for (size_t i = 0; i < NR; i++) { memcpy(R[i].p, in, R[i].n); in += R[i].n; } }
int amd(void) { return AMD; }
void log_reset(void) {
#if AMD
	g_nlog = 0; g_nenc = 0; g_enc_bp = 0;
#endif
}
/* log digest: n calls, enc calls, enc bp, and every logged call */
size_t log_snap(unsigned long *out) {
#if AMD
	size_t k = 0; out[k++] = g_nlog; out[k++] = g_nenc; out[k++] = (unsigned long)g_enc_bp;
	for (unsigned i = 0; i < g_nlog && i < LOGMAX; i++) { out[k++] = g_log[i][0]; out[k++] = g_log[i][1]; out[k++] = g_log[i][2]; }
	return k;
#else
	return 0;
#endif
}
void set_mask(unsigned long m) {
#if AMD
	sme_me_mask = m;
#endif
}
unsigned long c_run(unsigned long p2v, void *bp, unsigned long text, unsigned long end, unsigned long cr4, int la57cap,
		    unsigned long bss_lo, unsigned long bss_hi)
{
	g_text = text; g_end = end; g_cr4 = cr4; g_cpu_la57 = la57cap; g_bss_lo = bss_lo; g_bss_hi = bss_hi;
	return c_startup_64(p2v, (struct boot_params *)bp);
}
