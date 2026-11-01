/* Reference for the early page-fault group of arch/x86/kernel/head64.c: the REAL C (head64_gen.py extracts it from
 * port/pristine/), run over synthetic page-table objects. Build with -DAMD=0 or -DAMD=1. */
#include "head64_shim.h"
#include <stdio.h>
unsigned int next_early_pgt, __pgtable_l5_enabled, pgdir_shift = 39, ptrs_per_p4d = 1;
unsigned long early_pmd_flags, phys_base, page_offset_base, g_cr3;
#if AMD
unsigned long sme_me_mask;
#endif
pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD] __attribute__((aligned(4096)));
pgd_t early_top_pgt[PTRS_PER_PGD] __attribute__((aligned(4096)));

/* stub call log: every call the code under test makes outside the page tables */
#define LOGMAX 4096
unsigned long g_log[LOGMAX][3]; unsigned g_nlog;
unsigned long g_cr2; int g_vc_ret, g_ve_ret;
static void lg(unsigned long a, unsigned long b, unsigned long c) { if (g_nlog < LOGMAX) { g_log[g_nlog][0] = a; g_log[g_nlog][1] = b; g_log[g_nlog][2] = c; } g_nlog++; }
void sim_write_cr3(unsigned long v) { lg(1, v, 0); g_cr3 = v; }
unsigned long sim_read_cr2(void) { lg(2, 0, 0); return g_cr2; }
bool sim_vc(struct pt_regs *r) { lg(3, (unsigned long)r, 0); return g_vc_ret; }
bool sim_ve(struct pt_regs *r) { lg(4, (unsigned long)r, 0); return g_ve_ret; }
void sim_fixup(struct pt_regs *r, int t) { lg(5, (unsigned long)r, (unsigned long)t); }

#include HEADINC

bool c_make_pgtable(unsigned long a, unsigned long pmd) { return __early_make_pgtable(a, pmd); }
void c_reset(void) { reset_early_page_tables(); }
void c_exception(struct pt_regs *r, int t) { do_early_exception(r, t); }

/* ---- the harness interface (one state blob: tables + variables) ---- */
#define NVARS 8
static struct { void *p; size_t n; } R[] = {
	{ early_dynamic_pgts, sizeof early_dynamic_pgts }, { early_top_pgt, sizeof early_top_pgt },
	{ &next_early_pgt, 4 }, { &early_pmd_flags, 8 }, { &phys_base, 8 }, { &__pgtable_l5_enabled, 4 },
	{ &pgdir_shift, 4 }, { &ptrs_per_p4d, 4 }, { &page_offset_base, 8 }, { &g_cr3, 8 },
#if AMD
	{ &sme_me_mask, 8 },
#endif
};
#define NR (sizeof R / sizeof R[0])
void *region_ptr(int i) { return R[i].p; }
size_t region_off(int i) { size_t o = 0; for (int k = 0; k < i; k++) o += R[k].n; return o; }
size_t snap_size(void) { return region_off(NR); }
void snap(unsigned char *out) { for (size_t i = 0; i < NR; i++) { memcpy(out, R[i].p, R[i].n); out += R[i].n; } }
void restore(const unsigned char *in) { for (size_t i = 0; i < NR; i++) { memcpy(R[i].p, in, R[i].n); in += R[i].n; } }
int amd(void) { return AMD; }
void set_inputs(unsigned long cr2, int vc, int ve) { g_cr2 = cr2; g_vc_ret = vc; g_ve_ret = ve; }
void log_reset(void) { g_nlog = 0; }
size_t log_snap(unsigned long *out) { size_t k = 0; out[k++] = g_nlog; for (unsigned i = 0; i < g_nlog && i < LOGMAX; i++) { out[k++] = g_log[i][0]; out[k++] = g_log[i][1]; out[k++] = g_log[i][2]; } return k; }
unsigned long c_pa_nodebug(unsigned long x) { return __pa_nodebug(x); }
unsigned long c_read_cr3_pa(void) { return read_cr3_pa(); }
