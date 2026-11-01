/* The glue TU: the part of the REAL e820_glue.c the Rust links against in the kernel (glue.inc, cut out by
 * e820_gen.py): table definitions, the BUG_ON wrappers, the MAX_ARCH_PFN wrappers. The Rust symbols it calls
 * (e820_update_table_rs, e820_range_update_rs, e820_end_ram_pfn_rs) come from e820_rs.rs in the same binary. */
#include "e820_shim.h"
struct change_member;
extern int e820_update_table_rs(struct e820_table *table, u32 max_nr_entries, struct change_member *cpl,
				struct change_member **cp, struct e820_entry **ol, struct e820_entry *ne);
extern u64 e820_range_update_rs(struct e820_table *table, u64 start, u64 size, enum e820_type old_type, enum e820_type new_type);
extern unsigned long e820_end_ram_pfn_rs(unsigned long limit_pfn, unsigned long max_arch_pfn);
#include GLUEINC

void *g_tbl(int which) { return which == 0 ? (void *)e820_table : which == 1 ? (void *)e820_table_kexec : (void *)e820_table_firmware; }
size_t g_tbl_size(void) { return sizeof(struct e820_table); }
unsigned g_emax(void) { return e820_table_max_entries; }
void g_set_pci_mem_start(unsigned long v) { pci_mem_start = v; }
void g_scratch_fill(unsigned seed) {
	unsigned char *p; size_t n; unsigned x = seed * 2654435761u + 7;
	for (int k = 0; k < 4; k++) {
		p = k == 0 ? (void *)change_point_list : k == 1 ? (void *)change_point : k == 2 ? (void *)overlap_list : (void *)new_entries;
		n = k == 0 ? sizeof change_point_list : k == 1 ? sizeof change_point : k == 2 ? sizeof overlap_list : sizeof new_entries;
		for (size_t i = 0; i < n; i++) { x = x * 1664525u + 1013904223u; p[i] = x >> 24; }
	}
}
int g_userdef(void) { return e820_userdef; }
void g_set_userdef(int v) { e820_userdef = v; }
/* the entry points the kernel's C callers use, as the glue defines them */
int g_update_table(int which) { return e820__update_table((struct e820_table *)g_tbl(which)); }
u64 g_range_update(u64 s, u64 z, u32 o, u32 n) { return e820__range_update(s, z, o, n); }
u64 g_range_update_table(int which, u64 s, u64 z, u32 o, u32 n) { return e820__range_update_table((struct e820_table *)g_tbl(which), s, z, o, n); }
unsigned long g_end_of_ram_pfn(void) { return e820__end_of_ram_pfn(); }
unsigned long g_end_of_low_ram_pfn(void) { return e820__end_of_low_ram_pfn(); }
int g_update_table_g(int which) { if (setjmp(g_bug_jmp)) return -999; return e820__update_table((struct e820_table *)g_tbl(which)); }
u64 g_range_update_g(u64 s, u64 z, u32 o, u32 n) { if (setjmp(g_bug_jmp)) return ~0ULL - 7; return e820__range_update(s, z, o, n); }
