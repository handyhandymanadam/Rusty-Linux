/* Reference: the REAL C of the functions e820_rs.rs replaces (ref.inc, cut from the pristine e820.c by e820_gen.py).
 * Every global it defines is renamed c_<name> on the command line (-D), so it can sit beside the glue TU in one binary. */
#include "e820_shim.h"
#include REFINC

/* --- accessors for the harness --- */
void *c_tbl(int which) { return which == 0 ? (void *)e820_table : which == 1 ? (void *)e820_table_kexec : (void *)e820_table_firmware; }
size_t c_tbl_size(void) { return sizeof(struct e820_table); }
unsigned c_emax(void) { return E820_MAX_ENTRIES; }
unsigned long c_get_pci(void) { return pci_mem_start; }
void c_set_pci_mem_start(unsigned long v) { pci_mem_start = v; }
int c_userdef(void) { return userdef; }
void c_set_userdef(int v) { userdef = v; }
void c_scratch_fill(unsigned seed) {
	unsigned char *p; size_t n; unsigned x = seed * 2654435761u + 1;
	for (int k = 0; k < 4; k++) {
		p = k == 0 ? (void *)change_point_list : k == 1 ? (void *)change_point : k == 2 ? (void *)overlap_list : (void *)new_entries;
		n = k == 0 ? sizeof change_point_list : k == 1 ? sizeof change_point : k == 2 ? sizeof overlap_list : sizeof new_entries;
		for (size_t i = 0; i < n; i++) { x = x * 1664525u + 1013904223u; p[i] = x >> 24; }
	}
}
/* ops */
int c_update_table(int which) { return e820__update_table((struct e820_table *)c_tbl(which)); }
void c_range_add(u64 s, u64 z, u32 t) { e820__range_add(s, z, t); }
u64 c_range_update(u64 s, u64 z, u32 o, u32 n) { return e820__range_update(s, z, o, n); }
u64 c_range_update_table(int which, u64 s, u64 z, u32 o, u32 n) { return e820__range_update_table((struct e820_table *)c_tbl(which), s, z, o, n); }
u64 c_range_remove(u64 s, u64 z, u32 o, int chk) { return e820__range_remove(s, z, o, chk); }
int c_mapped_any(u64 s, u64 e, u32 t) { return e820__mapped_any(s, e, t); }
int c_mapped_raw_any(u64 s, u64 e, u32 t) { return e820__mapped_raw_any(s, e, t); }
int c_mapped_all(u64 s, u64 e, u32 t) { return e820__mapped_all(s, e, t); }
int c_get_entry_type(u64 s, u64 e) { return e820__get_entry_type(s, e); }
void c_print_table(char *who) { e820__print_table(who); }
void c_update_table_print(void) { e820__update_table_print(); }
void c_setup_pci_gap(void) { e820__setup_pci_gap(); }
unsigned long c_end_of_ram_pfn(void) { return e820__end_of_ram_pfn(); }
unsigned long c_end_of_low_ram_pfn(void) { return e820__end_of_low_ram_pfn(); }
const char *c_memory_setup_default(void) { return e820__memory_setup_default(); }
int c_parse_memopt(char *p) { return parse_memopt(p); }
int c_parse_memmap_opt(char *p) { return parse_memmap_opt(p); }
int c_update_table_g(int which) { if (setjmp(g_bug_jmp)) return -999; return e820__update_table((struct e820_table *)c_tbl(which)); }
u64 c_range_update_g(u64 s, u64 z, u32 o, u32 n) { if (setjmp(g_bug_jmp)) return ~0ULL - 7; return e820__range_update(s, z, o, n); }
