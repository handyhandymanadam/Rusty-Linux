/* Reference for idt.c: the REAL C of the functions idt_rs.rs replaces (idt_gen.py cuts it out of port/pristine), compiled against idt_shim.h. */
#include "idt_shim.h"
unsigned long system_vectors[NR_VECTORS / 64];
struct lidt_rec g_lidt[16]; unsigned g_nlidt;
/* distinct entry points, so the gate addresses differ per vector */
void asm_exc_debug(void) {} void asm_exc_int3(void) {} void asm_exc_page_fault(void) {} void asm_exc_virtualization_exception(void) {}
const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE] = { { 0 } };
#include IDTINC
void *c_idt(void) { return idt_table; }
void *c_descr(void) { return &idt_descr; }
void c_from_table(const struct idt_data *t, int n, int sys) { idt_setup_from_table(idt_table, t, n, sys); }
void c_early_traps(void) { idt_setup_early_traps(); }
void c_early_pf(void) { idt_setup_early_pf(); }
void c_early_handler(void) { idt_setup_early_handler(); }
void *c_vectors(void) { return system_vectors; }
unsigned c_bug(void) { return g_bug; }
void c_lidt_reset(void) { g_nlidt = 0; memset(g_lidt, 0, sizeof g_lidt); }
unsigned c_lidt_n(void) { return g_nlidt; }
void *c_lidt(void) { return g_lidt; }
size_t c_early_idts_len(void) { return ARRAY_SIZE(early_idts); }
const void *c_early_idts(void) { return early_idts; }
const void *c_early_pf_idts(void) { return early_pf_idts; }
unsigned long c_gate_vec(uint64_t addr, uint32_t seg, uint16_t bits, uint64_t *hi) {  /* idt_init_desc on its own */
	struct idt_data d; gate_desc g; memset(&d, 0, sizeof d); d.addr = (void *)addr; d.segment = seg; memcpy(&d.bits, &bits, 2); memset(&g, 0, sizeof g);
	idt_init_desc(&g, &d); uint64_t w[2]; memcpy(w, &g, 16); *hi = w[1]; return w[0];
}
