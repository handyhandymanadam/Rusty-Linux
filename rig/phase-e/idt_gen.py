#!/usr/bin/env python3
"""idt_gen.py <pristine idt.c> <out.inc>: the REAL C of the functions idt_rs.rs replaces, cut by markers out of the pristine
file with nothing edited: the G()/INTG()/SYSG() macros, early_idts[], idt_table + idt_descr, idt_setup_from_table(),
set_intr_gate(), idt_setup_early_traps(), early_pf_idts[] + idt_setup_early_pf() (inside the CONFIG_X86_64 block),
idt_setup_early_handler(). `#include` lines are dropped (the shim supplies the types)."""
import sys
src = open(sys.argv[1]).read().split('\n')
def idx(m, frm=0):
    for k in range(frm, len(src)):
        if m in src[k]: return k
    raise SystemExit('marker missing: ' + m)
def blk(a, b): return src[a:b + 1]
out = []
out += blk(idx('#define DPL0'), idx('static bool idt_setup_done') - 1)            # DPL, G, INTG, SYSG, ISTG, TSKG, IDT_TABLE_SIZE
k = idx('static const __initconst struct idt_data early_idts[]'); out += blk(k - 4, idx('};', k))
k = idx('static gate_desc idt_table'); out += blk(k, idx('static struct desc_ptr idt_descr') + 3)
k = idx('static __init void', idx('idt_is_f00f_address')); out += blk(k, idx('static __init void set_intr_gate') + 8)
k = idx('void __init idt_setup_early_traps'); out += blk(k, idx('}', k))
k = idx('static const __initconst struct idt_data early_pf_idts[]'); out += blk(k, idx('void __init idt_setup_early_pf', k) + 4)
k = idx('void __init idt_setup_early_handler'); out += blk(k, idx('}', k))
open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
