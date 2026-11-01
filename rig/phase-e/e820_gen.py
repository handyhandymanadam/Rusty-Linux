#!/usr/bin/env python3
"""e820_gen.py <pristine e820.c> <e820_glue.c> <pristine lib/cmdline.c> <outdir>

Writes, UNEDITED apart from `#line` directives:
  ref.inc    the REAL C of the functions e820_rs.rs replaces, cut out of the pristine arch/x86/kernel/e820.c by
             line range (each range is preceded by `#line N "arch/x86/kernel/e820.c"`, so a BUG_ON reports the
             same file:line the kernel's does);
  glue.inc   the part of e820_glue.c the Rust links against in the kernel: the table definitions and exports, the
             BUG_ON wrappers e820__update_table / __e820__range_update / e820__range_update[_table], the
             MAX_ARCH_PFN macros and e820__end_of_ram_pfn / e820__end_of_low_ram_pfn;
  memparse.inc  memparse() cut out of the pristine lib/cmdline.c.
"""
import sys, re
pe, ge, cm, out = sys.argv[1:5]
P = open(pe).read().split('\n')
def seg(a, b):
    return f'#line {a} "arch/x86/kernel/e820.c"\n' + '\n'.join(P[a-1:b]) + '\n'
# (first line, last line) of the pristine ranges; each starts at a declaration and ends at a closing brace/blank
RANGES = [(59, 71), (73, 215), (278, 419), (421, 459), (461, 538), (540, 600), (602, 610), (616, 683),
          (816, 873), (881, 989), (1186, 1217)]
ref = ''.join(seg(a, b) for a, b in RANGES)
for must in ("__e820__mapped_all", "e820__update_table(", "__e820__range_update", "e820__range_remove", "e820_search_gap",
             "e820__end_of_low_ram_pfn", "parse_memmap_one", "e820__memory_setup_default"):
    assert must in ref, must
open(f'{out}/ref.inc', 'w').write(ref)

G = open(ge).read()
a = G.index('static struct e820_table e820_table_init')
b = G.index('#line 278 "arch/x86/kernel/e820.c"')
top = G[a:b]
def block(first, nxt):
    i = G.index(f'#line {first} "arch/x86/kernel/e820.c"'); j = G.index(f'#line {nxt} "arch/x86/kernel/e820.c"')
    return G[i:j]
glue = top + block(278, 611) + block(816, 875)
import os
for must in () if os.environ.get("E820_GEN_LAX") else ("BUG_ON(table->nr_entries > max_nr_entries)", "BUG_ON(old_type == new_type)", "e820_update_table_rs(",
             "e820_range_update_rs(", "e820_end_ram_pfn_rs(", "MAX_ARCH_PFN", "e820_table_max_entries"):
    assert must in glue, must
open(f'{out}/glue.inc', 'w').write(glue)

C = open(cm).read()
i = C.index('unsigned long long memparse(const char *ptr, char **retptr)')
j = C.index('EXPORT_SYMBOL(memparse);')
open(f'{out}/memparse.inc', 'w').write(C[i:j])
print(f'ref.inc {len(ref)} B ({len(RANGES)} ranges of the pristine e820.c), glue.inc {len(glue)} B, memparse.inc {j-i} B')
