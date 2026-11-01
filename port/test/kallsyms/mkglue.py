#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- kallsyms_glue.c = upstream kallsyms.c with the table walkers replaced by calls into kallsyms_rs.rs (see kernel/kallsyms_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def replace_fn(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
decl = '''/* The table walkers are in kallsyms_rs.rs; it gets the generated tables in this structure. */
struct rust_ksyms {
	const u8 *names;
	const unsigned int *markers;
	const char *token_table;
	const u16 *token_index;
	const int *offsets;
	const u8 *seqs;
	unsigned int num_syms;
	unsigned long relative_base;
};
unsigned int rust_ks_expand_symbol(const struct rust_ksyms *t, unsigned int off, char *result, size_t maxlen);
char rust_ks_symbol_type(const struct rust_ksyms *t, unsigned int off);
unsigned int rust_ks_symbol_offset(const struct rust_ksyms *t, unsigned long pos);
unsigned long rust_ks_sym_address(const struct rust_ksyms *t, int idx);
unsigned int rust_ks_symbol_seq(const struct rust_ksyms *t, int index);
int rust_ks_lookup_names(const struct rust_ksyms *t, const char *name, unsigned int *start, unsigned int *end);
unsigned long rust_ks_symbol_pos(const struct rust_ksyms *t, unsigned long addr, unsigned long *symbol_start, unsigned long *symbol_end);

static inline struct rust_ksyms ksyms(void)
{
	struct rust_ksyms k = {
		kallsyms_names, kallsyms_markers, kallsyms_token_table, kallsyms_token_index,
		kallsyms_offsets, kallsyms_seqs_of_names, kallsyms_num_syms, kallsyms_relative_base,
	};

	return k;
}

static_assert(KSYM_NAME_LEN == 512 && sizeof(kallsyms_offsets[0]) == 4 && sizeof(kallsyms_token_index[0]) == 2 && sizeof(kallsyms_markers[0]) == 4);

'''
replace_fn("static unsigned int kallsyms_expand_symbol(", decl + '''static unsigned int kallsyms_expand_symbol(unsigned int off,
					   char *result, size_t maxlen)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_expand_symbol(&k, off, result, maxlen);
}
''')
replace_fn("static char kallsyms_get_symbol_type(", '''static char kallsyms_get_symbol_type(unsigned int off)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_symbol_type(&k, off);
}
''')
replace_fn("static unsigned int get_symbol_offset(", '''static unsigned int get_symbol_offset(unsigned long pos)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_symbol_offset(&k, pos);
}
''')
replace_fn("unsigned long kallsyms_sym_address(", '''unsigned long kallsyms_sym_address(int idx)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_sym_address(&k, idx);
}
''')
replace_fn("static unsigned int get_symbol_seq(", '''static unsigned int get_symbol_seq(int index)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_symbol_seq(&k, index);
}
''')
replace_fn("static int kallsyms_lookup_names(", '''static int kallsyms_lookup_names(const char *name,
				 unsigned int *start,
				 unsigned int *end)
{
	struct rust_ksyms k = ksyms();

	return rust_ks_lookup_names(&k, name, start, end);
}
''')
replace_fn("static unsigned long get_symbol_pos(", '''static unsigned long get_symbol_pos(unsigned long addr,
				    unsigned long *symbolsize,
				    unsigned long *offset)
{
	struct rust_ksyms k = ksyms();
	unsigned long symbol_start = 0, symbol_end = 0;
	unsigned long low;

	low = rust_ks_symbol_pos(&k, addr, &symbol_start, &symbol_end);

	/* If we found no next symbol, we use the end of the section. */
	if (!symbol_end) {
		if (is_kernel_inittext(addr))
			symbol_end = (unsigned long)_einittext;
		else if (IS_ENABLED(CONFIG_KALLSYMS_ALL))
			symbol_end = (unsigned long)_end;
		else
			symbol_end = (unsigned long)_etext;
	}

	if (symbolsize)
		*symbolsize = symbol_end - symbol_start;
	if (offset)
		*offset = addr - symbol_start;

	return low;
}
''')
hdr = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (kernel/kallsyms.c, 6.18.49): the symbol expansion, the marker scan, the by-name and by-address binary searches are in kallsyms_rs.rs, which gets the generated\n * tables in a structure. This file keeps the exports and their callers, module / ftrace / bpf / kprobe symbols, the section-end fallback of get_symbol_pos(), the seq_file iterator and\n * sprint_symbol as upstream has them. Upstream's whole file is installed as kallsyms_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", hdr, 1)
open(sys.argv[2], "w").write(s)
