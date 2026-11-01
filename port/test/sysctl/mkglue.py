#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- sysctl_glue.c = upstream sysctl.c with the integer-handler text engine replaced by calls into sysctl_rs.rs (see kernel/sysctl_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def replace_fn(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
decl = '''/* The text engine of the integer handlers is in sysctl_rs.rs. */
void rust_sysctl_skip_spaces(char **buf, size_t *size);
void rust_sysctl_skip_char(char **buf, size_t *size, char v);
int rust_sysctl_get_long(char **buf, size_t *size, unsigned long *val, bool *neg, const char *perm_tr, unsigned int perm_tr_len, char *tr);
void rust_sysctl_put_long(void **buf, size_t *size, unsigned long val, bool neg);
void rust_sysctl_put_char(void **buf, size_t *size, char c);
int rust_sysctl_dointvec_conv(bool *negp, unsigned long *lvalp, int *valp, int write, void *data);
int rust_sysctl_douintvec_conv(unsigned long *lvalp, unsigned int *valp, int write, void *data);
int rust_sysctl_dointvec_minmax_conv(bool *negp, unsigned long *lvalp, int *valp, int write, void *data);
int rust_sysctl_douintvec_minmax_conv(unsigned long *lvalp, unsigned int *valp, int write, void *data);
int rust_sysctl_dointvec_jiffies_conv(bool *negp, unsigned long *lvalp, int *valp, int write, int hz);
int rust_sysctl_do_dointvec(void *tbl_data, int maxlen, const struct ctl_table *table, int write, void *buffer, size_t *lenp, loff_t *ppos,
			    int (*conv)(bool *negp, unsigned long *lvalp, int *valp, int write, void *data), void *data, size_t page_size);
int rust_sysctl_do_douintvec_w(unsigned int *tbl_data, const struct ctl_table *table, void *buffer, size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp, unsigned int *valp, int write, void *data), void *data, size_t page_size);
int rust_sysctl_do_douintvec_r(unsigned int *tbl_data, void *buffer, size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp, unsigned int *valp, int write, void *data), void *data);
int rust_sysctl_do_doulongvec(void *data, int maxlen, const struct ctl_table *table, unsigned long *table_min, unsigned long *table_max, int write, void *buffer,
			      size_t *lenp, loff_t *ppos, unsigned long convmul, unsigned long convdiv, size_t page_size);

bool rust_sysctl_isspace(int c);
bool rust_sysctl_first_pos(loff_t *ppos, const struct ctl_table *table);
bool rust_sysctl_isspace(int c) { return isspace(c); }
bool rust_sysctl_first_pos(loff_t *ppos, const struct ctl_table *table) { return proc_first_pos_non_zero_ignore(ppos, table); }

/* The layout the Rust uses for the range-check parameters. */
static_assert(sizeof(struct { int *min; int *max; }) == 2 * sizeof(void *));

'''
replace_fn("static void proc_skip_spaces(", decl)   # only the Rust loops skip spaces now: no C wrapper (it would be unused)
replace_fn("static void proc_skip_char(", '''static void proc_skip_char(char **buf, size_t *size, const char v)
{
	rust_sysctl_skip_char(buf, size, v);
}
''')
replace_fn("static int strtoul_lenient(", "")
replace_fn("static int proc_get_long(", '''static int proc_get_long(char **buf, size_t *size,
			  unsigned long *val, bool *neg,
			  const char *perm_tr, unsigned perm_tr_len, char *tr)
{
	return rust_sysctl_get_long(buf, size, val, neg, perm_tr, perm_tr_len, tr);
}
''')
replace_fn("static void proc_put_long(", '''static void proc_put_long(void **buf, size_t *size, unsigned long val, bool neg)
{
	rust_sysctl_put_long(buf, size, val, neg);
}
''')
replace_fn("static void proc_put_char(", '''static void proc_put_char(void **buf, size_t *size, char c)
{
	rust_sysctl_put_char(buf, size, c);
}
''')
replace_fn("static int do_proc_dointvec_conv(", '''static int do_proc_dointvec_conv(bool *negp, unsigned long *lvalp,
				 int *valp,
				 int write, void *data)
{
	return rust_sysctl_dointvec_conv(negp, lvalp, valp, write, data);
}
''')
replace_fn("static int do_proc_douintvec_conv(", '''static int do_proc_douintvec_conv(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data)
{
	return rust_sysctl_douintvec_conv(lvalp, valp, write, data);
}
''')
replace_fn("static int __do_proc_dointvec(", '''static int __do_proc_dointvec(void *tbl_data, const struct ctl_table *table,
		  int write, void *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	if (!conv)
		conv = do_proc_dointvec_conv;

	return rust_sysctl_do_dointvec(tbl_data, table->maxlen, table, write, buffer, lenp, ppos, conv, data, PAGE_SIZE);
}
''')
replace_fn("static int do_proc_douintvec_w(", '''static int do_proc_douintvec_w(unsigned int *tbl_data,
			       const struct ctl_table *table,
			       void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	return rust_sysctl_do_douintvec_w(tbl_data, table, buffer, lenp, ppos, conv, data, PAGE_SIZE);
}
''')
replace_fn("static int do_proc_douintvec_r(", '''static int do_proc_douintvec_r(unsigned int *tbl_data, void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	return rust_sysctl_do_douintvec_r(tbl_data, buffer, lenp, ppos, conv, data);
}
''')
replace_fn("static int do_proc_dointvec_minmax_conv(", '''static int do_proc_dointvec_minmax_conv(bool *negp, unsigned long *lvalp,
					int *valp,
					int write, void *data)
{
	return rust_sysctl_dointvec_minmax_conv(negp, lvalp, valp, write, data);
}
''')
replace_fn("static int do_proc_douintvec_minmax_conv(", '''static int do_proc_douintvec_minmax_conv(unsigned long *lvalp,
					 unsigned int *valp,
					 int write, void *data)
{
	return rust_sysctl_douintvec_minmax_conv(lvalp, valp, write, data);
}
''')
replace_fn("static int __do_proc_doulongvec_minmax(", '''static int __do_proc_doulongvec_minmax(void *data,
		const struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos,
		unsigned long convmul, unsigned long convdiv)
{
	return rust_sysctl_do_doulongvec(data, table->maxlen, table, table->extra1, table->extra2, write, buffer, lenp, ppos, convmul, convdiv, PAGE_SIZE);
}
''')
replace_fn("static int do_proc_dointvec_jiffies_conv(", '''static int do_proc_dointvec_jiffies_conv(bool *negp, unsigned long *lvalp,
					 int *valp,
					 int write, void *data)
{
	return rust_sysctl_dointvec_jiffies_conv(negp, lvalp, valp, write, HZ);
}
''')
hdr = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/sysctl.c, 6.18.49): the integer-handler text engine (buffer primitives, the dointvec / douintvec / doulongvec loops and the plain, min/max and jiffies\n * conversion callbacks) is in sysctl_rs.rs. This file keeps every exported handler, the ctl_table plumbing, strings, bitmaps, the ms / USER_HZ handlers and the registration\n * tree as upstream has them, with static entry points that call the Rust. Upstream's whole file is installed as sysctl_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", hdr, 1)
open(sys.argv[2], "w").write(s)
