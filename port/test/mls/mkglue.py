#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- mls_glue.c: what is left of security/selinux/ss/mls.c once mls_rs.rs holds the code (mls_from_string, the NetLabel conversions, layout checks and rust_ml_* wrappers)."""
import sys
s = open(sys.argv[1]).read()
def cut(sig, nxt_sig):
    """remove from the start of sig's leading comment (if any) up to the start of nxt_sig's leading comment"""
    global s
    def start(sig):
        a = s.index(sig)
        # include a directly preceding block comment
        pre = s[:a].rstrip("\n")
        if pre.endswith("*/"):
            b = pre.rindex("/*")
            return b
        return a
    a = start(sig); b = start(nxt_sig)
    s = s[:a] + s[b:]
cut("int mls_compute_context_len(", "int mls_from_string(")
cut("int mls_range_set(", "#ifdef CONFIG_NETLABEL")
wr = r'''/* RUST-WRAPPERS BEGIN: what mls_rs.rs asks of the kernel. */
struct context *rust_ml_sidtab_search(struct sidtab *s, u32 sid);

struct context *rust_ml_sidtab_search(struct sidtab *s, u32 sid)
{
	return sidtab_search(s, sid);
}

/* mls_rs.rs hard-codes these layouts. */
static_assert(offsetof(struct policydb, mls_enabled) == 0 && offsetof(struct policydb, symtab) == 8 && sizeof(struct symtab) == 24 && offsetof(struct symtab, nprim) == 16 &&
	      SYM_USERS == 4 && SYM_LEVELS == 6 && SYM_CATS == 7 && SYM_CLASSES == 1 && offsetof(struct policydb, sym_val_to_name) == 200 &&
	      offsetof(struct policydb, class_val_to_struct) == 264 && offsetof(struct policydb, user_val_to_struct) == 280 && offsetof(struct policydb, process_class) == 598);
static_assert(offsetof(struct context, user) == 0 && offsetof(struct context, role) == 4 && offsetof(struct context, type) == 8 && offsetof(struct context, range) == 16 &&
	      sizeof(struct mls_level) == 24 && offsetof(struct mls_level, sens) == 0 && offsetof(struct mls_level, cat) == 8 && sizeof(struct mls_range) == 48);
static_assert(offsetof(struct ebitmap, node) == 0 && offsetof(struct ebitmap, highbit) == 8 && offsetof(struct ebitmap_node, next) == 0 && offsetof(struct ebitmap_node, maps) == 8 &&
	      offsetof(struct ebitmap_node, startbit) == 56 && EBITMAP_UNIT_NUMS == 6 && EBITMAP_SIZE == 384);
static_assert(offsetof(struct user_datum, range) == 24 && offsetof(struct user_datum, dfltlevel) == 72 && offsetof(struct level_datum, level) == 0 &&
	      offsetof(struct cat_datum, value) == 0 && offsetof(struct class_datum, default_range) == 67);
static_assert(OBJECT_R_VAL == 1 && SECSID_NULL == 0 && AVTAB_TRANSITION == 0x10 && AVTAB_MEMBER == 0x20 && AVTAB_CHANGE == 0x40 && DEFAULT_SOURCE_LOW == 1 && DEFAULT_SOURCE_HIGH == 2 &&
	      DEFAULT_SOURCE_LOW_HIGH == 3 && DEFAULT_TARGET_LOW == 4 && DEFAULT_TARGET_HIGH == 5 && DEFAULT_TARGET_LOW_HIGH == 6 && DEFAULT_GLBLUB == 7);
static_assert(sizeof(struct range_trans) == 12 && offsetof(struct range_trans, source_type) == 0 && offsetof(struct range_trans, target_type) == 4 && offsetof(struct range_trans, target_class) == 8);
/* RUST-WRAPPERS END */

'''
a = s.index("int mls_from_string(")
pre = s[:a].rstrip("\n"); 
if pre.endswith("*/"): a = pre.rindex("/*")
s = s[:a] + wr + s[a:]
note = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (security/selinux/ss/mls.c, 6.18.49): the context text, the validity checks, the parser, mls_range_set, mls_setup_user_range, mls_convert_context and\n * mls_compute_sid are in mls_rs.rs; this file keeps mls_from_string() and the NetLabel conversions. Upstream's whole file is installed as mls_norust.c for CONFIG_RUST=n.\n */\n"
assert s.startswith("// SPDX-License-Identifier: GPL-2.0\n")
s = note + s[len("// SPDX-License-Identifier: GPL-2.0\n"):]
open(sys.argv[2], "w").write(s)
