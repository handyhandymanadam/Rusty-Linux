#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- auditfilter_glue.c = upstream auditfilter.c with the comparators, audit_to_op, audit_field_valid, parent_len and audit_compare_dname_path replaced by calls
into auditfilter_rs.rs (see kernel/auditfilter_rs.rs). The constants of the Rust file are checked against the headers by static_asserts generated from the Rust file itself."""
import os, re, sys
here = os.path.dirname(os.path.abspath(__file__))
rs = open(os.path.join(here, "..", "..", "tree", "kernel", "auditfilter_rs.rs")).read()
s = open(sys.argv[1]).read()
def replace_fn(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
enum = {"AUDIT_EQUAL_": "Audit_equal", "AUDIT_NOT_EQUAL_": "Audit_not_equal", "AUDIT_BITMASK_": "Audit_bitmask", "AUDIT_BITTEST_": "Audit_bittest", "AUDIT_LT_": "Audit_lt", "AUDIT_GT_": "Audit_gt",
        "AUDIT_LE_": "Audit_le", "AUDIT_GE_": "Audit_ge", "AUDIT_BAD_": "Audit_bad"}
asserts = []
for name, val in re.findall(r"^const (\w+): (?:u32|c_int) = (-?[0-9a-fx]+(?:o[0-7]+)?);", rs, re.M):
    if name in enum: c = enum[name]
    elif name.startswith("FILTER_"): c = "AUDIT_" + name
    elif name in ("S_IFMT", "AF_MAX", "AUDIT_NAME_FULL", "EINVAL"): c = name
    else: c = "AUDIT_" + name
    asserts.append("static_assert(%s == %s);" % (c, val.replace("0o", "0") if val.startswith("0o") else val))
decl = '''/* The pure checks are in auditfilter_rs.rs. */
int rust_audit_comparator(u32 left, u32 op, u32 right);
int rust_audit_id_comparator(u32 left, u32 op, u32 right);
u32 rust_audit_to_op(u32 op, const u32 *ops);
int rust_audit_field_valid(u32 listnr, u32 ftype, u32 op, u32 val);
int rust_audit_parent_len(const char *path);
int rust_audit_compare_dname_path(int dlen, const unsigned char *dname, const char *path, int parentlen);

/* The constants the Rust uses are checked against the headers. */
''' + "\n".join(asserts) + "\n\n"
replace_fn("static u32 audit_to_op(", decl + '''static u32 audit_to_op(u32 op)
{
	return rust_audit_to_op(op, audit_ops);
}
''')
replace_fn("static int audit_field_valid(", '''static int audit_field_valid(struct audit_entry *entry, struct audit_field *f)
{
	return rust_audit_field_valid(entry->rule.listnr, f->type, f->op, f->val);
}
''')
replace_fn("int audit_comparator(", '''int audit_comparator(u32 left, u32 op, u32 right)
{
	return rust_audit_comparator(left, op, right);
}
''')
replace_fn("int audit_uid_comparator(", '''int audit_uid_comparator(kuid_t left, u32 op, kuid_t right)
{
	return rust_audit_id_comparator(__kuid_val(left), op, __kuid_val(right));
}
''')
replace_fn("int audit_gid_comparator(", '''int audit_gid_comparator(kgid_t left, u32 op, kgid_t right)
{
	return rust_audit_id_comparator(__kgid_val(left), op, __kgid_val(right));
}
''')
replace_fn("int parent_len(", '''int parent_len(const char *path)
{
	return rust_audit_parent_len(path);
}
''')
replace_fn("int audit_compare_dname_path(", '''int audit_compare_dname_path(const struct qstr *dname, const char *path, int parentlen)
{
	return rust_audit_compare_dname_path(dname->len, dname->name, path, parentlen);
}
''')
hdr = "// SPDX-License-Identifier: GPL-2.0-or-later\n/*\n * RUST PORT (kernel/auditfilter.c, 6.18.49): the comparators, audit_to_op, audit_field_valid, parent_len and audit_compare_dname_path are in auditfilter_rs.rs. This file keeps\n * everything with rule structures, lists, locks, user-space strings and the LSM as upstream has it, with the entry points as thunks that hand over the numbers. Upstream's whole file is\n * installed as auditfilter_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-or-later\n", hdr, 1)
open(sys.argv[2], "w").write(s)
