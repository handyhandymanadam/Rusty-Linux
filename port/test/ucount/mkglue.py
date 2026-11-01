#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- ucount_glue.c = upstream with the counter walks replaced by calls into ucount_rs.rs (see kernel/ucount_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def replace(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
replace("static inline bool atomic_long_inc_below(", "")
replace("struct ucounts *inc_ucount(", '''struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid,
			   enum ucount_type type)
{
	return rust_inc_ucount(ns, __kuid_val(uid), type);
}
''')
replace("void dec_ucount(", '''void dec_ucount(struct ucounts *ucounts, enum ucount_type type)
{
	rust_dec_ucount(ucounts, type);
}
''')
replace("long inc_rlimit_ucounts(", '''long inc_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	return rust_inc_rlimit_ucounts(ucounts, type, v);
}
''')
replace("bool dec_rlimit_ucounts(", '''bool dec_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	return rust_dec_rlimit_ucounts(ucounts, type, v);
}
''')
replace("static void do_dec_rlimit_put_ucounts(", "")
replace("void dec_rlimit_put_ucounts(", '''void dec_rlimit_put_ucounts(struct ucounts *ucounts, enum rlimit_type type)
{
	rust_dec_rlimit_put_ucounts(ucounts, type);
}
''')
replace("long inc_rlimit_get_ucounts(", '''long inc_rlimit_get_ucounts(struct ucounts *ucounts, enum rlimit_type type,
			    bool override_rlimit)
{
	return rust_inc_rlimit_get_ucounts(ucounts, type, override_rlimit);
}
''')
replace("bool is_rlimit_overlimit(", '''bool is_rlimit_overlimit(struct ucounts *ucounts, enum rlimit_type type, unsigned long rlimit)
{
	return rust_is_rlimit_overlimit(ucounts, type, rlimit);
}
''')
protos = '''
/* The counter walks are in ucount_rs.rs. */
struct ucounts *rust_inc_ucount(struct user_namespace *ns, u32 uid, int type);
void rust_dec_ucount(struct ucounts *ucounts, int type);
long rust_inc_rlimit_ucounts(struct ucounts *ucounts, int type, long v);
bool rust_dec_rlimit_ucounts(struct ucounts *ucounts, int type, long v);
void rust_dec_rlimit_put_ucounts(struct ucounts *ucounts, int type);
long rust_inc_rlimit_get_ucounts(struct ucounts *ucounts, int type, bool override_rlimit);
bool rust_is_rlimit_overlimit(struct ucounts *ucounts, int type, u64 rlimit);

extern const size_t rust_uc_off_ns, rust_uc_off_ucount, rust_uc_off_rlimit, rust_uc_off_ns_ucounts, rust_uc_off_ns_ucount_max, rust_uc_off_ns_rlimit_max;
const size_t rust_uc_off_ns = offsetof(struct ucounts, ns);
const size_t rust_uc_off_ucount = offsetof(struct ucounts, ucount);
const size_t rust_uc_off_rlimit = offsetof(struct ucounts, rlimit);
const size_t rust_uc_off_ns_ucounts = offsetof(struct user_namespace, ucounts);
const size_t rust_uc_off_ns_ucount_max = offsetof(struct user_namespace, ucount_max);
const size_t rust_uc_off_ns_rlimit_max = offsetof(struct user_namespace, rlimit_max);
static_assert(sizeof(atomic_long_t) == 8 && sizeof(((struct user_namespace *)0)->ucount_max[0]) == 8 && sizeof(((struct user_namespace *)0)->rlimit_max[0]) == 8);

struct ucounts *rust_uc_alloc(struct user_namespace *ns, u32 uid);
void rust_uc_put(struct ucounts *u);
struct ucounts *rust_uc_get(struct ucounts *u);
void rust_uc_warn_dec_ucount(void);
void rust_uc_warn_dec_rlimit(void);
void rust_uc_warn_do_dec(void);
void rust_uc_warn_unwind(void);
struct ucounts *rust_uc_alloc(struct user_namespace *ns, u32 uid) { return alloc_ucounts(ns, KUIDT_INIT(uid)); }
void rust_uc_put(struct ucounts *u) { put_ucounts(u); }
struct ucounts *rust_uc_get(struct ucounts *u) { return get_ucounts(u); }
/* one wrapper per WARN_ON_ONCE site: the once-flag is per site */
void rust_uc_warn_dec_ucount(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_dec_rlimit(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_do_dec(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_unwind(void) { WARN_ON_ONCE(1); }
'''
m = "static DEFINE_SPINLOCK(ucounts_lock);\n"
assert m in s
s = s.replace(m, m + protos, 1)
hdr = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (kernel/ucount.c, 6.18.49): the counter walks up the namespace chain (inc_ucount, dec_ucount, the rlimit counters, is_rlimit_overlimit) are in ucount_rs.rs.\n * This file keeps the hash table, its lock and RCU lookups (alloc_ucounts, put_ucounts), the sysctl tables and the initcall as upstream has them, the entry points as thunks, the\n * field offsets (struct ucounts and struct user_namespace depend on the configuration) and one WARN_ON_ONCE wrapper per site. Upstream's whole file is installed as\n * ucount_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", hdr, 1)
open(sys.argv[2], "w").write(s)
