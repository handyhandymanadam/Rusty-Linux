#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- kernel/sched/cputime.c as the glue: upstream with the arithmetic of the tick-based cputime_adjust() replaced by rust_cputime_adjust(). Without CONFIG_RUST the file includes
upstream's body, installed byte-identical as cputime_norust.c."""
import sys
s = open(sys.argv[1]).read()
head = s.index(" * Adjust tick based cputime random precision")
a = s.index("void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev,", head)
a = s.index("{", a)
b = s.index("\n}\n", a)
new_body = r'''{
	unsigned long flags;

	/* Serialize concurrent callers such that we can honour our guarantees */
	raw_spin_lock_irqsave(&prev->lock, flags);
	rust_cputime_adjust(curr->stime, curr->utime, curr->sum_exec_runtime, &prev->stime, &prev->utime);
	*ut = prev->utime;
	*st = prev->stime;
	raw_spin_unlock_irqrestore(&prev->lock, flags);'''
wr = r'''/* RUST-WRAPPERS BEGIN: the arithmetic of cputime_adjust() is in cputime_rs.rs. */
void rust_cputime_adjust(u64 curr_stime, u64 curr_utime, u64 rtime, u64 *prev_stime, u64 *prev_utime);
u64 rust_cp_mul_u64_u64_div_u64(u64 a, u64 b, u64 c);

u64 rust_cp_mul_u64_u64_div_u64(u64 a, u64 b, u64 c)
{
	return mul_u64_u64_div_u64(a, b, c);
}
/* RUST-WRAPPERS END */

'''
# the wrappers go just before the comment block that precedes cputime_adjust
c = s.rindex("/*\n * Adjust tick based cputime random precision", 0, a)
s = s[:c] + wr + s[c:a] + new_body + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (kernel/sched/cputime.c, 6.18.49): the arithmetic of the tick-based cputime_adjust() is in cputime_rs.rs; this file (included by build_policy.c) keeps the locking and\n * everything else. Without CONFIG_RUST upstream's whole file, installed byte-identical as cputime_norust.c, is used instead.\n */\n#ifndef CONFIG_RUST\n#include \"cputime_norust.c\"\n#else\n"
first = s.index("\n") + 1
s = note + s[first:] + "\n#endif /* CONFIG_RUST */\n"
open(sys.argv[2], "w").write(s)
