#!/usr/bin/env python3
"""notifier_mkglue.py PRISTINE.c OUT.c -- notifier_glue.c = upstream minus the chain core (see kernel/notifier_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int notifier_chain_register(")
b = s.index("int atomic_notifier_chain_register(")
# keep the doc comment that precedes the first exported function: it starts at the last "/**" before b
c = s.rindex("/**", a, b)
repl = '''/* The chain core is in notifier_rs.rs; these keep the names the rest of the file uses. */
int rust_nt_register(struct notifier_block **nl, struct notifier_block *n, bool unique_priority);
int rust_nt_unregister(struct notifier_block **nl, struct notifier_block *n);
int rust_nt_call_chain(struct notifier_block **nl, unsigned long val, void *v, int nr_to_call, int *nr_calls);
int rust_nt_call_chain_robust(struct notifier_block **nl, unsigned long val_up, unsigned long val_down, void *v);
void rust_nt_warn_dup(struct notifier_block *n);
void rust_nt_trace_register(struct notifier_block *n);
void rust_nt_trace_unregister(struct notifier_block *n);
int rust_nt_call(struct notifier_block *nb, unsigned long val, void *v);
bool rust_nt_callback_ok(struct notifier_block *nb);

void rust_nt_warn_dup(struct notifier_block *n)
{
	WARN(1, "notifier callback %ps already registered", n->notifier_call);
}

void rust_nt_trace_register(struct notifier_block *n)
{
	trace_notifier_register((void *)n->notifier_call);
}

void rust_nt_trace_unregister(struct notifier_block *n)
{
	trace_notifier_unregister((void *)n->notifier_call);
}

int rust_nt_call(struct notifier_block *nb, unsigned long val, void *v)
{
	trace_notifier_run((void *)nb->notifier_call);
	return nb->notifier_call(nb, val, v);
}

bool rust_nt_callback_ok(struct notifier_block *nb)
{
#ifdef CONFIG_DEBUG_NOTIFIERS
	if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
		WARN(1, "Invalid notifier called!");
		return false;
	}
#endif
	return true;
}
/* upstream: NOKPROBE_SYMBOL(notifier_call_chain) */
NOKPROBE_SYMBOL(rust_nt_call_chain);
NOKPROBE_SYMBOL(rust_nt_call);
NOKPROBE_SYMBOL(rust_nt_callback_ok);

static inline int notifier_chain_register(struct notifier_block **nl, struct notifier_block *n, bool unique_priority)
{
	return rust_nt_register(nl, n, unique_priority);
}

static inline int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n)
{
	return rust_nt_unregister(nl, n);
}

static inline int notifier_call_chain(struct notifier_block **nl, unsigned long val, void *v, int nr_to_call, int *nr_calls)
{
	return rust_nt_call_chain(nl, val, v, nr_to_call, nr_calls);
}

static inline int notifier_call_chain_robust(struct notifier_block **nl, unsigned long val_up, unsigned long val_down, void *v)
{
	return rust_nt_call_chain_robust(nl, val_up, val_down, v);
}

'''
out = s[:a] + repl + s[c:]
hdr = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (kernel/notifier.c, 6.18.49): notifier_chain_register/unregister, notifier_call_chain and notifier_call_chain_robust are in notifier_rs.rs. This file keeps\n * everything else as upstream has it (the four chain flavours with their locks, the die chain, the exports) plus the callback invocation, the tracepoints, the WARNs\n * and the DEBUG_NOTIFIERS check as rust_nt_* wrappers. Upstream's whole file is installed as notifier_norust.c for CONFIG_RUST=n.\n */\n"
out = out.replace("// SPDX-License-Identifier: GPL-2.0-only\n", hdr, 1)
open(sys.argv[2], "w").write(out)
