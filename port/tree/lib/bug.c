// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * report_bug()'s dispatch logic -- bug_addr()/bug_get_file_line()'s
 * relative-pointer arithmetic, find_bug()'s built-in-table search, the
 * warning/once/done flag bits, and clear_once_table() -- moved to
 * lib/bug_rs.rs, as report_bug_body(). Everything that stays here is
 * either the CONFIG_MODULES-entangled struct module / RCU-guarded list
 * machinery, or is itself the fragile piece of this file: the function
 * called DIRECTLY from the trap handler (arch/x86/kernel/traps.c,
 * arch/x86/mm/extable.c) for every ud2 bug/warning trap in the kernel --
 * this file is the callee those macros trap INTO, not a caller of them.
 *
 * report_bug() stays here UNCHANGED except for its call into Rust. Its
 * own logic is warn_rcu_enter()/warn_rcu_exit() -- real, substantial
 * per-CPU RCU-watching and preemption-count bookkeeping
 * (CONFIG_CONTEXT_TRACKING_IDLE=y on both this project's configs, so
 * this is the genuinely active body, not a no-op stub) -- the same
 * "keep the entry that does more than call the Rust" reasoning as
 * every retained-C bracket in this project (logs/c-entry-rule.md), and
 * doubly so here: a Rust bug reached from inside the SAME trap-handling
 * path this function reports on is a categorically worse failure than
 * anywhere else this project has ported, so this bracket is not a place
 * to take even the STAC/CLAC-style "genuinely expressible in Rust" risk.
 *
 * module_find_bug()/module_bug_finalize()/module_bug_cleanup() stay for
 * the same reason as lib/iomap.c's pci_iounmap(): real, RCU-guarded
 * `struct module` list traversal and raw ELF section-header parsing,
 * tied to a struct whose own transitive kabi-pin closure this project
 * has already measured as disproportionate to what porting one function
 * buys back (see logs/porting-hazards.md). None of it is EXPORT_SYMBOL'd
 * here anyway, so unlike buildid.c/iomap.c there is no kabi pin question
 * at all in this file -- lib/bug.c exports nothing to modules; every
 * caller (traps.c, extable.c, kprobes.c, panic.c) is itself built-in.
 *
 * generic_bug_clear_once() also stays -- its own logic IS the RCU-guarded
 * module list walk -- but its clear_once_table() calls now reach the
 * Rust version (calling a pure, non-blocking Rust function from inside
 * an RCU read-side critical section is fine; it is what "read-side" is
 * for).
 *
 * rust_bug_disable_trace_on_warning() is a one-line thunk:
 * disable_trace_on_warning() is `extern void ...(void);` (real,
 * out-of-line, kernel/trace/trace.c) only under CONFIG_TRACING
 * (config-full here); under config-fast it is a `static inline {}` in
 * the header, which is not a linkable symbol at all. The thunk gives
 * Rust one real symbol to call regardless of which this build has.
 *
 * is_valid_bugaddr() (arch/x86/kernel/traps.c) and __warn()
 * (kernel/panic.c) are both real, non-static, already-linkable
 * functions -- called directly via extern, not thunked, not
 * reimplemented. __warn() especially: it dumps registers, prints
 * modules, checks panic-on-warn, and marks the taint state -- real,
 * substantial infrastructure this port does not touch.
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/ftrace.h>
#include <linux/context_tracking.h>

extern struct bug_entry __start___bug_table[], __stop___bug_table[];

/* Same tiny relative-pointer computation as lib/bug_rs.rs's own
 * bug_addr() -- a deliberate, documented duplication (module_find_bug()
 * stays here in full, so it needs its own copy) rather than a call back
 * into Rust from an RCU read-side critical section for one add. */
static inline unsigned long bug_addr(const struct bug_entry *bug)
{
#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
	return (unsigned long)&bug->bug_addr_disp + bug->bug_addr_disp;
#else
	return bug->bug_addr;
#endif
}

#ifdef CONFIG_MODULES
/* Updates are protected by module mutex */
static LIST_HEAD(module_bug_list);

struct bug_entry *module_find_bug(unsigned long bugaddr);

struct bug_entry *module_find_bug(unsigned long bugaddr)
{
	struct bug_entry *bug;
	struct module *mod;

	guard(rcu)();
	list_for_each_entry_rcu(mod, &module_bug_list, bug_list) {
		unsigned i;

		bug = mod->bug_table;
		for (i = 0; i < mod->num_bugs; ++i, ++bug)
			if (bugaddr == bug_addr(bug))
				return bug;
	}
	return NULL;
}

void module_bug_finalize(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs,
			 struct module *mod)
{
	char *secstrings;
	unsigned int i;

	mod->bug_table = NULL;
	mod->num_bugs = 0;

	/* Find the __bug_table section, if present */
	secstrings = (char *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;
	for (i = 1; i < hdr->e_shnum; i++) {
		if (strcmp(secstrings+sechdrs[i].sh_name, "__bug_table"))
			continue;
		mod->bug_table = (void *) sechdrs[i].sh_addr;
		mod->num_bugs = sechdrs[i].sh_size / sizeof(struct bug_entry);
		break;
	}

	/*
	 * Strictly speaking this should have a spinlock to protect against
	 * traversals, but since we only traverse on a bug trap, a spinlock
	 * could potentially lead to deadlock and thus be counter-productive.
	 * Thus, this uses RCU to safely manipulate the bug list, since BUG
	 * must run in non-interruptive state.
	 */
	list_add_rcu(&mod->bug_list, &module_bug_list);
}

void module_bug_cleanup(struct module *mod)
{
	list_del_rcu(&mod->bug_list);
}

#else

struct bug_entry *module_find_bug(unsigned long bugaddr);

struct bug_entry *module_find_bug(unsigned long bugaddr)
{
	return NULL;
}
#endif

/* lib/bug_rs.rs. */
enum bug_trap_type report_bug_body(unsigned long bugaddr, struct pt_regs *regs);
void generic_bug_clear_once_body(struct bug_entry *start, struct bug_entry *end);

/* Forward-declared for the same reason as lib/strncpy_from_user.c's
 * rust_strncpy_uaccess_get_long(): config-full's -Wmissing-prototypes is
 * fatal (-Werror) and this symbol's only caller is Rust, via FFI.
 */
void rust_bug_disable_trace_on_warning(void);

void rust_bug_disable_trace_on_warning(void)
{
	disable_trace_on_warning();
}

enum bug_trap_type report_bug(unsigned long bugaddr, struct pt_regs *regs)
{
	enum bug_trap_type ret;
	bool rcu = false;

	rcu = warn_rcu_enter();
	ret = report_bug_body(bugaddr, regs);
	warn_rcu_exit(rcu);

	return ret;
}

void generic_bug_clear_once(void)
{
#ifdef CONFIG_MODULES
	struct module *mod;

	scoped_guard(rcu) {
		list_for_each_entry_rcu(mod, &module_bug_list, bug_list)
			generic_bug_clear_once_body(mod->bug_table,
						     mod->bug_table + mod->num_bugs);
	}
#endif

	generic_bug_clear_once_body(__start___bug_table, __stop___bug_table);
}
