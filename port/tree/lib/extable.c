// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT MOVE (YET)
 *
 * sort_extable(), search_extable() and their comparator/swap helpers are in
 * lib/extable_rs.rs. trim_init_extable() stays here: it is CONFIG_MODULES-only
 * and reaches into struct module's per-memory-type regions via the static
 * inline within_module_init(), which iterates mod->mem[type].{base,size} over
 * every "init" enum mod_mem_type -- real coupling to a large, evolving struct
 * for one trimming helper, and the kind of reach this project's own candidate
 * rule already excludes everywhere else. See lib/extable_rs.rs's module doc
 * comment for the rest of the account, including why ex_to_insn() is
 * duplicated here rather than exposed across the language boundary: it was
 * already file-local before this port, and staying that way costs nothing.
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/extable.h>

#ifndef ARCH_HAS_RELATIVE_EXTABLE
#define ex_to_insn(x)	((x)->insn)
#else
static inline unsigned long ex_to_insn(const struct exception_table_entry *x)
{
	return (unsigned long)&x->insn + x->insn;
}
#endif

#ifdef CONFIG_MODULES
/*
 * If the exception table is sorted, any referring to the module init
 * will be at the beginning or the end.
 */
void trim_init_extable(struct module *m)
{
	/*trim the beginning*/
	while (m->num_exentries &&
	       within_module_init(ex_to_insn(&m->extable[0]), m)) {
		m->extable++;
		m->num_exentries--;
	}
	/*trim the end*/
	while (m->num_exentries &&
	       within_module_init(ex_to_insn(&m->extable[m->num_exentries - 1]),
				  m))
		m->num_exentries--;
}
#endif /* CONFIG_MODULES */
