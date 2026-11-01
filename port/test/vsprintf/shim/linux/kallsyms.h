/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_KALLSYMS_H
#define _SHIM_LINUX_KALLSYMS_H
/* Real include/linux/kallsyms.h pulls in <linux/mm.h>, which is where
 * <linux/range.h> (struct range, range_string()'s own parameter type)
 * transitively comes from -- confirmed against build-full's own
 * lib/.vsprintf.o.cmd dependency list. Mirrored here rather than a direct
 * include from vsprintf.c itself, matching the real transitive path. */
#include <linux/range.h>

/* Real value: sizeof("%s+%#lx/%#lx [%s %s]") + (512-1) + 2*(64*3/10) +
 * (64-sizeof(long)-1) + (20*2) + 1 == 666, computed by hand against
 * include/linux/kallsyms.h and cross-checked in vsprintf_rs.rs's own
 * KSYM_SYMBOL_LEN comment. */
#define KSYM_SYMBOL_LEN 666

static inline void *dereference_symbol_descriptor(void *ptr)
{
	/* CONFIG_HAVE_FUNCTION_DESCRIPTORS: never selected under x86_64,
	 * checked directly -- identity here matches the real header. */
	return ptr;
}

/* Real kernel/kallsyms.c symbols. Stubbed here as deterministic,
 * DISTINCT-per-function formatters -- this harness cannot link real
 * kallsyms symbol-table resolution (no vmlinux, no symbol table in a
 * userspace binary), so `%pS`/`%ps`/`%pB` real name resolution is
 * structurally untestable here; what IS tested is that pointer()'s own
 * dispatch calls the RIGHT one of these five for each fmt suffix, and
 * that the surrounding buffer-copy logic (string_nocheck/widen_string)
 * matches -- both real, checkable properties. Same stubs are linked into
 * both the REF and RS arms, so a real Rust-side dispatch bug still shows
 * up as a mismatch.
 */
int sprint_symbol(char *buffer, unsigned long address);
int sprint_symbol_no_offset(char *buffer, unsigned long address);
int sprint_symbol_build_id(char *buffer, unsigned long address);
int sprint_backtrace(char *buffer, unsigned long address);
int sprint_backtrace_build_id(char *buffer, unsigned long address);

#endif
