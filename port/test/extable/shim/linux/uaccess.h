#pragma once
/* x86-64's struct exception_table_entry, ARCH_HAS_RELATIVE_EXTABLE and
 * swap_ex_entry_fixup, normally reached via asm/extable.h through the real
 * linux/uaccess.h. swap_ex_entry_fixup is the one that matters here: without
 * it, lib/extable.c's swap_ex() falls into its GENERIC #else arm, which does
 * not swap `data` -- the exact x86-specific behavior this port's swap_ex()
 * reproduces. Omitting it would make the pristine-C oracle exercise a
 * different arm than the one that actually compiles on this project's
 * target, which is a shim that compiles but does not match. */
struct exception_table_entry {
	int insn, fixup, data;
};
#define ARCH_HAS_RELATIVE_EXTABLE

#define swap_ex_entry_fixup(a, b, tmp, delta)			\
	do {							\
		(a)->fixup = (b)->fixup + (delta);		\
		(b)->fixup = (tmp).fixup - (delta);		\
		(a)->data = (b)->data;				\
		(b)->data = (tmp).data;				\
	} while (0)
