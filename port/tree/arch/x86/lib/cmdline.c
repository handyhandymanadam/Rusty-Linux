// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Misc librarized functions for cmdline poking.
 *
 * RUST PORT (arch/x86/lib/cmdline.c, 6.18.49). The two scanners that do the
 * parsing, __cmdline_find_option_bool() and __cmdline_find_option(), are in
 * cmdline_rs.rs (as __cmdline_find_option_bool_rs / __cmdline_find_option_rs).
 * What stays here are the two public entry points: they pass COMMAND_LINE_SIZE
 * and retry on builtin_cmdline under IS_ENABLED(CONFIG_CMDLINE_BOOL), a Kconfig
 * test plus a variable and a macro (builtin_cmdline_added) that a Rust body
 * cannot express without mirroring them. Neither is EXPORT_SYMBOL'ed.
 * Upstream's file is installed as cmdline_norust.c for CONFIG_RUST=n.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>

#include <asm/setup.h>
#include <asm/cmdline.h>
#include <asm/bug.h>

/*
 * Find a boolean option (like quiet,noapic,nosmp....): returns the position of
 * that @option (starts counting with 1) or 0 on not found, as upstream's
 * __cmdline_find_option_bool(); see cmdline_rs.rs for the original comments.
 */
int __cmdline_find_option_bool_rs(const char *cmdline, int max_cmdline_size,
				  const char *option);

/*
 * Find a non-boolean option (i.e. option=argument): returns the length of the
 * argument, or -1 on not found, as upstream's __cmdline_find_option().
 */
int __cmdline_find_option_rs(const char *cmdline, int max_cmdline_size,
			     const char *option, char *buffer, int bufsize);

#define __cmdline_find_option_bool __cmdline_find_option_bool_rs
#define __cmdline_find_option __cmdline_find_option_rs

int cmdline_find_option_bool(const char *cmdline, const char *option)
{
	int ret;

	ret = __cmdline_find_option_bool(cmdline, COMMAND_LINE_SIZE, option);
	if (ret > 0)
		return ret;

	if (IS_ENABLED(CONFIG_CMDLINE_BOOL) && !builtin_cmdline_added)
		return __cmdline_find_option_bool(builtin_cmdline, COMMAND_LINE_SIZE, option);

	return ret;
}

int cmdline_find_option(const char *cmdline, const char *option, char *buffer,
			int bufsize)
{
	int ret;

	ret = __cmdline_find_option(cmdline, COMMAND_LINE_SIZE, option, buffer, bufsize);
	if (ret > 0)
		return ret;

	if (IS_ENABLED(CONFIG_CMDLINE_BOOL) && !builtin_cmdline_added)
		return __cmdline_find_option(builtin_cmdline, COMMAND_LINE_SIZE, option, buffer, bufsize);

	return ret;
}
