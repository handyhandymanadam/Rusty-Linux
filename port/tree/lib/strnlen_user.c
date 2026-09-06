// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT MOVE (YET)
 *
 * do_strnlen_user()'s word-at-a-time algorithm is in lib/strnlen_user_rs.rs
 * (strnlen_user_body()). strnlen_user() -- the EXPORT_SYMBOL -- stays here:
 * it is not a pass-through, it holds the can_do_masked_user_access()
 * dispatch and the user_read_access_begin()/user_access_end() bracket, i.e.
 * the actual STAC/CLAC toggle (see logs/c-entry-rule.md, "A C ENTRY
 * FUNCTION THAT DOES WORK IS NOT OPTIONAL"). No kabi pin applies: the
 * export never leaves C, so its fingerprint never moves.
 *
 * rust_strnlen_uaccess_get_long() is a second, new retained thunk: one
 * unsafe_get_user() read plus its goto-efault fault recovery, called from
 * Rust once per word in place of the original's inlined
 * asm_goto_output()+hand-built exception-table entry, which Rust has no
 * stable way to construct itself. This is a real, measured divergence --
 * an out-of-line call replacing inlined asm on every word -- but it keeps
 * the STAC/CLAC bracket at its ORIGINAL granularity (once per
 * strnlen_user() call, not once per word). See logs/porting-hazards.md,
 * "raw uaccess", for the full account and the measurement.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/bitops.h>

/* lib/strnlen_user_rs.rs. */
long strnlen_user_body(const char __user *src, unsigned long count, unsigned long max);

/* Forward-declared for the same reason as sha1_blocks_dispatch()/
 * blake2s_compress_dispatch(): config-full's -Wmissing-prototypes is fatal
 * (-Werror) and this symbol's only caller is Rust, via FFI.
 */
bool notrace rust_strnlen_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val);

/*
 * Reads one unsigned long from user memory, assuming the caller is already
 * inside a user_read_access_begin()/user_access_end() (or masked_
 * equivalent) bracket -- exactly what unsafe_get_user() itself assumes, and
 * what strnlen_user_body()'s own Safety contract requires of ITS caller in
 * turn. Returns false, without touching *val, on a fault -- the same
 * information the original's efault goto carried, just handed back as a
 * value instead of a jump.
 *
 * notrace: adversarially found 2026-09-06. This runs inside the caller's
 * STAC-enabled bracket (AC set, SMAP disabled); without notrace, a
 * CONFIG_FUNCTION_TRACER=y kernel plants an __fentry__ call in this
 * function's own prologue that executes with AC still set, and
 * DYNAMIC_FTRACE means that call is live the moment anything attaches a
 * tracer or BPF probe here -- an ftrace/fentry trampoline then runs with
 * SMAP disabled. Free in both of this project's configs (neither sets
 * FUNCTION_TRACER), and closes the exposure permanently rather than only
 * while it happens to stay off. See logs/porting-hazards.md's "raw
 * uaccess" section for the rest of this hazard class.
 */
bool notrace rust_strnlen_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val)
{
	unsigned long tmp;

	unsafe_get_user(tmp, ptr, efault);
	*val = tmp;
	return true;
efault:
	return false;
}

/**
 * strnlen_user: - Get the size of a user string INCLUDING final NUL.
 * @str: The string to measure.
 * @count: Maximum count (including NUL character)
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * If the string is too long, returns a number larger than @count. User
 * has to check the return value against "> count".
 * On exception (or invalid count), returns 0.
 *
 * NOTE! You should basically never use this function. There is
 * almost never any valid case for using the length of a user space
 * string, since the string can be changed at any time by other
 * threads. Use "strncpy_from_user()" instead to get a stable copy
 * of the string.
 */
long strnlen_user(const char __user *str, long count)
{
	unsigned long max_addr, src_addr;

	if (unlikely(count <= 0))
		return 0;

	if (can_do_masked_user_access()) {
		long retval;

		str = masked_user_access_begin(str);
		retval = strnlen_user_body(str, count, count);
		user_read_access_end();
		return retval;
	}

	max_addr = TASK_SIZE_MAX;
	src_addr = (unsigned long)untagged_addr(str);
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		long retval;

		/*
		 * Truncate 'max' to the user-specified limit, so that
		 * we only have one limit we need to check in the loop
		 */
		if (max > count)
			max = count;

		if (user_read_access_begin(str, max)) {
			retval = strnlen_user_body(str, count, max);
			user_read_access_end();
			return retval;
		}
	}
	return 0;
}
EXPORT_SYMBOL(strnlen_user);
