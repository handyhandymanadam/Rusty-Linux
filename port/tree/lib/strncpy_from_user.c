// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT MOVE (YET)
 *
 * do_strncpy_from_user()'s word-at-a-time algorithm is in
 * lib/strncpy_from_user_rs.rs (strncpy_from_user_body()). strncpy_from_user()
 * -- the EXPORT_SYMBOL -- stays here for the same reason as
 * lib/strnlen_user.c's own entry: it holds the can_do_masked_user_access()
 * dispatch and the user_read_access_begin()/user_access_end() bracket (the
 * STAC/CLAC toggle), plus might_fault()/should_fail_usercopy()/
 * kasan_check_write()/check_object_size(). See logs/c-entry-rule.md. No
 * kabi pin applies: the export never leaves C.
 *
 * rust_strncpy_uaccess_get_long()/rust_strncpy_uaccess_get_byte() are the same shape as
 * lib/strnlen_user.c's rust_strncpy_uaccess_get_long(): one unsafe_get_user() read
 * plus its goto-efault recovery, called from Rust once per word/byte in
 * place of the inlined asm_goto_output()+hand-built exception-table entry
 * Rust cannot construct itself. Real, measured divergence -- see
 * logs/porting-hazards.md, "raw uaccess" -- but the STAC/CLAC bracket stays
 * at its original granularity, once per strncpy_from_user() call.
 */

#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/fault-inject-usercopy.h>
#include <linux/kasan-checks.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>

/* lib/strncpy_from_user_rs.rs. */
long strncpy_from_user_body(char *dst, const char __user *src,
			     unsigned long count, unsigned long max);

/* Forward-declared for the same reason as sha1_blocks_dispatch()/
 * blake2s_compress_dispatch(): config-full's -Wmissing-prototypes is fatal
 * (-Werror) and these symbols' only caller is Rust, via FFI.
 */
bool notrace rust_strncpy_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val);
bool notrace rust_strncpy_uaccess_get_byte(const char __user *ptr, char *val);

/*
 * See lib/strnlen_user.c's identically-named helper for the contract.
 *
 * notrace: same reasoning as strnlen_user.c's copy -- this runs inside the
 * caller's STAC-enabled bracket, and without it a CONFIG_FUNCTION_TRACER=y
 * kernel's __fentry__ prologue call would execute with SMAP disabled.
 * Adversarially found 2026-09-06; see logs/porting-hazards.md.
 */
bool notrace rust_strncpy_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val)
{
	unsigned long tmp;

	unsafe_get_user(tmp, ptr, efault);
	*val = tmp;
	return true;
efault:
	return false;
}

/* Same contract as rust_strncpy_uaccess_get_long(), one byte at a time --
 * including notrace, for the same reason. */
bool notrace rust_strncpy_uaccess_get_byte(const char __user *ptr, char *val)
{
	char tmp;

	unsafe_get_user(tmp, ptr, efault);
	*val = tmp;
	return true;
efault:
	return false;
}

/**
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */
long strncpy_from_user(char *dst, const char __user *src, long count)
{
	unsigned long max_addr, src_addr;

	might_fault();
	if (should_fail_usercopy())
		return -EFAULT;
	if (unlikely(count <= 0))
		return 0;

	kasan_check_write(dst, count);
	check_object_size(dst, count, false);

	if (can_do_masked_user_access()) {
		long retval;

		src = masked_user_access_begin(src);
		retval = strncpy_from_user_body(dst, src, count, count);
		user_read_access_end();
		return retval;
	}

	max_addr = TASK_SIZE_MAX;
	src_addr = (unsigned long)untagged_addr(src);
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		long retval;

		/*
		 * Truncate 'max' to the user-specified limit, so that
		 * we only have one limit we need to check in the loop
		 */
		if (max > count)
			max = count;

		if (user_read_access_begin(src, max)) {
			retval = strncpy_from_user_body(dst, src, count, max);
			user_read_access_end();
			return retval;
		}
	}
	return -EFAULT;
}
EXPORT_SYMBOL(strncpy_from_user);
