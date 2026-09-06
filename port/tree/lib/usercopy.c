// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT MOVE (YET)
 *
 * _copy_from_user()/_copy_to_user() are UNCHANGED: each is a one-line
 * forward to a `static __always_inline` function in <linux/uaccess.h>
 * (_inline_copy_from_user()/_inline_copy_to_user()). That header function
 * DOES contain real portable logic worth a port in its own right --
 * should_fail_usercopy(), the can_do_masked_user_access()/
 * mask_user_address() vs. access_ok()+barrier_nospec() fork, and
 * (_inline_copy_from_user() only) the `memset(to + (n - res), 0, res)`
 * zero-fill of the unfilled remainder on a partial copy. It is simply not
 * IN THIS FILE: it lives in include/linux/uaccess.h, and SCOPE.md's
 * porting unit is the .c file, so it is out of scope for a port of
 * lib/usercopy.c specifically, not exempt for lack of content (a wrong
 * claim caught by review: adversary, 2026-09-06 -- "no portable algorithm
 * there" would tell a future reader to stop looking, when the accurate
 * statement is "it's in a header, out of scope for this file"). What
 * usercopy.c's OWN two functions do is a one-line call each; there is no
 * SWAR/word-at-a-time hazard here comparable to strnlen_user()/
 * strncpy_from_user() or check_zeroed_user() below, so they stay exactly
 * as upstream wrote them.
 *
 * check_zeroed_user()'s word-at-a-time zero-scan is in lib/usercopy_rs.rs
 * (check_zeroed_user_body()). check_zeroed_user() itself -- the
 * EXPORT_SYMBOL -- stays here, same shape as strnlen_user()/
 * strncpy_from_user(): it is not a pass-through, it computes the word
 * alignment and adjusts `from`/`size` BEFORE calling
 * user_read_access_begin(from, size) (the adjusted, aligned-down range is
 * what that call needs to validate, since the first read covers up to
 * `align` bytes before the caller's own `from`), then holds the
 * user_read_access_begin()/user_read_access_end() bracket -- the actual
 * STAC/CLAC toggle -- around one call into Rust (see logs/c-entry-rule.md,
 * "A C ENTRY FUNCTION THAT DOES WORK IS NOT OPTIONAL"). No kabi pin applies:
 * the export never leaves C.
 *
 * rust_checkzeroeduser_uaccess_get_long() is a retained thunk with the same
 * job as lib/strnlen_user.c's rust_strnlen_uaccess_get_long() and
 * lib/strncpy_from_user.c's rust_strncpy_uaccess_get_long(): one
 * unsafe_get_user() read plus its goto-efault fault recovery, called from
 * Rust once per word in place of the original's inlined
 * asm_goto_output()+hand-built exception-table entry, which Rust has no
 * stable way to construct itself. Given its own name (not shared with the
 * other two files' helpers) because giving two of these retained thunks the
 * SAME name was a real duplicate-symbol link error caught during the
 * strnlen_user.c/strncpy_from_user.c port -- see logs/porting-hazards.md,
 * "raw uaccess", for the full account.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fault-inject-usercopy.h>
#include <linux/instrumented.h>
#include <linux/kernel.h>
#include <linux/nospec.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wordpart.h>

/* out-of-line parts */

#if !defined(INLINE_COPY_FROM_USER) || defined(CONFIG_RUST)
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return _inline_copy_from_user(to, from, n);
}
EXPORT_SYMBOL(_copy_from_user);
#endif

#if !defined(INLINE_COPY_TO_USER) || defined(CONFIG_RUST)
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return _inline_copy_to_user(to, from, n);
}
EXPORT_SYMBOL(_copy_to_user);
#endif

/* lib/usercopy_rs.rs. */
int check_zeroed_user_body(const unsigned long __user *from, size_t size, uintptr_t align);

/* Forward-declared for the same reason as rust_strnlen_uaccess_get_long()/
 * rust_strncpy_uaccess_get_long(): config-full's -Wmissing-prototypes is
 * fatal (-Werror) and this symbol's only caller is Rust, via FFI.
 */
bool notrace rust_checkzeroeduser_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val);

/*
 * Reads one unsigned long from user memory, assuming the caller is already
 * inside a user_read_access_begin()/user_access_end() bracket -- exactly
 * what unsafe_get_user() itself assumes, and what check_zeroed_user_body()'s
 * own Safety contract requires of ITS caller in turn. Returns false, without
 * touching *val, on a fault -- the same information the original's efault
 * goto carried, just handed back as a value instead of a jump.
 *
 * `notrace`: found by review (adversary, 2026-09-06) -- without it, under
 * CONFIG_FUNCTION_TRACER this function's own prologue gets an __fentry__
 * call, executed with EFLAGS.AC (SMAP) still set by the caller's
 * user_read_access_begin(). Neither config sets FUNCTION_TRACER today (see
 * logs/porting-hazards.md's addendum on this exact hazard), so this costs
 * nothing now and closes half the exposure permanently regardless of
 * future config changes -- the other half (the Rust body itself running
 * with AC set) can't be fixed this way and stays a recorded, accepted
 * divergence.
 */
bool notrace rust_checkzeroeduser_uaccess_get_long(const unsigned long __user *ptr, unsigned long *val)
{
	unsigned long tmp;

	unsafe_get_user(tmp, ptr, efault);
	*val = tmp;
	return true;
efault:
	return false;
}

/**
 * check_zeroed_user: check if a userspace buffer only contains zero bytes
 * @from: Source address, in userspace.
 * @size: Size of buffer.
 *
 * This is effectively shorthand for "memchr_inv(from, 0, size) == NULL" for
 * userspace addresses (and is more efficient because we don't care where the
 * first non-zero byte is).
 *
 * Returns:
 *  * 0: There were non-zero bytes present in the buffer.
 *  * 1: The buffer was full of zero bytes.
 *  * -EFAULT: access to userspace failed.
 */
int check_zeroed_user(const void __user *from, size_t size)
{
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);
	int ret;

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (!user_read_access_begin(from, size))
		return -EFAULT;

	ret = check_zeroed_user_body((const unsigned long __user *) from, size, align);

	user_read_access_end();

	if (ret < 0)
		return -EFAULT;
	return ret;
}
EXPORT_SYMBOL(check_zeroed_user);
