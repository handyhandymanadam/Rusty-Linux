// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/lib/string.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * This file should be used only for "library" routines that may have
 * alternative implementations on specific architectures (generally
 * found in <asm-xx/string.h>), or get overloaded by FORTIFY_SOURCE.
 * (Specifically, this file is built with __NO_FORTIFY.)
 *
 * Other helper functions should live in string_helpers.c.
 */

#define __NO_FORTIFY
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/linkage.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/page.h>
#include <asm/rwonce.h>
#include <linux/unaligned.h>
#include <asm/word-at-a-time.h>

/*
 * RUST PORT (lib/string.c, 6.18.49, x86-64 with CONFIG_RUST): every function the generic file builds on x86-64 is in
 * string_rs.rs except these two, which carry WARN_ON_ONCE / BUG_ON (bug-table entries naming this file and line, so the C
 * entries stay): sized_strscpy() and strlcat(). Upstream's file is installed as string_norust.c for every other build.
 */

#ifdef __BIG_ENDIAN
# define ALLBUTLAST_BYTE_MASK (~255ul)
#else
# define ALLBUTLAST_BYTE_MASK (~0ul >> 8)
#endif

ssize_t sized_strscpy(char *dest, const char *src, size_t count)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	size_t max = count;
	long res = 0;

	if (count == 0 || WARN_ON_ONCE(count > INT_MAX))
		return -E2BIG;

#ifndef CONFIG_DCACHE_WORD_ACCESS
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	/*
	 * If src is unaligned, don't cross a page boundary,
	 * since we don't know if the next page is mapped.
	 */
	if ((long)src & (sizeof(long) - 1)) {
		size_t limit = PAGE_SIZE - ((long)src & (PAGE_SIZE - 1));
		if (limit < max)
			max = limit;
	}
#else
	/* If src or dest is unaligned, don't do word-at-a-time. */
	if (((long) dest | (long) src) & (sizeof(long) - 1))
		max = 0;
#endif
#endif

	/*
	 * load_unaligned_zeropad() or read_word_at_a_time() below may read
	 * uninitialized bytes after the trailing zero and use them in
	 * comparisons. Disable this optimization under KMSAN to prevent
	 * false positive reports.
	 */
	if (IS_ENABLED(CONFIG_KMSAN))
		max = 0;

	while (max >= sizeof(unsigned long)) {
		unsigned long c, data;

#ifdef CONFIG_DCACHE_WORD_ACCESS
		c = load_unaligned_zeropad(src+res);
#else
		c = read_word_at_a_time(src+res);
#endif
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			*(unsigned long *)(dest+res) = c & zero_bytemask(data);
			return res + find_zero(data);
		}
		count -= sizeof(unsigned long);
		if (unlikely(!count)) {
			c &= ALLBUTLAST_BYTE_MASK;
			*(unsigned long *)(dest+res) = c;
			return -E2BIG;
		}
		*(unsigned long *)(dest+res) = c;
		res += sizeof(unsigned long);
		max -= sizeof(unsigned long);
	}

	while (count > 1) {
		char c;

		c = src[res];
		dest[res] = c;
		if (!c)
			return res;
		res++;
		count--;
	}

	/* Force NUL-termination. */
	dest[res] = '\0';

	/* Return E2BIG if the source didn't stop */
	return src[res] ? -E2BIG : res;
}
EXPORT_SYMBOL(sized_strscpy);

#ifndef __HAVE_ARCH_STRLCAT
size_t strlcat(char *dest, const char *src, size_t count)
{
	size_t dsize = strlen(dest);
	size_t len = strlen(src);
	size_t res = dsize + len;

	/* This would be a bug */
	BUG_ON(dsize >= count);

	dest += dsize;
	count -= dsize;
	if (len >= count)
		len = count-1;
	__builtin_memcpy(dest, src, len);
	dest[len] = 0;
	return res;
}
EXPORT_SYMBOL(strlcat);
#endif
