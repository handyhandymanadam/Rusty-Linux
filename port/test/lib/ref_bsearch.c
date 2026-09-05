/* SPDX-License-Identifier: GPL-2.0
 *
 * The bsearch() oracle. bsearch()'s body lives in include/linux/bsearch.h as
 * __inline_bsearch(), so that header is what gets compiled -- again read from
 * the kernel tree rather than transcribed. The port does not modify that
 * header, so src/linux is the right place to read it from.
 */
#include <linux/types.h>
#include <linux/compiler.h>

#include "bsearch_inline_generated.h"

void *ref_bsearch(const void *key, const void *base, size_t num, size_t size,
		  cmp_func_t cmp)
{
	return __inline_bsearch(key, base, num, size, cmp);
}
