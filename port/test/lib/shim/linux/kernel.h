/* SPDX-License-Identifier: GPL-2.0 */
/* Delta over port/test/common/shim/linux/kernel.h.
 *
 * lib/'s own headers come FIRST and the shared base second: every macro in the
 * base is #ifndef-guarded, so anything lib defines here wins. compiler.h
 * deliberately defines likely()/unlikely() as (x) with no branch hint, and
 * that must survive. */
#ifndef _SHIM_LIB_LINUX_KERNEL_H
#define _SHIM_LIB_LINUX_KERNEL_H
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/printk.h>
#include <string.h>

/* Only ever used with the two flags ref_crypto_utils.c defines. */
#define IS_ENABLED(x) (x)

#include_next <linux/kernel.h>
/* The base is MANDATORY. Without -I port/test/common/shim on the path,
 * #include_next above resolves to /usr/include/linux/kernel.h -- the UAPI
 * stub -- and several harnesses then compile CLEAN against it. That is the
 * same silent-wrong-header failure this shim arrangement exists to prevent,
 * so make it a build error instead of a mystery. Found 2026-09-03 by an
 * adversarial review of the commit that introduced it. */
#ifndef _SHIM_COMMON_LINUX_KERNEL_H
#error "port/test/common/shim must be on the include path (see run.sh -I flags)"
#endif

/* strscpy(): copy at most size-1 bytes, always NUL-terminate. */
static inline ssize_t strscpy(char *dst, const char *src, size_t size)
{
	size_t i = 0;

	if (!size)
		return -7;
	while (i < size - 1 && src[i]) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
	return src[i] ? -7 : (ssize_t)i;
}
#endif
