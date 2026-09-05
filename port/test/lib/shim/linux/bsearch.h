/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_BSEARCH_H
#define _SHIM_LINUX_BSEARCH_H
#include <linux/types.h>
#include <linux/compiler.h>
void *bsearch(const void *key, const void *base, size_t num, size_t size, cmp_func_t cmp);
#endif
