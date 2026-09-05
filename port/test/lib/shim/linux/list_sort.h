/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_LIST_SORT_H
#define _SHIM_LINUX_LIST_SORT_H
#include <linux/types.h>
typedef int (*list_cmp_func_t)(void *, const struct list_head *,
			       const struct list_head *);
void list_sort(void *priv, struct list_head *head, list_cmp_func_t cmp);
#endif
