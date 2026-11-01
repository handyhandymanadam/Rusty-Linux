/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SHIM_XARRAY_LINUX_LIST_H
#define _SHIM_XARRAY_LINUX_LIST_H
#include <linux/types.h>

#define LIST_HEAD_INIT(name) { &(name), &(name) }

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void list_add(struct list_head *n, struct list_head *head)
{
	n->next = head->next;
	n->prev = head;
	head->next->prev = n;
	head->next = n;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

#endif
