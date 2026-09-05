/* SPDX-License-Identifier: GPL-2.0
 *
 * Enough of <linux/plist.h> and <linux/list.h> to compile the pristine
 * lib/plist.c as a differential oracle. The list operations here are the
 * textbook ones and are checked by the test itself: the oracle and the port
 * are compared structure-for-structure after every operation, so a shim that
 * differed from the kernel's would show up as a disagreement, not as a
 * silent pass.
 */
#ifndef _SHIM_LINUX_PLIST_H
#define _SHIM_LINUX_PLIST_H
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <stddef.h>

struct plist_head { struct list_head node_list; };
struct plist_node { int prio; struct list_head prio_list, node_list; };

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(ptr, type, member) container_of(ptr, type, member)

static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline int list_empty(const struct list_head *l) { return l->next == l; }

static inline void __list_add(struct list_head *n, struct list_head *p,
			      struct list_head *x)
{
	x->prev = n;
	n->next = x;
	n->prev = p;
	p->next = n;
}
static inline void list_add(struct list_head *n, struct list_head *h)
{
	__list_add(n, h, h->next);
}
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{
	__list_add(n, h->prev, h);
}
static inline void list_del_init(struct list_head *n)
{
	n->next->prev = n->prev;
	n->prev->next = n->next;
	INIT_LIST_HEAD(n);
}

static inline int plist_head_empty(const struct plist_head *h)
{
	return list_empty(&h->node_list);
}
static inline int plist_node_empty(const struct plist_node *n)
{
	return list_empty(&n->node_list);
}
static inline struct plist_node *plist_first(const struct plist_head *h)
{
	return list_entry(h->node_list.next, struct plist_node, node_list);
}
static inline struct plist_node *plist_last(const struct plist_head *h)
{
	return list_entry(h->node_list.prev, struct plist_node, node_list);
}
#define plist_next(pos) list_entry((pos)->node_list.next, struct plist_node, node_list)
#define plist_for_each_continue(pos, head)				\
	for (pos = plist_next(pos); &pos->node_list != &(head)->node_list;	\
	     pos = plist_next(pos))

void plist_add(struct plist_node *node, struct plist_head *head);
void plist_del(struct plist_node *node, struct plist_head *head);
void plist_requeue(struct plist_node *node, struct plist_head *head);
#endif
