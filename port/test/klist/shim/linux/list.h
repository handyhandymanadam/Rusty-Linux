#ifndef SH_LIST_H
#define SH_LIST_H
#include <stddef.h>
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
#define LIST_POISON1 ((void *)0x100)
#define LIST_POISON2 ((void *)0x122)
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *p, struct list_head *x) { x->prev = n; n->next = x; n->prev = p; p->next = n; }
static inline void list_add(struct list_head *n, struct list_head *h) { __list_add(n, h, h->next); }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { __list_add(n, h->prev, h); }
static inline void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; e->next = LIST_POISON1; e->prev = LIST_POISON2; }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member), n = list_entry(pos->member.next, __typeof__(*pos), member); \
	     &pos->member != (head); pos = n, n = list_entry(n->member.next, __typeof__(*n), member))
#endif
