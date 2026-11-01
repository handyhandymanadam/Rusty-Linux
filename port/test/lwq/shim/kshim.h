/* kernel shim for the lwq differential: llist, spinlock (a real pthread mutex, the threaded phase needs mutual exclusion), the lwq header's inlines */
#ifndef KSHIM_H
#define KSHIM_H
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define static_assert _Static_assert
#define EXPORT_SYMBOL_GPL(x)
#define IS_ENABLED(x) 0
#define CONFIG_LWQ_TEST 0
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
struct llist_head { struct llist_node *first; };
struct llist_node { struct llist_node *next; };
typedef struct { pthread_mutex_t m; } spinlock_t;
static inline void spin_lock(spinlock_t *l) { pthread_mutex_lock(&l->m); }
static inline void spin_unlock(spinlock_t *l) { pthread_mutex_unlock(&l->m); }
static inline void spin_lock_init(spinlock_t *l) { pthread_mutex_init(&l->m, NULL); }
static inline bool llist_empty(const struct llist_head *h) { return READ_ONCE(h->first) == NULL; }
static inline struct llist_node *llist_next(struct llist_node *n) { return n->next; }
static inline struct llist_node *llist_del_all(struct llist_head *h) { return __atomic_exchange_n(&h->first, NULL, __ATOMIC_SEQ_CST); }
static inline bool llist_add(struct llist_node *n, struct llist_head *h)
{
	struct llist_node *first = READ_ONCE(h->first);
	do { n->next = first; } while (!__atomic_compare_exchange_n(&h->first, &first, n, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
	return !first;
}
/* lib/llist.c llist_reverse_order(), for both arms */
struct llist_node *llist_reverse_order(struct llist_node *head);
struct lwq { spinlock_t lock; struct llist_node *ready; struct llist_head new; };
struct lwq_node { struct llist_node node; };
static inline void lwq_init(struct lwq *q) { spin_lock_init(&q->lock); q->ready = NULL; q->new.first = NULL; }
static inline bool lwq_empty(struct lwq *q) { return smp_load_acquire(&q->ready) == NULL && llist_empty(&q->new); }
struct llist_node *__lwq_dequeue(struct lwq *q);
struct llist_node *lwq_dequeue_all(struct lwq *q);
static inline bool lwq_enqueue(struct lwq_node *n, struct lwq *q) { return llist_add(&n->node, &q->new) && smp_load_acquire(&q->ready) == NULL; }
#endif
