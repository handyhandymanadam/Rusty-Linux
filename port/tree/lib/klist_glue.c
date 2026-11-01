// SPDX-License-Identifier: GPL-2.0-only
/*
 * klist.c - Routines for manipulating klists.
 *
 * Copyright (C) 2005 Patrick Mochel
 *
 * RUST PORT (lib/klist.c, 6.18.49): the klist machinery -- add, del, release, the iterators -- is in klist_rs.rs. This file keeps klist_init() (spin_lock_init()
 * needs a lockdep key per call site) and klist_remove() (it sleeps on `current`), the exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the
 * definition), and the wrappers Rust cannot express: spinlock calls (spinlock_t depends on the configuration), list_add/list_add_tail/list_del (CONFIG_LIST_HARDENED
 * checks, poisoning), kref calls, wake_up_process(), mb() and the WARN_ON sites (warnings now name this file -- recorded divergence). Upstream's whole file is
 * installed as klist_norust.c for CONFIG_RUST=n.
 */

#include <linux/klist.h>
#include <linux/export.h>
#include <linux/sched.h>

static_assert(offsetof(struct klist, k_lock) == 0 && offsetof(struct klist_node, n_klist) == 0 && offsetof(struct klist_node, n_node) == 8 &&
	      offsetof(struct klist_iter, i_klist) == 0 && offsetof(struct klist_iter, i_cur) == 8 && sizeof(struct kref) == 4);
extern const size_t rust_kl_off_list, rust_kl_off_get, rust_kl_off_put;
const size_t rust_kl_off_list = offsetof(struct klist, k_list);
const size_t rust_kl_off_get = offsetof(struct klist, get);
const size_t rust_kl_off_put = offsetof(struct klist, put);

struct klist_waiter {
	struct list_head list;
	struct klist_node *node;
	struct task_struct *process;
	int woken;
};

static DEFINE_SPINLOCK(klist_remove_lock);
static LIST_HEAD(klist_remove_waiters);

void rust_klist_add_head(struct klist_node *n, struct klist *k);
void rust_klist_add_tail(struct klist_node *n, struct klist *k);
void rust_klist_add_behind(struct klist_node *n, struct klist_node *pos);
void rust_klist_add_before(struct klist_node *n, struct klist_node *pos);
void rust_klist_del(struct klist_node *n);
int rust_klist_node_attached(struct klist_node *n);
void rust_klist_iter_init_node(struct klist *k, struct klist_iter *i, struct klist_node *n);
void rust_klist_iter_exit(struct klist_iter *i);
struct klist_node *rust_klist_prev(struct klist_iter *i);
struct klist_node *rust_klist_next(struct klist_iter *i);

void rust_kl_lock(struct klist *k);
void rust_kl_unlock(struct klist *k);
void rust_kl_lock_irqsave(struct klist *k, unsigned long *flags);
void rust_kl_unlock_irqrestore(struct klist *k, unsigned long flags);
void rust_kl_remove_lock(void);
void rust_kl_remove_unlock(void);
struct list_head *rust_kl_waiters(void);
void rust_kl_list_add(struct list_head *new, struct list_head *head);
void rust_kl_list_add_tail(struct list_head *new, struct list_head *head);
void rust_kl_list_del(struct list_head *entry);
void rust_kl_init_list_head(struct list_head *l);
void rust_kl_kref_init(struct klist_node *n);
void rust_kl_kref_get(struct klist_node *n);
bool rust_kl_kref_get_unless_zero(struct klist_node *n);
bool rust_kl_kref_dec_and_test(struct klist_node *n);
void rust_kl_wake_up_process(struct task_struct *task);
void rust_kl_mb(void);
void rust_kl_warn_dead_at_start(bool cond);
void rust_kl_warn_dead_twice(bool cond);
void rust_kl_warn_release_not_dead(bool cond);

void rust_kl_lock(struct klist *k) { spin_lock(&k->k_lock); }
void rust_kl_unlock(struct klist *k) { spin_unlock(&k->k_lock); }
void rust_kl_lock_irqsave(struct klist *k, unsigned long *flags)
{
	unsigned long f;

	spin_lock_irqsave(&k->k_lock, f);
	*flags = f;
}
void rust_kl_unlock_irqrestore(struct klist *k, unsigned long flags) { spin_unlock_irqrestore(&k->k_lock, flags); }
void rust_kl_remove_lock(void) { spin_lock(&klist_remove_lock); }
void rust_kl_remove_unlock(void) { spin_unlock(&klist_remove_lock); }
struct list_head *rust_kl_waiters(void) { return &klist_remove_waiters; }
void rust_kl_list_add(struct list_head *new, struct list_head *head) { list_add(new, head); }
void rust_kl_list_add_tail(struct list_head *new, struct list_head *head) { list_add_tail(new, head); }
void rust_kl_list_del(struct list_head *entry) { list_del(entry); }
void rust_kl_init_list_head(struct list_head *l) { INIT_LIST_HEAD(l); }
void rust_kl_kref_init(struct klist_node *n) { kref_init(&n->n_ref); }
void rust_kl_kref_get(struct klist_node *n) { kref_get(&n->n_ref); }
bool rust_kl_kref_get_unless_zero(struct klist_node *n) { return kref_get_unless_zero(&n->n_ref); }
bool rust_kl_kref_dec_and_test(struct klist_node *n) { return refcount_dec_and_test(&n->n_ref.refcount); }
void rust_kl_wake_up_process(struct task_struct *task) { wake_up_process(task); }
void rust_kl_mb(void) { mb(); }
void rust_kl_warn_dead_at_start(bool cond) { WARN_ON(cond); }
void rust_kl_warn_dead_twice(bool cond) { WARN_ON(cond); }
void rust_kl_warn_release_not_dead(bool cond) { WARN_ON(cond); }

/**
 * klist_init - Initialize a klist structure.
 * @k: The klist we're initializing.
 * @get: The get function for the embedding object (NULL if none)
 * @put: The put function for the embedding object (NULL if none)
 *
 * Initialises the klist structure.  If the klist_node structures are
 * going to be embedded in refcounted objects (necessary for safe
 * deletion) then the get/put arguments are used to initialise
 * functions that take and release references on the embedding
 * objects.
 */
void klist_init(struct klist *k, void (*get)(struct klist_node *),
		void (*put)(struct klist_node *))
{
	INIT_LIST_HEAD(&k->k_list);
	spin_lock_init(&k->k_lock);
	k->get = get;
	k->put = put;
}
EXPORT_SYMBOL_GPL(klist_init);

/**
 * klist_add_head - Initialize a klist_node and add it to front.
 * @n: node we're adding.
 * @k: klist it's going on.
 */
void klist_add_head(struct klist_node *n, struct klist *k)
{
	rust_klist_add_head(n, k);
}
EXPORT_SYMBOL_GPL(klist_add_head);

/**
 * klist_add_tail - Initialize a klist_node and add it to back.
 * @n: node we're adding.
 * @k: klist it's going on.
 */
void klist_add_tail(struct klist_node *n, struct klist *k)
{
	rust_klist_add_tail(n, k);
}
EXPORT_SYMBOL_GPL(klist_add_tail);

/**
 * klist_add_behind - Init a klist_node and add it after an existing node
 * @n: node we're adding.
 * @pos: node to put @n after
 */
void klist_add_behind(struct klist_node *n, struct klist_node *pos)
{
	rust_klist_add_behind(n, pos);
}
EXPORT_SYMBOL_GPL(klist_add_behind);

/**
 * klist_add_before - Init a klist_node and add it before an existing node
 * @n: node we're adding.
 * @pos: node to put @n after
 */
void klist_add_before(struct klist_node *n, struct klist_node *pos)
{
	rust_klist_add_before(n, pos);
}
EXPORT_SYMBOL_GPL(klist_add_before);

/**
 * klist_del - Decrement the reference count of node and try to remove.
 * @n: node we're deleting.
 */
void klist_del(struct klist_node *n)
{
	rust_klist_del(n);
}
EXPORT_SYMBOL_GPL(klist_del);

/**
 * klist_remove - Decrement the refcount of node and wait for it to go away.
 * @n: node we're removing.
 */
void klist_remove(struct klist_node *n)
{
	struct klist_waiter waiter;

	waiter.node = n;
	waiter.process = current;
	waiter.woken = 0;
	spin_lock(&klist_remove_lock);
	list_add(&waiter.list, &klist_remove_waiters);
	spin_unlock(&klist_remove_lock);

	klist_del(n);

	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (waiter.woken)
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
}
EXPORT_SYMBOL_GPL(klist_remove);

/**
 * klist_node_attached - Say whether a node is bound to a list or not.
 * @n: Node that we're testing.
 */
int klist_node_attached(struct klist_node *n)
{
	return rust_klist_node_attached(n);
}
EXPORT_SYMBOL_GPL(klist_node_attached);

/**
 * klist_iter_init_node - Initialize a klist_iter structure.
 * @k: klist we're iterating.
 * @i: klist_iter we're filling.
 * @n: node to start with.
 *
 * Similar to klist_iter_init(), but starts the action off with @n,
 * instead of with the list head.
 */
void klist_iter_init_node(struct klist *k, struct klist_iter *i,
			  struct klist_node *n)
{
	rust_klist_iter_init_node(k, i, n);
}
EXPORT_SYMBOL_GPL(klist_iter_init_node);

/**
 * klist_iter_init - Iniitalize a klist_iter structure.
 * @k: klist we're iterating.
 * @i: klist_iter structure we're filling.
 *
 * Similar to klist_iter_init_node(), but start with the list head.
 */
void klist_iter_init(struct klist *k, struct klist_iter *i)
{
	klist_iter_init_node(k, i, NULL);
}
EXPORT_SYMBOL_GPL(klist_iter_init);

/**
 * klist_iter_exit - Finish a list iteration.
 * @i: Iterator structure.
 *
 * Must be called when done iterating over list, as it decrements the
 * refcount of the current node. Necessary in case iteration exited before
 * the end of the list was reached, and always good form.
 */
void klist_iter_exit(struct klist_iter *i)
{
	rust_klist_iter_exit(i);
}
EXPORT_SYMBOL_GPL(klist_iter_exit);

/**
 * klist_prev - Ante up prev node in list.
 * @i: Iterator structure.
 *
 * First grab list lock. Decrement the reference count of the previous
 * node, if there was one. Grab the prev node, increment its reference
 * count, drop the lock, and return that prev node.
 */
struct klist_node *klist_prev(struct klist_iter *i)
{
	return rust_klist_prev(i);
}
EXPORT_SYMBOL_GPL(klist_prev);

/**
 * klist_next - Ante up next node in list.
 * @i: Iterator structure.
 *
 * First grab list lock. Decrement the reference count of the previous
 * node, if there was one. Grab the next node, increment its reference
 * count, drop the lock, and return that next node.
 */
struct klist_node *klist_next(struct klist_iter *i)
{
	return rust_klist_next(i);
}
EXPORT_SYMBOL_GPL(klist_next);
