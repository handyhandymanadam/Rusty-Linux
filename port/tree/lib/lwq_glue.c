// SPDX-License-Identifier: GPL-2.0-only
/*
 * Light-weight single-linked queue.
 *
 * Entries are enqueued to the head of an llist, with no blocking.
 * This can happen in any context.
 *
 * Entries are dequeued using a spinlock to protect against multiple
 * access.  The llist is staged in reverse order, and refreshed
 * from the llist when it exhausts.
 *
 * This is particularly suitable when work items are queued in BH or
 * IRQ context, and where work items are handled one at a time by
 * dedicated threads.
 *
 * RUST PORT (lib/lwq.c, 6.18.49): __lwq_dequeue() and lwq_dequeue_all() are in lwq_rs.rs. This file keeps the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition), the lock calls as wrappers, the offsets of the fields behind the spinlock_t (its size
 * depends on the configuration) and the CONFIG_LWQ_TEST module verbatim. Upstream's whole file is installed as lwq_norust.c for CONFIG_RUST=n.
 */
#include <linux/rcupdate.h>
#include <linux/lwq.h>


static_assert(offsetof(struct lwq, lock) == 0 && sizeof(struct llist_node) == 8 && sizeof(struct llist_head) == 8);
extern const size_t rust_lwq_off_ready, rust_lwq_off_new;
const size_t rust_lwq_off_ready = offsetof(struct lwq, ready);
const size_t rust_lwq_off_new = offsetof(struct lwq, new);

struct llist_node *rust_lwq_dequeue(struct lwq *q);
struct llist_node *rust_lwq_dequeue_all(struct lwq *q);
void rust_lwqw_lock(void *q);
void rust_lwqw_unlock(void *q);
void rust_lwqw_lock(void *q) { spin_lock(&((struct lwq *)q)->lock); }
void rust_lwqw_unlock(void *q) { spin_unlock(&((struct lwq *)q)->lock); }

struct llist_node *__lwq_dequeue(struct lwq *q)
{
	return rust_lwq_dequeue(q);
}
EXPORT_SYMBOL_GPL(__lwq_dequeue);

/**
 * lwq_dequeue_all - dequeue all currently enqueued objects
 * @q:	the queue to dequeue from
 *
 * Remove and return a linked list of llist_nodes of all the objects that were
 * in the queue. The first on the list will be the object that was least
 * recently enqueued.
 */
struct llist_node *lwq_dequeue_all(struct lwq *q)
{
	return rust_lwq_dequeue_all(q);
}
EXPORT_SYMBOL_GPL(lwq_dequeue_all);

#if IS_ENABLED(CONFIG_LWQ_TEST)

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait_bit.h>
#include <linux/kthread.h>
#include <linux/delay.h>
struct tnode {
	struct lwq_node n;
	int i;
	int c;
};

static int lwq_exercise(void *qv)
{
	struct lwq *q = qv;
	int cnt;
	struct tnode *t;

	for (cnt = 0; cnt < 10000; cnt++) {
		wait_var_event(q, (t = lwq_dequeue(q, struct tnode, n)) != NULL);
		t->c++;
		if (lwq_enqueue(&t->n, q))
			wake_up_var(q);
	}
	while (!kthread_should_stop())
		schedule_timeout_idle(1);
	return 0;
}

static int lwq_test(void)
{
	int i;
	struct lwq q;
	struct llist_node *l, **t1, *t2;
	struct tnode *t;
	struct task_struct *threads[8];

	printk(KERN_INFO "testing lwq....\n");
	lwq_init(&q);
	printk(KERN_INFO " lwq: run some threads\n");
	for (i = 0; i < ARRAY_SIZE(threads); i++)
		threads[i] = kthread_run(lwq_exercise, &q, "lwq-test-%d", i);
	for (i = 0; i < 100; i++) {
		t = kmalloc(sizeof(*t), GFP_KERNEL);
		if (!t)
			break;
		t->i = i;
		t->c = 0;
		if (lwq_enqueue(&t->n, &q))
			wake_up_var(&q);
	}
	/* wait for threads to exit */
	for (i = 0; i < ARRAY_SIZE(threads); i++)
		if (!IS_ERR_OR_NULL(threads[i]))
			kthread_stop(threads[i]);
	printk(KERN_INFO " lwq: dequeue first 50:");
	for (i = 0; i < 50 ; i++) {
		if (i && (i % 10) == 0) {
			printk(KERN_CONT "\n");
			printk(KERN_INFO " lwq: ... ");
		}
		t = lwq_dequeue(&q, struct tnode, n);
		if (t)
			printk(KERN_CONT " %d(%d)", t->i, t->c);
		kfree(t);
	}
	printk(KERN_CONT "\n");
	l = lwq_dequeue_all(&q);
	printk(KERN_INFO " lwq: delete the multiples of 3 (test lwq_for_each_safe())\n");
	lwq_for_each_safe(t, t1, t2, &l, n) {
		if ((t->i % 3) == 0) {
			t->i = -1;
			kfree(t);
			t = NULL;
		}
	}
	if (l)
		lwq_enqueue_batch(l, &q);
	printk(KERN_INFO " lwq: dequeue remaining:");
	while ((t = lwq_dequeue(&q, struct tnode, n)) != NULL) {
		printk(KERN_CONT " %d", t->i);
		kfree(t);
	}
	printk(KERN_CONT "\n");
	return 0;
}

module_init(lwq_test);
#endif /* CONFIG_LWQ_TEST*/
