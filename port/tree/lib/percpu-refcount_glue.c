// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "%s: " fmt, __func__

/*
 * RUST PORT (lib/percpu-refcount.c, 6.18.49): the state machine -- init, exit, the mode switches, the two RCU callbacks, kill / reinit / resurrect,
 * is_zero -- is in percpu_refcount_rs.rs. This file keeps the exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition),
 * the global lock and wait queue, and one-line rust_prw_* wrappers for everything configuration-dependent: the percpu allocator, the header inlines,
 * the spinlock with irq save, wait_event / wake_up_all, call_rcu_hurry, lockdep, the bit-fields of struct percpu_ref_data, and every WARN / BUG
 * site (a warning now names this file -- recorded divergence). Upstream's whole file is installed as percpu-refcount_norust.c for CONFIG_RUST=n.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/percpu-refcount.h>

/*
 * Initially, a percpu refcount is just a set of percpu counters. Initially, we
 * don't try to detect the ref hitting 0 - which means that get/put can just
 * increment or decrement the local counter. Note that the counter on a
 * particular cpu can (and will) wrap - this is fine, when we go to shutdown the
 * percpu counters will all sum to the correct value
 *
 * (More precisely: because modular arithmetic is commutative the sum of all the
 * percpu_count vars will be equal to what it would have been if all the gets
 * and puts were done to a single integer, even if some of the percpu integers
 * overflow or underflow).
 *
 * The real trick to implementing percpu refcounts is shutdown. We can't detect
 * the ref hitting 0 on every put - this would require global synchronization
 * and defeat the whole purpose of using percpu refs.
 *
 * What we do is require the user to keep track of the initial refcount; we know
 * the ref can't hit 0 before the user drops the initial ref, so as long as we
 * convert to non percpu mode before the initial ref is dropped everything
 * works.
 *
 * Converting to non percpu mode is done with some RCUish stuff in
 * percpu_ref_kill. Additionally, we need a bias value so that the
 * atomic_long_t can't hit 0 before we've added up all the percpu refs.
 */

#define PERCPU_COUNT_BIAS	(1LU << (BITS_PER_LONG - 1))

static_assert(sizeof(unsigned long) == 8 && PERCPU_COUNT_BIAS == (1UL << 63) && __PERCPU_REF_FLAG_BITS == 2 && __PERCPU_REF_ATOMIC == 1 &&
	      __PERCPU_REF_DEAD == 2 && PERCPU_REF_INIT_ATOMIC == 1 && PERCPU_REF_INIT_DEAD == 2 && PERCPU_REF_ALLOW_REINIT == 4);
static_assert(offsetof(struct percpu_ref, percpu_count_ptr) == 0 && offsetof(struct percpu_ref, data) == 8 && sizeof(struct percpu_ref) == 16);
static_assert(offsetof(struct percpu_ref_data, count) == 0 && offsetof(struct percpu_ref_data, release) == 8 &&
	      offsetof(struct percpu_ref_data, confirm_switch) == 16 && offsetof(struct percpu_ref_data, rcu) == 32 &&
	      offsetof(struct percpu_ref_data, ref) == 48 && sizeof(struct percpu_ref_data) == 56 && sizeof(struct rcu_head) == 16);
static DEFINE_SPINLOCK(percpu_ref_switch_lock);
static DECLARE_WAIT_QUEUE_HEAD(percpu_ref_switch_waitq);

int rust_percpu_ref_init(struct percpu_ref *ref, percpu_ref_func_t *release, unsigned int flags, gfp_t gfp);
void rust_percpu_ref_exit(struct percpu_ref *ref);
void rust_percpu_ref_switch_to_atomic(struct percpu_ref *ref, percpu_ref_func_t *confirm_switch);
void rust_percpu_ref_switch_to_atomic_sync(struct percpu_ref *ref);
void rust_percpu_ref_switch_to_percpu(struct percpu_ref *ref);
void rust_percpu_ref_kill_and_confirm(struct percpu_ref *ref, percpu_ref_func_t *confirm_kill);
bool rust_percpu_ref_is_zero(struct percpu_ref *ref);
void rust_percpu_ref_reinit(struct percpu_ref *ref);
void rust_percpu_ref_resurrect(struct percpu_ref *ref);

unsigned long rust_prw_lock_irqsave(void);
void rust_prw_unlock_irqrestore(unsigned long flags);
void rust_prw_assert_held(void);
void rust_prw_wait_switched(struct percpu_ref_data *data);
void rust_prw_wait_switched_sync(struct percpu_ref *ref);
void rust_prw_wake_all(void);
void rust_prw_call_rcu_hurry(struct percpu_ref_data *data, rcu_callback_t cb);
unsigned long rust_prw_alloc_percpu(gfp_t gfp);
void rust_prw_free_percpu(unsigned long p);
struct percpu_ref_data *rust_prw_kzalloc_data(gfp_t gfp);
void rust_prw_kfree(void *p);
unsigned long rust_prw_sum_percpu(unsigned long p);
void rust_prw_zero_percpu(unsigned long p);
void rust_prw_get(struct percpu_ref *ref);
void rust_prw_put(struct percpu_ref *ref);
bool rust_prw_is_percpu(struct percpu_ref *ref);
void rust_prw_set_force_atomic(struct percpu_ref_data *data, bool v);
bool rust_prw_get_force_atomic(struct percpu_ref_data *data);
void rust_prw_set_allow_reinit(struct percpu_ref_data *data, bool v);
bool rust_prw_get_allow_reinit(struct percpu_ref_data *data);
void rust_prw_warn_exit_switching(bool cond);
void rust_prw_check_underflow(struct percpu_ref_data *data);
void rust_prw_bug_no_percpu(bool cond);
bool rust_prw_warn_no_reinit(bool cond);
void rust_prw_warn_kill_twice(struct percpu_ref *ref, bool cond);
void rust_prw_warn_not_zero(bool cond);
void rust_prw_warn_not_dying(bool cond);
void rust_prw_warn_percpu(bool cond);

unsigned long rust_prw_lock_irqsave(void)
{
	unsigned long flags;

	spin_lock_irqsave(&percpu_ref_switch_lock, flags);
	return flags;
}
void rust_prw_unlock_irqrestore(unsigned long flags) { spin_unlock_irqrestore(&percpu_ref_switch_lock, flags); }
void rust_prw_assert_held(void) { lockdep_assert_held(&percpu_ref_switch_lock); }
/* the caller holds percpu_ref_switch_lock with irqs saved; wait_event_lock_irq() drops and retakes it around the sleep */
void rust_prw_wait_switched(struct percpu_ref_data *data)
{
	wait_event_lock_irq(percpu_ref_switch_waitq, !data->confirm_switch, percpu_ref_switch_lock);
}
void rust_prw_wait_switched_sync(struct percpu_ref *ref) { wait_event(percpu_ref_switch_waitq, !ref->data->confirm_switch); }
void rust_prw_wake_all(void) { wake_up_all(&percpu_ref_switch_waitq); }
void rust_prw_call_rcu_hurry(struct percpu_ref_data *data, rcu_callback_t cb) { call_rcu_hurry(&data->rcu, cb); }
unsigned long rust_prw_alloc_percpu(gfp_t gfp)
{
	size_t align = max_t(size_t, 1 << __PERCPU_REF_FLAG_BITS, __alignof__(unsigned long));

	return (unsigned long)__alloc_percpu_gfp(sizeof(unsigned long), align, gfp);
}
void rust_prw_free_percpu(unsigned long p) { free_percpu((void __percpu *)p); }
struct percpu_ref_data *rust_prw_kzalloc_data(gfp_t gfp) { return kzalloc(sizeof(struct percpu_ref_data), gfp); }
void rust_prw_kfree(void *p) { kfree(p); }
unsigned long rust_prw_sum_percpu(unsigned long p)
{
	unsigned long __percpu *percpu_count = (unsigned long __percpu *)p;
	unsigned long count = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		count += *per_cpu_ptr(percpu_count, cpu);
	return count;
}
void rust_prw_zero_percpu(unsigned long p)
{
	unsigned long __percpu *percpu_count = (unsigned long __percpu *)p;
	int cpu;

	for_each_possible_cpu(cpu)
		*per_cpu_ptr(percpu_count, cpu) = 0;
}
void rust_prw_get(struct percpu_ref *ref) { percpu_ref_get(ref); }
void rust_prw_put(struct percpu_ref *ref) { percpu_ref_put(ref); }
bool rust_prw_is_percpu(struct percpu_ref *ref)
{
	unsigned long __percpu *percpu_count;

	return __ref_is_percpu(ref, &percpu_count);
}
void rust_prw_set_force_atomic(struct percpu_ref_data *data, bool v) { data->force_atomic = v; }
bool rust_prw_get_force_atomic(struct percpu_ref_data *data) { return data->force_atomic; }
void rust_prw_set_allow_reinit(struct percpu_ref_data *data, bool v) { data->allow_reinit = v; }
bool rust_prw_get_allow_reinit(struct percpu_ref_data *data) { return data->allow_reinit; }
void rust_prw_warn_exit_switching(bool cond) { WARN_ON_ONCE(cond); }
/* the WARN_ONCE + at most three underflow reports of percpu_ref_switch_to_atomic_rcu(), verbatim */
void rust_prw_check_underflow(struct percpu_ref_data *data)
{
	static atomic_t underflows;

	if (WARN_ONCE(atomic_long_read(&data->count) <= 0,
		      "percpu ref (%ps) <= 0 (%ld) after switching to atomic",
		      data->release, atomic_long_read(&data->count)) &&
	    atomic_inc_return(&underflows) < 4) {
		pr_err("%s(): percpu_ref underflow", "percpu_ref_switch_to_atomic_rcu");
		mem_dump_obj(data);
	}
}
void rust_prw_bug_no_percpu(bool cond) { BUG_ON(cond); }
bool rust_prw_warn_no_reinit(bool cond) { return WARN_ON_ONCE(cond); }
void rust_prw_warn_kill_twice(struct percpu_ref *ref, bool cond)
{
	WARN_ONCE(cond, "%s called more than once on %ps!", "percpu_ref_kill_and_confirm", cond ? ref->data->release : NULL);
}
void rust_prw_warn_not_zero(bool cond) { WARN_ON_ONCE(cond); }
void rust_prw_warn_not_dying(bool cond) { WARN_ON_ONCE(cond); }
void rust_prw_warn_percpu(bool cond) { WARN_ON_ONCE(cond); }

int percpu_ref_init(struct percpu_ref *ref, percpu_ref_func_t *release,
		    unsigned int flags, gfp_t gfp)
{
	return rust_percpu_ref_init(ref, release, flags, gfp);
}
EXPORT_SYMBOL_GPL(percpu_ref_init);

void percpu_ref_exit(struct percpu_ref *ref)
{
	rust_percpu_ref_exit(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_exit);

void percpu_ref_switch_to_atomic(struct percpu_ref *ref,
				 percpu_ref_func_t *confirm_switch)
{
	rust_percpu_ref_switch_to_atomic(ref, confirm_switch);
}
EXPORT_SYMBOL_GPL(percpu_ref_switch_to_atomic);

void percpu_ref_switch_to_atomic_sync(struct percpu_ref *ref)
{
	rust_percpu_ref_switch_to_atomic_sync(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_switch_to_atomic_sync);

void percpu_ref_switch_to_percpu(struct percpu_ref *ref)
{
	rust_percpu_ref_switch_to_percpu(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_switch_to_percpu);

void percpu_ref_kill_and_confirm(struct percpu_ref *ref,
				 percpu_ref_func_t *confirm_kill)
{
	rust_percpu_ref_kill_and_confirm(ref, confirm_kill);
}
EXPORT_SYMBOL_GPL(percpu_ref_kill_and_confirm);

bool percpu_ref_is_zero(struct percpu_ref *ref)
{
	return rust_percpu_ref_is_zero(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_is_zero);

void percpu_ref_reinit(struct percpu_ref *ref)
{
	rust_percpu_ref_reinit(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_reinit);

void percpu_ref_resurrect(struct percpu_ref *ref)
{
	rust_percpu_ref_resurrect(ref);
}
EXPORT_SYMBOL_GPL(percpu_ref_resurrect);
