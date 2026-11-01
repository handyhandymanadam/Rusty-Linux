// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (kernel/notifier.c, 6.18.49): notifier_chain_register/unregister, notifier_call_chain and notifier_call_chain_robust are in notifier_rs.rs. This file keeps
 * everything else as upstream has it (the four chain flavours with their locks, the die chain, the exports) plus the callback invocation, the tracepoints, the WARNs
 * and the DEBUG_NOTIFIERS check as rust_nt_* wrappers. Upstream's whole file is installed as notifier_norust.c for CONFIG_RUST=n.
 */
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>

#define CREATE_TRACE_POINTS
#include <trace/events/notifier.h>

/*
 *	Notifier chain core routines.  The exported routines below
 *	are layered on top of these, with appropriate locking added.
 */

/* The chain core is in notifier_rs.rs; these keep the names the rest of the file uses. */
int rust_nt_register(struct notifier_block **nl, struct notifier_block *n, bool unique_priority);
int rust_nt_unregister(struct notifier_block **nl, struct notifier_block *n);
int rust_nt_call_chain(struct notifier_block **nl, unsigned long val, void *v, int nr_to_call, int *nr_calls);
int rust_nt_call_chain_robust(struct notifier_block **nl, unsigned long val_up, unsigned long val_down, void *v);
void rust_nt_warn_dup(struct notifier_block *n);
void rust_nt_trace_register(struct notifier_block *n);
void rust_nt_trace_unregister(struct notifier_block *n);
int rust_nt_call(struct notifier_block *nb, unsigned long val, void *v);
bool rust_nt_callback_ok(struct notifier_block *nb);

void rust_nt_warn_dup(struct notifier_block *n)
{
	WARN(1, "notifier callback %ps already registered", n->notifier_call);
}

void rust_nt_trace_register(struct notifier_block *n)
{
	trace_notifier_register((void *)n->notifier_call);
}

void rust_nt_trace_unregister(struct notifier_block *n)
{
	trace_notifier_unregister((void *)n->notifier_call);
}

int rust_nt_call(struct notifier_block *nb, unsigned long val, void *v)
{
	trace_notifier_run((void *)nb->notifier_call);
	return nb->notifier_call(nb, val, v);
}

bool rust_nt_callback_ok(struct notifier_block *nb)
{
#ifdef CONFIG_DEBUG_NOTIFIERS
	if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
		WARN(1, "Invalid notifier called!");
		return false;
	}
#endif
	return true;
}
/* upstream: NOKPROBE_SYMBOL(notifier_call_chain) */
NOKPROBE_SYMBOL(rust_nt_call_chain);
NOKPROBE_SYMBOL(rust_nt_call);
NOKPROBE_SYMBOL(rust_nt_callback_ok);

static inline int notifier_chain_register(struct notifier_block **nl, struct notifier_block *n, bool unique_priority)
{
	return rust_nt_register(nl, n, unique_priority);
}

static inline int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n)
{
	return rust_nt_unregister(nl, n);
}

static inline int notifier_call_chain(struct notifier_block **nl, unsigned long val, void *v, int nr_to_call, int *nr_calls)
{
	return rust_nt_call_chain(nl, val, v, nr_to_call, nr_calls);
}

static inline int notifier_call_chain_robust(struct notifier_block **nl, unsigned long val_up, unsigned long val_down, void *v)
{
	return rust_nt_call_chain_robust(nl, val_up, val_down, v);
}

/**
 *	atomic_notifier_chain_register - Add notifier to an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an atomic notifier chain.
 *
 *	Returns 0 on success, %-EEXIST on error.
 */
int atomic_notifier_chain_register(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nh->lock, flags);
	ret = notifier_chain_register(&nh->head, n, false);
	spin_unlock_irqrestore(&nh->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_chain_register);

/**
 *	atomic_notifier_chain_register_unique_prio - Add notifier to an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an atomic notifier chain if there is no other
 *	notifier registered using the same priority.
 *
 *	Returns 0 on success, %-EEXIST or %-EBUSY on error.
 */
int atomic_notifier_chain_register_unique_prio(struct atomic_notifier_head *nh,
					       struct notifier_block *n)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nh->lock, flags);
	ret = notifier_chain_register(&nh->head, n, true);
	spin_unlock_irqrestore(&nh->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_chain_register_unique_prio);

/**
 *	atomic_notifier_chain_unregister - Remove notifier from an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from an atomic notifier chain.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int atomic_notifier_chain_unregister(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nh->lock, flags);
	ret = notifier_chain_unregister(&nh->head, n);
	spin_unlock_irqrestore(&nh->lock, flags);
	synchronize_rcu();
	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_chain_unregister);

/**
 *	atomic_notifier_call_chain - Call functions in an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an atomic context, so they must not block.
 *	This routine uses RCU to synchronize with changes to the chain.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then atomic_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int atomic_notifier_call_chain(struct atomic_notifier_head *nh,
			       unsigned long val, void *v)
{
	int ret;

	rcu_read_lock();
	ret = notifier_call_chain(&nh->head, val, v, -1, NULL);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(atomic_notifier_call_chain);
NOKPROBE_SYMBOL(atomic_notifier_call_chain);

/**
 *	atomic_notifier_call_chain_is_empty - Check whether notifier chain is empty
 *	@nh: Pointer to head of the atomic notifier chain
 *
 *	Checks whether notifier chain is empty.
 *
 *	Returns true is notifier chain is empty, false otherwise.
 */
bool atomic_notifier_call_chain_is_empty(struct atomic_notifier_head *nh)
{
	return !rcu_access_pointer(nh->head);
}

/*
 *	Blocking notifier chain routines.  All access to the chain is
 *	synchronized by an rwsem.
 */

static int __blocking_notifier_chain_register(struct blocking_notifier_head *nh,
					      struct notifier_block *n,
					      bool unique_priority)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call down_write().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_register(&nh->head, n, unique_priority);

	down_write(&nh->rwsem);
	ret = notifier_chain_register(&nh->head, n, unique_priority);
	up_write(&nh->rwsem);
	return ret;
}

/**
 *	blocking_notifier_chain_register - Add notifier to a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a blocking notifier chain.
 *	Must be called in process context.
 *
 *	Returns 0 on success, %-EEXIST on error.
 */
int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	return __blocking_notifier_chain_register(nh, n, false);
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_register);

/**
 *	blocking_notifier_chain_register_unique_prio - Add notifier to a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an blocking notifier chain if there is no other
 *	notifier registered using the same priority.
 *
 *	Returns 0 on success, %-EEXIST or %-EBUSY on error.
 */
int blocking_notifier_chain_register_unique_prio(struct blocking_notifier_head *nh,
						 struct notifier_block *n)
{
	return __blocking_notifier_chain_register(nh, n, true);
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_register_unique_prio);

/**
 *	blocking_notifier_chain_unregister - Remove notifier from a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a blocking notifier chain.
 *	Must be called from process context.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call down_write().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_unregister(&nh->head, n);

	down_write(&nh->rwsem);
	ret = notifier_chain_unregister(&nh->head, n);
	up_write(&nh->rwsem);
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_chain_unregister);

int blocking_notifier_call_chain_robust(struct blocking_notifier_head *nh,
		unsigned long val_up, unsigned long val_down, void *v)
{
	int ret = NOTIFY_DONE;

	/*
	 * We check the head outside the lock, but if this access is
	 * racy then it does not matter what the result of the test
	 * is, we re-check the list after having taken the lock anyway:
	 */
	if (rcu_access_pointer(nh->head)) {
		down_read(&nh->rwsem);
		ret = notifier_call_chain_robust(&nh->head, val_up, val_down, v);
		up_read(&nh->rwsem);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_call_chain_robust);

/**
 *	blocking_notifier_call_chain - Call functions in a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in a process context, so they are allowed to block.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then blocking_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
		unsigned long val, void *v)
{
	int ret = NOTIFY_DONE;

	/*
	 * We check the head outside the lock, but if this access is
	 * racy then it does not matter what the result of the test
	 * is, we re-check the list after having taken the lock anyway:
	 */
	if (rcu_access_pointer(nh->head)) {
		down_read(&nh->rwsem);
		ret = notifier_call_chain(&nh->head, val, v, -1, NULL);
		up_read(&nh->rwsem);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(blocking_notifier_call_chain);

/*
 *	Raw notifier chain routines.  There is no protection;
 *	the caller must provide it.  Use at your own risk!
 */

/**
 *	raw_notifier_chain_register - Add notifier to a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Returns 0 on success, %-EEXIST on error.
 */
int raw_notifier_chain_register(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_register(&nh->head, n, false);
}
EXPORT_SYMBOL_GPL(raw_notifier_chain_register);

/**
 *	raw_notifier_chain_unregister - Remove notifier from a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int raw_notifier_chain_unregister(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_unregister(&nh->head, n);
}
EXPORT_SYMBOL_GPL(raw_notifier_chain_unregister);

int raw_notifier_call_chain_robust(struct raw_notifier_head *nh,
		unsigned long val_up, unsigned long val_down, void *v)
{
	return notifier_call_chain_robust(&nh->head, val_up, val_down, v);
}
EXPORT_SYMBOL_GPL(raw_notifier_call_chain_robust);

/**
 *	raw_notifier_call_chain - Call functions in a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an undefined context.
 *	All locking must be provided by the caller.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then raw_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int raw_notifier_call_chain(struct raw_notifier_head *nh,
		unsigned long val, void *v)
{
	return notifier_call_chain(&nh->head, val, v, -1, NULL);
}
EXPORT_SYMBOL_GPL(raw_notifier_call_chain);

/*
 *	SRCU notifier chain routines.    Registration and unregistration
 *	use a mutex, and call_chain is synchronized by SRCU (no locks).
 */

/**
 *	srcu_notifier_chain_register - Add notifier to an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an SRCU notifier chain.
 *	Must be called in process context.
 *
 *	Returns 0 on success, %-EEXIST on error.
 */
int srcu_notifier_chain_register(struct srcu_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call mutex_lock().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_register(&nh->head, n, false);

	mutex_lock(&nh->mutex);
	ret = notifier_chain_register(&nh->head, n, false);
	mutex_unlock(&nh->mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(srcu_notifier_chain_register);

/**
 *	srcu_notifier_chain_unregister - Remove notifier from an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from an SRCU notifier chain.
 *	Must be called from process context.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int srcu_notifier_chain_unregister(struct srcu_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	/*
	 * This code gets used during boot-up, when task switching is
	 * not yet working and interrupts must remain disabled.  At
	 * such times we must not call mutex_lock().
	 */
	if (unlikely(system_state == SYSTEM_BOOTING))
		return notifier_chain_unregister(&nh->head, n);

	mutex_lock(&nh->mutex);
	ret = notifier_chain_unregister(&nh->head, n);
	mutex_unlock(&nh->mutex);
	synchronize_srcu(&nh->srcu);
	return ret;
}
EXPORT_SYMBOL_GPL(srcu_notifier_chain_unregister);

/**
 *	srcu_notifier_call_chain - Call functions in an SRCU notifier chain
 *	@nh: Pointer to head of the SRCU notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in a process context, so they are allowed to block.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then srcu_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int srcu_notifier_call_chain(struct srcu_notifier_head *nh,
		unsigned long val, void *v)
{
	int ret;
	int idx;

	idx = srcu_read_lock(&nh->srcu);
	ret = notifier_call_chain(&nh->head, val, v, -1, NULL);
	srcu_read_unlock(&nh->srcu, idx);
	return ret;
}
EXPORT_SYMBOL_GPL(srcu_notifier_call_chain);

/**
 *	srcu_init_notifier_head - Initialize an SRCU notifier head
 *	@nh: Pointer to head of the srcu notifier chain
 *
 *	Unlike other sorts of notifier heads, SRCU notifier heads require
 *	dynamic initialization.  Be sure to call this routine before
 *	calling any of the other SRCU notifier routines for this head.
 *
 *	If an SRCU notifier head is deallocated, it must first be cleaned
 *	up by calling srcu_cleanup_notifier_head().  Otherwise the head's
 *	per-cpu data (used by the SRCU mechanism) will leak.
 */
void srcu_init_notifier_head(struct srcu_notifier_head *nh)
{
	mutex_init(&nh->mutex);
	if (init_srcu_struct(&nh->srcu) < 0)
		BUG();
	nh->head = NULL;
}
EXPORT_SYMBOL_GPL(srcu_init_notifier_head);

static ATOMIC_NOTIFIER_HEAD(die_chain);

int notrace notify_die(enum die_val val, const char *str,
	       struct pt_regs *regs, long err, int trap, int sig)
{
	struct die_args args = {
		.regs	= regs,
		.str	= str,
		.err	= err,
		.trapnr	= trap,
		.signr	= sig,

	};
	RCU_LOCKDEP_WARN(!rcu_is_watching(),
			   "notify_die called but RCU thinks we're quiescent");
	return atomic_notifier_call_chain(&die_chain, val, &args);
}
NOKPROBE_SYMBOL(notify_die);

int register_die_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&die_chain, nb);
}
EXPORT_SYMBOL_GPL(register_die_notifier);

int unregister_die_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&die_chain, nb);
}
EXPORT_SYMBOL_GPL(unregister_die_notifier);
