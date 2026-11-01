// SPDX-License-Identifier: GPL-2.0

#include <linux/spinlock.h>

void rust_helper___spin_lock_init(spinlock_t *lock, const char *name,
				  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_SPINLOCK
# if defined(CONFIG_PREEMPT_RT)
	__spin_lock_init(lock, name, key, false);
# else /*!CONFIG_PREEMPT_RT */
	__raw_spin_lock_init(spinlock_check(lock), name, key, LD_WAIT_CONFIG);
# endif /* CONFIG_PREEMPT_RT */
#else /* !CONFIG_DEBUG_SPINLOCK */
	spin_lock_init(lock);
#endif /* CONFIG_DEBUG_SPINLOCK */
}

void rust_helper_spin_lock(spinlock_t *lock)
{
	spin_lock(lock);
}

void rust_helper_spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}

int rust_helper_spin_trylock(spinlock_t *lock)
{
	return spin_trylock(lock);
}

void rust_helper_spin_assert_is_held(spinlock_t *lock)
{
	lockdep_assert_held(lock);
}

/*
 * Added for lib/xarray.c's Rust port (xa_destroy() is unconditionally
 * interrupt-safe, matching the C's own xas_lock_irqsave()/
 * xas_unlock_irqrestore() -- neither existed as a Rust helper before
 * this port needed one). `flags` is passed by pointer because
 * spin_lock_irqsave() is itself a macro that assigns into its `flags`
 * argument; there is no way to return it and keep the real
 * save-then-restore ordering the compiler enforces around it.
 */
void rust_helper_spin_lock_irqsave(spinlock_t *lock, unsigned long *flags)
{
	spin_lock_irqsave(lock, *flags);
}

void rust_helper_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	spin_unlock_irqrestore(lock, flags);
}

/*
 * Also added for lib/xarray.c: __xas_nomem()'s lock-type dispatch
 * (xa_lock_type()/xas_lock_type()/xas_unlock_type() in the C) covers
 * plain, IRQ-disabling and BH-disabling locking depending on how the
 * caller initialised their xarray (XA_FLAGS_LOCK_IRQ / XA_FLAGS_LOCK_BH)
 * -- real drivers use all three (e.g. drivers/firewire/core-cdev.c uses
 * XA_FLAGS_LOCK_BH), so the dispatch needs to be complete, not just
 * whichever flavour this project's own boot path happens to exercise.
 */
void rust_helper_spin_lock_bh(spinlock_t *lock)
{
	spin_lock_bh(lock);
}

void rust_helper_spin_unlock_bh(spinlock_t *lock)
{
	spin_unlock_bh(lock);
}

/*
 * xas_lock_irq()/xas_unlock_irq() (unconditional disable, no saved
 * state -- distinct from the irqsave/irqrestore pair above, which saves
 * whatever interrupt state already existed) back __xas_nomem()'s
 * XA_LOCK_IRQ dispatch arm.
 */
void rust_helper_spin_lock_irq(spinlock_t *lock)
{
	spin_lock_irq(lock);
}

void rust_helper_spin_unlock_irq(spinlock_t *lock)
{
	spin_unlock_irq(lock);
}
