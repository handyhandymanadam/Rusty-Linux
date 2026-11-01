/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Userspace stand-ins for the real kernel symbols xarray_rs.rs links
 * against directly: rust_helper_spin_* (normally rust/helpers/
 * spinlock.c, part of the real kernel's Rust build) and call_rcu()
 * (normally kernel/rcu/tree.c). Single-threaded harness: no real
 * locking or grace periods needed, only the same signatures.
 */
#include <linux/xarray.h>

void rust_helper_spin_lock(void *lock) { (void)lock; }
void rust_helper_spin_unlock(void *lock) { (void)lock; }
void rust_helper_spin_lock_bh(void *lock) { (void)lock; }
void rust_helper_spin_unlock_bh(void *lock) { (void)lock; }
void rust_helper_spin_lock_irq(void *lock) { (void)lock; }
void rust_helper_spin_unlock_irq(void *lock) { (void)lock; }
void rust_helper_spin_lock_irqsave(void *lock, unsigned long *flags)
{
	(void)lock;
	*flags = 0;
}
void rust_helper_spin_unlock_irqrestore(void *lock, unsigned long flags)
{
	(void)lock;
	(void)flags;
}
void rust_helper_rcu_read_lock(void) {}
void rust_helper_rcu_read_unlock(void) {}

void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head))
{
	func(head);
}

/* __GFP_BITS_SHIFT of this harness (shim/linux/gfp.h) -- the kernel's xarray.c exports the real one. */
const unsigned int rust_xa_gfp_bits_shift = 8;
