// SPDX-License-Identifier: GPL-2.0-only
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * ___ratelimit() is in lib/ratelimit_rs.rs, EXPORT_SYMBOL'd there via
 * kernel::kabi_export!() -- no C entry thunk needed for the export itself,
 * same as lib/crypto/mpi/mpi-mul.c's exports. What stays here:
 *
 *   - rust_ratelimit_warn_once(): WARN_ONCE()'s bug-table entry names its
 *     own file and line, same reason as lib/dynamic_queue_limits.c's
 *     __dql_completed_bug_on() (that file's own header comment,
 *     logs/c-entry-rule.md) -- a Rust-side warning from inside
 *     ratelimit_rs.rs would name the wrong function.
 *   - rust_ratelimit_trylock_irqsave()/rust_ratelimit_unlock_irqrestore():
 *     raw_spin_trylock_irqsave()/raw_spin_unlock_irqrestore() do real work
 *     beyond the bare qspinlock instructions -- preempt_disable()/
 *     preempt_enable(), lockdep's spin_acquire()/spin_release(), and
 *     LOCK_CONTENDED()'s dispatch into queued_spin_lock_slowpath()
 *     (kernel/locking/qspinlock.c, a different subsystem entirely).
 *     Reimplementing preempt-count and the qspinlock protocol to port this
 *     one file would be wildly disproportionate -- see
 *     logs/porting-hazards.md, "spinlock + IRQ state".
 */
#include <linux/ratelimit_types.h>
#include <linux/bug.h>
#include <linux/spinlock.h>

/* Forward-declared for the same reason as
 * lib/dynamic_queue_limits.c's __dql_completed_bug_on(): -Wmissing-prototypes
 * is fatal (-Werror) and these symbols' only caller is Rust, via FFI. */
void rust_ratelimit_warn_once(int interval, int burst);
bool rust_ratelimit_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags);
void rust_ratelimit_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags);

void rust_ratelimit_warn_once(int interval, int burst)
{
	WARN_ONCE(interval < 0 || burst < 0,
		  "Negative interval (%d) or burst (%d): Uninitialized ratelimit_state structure?\n",
		  interval, burst);
}

bool rust_ratelimit_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
{
	unsigned long f;
	bool ok = raw_spin_trylock_irqsave(lock, f);

	*flags = f;
	return ok;
}

void rust_ratelimit_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
	raw_spin_unlock_irqrestore(lock, flags);
}
