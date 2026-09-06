// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * Every function is in lib/flex_proportions_rs.rs. None is EXPORT_SYMBOL
 * (confirmed by reading the pristine C -- no kabi pin needed, the same
 * conclusion lib/ratelimit.c's ___ratelimit() needed a capture for, this
 * file simply never had the export to begin with).
 *
 * What stays here: rust_flexprop_lock_irqsave()/unlock_irqrestore()/
 * lock_init() -- same reason as lib/ratelimit.c's rust_ratelimit_
 * trylock_irqsave()/unlock_irqrestore(): raw_spin_lock_irqsave()/
 * raw_spin_unlock_irqrestore() are not bare qspinlock instructions --
 * preempt_disable()/preempt_enable(), lockdep's spin_acquire()/
 * spin_release(), and LOCK_CONTENDED()'s dispatch into
 * queued_spin_lock_slowpath() (kernel/locking/qspinlock.c, a different
 * subsystem) all come along. See logs/porting-hazards.md, "spinlock +
 * IRQ state".
 *
 * local_irq_save()/local_irq_restore() (fprop_new_period(), standalone,
 * not wrapped in a spinlock) do NOT get a thunk -- CONFIG_TRACE_IRQFLAGS
 * is off in both project configs, so they reduce to bare
 * arch_local_irq_save()/arch_local_irq_restore(): plain pushf/pop, cli,
 * sti, no exception table, no goto, nothing asm_goto_output-shaped.
 * Reproduced directly in Rust via core::arch::asm!, matching the real
 * arch/x86/include/asm/irqflags.h sequence instruction-for-instruction --
 * see flex_proportions_rs.rs's module doc.
 */
#include <linux/flex_proportions.h>

/* Forward-declared for the same reason as lib/ratelimit.c's thunks:
 * -Wmissing-prototypes is fatal (-Werror) and these symbols' only caller
 * is Rust, via FFI. */
void rust_flexprop_lock_irqsave(raw_spinlock_t *lock, unsigned long *flags);
void rust_flexprop_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags);
void rust_flexprop_lock_init(raw_spinlock_t *lock);

void rust_flexprop_lock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
{
	unsigned long f;

	raw_spin_lock_irqsave(lock, f);
	*flags = f;
}

void rust_flexprop_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
	raw_spin_unlock_irqrestore(lock, flags);
}

void rust_flexprop_lock_init(raw_spinlock_t *lock)
{
	raw_spin_lock_init(lock);
}
