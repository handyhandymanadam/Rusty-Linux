// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (lib/dec_and_lock.c, 6.18.49): the four _atomic_dec_and_*lock*() bodies are in dec_and_lock_rs.rs. This file keeps the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition) and one-line wrappers for the locks (spinlock_t and raw_spinlock_t depend on the configuration). Upstream's whole file
 * is installed as dec_and_lock_norust.c for CONFIG_RUST=n.
 */
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

static_assert(sizeof(atomic_t) == 4 && __alignof__(atomic_t) == 4);

int rust__atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock);
int rust__atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock, unsigned long *flags);
int rust__atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock);
int rust__atomic_dec_and_raw_lock_irqsave(atomic_t *atomic, raw_spinlock_t *lock, unsigned long *flags);
void rust_dl_lock(spinlock_t *lock);
void rust_dl_unlock(spinlock_t *lock);
void rust_dl_lock_irqsave(spinlock_t *lock, unsigned long *flags);
void rust_dl_unlock_irqrestore(spinlock_t *lock, unsigned long flags);
void rust_dl_raw_lock(raw_spinlock_t *lock);
void rust_dl_raw_unlock(raw_spinlock_t *lock);
void rust_dl_raw_lock_irqsave(raw_spinlock_t *lock, unsigned long *flags);
void rust_dl_raw_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags);

void rust_dl_lock(spinlock_t *lock) { spin_lock(lock); }
void rust_dl_unlock(spinlock_t *lock) { spin_unlock(lock); }
void rust_dl_lock_irqsave(spinlock_t *lock, unsigned long *flags)
{
	unsigned long f;

	spin_lock_irqsave(lock, f);
	*flags = f;
}
void rust_dl_unlock_irqrestore(spinlock_t *lock, unsigned long flags) { spin_unlock_irqrestore(lock, flags); }
void rust_dl_raw_lock(raw_spinlock_t *lock) { raw_spin_lock(lock); }
void rust_dl_raw_unlock(raw_spinlock_t *lock) { raw_spin_unlock(lock); }
void rust_dl_raw_lock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
{
	unsigned long f;

	raw_spin_lock_irqsave(lock, f);
	*flags = f;
}
void rust_dl_raw_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags) { raw_spin_unlock_irqrestore(lock, flags); }

int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock)
{
	return rust__atomic_dec_and_lock(atomic, lock);
}
EXPORT_SYMBOL(_atomic_dec_and_lock);

int _atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock,
				 unsigned long *flags)
{
	return rust__atomic_dec_and_lock_irqsave(atomic, lock, flags);
}
EXPORT_SYMBOL(_atomic_dec_and_lock_irqsave);

int _atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock)
{
	return rust__atomic_dec_and_raw_lock(atomic, lock);
}
EXPORT_SYMBOL(_atomic_dec_and_raw_lock);

int _atomic_dec_and_raw_lock_irqsave(atomic_t *atomic, raw_spinlock_t *lock,
				     unsigned long *flags)
{
	return rust__atomic_dec_and_raw_lock_irqsave(atomic, lock, flags);
}
EXPORT_SYMBOL(_atomic_dec_and_raw_lock_irqsave);
