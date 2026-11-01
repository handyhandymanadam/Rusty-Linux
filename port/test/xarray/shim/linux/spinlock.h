/* SPDX-License-Identifier: GPL-2.0-only */
/* Single-threaded differential -- no contention. Sized to match the real
 * kernel's spinlock_t (4 bytes, confirmed via pahole on build-fast/vmlinux:
 * qspinlock, CONFIG_DEBUG_SPINLOCK=n, CONFIG_DEBUG_LOCK_ALLOC=n both
 * configs) so a `struct xarray` in this harness has the same size/layout
 * as the real kernel's, even though this harness never links against it. */
#ifndef _SHIM_XARRAY_LINUX_SPINLOCK_H
#define _SHIM_XARRAY_LINUX_SPINLOCK_H

typedef struct { int locked; } spinlock_t;

#define __SPIN_LOCK_UNLOCKED(name) { 0 }

static inline void spin_lock_init(spinlock_t *lock) { lock->locked = 0; }
static inline void spin_lock(spinlock_t *lock) { lock->locked = 1; }
static inline void spin_unlock(spinlock_t *lock) { lock->locked = 0; }
static inline int spin_trylock(spinlock_t *lock) { lock->locked = 1; return 1; }
#define spin_lock_bh(lock) spin_lock(lock)
#define spin_unlock_bh(lock) spin_unlock(lock)
#define spin_lock_irq(lock) spin_lock(lock)
#define spin_unlock_irq(lock) spin_unlock(lock)
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; spin_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); spin_unlock(lock); } while (0)
#define spin_lock_nested(lock, subclass) spin_lock(lock)
#define spin_lock_bh_nested(lock, subclass) spin_lock(lock)
#define spin_lock_irq_nested(lock, subclass) spin_lock(lock)
#define spin_lock_irqsave_nested(lock, flags, subclass) spin_lock_irqsave(lock, flags)

#endif
