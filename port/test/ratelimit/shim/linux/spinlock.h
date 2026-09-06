#pragma once
/* Single-threaded differential -- no contention, so trylock always
 * succeeds. What this harness verifies is ___ratelimit()'s own
 * arithmetic and control flow, not the qspinlock algorithm (which
 * neither arm reimplements -- see lib/ratelimit_rs.rs's module doc). */
typedef struct {
	int locked;
} raw_spinlock_t;

#define raw_spin_lock_init(lock) do { (lock)->locked = 0; } while (0)

#define raw_spin_trylock_irqsave(lock, flags) \
	({ (flags) = 0; (lock)->locked = 1; 1; })

#define raw_spin_unlock_irqrestore(lock, flags) \
	do { (lock)->locked = 0; (void)(flags); } while (0)
