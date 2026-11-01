// SPDX-License-Identifier: GPL-2.0
/*
 * Out-of-line refcount functions.
 *
 * RUST PORT (lib/refcount.c, 6.18.49): refcount_warn_saturate(), refcount_dec_if_one() and refcount_dec_not_one() are in refcount_rs.rs. This file
 * keeps the exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition), the three dec_and_{mutex_,}lock* functions
 * (a lock around Rust's refcount_dec_not_one) and one WARN_ONCE per site, so each still warns once (a warning now names this file -- recorded
 * divergence). Upstream's whole file is installed as refcount_norust.c for CONFIG_RUST=n.
 */

#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/bug.h>

static_assert(sizeof(refcount_t) == 4 && offsetof(refcount_t, refs) == 0 && sizeof(atomic_t) == 4);
static_assert(REFCOUNT_SATURATED == (-1073741824) && REFCOUNT_ADD_NOT_ZERO_OVF == 0 && REFCOUNT_ADD_OVF == 1 && REFCOUNT_ADD_UAF == 2 &&
	      REFCOUNT_SUB_UAF == 3 && REFCOUNT_DEC_LEAK == 4);

void rust_refcount_warn_saturate(atomic_t *refs, unsigned int t);
bool rust_refcount_dec_if_one(atomic_t *refs);
bool rust_refcount_dec_not_one(atomic_t *refs);
void rust_rfw_warn(unsigned int site);

#define REFCOUNT_WARN(str)	WARN_ONCE(1, "refcount_t: " str ".\n")

void rust_rfw_warn(unsigned int site)
{
	switch (site) {
	case 0:
		REFCOUNT_WARN("saturated; leaking memory");
		break;
	case 1:
		REFCOUNT_WARN("saturated; leaking memory");
		break;
	case 2:
		REFCOUNT_WARN("addition on 0; use-after-free");
		break;
	case 3:
		REFCOUNT_WARN("underflow; use-after-free");
		break;
	case 4:
		REFCOUNT_WARN("decrement hit 0; leaking memory");
		break;
	case 5:
		REFCOUNT_WARN("unknown saturation event!?");
		break;
	default:
		WARN_ONCE(1, "refcount_t: underflow; use-after-free.\n");
	}
}

void refcount_warn_saturate(refcount_t *r, enum refcount_saturation_type t)
{
	rust_refcount_warn_saturate(&r->refs, t);
}
EXPORT_SYMBOL(refcount_warn_saturate);

bool refcount_dec_if_one(refcount_t *r)
{
	return rust_refcount_dec_if_one(&r->refs);
}
EXPORT_SYMBOL(refcount_dec_if_one);

bool refcount_dec_not_one(refcount_t *r)
{
	return rust_refcount_dec_not_one(&r->refs);
}
EXPORT_SYMBOL(refcount_dec_not_one);

/**
 * refcount_dec_and_mutex_lock - return holding mutex if able to decrement
 *                               refcount to 0
 * @r: the refcount
 * @lock: the mutex to be locked
 *
 * Similar to atomic_dec_and_mutex_lock(), it will WARN on underflow and fail
 * to decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides a control dependency such that free() must come after.
 * See the comment on top.
 *
 * Return: true and hold mutex if able to decrement refcount to 0, false
 *         otherwise
 */
bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock)
{
	if (refcount_dec_not_one(r))
		return false;

	mutex_lock(lock);
	if (!refcount_dec_and_test(r)) {
		mutex_unlock(lock);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(refcount_dec_and_mutex_lock);

/**
 * refcount_dec_and_lock - return holding spinlock if able to decrement
 *                         refcount to 0
 * @r: the refcount
 * @lock: the spinlock to be locked
 *
 * Similar to atomic_dec_and_lock(), it will WARN on underflow and fail to
 * decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides a control dependency such that free() must come after.
 * See the comment on top.
 *
 * Return: true and hold spinlock if able to decrement refcount to 0, false
 *         otherwise
 */
bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock)
{
	if (refcount_dec_not_one(r))
		return false;

	spin_lock(lock);
	if (!refcount_dec_and_test(r)) {
		spin_unlock(lock);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(refcount_dec_and_lock);

/**
 * refcount_dec_and_lock_irqsave - return holding spinlock with disabled
 *                                 interrupts if able to decrement refcount to 0
 * @r: the refcount
 * @lock: the spinlock to be locked
 * @flags: saved IRQ-flags if the is acquired
 *
 * Same as refcount_dec_and_lock() above except that the spinlock is acquired
 * with disabled interrupts.
 *
 * Return: true and hold spinlock if able to decrement refcount to 0, false
 *         otherwise
 */
bool refcount_dec_and_lock_irqsave(refcount_t *r, spinlock_t *lock,
				   unsigned long *flags)
{
	if (refcount_dec_not_one(r))
		return false;

	spin_lock_irqsave(lock, *flags);
	if (!refcount_dec_and_test(r)) {
		spin_unlock_irqrestore(lock, *flags);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(refcount_dec_and_lock_irqsave);
