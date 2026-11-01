// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (lib/lockref.c, 6.18.49): the lock-free fast path -- what CMPXCHG_LOOP() expands to -- is in lockref_rs.rs. This file keeps
 * the public entry points (they also carry the spin_lock() fallback paths, whose unlock is configuration-dependent inline code) and
 * lockref_mark_dead() (assert_spin_locked() is a BUG_ON). Gated by lib/Makefile on the configurations where USE_CMPXCHG_LOCKREF
 * holds; every other build gets upstream's body as lockref_norust.c.
 */
#include <linux/export.h>
#include <linux/lockref.h>

static_assert(USE_CMPXCHG_LOCKREF, "lockref_rs.rs needs the cmpxchg lockref");

bool rust_lockref_get_fast(struct lockref *lockref);
int rust_lockref_get_not_zero_fast(struct lockref *lockref);
int rust_lockref_put_return(struct lockref *lockref);
bool rust_lockref_put_or_lock_fast(struct lockref *lockref);
int rust_lockref_get_not_dead_fast(struct lockref *lockref);

void lockref_get(struct lockref *lockref)
{
	if (rust_lockref_get_fast(lockref))
		return;

	spin_lock(&lockref->lock);
	lockref->count++;
	spin_unlock(&lockref->lock);
}
EXPORT_SYMBOL(lockref_get);

bool lockref_get_not_zero(struct lockref *lockref)
{
	bool retval = false;
	int fast = rust_lockref_get_not_zero_fast(lockref);

	if (fast >= 0)
		return fast;

	spin_lock(&lockref->lock);
	if (lockref->count > 0) {
		lockref->count++;
		retval = true;
	}
	spin_unlock(&lockref->lock);
	return retval;
}
EXPORT_SYMBOL(lockref_get_not_zero);

int lockref_put_return(struct lockref *lockref)
{
	return rust_lockref_put_return(lockref);
}
EXPORT_SYMBOL(lockref_put_return);

bool lockref_put_or_lock(struct lockref *lockref)
{
	if (rust_lockref_put_or_lock_fast(lockref))
		return true;

	spin_lock(&lockref->lock);
	if (lockref->count <= 1)
		return false;
	lockref->count--;
	spin_unlock(&lockref->lock);
	return true;
}
EXPORT_SYMBOL(lockref_put_or_lock);

void lockref_mark_dead(struct lockref *lockref)
{
	assert_spin_locked(&lockref->lock);
	lockref->count = -128;
}
EXPORT_SYMBOL(lockref_mark_dead);

bool lockref_get_not_dead(struct lockref *lockref)
{
	bool retval = false;
	int fast = rust_lockref_get_not_dead_fast(lockref);

	if (fast >= 0)
		return fast;

	spin_lock(&lockref->lock);
	if (lockref->count >= 0) {
		lockref->count++;
		retval = true;
	}
	spin_unlock(&lockref->lock);
	return retval;
}
EXPORT_SYMBOL(lockref_get_not_dead);
