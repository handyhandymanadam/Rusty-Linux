// SPDX-License-Identifier: GPL-2.0-only

/*
 * Scalable reference counting for RCU protected objects (Thomas Gleixner)
 *
 * RUST PORT (lib/rcuref.c, 6.18.49): the two slow paths are in rcuref_rs.rs. This file keeps the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition) and the two WARN_ONCE sites, one wrapper each (the warning now names this file --
 * recorded divergence). Upstream's whole file is installed as rcuref_norust.c for CONFIG_RUST=n.
 */
#include <linux/export.h>
#include <linux/rcuref.h>
#include <linux/stddef.h>

static_assert(sizeof(rcuref_t) == 4 && offsetof(rcuref_t, refcnt) == 0 && sizeof(atomic_t) == 4);
static_assert(RCUREF_MAXREF == 0x7FFFFFFFU && RCUREF_SATURATED == 0xA0000000U && RCUREF_RELEASED == 0xC0000000U &&
	      RCUREF_DEAD == 0xE0000000U && RCUREF_NOREF == 0xFFFFFFFFU);

bool rust_rcuref_get_slowpath(atomic_t *refcnt);
bool rust_rcuref_put_slowpath(atomic_t *refcnt, unsigned int cnt);
bool rust_rcw_warn_saturated(bool cond);
bool rust_rcw_warn_imbalanced(bool cond);

bool rust_rcw_warn_saturated(bool cond) { return WARN_ONCE(cond, "rcuref saturated - leaking memory"); }
bool rust_rcw_warn_imbalanced(bool cond) { return WARN_ONCE(cond, "rcuref - imbalanced put()"); }

bool rcuref_get_slowpath(rcuref_t *ref)
{
	return rust_rcuref_get_slowpath(&ref->refcnt);
}
EXPORT_SYMBOL_GPL(rcuref_get_slowpath);

bool rcuref_put_slowpath(rcuref_t *ref, unsigned int cnt)
{
	return rust_rcuref_put_slowpath(&ref->refcnt, cnt);
}
EXPORT_SYMBOL_GPL(rcuref_put_slowpath);
