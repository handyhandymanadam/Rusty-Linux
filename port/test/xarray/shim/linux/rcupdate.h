/* SPDX-License-Identifier: GPL-2.0-only */
/* Single-threaded harness: no concurrent readers, so the read-side
 * primitives are plain accesses and call_rcu() runs its callback
 * synchronously (no grace period to wait for with one thread). The
 * WRITE side (rcu_assign_pointer/RCU_INIT_POINTER) keeps real
 * release-barrier vs. plain-store semantics -- same reasoning as
 * port/test/interval_tree/shim/linux/rcupdate.h: a harness that
 * quietly downgraded these would not be testing what the kernel
 * actually builds, even though a single thread can't observe the
 * difference itself. */
#ifndef _SHIM_XARRAY_LINUX_RCUPDATE_H
#define _SHIM_XARRAY_LINUX_RCUPDATE_H
#include <linux/types.h>

#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)

#define rcu_assign_pointer(p, v) \
	__atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
#define RCU_INIT_POINTER(p, v) do { (p) = (v); } while (0)

#define rcu_dereference_raw(p) (p)
#define rcu_dereference_check(p, c) ((void)(c), (p))
#define rcu_dereference_protected(p, c) ((void)(c), (p))

/* A REAL (non-static) symbol, not inlined here -- xarray_rs.rs links
 * against `call_rcu` directly via extern "C", the same as it would
 * against the real kernel's kernel/rcu/tree.c EXPORT_SYMBOL_GPL. A
 * `static inline` here would give every *.c file its own private,
 * unlinkable copy and leave the Rust side with nothing to link
 * against. Defined once, for real, in rust_helpers_stub.c.
 */
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head));

#endif
