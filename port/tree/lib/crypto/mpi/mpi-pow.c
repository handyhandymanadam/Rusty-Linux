// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * mpi_powm() is now lib/crypto/mpi/mpi_pow_rs.rs. What stays here is
 * cond_resched() -- a scheduling primitive that, under
 * CONFIG_PREEMPT_DYNAMIC, is a static call patched at boot, not something
 * Rust can reach directly. Same shape as lib/sort.c's
 * rust_sort_cond_resched().
 */

#include <linux/sched.h>

/* config-full's -Wmissing-prototypes is fatal (-Werror); Rust FFI callers
 * give the compiler nothing else to infer a prototype from. Same shape as
 * lib/crypto/mpi/mpiutil.c's rust_mpi_k*() thunks. */
void rust_mpi_pow_cond_resched(void);

void rust_mpi_pow_cond_resched(void)
{
	cond_resched();
}
