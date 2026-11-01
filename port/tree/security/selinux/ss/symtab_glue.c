// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (security/selinux/ss/symtab.c, 6.18.49): the whole file is in symtab_rs.rs; this file keeps the layout checks and the cond_resched() wrapper.
 * Upstream's file is installed as symtab_norust.c for CONFIG_RUST=n.
 */
/*
 * Implementation of the symbol table type.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "symtab.h"

/* RUST-WRAPPERS BEGIN: what symtab_rs.rs asks of the kernel. */
void rust_st_cond_resched(void);

/* symtab_rs.rs hard-codes these layouts (and the hash and compare of upstream's symtab_key_params). */
static_assert(sizeof(struct symtab) == 24 && offsetof(struct symtab, table) == 0 && offsetof(struct symtab, nprim) == 16);

void rust_st_cond_resched(void)
{
	cond_resched();
}
/* RUST-WRAPPERS END */
