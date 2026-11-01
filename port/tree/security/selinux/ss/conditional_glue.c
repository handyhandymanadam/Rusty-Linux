/* SPDX-License-Identifier: GPL-2.0-only */
/* RUST PORT (security/selinux/ss/conditional.c, 6.18.49): the whole file is in conditional_rs.rs; this file keeps the layout checks and the rust_cd_* wrappers.
 * Upstream's file is installed as conditional_norust.c for CONFIG_RUST=n. */
/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Frank Mayer <mayerf@tresys.com>
 *          Copyright (C) 2003 - 2004 Tresys Technology, LLC
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "security.h"
#include "conditional.h"
#include "services.h"

/* RUST-WRAPPERS BEGIN: what conditional_rs.rs asks of the kernel. */
void rust_cd_kfree(void *p);
void *rust_cd_kcalloc(u32 n, size_t size);
void *rust_cd_kzalloc(size_t size);
void *rust_cd_kmemdup(const void *src, size_t size);
int rust_cd_str_read(char **strp, struct policy_file *fp, u32 len);
void rust_cd_hash_eval(struct avtab *h);
void rust_cd_err(int which);

void rust_cd_kfree(void *p)
{
	kfree(p);
}

void *rust_cd_kcalloc(u32 n, size_t size)
{
	return kcalloc(n, size, GFP_KERNEL);
}

void *rust_cd_kzalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void *rust_cd_kmemdup(const void *src, size_t size)
{
	return kmemdup(src, size, GFP_KERNEL);
}

int rust_cd_str_read(char **strp, struct policy_file *fp, u32 len)
{
	return str_read(strp, GFP_KERNEL, fp, len);
}

void rust_cd_hash_eval(struct avtab *h)
{
	avtab_hash_eval(h, "conditional_rules");
}

/* The pr_err() calls, in the order of the rust numbering. */
void rust_cd_err(int which)
{
	switch (which) {
	case 0:
		pr_err("SELinux: expression result was undefined - disabling all rules.\n");
		break;
	case 1:
		pr_err("SELinux: conditional: failed to read boolean\n");
		break;
	case 2:
		pr_err("SELinux: type rule already exists outside of a conditional.\n");
		break;
	case 3:
		pr_err("SELinux: too many conflicting type rules.\n");
		break;
	case 4:
		pr_err("SELinux: conflicting type rules.\n");
		break;
	case 5:
		pr_err("SELinux: conflicting type rules when adding type rule for true.\n");
		break;
	case 6:
		pr_err("SELinux: could not insert rule.\n");
		break;
	case 7:
		pr_err("SELinux: conditional expressions uses unknown operator.\n");
		break;
	case 8:
		pr_err("SELinux: conditional expressions uses unknown bool.\n");
		break;
	}
}
/* RUST-WRAPPERS END */

/* conditional_rs.rs reads struct policydb at these offsets and hard-codes these layouts. */
static_assert(offsetof(struct policydb, p_bools.table) == 128 && offsetof(struct policydb, p_bools.nprim) == 144 && offsetof(struct policydb, sym_val_to_name[SYM_BOOLS]) == 240 &&
	      offsetof(struct policydb, te_avtab) == 296 && offsetof(struct policydb, bool_val_to_struct) == 376 && offsetof(struct policydb, te_cond_avtab) == 384 &&
	      offsetof(struct policydb, cond_list) == 408 && offsetof(struct policydb, cond_list_len) == 416);
static_assert(offsetof(struct avtab, nel) == 8 && sizeof(struct avtab_node) == 24 && offsetof(struct avtab_node, datum) == 8);
static_assert(sizeof(struct cond_bool_datum) == 8 && offsetof(struct cond_bool_datum, value) == 0 && offsetof(struct cond_bool_datum, state) == 4);
static_assert(sizeof(struct cond_expr_node) == 8 && offsetof(struct cond_expr_node, expr_type) == 0 && offsetof(struct cond_expr_node, boolean) == 4);
static_assert(sizeof(struct cond_node) == 56 && offsetof(struct cond_node, cur_state) == 0 && offsetof(struct cond_node, expr) == 8 && offsetof(struct cond_node, true_list) == 24 &&
	      offsetof(struct cond_node, false_list) == 40 && offsetof(struct cond_expr, len) == 8 && offsetof(struct cond_av_list, len) == 8);
static_assert(offsetof(struct policy_data, fp) == 8 && sizeof(struct policy_file) == 16);
static_assert(offsetof(struct av_decision, allowed) == 0 && offsetof(struct av_decision, auditallow) == 4 && offsetof(struct av_decision, auditdeny) == 8);
static_assert(sizeof(struct hashtab_node) == 24 && offsetof(struct hashtab_node, key) == 0 && offsetof(struct hashtab_node, datum) == 8);
static_assert(COND_BOOL == 1 && COND_NOT == 2 && COND_OR == 3 && COND_AND == 4 && COND_XOR == 5 && COND_EQ == 6 && COND_NEQ == 7 && COND_EXPR_MAXDEPTH == 10);
