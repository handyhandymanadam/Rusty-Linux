// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (security/selinux/ss/mls.c, 6.18.49): the context text, the validity checks, the parser, mls_range_set, mls_setup_user_range, mls_convert_context and
 * mls_compute_sid are in mls_rs.rs; this file keeps mls_from_string() and the NetLabel conversions. Upstream's whole file is installed as mls_norust.c for CONFIG_RUST=n.
 */
/*
 * Implementation of the multi-level security (MLS) policy.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *          Support for enhanced MLS infrastructure.
 *          Copyright (C) 2004-2006 Trusted Computer Solutions, Inc.
 *
 * Updated: Hewlett-Packard <paul@paul-moore.com>
 *          Added support to import/export the MLS label from NetLabel
 *          Copyright (C) Hewlett-Packard Development Company, L.P., 2006
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <net/netlabel.h>
#include "sidtab.h"
#include "mls.h"
#include "policydb.h"
#include "services.h"

/* RUST-WRAPPERS BEGIN: what mls_rs.rs asks of the kernel. */
struct context *rust_ml_sidtab_search(struct sidtab *s, u32 sid);

struct context *rust_ml_sidtab_search(struct sidtab *s, u32 sid)
{
	return sidtab_search(s, sid);
}

/* mls_rs.rs hard-codes these layouts. */
static_assert(offsetof(struct policydb, mls_enabled) == 0 && offsetof(struct policydb, symtab) == 8 && sizeof(struct symtab) == 24 && offsetof(struct symtab, nprim) == 16 &&
	      SYM_USERS == 4 && SYM_LEVELS == 6 && SYM_CATS == 7 && SYM_CLASSES == 1 && offsetof(struct policydb, sym_val_to_name) == 200 &&
	      offsetof(struct policydb, class_val_to_struct) == 264 && offsetof(struct policydb, user_val_to_struct) == 280 && offsetof(struct policydb, process_class) == 598);
static_assert(offsetof(struct context, user) == 0 && offsetof(struct context, role) == 4 && offsetof(struct context, type) == 8 && offsetof(struct context, range) == 16 &&
	      sizeof(struct mls_level) == 24 && offsetof(struct mls_level, sens) == 0 && offsetof(struct mls_level, cat) == 8 && sizeof(struct mls_range) == 48);
static_assert(offsetof(struct ebitmap, node) == 0 && offsetof(struct ebitmap, highbit) == 8 && offsetof(struct ebitmap_node, next) == 0 && offsetof(struct ebitmap_node, maps) == 8 &&
	      offsetof(struct ebitmap_node, startbit) == 56 && EBITMAP_UNIT_NUMS == 6 && EBITMAP_SIZE == 384);
static_assert(offsetof(struct user_datum, range) == 24 && offsetof(struct user_datum, dfltlevel) == 72 && offsetof(struct level_datum, level) == 0 &&
	      offsetof(struct cat_datum, value) == 0 && offsetof(struct class_datum, default_range) == 67);
static_assert(OBJECT_R_VAL == 1 && SECSID_NULL == 0 && AVTAB_TRANSITION == 0x10 && AVTAB_MEMBER == 0x20 && AVTAB_CHANGE == 0x40 && DEFAULT_SOURCE_LOW == 1 && DEFAULT_SOURCE_HIGH == 2 &&
	      DEFAULT_SOURCE_LOW_HIGH == 3 && DEFAULT_TARGET_LOW == 4 && DEFAULT_TARGET_HIGH == 5 && DEFAULT_TARGET_LOW_HIGH == 6 && DEFAULT_GLBLUB == 7);
static_assert(sizeof(struct range_trans) == 12 && offsetof(struct range_trans, source_type) == 0 && offsetof(struct range_trans, target_type) == 4 && offsetof(struct range_trans, target_class) == 8);
/* RUST-WRAPPERS END */

/*
 * Set the MLS fields in the security context structure
 * `context' based on the string representation in
 * the string `str'.  This function will allocate temporary memory with the
 * given constraints of gfp_mask.
 */
int mls_from_string(struct policydb *p, char *str, struct context *context,
		    gfp_t gfp_mask)
{
	char *tmpstr;
	int rc;

	if (!p->mls_enabled)
		return -EINVAL;

	tmpstr = kstrdup(str, gfp_mask);
	if (!tmpstr) {
		rc = -ENOMEM;
	} else {
		rc = mls_context_to_sid(p, ':', tmpstr, context, NULL,
					SECSID_NULL);
		kfree(tmpstr);
	}

	return rc;
}

#ifdef CONFIG_NETLABEL
/**
 * mls_export_netlbl_lvl - Export the MLS sensitivity levels to NetLabel
 * @p: the policy
 * @context: the security context
 * @secattr: the NetLabel security attributes
 *
 * Description:
 * Given the security context copy the low MLS sensitivity level into the
 * NetLabel MLS sensitivity level field.
 *
 */
void mls_export_netlbl_lvl(struct policydb *p, struct context *context,
			   struct netlbl_lsm_secattr *secattr)
{
	if (!p->mls_enabled)
		return;

	secattr->attr.mls.lvl = context->range.level[0].sens - 1;
	secattr->flags |= NETLBL_SECATTR_MLS_LVL;
}

/**
 * mls_import_netlbl_lvl - Import the NetLabel MLS sensitivity levels
 * @p: the policy
 * @context: the security context
 * @secattr: the NetLabel security attributes
 *
 * Description:
 * Given the security context and the NetLabel security attributes, copy the
 * NetLabel MLS sensitivity level into the context.
 *
 */
void mls_import_netlbl_lvl(struct policydb *p, struct context *context,
			   struct netlbl_lsm_secattr *secattr)
{
	if (!p->mls_enabled)
		return;

	context->range.level[0].sens = secattr->attr.mls.lvl + 1;
	context->range.level[1].sens = context->range.level[0].sens;
}

/**
 * mls_export_netlbl_cat - Export the MLS categories to NetLabel
 * @p: the policy
 * @context: the security context
 * @secattr: the NetLabel security attributes
 *
 * Description:
 * Given the security context copy the low MLS categories into the NetLabel
 * MLS category field.  Returns zero on success, negative values on failure.
 *
 */
int mls_export_netlbl_cat(struct policydb *p, struct context *context,
			  struct netlbl_lsm_secattr *secattr)
{
	int rc;

	if (!p->mls_enabled)
		return 0;

	rc = ebitmap_netlbl_export(&context->range.level[0].cat,
				   &secattr->attr.mls.cat);
	if (rc == 0 && secattr->attr.mls.cat != NULL)
		secattr->flags |= NETLBL_SECATTR_MLS_CAT;

	return rc;
}

/**
 * mls_import_netlbl_cat - Import the MLS categories from NetLabel
 * @p: the policy
 * @context: the security context
 * @secattr: the NetLabel security attributes
 *
 * Description:
 * Copy the NetLabel security attributes into the SELinux context; since the
 * NetLabel security attribute only contains a single MLS category use it for
 * both the low and high categories of the context.  Returns zero on success,
 * negative values on failure.
 *
 */
int mls_import_netlbl_cat(struct policydb *p, struct context *context,
			  struct netlbl_lsm_secattr *secattr)
{
	int rc;

	if (!p->mls_enabled)
		return 0;

	rc = ebitmap_netlbl_import(&context->range.level[0].cat,
				   secattr->attr.mls.cat);
	if (rc)
		goto import_netlbl_cat_failure;
	memcpy(&context->range.level[1].cat, &context->range.level[0].cat,
	       sizeof(context->range.level[0].cat));

	return 0;

import_netlbl_cat_failure:
	ebitmap_destroy(&context->range.level[0].cat);
	return rc;
}
#endif /* CONFIG_NETLABEL */
