/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RUST PORT (security/selinux/ss/ebitmap.c, 6.18.49): the bitmap functions are in ebitmap_rs.rs. This file keeps the node cache, ebitmap_cache_init() and the NetLabel
 * import / export as upstream has them, plus the rust_eb_* wrappers. Upstream's whole file is installed as ebitmap_norust.c for CONFIG_RUST=n.
 */
/*
 * Implementation of the extensible bitmap type.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */
/*
 * Updated: Hewlett-Packard <paul@paul-moore.com>
 *          Added support to import/export the NetLabel category bitmap
 *          (c) Copyright Hewlett-Packard Development Company, L.P., 2006
 *
 * Updated: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *          Applied standard bit operations to improve bitmap scanning.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/jhash.h>
#include <net/netlabel.h>
#include "ebitmap.h"
#include "policydb.h"

#define BITS_PER_U64 ((u32)(sizeof(u64) * 8))

static struct kmem_cache *ebitmap_node_cachep __ro_after_init;

#ifdef CONFIG_NETLABEL
/**
 * ebitmap_netlbl_export - Export an ebitmap into a NetLabel category bitmap
 * @ebmap: the ebitmap to export
 * @catmap: the NetLabel category bitmap
 *
 * Description:
 * Export a SELinux extensibile bitmap into a NetLabel category bitmap.
 * Returns zero on success, negative values on error.
 *
 */
int ebitmap_netlbl_export(struct ebitmap *ebmap,
			  struct netlbl_lsm_catmap **catmap)
{
	struct ebitmap_node *e_iter = ebmap->node;
	unsigned long e_map;
	u32 offset;
	unsigned int iter;
	int rc;

	if (e_iter == NULL) {
		*catmap = NULL;
		return 0;
	}

	if (*catmap != NULL)
		netlbl_catmap_free(*catmap);
	*catmap = NULL;

	while (e_iter) {
		offset = e_iter->startbit;
		for (iter = 0; iter < EBITMAP_UNIT_NUMS; iter++) {
			e_map = e_iter->maps[iter];
			if (e_map != 0) {
				rc = netlbl_catmap_setlong(catmap, offset,
							   e_map, GFP_ATOMIC);
				if (rc != 0)
					goto netlbl_export_failure;
			}
			offset += EBITMAP_UNIT_SIZE;
		}
		e_iter = e_iter->next;
	}

	return 0;

netlbl_export_failure:
	netlbl_catmap_free(*catmap);
	return -ENOMEM;
}

/**
 * ebitmap_netlbl_import - Import a NetLabel category bitmap into an ebitmap
 * @ebmap: the ebitmap to import
 * @catmap: the NetLabel category bitmap
 *
 * Description:
 * Import a NetLabel category bitmap into a SELinux extensibile bitmap.
 * Returns zero on success, negative values on error.
 *
 */
int ebitmap_netlbl_import(struct ebitmap *ebmap,
			  struct netlbl_lsm_catmap *catmap)
{
	int rc;
	struct ebitmap_node *e_iter = NULL;
	struct ebitmap_node *e_prev = NULL;
	u32 offset = 0, idx;
	unsigned long bitmap;

	for (;;) {
		rc = netlbl_catmap_getlong(catmap, &offset, &bitmap);
		if (rc < 0)
			goto netlbl_import_failure;
		if (offset == (u32)-1)
			return 0;

		/* don't waste ebitmap space if the netlabel bitmap is empty */
		if (bitmap == 0) {
			offset += EBITMAP_UNIT_SIZE;
			continue;
		}

		if (e_iter == NULL ||
		    offset >= e_iter->startbit + EBITMAP_SIZE) {
			e_prev = e_iter;
			e_iter = kmem_cache_zalloc(ebitmap_node_cachep,
						   GFP_ATOMIC);
			if (e_iter == NULL)
				goto netlbl_import_failure;
			e_iter->startbit = offset - (offset % EBITMAP_SIZE);
			if (e_prev == NULL)
				ebmap->node = e_iter;
			else
				e_prev->next = e_iter;
			ebmap->highbit = e_iter->startbit + EBITMAP_SIZE;
		}

		/* offset will always be aligned to an unsigned long */
		idx = EBITMAP_NODE_INDEX(e_iter, offset);
		e_iter->maps[idx] = bitmap;

		/* next */
		offset += EBITMAP_UNIT_SIZE;
	}

	/* NOTE: we should never reach this return */
	return 0;

netlbl_import_failure:
	ebitmap_destroy(ebmap);
	return -ENOMEM;
}
#endif /* CONFIG_NETLABEL */

/* RUST-WRAPPERS BEGIN: what ebitmap_rs.rs asks of the kernel. */
void *rust_eb_node_alloc(int atomic);
void rust_eb_node_free(void *n);
u32 rust_eb_jhash_1word(u32 a, u32 initval);
u32 rust_eb_jhash(const void *key, u32 length, u32 initval);
void rust_eb_err(int which, u32 a, u32 b, u64 c);
void __noreturn rust_eb_bug(void);

/* The bitmap functions (equal, cpy, and, contains, get_bit, set_bit, destroy, read, write, hash) are in ebitmap_rs.rs; it hard-codes this node layout. */
static_assert(sizeof(struct ebitmap_node) == 64 && EBITMAP_UNIT_NUMS == 6 && EBITMAP_UNIT_SIZE == 64 && EBITMAP_SIZE == 384);
static_assert(offsetof(struct ebitmap_node, next) == 0 && offsetof(struct ebitmap_node, maps) == 8 && offsetof(struct ebitmap_node, startbit) == 56);
static_assert(sizeof(struct ebitmap) == 16 && offsetof(struct ebitmap, node) == 0 && offsetof(struct ebitmap, highbit) == 8);
static_assert(sizeof(struct policy_file) == 16 && offsetof(struct policy_file, data) == 0 && offsetof(struct policy_file, len) == 8);

void *rust_eb_node_alloc(int atomic)
{
	return kmem_cache_zalloc(ebitmap_node_cachep, atomic ? GFP_ATOMIC : GFP_KERNEL);
}

void rust_eb_node_free(void *n)
{
	kmem_cache_free(ebitmap_node_cachep, n);
}

u32 rust_eb_jhash_1word(u32 a, u32 initval)
{
	return jhash_1word(a, initval);
}

u32 rust_eb_jhash(const void *key, u32 length, u32 initval)
{
	return jhash(key, length, initval);
}

/* The pr_err() calls of ebitmap_read(), in the order of the rust numbering. */
void rust_eb_err(int which, u32 a, u32 b, u64 c)
{
	switch (which) {
	case 0:
		pr_err("SELinux: ebitmap: map size %u does not "
		       "match my size %u (high bit was %u)\n",
		       a, b, (u32)c);
		break;
	case 1:
		pr_err("SELinux: ebitmap: truncated map\n");
		break;
	case 2:
		pr_err("SELinux: ebitmap start bit (%u) is "
		       "not a multiple of the map unit size (%u)\n",
		       a, b);
		break;
	case 3:
		pr_err("SELinux: ebitmap start bit (%u) is "
		       "beyond the end of the bitmap (%u)\n",
		       a, b);
		break;
	case 4:
		pr_err("SELinux: ebitmap: out of memory\n");
		break;
	case 5:
		pr_err("SELinux: ebitmap: start bit %u"
		       " comes after start bit %u\n",
		       a, b);
		break;
	case 6:
		pr_err("SELinux: ebitmap: empty map\n");
		break;
	case 7:
		pr_err("SELinux: ebitmap: high bit %u is not equal to the expected value %zu\n",
		       a, (size_t)c);
		break;
	}
}

void __noreturn rust_eb_bug(void)
{
	BUG();
}
/* RUST-WRAPPERS END */

void __init ebitmap_cache_init(void)
{
	ebitmap_node_cachep = KMEM_CACHE(ebitmap_node, SLAB_PANIC);
}
