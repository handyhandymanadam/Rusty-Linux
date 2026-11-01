// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (security/selinux/ss/hashtab.c, 6.18.49): the table functions are in hashtab_rs.rs. This file keeps the node cache, hashtab_cache_init(), hashtab_stat() (debug only)
 * and the rust_ht_* wrappers. Upstream's whole file is installed as hashtab_norust.c for CONFIG_RUST=n.
 */
/*
 * Implementation of the hash table type.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include "hashtab.h"
#include "security.h"

static struct kmem_cache *hashtab_node_cachep __ro_after_init;

/*
 * Here we simply round the number of elements up to the nearest power of two.
 * I tried also other options like rounding down or rounding to the closest
 * power of two (up or down based on which is closer), but I was unable to
 * find any significant difference in lookup/insert performance that would
 * justify switching to a different (less intuitive) formula. It could be that
 * a different formula is actually more optimal, but any future changes here
 * should be supported with performance/memory usage data.
 *
 * The total memory used by the htable arrays (only) with Fedora policy loaded
 * is approximately 163 KB at the time of writing.
 */
/* RUST-WRAPPERS BEGIN: what hashtab_rs.rs asks of the kernel. */
struct hashtab_node *rust_ht_node_alloc(void);
void rust_ht_node_free(struct hashtab_node *n);
void *rust_ht_kcalloc_nowarn(u32 n);
void *rust_ht_kcalloc(u32 n);
void rust_ht_kfree(void *p);

/* The table functions are in hashtab_rs.rs; it hard-codes these layouts. */
static_assert(sizeof(struct hashtab_node) == 24 && offsetof(struct hashtab_node, key) == 0 && offsetof(struct hashtab_node, datum) == 8 && offsetof(struct hashtab_node, next) == 16);
static_assert(sizeof(struct hashtab) == 16 && offsetof(struct hashtab, htable) == 0 && offsetof(struct hashtab, size) == 8 && offsetof(struct hashtab, nel) == 12);

struct hashtab_node *rust_ht_node_alloc(void)
{
	return kmem_cache_zalloc(hashtab_node_cachep, GFP_KERNEL);
}

void rust_ht_node_free(struct hashtab_node *n)
{
	kmem_cache_free(hashtab_node_cachep, n);
}

void *rust_ht_kcalloc_nowarn(u32 n)
{
	return kcalloc(n, sizeof(struct hashtab_node *), GFP_KERNEL | __GFP_NOWARN);
}

void *rust_ht_kcalloc(u32 n)
{
	return kcalloc(n, sizeof(struct hashtab_node *), GFP_KERNEL);
}

void rust_ht_kfree(void *p)
{
	kfree(p);
}
/* RUST-WRAPPERS END */

#ifdef CONFIG_SECURITY_SELINUX_DEBUG
void hashtab_stat(struct hashtab *h, struct hashtab_info *info)
{
	u32 i, chain_len, slots_used, max_chain_len;
	u64 chain2_len_sum;
	struct hashtab_node *cur;

	slots_used = 0;
	max_chain_len = 0;
	chain2_len_sum = 0;
	for (i = 0; i < h->size; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;

			chain2_len_sum += (u64)chain_len * chain_len;
		}
	}

	info->slots_used = slots_used;
	info->max_chain_len = max_chain_len;
	info->chain2_len_sum = chain2_len_sum;
}
#endif /* CONFIG_SECURITY_SELINUX_DEBUG */

void __init hashtab_cache_init(void)
{
	hashtab_node_cachep = KMEM_CACHE(hashtab_node, SLAB_PANIC);
}
