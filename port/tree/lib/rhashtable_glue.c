// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resizable, Scalable, Concurrent Hash Table
 *
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2014-2015 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2008-2014 Patrick McHardy <kaber@trash.net>
 *
 * Code partially derived from nft_hash
 * Rewritten with rehash code from br_multicast plus single list
 * pointer as suggested by Josh Triplett
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/stddef.h>

/*
 * RUST PORT (lib/rhashtable.c, 6.18.49): the algorithms -- bucket-table allocation and free (with the nested tables), the incremental
 * rehash, the deferred resize worker, the insert slow path, the walker, rhashtable_init and free_and_destroy -- are in rhashtable_rs.rs.
 * This file keeps every exported entry point (its MODVERSIONS fingerprint comes from the DWARF of the definition) as a thunk, the
 * functions whose body only calls other exports (rhltable_init_noprof, rhashtable_destroy, rht_bucket_nested), the lockdep exports,
 * and one-line wrappers (rust_rhw_*) for every header inline or macro whose body depends on the configuration (the bit-spin bucket
 * lock with irq save and the lockdep map, rht_assign_unlock, mutex / spinlock / RCU / workqueue calls, the allocator calls with the
 * allocation tag, list_add / list_del, rht_head_hashfn, the compare callback, BUG_ON). A BUG raised from a wrapper names this file, not
 * rhashtable.c (recorded divergence). struct rhashtable and struct bucket_table are mirrored only where their layout cannot vary; the
 * rest is handed over as offsets. Upstream's whole file is installed as rhashtable_norust.c for CONFIG_RUST=n.
 */
static_assert(PAGE_SHIFT == 12);
static_assert(sizeof(gfp_t) == 4);
static_assert(offsetof(struct rhash_head, next) == 0 && sizeof(struct rhash_head) == 8);
static_assert(offsetof(struct rhlist_head, rhead) == 0 && offsetof(struct rhlist_head, next) == 8 && sizeof(struct rhlist_head) == 16);
static_assert(sizeof(struct list_head) == 16 && offsetof(struct list_head, next) == 0 && offsetof(struct list_head, prev) == 8);
static_assert(sizeof(struct rhashtable_params) == 40 && offsetof(struct rhashtable_params, nelem_hint) == 0 &&
	      offsetof(struct rhashtable_params, key_len) == 2 && offsetof(struct rhashtable_params, key_offset) == 4 &&
	      offsetof(struct rhashtable_params, head_offset) == 6 && offsetof(struct rhashtable_params, max_size) == 8 &&
	      offsetof(struct rhashtable_params, min_size) == 12 && offsetof(struct rhashtable_params, automatic_shrinking) == 14 &&
	      offsetof(struct rhashtable_params, hashfn) == 16 && offsetof(struct rhashtable_params, obj_hashfn) == 24 &&
	      offsetof(struct rhashtable_params, obj_cmpfn) == 32);
static_assert(offsetof(struct rhashtable, tbl) == 0 && offsetof(struct rhashtable, key_len) == 8 &&
	      offsetof(struct rhashtable, max_elems) == 12 && offsetof(struct rhashtable, p) == 16 &&
	      offsetof(struct rhashtable, rhlist) == 56);
static_assert(sizeof(atomic_t) == 4);
static_assert(offsetof(struct bucket_table, size) == 0 && offsetof(struct bucket_table, nest) == 4 &&
	      offsetof(struct bucket_table, hash_rnd) == 8 && offsetof(struct bucket_table, walkers) == 16 &&
	      offsetof(struct bucket_table, rcu) == 32 && offsetof(struct bucket_table, future_tbl) == 48);
static_assert(sizeof(struct rcu_head) == 16);
static_assert(offsetof(struct rhashtable_walker, list) == 0 && offsetof(struct rhashtable_walker, tbl) == 16);
static_assert(offsetof(struct rhashtable_iter, ht) == 0 && offsetof(struct rhashtable_iter, p) == 8 &&
	      offsetof(struct rhashtable_iter, list) == 16 && offsetof(struct rhashtable_iter, walker) == 24 &&
	      offsetof(struct rhashtable_iter, slot) == 48 && offsetof(struct rhashtable_iter, skip) == 52 &&
	      offsetof(struct rhashtable_iter, end_of_table) == 56);

/* Constants handed to the Rust. */
extern const size_t rust_rhw_buckets_off, rust_rhw_tbl_sizeof, rust_rhw_nelems_off;
extern const gfp_t rust_rhw_gfp_kernel, rust_rhw_gfp_kernel_nofail, rust_rhw_gfp_atomic_nowarn;
const size_t rust_rhw_buckets_off = offsetof(struct bucket_table, buckets);
const size_t rust_rhw_tbl_sizeof = sizeof(struct bucket_table);
const size_t rust_rhw_nelems_off = offsetof(struct rhashtable, nelems);
const gfp_t rust_rhw_gfp_kernel = GFP_KERNEL;
const gfp_t rust_rhw_gfp_kernel_nofail = GFP_KERNEL | __GFP_NOFAIL;
const gfp_t rust_rhw_gfp_atomic_nowarn = GFP_ATOMIC | __GFP_NOWARN;

/* lib/rhashtable_rs.rs */
void rust_rht_bucket_table_free(struct bucket_table *tbl);
void rust_rht_deferred_worker(struct rhashtable *ht);
void *rust_rhashtable_insert_slow(struct rhashtable *ht, const void *key, struct rhash_head *obj);
void rust_rhashtable_walk_enter(struct rhashtable *ht, struct rhashtable_iter *iter);
void rust_rhashtable_walk_exit(struct rhashtable_iter *iter);
int rust_rhashtable_walk_start_check(struct rhashtable_iter *iter);
void *rust_rhashtable_walk_next(struct rhashtable_iter *iter);
void *rust_rhashtable_walk_peek(struct rhashtable_iter *iter);
void rust_rhashtable_walk_stop(struct rhashtable_iter *iter);
int rust_rhashtable_init_noprof(struct rhashtable *ht, const struct rhashtable_params *params);
void rust_rhashtable_free_and_destroy(struct rhashtable *ht, void (*free_fn)(void *ptr, void *arg), void *arg);
struct rhash_lock_head __rcu **rust___rht_bucket_nested(const struct bucket_table *tbl, unsigned int hash);
struct rhash_lock_head __rcu **rust_rht_bucket_nested_insert(struct rhashtable *ht, struct bucket_table *tbl, unsigned int hash);

/* helpers the Rust calls: locks, RCU, allocation, lists, hashing */
unsigned long rust_rhw_lock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt);
unsigned long rust_rhw_lock_nested(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt);
void rust_rhw_unlock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt, unsigned long flags);
void rust_rhw_assign_unlock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt, struct rhash_head *obj, unsigned long flags);
u32 rust_rhw_head_hashfn(struct rhashtable *ht, const struct bucket_table *tbl, const struct rhash_head *he);
int rust_rhw_cmp(struct rhashtable *ht, const void *key, const struct rhash_head *he);
void *rust_rhw_kmalloc_page(struct rhashtable *ht);
struct bucket_table *rust_rhw_kmalloc_tbl(struct rhashtable *ht, size_t size, gfp_t gfp);
struct bucket_table *rust_rhw_kvmalloc_tbl(struct rhashtable *ht, size_t nbuckets, gfp_t gfp);
void rust_rhw_kfree(void *p);
void rust_rhw_kvfree(const void *p);
bool rust_rhw_gfp_allow_blocking(gfp_t gfp);
void rust_rhw_tbl_prepare(struct bucket_table *tbl, size_t size);
void rust_rhw_call_rcu_free(struct bucket_table *tbl);
bool rust_rhw_after_call_rcu(struct bucket_table *tbl);
void rust_rhw_mutex_lock(struct rhashtable *ht);
void rust_rhw_mutex_unlock(struct rhashtable *ht);
void rust_rhw_spin_lock(struct rhashtable *ht);
void rust_rhw_spin_unlock(struct rhashtable *ht);
void rust_rhw_schedule_work(struct rhashtable *ht);
void rust_rhw_cancel_work_sync(struct rhashtable *ht);
void rust_rhw_rcu_read_lock(void);
void rust_rhw_rcu_read_unlock(void);
void rust_rhw_list_add(struct list_head *new, struct list_head *head);
void rust_rhw_list_del(struct list_head *entry);
void rust_rhw_cond_resched(void);
void rust_rhw_assert_mutex(struct rhashtable *ht);
void rust_rhw_init_prep(struct rhashtable *ht, const struct rhashtable_params *params);
void rust_rhw_init_work(struct rhashtable *ht);
rht_hashfn_t rust_rhw_jhash_fn(void);
rht_hashfn_t rust_rhw_jhash2_fn(void);

#ifdef CONFIG_PROVE_LOCKING
#define ASSERT_RHT_MUTEX(HT) BUG_ON(!lockdep_rht_mutex_is_held(HT))

int lockdep_rht_mutex_is_held(struct rhashtable *ht)
{
	return (debug_locks) ? lockdep_is_held(&ht->mutex) : 1;
}
EXPORT_SYMBOL_GPL(lockdep_rht_mutex_is_held);

int lockdep_rht_bucket_is_held(const struct bucket_table *tbl, u32 hash)
{
	if (!debug_locks)
		return 1;
	if (unlikely(tbl->nest))
		return 1;
	return bit_spin_is_locked(0, (unsigned long *)&tbl->buckets[hash]);
}
EXPORT_SYMBOL_GPL(lockdep_rht_bucket_is_held);
#else
#define ASSERT_RHT_MUTEX(HT)
#endif

static void bucket_table_free_rcu(struct rcu_head *head)
{
	rust_rht_bucket_table_free(container_of(head, struct bucket_table, rcu));
}

static void rht_deferred_worker(struct work_struct *work)
{
	rust_rht_deferred_worker(container_of(work, struct rhashtable, run_work));
}

static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
{
	return jhash2(key, length, seed);
}

static u32 rhashtable_jhash(const void *key, u32 length, u32 seed)
{
	return jhash(key, length, seed);
}

/* ---- the wrappers ---- */

unsigned long rust_rhw_lock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt)
{
	return rht_lock(tbl, bkt);
}

unsigned long rust_rhw_lock_nested(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt)
{
	return rht_lock_nested(tbl, bkt, SINGLE_DEPTH_NESTING);
}

void rust_rhw_unlock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt, unsigned long flags)
{
	rht_unlock(tbl, bkt, flags);
}

void rust_rhw_assign_unlock(struct bucket_table *tbl, struct rhash_lock_head __rcu **bkt, struct rhash_head *obj, unsigned long flags)
{
	rht_assign_unlock(tbl, bkt, obj, flags);
}

u32 rust_rhw_head_hashfn(struct rhashtable *ht, const struct bucket_table *tbl, const struct rhash_head *he)
{
	return rht_head_hashfn(ht, tbl, he, ht->p);
}

/* 0 = the object matches the key (rhashtable_lookup_one's test, inverted: the C skips the entry when this is nonzero) */
int rust_rhw_cmp(struct rhashtable *ht, const void *key, const struct rhash_head *he)
{
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};

	return ht->p.obj_cmpfn ?
	       ht->p.obj_cmpfn(&arg, rht_obj(ht, he)) :
	       rhashtable_compare(&arg, rht_obj(ht, he));
}

void *rust_rhw_kmalloc_page(struct rhashtable *ht)
{
	return alloc_hooks_tag(ht->alloc_tag, kmalloc_noprof(PAGE_SIZE, GFP_ATOMIC|__GFP_ZERO));
}

struct bucket_table *rust_rhw_kmalloc_tbl(struct rhashtable *ht, size_t size, gfp_t gfp)
{
	return alloc_hooks_tag(ht->alloc_tag, kmalloc_noprof(size, gfp|__GFP_ZERO));
}

struct bucket_table *rust_rhw_kvmalloc_tbl(struct rhashtable *ht, size_t nbuckets, gfp_t gfp)
{
	struct bucket_table *tbl;

	return alloc_hooks_tag(ht->alloc_tag,
			kvmalloc_node_align_noprof(struct_size(tbl, buckets, nbuckets),
					     1, gfp|__GFP_ZERO, NUMA_NO_NODE));
}

void rust_rhw_kfree(void *p) { kfree(p); }
void rust_rhw_kvfree(const void *p) { kvfree(p); }
bool rust_rhw_gfp_allow_blocking(gfp_t gfp) { return gfpflags_allow_blocking(gfp); }

void rust_rhw_tbl_prepare(struct bucket_table *tbl, size_t size)
{
	static struct lock_class_key __key;

	lockdep_init_map(&tbl->dep_map, "rhashtable_bucket", &__key, 0);

	tbl->size = size;

	rcu_head_init(&tbl->rcu);
	INIT_LIST_HEAD(&tbl->walkers);

	tbl->hash_rnd = get_random_u32();
}

void rust_rhw_call_rcu_free(struct bucket_table *tbl) { call_rcu(&tbl->rcu, bucket_table_free_rcu); }
bool rust_rhw_after_call_rcu(struct bucket_table *tbl) { return rcu_head_after_call_rcu(&tbl->rcu, bucket_table_free_rcu); }
void rust_rhw_mutex_lock(struct rhashtable *ht) { mutex_lock(&ht->mutex); }
void rust_rhw_mutex_unlock(struct rhashtable *ht) { mutex_unlock(&ht->mutex); }
void rust_rhw_spin_lock(struct rhashtable *ht) { spin_lock(&ht->lock); }
void rust_rhw_spin_unlock(struct rhashtable *ht) { spin_unlock(&ht->lock); }
void rust_rhw_schedule_work(struct rhashtable *ht) { schedule_work(&ht->run_work); }
void rust_rhw_cancel_work_sync(struct rhashtable *ht) { cancel_work_sync(&ht->run_work); }
void rust_rhw_rcu_read_lock(void) { rcu_read_lock(); }
void rust_rhw_rcu_read_unlock(void) { rcu_read_unlock(); }
void rust_rhw_list_add(struct list_head *new, struct list_head *head) { list_add(new, head); }
void rust_rhw_list_del(struct list_head *entry) { list_del(entry); }
void rust_rhw_cond_resched(void) { cond_resched(); }
void rust_rhw_assert_mutex(struct rhashtable *ht) { ASSERT_RHT_MUTEX(ht); }

/* the head of rhashtable_init_noprof(): everything up to and including alloc_tag_record() */
void rust_rhw_init_prep(struct rhashtable *ht, const struct rhashtable_params *params)
{
	memset(ht, 0, sizeof(*ht));
	mutex_init(&ht->mutex);
	spin_lock_init(&ht->lock);
	memcpy(&ht->p, params, sizeof(*params));

	alloc_tag_record(ht->alloc_tag);
}

void rust_rhw_init_work(struct rhashtable *ht) { INIT_WORK(&ht->run_work, rht_deferred_worker); }
rht_hashfn_t rust_rhw_jhash_fn(void) { return rhashtable_jhash; }
rht_hashfn_t rust_rhw_jhash2_fn(void) { return rhashtable_jhash2; }

/* ---- the exports ---- */

void *rhashtable_insert_slow(struct rhashtable *ht, const void *key,
			     struct rhash_head *obj)
{
	return rust_rhashtable_insert_slow(ht, key, obj);
}
EXPORT_SYMBOL_GPL(rhashtable_insert_slow);

void rhashtable_walk_enter(struct rhashtable *ht, struct rhashtable_iter *iter)
{
	rust_rhashtable_walk_enter(ht, iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_enter);

void rhashtable_walk_exit(struct rhashtable_iter *iter)
{
	rust_rhashtable_walk_exit(iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_exit);

int rhashtable_walk_start_check(struct rhashtable_iter *iter)
	__acquires(RCU)
{
	return rust_rhashtable_walk_start_check(iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_start_check);

void *rhashtable_walk_next(struct rhashtable_iter *iter)
{
	return rust_rhashtable_walk_next(iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_next);

void *rhashtable_walk_peek(struct rhashtable_iter *iter)
{
	return rust_rhashtable_walk_peek(iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_peek);

void rhashtable_walk_stop(struct rhashtable_iter *iter)
	__releases(RCU)
{
	rust_rhashtable_walk_stop(iter);
}
EXPORT_SYMBOL_GPL(rhashtable_walk_stop);

int rhashtable_init_noprof(struct rhashtable *ht,
		    const struct rhashtable_params *params)
{
	return rust_rhashtable_init_noprof(ht, params);
}
EXPORT_SYMBOL_GPL(rhashtable_init_noprof);

int rhltable_init_noprof(struct rhltable *hlt, const struct rhashtable_params *params)
{
	int err;

	err = rhashtable_init_noprof(&hlt->ht, params);
	hlt->ht.rhlist = true;
	return err;
}
EXPORT_SYMBOL_GPL(rhltable_init_noprof);

void rhashtable_free_and_destroy(struct rhashtable *ht,
				 void (*free_fn)(void *ptr, void *arg),
				 void *arg)
{
	rust_rhashtable_free_and_destroy(ht, free_fn, arg);
}
EXPORT_SYMBOL_GPL(rhashtable_free_and_destroy);

void rhashtable_destroy(struct rhashtable *ht)
{
	return rhashtable_free_and_destroy(ht, NULL, NULL);
}
EXPORT_SYMBOL_GPL(rhashtable_destroy);

struct rhash_lock_head __rcu **__rht_bucket_nested(
	const struct bucket_table *tbl, unsigned int hash)
{
	return rust___rht_bucket_nested(tbl, hash);
}
EXPORT_SYMBOL_GPL(__rht_bucket_nested);

struct rhash_lock_head __rcu **rht_bucket_nested(
	const struct bucket_table *tbl, unsigned int hash)
{
	static struct rhash_lock_head __rcu *rhnull;

	if (!rhnull)
		INIT_RHT_NULLS_HEAD(rhnull);
	return __rht_bucket_nested(tbl, hash) ?: &rhnull;
}
EXPORT_SYMBOL_GPL(rht_bucket_nested);

struct rhash_lock_head __rcu **rht_bucket_nested_insert(
	struct rhashtable *ht, struct bucket_table *tbl, unsigned int hash)
{
	return rust_rht_bucket_nested_insert(ht, tbl, hash);
}
EXPORT_SYMBOL_GPL(rht_bucket_nested_insert);
