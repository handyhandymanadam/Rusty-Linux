// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack depot - a stack trace storage that avoids duplication.
 *
 * Internally, stack depot maintains a hash table of unique stacktraces. The
 * stack traces themselves are stored contiguously one after another in a set
 * of separate page allocations.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on the code by Dmitry Chernenkov.
 */

#define pr_fmt(fmt) "stackdepot: " fmt

#include <linux/debugfs.h>
#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kmsan.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poison.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/kasan-enabled.h>

/*
 * RUST PORT (lib/stackdepot.c, 6.18.49): the algorithms -- the lockless bucket search, the pool bookkeeping, record allocation, the freelist
 * with its RCU cookies, fetch and put -- are in stackdepot_rs.rs. This file keeps all the global state (handed to the Rust as pointers by
 * rust_sd_state()), the boot parameters and init, debugfs, print / snprint, the handle bit-field accessors, the exports as thunks (their
 * MODVERSIONS fingerprints come from the DWARF of the definition), and one-line wrappers (rust_sdw_*) for every primitive whose body
 * depends on the configuration (raw spinlock with irq save, printk_deferred, refcount_t, the RCU list helpers, the allocator, KMSAN,
 * lockdep asserts) and every WARN site (a warning now names this file -- recorded divergence). Upstream's whole file is installed as
 * stackdepot_norust.c for CONFIG_RUST=n.
 */
static_assert(sizeof(unsigned long) == 8 && sizeof(refcount_t) == 4 && sizeof(struct list_head) == 16);
static_assert(offsetof(struct stack_record, hash_list) == 0 && offsetof(struct stack_record, hash) == 16 &&
	      offsetof(struct stack_record, size) == 20 && offsetof(struct stack_record, handle) == 24 &&
	      offsetof(struct stack_record, count) == 28 && offsetof(struct stack_record, entries) == 32 &&
	      offsetof(struct stack_record, free_list) == 32 && offsetof(struct stack_record, rcu_state) == 48);
static_assert(sizeof(union handle_parts) == 4);

struct rust_sd_state_s {
	void *pool_lock;
	struct list_head *free_stacks;
	void **new_pool;
	int *pools_num;
	size_t *pool_offset;
	void ***stack_pools;
	long *counters;
	struct list_head **stack_table;
	unsigned int *stack_hash_mask;
	unsigned int *stack_max_pools;
	bool *disabled;
};
extern const size_t rust_sd_record_size, rust_sd_max_frames, rust_sd_pool_size, rust_sd_poison;
extern const unsigned int rust_sd_stack_align;
const size_t rust_sd_record_size = sizeof(struct stack_record);
const size_t rust_sd_max_frames = CONFIG_STACKDEPOT_MAX_FRAMES;
const size_t rust_sd_pool_size = DEPOT_POOL_SIZE;
const size_t rust_sd_poison = (size_t)STACK_DEPOT_POISON;
const unsigned int rust_sd_stack_align = DEPOT_STACK_ALIGN;

/* lib/stackdepot_rs.rs */
depot_stack_handle_t rust_stack_depot_save_flags(unsigned long *entries, unsigned int nr_entries, gfp_t alloc_flags, depot_flags_t depot_flags);
struct stack_record *rust_stack_depot_get_stack_record(depot_stack_handle_t handle);
unsigned int rust_stack_depot_fetch(depot_stack_handle_t handle, unsigned long **entries);
void rust_stack_depot_put(depot_stack_handle_t handle);

/*
 * The pool_index is offset by 1 so the first record does not have a 0 handle.
 */
static unsigned int stack_max_pools __read_mostly =
	MIN((1LL << DEPOT_POOL_INDEX_BITS) - 1, 8192);

static bool stack_depot_disabled;
static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
static bool __stack_depot_early_init_passed __initdata;

/* Use one hash table bucket per 16 KB of memory. */
#define STACK_HASH_TABLE_SCALE 14
/* Limit the number of buckets between 4K and 1M. */
#define STACK_BUCKET_NUMBER_ORDER_MIN 12
#define STACK_BUCKET_NUMBER_ORDER_MAX 20
/* Initial seed for jhash2. */
#define STACK_HASH_SEED 0x9747b28c

/* Hash table of stored stack records. */
static struct list_head *stack_table;
/* Fixed order of the number of table buckets. Used when KASAN is enabled. */
static unsigned int stack_bucket_number_order;
/* Hash mask for indexing the table. */
static unsigned int stack_hash_mask;

/* Array of memory regions that store stack records. */
static void **stack_pools;
/* Newly allocated pool that is not yet added to stack_pools. */
static void *new_pool;
/* Number of pools in stack_pools. */
static int pools_num;
/* Offset to the unused space in the currently used pool. */
static size_t pool_offset = DEPOT_POOL_SIZE;
/* Freelist of stack records within stack_pools. */
static LIST_HEAD(free_stacks);
/* The lock must be held when performing pool or freelist modifications. */
static DEFINE_RAW_SPINLOCK(pool_lock);

/* Statistics counters for debugfs. */
enum depot_counter_id {
	DEPOT_COUNTER_REFD_ALLOCS,
	DEPOT_COUNTER_REFD_FREES,
	DEPOT_COUNTER_REFD_INUSE,
	DEPOT_COUNTER_FREELIST_SIZE,
	DEPOT_COUNTER_PERSIST_COUNT,
	DEPOT_COUNTER_PERSIST_BYTES,
	DEPOT_COUNTER_COUNT,
};
static long counters[DEPOT_COUNTER_COUNT];
static const char *const counter_names[] = {
	[DEPOT_COUNTER_REFD_ALLOCS]	= "refcounted_allocations",
	[DEPOT_COUNTER_REFD_FREES]	= "refcounted_frees",
	[DEPOT_COUNTER_REFD_INUSE]	= "refcounted_in_use",
	[DEPOT_COUNTER_FREELIST_SIZE]	= "freelist_size",
	[DEPOT_COUNTER_PERSIST_COUNT]	= "persistent_count",
	[DEPOT_COUNTER_PERSIST_BYTES]	= "persistent_bytes",
};
static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);

static struct rust_sd_state_s sd_state;
const struct rust_sd_state_s *rust_sd_state(void);
const struct rust_sd_state_s *rust_sd_state(void)
{
	/* the globals never move; every call writes the same values, so a race between first calls is harmless */
	sd_state = (struct rust_sd_state_s){ &pool_lock, &free_stacks, &new_pool, &pools_num, &pool_offset, &stack_pools, counters, &stack_table,
					      &stack_hash_mask, &stack_max_pools, &stack_depot_disabled };
	return &sd_state;
}

unsigned long rust_sdw_lock_irqsave(void *lock);
bool rust_sdw_trylock_irqsave(void *lock, unsigned long *flags);
void rust_sdw_unlock_irqrestore(void *lock, unsigned long flags);
void rust_sdw_printk_deferred_enter(void);
void rust_sdw_printk_deferred_exit(void);
void rust_sdw_assert_held(void *lock);
void rust_sdw_assert_not_held(void *lock);
u32 rust_sdw_hash(unsigned long *entries, unsigned int size);
void rust_sdw_refcount_set(u32 *r, unsigned int v);
unsigned int rust_sdw_refcount_read(const u32 *r);
bool rust_sdw_refcount_inc_not_zero(u32 *r);
bool rust_sdw_refcount_dec_and_test(u32 *r);
void rust_sdw_list_add_rcu(struct list_head *new, struct list_head *head);
void rust_sdw_list_del_rcu(struct list_head *entry);
void rust_sdw_list_add_tail(struct list_head *new, struct list_head *head);
void rust_sdw_list_del(struct list_head *entry);
void rust_sdw_rcu_read_lock_sched_notrace(void);
void rust_sdw_rcu_read_unlock_sched_notrace(void);
unsigned long rust_sdw_get_state_synchronize_rcu(void);
bool rust_sdw_poll_state_synchronize_rcu(unsigned long cookie);
void rust_sdw_kmsan_unpoison(void *p, size_t size);
bool rust_sdw_in_nmi(void);
bool rust_sdw_allow_spinning(gfp_t gfp);
void *rust_sdw_alloc_pool(gfp_t gfp);
void rust_sdw_free_pool(void *p, bool nolock);
unsigned int rust_sdw_filter_irq_stacks(unsigned long *entries, unsigned int nr);
void rust_sdw_init_handle(void *stack, u32 pool_index_plus_1, u32 offset_units);
void rust_sdw_handle_split(u32 handle, u32 *pool_index_plus_1, u32 *offset_units);
void rust_sdw_warn_init_pool_gt(bool cond);
void rust_sdw_warn_init_pool_nonew(bool cond);
void rust_sdw_warn_limit(void);
bool rust_sdw_warn_pools_lt1(bool cond);
bool rust_sdw_warn_no_pool(bool cond);
void rust_sdw_warn_record_size(bool cond);
bool rust_sdw_warn_no_entries(bool cond);
void rust_sdw_warn_index(u32 pool_index, int pools_num, u32 handle);
bool rust_sdw_warn_nopool_ptr(bool cond);
bool rust_sdw_warn_zero_count(bool cond);
bool rust_sdw_warn_flags(bool cond);
void rust_sdw_warn_nmi_alloc(bool cond);
bool rust_sdw_warn_corrupt_fetch(bool cond);
bool rust_sdw_warn_corrupt_put(bool cond);

unsigned long rust_sdw_lock_irqsave(void *lock) { unsigned long flags; raw_spin_lock_irqsave((raw_spinlock_t *)lock, flags); return flags; }
bool rust_sdw_trylock_irqsave(void *lock, unsigned long *flags) { return raw_spin_trylock_irqsave((raw_spinlock_t *)lock, *flags); }
void rust_sdw_unlock_irqrestore(void *lock, unsigned long flags) { raw_spin_unlock_irqrestore((raw_spinlock_t *)lock, flags); }
void rust_sdw_printk_deferred_enter(void) { printk_deferred_enter(); }
void rust_sdw_printk_deferred_exit(void) { printk_deferred_exit(); }
void rust_sdw_assert_held(void *lock) { lockdep_assert_held((raw_spinlock_t *)lock); }
void rust_sdw_assert_not_held(void *lock) { lockdep_assert_not_held((raw_spinlock_t *)lock); }
u32 rust_sdw_hash(unsigned long *entries, unsigned int size)
{
	return jhash2((u32 *)entries, array_size(size, sizeof(*entries)) / sizeof(u32), STACK_HASH_SEED);
}
void rust_sdw_refcount_set(u32 *r, unsigned int v) { refcount_set((refcount_t *)r, (int)v); }
unsigned int rust_sdw_refcount_read(const u32 *r) { return refcount_read((const refcount_t *)r); }
bool rust_sdw_refcount_inc_not_zero(u32 *r) { return refcount_inc_not_zero((refcount_t *)r); }
bool rust_sdw_refcount_dec_and_test(u32 *r) { return refcount_dec_and_test((refcount_t *)r); }
void rust_sdw_list_add_rcu(struct list_head *new, struct list_head *head) { list_add_rcu(new, head); }
void rust_sdw_list_del_rcu(struct list_head *entry) { list_del_rcu(entry); }
void rust_sdw_list_add_tail(struct list_head *new, struct list_head *head) { list_add_tail(new, head); }
void rust_sdw_list_del(struct list_head *entry) { list_del(entry); }
void rust_sdw_rcu_read_lock_sched_notrace(void) { rcu_read_lock_sched_notrace(); }
void rust_sdw_rcu_read_unlock_sched_notrace(void) { rcu_read_unlock_sched_notrace(); }
unsigned long rust_sdw_get_state_synchronize_rcu(void) { return get_state_synchronize_rcu(); }
bool rust_sdw_poll_state_synchronize_rcu(unsigned long cookie) { return poll_state_synchronize_rcu(cookie); }
void rust_sdw_kmsan_unpoison(void *p, size_t size) { kmsan_unpoison_memory(p, size); }
bool rust_sdw_in_nmi(void) { return in_nmi(); }
bool rust_sdw_allow_spinning(gfp_t gfp) { return gfpflags_allow_spinning(gfp); }
void *rust_sdw_alloc_pool(gfp_t gfp)
{
	struct page *page = alloc_pages(gfp_nested_mask(gfp), DEPOT_POOL_ORDER);

	return page ? page_address(page) : NULL;
}
void rust_sdw_free_pool(void *p, bool nolock)
{
	if (nolock)
		free_pages_nolock(virt_to_page(p), DEPOT_POOL_ORDER);
	else
		free_pages((unsigned long)p, DEPOT_POOL_ORDER);
}
unsigned int rust_sdw_filter_irq_stacks(unsigned long *entries, unsigned int nr) { return filter_irq_stacks(entries, nr); }
void rust_sdw_init_handle(void *stack, u32 pool_index_plus_1, u32 offset_units)
{
	struct stack_record *s = stack;

	s->handle.pool_index_plus_1 = pool_index_plus_1;
	s->handle.offset = offset_units;
	s->handle.extra = 0;
}
void rust_sdw_handle_split(u32 handle, u32 *pool_index_plus_1, u32 *offset_units)
{
	union handle_parts parts = { .handle = handle };

	*pool_index_plus_1 = parts.pool_index_plus_1;
	*offset_units = parts.offset;
}
void rust_sdw_warn_init_pool_gt(bool cond) { WARN_ON_ONCE(cond); }
void rust_sdw_warn_init_pool_nonew(bool cond) { WARN_ON_ONCE(cond); }
void rust_sdw_warn_limit(void) { WARN_ONCE(1, "Stack depot reached limit capacity"); }
bool rust_sdw_warn_pools_lt1(bool cond) { return WARN_ON_ONCE(cond); }
bool rust_sdw_warn_no_pool(bool cond) { return WARN_ON_ONCE(cond); }
void rust_sdw_warn_record_size(bool cond) { WARN_ON_ONCE(cond); }
bool rust_sdw_warn_no_entries(bool cond) { return WARN_ON_ONCE(cond); }
void rust_sdw_warn_index(u32 pool_index, int pools_num, u32 handle)
{
	WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n", pool_index, pools_num, handle);
}
bool rust_sdw_warn_nopool_ptr(bool cond) { return WARN_ON(cond); }
bool rust_sdw_warn_zero_count(bool cond) { return WARN_ON(cond); }
bool rust_sdw_warn_flags(bool cond) { return WARN_ON(cond); }
void rust_sdw_warn_nmi_alloc(bool cond) { WARN_ON_ONCE(cond); }
bool rust_sdw_warn_corrupt_fetch(bool cond) { return WARN(cond, "corrupt handle or use after stack_depot_put()"); }
bool rust_sdw_warn_corrupt_put(bool cond) { return WARN(cond, "corrupt handle or unbalanced stack_depot_put()"); }

static int __init disable_stack_depot(char *str)
{
	return kstrtobool(str, &stack_depot_disabled);
}
early_param("stack_depot_disable", disable_stack_depot);

static int __init parse_max_pools(char *str)
{
	const long long limit = (1LL << (DEPOT_POOL_INDEX_BITS)) - 1;
	unsigned int max_pools;
	int rv;

	rv = kstrtouint(str, 0, &max_pools);
	if (rv)
		return rv;

	if (max_pools < 1024) {
		pr_err("stack_depot_max_pools below 1024, using default of %u\n",
		       stack_max_pools);
		goto out;
	}

	if (max_pools > limit) {
		pr_err("stack_depot_max_pools exceeds %lld, using default of %u\n",
		       limit, stack_max_pools);
		goto out;
	}

	stack_max_pools = max_pools;
out:
	return 0;
}
early_param("stack_depot_max_pools", parse_max_pools);

void __init stack_depot_request_early_init(void)
{
	/* Too late to request early init now. */
	WARN_ON(__stack_depot_early_init_passed);

	__stack_depot_early_init_requested = true;
}

/* Initialize list_head's within the hash table. */
static void init_stack_table(unsigned long entries)
{
	unsigned long i;

	for (i = 0; i < entries; i++)
		INIT_LIST_HEAD(&stack_table[i]);
}

/* Allocates a hash table via memblock. Can only be used during early boot. */
int __init stack_depot_early_init(void)
{
	unsigned long entries = 0;

	/* This function must be called only once, from mm_init(). */
	if (WARN_ON(__stack_depot_early_init_passed))
		return 0;
	__stack_depot_early_init_passed = true;

	/*
	 * Print disabled message even if early init has not been requested:
	 * stack_depot_init() will not print one.
	 */
	if (stack_depot_disabled) {
		pr_info("disabled\n");
		return 0;
	}

	/*
	 * If KASAN is enabled, use the maximum order: KASAN is frequently used
	 * in fuzzing scenarios, which leads to a large number of different
	 * stack traces being stored in stack depot.
	 */
	if (kasan_enabled() && !stack_bucket_number_order)
		stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;

	/*
	 * Check if early init has been requested after setting
	 * stack_bucket_number_order: stack_depot_init() uses its value.
	 */
	if (!__stack_depot_early_init_requested)
		return 0;

	/*
	 * If stack_bucket_number_order is not set, leave entries as 0 to rely
	 * on the automatic calculations performed by alloc_large_system_hash().
	 */
	if (stack_bucket_number_order)
		entries = 1UL << stack_bucket_number_order;
	pr_info("allocating hash table via alloc_large_system_hash\n");
	stack_table = alloc_large_system_hash("stackdepot",
						sizeof(struct list_head),
						entries,
						STACK_HASH_TABLE_SCALE,
						HASH_EARLY,
						NULL,
						&stack_hash_mask,
						1UL << STACK_BUCKET_NUMBER_ORDER_MIN,
						1UL << STACK_BUCKET_NUMBER_ORDER_MAX);
	if (!stack_table) {
		pr_err("hash table allocation failed, disabling\n");
		stack_depot_disabled = true;
		return -ENOMEM;
	}
	if (!entries) {
		/*
		 * Obtain the number of entries that was calculated by
		 * alloc_large_system_hash().
		 */
		entries = stack_hash_mask + 1;
	}
	init_stack_table(entries);

	pr_info("allocating space for %u stack pools via memblock\n",
		stack_max_pools);
	stack_pools =
		memblock_alloc(stack_max_pools * sizeof(void *), PAGE_SIZE);
	if (!stack_pools) {
		pr_err("stack pools allocation failed, disabling\n");
		memblock_free(stack_table, entries * sizeof(struct list_head));
		stack_depot_disabled = true;
		return -ENOMEM;
	}

	return 0;
}

/* Allocates a hash table via kvcalloc. Can be used after boot. */
int stack_depot_init(void)
{
	static DEFINE_MUTEX(stack_depot_init_mutex);
	unsigned long entries;
	int ret = 0;

	mutex_lock(&stack_depot_init_mutex);

	if (stack_depot_disabled || stack_table)
		goto out_unlock;

	/*
	 * Similarly to stack_depot_early_init, use stack_bucket_number_order
	 * if assigned, and rely on automatic scaling otherwise.
	 */
	if (stack_bucket_number_order) {
		entries = 1UL << stack_bucket_number_order;
	} else {
		int scale = STACK_HASH_TABLE_SCALE;

		entries = nr_free_buffer_pages();
		entries = roundup_pow_of_two(entries);

		if (scale > PAGE_SHIFT)
			entries >>= (scale - PAGE_SHIFT);
		else
			entries <<= (PAGE_SHIFT - scale);
	}

	if (entries < 1UL << STACK_BUCKET_NUMBER_ORDER_MIN)
		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MIN;
	if (entries > 1UL << STACK_BUCKET_NUMBER_ORDER_MAX)
		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;

	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
	stack_table = kvcalloc(entries, sizeof(struct list_head), GFP_KERNEL);
	if (!stack_table) {
		pr_err("hash table allocation failed, disabling\n");
		stack_depot_disabled = true;
		ret = -ENOMEM;
		goto out_unlock;
	}
	stack_hash_mask = entries - 1;
	init_stack_table(entries);

	pr_info("allocating space for %u stack pools via kvcalloc\n",
		stack_max_pools);
	stack_pools = kvcalloc(stack_max_pools, sizeof(void *), GFP_KERNEL);
	if (!stack_pools) {
		pr_err("stack pools allocation failed, disabling\n");
		kvfree(stack_table);
		stack_depot_disabled = true;
		ret = -ENOMEM;
	}

out_unlock:
	mutex_unlock(&stack_depot_init_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(stack_depot_init);

/*
 * Initializes new stack pool, and updates the list of pools.
 */
/* Keeps the preallocated memory to be used for a new stack depot pool. */
/*
 * Try to initialize a new stack record from the current pool, a cached pool, or
 * the current pre-allocation.
 */
/* Try to find next free usable entry from the freelist. */
/* Allocates a new stack in a stack depot pool. */
/* Links stack into the freelist. */
/* Calculates the hash for a stack. */
/*
 * Non-instrumented version of memcmp().
 * Does not check the lexicographical order, only the equality.
 */
/* Finds a stack in a bucket of the hash table. */
depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
					    unsigned int nr_entries,
					    gfp_t alloc_flags,
					    depot_flags_t depot_flags)
{
	return rust_stack_depot_save_flags(entries, nr_entries, alloc_flags, depot_flags);
}
EXPORT_SYMBOL_GPL(stack_depot_save_flags);

depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries,
				      gfp_t alloc_flags)
{
	return stack_depot_save_flags(entries, nr_entries, alloc_flags,
				      STACK_DEPOT_FLAG_CAN_ALLOC);
}
EXPORT_SYMBOL_GPL(stack_depot_save);

struct stack_record *__stack_depot_get_stack_record(depot_stack_handle_t handle)
{
	return rust_stack_depot_get_stack_record(handle);
}

unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries)
{
	return rust_stack_depot_fetch(handle, entries);
}
EXPORT_SYMBOL_GPL(stack_depot_fetch);

void stack_depot_put(depot_stack_handle_t handle)
{
	rust_stack_depot_put(handle);
}
EXPORT_SYMBOL_GPL(stack_depot_put);

void stack_depot_print(depot_stack_handle_t stack)
{
	unsigned long *entries;
	unsigned int nr_entries;

	nr_entries = stack_depot_fetch(stack, &entries);
	if (nr_entries > 0)
		stack_trace_print(entries, nr_entries, 0);
}
EXPORT_SYMBOL_GPL(stack_depot_print);

int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
		       int spaces)
{
	unsigned long *entries;
	unsigned int nr_entries;

	nr_entries = stack_depot_fetch(handle, &entries);
	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
						spaces) : 0;
}
EXPORT_SYMBOL_GPL(stack_depot_snprint);

depot_stack_handle_t __must_check stack_depot_set_extra_bits(
			depot_stack_handle_t handle, unsigned int extra_bits)
{
	union handle_parts parts = { .handle = handle };

	/* Don't set extra bits on empty handles. */
	if (!handle)
		return 0;

	parts.extra = extra_bits;
	return parts.handle;
}
EXPORT_SYMBOL(stack_depot_set_extra_bits);

unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };

	return parts.extra;
}
EXPORT_SYMBOL(stack_depot_get_extra_bits);

static int stats_show(struct seq_file *seq, void *v)
{
	/*
	 * data race ok: These are just statistics counters, and approximate
	 * statistics are ok for debugging.
	 */
	seq_printf(seq, "pools: %d\n", data_race(pools_num));
	for (int i = 0; i < DEPOT_COUNTER_COUNT; i++)
		seq_printf(seq, "%s: %ld\n", counter_names[i], data_race(counters[i]));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(stats);

static int depot_debugfs_init(void)
{
	struct dentry *dir;

	if (stack_depot_disabled)
		return 0;

	dir = debugfs_create_dir("stackdepot", NULL);
	debugfs_create_file("stats", 0444, dir, NULL, &stats_fops);
	return 0;
}
late_initcall(depot_debugfs_init);
