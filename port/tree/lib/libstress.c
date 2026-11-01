// SPDX-License-Identifier: GPL-2.0
/*
 * lib/ concurrency stress harness (criterion 4 of logs/concurrency-bar.md).
 *
 * A kthread-per-CPU harness: N threads, each bound to one CPU, hammer one
 * TARGET for a fixed time, then the harness checks an invariant and prints
 * `libstress:` lines. It is OFF unless the kernel command line asks:
 *
 *   libstress.run=<seconds>     0 (default) = do nothing, print nothing
 *   libstress.cpus=<n>          threads (default: online CPUs)
 *   libstress.target=<name>     "spinlock", "lockref", "kfifo", "genalloc", "assoc_array", "radix_tree", "maple_tree", "rhashtable", "rcuref", "stackdepot", "sbitmap", "refcount", "lwq", "notifier", "ucount" or "percpu_ref"
 *   libstress.sabotage=1        remove the target's lock: the run MUST fail
 *   libstress.probe=<list>      one-shot checker probes, each of which MUST
 *                               make the matching kernel checker report:
 *                               lockdep (ABBA), sleep (might_sleep under a
 *                               spinlock), rcu (rcu_dereference outside a
 *                               read-side section), kasan (1 byte past a
 *                               kmalloc(8)). Comma separated.
 *
 * It is built only with CONFIG_LIB_STRESS (default n, in no normal
 * fragment), so the normal builds do not contain it. It does not test
 * correctness of any port; it gives the kernel's own checkers (lockdep,
 * KASAN, KCSAN, PROVE_RCU, atomic-sleep) concurrent traffic to look at.
 *
 * Adding a target: fill a struct libstress_target (init/op/check) and add it
 * to targets[]. op() runs in a tight loop on every thread; check() gets the
 * summed per-thread op count and returns 0 when the invariant holds.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/cpumask.h>
#include <linux/lockref.h>
#include <linux/kfifo.h>
#include <linux/genalloc.h>
#include <linux/assoc_array.h>
#include <linux/radix-tree.h>
#include <linux/maple_tree.h>
#include <linux/rhashtable.h>
#include <linux/rcuref.h>
#include <linux/stackdepot.h>
#include <linux/sbitmap.h>
#include <linux/refcount.h>
#include <linux/lwq.h>
#include <linux/notifier.h>
#include <linux/user_namespace.h>
#include <linux/rcuref.h>
#include <linux/percpu-refcount.h>
#include <linux/bitmap.h>
#include <linux/random.h>

#undef pr_fmt
#define pr_fmt(fmt) "libstress: " fmt

static unsigned int run_seconds;
module_param_named(run, run_seconds, uint, 0444);
static unsigned int nthreads;
module_param_named(cpus, nthreads, uint, 0444);
static char *target_name = "spinlock";
module_param_named(target, target_name, charp, 0444);
static bool sabotage;
module_param_named(sabotage, sabotage, bool, 0444);
static char *probe_list;
module_param_named(probe, probe_list, charp, 0444);

struct libstress_target {
	const char *name;
	void (*init)(void);
	void (*op)(bool sabotage);
	/* 0 = invariant holds; msg describes the violation */
	int (*check)(u64 total_ops, char *msg, size_t len);
};

/* ---- target "spinlock": a counter that is only correct under its lock ---- */

static DEFINE_SPINLOCK(sl_lock);
static unsigned long sl_counter;	/* deliberately plain: KCSAN must see it */

static void sl_init(void)
{
	sl_counter = 0;
}

static void sl_op(bool sab)
{
	unsigned long tmp;

	if (!sab)
		spin_lock(&sl_lock);
	/*
	 * Read-modify-write split by cpu_relax() so a missing lock loses
	 * updates reliably instead of rarely. Same code in both modes.
	 */
	tmp = sl_counter;
	cpu_relax();
	sl_counter = tmp + 1;
	if (!sab)
		spin_unlock(&sl_lock);
}

static int sl_check(u64 total, char *msg, size_t len)
{
	if (sl_counter == total)
		return 0;
	snprintf(msg, len, "counter %lu != ops %llu (lost %lld updates)",
		 sl_counter, total, (long long)(total - sl_counter));
	return -EIO;
}

/* ---- target "lockref": lib/lockref.c, the lock-free fast path of lockref_rs.rs (and the spinlock fallback paths) ----
 *
 * One shared lockref. Each op takes three references and gives three back, mixing the five entry points, so the NET effect of every op is
 * zero and the final count must equal the start value; lockref_put_or_lock() refusing (count <= 1) cannot happen (the count is ~1e6), but
 * its lock-held return path is taken when a competitor holds the lock, and then the op drops the reference by hand under that lock;
 * lockref_put_return() may return -1 under contention (the API has no lock fallback) and the op then drops it under the lock too.
 * Sabotage: the references are taken and dropped with a plain read / cpu_relax / write instead of the lockref functions: lost updates
 * MUST show as a count != start. The spinlock is NOT taken in sabotage mode, so lockref's own lock is never contended there.
 */

#define LR_START 1000000

static struct lockref lr_ref;

static void lr_init(void)
{
	lockref_init(&lr_ref);
	lr_ref.count = LR_START;
}

static void lr_op(bool sab)
{
	if (sab) {
		int tmp = lr_ref.count;

		cpu_relax();
		lr_ref.count = tmp + 1;
		tmp = lr_ref.count;
		cpu_relax();
		lr_ref.count = tmp - 1;
		return;
	}
	lockref_get(&lr_ref);
	if (!lockref_get_not_zero(&lr_ref))
		lr_ref.count = -1000;			/* impossible: poison */
	if (!lockref_get_not_dead(&lr_ref))
		lr_ref.count = -2000;
	if (lockref_put_return(&lr_ref) < 0) {
		/* the API allows -1 under contention (no lock fallback by design): drop the reference under the lock */
		spin_lock(&lr_ref.lock);
		lr_ref.count--;
		spin_unlock(&lr_ref.lock);
	}
	if (!lockref_put_or_lock(&lr_ref)) {
		lr_ref.count--;			/* refused: we hold the lock, drop the reference by hand */
		spin_unlock(&lr_ref.lock);
	}
	if (!lockref_put_or_lock(&lr_ref)) {
		lr_ref.count--;
		spin_unlock(&lr_ref.lock);
	}
}

static int lr_check(u64 total, char *msg, size_t len)
{
	if (lr_ref.count == LR_START && !spin_is_locked(&lr_ref.lock))
		return 0;
	snprintf(msg, len, "lockref count %d != %d (or lock left held: %d) after %llu ops",
		 lr_ref.count, LR_START, spin_is_locked(&lr_ref.lock), total);
	return -EIO;
}

/* ---- target "kfifo": lib/kfifo.c record FIFO, one producer (CPU 0) and one consumer (CPU 1), no lock ----
 *
 * The structure kfifo exists to make safe without a lock. The producer (the thread bound to CPU 0) puts records of 1..40 bytes
 * (byte 0 = length, byte i = low byte of the stream position + i); the consumer (CPU 1) takes them out and checks the length byte and
 * the content in order. Other CPUs do nothing. check(): drain what is left, then bytes consumed == bytes produced and no mismatch.
 * Sabotage: the producer publishes the record's length prefix and index BEFORE it has written the data (it calls __kfifo_in_r on a
 * buffer it fills AFTER the call), so the consumer must see garbage or a wrong length.
 */

static struct __kfifo kf_fifo;
static u8 kf_buf[1 << 12];
static u64 kf_produced, kf_consumed, kf_bad;
static u64 kf_pseq, kf_cseq;

static void kf_init(void)
{
	kf_produced = kf_consumed = kf_bad = kf_pseq = kf_cseq = 0;
	__kfifo_init(&kf_fifo, kf_buf, sizeof(kf_buf), 1);
}

static void kf_op(bool sab)
{
	unsigned int cpu = raw_smp_processor_id();
	u8 rec[48];

	if (cpu == 0) {
		unsigned int len = 1 + (unsigned int)((kf_pseq * 2654435761u) >> 7) % 40, i;

		if (sab) {
			/* publish first, fill after: the record is visible with whatever the buffer held */
			if (__kfifo_in_r(&kf_fifo, rec, len, 1) == len) {
				kf_pseq += len;
				kf_produced += len;
			}
			return;
		}
		rec[0] = len;
		for (i = 1; i < len; i++)
			rec[i] = (u8)(kf_pseq + i);
		if (__kfifo_in_r(&kf_fifo, rec, len, 1) == len) {
			kf_pseq += len;
			kf_produced += len;
		}
	} else if (cpu == 1) {
		unsigned int n = __kfifo_out_r(&kf_fifo, rec, sizeof(rec), 1), i;

		if (n) {
			if (rec[0] != n)
				kf_bad++;
			for (i = 1; i < n; i++)
				if (rec[i] != (u8)(kf_cseq + i)) {
					kf_bad++;
					break;
				}
			kf_cseq += n;
			kf_consumed += n;
		}
	}
}

static int kf_check(u64 total, char *msg, size_t len)
{
	u8 rec[48];
	unsigned int n;

	while ((n = __kfifo_out_r(&kf_fifo, rec, sizeof(rec), 1))) {
		if (rec[0] != n)
			kf_bad++;
		kf_cseq += n;
		kf_consumed += n;
	}
	if (!kf_bad && kf_produced == kf_consumed && kf_produced)
		return 0;
	snprintf(msg, len, "kfifo: produced %llu consumed %llu bad %llu after %llu ops", kf_produced, kf_consumed, kf_bad, total);
	return -EIO;
}


/* ---- target "genalloc": lib/genalloc.c, the lock-free bitmap helpers of genalloc_rs.rs (and the allocation algorithms) ----
 *
 * One pool of 512 one-byte units. Each op takes three blocks of 1..40 units from it (first fit, best fit or order-aligned, at random),
 * claims every unit in a shared ownership table with an exchange (a unit that was already owned means two allocations overlapped: bad++),
 * then releases the claim and gives the block back. Pool exhaustion just skips a block. check(): no overlap seen, the chunk bitmap is
 * empty again and avail is back to 512.
 * Sabotage: blocks are given back with a plain read / cpu_relax / write of the chunk's bitmap word instead of gen_pool_free(): another CPU's
 * bit set in between is lost, which shows as an overlap or a stuck bit. (avail is still adjusted by atomic add, so only the bitmap races.)
 */
#define GA_UNITS 512
#define GA_BASE 0x100000UL
static struct gen_pool *ga_pool;
static u8 ga_owner[GA_UNITS];
static atomic_t ga_bad;

static void ga_init(void)
{
	if (ga_pool)
		gen_pool_destroy(ga_pool);
	ga_pool = gen_pool_create(0, -1);
	if (ga_pool && gen_pool_add(ga_pool, GA_BASE, GA_UNITS, -1))
		ga_pool = NULL;
	memset(ga_owner, 0, sizeof(ga_owner));
	atomic_set(&ga_bad, ga_pool ? 0 : 1);
}

static void ga_free_sab(unsigned long addr, size_t n)
{
	struct gen_pool_chunk *c = list_first_entry(&ga_pool->chunks, struct gen_pool_chunk, next_chunk);
	unsigned long b, first = addr - c->start_addr;

	for (b = first; b < first + n; b++) {
		unsigned long *w = &c->bits[BIT_WORD(b)];
		unsigned long v = *w;

		cpu_relax();
		*w = v & ~BIT_MASK(b);
	}
	atomic_long_add(n, &c->avail);
}

static void ga_op(bool sab)
{
	unsigned long a[3];
	size_t n[3];
	int i;
	unsigned long j;

	for (i = 0; i < 3; i++) {
		n[i] = 1 + get_random_u32() % 40;
		switch (get_random_u32() % 3) {
		case 0:
			a[i] = gen_pool_alloc(ga_pool, n[i]);
			break;
		case 1:
			a[i] = gen_pool_alloc_algo(ga_pool, n[i], gen_pool_best_fit, NULL);
			break;
		default:
			a[i] = gen_pool_alloc_algo(ga_pool, n[i], gen_pool_first_fit_order_align, NULL);
			break;
		}
		if (!a[i])
			continue;
		for (j = a[i] - GA_BASE; j < a[i] - GA_BASE + n[i]; j++)
			if (xchg(&ga_owner[j], 1))
				atomic_inc(&ga_bad);
	}
	for (i = 0; i < 3; i++) {
		if (!a[i])
			continue;
		for (j = a[i] - GA_BASE; j < a[i] - GA_BASE + n[i]; j++)
			if (!xchg(&ga_owner[j], 0))
				atomic_inc(&ga_bad);
		if (sab)
			ga_free_sab(a[i], n[i]);
		else
			gen_pool_free(ga_pool, a[i], n[i]);
	}
}

static int ga_check(u64 total, char *msg, size_t len)
{
	struct gen_pool_chunk *c;

	if (!ga_pool) {
		snprintf(msg, len, "genalloc: pool could not be created");
		return -ENOMEM;
	}
	c = list_first_entry(&ga_pool->chunks, struct gen_pool_chunk, next_chunk);
	if (!atomic_read(&ga_bad) && bitmap_empty(c->bits, GA_UNITS) && gen_pool_avail(ga_pool) == GA_UNITS)
		return 0;
	snprintf(msg, len, "genalloc: overlaps %d, bitmap empty %d, avail %zu of %d after %llu ops", atomic_read(&ga_bad),
		 bitmap_empty(c->bits, GA_UNITS), gen_pool_avail(ga_pool), GA_UNITS, total);
	return -EIO;
}


/* ---- target "assoc_array": lib/assoc_array.c, readers under RCU against one writer ----
 *
 * The structure exists so that readers need no lock: the writer builds every change off to the side, publishes it with a few stores,
 * and the old pieces are freed by call_rcu() after a grace period. CPU 0 is the writer: it inserts and deletes "churn" keys 1000..1063
 * (random order, replacing as well). Every other CPU is a reader inside rcu_read_lock(): the 32 "stable" keys 1..32 (inserted at init,
 * never touched again) must ALWAYS be found with the right content, and a churn object it finds is dereferenced AGAIN after a short
 * busy wait -- if the writer's cleanup freed it too early, KASAN reports a use-after-free there.
 * Sabotage: the readers take no rcu_read_lock() and sleep 30 ms while holding a churn object; the writer keeps deleting, so the
 * object's cleanup runs while the reader still holds it: KASAN must report the use-after-free.
 */
struct as_obj { unsigned long key; };
static struct assoc_array as_arr;
static atomic_t as_bad;
static unsigned long as_chunk(const void *k, int level) { return level >= 64 ? 0 : *(const unsigned long *)k; }
static unsigned long as_obj_chunk(const void *o, int level) { return level >= 64 ? 0 : ((const struct as_obj *)o)->key; }
static bool as_cmp(const void *o, const void *k) { return ((const struct as_obj *)o)->key == *(const unsigned long *)k; }
static int as_diff(const void *o, const void *k)
{
	unsigned long x = ((const struct as_obj *)o)->key ^ *(const unsigned long *)k;

	return x ? __ffs(x) : -1;
}
static void as_free(void *o) { kfree(o); }
static const struct assoc_array_ops as_ops = { as_chunk, as_obj_chunk, as_cmp, as_diff, as_free };

static void as_put(unsigned long key)
{
	struct as_obj *o = kzalloc(sizeof(*o), GFP_KERNEL);
	struct assoc_array_edit *e;

	if (!o)
		return;
	o->key = key;
	e = assoc_array_insert(&as_arr, &as_ops, &key, o);
	if (IS_ERR(e)) {
		kfree(o);
		return;
	}
	assoc_array_apply_edit(e);
}

static void as_init(void)
{
	unsigned long k;

	rcu_barrier();
	assoc_array_destroy(&as_arr, &as_ops);
	assoc_array_init(&as_arr);
	atomic_set(&as_bad, 0);
	for (k = 1; k <= 32; k++)
		as_put(k);
}

static void as_op(bool sab)
{
	unsigned long key;
	struct as_obj *o;
	int i;

	if (raw_smp_processor_id() == 0) {		/* the writer */
		key = 1000 + get_random_u32() % 64;
		if (get_random_u32() & 1) {
			as_put(key);
		} else {
			struct assoc_array_edit *e = assoc_array_delete(&as_arr, &as_ops, &key);

			if (e && !IS_ERR(e)) {
				assoc_array_apply_edit(e);
				if (sab)
					rcu_barrier();
			}
		}
		if (!sab)
			cond_resched();
		return;
	}

	if (!sab)
		rcu_read_lock();
	for (key = 1; key <= 32; key++) {
		o = assoc_array_find(&as_arr, &as_ops, &key);
		if (!o || o->key != key)
			atomic_inc(&as_bad);
	}
	key = 1000 + get_random_u32() % 64;
	o = assoc_array_find(&as_arr, &as_ops, &key);
	if (o) {
		if (sab)
			msleep(30);		/* long enough for a grace period and the cleanup: the object is freed under our feet */
		else
			for (i = 0; i < 4000; i++)
				cpu_relax();
		if (READ_ONCE(o->key) != key)
			atomic_inc(&as_bad);
	}
	if (!sab)
		rcu_read_unlock();
	else
		cond_resched();
}

static int as_check(u64 total, char *msg, size_t len)
{
	unsigned long k;
	int missing = 0;

	rcu_barrier();
	for (k = 1; k <= 32; k++)
		if (!assoc_array_find(&as_arr, &as_ops, &k))
			missing++;
	if (!atomic_read(&as_bad) && !missing && as_arr.nr_leaves_on_tree >= 32)
		return 0;
	snprintf(msg, len, "assoc_array: bad reads %d, stable keys missing %d, leaves %lu after %llu ops", atomic_read(&as_bad), missing,
		 as_arr.nr_leaves_on_tree, total);
	return -EIO;
}


/* ---- target "radix_tree": lib/radix-tree.c, readers under RCU against one writer that grows and shrinks the tree ----
 *
 * The 32 "stable" entries sit at indices 0..31 (tag 1 set on all of them, never touched again). CPU 0 is the writer: it inserts and deletes a "far" entry
 * at a random height (index 64 << 6*k, k = 0..3) -- every insert extends the tree by up to three levels and every delete shrinks it again (the shrink leaves
 * a RETRY entry in the dropped node so a reader that is still in it starts over) -- and churns single entries 64..127 in a leaf next to the stable ones.
 * Every other CPU is a reader inside rcu_read_lock(): radix_tree_lookup() of the 32 stable indices must ALWAYS find the right object, a tagged gang lookup
 * must return all 32 in order, and a far/churn object it finds is dereferenced AGAIN after a short busy wait -- freed too early, KASAN reports the
 * use-after-free there.
 * Sabotage: the readers take no rcu_read_lock() and sleep 30 ms holding a churn object; the writer keeps deleting (kfree_rcu), so the object is freed
 * under the reader and KASAN must report it.
 */
struct rtr_obj { unsigned long key; struct rcu_head rcu; };
static RADIX_TREE(rtr_tree, GFP_KERNEL);
static atomic_t rtr_bad;

static void rtr_put(unsigned long key)
{
	struct rtr_obj *o = kzalloc(sizeof(*o), GFP_KERNEL);

	if (!o)
		return;
	o->key = key;
	if (radix_tree_insert(&rtr_tree, key, o))
		kfree(o);
}

static void rtr_del(unsigned long key, bool sab)
{
	struct rtr_obj *o = radix_tree_delete(&rtr_tree, key);

	if (o) {
		kfree_rcu(o, rcu);
		if (sab)
			rcu_barrier();
	}
}

static void rtr_init(void)
{
	unsigned long k;

	rcu_barrier();
	INIT_RADIX_TREE(&rtr_tree, GFP_KERNEL);
	atomic_set(&rtr_bad, 0);
	for (k = 0; k < 32; k++) {
		rtr_put(k);
		radix_tree_tag_set(&rtr_tree, k, 1);
	}
}

static void rtr_op(bool sab)
{
	unsigned long key;
	struct rtr_obj *o, *res[40];
	unsigned int n, i;

	if (raw_smp_processor_id() == 0) {		/* the writer */
		key = (get_random_u32() & 1) ? 64 + get_random_u32() % 64 : (64UL << (6 * (get_random_u32() % 4))) + get_random_u32() % 3;
		if (get_random_u32() & 1)
			rtr_put(key);
		else
			rtr_del(key, sab);
		if (!sab)
			cond_resched();
		return;
	}

	if (!sab)
		rcu_read_lock();
	for (key = 0; key < 32; key++) {
		o = radix_tree_lookup(&rtr_tree, key);
		if (!o || o->key != key)
			atomic_inc(&rtr_bad);
	}
	if (!sab) {
		n = radix_tree_gang_lookup_tag(&rtr_tree, (void **)res, 0, 40, 1);
		if (n != 32)
			atomic_inc(&rtr_bad);
		for (i = 0; i < n && i < 32; i++)
			if (res[i]->key != i)
				atomic_inc(&rtr_bad);
	}
	key = (get_random_u32() & 1) ? 64 + get_random_u32() % 64 : (64UL << (6 * (get_random_u32() % 4))) + get_random_u32() % 3;
	o = radix_tree_lookup(&rtr_tree, key);
	if (o) {
		if (sab)
			msleep(30);		/* long enough for a grace period: the object is freed under our feet */
		else
			for (i = 0; i < 4000; i++)
				cpu_relax();
		if (READ_ONCE(o->key) != key)
			atomic_inc(&rtr_bad);
	}
	if (!sab)
		rcu_read_unlock();
	else
		cond_resched();
}

static int rtr_check(u64 total, char *msg, size_t len)
{
	unsigned long k;
	int missing = 0;

	rcu_barrier();
	for (k = 0; k < 32; k++)
		if (!radix_tree_lookup(&rtr_tree, k))
			missing++;
	if (!atomic_read(&rtr_bad) && !missing && radix_tree_tagged(&rtr_tree, 1))
		return 0;
	snprintf(msg, len, "radix_tree: bad reads %d, stable entries missing %d, tag 1 %d after %llu ops", atomic_read(&rtr_bad), missing,
		 radix_tree_tagged(&rtr_tree, 1), total);
	return -EIO;
}


/* ---- target "maple_tree": lib/maple_tree.c in RCU mode, readers against one writer ----
 *
 * A tree in RCU mode never changes a node a reader may be looking at: the writer builds replacement nodes, publishes them, and the old
 * ones go through call_rcu(). CPU 0 is the writer: on single indices 1001..1127 that sit BETWEEN the stable ones it stores new objects
 * (freeing the one it replaced with kfree_rcu()) and erases, so the nodes holding the stable entries are split, merged and rebuilt all
 * the time. The stable entries are 32 values at indices 1000, 1004, ..., 1124 (never touched again). Every other CPU is a reader inside
 * rcu_read_lock(): mas_for_each() over 1000..1127 must see all 32 stable values, each exactly once and in increasing index order, and a
 * churn object it meets is dereferenced AGAIN after a short busy wait -- freed too early, KASAN reports the use-after-free there.
 * Sabotage: the readers look an object up with mtree_load() and use it 30 ms later with no RCU read lock held; the writer keeps
 * replacing it, so kfree_rcu() frees it under the reader and KASAN must report it.
 */
struct mp_obj { unsigned long key; struct rcu_head rcu; };
static struct maple_tree mp_tree;
static atomic_t mp_bad;
static bool mp_up;

static void mp_put(unsigned long key)
{
	struct mp_obj *o = kzalloc(sizeof(*o), GFP_KERNEL), *old;

	if (!o)
		return;
	o->key = key;
	old = mtree_load(&mp_tree, key);
	if (mtree_store(&mp_tree, key, o, GFP_KERNEL)) {
		kfree(o);
		return;
	}
	if (old)
		kfree_rcu(old, rcu);
}

static void mp_free_all(void)
{
	MA_STATE(mas, &mp_tree, 0, 0);
	void *e;

	if (!mp_up)
		return;
	rcu_barrier();
	mas_lock(&mas);
	mas_for_each(&mas, e, ULONG_MAX)
		if (!xa_is_value(e))
			kfree(e);
	mas_unlock(&mas);
	mtree_destroy(&mp_tree);
}

static void mp_init(void)
{
	unsigned long k;

	mp_free_all();
	mt_init_flags(&mp_tree, MT_FLAGS_USE_RCU);
	mp_up = true;
	atomic_set(&mp_bad, 0);
	for (k = 0; k < 32; k++)
		mtree_store(&mp_tree, 1000 + 4 * k, xa_mk_value(k + 1), GFP_KERNEL);
}

static void mp_op(bool sab)
{
	unsigned long key;
	struct mp_obj *o;
	void *e;
	int i, seen = 0;
	unsigned long last = 0;

	if (raw_smp_processor_id() == 0) {		/* the writer */
		key = 1000 + 4 * (get_random_u32() % 32) + 1 + get_random_u32() % 3;
		if (get_random_u32() % 3) {
			mp_put(key);
		} else {
			o = mtree_erase(&mp_tree, key);
			if (o)
				kfree_rcu(o, rcu);
		}
		if (!sab)
			cond_resched();
		return;
	}

	if (sab) {
		key = 1000 + 4 * (get_random_u32() % 32) + 1 + get_random_u32() % 3;
		o = mtree_load(&mp_tree, key);
		if (o) {
			msleep(30);		/* a grace period and the free pass: the object is gone under our feet */
			if (READ_ONCE(o->key) != key)
				atomic_inc(&mp_bad);
		}
		cond_resched();
		return;
	}

	{
		MA_STATE(mas, &mp_tree, 1000, 1000);

		rcu_read_lock();
		mas_for_each(&mas, e, 1127) {
			if (mas.index < last)
				atomic_inc(&mp_bad);
			last = mas.index;
			if (xa_is_value(e)) {
				if (mas.index != 1000 + 4 * (xa_to_value(e) - 1))
					atomic_inc(&mp_bad);
				seen++;
			} else {
				o = e;
				for (i = 0; i < 2000; i++)
					cpu_relax();
				if (READ_ONCE(o->key) != mas.index)
					atomic_inc(&mp_bad);
			}
		}
		rcu_read_unlock();
	}
	if (seen != 32)
		atomic_inc(&mp_bad);
}

static int mp_check(u64 total, char *msg, size_t len)
{
	unsigned long k;
	int missing = 0;

	rcu_barrier();
	for (k = 0; k < 32; k++)
		if (mtree_load(&mp_tree, 1000 + 4 * k) != xa_mk_value(k + 1))
			missing++;
	if (!atomic_read(&mp_bad) && !missing)
		return 0;
	snprintf(msg, len, "maple_tree: bad reads %d, stable entries missing %d after %llu ops", atomic_read(&mp_bad), missing, total);
	return -EIO;
}


/* ---- target "rhashtable": lib/rhashtable.c, inserts / removes / lookups / walks racing the resize worker ----
 *
 * One table with automatic shrinking and a tiny minimum size, so it grows and shrinks all the time. 256 STABLE objects (keys 1..256) are put in
 * at init and never removed: whatever the resizer does, a lookup must always find them and a walk must see every one of them at least once.
 * Every CPU also owns 1024 CHURN keys (0x10000 * (cpu + 1) + n) that it alone inserts and removes (removed objects go through kfree_rcu), and
 * now and then inserts or removes ALL of them in a burst so the table keeps resizing. Lookups of its own keys must agree with what the CPU
 * did; lookups of the other CPUs' churn keys happen under rcu_read_lock and read the object for a while (a freed-too-early object shows as a
 * bad key / checksum, and under KASAN as a use-after-free). The invariant at the end: no bad reads, all stable keys present, every churn key
 * the CPUs still own findable.
 * Sabotage: the other-CPU lookups drop the RCU read lock and use the object 30 ms later; kfree_rcu() frees it under the reader and KASAN
 * must report it (and the checksum check fails).
 */
#define RH_STABLE	256
#define RH_CHURN	1024
#define RH_MAXCPU	64
struct rh_obj {
	u32 key;
	u32 chk;
	struct rhash_head node;
	struct rcu_head rcu;
};
static const struct rhashtable_params rh_params = {
	.head_offset = offsetof(struct rh_obj, node),
	.key_offset = offsetof(struct rh_obj, key),
	.key_len = sizeof(u32),
	.automatic_shrinking = true,
	.min_size = 4,
};
static struct rhashtable rh_ht;
static struct rh_obj *rh_own[RH_MAXCPU][RH_CHURN];
static unsigned int rh_nown[RH_MAXCPU];
static atomic_t rh_bad;
static bool rh_up;
static unsigned int rh_last_size, rh_size_changes, rh_peak_size;	/* sampled by CPU 0: the table really did resize */

static u32 rh_chk(u32 key) { return key ^ 0x5a5a5a5a; }
static u32 rh_churn_key(unsigned int cpu, unsigned int n) { return 0x10000 * (cpu + 1) + n; }

static struct rh_obj *rh_new(u32 key)
{
	struct rh_obj *o = kzalloc(sizeof(*o), GFP_KERNEL);

	if (o) {
		o->key = key;
		o->chk = rh_chk(key);
	}
	return o;
}

static void rh_free_fn(void *ptr, void *arg)
{
	kfree(ptr);
}

static void rh_free_all(void)
{
	if (!rh_up)
		return;
	rcu_barrier();
	rhashtable_free_and_destroy(&rh_ht, rh_free_fn, NULL);	/* every object still in the table, stable and churn */
	memset(rh_own, 0, sizeof(rh_own));
	memset(rh_nown, 0, sizeof(rh_nown));
	rh_up = false;
}

static void rh_init(void)
{
	u32 k;

	rh_free_all();
	atomic_set(&rh_bad, 0);
	rh_last_size = rh_size_changes = rh_peak_size = 0;
	if (rhashtable_init(&rh_ht, &rh_params))
		return;
	rh_up = true;
	for (k = 1; k <= RH_STABLE; k++) {
		struct rh_obj *o = rh_new(k);

		if (o && rhashtable_insert_fast(&rh_ht, &o->node, rh_params))
			kfree(o);
	}
}

static void rh_check_obj(struct rh_obj *o, u32 key)
{
	if (READ_ONCE(o->key) != key || READ_ONCE(o->chk) != rh_chk(key))
		atomic_inc(&rh_bad);
}

static void rh_toggle(unsigned int cpu, unsigned int n)
{
	struct rh_obj *o = rh_own[cpu][n];
	u32 key = rh_churn_key(cpu, n);

	if (!o) {
		o = rh_new(key);
		if (!o)
			return;
		if (rhashtable_lookup_insert_fast(&rh_ht, &o->node, rh_params)) {
			atomic_inc(&rh_bad);		/* the key is ours alone: it cannot already be there */
			kfree(o);
			return;
		}
		rh_own[cpu][n] = o;
		rh_nown[cpu]++;
	} else {
		if (rhashtable_remove_fast(&rh_ht, &o->node, rh_params))
			atomic_inc(&rh_bad);		/* it must be there */
		kfree_rcu(o, rcu);
		rh_own[cpu][n] = NULL;
		rh_nown[cpu]--;
	}
}

static void rh_walk(void)
{
	struct rhashtable_iter it;
	unsigned long seen[BITS_TO_LONGS(RH_STABLE + 1)] = { 0 };
	struct rh_obj *o;
	u32 k;

	rhashtable_walk_enter(&rh_ht, &it);
	rhashtable_walk_start(&it);
	while ((o = rhashtable_walk_next(&it)) != NULL) {
		if (IS_ERR(o)) {
			if (PTR_ERR(o) != -EAGAIN)
				atomic_inc(&rh_bad);
			continue;		/* a resize: the walk restarts, entries may be seen twice */
		}
		if (o->chk != rh_chk(o->key))
			atomic_inc(&rh_bad);
		if (o->key >= 1 && o->key <= RH_STABLE)
			__set_bit(o->key, seen);
	}
	rhashtable_walk_stop(&it);
	rhashtable_walk_exit(&it);
	for (k = 1; k <= RH_STABLE; k++)
		if (!test_bit(k, seen))
			atomic_inc(&rh_bad);
}

static void rh_op(bool sab)
{
	unsigned int cpu = raw_smp_processor_id() % RH_MAXCPU, r = get_random_u32() % 1000, n, i, other;
	struct rh_obj *o;
	u32 key;

	if (!rh_up)
		return;
	if (cpu == 0 && !(get_random_u32() % 16)) {
		unsigned int sz;

		rcu_read_lock();
		sz = rcu_dereference(rh_ht.tbl)->size;
		rcu_read_unlock();
		if (sz != rh_last_size) {
			rh_last_size = sz;
			rh_size_changes++;
			if (sz > rh_peak_size)
				rh_peak_size = sz;
		}
	}
	if (r < 400) {
		rh_toggle(cpu, get_random_u32() % RH_CHURN);
	} else if (r < 700) {			/* own key: the table must agree with what this CPU did */
		n = get_random_u32() % RH_CHURN;
		key = rh_churn_key(cpu, n);
		rcu_read_lock();
		o = rhashtable_lookup_fast(&rh_ht, &key, rh_params);
		if (o != rh_own[cpu][n])
			atomic_inc(&rh_bad);
		else if (o)
			rh_check_obj(o, key);
		rcu_read_unlock();
	} else if (r < 800) {			/* a stable key: found, whatever the resizer is doing */
		key = 1 + get_random_u32() % RH_STABLE;
		rcu_read_lock();
		o = rhashtable_lookup_fast(&rh_ht, &key, rh_params);
		if (!o)
			atomic_inc(&rh_bad);
		else
			rh_check_obj(o, key);
		rcu_read_unlock();
	} else if (r < 950) {			/* another CPU's churn key: maybe there, maybe being freed */
		other = get_random_u32() % num_possible_cpus();
		key = rh_churn_key(other % RH_MAXCPU, get_random_u32() % RH_CHURN);
		if (sab) {
			o = rhashtable_lookup_fast(&rh_ht, &key, rh_params);	/* no RCU read lock */
			if (o) {
				msleep(30);	/* a grace period and the free pass: the object is gone under our feet */
				rh_check_obj(o, key);
			}
			cond_resched();
			return;
		}
		rcu_read_lock();
		o = rhashtable_lookup_fast(&rh_ht, &key, rh_params);
		if (o) {
			for (i = 0; i < 1000; i++)
				cpu_relax();
			rh_check_obj(o, key);
		}
		rcu_read_unlock();
	} else if (r < 960) {			/* a burst: every churn key in, or every churn key out, so the table resizes */
		bool fill = rh_nown[cpu] < RH_CHURN / 2;

		for (n = 0; n < RH_CHURN; n++)
			if (!!rh_own[cpu][n] != fill)
				rh_toggle(cpu, n);
		if (!sab)
			cond_resched();
	} else if (r < 970) {
		rh_walk();
	}
}

static int rh_check(u64 total, char *msg, size_t len)
{
	unsigned int cpu, n, missing = 0;
	u32 key;

	rcu_barrier();
	for (key = 1; key <= RH_STABLE; key++)
		if (!rhashtable_lookup_fast(&rh_ht, &key, rh_params))
			missing++;
	for (cpu = 0; cpu < RH_MAXCPU; cpu++)
		for (n = 0; n < RH_CHURN; n++) {
			key = rh_churn_key(cpu, n);
			if (rhashtable_lookup_fast(&rh_ht, &key, rh_params) != rh_own[cpu][n])
				missing++;
		}
	pr_info("rhashtable: table size changed %u times as sampled by CPU 0, peak %u buckets\n", rh_size_changes, rh_peak_size);
	if (!atomic_read(&rh_bad) && !missing)
		return 0;
	snprintf(msg, len, "rhashtable: bad reads %d, keys wrong %u after %llu ops", atomic_read(&rh_bad), missing, total);
	return -EIO;
}

/* ---- target "rcuref": lib/rcuref.c, object lifetime through an RCU-protected pointer ----
 *
 * CPU 0 is the writer: it publishes a new object (reference count 1, held by the pointer), lets the readers run, then unpublishes it
 * and drops the pointer's reference. Every other CPU is a reader: under rcu_read_lock it loads the pointer and tries rcuref_get();
 * if that succeeds it uses the object for a while, then rcuref_put(). Whoever's put() reports "last reference" frees the object
 * (kfree_rcu). Invariants: every object is freed exactly once (created == freed at the end), and nobody sees a bad magic number (a
 * freed-too-early object shows as one, and under KASAN as a use-after-free). A get() that races the last put() must fail, never
 * revive the object.
 * Sabotage: the readers skip rcuref_get() and use the object 30 ms after loading it; kfree_rcu() frees it under them and KASAN must report it.
 */
struct rc_obj { rcuref_t ref; u32 magic; struct rcu_head rcu; };
#define RC_MAGIC 0x600dcafe
static struct rc_obj __rcu *rc_cur;
static atomic_t rc_created, rc_freed, rc_bad;

static void rc_release(struct rc_obj *o)
{
	WRITE_ONCE(o->magic, 0);
	atomic_inc(&rc_freed);
	kfree_rcu(o, rcu);
}

static void rc_init(void)
{
	struct rc_obj *o;

	rcu_barrier();
	o = rcu_dereference_protected(rc_cur, 1);
	if (o)
		kfree(o);
	atomic_set(&rc_created, 0);
	atomic_set(&rc_freed, 0);
	atomic_set(&rc_bad, 0);
	rcu_assign_pointer(rc_cur, NULL);
}

static void rc_op(bool sab)
{
	struct rc_obj *o;

	if (raw_smp_processor_id() == 0) {		/* the writer */
		o = kzalloc(sizeof(*o), GFP_KERNEL);
		if (!o)
			return;
		o->magic = RC_MAGIC;
		rcuref_init(&o->ref, 1);
		atomic_inc(&rc_created);
		rcu_assign_pointer(rc_cur, o);
		udelay(20 + get_random_u32() % 40);
		rcu_assign_pointer(rc_cur, NULL);
		if (rcuref_put(&o->ref))
			rc_release(o);
		if (!sab)
			cond_resched();
		return;
	}

	if (sab) {
		rcu_read_lock();
		o = rcu_dereference(rc_cur);
		rcu_read_unlock();
		if (o) {
			msleep(30);		/* the writer has dropped it and the grace period has passed */
			if (READ_ONCE(o->magic) != RC_MAGIC)
				atomic_inc(&rc_bad);
		}
		cond_resched();
		return;
	}

	rcu_read_lock();
	o = rcu_dereference(rc_cur);
	if (o && rcuref_get(&o->ref)) {
		rcu_read_unlock();
		if (READ_ONCE(o->magic) != RC_MAGIC)
			atomic_inc(&rc_bad);
		cpu_relax();
		if (READ_ONCE(o->magic) != RC_MAGIC)
			atomic_inc(&rc_bad);
		if (rcuref_put(&o->ref))
			rc_release(o);
		return;
	}
	rcu_read_unlock();
}

static int rc_check(u64 total, char *msg, size_t len)
{
	rcu_barrier();
	if (!atomic_read(&rc_bad) && atomic_read(&rc_created) == atomic_read(&rc_freed))
		return 0;
	snprintf(msg, len, "rcuref: bad reads %d, objects created %d freed %d after %llu ops", atomic_read(&rc_bad), atomic_read(&rc_created),
		 atomic_read(&rc_freed), total);
	return -EIO;
}

/* ---- target "stackdepot": lib/stackdepot.c, reference-counted records saved, found, freed and reused from every CPU ----
 *
 * 64 shared stacks of 1-8 frames each (frame values unique per stack), saved by every CPU with STACK_DEPOT_FLAG_GET | CAN_ALLOC, so records are
 * constantly created, found by the lockless bucket search, freed to the freelist when the last reference goes, and popped from it again (for another
 * stack, or the same one) once the RCU grace period has passed. While a CPU holds a reference: stack_depot_fetch() must return exactly that
 * stack's frames (twice, with a pause between), and saving the same stack again must return the same handle. A persistent (no GET) stack per CPU is
 * saved repeatedly and must keep its handle and frames for the whole run. Any mismatch counts as bad.
 * Sabotage: each CPU saves a private stack with GET, fetches it, puts it (so the record is freed and its entries are overwritten by the freelist links)
 * and then reads the old entries pointer: the use-after-put must be seen as a changed stack.
 */
#define SD_NSTK 64
static unsigned long sd_stk[SD_NSTK + NR_CPUS][8];
static unsigned int sd_n[SD_NSTK + NR_CPUS];
static depot_stack_handle_t sd_persist[NR_CPUS];
static atomic_t sd_bad, sd_ops_ok, sd_zero;

static void sd_init(void)
{
	unsigned int k, j;

	for (k = 0; k < SD_NSTK + NR_CPUS; k++) {
		sd_n[k] = 1 + k % 8;
		for (j = 0; j < 8; j++)
			sd_stk[k][j] = 0xffffffffa0000000UL + k * 0x100 + j * 8;
	}
	memset(sd_persist, 0, sizeof(sd_persist));
	atomic_set(&sd_bad, 0);
	atomic_set(&sd_ops_ok, 0);
	atomic_set(&sd_zero, 0);
}

static bool sd_matches(depot_stack_handle_t h, unsigned int k)
{
	unsigned long *e;
	unsigned int n = stack_depot_fetch(h, &e);

	return n == sd_n[k] && !memcmp(e, sd_stk[k], n * sizeof(*e));
}

static void sd_round(unsigned int cpu)
{
	unsigned int k;
	depot_stack_handle_t h, h2;

	k = get_random_u32() % SD_NSTK;
	h = stack_depot_save_flags(sd_stk[k], sd_n[k], GFP_KERNEL, STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_CAN_ALLOC);
	if (!h) {
		atomic_inc(&sd_zero);	/* allocation failed (pool limit, no spare pool): nothing to check */
		return;
	}
	if (!sd_matches(h, k))
		atomic_inc(&sd_bad);
	cpu_relax();
	h2 = stack_depot_save_flags(sd_stk[k], sd_n[k], GFP_KERNEL, STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_CAN_ALLOC);
	if (h2 != h)
		atomic_inc(&sd_bad);
	if (!sd_matches(h, k))
		atomic_inc(&sd_bad);
	if (h2)
		stack_depot_put(h2);
	stack_depot_put(h);

	/* a persistent stack of this CPU's own: same handle every time, frames intact */
	k = SD_NSTK + cpu;
	h = stack_depot_save_flags(sd_stk[k], sd_n[k], GFP_KERNEL, STACK_DEPOT_FLAG_CAN_ALLOC);
	if (h) {
		if (sd_persist[cpu] && sd_persist[cpu] != h)
			atomic_inc(&sd_bad);
		sd_persist[cpu] = h;
		if (!sd_matches(h, k))
			atomic_inc(&sd_bad);
	}
	atomic_inc(&sd_ops_ok);
}

static void sd_op(bool sab)
{
	unsigned int cpu = raw_smp_processor_id(), i, k;
	depot_stack_handle_t h;
	unsigned long *e;
	unsigned long saved[8];
	unsigned long j;

	if (sab) {
		k = SD_NSTK + cpu;
		h = stack_depot_save_flags(sd_stk[k], sd_n[k], GFP_KERNEL, STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_CAN_ALLOC);
		if (!h)
			return;
		if (stack_depot_fetch(h, &e) != sd_n[k])
			return;
		memcpy(saved, sd_stk[k], sizeof(saved));
		stack_depot_put(h);		/* last reference: the record goes to the freelist and its entries are overwritten */
		udelay(50);
		if (memcmp(e, saved, sd_n[k] * sizeof(*e)))
			atomic_inc(&sd_bad);
		msleep(1);			/* slow enough not to exhaust the pool limit */
		return;
	}

	/* Every CPU starts its burst on the same jiffy, so the bursts overlap. A burst frees at most 32 records; freed records can be reused only
	 * after an RCU grace period, and churning faster than that exhausts the pool limit (seen: limit reached after 2.7 s at ~700k rounds/s, after
	 * which every save fails and nothing is tested). */
	j = jiffies;
	while (READ_ONCE(jiffies) == j)
		cond_resched();
	for (i = 0; i < 32; i++)
		sd_round(cpu);
	/* Freed records are reused only once poll_state_synchronize_rcu() says a grace period has passed, and nothing else here starts one: CPU 0 does. */
	if (cpu == 0)
		synchronize_rcu();
}

static int sd_check(u64 total, char *msg, size_t len)
{
	pr_info("stackdepot: %d complete rounds (save/fetch/save again/put/persistent), %d failed saves, %d bad\n", atomic_read(&sd_ops_ok),
		atomic_read(&sd_zero), atomic_read(&sd_bad));
	if (!atomic_read(&sd_bad) && atomic_read(&sd_ops_ok) && atomic_read(&sd_zero) <= atomic_read(&sd_ops_ok))
		return 0;
	snprintf(msg, len, "stackdepot: bad %d, ok rounds %d, failed saves %d after %llu ops", atomic_read(&sd_bad), atomic_read(&sd_ops_ok),
		 atomic_read(&sd_zero), total);
	return -EIO;
}

/* ---- target "sbitmap": lib/sbitmap.c, tag allocation from a small shared queue by every CPU ----
 *
 * A sbitmap_queue of 12 tags in words of 4 bits (so the CPUs fight over three words, run it dry, and exercise the deferred-clear fold). Each CPU
 * repeatedly allocates tags by one of three routes -- sbitmap_queue_get(), sbitmap_queue_get_shallow() and __sbitmap_queue_get_batch() -- and claims
 * each tag by cmpxchg on owner[tag] (0 -> cpu + 1): a failed claim means two CPUs were handed the same tag. After a short hold it checks that it
 * still owns the tag, releases the claim, and frees the tag with sbitmap_queue_clear() or sbitmap_queue_clear_batch(). CPU 0 also parks a waiter on a
 * wait queue now and then so that the clear path's wake-ups run for real. At the end every tag must be free (weight 0).
 * Sabotage: the tag is freed first and the claim released after a delay, so another CPU is handed the tag in between and finds it owned.
 */
#define SB_TAGS 12
static struct sbitmap_queue sb_q;
static atomic_t sb_owner[SB_TAGS];
static atomic_t sb_bad, sb_rounds, sb_dry;

static void sb_init(void)
{
	int i;

	sbitmap_queue_free(&sb_q);			/* from a previous run, if any */
	memset(&sb_q, 0, sizeof(sb_q));
	if (sbitmap_queue_init_node(&sb_q, SB_TAGS, 2, false, GFP_KERNEL, NUMA_NO_NODE))
		pr_err("libstress: sbitmap_queue_init_node failed\n");
	sbitmap_queue_min_shallow_depth(&sb_q, 6);
	for (i = 0; i < SB_TAGS; i++)
		atomic_set(&sb_owner[i], 0);
	atomic_set(&sb_bad, 0);
	atomic_set(&sb_rounds, 0);
	atomic_set(&sb_dry, 0);
}

static bool sb_claim(int tag, int me)
{
	if (tag < 0 || tag >= SB_TAGS || atomic_cmpxchg(&sb_owner[tag], 0, me) != 0) {
		atomic_inc(&sb_bad);
		return false;
	}
	return true;
}

static void sb_release_check(int tag, int me)
{
	if (atomic_cmpxchg(&sb_owner[tag], me, 0) != me)
		atomic_inc(&sb_bad);
}

static void sb_op(bool sab)
{
	int me = raw_smp_processor_id() + 1, mode = get_random_u32() % 8, i, n = 0, tag[4];
	unsigned long mask;
	unsigned int off;

	if (me == 1 && !(get_random_u32() % 16)) {	/* a waiter, so that wake-ups find someone */
		DEFINE_SBQ_WAIT(w);

		sbitmap_prepare_to_wait(&sb_q, &sb_q.ws[get_random_u32() % SBQ_WAIT_QUEUES], &w, TASK_UNINTERRUPTIBLE);
		schedule_timeout(1);
		sbitmap_finish_wait(&sb_q, &sb_q.ws[0], &w);
		return;
	}

	if (mode < 4) {
		tag[0] = __sbitmap_queue_get(&sb_q);
		n = tag[0] >= 0;
	} else if (mode < 6) {
		tag[0] = sbitmap_queue_get_shallow(&sb_q, 6);
		n = tag[0] >= 0;
	} else {
		mask = __sbitmap_queue_get_batch(&sb_q, 3, &off);
		for (i = 0; i < 3; i++)
			if (mask & (1UL << i))
				tag[n++] = off + i;
	}
	if (!n) {
		atomic_inc(&sb_dry);
		cpu_relax();
		return;
	}
	for (i = 0; i < n; i++)
		sb_claim(tag[i], me);
	udelay(get_random_u32() % 4);

	if (sab) {			/* free first, check the claim afterwards: somebody else may hold the tag by then */
		for (i = 0; i < n; i++)
			sbitmap_queue_clear(&sb_q, tag[i], raw_smp_processor_id());
		udelay(20);
		for (i = 0; i < n; i++)
			sb_release_check(tag[i], me);
		return;
	}
	for (i = 0; i < n; i++)
		sb_release_check(tag[i], me);
	if (n > 1) {
		sbitmap_queue_clear_batch(&sb_q, 0, tag, n);
	} else {
		sbitmap_queue_clear(&sb_q, tag[0], raw_smp_processor_id());
	}
	atomic_inc(&sb_rounds);
}

static int sb_check(u64 total, char *msg, size_t len)
{
	unsigned int busy = sbitmap_weight(&sb_q.sb);

	pr_info("libstress: sbitmap: %d complete rounds, %d times the map was dry, %d bad, %u tags still busy\n", atomic_read(&sb_rounds),
		atomic_read(&sb_dry), atomic_read(&sb_bad), busy);
	if (!atomic_read(&sb_bad) && !busy && atomic_read(&sb_rounds) > atomic_read(&sb_dry) / 8)
		return 0;
	snprintf(msg, len, "sbitmap: bad %d, busy %u, rounds %d, dry %d after %llu ops", atomic_read(&sb_bad), busy, atomic_read(&sb_rounds),
		 atomic_read(&sb_dry), total);
	return -EIO;
}

/* ---- target "refcount": lib/refcount.c, no lost update ----
 *
 * One shared refcount_t starts high. Every CPU randomly takes a reference (refcount_inc) or drops one with refcount_dec_not_one() (it can never reach 1
 * here), counting its own successes. If the counter is exact, final == start + incs - decs; a lost update shows as a different value, a reference count
 * that went through the saturation or underflow paths shows as REFCOUNT_SATURATED. CPU 0 also runs refcount_dec_if_one() on a private count (1 -> 0 once,
 * then false) as a sanity check of the other exported function.
 * Sabotage: the drop is a plain read and write of the counter.
 */
#define RF_START (1 << 24)
static refcount_t rf_cnt;
static atomic64_t rf_incs, rf_decs;

static void rf_init(void)
{
	refcount_set(&rf_cnt, RF_START);
	atomic64_set(&rf_incs, 0);
	atomic64_set(&rf_decs, 0);
}

static void rf_op(bool sab)
{
	bool inc = get_random_u32() & 1;

	if (inc) {
		refcount_inc(&rf_cnt);
		atomic64_inc(&rf_incs);
	} else if (sab) {
		refcount_set(&rf_cnt, refcount_read(&rf_cnt) - 1);	/* not atomic: a concurrent update between the read and the write is lost */
		atomic64_inc(&rf_decs);
	} else if (refcount_dec_not_one(&rf_cnt)) {
		atomic64_inc(&rf_decs);
	}
}

static int rf_check(u64 total, char *msg, size_t len)
{
	long want = RF_START + atomic64_read(&rf_incs) - atomic64_read(&rf_decs), got = refcount_read(&rf_cnt);
	refcount_t one = REFCOUNT_INIT(1);

	pr_info("libstress: refcount: %lld incs, %lld decs, counter %ld (expected %ld)\n", (long long)atomic64_read(&rf_incs),
		(long long)atomic64_read(&rf_decs), got, want);
	if (got == want && refcount_dec_if_one(&one) && !refcount_dec_if_one(&one))
		return 0;
	snprintf(msg, len, "refcount: counter %ld, expected %ld (%lld incs, %lld decs) after %llu ops", got, want, (long long)atomic64_read(&rf_incs),
		 (long long)atomic64_read(&rf_decs), total);
	return -EIO;
}

/* ---- target "lwq": lib/lwq.c, producers and consumers on one queue ----
 *
 * Every CPU is both: it enqueues numbered items (cpu, sequence) allocated with kmalloc, and dequeues them one at a time (__lwq_dequeue) or in bulk
 * (lwq_dequeue_all). Invariants: an item is consumed exactly once (created == consumed once the queue is drained at the end, and KASAN sees no
 * double free or use-after-free as the consumer frees what it dequeued), and each consumer sees the items of any one producer in increasing sequence
 * (the queue is FIFO and a consumer sees a subsequence of it).
 * Sabotage: a bulk dequeue keeps only the first entry of the batch and drops the rest on the floor, so items are lost.
 */
struct lq_item { struct lwq_node n; int cpu; int seq; };
static struct lwq lq_q;
static atomic_t lq_created, lq_consumed, lq_bad;
static int lq_next_seq[NR_CPUS], lq_last[NR_CPUS][NR_CPUS];

static void lq_init(void)
{
	int i, j;

	lwq_init(&lq_q);
	atomic_set(&lq_created, 0);
	atomic_set(&lq_consumed, 0);
	atomic_set(&lq_bad, 0);
	for (i = 0; i < NR_CPUS; i++) {
		lq_next_seq[i] = 0;
		for (j = 0; j < NR_CPUS; j++)
			lq_last[i][j] = -1;
	}
}

static void lq_consume(struct llist_node *l, int me)
{
	struct lq_item *it = container_of(l, struct lq_item, n.node);

	if (it->cpu < 0 || it->cpu >= NR_CPUS || it->seq <= lq_last[me][it->cpu])
		atomic_inc(&lq_bad);
	else
		lq_last[me][it->cpu] = it->seq;
	kfree(it);
	atomic_inc(&lq_consumed);
}

static void lq_op(bool sab)
{
	int me = raw_smp_processor_id(), r = get_random_u32() % 4;
	struct llist_node *l, *next;
	struct lq_item *it;

	if (r < 2) {
		it = kmalloc(sizeof(*it), GFP_KERNEL);
		if (!it)
			return;
		it->cpu = me;
		it->seq = lq_next_seq[me]++;
		atomic_inc(&lq_created);
		lwq_enqueue(&it->n, &lq_q);
	} else if (r == 2) {
		l = __lwq_dequeue(&lq_q);
		if (l)
			lq_consume(l, me);
	} else {
		l = lwq_dequeue_all(&lq_q);
		if (sab && l) {			/* keep the first entry, lose the rest */
			next = l->next;
			l->next = NULL;
			lq_consume(l, me);
			return;
		}
		while (l) {
			next = l->next;
			lq_consume(l, me);
			l = next;
		}
	}
}

static int lq_check(u64 total, char *msg, size_t len)
{
	struct llist_node *l, *next;

	for (l = lwq_dequeue_all(&lq_q); l; l = next) {		/* drain what is left, single-threaded now */
		next = l->next;
		lq_consume(l, 0);
	}
	pr_info("libstress: lwq: %d created, %d consumed, %d out of order\n", atomic_read(&lq_created), atomic_read(&lq_consumed), atomic_read(&lq_bad));
	if (!atomic_read(&lq_bad) && atomic_read(&lq_created) == atomic_read(&lq_consumed) && lwq_empty(&lq_q))
		return 0;
	snprintf(msg, len, "lwq: %d created, %d consumed, %d out of order after %llu ops", atomic_read(&lq_created), atomic_read(&lq_consumed),
		 atomic_read(&lq_bad), total);
	return -EIO;
}

/* ---- target "notifier": kernel/notifier.c, readers walking an atomic chain while a writer registers and unregisters blocks ----
 *
 * Four permanent blocks (priorities 100, 50, 50, 10) sit on an atomic notifier chain. CPU 0 is the writer: it registers heap-allocated blocks with random priorities,
 * later unregisters them (atomic_notifier_chain_unregister() waits for a grace period), poisons and frees them. Every CPU (the writer too) also calls the chain.
 * Invariants per call: the priorities seen are non-increasing, every permanent block runs exactly once, and a dynamic block that runs still has its magic number (a
 * block freed while a reader is inside it shows as a bad magic and, under KASAN, as a use-after-free).
 * Sabotage: the writer unregisters with the raw variant (no grace period) and frees at once while the callback is still running (it pauses inside).
 */
#define NT_MAGIC 0x6e6f7469
#define NT_LIVE 8
struct nt_dyn { struct notifier_block nb; u32 magic; };
struct nt_call { int last_prio; unsigned int mask; int bad; };
static ATOMIC_NOTIFIER_HEAD(nt_ah);
static struct notifier_block nt_perm[4];
static struct nt_dyn *nt_live[NT_LIVE];
static atomic_t nt_bad, nt_calls;

static int nt_cb(struct notifier_block *nb, unsigned long action, void *data)
{
	struct nt_call *c = data;
	struct nt_dyn *d = container_of(nb, struct nt_dyn, nb);

	if (nb->priority > c->last_prio)
		c->bad++;
	c->last_prio = nb->priority;
	if (nb >= nt_perm && nb < nt_perm + 4) {
		unsigned int bit = 1u << (nb - nt_perm);

		if (c->mask & bit)
			c->bad++;
		c->mask |= bit;
	} else {
		udelay(10 + get_random_u32() % 20);
		if (READ_ONCE(d->magic) != NT_MAGIC)
			c->bad++;
	}
	return NOTIFY_OK;
}

static void nt_init(void)
{
	static const int prio[4] = { 100, 50, 50, 10 };
	int i;

	for (i = 0; i < NT_LIVE; i++)
		nt_live[i] = NULL;
	atomic_set(&nt_bad, 0);
	atomic_set(&nt_calls, 0);
	for (i = 0; i < 4; i++) {
		nt_perm[i].notifier_call = nt_cb;
		nt_perm[i].priority = prio[i];
		atomic_notifier_chain_register(&nt_ah, &nt_perm[i]);
	}
}

static void nt_op(bool sab)
{
	struct nt_call c = { .last_prio = INT_MAX };
	int slot;

	if (raw_smp_processor_id() == 0 && get_random_u32() % 3 == 0) {
		struct nt_dyn *d;

		slot = get_random_u32() % NT_LIVE;
		d = nt_live[slot];
		if (d) {
			if (sab) {
				unsigned long flags;

				spin_lock_irqsave(&nt_ah.lock, flags);
				raw_notifier_chain_unregister((struct raw_notifier_head *)&nt_ah.head, &d->nb);
				spin_unlock_irqrestore(&nt_ah.lock, flags);
			} else {
				atomic_notifier_chain_unregister(&nt_ah, &d->nb);
			}
			WRITE_ONCE(d->magic, 0);
			kfree(d);
			nt_live[slot] = NULL;
		} else {
			d = kzalloc(sizeof(*d), GFP_KERNEL);
			if (!d)
				return;
			d->magic = NT_MAGIC;
			d->nb.notifier_call = nt_cb;
			d->nb.priority = get_random_u32() % 120;
			atomic_notifier_chain_register(&nt_ah, &d->nb);
			nt_live[slot] = d;
		}
		return;
	}
	atomic_notifier_call_chain(&nt_ah, 0, &c);
	atomic_inc(&nt_calls);
	if (c.bad || c.mask != 0xf)
		atomic_add(c.bad ? c.bad : 1, &nt_bad);
}

static int nt_check(u64 total, char *msg, size_t len)
{
	int i;

	for (i = 0; i < NT_LIVE; i++) {
		if (nt_live[i]) {
			atomic_notifier_chain_unregister(&nt_ah, &nt_live[i]->nb);
			kfree(nt_live[i]);
			nt_live[i] = NULL;
		}
	}
	for (i = 0; i < 4; i++)
		atomic_notifier_chain_unregister(&nt_ah, &nt_perm[i]);
	pr_info("libstress: notifier: %d calls, %d violations\n", atomic_read(&nt_calls), atomic_read(&nt_bad));
	if (!atomic_read(&nt_bad) && atomic_notifier_call_chain_is_empty(&nt_ah))
		return 0;
	snprintf(msg, len, "notifier: %d violations in %d calls after %llu ops", atomic_read(&nt_bad), atomic_read(&nt_calls), total);
	return -EIO;
}

/* ---- target "ucount": kernel/ucount.c, rlimit and ucount charges along a namespace chain from all CPUs ----
 *
 * A fake chain of three levels (u2 -> u1 -> u0) with generous and tight limits. Every CPU repeatedly charges and uncharges: inc_rlimit_ucounts() paired with
 * dec_rlimit_ucounts(); inc_rlimit_get_ucounts() (success holds a charge and a reference on each level that went 0 -> 1) later released by dec_rlimit_put_ucounts();
 * dec_ucount() on counters it raised itself; and is_rlimit_overlimit() reads. Invariants: when everyone has uncharged, every counter is back to its starting
 * value (a lost update from a non-atomic add shows), and the reference counts equal the initial ones (a leaked or double-put reference shows).
 * Sabotage: a thread sometimes skips an uncharge, so counters stay non-zero.
 */
#define UC_LEVELS 3
#define UC_REFS 1000000
static struct user_namespace uc_ns[UC_LEVELS];
static struct ucounts uc_u[UC_LEVELS];
static atomic_t uc_bad;
static int uc_held[NR_CPUS];

static void uc_init(void)
{
	int i, t;

	memset(uc_ns, 0, sizeof(uc_ns));
	memset(uc_u, 0, sizeof(uc_u));
	atomic_set(&uc_bad, 0);
	for (i = 0; i < NR_CPUS; i++)
		uc_held[i] = 0;
	for (i = 0; i < UC_LEVELS; i++) {
		uc_u[i].ns = &uc_ns[i];
		uc_ns[i].ucounts = i ? &uc_u[i - 1] : NULL;
		rcuref_init(&uc_u[i].count, UC_REFS);
		for (t = 0; t < UCOUNT_RLIMIT_COUNTS; t++)
			uc_ns[i].rlimit_max[t] = (i == 1) ? 6 : LONG_MAX;
	}
}

static void uc_op(bool sab)
{
	int me = raw_smp_processor_id(), r = get_random_u32() % 8;

	if (r < 2) {
		inc_rlimit_ucounts(&uc_u[2], UCOUNT_RLIMIT_NPROC, 1);
		cond_resched();
		if (!(sab && get_random_u32() % 50 == 0))
			dec_rlimit_ucounts(&uc_u[2], UCOUNT_RLIMIT_NPROC, 1);
	} else if (r < 5) {
		if (uc_held[me] < 3 && inc_rlimit_get_ucounts(&uc_u[2], UCOUNT_RLIMIT_MSGQUEUE, get_random_u32() & 1))
			uc_held[me]++;
		else if (uc_held[me]) {
			dec_rlimit_put_ucounts(&uc_u[2], UCOUNT_RLIMIT_MSGQUEUE);
			uc_held[me]--;
		}
	} else if (r < 7) {
		atomic_long_inc(&uc_u[2].ucount[UCOUNT_USER_NAMESPACES]);
		atomic_long_inc(&uc_u[1].ucount[UCOUNT_USER_NAMESPACES]);
		atomic_long_inc(&uc_u[0].ucount[UCOUNT_USER_NAMESPACES]);
		if (rcuref_get(&uc_u[2].count))		/* dec_ucount() drops a reference of its own */
			dec_ucount(&uc_u[2], UCOUNT_USER_NAMESPACES);
	} else {
		(void)is_rlimit_overlimit(&uc_u[2], UCOUNT_RLIMIT_NPROC, 3);
	}
}

static int uc_check(u64 total, char *msg, size_t len)
{
	int i, t, me;

	for (me = 0; me < NR_CPUS; me++)
		while (uc_held[me]-- > 0)
			dec_rlimit_put_ucounts(&uc_u[2], UCOUNT_RLIMIT_MSGQUEUE);
	for (i = 0; i < UC_LEVELS; i++) {
		for (t = 0; t < UCOUNT_RLIMIT_COUNTS; t++)
			if (atomic_long_read(&uc_u[i].rlimit[t]) != 0)
				atomic_inc(&uc_bad);
		if (atomic_long_read(&uc_u[i].ucount[UCOUNT_USER_NAMESPACES]) != 0)
			atomic_inc(&uc_bad);
		if (rcuref_read(&uc_u[i].count) != UC_REFS)
			atomic_inc(&uc_bad);
	}
	pr_info("libstress: ucount: %d violations\n", atomic_read(&uc_bad));
	if (!atomic_read(&uc_bad))
		return 0;
	snprintf(msg, len, "ucount: %d violations after %llu ops", atomic_read(&uc_bad), total);
	return -EIO;
}

/* ---- target "percpu_ref": lib/percpu-refcount.c, object lifetime driven by a percpu_ref ----
 *
 * CPU 0 is the writer: it allocates an object holding a percpu_ref (initial reference, percpu mode, sometimes ALLOW_REINIT), publishes it behind an RCU
 * pointer, lets the readers run, optionally pushes the ref to atomic mode and back to percpu mode while they run (switch_to_atomic_sync, switch_to_percpu), then
 * unpublishes it and kills the ref with a confirmation callback. Every other CPU is a reader: under rcu_read_lock it loads the pointer and calls
 * percpu_ref_tryget_live_rcu(); on success it checks the object is intact (twice, with a pause) and drops the reference. The release callback (run from the
 * switch-to-atomic RCU callback or by the last put, in any context) frees the object. Invariants: every object is released exactly once (created == released
 * at the end), nobody sees a bad magic number (an early release shows as one, and under KASAN as a use-after-free), and tryget_live never succeeds once the
 * kill has been confirmed (the confirm callback sets a flag; a reader that read the flag set *before* its tryget must have failed).
 * Sabotage: readers take no reference and use the object 30 ms after loading it.
 */
struct pr_obj { struct percpu_ref ref; u32 magic; u32 confirmed; struct rcu_head rcu; };
#define PR_MAGIC 0x7e57ab1e
static struct pr_obj __rcu *pr_cur;
static atomic_t pr_created, pr_released, pr_bad;

static void pr_release(struct percpu_ref *ref)
{
	struct pr_obj *o = container_of(ref, struct pr_obj, ref);

	WRITE_ONCE(o->magic, 0);
	atomic_inc(&pr_released);
	percpu_ref_exit(ref);
	kfree_rcu(o, rcu);
}

static void pr_confirm(struct percpu_ref *ref)
{
	struct pr_obj *o = container_of(ref, struct pr_obj, ref);

	smp_store_release(&o->confirmed, 1);
}

static void pr_init(void)
{
	rcu_barrier();
	rcu_assign_pointer(pr_cur, NULL);
	atomic_set(&pr_created, 0);
	atomic_set(&pr_released, 0);
	atomic_set(&pr_bad, 0);
}

static void pr_op(bool sab)
{
	struct pr_obj *o;
	unsigned int c;

	if (raw_smp_processor_id() == 0) {		/* the writer */
		bool reinit = get_random_u32() & 1;

		o = kzalloc(sizeof(*o), GFP_KERNEL);
		if (!o)
			return;
		o->magic = PR_MAGIC;
		if (percpu_ref_init(&o->ref, pr_release, reinit ? PERCPU_REF_ALLOW_REINIT : 0, GFP_KERNEL)) {
			kfree(o);
			return;
		}
		atomic_inc(&pr_created);
		rcu_assign_pointer(pr_cur, o);
		udelay(20 + get_random_u32() % 40);
		if (reinit && !sab) {
			percpu_ref_switch_to_atomic_sync(&o->ref);
			udelay(10 + get_random_u32() % 20);
			percpu_ref_switch_to_percpu(&o->ref);
			udelay(10 + get_random_u32() % 20);
		}
		rcu_assign_pointer(pr_cur, NULL);
		percpu_ref_kill_and_confirm(&o->ref, pr_confirm);
		if (!sab)
			cond_resched();
		return;
	}

	if (sab) {
		rcu_read_lock();
		o = rcu_dereference(pr_cur);
		rcu_read_unlock();
		if (o) {
			msleep(30);		/* the writer has killed it, the last reference is gone and the grace period has passed */
			if (READ_ONCE(o->magic) != PR_MAGIC)
				atomic_inc(&pr_bad);
		}
		cond_resched();
		return;
	}

	rcu_read_lock();
	o = rcu_dereference(pr_cur);
	if (o) {
		c = smp_load_acquire(&o->confirmed);
		if (percpu_ref_tryget_live_rcu(&o->ref)) {
			rcu_read_unlock();
			if (c)
				atomic_inc(&pr_bad);			/* the kill had been confirmed before this tryget_live started */
			if (READ_ONCE(o->magic) != PR_MAGIC)
				atomic_inc(&pr_bad);
			cpu_relax();
			if (READ_ONCE(o->magic) != PR_MAGIC)
				atomic_inc(&pr_bad);
			percpu_ref_put(&o->ref);
			return;
		}
	}
	rcu_read_unlock();
}

static int pr_check(u64 total, char *msg, size_t len)
{
	int i;

	for (i = 0; i < 100 && atomic_read(&pr_created) != atomic_read(&pr_released); i++) {	/* releases can still be in flight */
		rcu_barrier();
		msleep(10);
	}
	rcu_barrier();
	pr_info("libstress: percpu_ref: %d objects created, %d released, %d bad\n", atomic_read(&pr_created), atomic_read(&pr_released), atomic_read(&pr_bad));
	if (!atomic_read(&pr_bad) && atomic_read(&pr_created) == atomic_read(&pr_released))
		return 0;
	snprintf(msg, len, "percpu_ref: bad reads %d, objects created %d released %d after %llu ops", atomic_read(&pr_bad), atomic_read(&pr_created),
		 atomic_read(&pr_released), total);
	return -EIO;
}

static const struct libstress_target targets[] = {
	{ "spinlock", sl_init, sl_op, sl_check },
	{ "lockref", lr_init, lr_op, lr_check },
	{ "kfifo", kf_init, kf_op, kf_check },
	{ "genalloc", ga_init, ga_op, ga_check },
	{ "assoc_array", as_init, as_op, as_check },
	{ "radix_tree", rtr_init, rtr_op, rtr_check },
	{ "maple_tree", mp_init, mp_op, mp_check },
	{ "rhashtable", rh_init, rh_op, rh_check },
	{ "rcuref", rc_init, rc_op, rc_check },
	{ "stackdepot", sd_init, sd_op, sd_check },
	{ "sbitmap", sb_init, sb_op, sb_check },
	{ "refcount", rf_init, rf_op, rf_check },
	{ "lwq", lq_init, lq_op, lq_check },
	{ "notifier", nt_init, nt_op, nt_check },
	{ "ucount", uc_init, uc_op, uc_check },
	{ "percpu_ref", pr_init, pr_op, pr_check },
};

/* ---- harness ---- */

struct worker {
	struct task_struct *task;
	u64 ops;
	bool sab;
	void (*op)(bool);
};

static int worker_fn(void *data)
{
	struct worker *w = data;

	while (!kthread_should_stop()) {
		unsigned int i;

		for (i = 0; i < 256; i++) {
			w->op(w->sab);
			w->ops++;
		}
		cond_resched();
	}
	return 0;
}

static DEFINE_SPINLOCK(pa);
static DEFINE_SPINLOCK(pb);
static int __rcu *probe_rcu_ptr;

static void run_probes(void)
{
	char *p, *copy, *tok;

	if (!probe_list || !*probe_list)
		return;
	copy = kstrdup(probe_list, GFP_KERNEL);
	if (!copy)
		return;
	p = copy;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (!strcmp(tok, "lockdep")) {
			pr_info("probe lockdep: taking A->B then B->A (a checker report must follow)\n");
			spin_lock(&pa); spin_lock(&pb); spin_unlock(&pb); spin_unlock(&pa);
			spin_lock(&pb); spin_lock(&pa); spin_unlock(&pa); spin_unlock(&pb);
		} else if (!strcmp(tok, "sleep")) {
			pr_info("probe sleep: might_sleep() under a spinlock (a checker report must follow)\n");
			spin_lock(&pa);
			might_sleep();
			spin_unlock(&pa);
		} else if (!strcmp(tok, "rcu")) {
			pr_info("probe rcu: rcu_dereference() outside a read-side section (a checker report must follow)\n");
			(void)rcu_dereference(probe_rcu_ptr);
		} else if (!strcmp(tok, "kasan")) {
			volatile char *m = kmalloc(8, GFP_KERNEL);

			pr_info("probe kasan: reading 1 byte past kmalloc(8) (a checker report must follow)\n");
			if (m) {
				(void)m[8];
				kfree((void *)m);
			}
		} else {
			pr_info("probe '%s': unknown\n", tok);
		}
	}
	kfree(copy);
}

static int __init libstress_init(void)
{
	const struct libstress_target *t = NULL;
	struct worker *w;
	unsigned int n, i, started = 0, cpu;
	unsigned int passed = 0, failed = 0;
	u64 total = 0;
	char msg[96];

	if (!run_seconds && !(probe_list && *probe_list))
		return 0;			/* default: silent */

	run_probes();
	if (!run_seconds)
		return 0;

	for (i = 0; i < ARRAY_SIZE(targets); i++)
		if (!strcmp(targets[i].name, target_name))
			t = &targets[i];
	if (!t) {
		pr_err("unknown target '%s'\n", target_name);
		pr_info("%u passed, 1 failed\n", 0);
		return 0;
	}

	n = nthreads ? nthreads : num_online_cpus();
	w = kcalloc(n, sizeof(*w), GFP_KERNEL);
	if (!w)
		return 0;
	t->init();

	pr_info("start target=%s threads=%u online=%u seconds=%u sabotage=%d\n",
		t->name, n, num_online_cpus(), run_seconds, sabotage);
	cpu = cpumask_first(cpu_online_mask);
	for (i = 0; i < n; i++) {
		w[i].op = t->op;
		w[i].sab = sabotage;
		w[i].task = kthread_create(worker_fn, &w[i], "libstress/%u", i);
		if (IS_ERR(w[i].task)) {
			w[i].task = NULL;
			failed++;
			continue;
		}
		kthread_bind(w[i].task, cpu);
		cpu = cpumask_next(cpu, cpu_online_mask);
		if (cpu >= nr_cpu_ids)
			cpu = cpumask_first(cpu_online_mask);
		started++;
	}
	for (i = 0; i < n; i++)
		if (w[i].task)
			wake_up_process(w[i].task);
	msleep(run_seconds * 1000);
	for (i = 0; i < n; i++) {
		if (w[i].task) {
			kthread_stop(w[i].task);
			total += w[i].ops;
		}
		pr_info("thread %u ops=%llu\n", i, w[i].ops);
	}

	msg[0] = 0;
	if (t->check(total, msg, sizeof(msg)))
		failed++;
	else
		passed++;
	pr_info("target=%s threads_started=%u total_ops=%llu %s%s\n", t->name,
		started, total, msg[0] ? "FAIL: " : "ok", msg);
	pr_info("%u passed, %u failed\n", passed, failed);
	kfree(w);
	return 0;
}
late_initcall(libstress_init);

MODULE_DESCRIPTION("lib/ concurrency stress harness");
MODULE_LICENSE("GPL");
