// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Facebook
 * Copyright (C) 2013-2014 Jens Axboe
 *
 * RUST PORT (lib/sbitmap.c, 6.18.49): the algorithms -- allocation, deferred clear, resize, weight, the batch allocator, the wake-batch arithmetic
 * and the wake-up / clear paths -- are in sbitmap_rs.rs. This file keeps initialisation (percpu and kvzalloc allocation, lock and waitqueue init),
 * the seq_file output, the wait-queue plumbing, the exports as thunks (their MODVERSIONS fingerprints come from the DWARF of the definition) and
 * one-line wrappers (rust_sbw_*) for every primitive whose body depends on the configuration (raw spinlock with irq save, per-CPU access, memory
 * barriers, wait-queue wake-ups, the header's deferred-clear inline, WARN sites -- a warning now names this file: recorded divergence). The
 * strides that vary with the configuration are exported as constants. Upstream's whole file is installed as sbitmap_norust.c for CONFIG_RUST=n.
 */

#include <linux/sched.h>
#include <linux/random.h>
#include <linux/sbitmap.h>
#include <linux/seq_file.h>

static_assert(sizeof(struct sbitmap) == 32 && offsetof(struct sbitmap, depth) == 0 && offsetof(struct sbitmap, shift) == 4 &&
	      offsetof(struct sbitmap, map_nr) == 8 && offsetof(struct sbitmap, round_robin) == 12 && offsetof(struct sbitmap, map) == 16 &&
	      offsetof(struct sbitmap, alloc_hint) == 24);
static_assert(offsetof(struct sbitmap_queue, sb) == 0 && offsetof(struct sbitmap_queue, wake_batch) == 32 &&
	      offsetof(struct sbitmap_queue, wake_index) == 36 && offsetof(struct sbitmap_queue, ws) == 40 &&
	      offsetof(struct sbitmap_queue, ws_active) == 48 && offsetof(struct sbitmap_queue, min_shallow_depth) == 52 &&
	      offsetof(struct sbitmap_queue, completion_cnt) == 56 && offsetof(struct sbitmap_queue, wakeup_cnt) == 60);
static_assert(offsetof(struct sbitmap_word, word) == 0 && offsetof(struct sbq_wait_state, wait) == 0 && sizeof(atomic_t) == 4);
static_assert(SBQ_WAIT_QUEUES == 8 && SBQ_WAKE_BATCH == 8 && BITS_PER_LONG == 64);

extern const size_t rust_sb_word_size, rust_sb_off_cleared, rust_sb_off_lock, rust_sb_ws_size;
const size_t rust_sb_word_size = sizeof(struct sbitmap_word);
const size_t rust_sb_off_cleared = offsetof(struct sbitmap_word, cleared);
const size_t rust_sb_off_lock = offsetof(struct sbitmap_word, swap_lock);
const size_t rust_sb_ws_size = sizeof(struct sbq_wait_state);

/* lib/sbitmap_rs.rs */
void rust_sbitmap_resize(struct sbitmap *sb, unsigned int depth);
int rust_sbitmap_get(struct sbitmap *sb);
int rust_sbitmap_get_shallow(struct sbitmap *sb, unsigned long shallow_depth);
bool rust_sbitmap_any_bit_set(const struct sbitmap *sb);
unsigned int rust_sbitmap_cleared(const struct sbitmap *sb);
unsigned int rust_sbitmap_weight(const struct sbitmap *sb);
unsigned int rust_sbq_calc_wake_batch(struct sbitmap_queue *sbq, unsigned int depth);
void rust_sbitmap_queue_recalculate_wake_batch(struct sbitmap_queue *sbq, unsigned int users);
void rust_sbitmap_queue_resize(struct sbitmap_queue *sbq, unsigned int depth);
unsigned long rust_sbitmap_queue_get_batch(struct sbitmap_queue *sbq, int nr_tags, unsigned int *offset);
int rust_sbitmap_queue_get_shallow(struct sbitmap_queue *sbq, unsigned int shallow_depth);
void rust_sbitmap_queue_min_shallow_depth(struct sbitmap_queue *sbq, unsigned int min_shallow_depth);
void rust_sbitmap_queue_wake_up(struct sbitmap_queue *sbq, int nr);
void rust_sbitmap_queue_clear_batch(struct sbitmap_queue *sbq, int offset, int *tags, int nr_tags);
void rust_sbitmap_queue_clear(struct sbitmap_queue *sbq, unsigned int nr, unsigned int cpu);
void rust_sbitmap_queue_wake_all(struct sbitmap_queue *sbq);

unsigned long rust_sbw_lock_irqsave(void *lock);
void rust_sbw_unlock_irqrestore(void *lock, unsigned long flags);
unsigned int rust_sbw_hint_read(struct sbitmap *sb);
void rust_sbw_hint_write(struct sbitmap *sb, unsigned int v);
void rust_sbw_hint_write_cpu(struct sbitmap *sb, int cpu, unsigned int v);
unsigned int rust_sbw_random_below(unsigned int n);
int rust_sbw_cpu(void);
bool rust_sbw_warn_no_hint_get(bool cond);
bool rust_sbw_warn_no_hint_shallow(bool cond);
void rust_sbw_warn_shallow(bool cond);
bool rust_sbw_waitqueue_active(void *ws);
int rust_sbw_wake_up_nr(void *ws, int nr);
void rust_sbw_wake_up(void *ws);
void rust_sbw_mb_before_atomic(void);
void rust_sbw_mb_after_atomic(void);
void rust_sbw_mb(void);
void rust_sbw_deferred_clear_bit(struct sbitmap *sb, unsigned int nr);

unsigned long rust_sbw_lock_irqsave(void *lock)
{
	unsigned long flags;

	raw_spin_lock_irqsave((raw_spinlock_t *)lock, flags);
	return flags;
}
void rust_sbw_unlock_irqrestore(void *lock, unsigned long flags) { raw_spin_unlock_irqrestore((raw_spinlock_t *)lock, flags); }
unsigned int rust_sbw_hint_read(struct sbitmap *sb) { return this_cpu_read(*sb->alloc_hint); }
void rust_sbw_hint_write(struct sbitmap *sb, unsigned int v) { this_cpu_write(*sb->alloc_hint, v); }
void rust_sbw_hint_write_cpu(struct sbitmap *sb, int cpu, unsigned int v) { data_race(*per_cpu_ptr(sb->alloc_hint, cpu) = v); }
unsigned int rust_sbw_random_below(unsigned int n) { return get_random_u32_below(n); }
int rust_sbw_cpu(void) { return raw_smp_processor_id(); }
bool rust_sbw_warn_no_hint_get(bool cond) { return WARN_ON_ONCE(cond); }
bool rust_sbw_warn_no_hint_shallow(bool cond) { return WARN_ON_ONCE(cond); }
void rust_sbw_warn_shallow(bool cond) { WARN_ON_ONCE(cond); }
bool rust_sbw_waitqueue_active(void *ws) { return waitqueue_active(&((struct sbq_wait_state *)ws)->wait); }
int rust_sbw_wake_up_nr(void *ws, int nr) { return __wake_up(&((struct sbq_wait_state *)ws)->wait, TASK_NORMAL, nr, NULL); }
void rust_sbw_wake_up(void *ws) { wake_up(&((struct sbq_wait_state *)ws)->wait); }
void rust_sbw_mb_before_atomic(void) { smp_mb__before_atomic(); }
void rust_sbw_mb_after_atomic(void) { smp_mb__after_atomic(); }
void rust_sbw_mb(void) { smp_mb(); }
void rust_sbw_deferred_clear_bit(struct sbitmap *sb, unsigned int nr) { sbitmap_deferred_clear_bit(sb, nr); }

static int init_alloc_hint(struct sbitmap *sb, gfp_t flags)
{
	unsigned depth = sb->depth;

	sb->alloc_hint = alloc_percpu_gfp(unsigned int, flags);
	if (!sb->alloc_hint)
		return -ENOMEM;

	if (depth && !sb->round_robin) {
		int i;

		for_each_possible_cpu(i)
			*per_cpu_ptr(sb->alloc_hint, i) = get_random_u32_below(depth);
	}
	return 0;
}

int sbitmap_init_node(struct sbitmap *sb, unsigned int depth, int shift,
		      gfp_t flags, int node, bool round_robin,
		      bool alloc_hint)
{
	unsigned int bits_per_word;
	int i;

	if (shift < 0)
		shift = sbitmap_calculate_shift(depth);

	bits_per_word = 1U << shift;
	if (bits_per_word > BITS_PER_LONG)
		return -EINVAL;

	sb->shift = shift;
	sb->depth = depth;
	sb->map_nr = DIV_ROUND_UP(sb->depth, bits_per_word);
	sb->round_robin = round_robin;

	if (depth == 0) {
		sb->map = NULL;
		return 0;
	}

	if (alloc_hint) {
		if (init_alloc_hint(sb, flags))
			return -ENOMEM;
	} else {
		sb->alloc_hint = NULL;
	}

	sb->map = kvzalloc_node(sb->map_nr * sizeof(*sb->map), flags, node);
	if (!sb->map) {
		free_percpu(sb->alloc_hint);
		return -ENOMEM;
	}

	for (i = 0; i < sb->map_nr; i++)
		raw_spin_lock_init(&sb->map[i].swap_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(sbitmap_init_node);

void sbitmap_resize(struct sbitmap *sb, unsigned int depth)
{
	rust_sbitmap_resize(sb, depth);
}
EXPORT_SYMBOL_GPL(sbitmap_resize);

int sbitmap_get(struct sbitmap *sb)
{
	return rust_sbitmap_get(sb);
}
EXPORT_SYMBOL_GPL(sbitmap_get);

bool sbitmap_any_bit_set(const struct sbitmap *sb)
{
	return rust_sbitmap_any_bit_set(sb);
}
EXPORT_SYMBOL_GPL(sbitmap_any_bit_set);

unsigned int sbitmap_weight(const struct sbitmap *sb)
{
	return rust_sbitmap_weight(sb);
}
EXPORT_SYMBOL_GPL(sbitmap_weight);

void sbitmap_show(struct sbitmap *sb, struct seq_file *m)
{
	seq_printf(m, "depth=%u\n", sb->depth);
	seq_printf(m, "busy=%u\n", sbitmap_weight(sb));
	seq_printf(m, "cleared=%u\n", rust_sbitmap_cleared(sb));
	seq_printf(m, "bits_per_word=%u\n", 1U << sb->shift);
	seq_printf(m, "map_nr=%u\n", sb->map_nr);
}
EXPORT_SYMBOL_GPL(sbitmap_show);

static inline void emit_byte(struct seq_file *m, unsigned int offset, u8 byte)
{
	if ((offset & 0xf) == 0) {
		if (offset != 0)
			seq_putc(m, '\n');
		seq_printf(m, "%08x:", offset);
	}
	if ((offset & 0x1) == 0)
		seq_putc(m, ' ');
	seq_printf(m, "%02x", byte);
}

void sbitmap_bitmap_show(struct sbitmap *sb, struct seq_file *m)
{
	u8 byte = 0;
	unsigned int byte_bits = 0;
	unsigned int offset = 0;
	int i;

	for (i = 0; i < sb->map_nr; i++) {
		unsigned long word = READ_ONCE(sb->map[i].word);
		unsigned long cleared = READ_ONCE(sb->map[i].cleared);
		unsigned int word_bits = __map_depth(sb, i);

		word &= ~cleared;

		while (word_bits > 0) {
			unsigned int bits = min(8 - byte_bits, word_bits);

			byte |= (word & (BIT(bits) - 1)) << byte_bits;
			byte_bits += bits;
			if (byte_bits == 8) {
				emit_byte(m, offset, byte);
				byte = 0;
				byte_bits = 0;
				offset++;
			}
			word >>= bits;
			word_bits -= bits;
		}
	}
	if (byte_bits) {
		emit_byte(m, offset, byte);
		offset++;
	}
	if (offset)
		seq_putc(m, '\n');
}
EXPORT_SYMBOL_GPL(sbitmap_bitmap_show);

int sbitmap_queue_init_node(struct sbitmap_queue *sbq, unsigned int depth,
			    int shift, bool round_robin, gfp_t flags, int node)
{
	int ret;
	int i;

	ret = sbitmap_init_node(&sbq->sb, depth, shift, flags, node,
				round_robin, true);
	if (ret)
		return ret;

	sbq->min_shallow_depth = UINT_MAX;
	sbq->wake_batch = rust_sbq_calc_wake_batch(sbq, depth);
	atomic_set(&sbq->wake_index, 0);
	atomic_set(&sbq->ws_active, 0);
	atomic_set(&sbq->completion_cnt, 0);
	atomic_set(&sbq->wakeup_cnt, 0);

	sbq->ws = kzalloc_node(SBQ_WAIT_QUEUES * sizeof(*sbq->ws), flags, node);
	if (!sbq->ws) {
		sbitmap_free(&sbq->sb);
		return -ENOMEM;
	}

	for (i = 0; i < SBQ_WAIT_QUEUES; i++)
		init_waitqueue_head(&sbq->ws[i].wait);

	return 0;
}
EXPORT_SYMBOL_GPL(sbitmap_queue_init_node);

void sbitmap_queue_recalculate_wake_batch(struct sbitmap_queue *sbq,
					    unsigned int users)
{
	rust_sbitmap_queue_recalculate_wake_batch(sbq, users);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_recalculate_wake_batch);

void sbitmap_queue_resize(struct sbitmap_queue *sbq, unsigned int depth)
{
	rust_sbitmap_queue_resize(sbq, depth);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_resize);

int __sbitmap_queue_get(struct sbitmap_queue *sbq)
{
	return sbitmap_get(&sbq->sb);
}
EXPORT_SYMBOL_GPL(__sbitmap_queue_get);

unsigned long __sbitmap_queue_get_batch(struct sbitmap_queue *sbq, int nr_tags,
					unsigned int *offset)
{
	return rust_sbitmap_queue_get_batch(sbq, nr_tags, offset);
}

int sbitmap_queue_get_shallow(struct sbitmap_queue *sbq,
			      unsigned int shallow_depth)
{
	return rust_sbitmap_queue_get_shallow(sbq, shallow_depth);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_get_shallow);

void sbitmap_queue_min_shallow_depth(struct sbitmap_queue *sbq,
				     unsigned int min_shallow_depth)
{
	rust_sbitmap_queue_min_shallow_depth(sbq, min_shallow_depth);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_min_shallow_depth);

void sbitmap_queue_wake_up(struct sbitmap_queue *sbq, int nr)
{
	rust_sbitmap_queue_wake_up(sbq, nr);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_wake_up);

void sbitmap_queue_clear_batch(struct sbitmap_queue *sbq, int offset,
				int *tags, int nr_tags)
{
	rust_sbitmap_queue_clear_batch(sbq, offset, tags, nr_tags);
}

void sbitmap_queue_clear(struct sbitmap_queue *sbq, unsigned int nr,
			 unsigned int cpu)
{
	rust_sbitmap_queue_clear(sbq, nr, cpu);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_clear);

void sbitmap_queue_wake_all(struct sbitmap_queue *sbq)
{
	rust_sbitmap_queue_wake_all(sbq);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_wake_all);

void sbitmap_queue_show(struct sbitmap_queue *sbq, struct seq_file *m)
{
	bool first;
	int i;

	sbitmap_show(&sbq->sb, m);

	seq_puts(m, "alloc_hint={");
	first = true;
	for_each_possible_cpu(i) {
		if (!first)
			seq_puts(m, ", ");
		first = false;
		seq_printf(m, "%u", *per_cpu_ptr(sbq->sb.alloc_hint, i));
	}
	seq_puts(m, "}\n");

	seq_printf(m, "wake_batch=%u\n", sbq->wake_batch);
	seq_printf(m, "wake_index=%d\n", atomic_read(&sbq->wake_index));
	seq_printf(m, "ws_active=%d\n", atomic_read(&sbq->ws_active));

	seq_puts(m, "ws={\n");
	for (i = 0; i < SBQ_WAIT_QUEUES; i++) {
		struct sbq_wait_state *ws = &sbq->ws[i];
		seq_printf(m, "\t{.wait=%s},\n",
			   waitqueue_active(&ws->wait) ? "active" : "inactive");
	}
	seq_puts(m, "}\n");

	seq_printf(m, "round_robin=%d\n", sbq->sb.round_robin);
	seq_printf(m, "min_shallow_depth=%u\n", sbq->min_shallow_depth);
}
EXPORT_SYMBOL_GPL(sbitmap_queue_show);

void sbitmap_add_wait_queue(struct sbitmap_queue *sbq,
			    struct sbq_wait_state *ws,
			    struct sbq_wait *sbq_wait)
{
	if (!sbq_wait->sbq) {
		sbq_wait->sbq = sbq;
		atomic_inc(&sbq->ws_active);
		add_wait_queue(&ws->wait, &sbq_wait->wait);
	}
}
EXPORT_SYMBOL_GPL(sbitmap_add_wait_queue);

void sbitmap_del_wait_queue(struct sbq_wait *sbq_wait)
{
	list_del_init(&sbq_wait->wait.entry);
	if (sbq_wait->sbq) {
		atomic_dec(&sbq_wait->sbq->ws_active);
		sbq_wait->sbq = NULL;
	}
}
EXPORT_SYMBOL_GPL(sbitmap_del_wait_queue);

void sbitmap_prepare_to_wait(struct sbitmap_queue *sbq,
			     struct sbq_wait_state *ws,
			     struct sbq_wait *sbq_wait, int state)
{
	if (!sbq_wait->sbq) {
		atomic_inc(&sbq->ws_active);
		sbq_wait->sbq = sbq;
	}
	prepare_to_wait_exclusive(&ws->wait, &sbq_wait->wait, state);
}
EXPORT_SYMBOL_GPL(sbitmap_prepare_to_wait);

void sbitmap_finish_wait(struct sbitmap_queue *sbq, struct sbq_wait_state *ws,
			 struct sbq_wait *sbq_wait)
{
	finish_wait(&ws->wait, &sbq_wait->wait);
	if (sbq_wait->sbq) {
		atomic_dec(&sbq->ws_active);
		sbq_wait->sbq = NULL;
	}
}
EXPORT_SYMBOL_GPL(sbitmap_finish_wait);

