/* sbitmap differential: the same op stream drives pristine lib/sbitmap.c (ARM_REF) or sbitmap_glue.c over sbitmap_rs.rs (ARM_RS); every op prints its
 * result and the whole visible state (each word and cleared mask, the per-CPU hints, the queue's wake counters, waiter wake-ups). The two transcripts
 * must be byte-identical.  usage: t SHARD   (env SB_N ops per shard, SB_PROVE=1 poisons the Rust arm to show the harness can fail) */
#include "kshim.h"
#include SRC

bool warn_site[64]; int warn_count, shim_cpu, alloc_fail_in; u64 shim_rng; long wakeups_seen;

static u64 rs_;
static u32 rnd(u32 n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (u32)(rs_ >> 33) % n : 0; }

static struct sbitmap sb; static struct sbitmap_queue sbq;
static unsigned int sb_alloc_words, sbq_alloc_words;
static int sb_ok, sbq_ok;
static int wake_log[8];
static struct sbq_wait waiters[4]; static bool queued[4];

static int wfn(struct wait_queue_entry *e, unsigned m, int s, void *k)
{
	int id = (int)(long)e->private;
	wake_log[id]++;
	return id & 1 ? 1 : (int)(wake_log[id] & 1);	/* odd ids always accept, even ids every other time */
}

static u64 fnv(const void *p, size_t n) { const unsigned char *c = p; u64 h = 1469598103934665603ULL; while (n--) { h ^= *c++; h *= 1099511628211ULL; } return h; }

static void show_sb(const char *tag, struct sbitmap *s, unsigned int words)
{
	printf("  %s d=%u sh=%u mn=%u rr=%d hint=", tag, s->depth, s->shift, s->map_nr, s->round_robin);
	if (s->alloc_hint) for (int c = 0; c < NSHIM_CPUS; c++) printf("%u,", s->alloc_hint[c]); else printf("-");
	printf(" words=");
	if (s->map) for (unsigned i = 0; i < words; i++) printf("%lx/%lx,", s->map[i].word, s->map[i].cleared);
	printf("\n");
}

static void state(void)
{
	if (sb_ok) show_sb("S", &sb, sb_alloc_words);
	if (sbq_ok) {
		show_sb("Q", &sbq.sb, sbq_alloc_words);
		printf("  Q wb=%u wi=%d wa=%d ms=%u cc=%d wc=%d warn=%d seen=%ld wk=%d,%d,%d,%d\n", sbq.wake_batch, atomic_read(&sbq.wake_index),
		       atomic_read(&sbq.ws_active), sbq.min_shallow_depth, atomic_read(&sbq.completion_cnt), atomic_read(&sbq.wakeup_cnt), warn_count,
		       wakeups_seen, wake_log[0], wake_log[1], wake_log[2], wake_log[3]);
	}
}

static void dump_show(const char *what, void (*fn)(void *, struct seq_file *), void *obj)
{
	struct seq_file m = { 0 };
	fn(obj, &m);
	printf("%s len=%zu h=%016llx\n", what, m.n, (unsigned long long)(m.n ? fnv(m.buf, m.n) : 0));
	free(m.buf);
}
static void f_sb_show(void *o, struct seq_file *m) { sbitmap_show(o, m); }
static void f_sb_bshow(void *o, struct seq_file *m) { sbitmap_bitmap_show(o, m); }
static void f_q_show(void *o, struct seq_file *m) { sbitmap_queue_show(o, m); }

static int tags[256]; static int ntags;
static void push(int t) { if (t >= 0) { if (ntags < 256) tags[ntags++] = t; else tags[rnd(256)] = t; } }
static int pick(int dflt) { return ntags && rnd(8) ? tags[rnd(ntags)] : dflt; }

static void reinit(void)
{
	int depth = rnd(6) == 0 ? rnd(8) : rnd(5) == 0 ? 64 + rnd(100) : 1 + rnd(150);
	int shift = rnd(3) == 0 ? -1 : rnd(8) - (rnd(10) == 0 ? 0 : 1) ;
	bool rr = rnd(3) == 0;
	if (shift < -1) shift = -1;
	memset(&sb, 0, sizeof(sb)); memset(&sbq, 0, sizeof(sbq)); memset(warn_site, 0, sizeof(warn_site));
	for (int i = 0; i < 4; i++) { if (queued[i]) { list_del_init(&waiters[i].wait.entry); queued[i] = false; } }
	alloc_fail_in = rnd(8) == 0 ? 1 + rnd(3) : 0;
	int r1 = sbitmap_init_node(&sb, depth, shift, GFP_KERNEL, NUMA_NO_NODE, rr, rnd(6) != 0);
	alloc_fail_in = rnd(8) == 0 ? 1 + rnd(4) : 0;
	int r2 = sbitmap_queue_init_node(&sbq, depth, shift, rr, GFP_KERNEL, NUMA_NO_NODE);
	alloc_fail_in = 0;
	sb_ok = r1 == 0; sbq_ok = r2 == 0;
	sb_alloc_words = sb_ok ? sb.map_nr : 0; sbq_alloc_words = sbq_ok ? sbq.sb.map_nr : 0;
	ntags = 0;
	for (int i = 0; i < 4; i++) {
		memset(&waiters[i], 0, sizeof(waiters[i]));
		waiters[i].wait.private = (void *)(long)i; waiters[i].wait.func = wfn; INIT_LIST_HEAD(&waiters[i].wait.entry); wake_log[i] = 0;
	}
	printf("init d=%d sh=%d rr=%d -> %d %d\n", depth, shift, rr, r1, r2);
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("SB_N") ? atol(getenv("SB_N")) : 20000;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1); shim_rng = 0x1234567ULL * (shard + 3);
	reinit(); state();
	for (long i = 0; i < n; i++) {
		unsigned op = rnd(34);
		shim_cpu = rnd(NSHIM_CPUS);
		if (i % 600 == 599) { reinit(); state(); continue; }
		if (op < 4 && sb_ok) { int r = sbitmap_get(&sb); push(r); printf("sb_get cpu=%d -> %d\n", shim_cpu, r); }
		else if (op < 6 && sb_ok) { int t = pick(rnd(sb.depth + 3)); if (t >= 0 && (unsigned)t < sb.depth) sbitmap_put(&sb, t); printf("sb_put %d\n", t); }
		else if (op == 6 && sb_ok) { unsigned d = rnd(sb_alloc_words * (1u << sb.shift) + 1); sbitmap_resize(&sb, d); printf("sb_resize %u\n", d); }
		else if (op == 7 && sb_ok) printf("sb_any %d\n", sbitmap_any_bit_set(&sb));
		else if (op == 8 && sb_ok) printf("sb_weight %u\n", sbitmap_weight(&sb));
		else if (op == 9 && sb_ok) dump_show("sb_show", f_sb_show, &sb);
		else if (op == 10 && sb_ok) dump_show("sb_bshow", f_sb_bshow, &sb);
		else if (op < 14 && sbq_ok) { int r = __sbitmap_queue_get(&sbq); push(r); printf("q_get cpu=%d -> %d\n", shim_cpu, r); }
		else if (op < 16 && sbq_ok) { unsigned sd = rnd(sbq.sb.depth + 4); int r = sbitmap_queue_get_shallow(&sbq, sd); push(r); printf("q_shallow %u -> %d\n", sd, r); }
		else if (op < 19 && sbq_ok && sbq.sb.alloc_hint) {
			int nt = 1 + rnd(8); unsigned off = 0xdead; unsigned long m = __sbitmap_queue_get_batch(&sbq, nt, &off);
			if (m) { for (int b = 0; b < 64; b++) if (m >> b & 1) push(off + b); }
			printf("q_batch %d -> %lx off=%x\n", nt, m, m ? off : 0);
		} else if (op < 21 && sbq_ok) { int t = pick(rnd(sbq.sb.depth + 3)); unsigned cc = rnd(NSHIM_CPUS); if (rnd(10) == 0 && (sbq.sb.depth & ((1u << sbq.sb.shift) - 1))) t = sbq.sb.depth; if (t >= 0 && (unsigned)t <= sbq.sb.depth && sbq.sb.depth && (unsigned)t < sbq.sb.map_nr * (1u << sbq.sb.shift)) sbitmap_queue_clear(&sbq, t, cc); printf("q_clear %d cpu=%u\n", t, cc); }
		else if (op == 21 && sbq_ok) {
			int nt = 1 + rnd(5), off = rnd(4); int tg[5];
			for (int k = 0; k < nt; k++) { int t = pick(rnd(sbq.sb.depth + 1)); if (t < 0 || (unsigned)t >= sbq.sb.depth) t = 0; tg[k] = t + off; }
			if (sbq.sb.depth) sbitmap_queue_clear_batch(&sbq, off, tg, nt);
			printf("q_clear_batch off=%d n=%d t0=%d\n", off, nt, tg[0]);
		} else if (op < 24 && sbq_ok) { int k = 1 + rnd(5); sbitmap_queue_wake_up(&sbq, k); printf("q_wake %d\n", k); }
		else if (op == 24 && sbq_ok) { sbitmap_queue_wake_all(&sbq); printf("q_wake_all\n"); }
		else if (op == 25 && sbq_ok) { unsigned v = rnd(40); sbitmap_queue_min_shallow_depth(&sbq, v); printf("q_minshallow %u\n", v); }
		else if (op == 26 && sbq_ok) { unsigned u = 1 + rnd(12); sbitmap_queue_recalculate_wake_batch(&sbq, u); printf("q_recalc %u\n", u); }
		else if (op == 27 && sbq_ok) { unsigned d = rnd(sbq_alloc_words * (1u << sbq.sb.shift) + 1); sbitmap_queue_resize(&sbq, d); printf("q_resize %u\n", d); }
		else if (op == 28 && sbq_ok && sbq.sb.alloc_hint) dump_show("q_show", f_q_show, &sbq);
		else if (op < 31 && sbq_ok) {
			int w = rnd(4), q = rnd(8);
			if (!queued[w]) { if (rnd(2)) sbitmap_add_wait_queue(&sbq, &sbq.ws[q], &waiters[w]); else sbitmap_prepare_to_wait(&sbq, &sbq.ws[q], &waiters[w], 2); queued[w] = true; }
			printf("q_wait_add w=%d ws=%d\n", w, q);
		} else if (op < 33 && sbq_ok) {
			int w = rnd(4);
			if (queued[w]) { if (rnd(2)) sbitmap_del_wait_queue(&waiters[w]); else sbitmap_finish_wait(&sbq, &sbq.ws[0], &waiters[w]); queued[w] = false; }
			printf("q_wait_del w=%d\n", w);
		} else printf("nop\n");
		state();
	}
#ifdef ARM_RS
	if (getenv("SB_PROVE")) printf("poison\n");
#endif
	return 0;
}
