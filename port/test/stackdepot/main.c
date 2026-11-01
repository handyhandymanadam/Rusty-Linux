/* stackdepot differential: the same op stream drives pristine lib/stackdepot.c (ARM_REF) or stackdepot_glue.c over stackdepot_rs.rs (ARM_RS);
 * every op prints its result and the whole visible state (pools, offset, counters, freelist length, bucket occupancy). The two transcripts must be
 * byte-identical.  usage: t SHARD   (env SD_N ops, SD_PROVE=1 poisons the Rust arm to show the harness can fail) */
#include "kshim.h"
#include SRC

int warn_count; unsigned long rcu_gp_seq, rcu_gp_done; int in_nmi_flag, alloc_fail_in, trylock_fail_flag, sd_weak_hash; long pages_live;

static u64 rs_;
static u32 rnd(u32 n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (u32)(rs_ >> 33) % n : 0; }

#define NST 400
static unsigned long st[NST][72]; static unsigned nst[NST];
static depot_stack_handle_t issued[4096]; static int nissued;

static u64 fnv(const void *p, size_t n) { const unsigned char *c = p; u64 h = 1469598103934665603ULL; while (n--) { h ^= *c++; h *= 1099511628211ULL; } return h; }

static void state(void)
{
	long fl = 0, occ = 0; struct list_head *p;
	for (p = free_stacks.next; p != &free_stacks && fl < 100000; p = p->next) fl++;
	if (stack_table) for (unsigned i = 0; i <= stack_hash_mask; i++) if (!list_empty(&stack_table[i])) occ += 1 + i % 7;
	printf("  S pools=%d off=%zu new=%d c=%ld,%ld,%ld,%ld,%ld,%ld fl=%ld occ=%ld warn=%d live=%ld dis=%d\n", pools_num, pool_offset,
	       new_pool == NULL ? 0 : new_pool == STACK_DEPOT_POISON ? 2 : 1, counters[0], counters[1], counters[2], counters[3], counters[4], counters[5],
	       fl, occ, warn_count, pages_live, stack_depot_disabled);
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("SD_N") ? atol(getenv("SD_N")) : 20000;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (int i = 0; i < NST; i++) {
		nst[i] = rnd(10) == 0 ? rnd(72) : 1 + rnd(i % 5 == 0 ? 70 : 12);
		for (unsigned j = 0; j < 72; j++) st[i][j] = 0xffffffff81000000UL + rnd(i % 3 ? 40 : 100000) * 16;
		if (rnd(8) == 0 && nst[i] > 2) st[i][rnd(nst[i])] = SD_IRQ_FRAME;
	}
	if (shard & 1) stack_max_pools = 2 + shard % 3;	/* tiny limit: the capacity warning and pool-full paths */
	if (shard & 2) sd_weak_hash = 1;	/* 4 hash values: long bucket chains, so the entry compare decides */
	printf("init %d\n", stack_depot_init());
	state();
	for (long i = 0; i < n; i++) {
		unsigned op = rnd(20);
		if (op < 9) {
			int k = rnd(NST); depot_flags_t fl = rnd(30) == 0 ? rnd(8) : rnd(4);
			gfp_t g = rnd(8) == 0 ? 0x8000u : GFP_KERNEL;
			alloc_fail_in = rnd(6) == 0 ? 1 + rnd(3) : 0; in_nmi_flag = rnd(12) == 0; trylock_fail_flag = (in_nmi_flag || g == 0x8000u) && rnd(2) == 0;
			depot_stack_handle_t h = stack_depot_save_flags(st[k], nst[k], g, fl);
			alloc_fail_in = 0; in_nmi_flag = 0; trylock_fail_flag = 0;
			if (h && nissued < 4096) issued[nissued++] = h; else if (h) issued[rnd(4096)] = h;
			printf("save k=%d n=%u fl=%u g=%x -> %08x\n", k, nst[k], fl, g, h);
		} else if (op < 12) {
			depot_stack_handle_t h = nissued && rnd(8) ? issued[rnd(nissued)] : rnd(4) ? rnd(0x7fffffff) * 2 + rnd(2) : 0;
			unsigned long *e = (void *)0x1; unsigned r = stack_depot_fetch(h, &e);
			printf("fetch %08x -> %u e=%d h=%016llx\n", h, r, e == NULL, (unsigned long long)(r ? fnv(e, r * sizeof(*e)) : 0));
		} else if (op < 15) {
			depot_stack_handle_t h = nissued && rnd(8) ? issued[rnd(nissued)] : rnd(4) ? rnd(0x7fffffff) * 2 + rnd(2) : 0;
			stack_depot_put(h); printf("put %08x\n", h);
		} else if (op < 17) {
			depot_stack_handle_t h = nissued && rnd(8) ? issued[rnd(nissued)] : rnd(0x7fffffff) * 2;
			struct stack_record *s = __stack_depot_get_stack_record(h);
			printf("getrec %08x -> %d", h, s != NULL);
			if (s) printf(" hash=%08x size=%u handle=%08x cnt=%u", s->hash, s->size, s->handle.handle, refcount_read(&s->count));
			printf("\n");
		} else if (op < 19) {
			rcu_gp_done = rcu_gp_seq - rnd(3) * (rcu_gp_seq > 2); if (rnd(2)) rcu_gp_done = rcu_gp_seq; printf("gp %lu %lu\n", rcu_gp_seq, rcu_gp_done);
		} else {
			depot_stack_handle_t h = nissued ? issued[rnd(nissued)] : 0; unsigned x = rnd(32);
			depot_stack_handle_t h2 = stack_depot_set_extra_bits(h, x);
			printf("extra %08x %u -> %08x %u\n", h, x, h2, stack_depot_get_extra_bits(h2));
		}
		state();
	}
#ifdef ARM_RS
	if (getenv("SD_PROVE")) printf("poison\n");
#endif
	return 0;
}
