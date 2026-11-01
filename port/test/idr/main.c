/* IDA differential: the same op stream drives the IDA half of pristine lib/idr.c (ARM_REF) or idr_glue.c's wrappers over idr_rs.rs (ARM_RS), both on top of
 * the pristine lib/xarray.c (XA_CHUNK_SHIFT 4). Ops: ida_alloc_range / ida_find_first_range / ida_free / ida_destroy, with ranges near the value-entry and
 * bitmap boundaries, negative (>INT_MAX) arguments, GFP_NOWAIT, and allocation failures injected into kzalloc and into xarray node allocation. After every op
 * the result, the warning count, the live bitmap count and the whole array (every entry and its free mark) are printed.  usage: t SHARD (env IDA_N, IDA_PROVE=1) */
#include "kshim.h"
#include SRC

long fail_alloc, fail_node, live_bitmaps; int warn_count;
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }

static struct ida ida;
static unsigned pool[4096]; static int npool;

static void dump(void)
{
	unsigned long idx = 0; void *e;
	printf("  S live=%ld warn=%d :", live_bitmaps, warn_count);
	for (e = xa_find(&ida.xa, &idx, ULONG_MAX, XA_PRESENT); e; e = xa_find_after(&ida.xa, &idx, ULONG_MAX, XA_PRESENT)) {
		printf(" [%lu%s%s", idx, xa_get_mark(&ida.xa, idx, XA_FREE_MARK) ? " F" : "", xa_is_value(e) ? " v:" : " b:");
		if (xa_is_value(e)) printf("%lx]", xa_to_value(e));
		else { struct ida_bitmap *b = e; for (int i = 0; i < (int)IDA_BITMAP_LONGS; i++) printf("%lx%c", b->bitmap[i], i + 1 < (int)IDA_BITMAP_LONGS ? '.' : ']'); }
	}
	printf("\n");
}

static unsigned pick_min(void)
{
	switch (rnd(10)) {
	case 0: return 0;
	case 1: return 62 + rnd(4);
	case 2: return 1022 + rnd(4);
	case 3: return 2046 + rnd(4);
	case 4: return 0x7ffffff0u + rnd(16);
	case 5: return 0x80000000u + rnd(4);
	case 6: return rnd(40960);
	default: return rnd(3000);
	}
}
static unsigned pick_max(unsigned min)
{
	switch (rnd(8)) {
	case 0: return UINT_MAX;
	case 1: return INT_MAX;
	case 2: return min + rnd(3);
	case 3: return min + 1000 + rnd(200);
	case 4: return rnd(100);
	default: return min + rnd(4000);
	}
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("IDA_N") ? atol(getenv("IDA_N")) : 6000;
	int prove = getenv("IDA_PROVE") != NULL;
	rs_ = 0x1234567ULL * (shard + 1) + 99; xa_init_flags(&ida.xa, IDA_INIT_FLAGS);
	for (long i = 0; i < n; i++) {
		unsigned op = rnd(100); long fa, fn; int r = 0; gfp_t gfp = rnd(4) ? GFP_KERNEL : GFP_NOWAIT;
		if (!rnd(4)) fail_alloc = rnd(2) ? (long)(1 + rnd(3)) : -1L;
		if (!rnd(5)) fail_node = rnd(2) ? (long)(1 + rnd(3)) : -1L;
		fa = fail_alloc; fn = fail_node;
		if (op < 55) {
			unsigned min = pick_min(), max = pick_max(min);
			r = ida_alloc_range(&ida, min, max, gfp);
			printf("%ld alloc %u %u %s f=%ld,%ld -> %d\n", i, min, max, gfp == GFP_KERNEL ? "K" : "N", fa, fn, r);
			if (r >= 0 && npool < 4096) pool[npool++] = r;
		} else if (op < 85) {
			unsigned id;
			if (npool && rnd(8)) { int k = rnd(npool); id = pool[k]; pool[k] = pool[--npool]; } else id = rnd(4) ? rnd(5000) : (unsigned)rnd(0xffffffffu);
			ida_free(&ida, id); printf("%ld free %u\n", i, id);
		} else if (op < 94) {
			unsigned min = pick_min(), max = pick_max(min);
			r = ida_find_first_range(&ida, min, max);
			printf("%ld find %u %u -> %d\n", i, min, max, r);
		} else if (op < 97) {
			/* a burst of allocations from one place: fills value entries, words and whole bitmaps (clears the free mark, moves on to the next chunk) */
			unsigned min = rnd(2) ? rnd(3) * 1024 + rnd(70) : pick_min(), k = 40 + rnd(1300); int last = 0;
			for (unsigned j = 0; j < k; j++) { last = ida_alloc_range(&ida, min, UINT_MAX, GFP_KERNEL); if (last >= 0 && npool < 4096) pool[npool++] = last; if (last < 0) break; }
			printf("%ld burst %u %u -> %d\n", i, min, k, last);
		} else { ida_destroy(&ida); npool = 0; printf("%ld destroy\n", i); }
		if (prove && i == 20) printf("  POISON\n");
		fail_alloc = fail_node = 0;
		dump();
	}
	ida_destroy(&ida); printf("final live=%ld\n", live_bitmaps);
	return 0;
}
