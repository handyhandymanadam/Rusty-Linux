/* SELinux ebitmap differential: the pristine bitmap functions (ARM_REF) against ebitmap_rs.rs with the glue's wrappers (ARM_RS). A pool of four bitmaps takes random operations: set / clear
 * bits (dense, around node edges, sparse, at the top of the u32 range), get, equal, copy, and, contains (with and without a last-bit limit), hash, write (into buffers of every size)
 * and read (of what was written, mutated or truncated, and of crafted streams that reach every error message), with allocation failures injected. The result of each operation and
 * the whole contents of the bitmaps it touched are printed, so any difference in the lists, the high bits, the bytes or the messages shows.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include "ebitmap.h"
struct kmem_cache *ebitmap_node_cachep; long fail_in, live_nodes, allocs; unsigned long gfp_log;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
#define K 4
static struct ebitmap pool[K]; static int poked[K]; /* set when a state no operation makes was poked in: writing such a bitmap is outside the function's contract (C shifts by a wrapped count) */
static unsigned char lastbuf[4096]; static size_t lastlen;
static void dump(int i)
{
	const struct ebitmap_node *n; int j;
	printf("  [%d] high=%u", i, pool[i].highbit);
	for (n = pool[i].node; n; n = n->next) { printf(" {%u", n->startbit); for (j = 0; j < 6; j++) if (n->maps[j]) printf(" %d:%llx", j, (unsigned long long)n->maps[j]); printf("}"); }
	printf("\n");
}
static u32 pickbit(void)
{
	u32 r;
	switch (rnd(10)) {
	case 0: case 1: case 2: case 3: case 4: case 5: return rnd(1800);
	case 6: case 7: { static const int d[] = { -1, 0, 1, 63, 64, 65, 382, 383, 384, 385 }; r = rnd(8) * 384 + d[rnd(10)]; return r; }
	case 8: return (u32)rnd64();
	default: return 0xffffff00u + rnd(256);
	}
}
/* A random bit that is set in pool[i] (a random bit if it is empty). */
static u32 pickset(int i)
{
	const struct ebitmap_node *nn = pool[i].node; int cnt = 0, skip, q, b0;
	if (!nn) return pickbit();
	for (; nn; nn = nn->next) cnt++;
	skip = rnd(cnt); nn = pool[i].node;
	while (skip-- && nn->next) nn = nn->next;
	b0 = rnd(384);
	for (q = 0; q < 384; q++) { int b = (b0 + q) % 384; if (nn->maps[b / 64] >> (b % 64) & 1) return nn->startbit + b; }
	return nn->startbit + b0;
}
/* destroy, then leave garbage where the bitmap was: functions that start with ebitmap_init() must not look at it */
static void scrub(int i) { ebitmap_destroy(&pool[i]); pool[i].highbit = 0xdeadbeef; pool[i].node = (struct ebitmap_node *)0x10; }
static void hexdump(const unsigned char *p, size_t n) { size_t i; for (i = 0; i < n; i++) printf("%02x", p[i]); }
static void put32(unsigned char *p, u32 v) { memcpy(p, &v, 4); }
static void put64(unsigned char *p, u64 v) { memcpy(p, &v, 8); }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 120000, it; int i, j, k, rc, pc = 0;
	struct kmem_cache cache; ebitmap_node_cachep = &cache;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < K; i++) ebitmap_init(&pool[i]);
	for (it = 0; it < n; it++) {
		int op = rnd(100);
		i = rnd(K); j = rnd(K); k = rnd(K);
		fail_in = rnd(8) == 0 ? 1 + rnd(4) : 0;
		if (op < 30) { int v = rnd(10) < 7; u32 b = (!v && rnd(10) < 6) ? pickset(i) : pickbit(); rc = ebitmap_set_bit(&pool[i], b, v); printf("%ld set %d %u %d -> %d\n", it, i, b, v, rc); dump(i); }
		else if (op < 38) { u32 b = rnd(2) ? pickset(i) : pickbit(); rc = ebitmap_get_bit(&pool[i], b); if (prove && pc++ == 3) rc ^= 1; printf("%ld get %d %u -> %d\n", it, i, b, rc); }
		else if (op < 42) { printf("%ld equal %d %d -> %d\n", it, i, j, (int)ebitmap_equal(&pool[i], &pool[j])); }
		else if (op < 47) { if (i != j) { scrub(i); poked[i] = poked[j]; rc = ebitmap_cpy(&pool[i], &pool[j]); printf("%ld cpy %d %d -> %d\n", it, i, j, rc); dump(i); } }
		else if (op < 52) { if (i != j && i != k) { scrub(i); poked[i] = 0; rc = ebitmap_and(&pool[i], &pool[j], &pool[k]); printf("%ld and %d %d %d -> %d\n", it, i, j, k, rc); dump(i); } }
		else if (op < 60) {
			u32 last = rnd(3) == 0 ? 0 : (rnd(2) && pool[j].highbit ? pool[j].highbit - 1 - rnd(100) : pickbit());
			printf("%ld contains %d %d %u -> %d\n", it, i, j, last, ebitmap_contains(&pool[i], &pool[j], last));
		}
		else if (op < 62) { ebitmap_destroy(&pool[i]); poked[i] = 0; printf("%ld destroy %d\n", it, i); dump(i); }
		else if (op < 65) { u32 seed = rnd(3) ? 0 : (u32)rnd64(); printf("%ld hash %d %u -> %08x\n", it, i, seed, ebitmap_hash(&pool[i], seed)); }
		else if (op < 75) {
			static unsigned char buf[4096]; struct policy_file fp; size_t L = rnd(3) == 0 ? rnd(40) : sizeof buf;
			memset(buf, 0xaa, sizeof buf); fp.data = (char *)buf; fp.len = L;
			if (poked[i]) { printf("%ld write %d skipped\n", it, i); continue; }
			rc = ebitmap_write(&pool[i], &fp);
			printf("%ld write %d len=%zu -> %d used=%zu ", it, i, L, rc, L - fp.len); hexdump(buf, L - fp.len); printf("\n");
			if (rc == 0) { lastlen = L - fp.len; memcpy(lastbuf, buf, lastlen); }
		}
		else if (op < 84) {
			unsigned char buf[4096]; struct policy_file fp; size_t L = lastlen;
			memcpy(buf, lastbuf, L);
			switch (rnd(5)) {
			case 0: break;
			case 1: L = rnd(L + 1); break;
			case 2: if (L) buf[rnd(L)] ^= 1 << rnd(8); break;
			case 3: if (L >= 12) put32(buf + 4 * rnd(3), rnd(3) ? rnd(4000) : (u32)rnd64()); break;
			default: if (L >= 16) put32(buf + 12, (u32)rnd(1000) & ~63u); break;
			}
			scrub(i); poked[i] = 0; fp.data = (char *)buf; fp.len = L;
			rc = ebitmap_read(&pool[i], &fp);
			printf("%ld read %d len=%zu -> %d left=%zu\n", it, i, L, rc, fp.len); dump(i);
		}
		else if (op < 90) {
			unsigned char buf[4096]; struct policy_file fp; size_t L = 12; int cnt = rnd(4), e;
			static const u32 highs[] = { 0, 1, 63, 64, 100, 383, 384, 385, 768, 1000, 1152, 2000 };
			put32(buf, rnd(8) ? 64 : 32); put32(buf + 4, rnd(5) ? highs[rnd(12)] : rnd(6000)); put32(buf + 8, cnt);
			for (e = 0; e < cnt; e++) {
				u32 sb = rnd(5) ? (rnd(6) * 64 + (rnd(8) ? 0 : rnd(64))) : rnd(1000) * 64; u64 m = rnd(8) ? ((u64)1 << rnd(64)) | (rnd(2) ? rnd64() : 0) : (rnd(2) ? 0 : rnd64());
				put32(buf + L, sb); L += 4; put64(buf + L, m); L += 8;
			}
			if (rnd(6) == 0) L = rnd(L + 1);
			scrub(i); poked[i] = 0; fp.data = (char *)buf; fp.len = L;
			rc = ebitmap_read(&pool[i], &fp);
			printf("%ld readc %d len=%zu -> %d left=%zu\n", it, i, L, rc, fp.len); dump(i);
		}
		else if (op < 92) {
			/* a near copy: j becomes a copy of i, then loses a bit, gains a bit, or changes its high bit; compare both ways */
			if (i != j) {
				int how = rnd(5);
				scrub(j); fail_in = 0; rc = ebitmap_cpy(&pool[j], &pool[i]);
				if (how >= 3) poked[j] = 1; else poked[j] = poked[i];
				if (how == 1) ebitmap_set_bit(&pool[j], pickset(j), 0);
				else if (how == 2) ebitmap_set_bit(&pool[j], pool[j].node ? pool[j].node->startbit + rnd(384) : pickbit(), 1);
				else if (how == 3) pool[j].highbit += rnd(2) ? 384 : -384;
				else if (how == 4 && pool[j].node) { struct ebitmap_node *nn = pool[j].node; while (nn->next && rnd(2)) nn = nn->next; nn->maps[rnd(6)] ^= (u64)1 << rnd(64); }
				printf("%ld near %d %d how=%d -> eq %d %d contains %d %d %d %d\n", it, i, j, how, (int)ebitmap_equal(&pool[i], &pool[j]), (int)ebitmap_equal(&pool[j], &pool[i]),
				       ebitmap_contains(&pool[i], &pool[j], 0), ebitmap_contains(&pool[j], &pool[i], 0), ebitmap_contains(&pool[i], &pool[j], pickset(j)), ebitmap_contains(&pool[j], &pool[i], pickset(i)));
				dump(j);
			}
		}
		else if (op < 94) {
			/* twins: the same node contents at different positions, ending on the same node, so the high bits agree */
			int m = 1 + rnd(4), p1[4], p2[4], t, q; u32 pat[4][2];
			if (i != j) {
				ebitmap_destroy(&pool[i]); ebitmap_destroy(&pool[j]); poked[i] = poked[j] = 0; fail_in = 0;
				for (t = 0; t < m; t++) { pat[t][0] = rnd(384); pat[t][1] = rnd(384); }
				for (t = 0; t < m; t++) { p1[t] = t * 2 + rnd(2); p2[t] = t * 2 + rnd(2); }
				p1[m - 1] = p2[m - 1] = 2 * m + rnd(3);
				if (rnd(5) == 0) { for (t = 0; t < m; t++) p2[t] = p1[t]; }
				if (rnd(6) == 0) { pat[m - 1][1] = pat[m - 1][0]; }
				for (t = 0; t < m; t++) { for (q = 0; q < 2; q++) { ebitmap_set_bit(&pool[i], p1[t] * 384 + pat[t][q], 1); ebitmap_set_bit(&pool[j], p2[t] * 384 + (q == 1 && rnd(8) == 0 ? (pat[t][q] + 1) % 384 : pat[t][q]), 1); } }
				printf("%ld twin %d %d m=%d -> eq %d %d contains %d %d\n", it, i, j, m, (int)ebitmap_equal(&pool[i], &pool[j]), (int)ebitmap_equal(&pool[j], &pool[i]), ebitmap_contains(&pool[i], &pool[j], 0), ebitmap_contains(&pool[j], &pool[i], 0));
				dump(i); dump(j);
			}
		}
		else if (op < 97) {
			/* a small bitmap emptied again: the node and the high bit must go with the last bit */
			int cnt = 1 + rnd(3), t; u32 b[3]; u32 base = rnd(4) == 0 ? 0xffffff00u : rnd(6) * 384;
			ebitmap_destroy(&pool[i]); poked[i] = 0; fail_in = 0;
			for (t = 0; t < cnt; t++) { b[t] = base + rnd(rnd(2) ? 384 : 64); ebitmap_set_bit(&pool[i], b[t], 1); }
			dump(i);
			for (t = 0; t < cnt; t++) { int u = rnd(cnt); ebitmap_set_bit(&pool[i], b[u], 0); if (rnd(2)) ebitmap_set_bit(&pool[i], b[u], 0); dump(i); }
			for (t = 0; t < cnt; t++) { ebitmap_set_bit(&pool[i], b[t], 0); }
			printf("%ld mini %d cnt=%d\n", it, i, cnt); dump(i);
		}
		else {
			/* poke a state no operation makes: a stale high bit, an emptied node */
			if (rnd(8) == 0) pool[i].highbit = 0xffffffffu;
			else if (rnd(2)) pool[i].highbit += rnd(3) - 1;
			else if (pool[i].node) { struct ebitmap_node *nn = pool[i].node; while (nn->next && rnd(2)) nn = nn->next; memset(nn->maps, 0, sizeof nn->maps); if (rnd(2)) nn->maps[rnd(6)] = (u64)1 << rnd(64); }
			poked[i] = 1; printf("%ld poke %d\n", it, i); dump(i);
		}
		printf("  gfp=%lx\n", gfp_log);
		fail_in = 0;
	}
	for (i = 0; i < K; i++) ebitmap_destroy(&pool[i]);
	printf("live nodes at the end: %ld\n", live_nodes);
	return 0;
}
