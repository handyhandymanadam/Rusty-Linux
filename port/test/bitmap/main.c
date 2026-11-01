/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/bitmap.c: pristine C (c_*) vs bitmap_rs.rs, on random bitmaps of 0..320 bits (words after the
 * bitmap are canaries; every word of dst is compared, including bits past nbits). Both arms share the find_* helpers
 * defined here (simple loops, independent of both). usage: main SHARD ; BM_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
typedef unsigned long ul;
#define DECL2(n) bool c___bitmap_##n(const ul *, const ul *, unsigned), __bitmap_##n(const ul *, const ul *, unsigned);
bool c___bitmap_equal(const ul *, const ul *, unsigned), __bitmap_equal(const ul *, const ul *, unsigned);
bool c___bitmap_or_equal(const ul *, const ul *, const ul *, unsigned), __bitmap_or_equal(const ul *, const ul *, const ul *, unsigned);
void c___bitmap_complement(ul *, const ul *, unsigned), __bitmap_complement(ul *, const ul *, unsigned);
void c___bitmap_shift_right(ul *, const ul *, unsigned, unsigned), __bitmap_shift_right(ul *, const ul *, unsigned, unsigned);
void c___bitmap_shift_left(ul *, const ul *, unsigned, unsigned), __bitmap_shift_left(ul *, const ul *, unsigned, unsigned);
void c_bitmap_cut(ul *, const ul *, unsigned, unsigned, unsigned), bitmap_cut(ul *, const ul *, unsigned, unsigned, unsigned);
bool c___bitmap_and(ul *, const ul *, const ul *, unsigned), __bitmap_and(ul *, const ul *, const ul *, unsigned);
bool c___bitmap_andnot(ul *, const ul *, const ul *, unsigned), __bitmap_andnot(ul *, const ul *, const ul *, unsigned);
void c___bitmap_or(ul *, const ul *, const ul *, unsigned), __bitmap_or(ul *, const ul *, const ul *, unsigned);
void c___bitmap_xor(ul *, const ul *, const ul *, unsigned), __bitmap_xor(ul *, const ul *, const ul *, unsigned);
void c___bitmap_replace(ul *, const ul *, const ul *, const ul *, unsigned), __bitmap_replace(ul *, const ul *, const ul *, const ul *, unsigned);
bool c___bitmap_intersects(const ul *, const ul *, unsigned), __bitmap_intersects(const ul *, const ul *, unsigned);
bool c___bitmap_subset(const ul *, const ul *, unsigned), __bitmap_subset(const ul *, const ul *, unsigned);
unsigned c___bitmap_weight(const ul *, unsigned), __bitmap_weight(const ul *, unsigned);
unsigned c___bitmap_weight_and(const ul *, const ul *, unsigned), __bitmap_weight_and(const ul *, const ul *, unsigned);
unsigned c___bitmap_weight_andnot(const ul *, const ul *, unsigned), __bitmap_weight_andnot(const ul *, const ul *, unsigned);
void c___bitmap_set(ul *, unsigned, int), __bitmap_set(ul *, unsigned, int);
void c___bitmap_clear(ul *, unsigned, int), __bitmap_clear(ul *, unsigned, int);
ul c_bitmap_find_next_zero_area_off(ul *, ul, ul, unsigned, ul, ul), bitmap_find_next_zero_area_off(ul *, ul, ul, unsigned, ul, ul);
void c_bitmap_remap(ul *, const ul *, const ul *, const ul *, unsigned), bitmap_remap(ul *, const ul *, const ul *, const ul *, unsigned);
int c_bitmap_bitremap(int, const ul *, const ul *, int), bitmap_bitremap(int, const ul *, const ul *, int);
void c_bitmap_onto(ul *, const ul *, const ul *, unsigned), bitmap_onto(ul *, const ul *, const ul *, unsigned);
void c_bitmap_fold(ul *, const ul *, unsigned, unsigned), bitmap_fold(ul *, const ul *, unsigned, unsigned);
void c_bitmap_from_arr32(ul *, const uint32_t *, unsigned), bitmap_from_arr32(ul *, const uint32_t *, unsigned);
void c_bitmap_to_arr32(uint32_t *, const ul *, unsigned), bitmap_to_arr32(uint32_t *, const ul *, unsigned);

ul _find_next_bit(const ul *a, ul n, ul s) { for (; s < n; s++) if (a[s / 64] >> (s & 63) & 1) return s; return n; }
ul _find_next_zero_bit(const ul *a, ul n, ul s) { for (; s < n; s++) if (!(a[s / 64] >> (s & 63) & 1)) return s; return n; }
ul __find_nth_bit(const ul *a, ul n, ul k) { for (ul i = 0; i < n; i++) if (a[i / 64] >> (i & 63) & 1) { if (!k--) return i; } return n; }

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
#define W 8
static void fill(ul *b)
{
	int style = rnd() % 5;
	for (int i = 0; i < W; i++)
		b[i] = style == 0 ? 0 : style == 1 ? ~0UL : style == 2 ? (ul)(rnd() & rnd() & rnd()) : style == 3 ? (ul)(rnd() | rnd() | rnd()) : (ul)rnd();
}
static unsigned rn(unsigned max) { return max ? rnd() % (max + 1) : 0; }
#define NB (rnd() % 4 == 0 ? 64 * (rnd() % 6) : rn(300))
static void cmp(const char *what, const ul *a, const ul *b, int n, long ra, long rb, unsigned nbits)
{
	checks++;
	if (poison && !strcmp(what, "shift_left") && nbits == 77) rb++;
	if (ra != rb || memcmp(a, b, n * sizeof(ul))) FAIL("%s MISMATCH nbits=%u c=%ld rs=%ld\n", what, nbits, ra, rb);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("BM_N") ? atoll(getenv("BM_N")) : 5000000LL;
	poison = getenv("BM_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		ul s1[W], s2[W], s3[W], s4[W], da[W], db[W], dd[W + 2];
		unsigned nbits = NB;
		fill(s1); fill(s2); fill(s3); fill(s4);
		if (nbits == 77 && poison) { /* make sure the poisoned case is hit */ }
		long ra, rb;
		#define CANARY(d) memset(d, 0xA5, sizeof(d))
		/* predicates */
		cmp("equal", s1, s1, 0, c___bitmap_equal(s1, s2, nbits), __bitmap_equal(s1, s2, nbits), nbits);
		memcpy(s2, s1, sizeof s1); if (rnd() % 2) s2[rnd() % W] ^= 1UL << (rnd() % 64);
		cmp("equal2", s1, s1, 0, c___bitmap_equal(s1, s2, nbits), __bitmap_equal(s1, s2, nbits), nbits);
		cmp("or_equal", s1, s1, 0, c___bitmap_or_equal(s1, s2, s3, nbits), __bitmap_or_equal(s1, s2, s3, nbits), nbits);
		for (int i = 0; i < W; i++) s3[i] = s1[i] | s2[i];
		cmp("or_equal2", s1, s1, 0, c___bitmap_or_equal(s1, s2, s3, nbits), __bitmap_or_equal(s1, s2, s3, nbits), nbits);
		cmp("intersects", s1, s1, 0, c___bitmap_intersects(s1, s2, nbits), __bitmap_intersects(s1, s2, nbits), nbits);
		cmp("subset", s1, s1, 0, c___bitmap_subset(s1, s2, nbits), __bitmap_subset(s1, s2, nbits), nbits);
		cmp("weight", s1, s1, 0, c___bitmap_weight(s1, nbits), __bitmap_weight(s1, nbits), nbits);
		cmp("weight_and", s1, s1, 0, c___bitmap_weight_and(s1, s2, nbits), __bitmap_weight_and(s1, s2, nbits), nbits);
		cmp("weight_andnot", s1, s1, 0, c___bitmap_weight_andnot(s1, s2, nbits), __bitmap_weight_andnot(s1, s2, nbits), nbits);
		/* word ops */
		CANARY(da); CANARY(db); ra = c___bitmap_and(da, s1, s2, nbits); rb = __bitmap_and(db, s1, s2, nbits); cmp("and", da, db, W, ra, rb, nbits);
		CANARY(da); CANARY(db); c___bitmap_or(da, s1, s2, nbits); __bitmap_or(db, s1, s2, nbits); cmp("or", da, db, W, 0, 0, nbits);
		CANARY(da); CANARY(db); c___bitmap_xor(da, s1, s2, nbits); __bitmap_xor(db, s1, s2, nbits); cmp("xor", da, db, W, 0, 0, nbits);
		CANARY(da); CANARY(db); ra = c___bitmap_andnot(da, s1, s2, nbits); rb = __bitmap_andnot(db, s1, s2, nbits); cmp("andnot", da, db, W, ra, rb, nbits);
		CANARY(da); CANARY(db); c___bitmap_complement(da, s1, nbits); __bitmap_complement(db, s1, nbits); cmp("complement", da, db, W, 0, 0, nbits);
		CANARY(da); CANARY(db); c___bitmap_replace(da, s1, s2, s3, nbits); __bitmap_replace(db, s1, s2, s3, nbits); cmp("replace", da, db, W, 0, 0, nbits);
		/* shifts: shift in 0..=nbits (beyond is undefined in the C) */
		if (nbits) {
			unsigned sh = rn(nbits);
			CANARY(da); CANARY(db); c___bitmap_shift_right(da, s1, sh, nbits); __bitmap_shift_right(db, s1, sh, nbits); cmp("shift_right", da, db, W, 0, 0, nbits);
			CANARY(da); CANARY(db); c___bitmap_shift_left(da, s1, sh, nbits); __bitmap_shift_left(db, s1, sh, nbits); cmp("shift_left", da, db, W, 0, 0, nbits);
			unsigned first = rn(nbits - 1), cut = rn(nbits - first);
			memcpy(da, s1, sizeof da); memcpy(db, s1, sizeof db);
			c_bitmap_cut(da, s1, first, cut, nbits); bitmap_cut(db, s1, first, cut, nbits); cmp("cut", da, db, W, 0, 0, nbits);
			/* set / clear */
			unsigned st = rn(nbits); int len = rn(nbits - st);
			memcpy(da, s1, sizeof da); memcpy(db, s1, sizeof db);
			c___bitmap_set(da, st, len); __bitmap_set(db, st, len); cmp("set", da, db, W, 0, 0, nbits);
			memcpy(da, s1, sizeof da); memcpy(db, s1, sizeof db);
			c___bitmap_clear(da, st, len); __bitmap_clear(db, st, len); cmp("clear", da, db, W, 0, 0, nbits);
			/* area search */
			unsigned nr = rn(70); ul amask = (1UL << rn(6)) - 1, aoff = rn(40), start = rn(nbits);
			ra = c_bitmap_find_next_zero_area_off(s1, nbits, start, nr, amask, aoff); rb = bitmap_find_next_zero_area_off(s1, nbits, start, nr, amask, aoff);
			cmp("area_off", s1, s1, 0, ra, rb, nbits);
			/* remap family */
			CANARY(da); CANARY(db); c_bitmap_remap(da, s1, s2, s3, nbits); bitmap_remap(db, s1, s2, s3, nbits); cmp("remap", da, db, W, 0, 0, nbits);
			int bit = (int)rn(nbits + 3) - 1;
			ra = c_bitmap_bitremap(bit, s2, s3, nbits); rb = bitmap_bitremap(bit, s2, s3, nbits); cmp("bitremap", s1, s1, 0, ra, rb, nbits);
			CANARY(da); CANARY(db); c_bitmap_onto(da, s1, s2, nbits); bitmap_onto(db, s1, s2, nbits); cmp("onto", da, db, W, 0, 0, nbits);
			unsigned sz = 1 + rn(nbits);
			CANARY(da); CANARY(db); c_bitmap_fold(da, s1, sz, nbits); bitmap_fold(db, s1, sz, nbits); cmp("fold", da, db, W, 0, 0, nbits);
			/* arr32 */
			uint32_t b32a[2 * W + 2], b32b[2 * W + 2];
			memset(b32a, 0x5a, sizeof b32a); memset(b32b, 0x5a, sizeof b32b);
			c_bitmap_to_arr32(b32a, s1, nbits); bitmap_to_arr32(b32b, s1, nbits); cmp("to_arr32", (ul *)b32a, (ul *)b32b, W, 0, 0, nbits);
			uint32_t src32[2 * W + 2]; for (int i = 0; i < 2 * W + 2; i++) src32[i] = (uint32_t)rnd();
			CANARY(da); CANARY(db); c_bitmap_from_arr32(da, src32, nbits); bitmap_from_arr32(db, src32, nbits); cmp("from_arr32", da, db, W, 0, 0, nbits);
		}
		(void)s4; (void)dd;
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
