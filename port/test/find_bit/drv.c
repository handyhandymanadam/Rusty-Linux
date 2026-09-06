/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/find_bit/drv.c -- differential for lib/find_bit.c.
 *
 * Random bitmaps of varying size (1..320 bits, spanning 1..5 words),
 * random start offsets, exercised against all 17 live exported symbols
 * (the three `#ifdef __BIG_ENDIAN` functions are dead on this project's
 * x86-64 target and are not ported -- see find_bit_rs.rs's module doc).
 *
 * __bitmap_weight() is a real reimplementation (BITMAP_WEIGHT copied
 * verbatim from lib/bitmap.c), since find_random_bit() genuinely calls
 * through it -- not a mock. __get_random_u32_below() is deterministic
 * (a settable global) so the same draw can be compared between arms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned long ul;

/* ---- C arm (renamed) ---- */
ul cref__find_first_bit(const ul *addr, ul size);
ul cref__find_first_and_bit(const ul *addr1, const ul *addr2, ul size);
ul cref__find_first_andnot_bit(const ul *addr1, const ul *addr2, ul size);
ul cref__find_first_and_and_bit(const ul *addr1, const ul *addr2, const ul *addr3, ul size);
ul cref__find_first_zero_bit(const ul *addr, ul size);
ul cref__find_next_bit(const ul *addr, ul nbits, ul start);
ul cref__find_nth_bit(const ul *addr, ul size, ul n);
ul cref__find_nth_and_bit(const ul *addr1, const ul *addr2, ul size, ul n);
ul cref__find_nth_andnot_bit(const ul *addr1, const ul *addr2, ul size, ul n);
ul cref__find_nth_and_andnot_bit(const ul *addr1, const ul *addr2, const ul *addr3, ul size, ul n);
ul cref__find_next_and_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul cref__find_next_andnot_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul cref__find_next_or_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul cref__find_next_zero_bit(const ul *addr, ul nbits, ul start);
ul cref__find_last_bit(const ul *addr, ul size);
ul cref_find_next_clump8(ul *clump, const ul *addr, ul size, ul offset);
ul cref_find_random_bit(const ul *addr, ul size);

/* ---- Rust arm ---- */
ul _find_first_bit(const ul *addr, ul size);
ul _find_first_and_bit(const ul *addr1, const ul *addr2, ul size);
ul _find_first_andnot_bit(const ul *addr1, const ul *addr2, ul size);
ul _find_first_and_and_bit(const ul *addr1, const ul *addr2, const ul *addr3, ul size);
ul _find_first_zero_bit(const ul *addr, ul size);
ul _find_next_bit(const ul *addr, ul nbits, ul start);
ul __find_nth_bit(const ul *addr, ul size, ul n);
ul __find_nth_and_bit(const ul *addr1, const ul *addr2, ul size, ul n);
ul __find_nth_andnot_bit(const ul *addr1, const ul *addr2, ul size, ul n);
ul __find_nth_and_andnot_bit(const ul *addr1, const ul *addr2, const ul *addr3, ul size, ul n);
ul _find_next_and_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul _find_next_andnot_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul _find_next_or_bit(const ul *addr1, const ul *addr2, ul nbits, ul start);
ul _find_next_zero_bit(const ul *addr, ul nbits, ul start);
ul _find_last_bit(const ul *addr, ul size);
ul find_next_clump8(ul *clump, const ul *addr, ul size, ul offset);
ul find_random_bit(const ul *addr, ul size);

/* Real dependency, not a mock -- BITMAP_WEIGHT copied verbatim from
 * lib/bitmap.c. Linked as the ONE definition both arms call through
 * (the C via bitmap_weight()'s shim inline, the Rust via its own
 * `unsafe extern "C" { fn __bitmap_weight(...) }`). */
unsigned int __bitmap_weight(const ul *bitmap, unsigned int bits)
{
	unsigned int idx, w = 0;

	for (idx = 0; idx < bits / 64; idx++)
		w += __builtin_popcountl(bitmap[idx]);
	if (bits % 64)
		w += __builtin_popcountl(bitmap[idx] & (~0UL >> (-bits & 63)));
	return w;
}

static unsigned int g_rand_draw;
unsigned int __get_random_u32_below(unsigned int ceil)
{
	return ceil ? g_rand_draw % ceil : 0;
}

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

#define CHECK1(name, c_call, r_call) do {			\
	ul c = (c_call), r = (r_call);				\
	cases++;						\
	if (poison && (data[0] & 1))				\
		r = c + 1;					\
	if (c != r)						\
		bad(name);					\
} while (0)

int main(void)
{
	unsigned long seed = 12345;
	unsigned long data[6];
	unsigned long other[6];
	unsigned long other2[6];
	int iter, i;

	if (getenv("FB_PROVE_CAN_FAIL"))
		poison = 1;

	for (iter = 0; iter < 200000; iter++) {
		/* xorshift64 -- fast, deterministic, reproducible. */
		unsigned int nwords = 1 + (seed % 5);
		unsigned int size, start, n;
		ul clump_c = 0xAAAAAAAAUL, clump_r = 0xAAAAAAAAUL;
		ul rc, rr;

		for (i = 0; i < 6; i++) {
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			data[i] = seed;
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			other[i] = seed;
			seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
			other2[i] = seed;
		}
		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		size = 1 + (unsigned int)(seed % (nwords * 64));
		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		start = (unsigned int)(seed % (size + 1));
		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		n = (unsigned int)(seed % (size + 2));
		seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
		g_rand_draw = (unsigned int)seed;

		CHECK1("_find_first_bit", cref__find_first_bit(data, size), _find_first_bit(data, size));
		CHECK1("_find_first_and_bit", cref__find_first_and_bit(data, other, size),
		       _find_first_and_bit(data, other, size));
		CHECK1("_find_first_andnot_bit", cref__find_first_andnot_bit(data, other, size),
		       _find_first_andnot_bit(data, other, size));
		CHECK1("_find_first_and_and_bit", cref__find_first_and_and_bit(data, other, other2, size),
		       _find_first_and_and_bit(data, other, other2, size));
		CHECK1("_find_first_zero_bit", cref__find_first_zero_bit(data, size),
		       _find_first_zero_bit(data, size));
		CHECK1("_find_next_bit", cref__find_next_bit(data, size, start),
		       _find_next_bit(data, size, start));
		CHECK1("__find_nth_bit", cref__find_nth_bit(data, size, n), __find_nth_bit(data, size, n));
		CHECK1("__find_nth_and_bit", cref__find_nth_and_bit(data, other, size, n),
		       __find_nth_and_bit(data, other, size, n));
		CHECK1("__find_nth_andnot_bit", cref__find_nth_andnot_bit(data, other, size, n),
		       __find_nth_andnot_bit(data, other, size, n));
		CHECK1("__find_nth_and_andnot_bit",
		       cref__find_nth_and_andnot_bit(data, other, other2, size, n),
		       __find_nth_and_andnot_bit(data, other, other2, size, n));
		CHECK1("_find_next_and_bit", cref__find_next_and_bit(data, other, size, start),
		       _find_next_and_bit(data, other, size, start));
		CHECK1("_find_next_andnot_bit", cref__find_next_andnot_bit(data, other, size, start),
		       _find_next_andnot_bit(data, other, size, start));
		CHECK1("_find_next_or_bit", cref__find_next_or_bit(data, other, size, start),
		       _find_next_or_bit(data, other, size, start));
		CHECK1("_find_next_zero_bit", cref__find_next_zero_bit(data, size, start),
		       _find_next_zero_bit(data, size, start));
		CHECK1("_find_last_bit", cref__find_last_bit(data, size), _find_last_bit(data, size));

		rc = cref_find_next_clump8(&clump_c, data, size, start & ~7u);
		rr = find_next_clump8(&clump_r, data, size, start & ~7u);
		cases++;
		if (poison && (data[0] & 1))
			rr = rc + 1;
		if (rc != rr)
			bad("find_next_clump8-retval");
		if (rc != size && clump_c != clump_r)
			bad("find_next_clump8-clump");

		rc = cref_find_random_bit(data, size);
		rr = find_random_bit(data, size);
		cases++;
		if (poison && (data[0] & 1))
			rr = rc + 1;
		if (rc != rr)
			bad("find_random_bit");
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
