/* SPDX-License-Identifier: GPL-2.0 */
/* Exhaustive differential for arch/x86/lib/misc.c: num_digits() over ALL 2^32
 * int values, C (port/pristine, renamed c_num_digits) against Rust.
 *
 * Three arms per value:
 *   1. C (pristine)  == Rust                          every one of 2^32 values
 *   2. both == an INDEPENDENT oracle: sign + the number of decimal digits,
 *      found by comparing against a table of powers of ten (no loop shared
 *      with either implementation) - everywhere except INT_MIN, whose
 *      negation wraps (kernel is built -fwrapv) so the C answers 2
 *   3. both == strlen(snprintf("%d")) on a strided sample plus all
 *      boundaries around every power of ten and INT_MIN/INT_MAX
 *
 * usage: main SHARD NSHARDS   (values v with (v mod NSHARDS) == SHARD)
 *        NUM_PROVE_CAN_FAIL=1 poisons the Rust result for one value.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

int c_num_digits(int val);
int num_digits(int val);	/* the Rust */

static const long long pow10t[] = { 10LL, 100LL, 1000LL, 10000LL, 100000LL,
	1000000LL, 10000000LL, 100000000LL, 1000000000LL, 10000000000LL };

static int oracle(int v)
{
	long long a = v;
	int d = 1, i;

	if (a < 0) {
		if (v == INT_MIN)
			return 2;	/* -fwrapv: val stays INT_MIN, loop skipped */
		d++;
		a = -a;
	}
	for (i = 0; i < 10; i++)
		if (a >= pow10t[i])
			d++;
	return d;
}

static int snp(int v)
{
	char b[32];

	return (int)strlen((snprintf(b, sizeof b, "%d", v), b));
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
	unsigned nsh = argc > 2 ? (unsigned)atoi(argv[2]) : 1;
	int poison = getenv("NUM_PROVE_CAN_FAIL") != NULL;
	int failfast = getenv("NUM_FAILFAST") != NULL;
	unsigned long long n = 0, fails = 0, nsn = 0;
	uint64_t i;

	for (i = shard; i <= 0xffffffffULL; i += nsh) {
		int v = (int)(uint32_t)i;
		int c = c_num_digits(v), r = num_digits(v);

		if (poison && v == 12345)
			r++;
		n++;
		if (c != r || c != oracle(v)) {
			if (fails++ < 10)
				fprintf(stderr, "MISMATCH v=%d c=%d rust=%d oracle=%d\n",
					v, c, r, oracle(v));
		}
		if (fails && failfast)
			break;
		/* strided snprintf arm + boundaries (exact in every shard) */
		if ((i % 4093) == 0 || (i & 0xfff) < 3 || ((uint32_t)i + 3) < 6) {
			if (v != INT_MIN) {
				nsn++;
				if (snprintf(NULL, 0, "%d", v) != c) {
					if (fails++ < 10)
						fprintf(stderr, "SNPRINTF MISMATCH v=%d c=%d\n", v, c);
				}
			}
		}
	}
	/* boundaries around each power of ten, both signs, and the extremes */
	if (shard == 0) {
		int k;

		for (k = 0; k < 10; k++) {
			long long p = pow10t[k];
			long long d;

			for (d = -2; d <= 2; d++) {
				long long cand[2] = { p + d, -(p + d) };
				int j;

				for (j = 0; j < 2; j++) {
					long long x = cand[j];

					if (x < INT_MIN || x > INT_MAX || x == INT_MIN)
						continue;
					nsn++;
					if (snp((int)x) != c_num_digits((int)x) ||
					    snp((int)x) != num_digits((int)x)) {
						fails++;
						fprintf(stderr, "BOUNDARY MISMATCH %lld\n", x);
					}
				}
			}
		}
		if (c_num_digits(INT_MAX) != 10 || num_digits(INT_MAX) != 10 ||
		    c_num_digits(INT_MIN) != 2 || num_digits(INT_MIN) != 2 ||
		    c_num_digits(0) != 1 || num_digits(0) != 1) {
			fails++;
			fprintf(stderr, "EXTREME MISMATCH\n");
		}
	}
	printf("shard %u/%u: %llu values compared (C==Rust==oracle), %llu snprintf checks, %llu failure(s)\n",
	       shard, nsh, n, nsn, fails);
	return fails ? 1 : 0;
}
