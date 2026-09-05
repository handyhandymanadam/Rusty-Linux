/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential test for the lib/math/ port. Userspace, seconds, no kernel.
 * The C bodies in ref_math.c are the oracle; the Rust is what changes if
 * they disagree.
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

unsigned long ref_int_sqrt(unsigned long x);
uint64_t ref_int_pow(uint64_t base, unsigned int exp);
unsigned long rust_int_sqrt(unsigned long x);
uint64_t rust_int_pow(uint64_t base, unsigned int exp);

static unsigned long checked, mismatches;

void ref_rational_best_approximation(unsigned long, unsigned long, unsigned long,
				     unsigned long, unsigned long *, unsigned long *);
void rust_rational_best_approximation(unsigned long, unsigned long, unsigned long,
				      unsigned long, unsigned long *, unsigned long *);
uint32_t ref_iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder);
uint32_t rust_iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder);

static void cmp_rational(unsigned long gn, unsigned long gd,
			 unsigned long mn, unsigned long md)
{
	unsigned long an, ad, bn, bd;

	ref_rational_best_approximation(gn, gd, mn, md, &an, &ad);
	rust_rational_best_approximation(gn, gd, mn, md, &bn, &bd);

	checked++;
	if (an != bn || ad != bd) {
		if (mismatches < 20)
			fprintf(stderr, "rational(%lu/%lu, %lu, %lu): C=%lu/%lu rust=%lu/%lu\n",
				gn, gd, mn, md, an, ad, bn, bd);
		mismatches++;
	}
	/* Independent of the C: the answer must be within the stated limits.
	 * The C could be wrong about the value and this would still hold, but
	 * a port that walked off the limits would not.
	 *
	 * TWO DEGENERATE INPUTS ARE EXEMPT, and this was found by the check
	 * firing rather than assumed. Both arms agree on them; it is the
	 * property that does not hold, because the C does not hold it:
	 *
	 *   given_denominator == 0  the loop never runs at all, so 1/0 comes
	 *                           straight back out regardless of the limits
	 *   max_denominator == 0    the only reachable answer is 0/1, and 1 > 0
	 *
	 * GOALS.md §7: the C is a reference, not a specification, and it is
	 * sometimes wrong. Making the Rust "fix" either case would change
	 * what callers observe, which §5 forbids. Recorded, not corrected. */
	if (gd == 0 || md == 0)
		return;
	checked++;
	if (bn > mn || bd > md) {
		if (mismatches < 20)
			fprintf(stderr, "rational(%lu/%lu, %lu, %lu) = %lu/%lu exceeds limits\n",
				gn, gd, mn, md, bn, bd);
		mismatches++;
	}
}

static void cmp_iter_div(uint64_t dividend, uint32_t divisor)
{
	uint64_t ra = 0, rb = 0;
	uint32_t qa, qb;

	if (divisor == 0)
		return;

	qa = ref_iter_div_u64_rem(dividend, divisor, &ra);
	qb = rust_iter_div_u64_rem(dividend, divisor, &rb);

	checked += 2;
	if (qa != qb || ra != rb) {
		if (mismatches < 20)
			fprintf(stderr, "iter_div_u64_rem(%llu,%u): C=%u r%llu rust=%u r%llu\n",
				(unsigned long long)dividend, divisor,
				qa, (unsigned long long)ra, qb, (unsigned long long)rb);
		mismatches++;
	}
	/* Independent: q*divisor + r must reconstruct the dividend. */
	if ((uint64_t)qb * divisor + rb != dividend || rb >= divisor) {
		if (mismatches < 20)
			fprintf(stderr, "iter_div_u64_rem(%llu,%u) = %u r%llu does not reconstruct\n",
				(unsigned long long)dividend, divisor, qb,
				(unsigned long long)rb);
		mismatches++;
	}
}

unsigned long ref_binary_gcd(unsigned long a, unsigned long b);
unsigned long ref_gcd_even_odd(unsigned long a, unsigned long b);
unsigned long ref_gcd_euclid(unsigned long a, unsigned long b);
unsigned long ref_lcm(unsigned long a, unsigned long b);
unsigned long ref_lcm_not_zero(unsigned long a, unsigned long b);
unsigned long rust_binary_gcd(unsigned long a, unsigned long b);
unsigned long rust_gcd_even_odd(unsigned long a, unsigned long b);
unsigned long rust_lcm(unsigned long a, unsigned long b);
unsigned long rust_lcm_not_zero(unsigned long a, unsigned long b);

static void cmp_gcd(unsigned long a, unsigned long b)
{
	unsigned long r1, r2, r3, r4, e;

	if (!a || !b)		/* gcd() handles these before dispatching */
		return;

	r1 = ref_binary_gcd(a, b);
	r2 = rust_binary_gcd(a, b);
	r3 = ref_gcd_even_odd(a, b);
	r4 = rust_gcd_even_odd(a, b);
	e  = ref_gcd_euclid(a, b);

	checked += 3;
	if (r1 != r2) {
		if (mismatches < 20)
			fprintf(stderr, "binary_gcd(%lu,%lu): C=%lu rust=%lu\n", a, b, r1, r2);
		mismatches++;
	}
	if (r3 != r4) {
		if (mismatches < 20)
			fprintf(stderr, "gcd_even_odd(%lu,%lu): C=%lu rust=%lu\n", a, b, r3, r4);
		mismatches++;
	}
	/* Independent of both C bodies: plain Euclid must agree with the
	 * Rust. If the C were wrong, comparing against it would not say so. */
	if (r2 != e || r4 != e) {
		if (mismatches < 20)
			fprintf(stderr, "gcd(%lu,%lu): euclid=%lu rust binary=%lu even_odd=%lu\n",
				a, b, e, r2, r4);
		mismatches++;
	}
}

static void cmp_lcm(unsigned long a, unsigned long b)
{
	unsigned long r1 = ref_lcm(a, b), r2 = rust_lcm(a, b);
	unsigned long r3 = ref_lcm_not_zero(a, b), r4 = rust_lcm_not_zero(a, b);

	checked += 2;
	if (r1 != r2) {
		if (mismatches < 20)
			fprintf(stderr, "lcm(%lu,%lu): C=%lu rust=%lu\n", a, b, r1, r2);
		mismatches++;
	}
	if (r3 != r4) {
		if (mismatches < 20)
			fprintf(stderr, "lcm_not_zero(%lu,%lu): C=%lu rust=%lu\n", a, b, r3, r4);
		mismatches++;
	}
}

unsigned int ref_intlog2(uint32_t value);
unsigned int ref_intlog10(uint32_t value);
unsigned int rust_intlog2(uint32_t value);
unsigned int rust_intlog10(uint32_t value);

struct ref_reciprocal_value { uint32_t m; unsigned char sh1, sh2; };
struct ref_reciprocal_value_adv { uint32_t m; unsigned char sh, exp; _Bool is_wide_m; };
struct ref_reciprocal_value ref_reciprocal_value(uint32_t d);
struct ref_reciprocal_value_adv ref_reciprocal_value_adv(uint32_t d, unsigned char prec);
struct ref_reciprocal_value rust_reciprocal_value(uint32_t d);
struct ref_reciprocal_value_adv rust_reciprocal_value_adv(uint32_t d, unsigned char prec);

static void cmp_log(uint32_t v)
{
	unsigned int a2 = ref_intlog2(v), b2 = rust_intlog2(v);
	unsigned int a10 = ref_intlog10(v), b10 = rust_intlog10(v);

	checked += 2;
	if (a2 != b2) {
		if (mismatches < 20)
			fprintf(stderr, "intlog2(%u): C=%u rust=%u\n", v, a2, b2);
		mismatches++;
	}
	if (a10 != b10) {
		if (mismatches < 20)
			fprintf(stderr, "intlog10(%u): C=%u rust=%u\n", v, a10, b10);
		mismatches++;
	}
}

static void cmp_recip(uint32_t d, unsigned char prec)
{
	struct ref_reciprocal_value a = ref_reciprocal_value(d);
	struct ref_reciprocal_value b = rust_reciprocal_value(d);
	struct ref_reciprocal_value_adv c = ref_reciprocal_value_adv(d, prec);
	struct ref_reciprocal_value_adv e = rust_reciprocal_value_adv(d, prec);

	checked += 2;
	if (a.m != b.m || a.sh1 != b.sh1 || a.sh2 != b.sh2) {
		if (mismatches < 20)
			fprintf(stderr, "reciprocal_value(%u): C={%u,%u,%u} rust={%u,%u,%u}\n",
				d, a.m, a.sh1, a.sh2, b.m, b.sh1, b.sh2);
		mismatches++;
	}
	if (c.m != e.m || c.sh != e.sh || c.exp != e.exp || c.is_wide_m != e.is_wide_m) {
		if (mismatches < 20)
			fprintf(stderr, "reciprocal_value_adv(%u,%u): C={%u,%u,%u,%d} rust={%u,%u,%u,%d}\n",
				d, prec, c.m, c.sh, c.exp, c.is_wide_m,
				e.m, e.sh, e.exp, e.is_wide_m);
		mismatches++;
	}
}


static void cmp_sqrt(unsigned long x)
{
	unsigned long a = ref_int_sqrt(x), b = rust_int_sqrt(x);

	checked++;
	if (a != b) {
		if (mismatches < 20)
			fprintf(stderr, "int_sqrt(%lu): C=%lu rust=%lu\n", x, a, b);
		mismatches++;
	}
}

static void cmp_pow(uint64_t base, unsigned int exp)
{
	uint64_t a = ref_int_pow(base, exp), b = rust_int_pow(base, exp);

	checked++;
	if (a != b) {
		if (mismatches < 20)
			fprintf(stderr, "int_pow(%" PRIu64 ", %u): C=%" PRIu64 " rust=%" PRIu64 "\n",
				base, exp, a, b);
		mismatches++;
	}
}

static uint64_t rnd_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 7;
	rnd_state ^= rnd_state << 17;
	return rnd_state;
}

int main(int argc, char **argv)
{
	unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 0) : 4000000;
	unsigned long before;

	printf("lib/math differential: C bodies (oracle) vs the Rust\n");

	/* int_sqrt: every value up to 2^24, so every result up to 4096 is
	 * hit at both ends of its interval. */
	before = checked;
	for (unsigned long x = 0; x <= (1UL << 24); x++)
		cmp_sqrt(x);
	printf("  int_sqrt dense    %lu cases  (0 .. 2^24)\n", checked - before);

	/* Every power-of-two boundary, and one either side. These are where a
	 * __fls/leading_zeros mistranslation would show. */
	before = checked;
	for (int k = 0; k < 64; k++) {
		unsigned long p = 1UL << k;

		cmp_sqrt(p - 1);
		cmp_sqrt(p);
		cmp_sqrt(p + 1);
		cmp_sqrt(p * 3);
		cmp_sqrt(~p);
	}
	cmp_sqrt(ULONG_MAX);
	cmp_sqrt(ULONG_MAX - 1);
	printf("  int_sqrt bounds   %lu cases  (2^k-1, 2^k, 2^k+1, 3*2^k, ~2^k, ULONG_MAX)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++)
		cmp_sqrt(rnd());
	printf("  int_sqrt fuzz     %lu cases  (full 64-bit range)\n", checked - before);

	/* An independent property, not a comparison: floor(sqrt(x)) must
	 * satisfy y*y <= x < (y+1)*(y+1). Checked below 2^32 so (y+1)^2
	 * cannot overflow. */
	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		unsigned long x = rnd() >> 32;
		unsigned long y = rust_int_sqrt(x);

		checked++;
		if (y * y > x || (y + 1) * (y + 1) <= x) {
			if (mismatches < 20)
				fprintf(stderr, "int_sqrt(%lu)=%lu violates y^2<=x<(y+1)^2\n", x, y);
			mismatches++;
		}
	}
	printf("  int_sqrt property %lu cases  (y^2 <= x < (y+1)^2, x < 2^32)\n",
	       checked - before);

	/* int_pow: small bases against every exponent, including the wrapping
	 * ones -- the C wraps and callers depend on that, so the Rust must. */
	before = checked;
	for (uint64_t base = 0; base < 512; base++)
		for (unsigned int exp = 0; exp < 96; exp++)
			cmp_pow(base, exp);
	printf("  int_pow dense     %lu cases  (base<512, exp<96, wrapping included)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++)
		cmp_pow(rnd(), (unsigned int)(rnd() & 0xff));
	printf("  int_pow fuzz      %lu cases\n", checked - before);

	/* intlog2/intlog10: every value that selects a distinct table entry
	 * plus its neighbours, then the whole low range densely, then fuzz.
	 * Zero is excluded -- the C wrapper handles it and WARNs. */
	before = checked;
	for (uint32_t v = 1; v <= (1u << 22); v++)
		cmp_log(v);
	printf("  intlog dense      %lu cases  (1 .. 2^22)\n", checked - before);

	before = checked;
	for (int k = 0; k < 32; k++) {
		uint32_t p = 1u << k;

		cmp_log(p);
		if (p > 1)
			cmp_log(p - 1);
		if (k < 31)
			cmp_log(p + 1);
		/* walk the top nine bits: this is what indexes the table, and
		 * entry 255 -> 0 is the wrap the C's & 0xffff exists for */
		for (int t = 0; t < 256 && k >= 9; t++)
			cmp_log(p | ((uint32_t)t << (k - 9)) | 1);
	}
	printf("  intlog table      %lu cases  (every table entry at every msb, and the 255->0 wrap)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		uint32_t v = (uint32_t)rnd();

		cmp_log(v ? v : 1);
	}
	printf("  intlog fuzz       %lu cases\n", checked - before);

	/* reciprocal_value/_adv: d == 0 is nonsense the C still computes, and
	 * d > 2^31 makes ceil(log2(d)) == 32, where the C's shift is UB and
	 * lowers to a masked x86 shl. Both are included on purpose. */
	before = checked;
	for (uint32_t d = 1; d <= (1u << 20); d++)
		cmp_recip(d, 32);
	printf("  recip dense       %lu cases  (d in 1 .. 2^20, prec 32)\n", checked - before);

	before = checked;
	for (int k = 0; k < 32; k++) {
		uint32_t p = 1u << k;

		for (unsigned char prec = 1; prec <= 32; prec++) {
			cmp_recip(p, prec);
			if (p > 1)
				cmp_recip(p - 1, prec);
			if (k < 31)
				cmp_recip(p + 1, prec);
		}
	}
	/* d == 0 is NOT tested: the C's do_div(m, 0) faults, so it is not an
	 * input the C defines either, and the Rust's own divide would panic.
	 * A test that crashes both arms identically proves nothing. */
	cmp_recip(0xffffffffu, 32);
	printf("  recip bounds      %lu cases  (2^k+-1 x prec 1..32, incl. ceil(log2(d))==32)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		uint32_t d = (uint32_t)rnd();

		cmp_recip(d ? d : 1, (unsigned char)(1 + (rnd() % 32)));
	}
	printf("  recip fuzz        %lu cases\n", checked - before);

	/* gcd/lcm: dense over small pairs, then powers of two and their
	 * neighbours (where the shifting normalisation earns its keep), then
	 * full-range fuzz. Both algorithms are exercised on every pair, and
	 * both are also checked against Euclid, which shares no code. */
	before = checked;
	for (unsigned long a = 1; a <= 400; a++)
		for (unsigned long b = 1; b <= 400; b++) {
			cmp_gcd(a, b);
			cmp_lcm(a, b);
		}
	printf("  gcd/lcm dense     %lu cases  (1..400 x 1..400)\n", checked - before);

	before = checked;
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 64; j++) {
			unsigned long p = 1UL << i, q = 1UL << j;

			cmp_gcd(p, q);
			cmp_gcd(p - 1 ? p - 1 : 1, q);
			cmp_gcd(p, q - 1 ? q - 1 : 1);
			cmp_gcd(p + 1, q + 1);
			cmp_lcm(p, q);
		}
	cmp_gcd(ULONG_MAX, ULONG_MAX);
	cmp_gcd(ULONG_MAX, 1);
	cmp_gcd(ULONG_MAX - 1, ULONG_MAX);
	printf("  gcd/lcm bounds    %lu cases  (2^i,2^j and neighbours, ULONG_MAX)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds; i++) {
		unsigned long a = rnd(), b = rnd();

		cmp_gcd(a ? a : 1, b ? b : 1);
		cmp_lcm(a, b);
	}
	printf("  gcd/lcm fuzz      %lu cases  (full 64-bit range)\n", checked - before);

	/* rational: dense over small fractions and limits, then the extremes
	 * where the C's multiplications wrap and the Rust must wrap with it. */
	before = checked;
	for (unsigned long gn = 0; gn <= 60; gn++)
		for (unsigned long gd = 0; gd <= 60; gd++)
			for (unsigned long m = 1; m <= 12; m++)
				cmp_rational(gn, gd, m, m);
	printf("  rational dense    %lu cases  (0..60 / 0..60, limits 1..12)\n",
	       checked - before);

	before = checked;
	for (int k = 0; k < 64; k++) {
		unsigned long p = 1UL << k;

		cmp_rational(p, p - 1 ? p - 1 : 1, ULONG_MAX, ULONG_MAX);
		cmp_rational(ULONG_MAX, p, ULONG_MAX, ULONG_MAX);
		cmp_rational(p, ULONG_MAX, p, p);
		cmp_rational(ULONG_MAX - 1, ULONG_MAX, ULONG_MAX, ULONG_MAX);
	}
	cmp_rational(31415, 10000, 255, 31);
	cmp_rational(0, 0, 0, 0);
	printf("  rational extremes %lu cases  (ULONG_MAX limits, where the C's arithmetic wraps)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds / 4; i++)
		cmp_rational(rnd(), rnd(), rnd(), rnd());
	printf("  rational fuzz     %lu cases  (full 64-bit range)\n", checked - before);

	/* iter_div_u64_rem: the loop is O(quotient), so the dividend has to
	 * stay near the divisor -- which is the case the function is for. */
	before = checked;
	for (uint64_t dd = 0; dd < 4096; dd++)
		for (uint32_t dv = 1; dv <= 32; dv++)
			cmp_iter_div(dd, dv);
	printf("  iter_div dense    %lu cases  (dividend<4096, divisor 1..32)\n",
	       checked - before);

	before = checked;
	for (unsigned long i = 0; i < rounds / 100; i++) {
		uint32_t dv = 1 + (uint32_t)(rnd() % 1000000);
		uint64_t dd = (uint64_t)dv * (rnd() % 64) + (rnd() % dv);

		cmp_iter_div(dd, dv);
	}
	printf("  iter_div fuzz     %lu cases  (quotient under 64, as intended)\n",
	       checked - before);

	printf("\n  checked      %lu\n  mismatches   %lu\n", checked, mismatches);
	if (mismatches) {
		printf("\nFAIL\n");
		return 1;
	}
	printf("\nPASS\n");
	return 0;
}
