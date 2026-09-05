/* SPDX-License-Identifier: GPL-2.0
 *
 * lib/math/ bodies, verbatim from linux-6.18.49 apart from the kernel-isms
 * that do not exist in userspace. These are the ORACLES and are never edited
 * to agree with the Rust.
 */
#include <stdint.h>
#include <limits.h>

/* __fls(x): index of the highest set bit. x must be non-zero. */
static inline unsigned long ref_fls(unsigned long x)
{
	return (unsigned long)(8 * sizeof(unsigned long) - 1 - __builtin_clzl(x));
}

/* lib/math/int_sqrt.c */
unsigned long ref_int_sqrt(unsigned long x)
{
	unsigned long b, m, y = 0;

	if (x <= 1)
		return x;

	m = 1UL << (ref_fls(x) & ~1UL);
	while (m != 0) {
		b = y + m;
		y >>= 1;

		if (x >= b) {
			x -= b;
			y += m;
		}
		m >>= 2;
	}

	return y;
}

/* lib/math/int_pow.c */
uint64_t ref_int_pow(uint64_t base, unsigned int exp)
{
	uint64_t result = 1;

	while (exp) {
		if (exp & 1)
			result *= base;
		exp >>= 1;
		base *= base;
	}

	return result;
}

/* ---- lib/math/int_log.c ---------------------------------------------- */

#include "ref_logtable_generated.h"

#define REF_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* fls(x): one plus the index of the highest set bit, 0 for x == 0. */
static inline int ref_fls32(unsigned int x)
{
	return x ? 32 - __builtin_clz(x) : 0;
}

unsigned int ref_intlog2(uint32_t value)
{
	unsigned int msb, logentry, significand, interpolation;

	/* the C WARNs and returns 0; the wrapper handles that, not this */
	if (value == 0)
		return 0;

	msb = ref_fls32(value) - 1;
	significand = value << (31 - msb);
	logentry = (significand >> 23) % REF_ARRAY_SIZE(ref_logtable);
	interpolation = ((significand & 0x7fffff) *
			((ref_logtable[(logentry + 1) % REF_ARRAY_SIZE(ref_logtable)] -
			  ref_logtable[logentry]) & 0xffff)) >> 15;

	return ((msb << 24) + (ref_logtable[logentry] << 8) + interpolation);
}

unsigned int ref_intlog10(uint32_t value)
{
	uint64_t log;

	if (value == 0)
		return 0;

	log = ref_intlog2(value);
	return (log * 646456993) >> 31;
}

/* ---- lib/math/reciprocal_div.c --------------------------------------- */

struct ref_reciprocal_value {
	uint32_t m;
	unsigned char sh1, sh2;
};

struct ref_reciprocal_value_adv {
	uint32_t m;
	unsigned char sh, exp;
	_Bool is_wide_m;
};

struct ref_reciprocal_value ref_reciprocal_value(uint32_t d)
{
	struct ref_reciprocal_value R;
	uint64_t m;
	int l;

	l = ref_fls32(d - 1);
	m = ((1ULL << 32) * ((1ULL << l) - d));
	m /= d;
	++m;
	R.m = (uint32_t)m;
	R.sh1 = l < 1 ? l : 1;
	R.sh2 = (l - 1) > 0 ? (l - 1) : 0;

	return R;
}

struct ref_reciprocal_value_adv ref_reciprocal_value_adv(uint32_t d, unsigned char prec)
{
	struct ref_reciprocal_value_adv R;
	uint32_t l, post_shift;
	uint64_t mhigh, mlow;

	l = ref_fls32(d - 1);
	/* the C WARNs when l == 32 and carries on; so does this */
	post_shift = l;
	mlow = 1ULL << (32 + l);
	mlow /= d;
	mhigh = (1ULL << (32 + l)) + (1ULL << (32 + l - prec));
	mhigh /= d;

	for (; post_shift > 0; post_shift--) {
		uint64_t lo = mlow >> 1, hi = mhigh >> 1;

		if (lo >= hi)
			break;

		mlow = lo;
		mhigh = hi;
	}

	R.m = (uint32_t)mhigh;
	R.sh = post_shift;
	R.exp = l;
	R.is_wide_m = mhigh > 0xffffffffULL;

	return R;
}

/* ---- lib/math/gcd.c and lib/math/lcm.c ------------------------------- */

/* __ffs(x): index of the lowest set bit. x must be non-zero. */
static inline unsigned long ref_ffs(unsigned long x)
{
	return (unsigned long)__builtin_ctzl(x);
}

#define REF_SWAP(x, y) do { unsigned long _t = (x); (x) = (y); (y) = _t; } while (0)

unsigned long ref_binary_gcd(unsigned long a, unsigned long b)
{
	unsigned long r = a | b;

	b >>= ref_ffs(b);
	if (b == 1)
		return r & -r;

	for (;;) {
		a >>= ref_ffs(a);
		if (a == 1)
			return r & -r;
		if (a == b)
			return a << ref_ffs(r);

		if (a < b)
			REF_SWAP(a, b);
		a -= b;
	}
}

unsigned long ref_gcd_even_odd(unsigned long a, unsigned long b)
{
	unsigned long r = a | b;

	/* Isolate lsbit of r */
	r &= -r;

	while (!(b & r))
		b >>= 1;
	if (b == r)
		return r;

	for (;;) {
		while (!(a & r))
			a >>= 1;
		if (a == r)
			return r;
		if (a == b)
			return a;

		if (a < b)
			REF_SWAP(a, b);
		a -= b;
		a >>= 1;
		if (a & r)
			a += b;
		a >>= 1;
	}
}

/* The dispatcher, as lib/math/gcd.c has it. The static key is always true on
 * x86, so this is the shape the kernel actually runs. It is also the `gcd`
 * symbol lcm_rs.rs links against, exactly as in the kernel. */
unsigned long gcd(unsigned long a, unsigned long b)
{
	unsigned long r = a | b;

	if (!a || !b)
		return r;

	return ref_binary_gcd(a, b);
}

/* An independent reference that shares no code with either: plain Euclid. */
unsigned long ref_gcd_euclid(unsigned long a, unsigned long b)
{
	while (b) {
		unsigned long t = a % b;

		a = b;
		b = t;
	}
	return a;
}

unsigned long ref_lcm(unsigned long a, unsigned long b)
{
	if (a && b)
		return (a / gcd(a, b)) * b;
	return 0;
}

unsigned long ref_lcm_not_zero(unsigned long a, unsigned long b)
{
	unsigned long l = ref_lcm(a, b);

	if (l)
		return l;
	return b ? b : a;
}

/* ---- lib/math/rational.c --------------------------------------------- */

void ref_rational_best_approximation(
	unsigned long given_numerator, unsigned long given_denominator,
	unsigned long max_numerator, unsigned long max_denominator,
	unsigned long *best_numerator, unsigned long *best_denominator)
{
	unsigned long n, d, n0, d0, n1, d1, n2, d2;

	n = given_numerator;
	d = given_denominator;
	n0 = d1 = 0;
	n1 = d0 = 1;

	for (;;) {
		unsigned long dp, a;

		if (d == 0)
			break;
		dp = d;
		a = n / d;
		d = n % d;
		n = dp;

		n2 = n0 + a * n1;
		d2 = d0 + a * d1;

		if ((n2 > max_numerator) || (d2 > max_denominator)) {
			unsigned long t = ~0UL;

			if (d1)
				t = (max_denominator - d0) / d1;
			if (n1) {
				unsigned long u = (max_numerator - n0) / n1;

				if (u < t)
					t = u;
			}

			if (!d1 || 2u * t > a || (2u * t == a && d0 * dp > d1 * d)) {
				n1 = n0 + t * n1;
				d1 = d0 + t * d1;
			}
			break;
		}
		n0 = n1;
		n1 = n2;
		d0 = d1;
		d1 = d2;
	}
	*best_numerator = n1;
	*best_denominator = d1;
}

/* ---- lib/math/div64.c, __iter_div_u64_rem from include/vdso/math64.h -- */

uint32_t ref_iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder)
{
	uint32_t ret = 0;

	while (dividend >= divisor) {
		/* the barrier the C carries, so the compiler cannot turn this
		 * into a modulo -- the whole point of the function */
		__asm__("" : "+rm"(dividend));

		dividend -= divisor;
		ret++;
	}

	*remainder = dividend;
	return ret;
}
