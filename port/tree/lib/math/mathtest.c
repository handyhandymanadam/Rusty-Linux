// SPDX-License-Identifier: GPL-2.0
/*
 * lib/math self-test -- the SCOPE.md §4 class-A proof caller for the ported
 * lib/math/ functions.
 *
 * WHY THIS EXISTS AND lib/glob's DID NOT
 *   glob already had CONFIG_GLOB_SELFTEST in tree, so nothing had to be
 *   written. lib/math has KUnit tests for div64 and rational and nothing at
 *   all for int_pow or int_sqrt, and pulling KUnit into config-fast costs
 *   more than these thirty lines.
 *
 * WHAT IT IS FOR, EXACTLY
 *   Not correctness. Correctness is settled in userspace by
 *   port/test/math/, which runs tens of millions of cases against the
 *   original C bodies in seconds. This runs in the kernel to answer one
 *   question a userspace test cannot: DID THE RUST ACTUALLY RUN, in the
 *   kernel, on the boot path. A previous kernel passed every behavioural
 *   check while containing no Rust at all.
 *
 *   So the vectors here are few and deliberately chosen: the ones a
 *   mistranslation would break, not a lattice.
 *
 * ONE TEST PER PORTED FUNCTION, added when the function is ported.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/gcd.h>
#include <linux/int_log.h>
#include <linux/lcm.h>
#include <linux/math64.h>
#include <linux/rational.h>
#include <linux/math.h>
#include <linux/reciprocal_div.h>
#include <linux/module.h>
#include <linux/printk.h>

static unsigned int passed __initdata, failed __initdata;

static void __init check(bool ok, const char *what)
{
	if (ok) {
		passed++;
		return;
	}
	failed++;
	pr_err("mathtest: %s *** ERROR ***\n", what);
}

static void __init test_int_sqrt(void)
{
	/* Exact squares, the value either side of one, and the boundaries
	 * where the C's `1UL << (__fls(x) & ~1UL)` and the Rust's
	 * leading_zeros() would part company if the port were wrong. */
	check(int_sqrt(0) == 0, "int_sqrt(0)");
	check(int_sqrt(1) == 1, "int_sqrt(1)");
	check(int_sqrt(2) == 1, "int_sqrt(2)");
	check(int_sqrt(3) == 1, "int_sqrt(3)");
	check(int_sqrt(4) == 2, "int_sqrt(4)");
	check(int_sqrt(99) == 9, "int_sqrt(99)");
	check(int_sqrt(100) == 10, "int_sqrt(100)");
	check(int_sqrt(101) == 10, "int_sqrt(101)");
	check(int_sqrt(1UL << 32) == (1UL << 16), "int_sqrt(2^32)");
	check(int_sqrt((1UL << 32) - 1) == (1UL << 16) - 1, "int_sqrt(2^32-1)");
	check(int_sqrt(ULONG_MAX) == 0xffffffffUL, "int_sqrt(ULONG_MAX)");
}

static void __init test_int_pow(void)
{
	/* Including the wrapping cases: the C multiplies u64s and lets them
	 * wrap, callers get that today, so the Rust wraps too rather than
	 * saturating or panicking. */
	check(int_pow(0, 0) == 1, "int_pow(0,0)");
	check(int_pow(0, 5) == 0, "int_pow(0,5)");
	check(int_pow(2, 0) == 1, "int_pow(2,0)");
	check(int_pow(2, 10) == 1024, "int_pow(2,10)");
	check(int_pow(2, 63) == (1ULL << 63), "int_pow(2,63)");
	check(int_pow(2, 64) == 0, "int_pow(2,64) wraps to 0");
	check(int_pow(10, 19) == 10000000000000000000ULL, "int_pow(10,19)");
	check(int_pow(3, 40) == 12157665459056928801ULL, "int_pow(3,40)");
}

static void __init test_intlog(void)
{
	/* intlog2(2^k) is exactly k << 24: the significand lands on table
	 * entry 0 with no interpolation, so any drift in the msb arithmetic
	 * or the table index shows here immediately. */
	unsigned int k;

	for (k = 0; k < 32; k++)
		check(intlog2(1u << k) == (k << 24), "intlog2(2^k) == k<<24");

	/* Values computed from the ORIGINAL C body in port/pristine/, not
	 * from the Rust. Two of them exercise the table interpolation and
	 * one the top of the range. */
	check(intlog2(3) == 26591232u, "intlog2(3)");
	check(intlog2(12345) == 228029800u, "intlog2(12345)");
	check(intlog2(0xffffffffu) == 536870911u, "intlog2(UINT_MAX)");

	check(intlog10(1) == 0u, "intlog10(1)");
	check(intlog10(10) == 16777225u, "intlog10(10)");
	check(intlog10(1000) == 50331675u, "intlog10(1000)");
	check(intlog10(0xffffffffu) == 161614247u, "intlog10(UINT_MAX)");
}

static void __init test_reciprocal(void)
{
	static const u32 ds[] __initconst = { 1, 2, 3, 7, 10, 1000, 0x7fffffffu };
	unsigned int i;

	/* The magic constants, from the original C body. */
	check(reciprocal_value(3).m == 1431655766u, "reciprocal_value(3).m");
	check(reciprocal_value(3).sh1 == 1, "reciprocal_value(3).sh1");
	check(reciprocal_value(3).sh2 == 1, "reciprocal_value(3).sh2");
	check(reciprocal_value(1000).m == 103079216u, "reciprocal_value(1000).m");
	check(reciprocal_value(1000).sh2 == 9, "reciprocal_value(1000).sh2");

	/* And the property the constants exist for, which does not depend on
	 * anyone's arithmetic being transcribed correctly: dividing by the
	 * reciprocal must equal dividing. */
	for (i = 0; i < ARRAY_SIZE(ds); i++) {
		struct reciprocal_value R = reciprocal_value(ds[i]);
		u32 a;
		bool ok = true;

		for (a = 0; a < 4096 && ok; a++)
			ok = reciprocal_divide(a, R) == a / ds[i];
		ok = ok && reciprocal_divide(0xffffffffu, R) == 0xffffffffu / ds[i];
		check(ok, "reciprocal_divide(a, reciprocal_value(d)) == a / d");
	}
}

/* Plain Euclid, sharing no code with either binary-GCD body. Comparing the
 * port against the C it came from cannot notice a mistake both make; this
 * can. */
static unsigned long __init euclid(unsigned long a, unsigned long b)
{
	while (b) {
		unsigned long t = a % b;

		a = b;
		b = t;
	}
	return a;
}

static void __init test_gcd_lcm(void)
{
	static const unsigned long pairs[][2] __initconst = {
		{ 1, 1 }, { 2, 3 }, { 12, 18 }, { 48, 180 }, { 1071, 462 },
		{ 1UL << 40, 3UL << 20 }, { 0xffffffffffffffffUL, 3 },
		{ 0xfffffffffffffffeUL, 0xffffffffffffffffUL },
	};
	unsigned int i;
	bool ok = true;

	/* The zero cases, which gcd() answers before any Rust runs. */
	check(gcd(0, 0) == 0, "gcd(0,0)");
	check(gcd(0, 7) == 7, "gcd(0,7)");
	check(gcd(7, 0) == 7, "gcd(7,0)");

	check(gcd(12, 18) == 6, "gcd(12,18)");
	check(gcd(1071, 462) == 21, "gcd(1071,462)");
	check(gcd(0xffffffffffffffffUL, 3) == 3, "gcd(ULONG_MAX,3)");

	for (i = 0; i < ARRAY_SIZE(pairs); i++)
		ok = ok && gcd(pairs[i][0], pairs[i][1]) ==
			   euclid(pairs[i][0], pairs[i][1]);
	check(ok, "gcd() agrees with Euclid on every pair");

	check(lcm(0, 5) == 0, "lcm(0,5)");
	check(lcm(5, 0) == 0, "lcm(5,0)");
	check(lcm(4, 6) == 12, "lcm(4,6)");
	check(lcm(21, 6) == 42, "lcm(21,6)");
	check(lcm_not_zero(0, 5) == 5, "lcm_not_zero(0,5)");
	check(lcm_not_zero(5, 0) == 5, "lcm_not_zero(5,0)");
	check(lcm_not_zero(0, 0) == 0, "lcm_not_zero(0,0)");
	check(lcm_not_zero(4, 6) == 12, "lcm_not_zero(4,6)");
}

static void __init test_iter_div(void)
{
	u64 rem;

	check(iter_div_u64_rem(0, 7, &rem) == 0 && rem == 0, "iter_div_u64_rem(0,7)");
	check(iter_div_u64_rem(6, 7, &rem) == 0 && rem == 6, "iter_div_u64_rem(6,7)");
	check(iter_div_u64_rem(7, 7, &rem) == 1 && rem == 0, "iter_div_u64_rem(7,7)");
	check(iter_div_u64_rem(20, 7, &rem) == 2 && rem == 6, "iter_div_u64_rem(20,7)");
	check(iter_div_u64_rem(1000, 1, &rem) == 1000 && rem == 0, "iter_div_u64_rem(1000,1)");
	check(iter_div_u64_rem(999999, 1000, &rem) == 999 && rem == 999,
	      "iter_div_u64_rem(999999,1000)");
}

#if IS_ENABLED(CONFIG_RATIONAL)
static void __init test_rational(void)
{
	unsigned long n, d;

	/* The example from lib/math/rational.c's own comment. */
	rational_best_approximation(31415, 10000, (1 << 8) - 1, (1 << 5) - 1, &n, &d);
	check(n == 22 && d == 7, "rational(31415/10000, 255, 31) == 22/7");

	rational_best_approximation(1, 1, 1, 1, &n, &d);
	check(n == 1 && d == 1, "rational(1/1, 1, 1) == 1/1");

	rational_best_approximation(0, 1, 100, 100, &n, &d);
	check(n == 0 && d == 1, "rational(0/1, 100, 100) == 0/1");

	rational_best_approximation(1, 0, 100, 100, &n, &d);
	check(n == 1 && d == 0, "rational(1/0, 100, 100) == 1/0");

	/* 355/113 is the classic close approximation to pi. */
	rational_best_approximation(31415926, 10000000, 1000, 1000, &n, &d);
	check(n == 355 && d == 113, "rational(pi, 1000, 1000) == 355/113");

	/* An exact fraction must come back reduced, not rounded. */
	rational_best_approximation(1000, 2000, 10000, 10000, &n, &d);
	check(n == 1 && d == 2, "rational(1000/2000) == 1/2");
}
#else
static void __init test_rational(void) { }
#endif

static int __init mathtest_init(void)
{
	test_int_sqrt();
	test_int_pow();
	test_intlog();
	test_reciprocal();
	test_gcd_lcm();
	test_iter_div();
	test_rational();

	pr_info("mathtest: %u self-tests passed, %u failed\n", passed, failed);

	/* Same convention as lib/globtest.c: refuse to load on mismatch. */
	return failed ? -ECANCELED : 0;
}

static void __exit mathtest_exit(void) { }

module_init(mathtest_init);
module_exit(mathtest_exit);

MODULE_DESCRIPTION("lib/math self-test");
MODULE_LICENSE("GPL");
