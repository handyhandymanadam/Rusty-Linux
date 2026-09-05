// SPDX-License-Identifier: GPL-2.0-only
/*
 * PORTED TO RUST. Both algorithms are lib/math/gcd_rs.rs; what is left here
 * is the C entry symbol, its EXPORT_SYMBOL_GPL(), the zero cases, and the
 * static key.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 *
 * THE STATIC KEY STAYS IN C, and not for want of trying. static_branch_likely()
 * is a jump label: the branch is patched into the instruction stream at boot
 * and read by the CPU, not by any function that could be called from Rust.
 * Reading it here and passing the answer down would work but would cost the
 * call the jump label exists to avoid. So gcd() consults the key and calls
 * one of the two Rust bodies directly.
 */

#include <linux/export.h>
#include <linux/gcd.h>
#include <linux/kernel.h>

/*
 * This implements the binary GCD algorithm. (Often attributed to Stein,
 * but as Knuth has noted, appears in a first-century Chinese math text.)
 *
 * This is faster than the division-based algorithm even on x86, which
 * has decent hardware division.
 */

DEFINE_STATIC_KEY_TRUE(efficient_ffs_key);

/* lib/math/gcd_rs.rs */
unsigned long rust_binary_gcd(unsigned long a, unsigned long b);
unsigned long rust_gcd_even_odd(unsigned long a, unsigned long b);

/**
 * gcd - calculate and return the greatest common divisor of 2 unsigned longs
 * @a: first value
 * @b: second value
 */
unsigned long gcd(unsigned long a, unsigned long b)
{
	unsigned long r = a | b;

	if (!a || !b)
		return r;

#if !defined(CONFIG_CPU_NO_EFFICIENT_FFS)
	if (static_branch_likely(&efficient_ffs_key))
		return rust_binary_gcd(a, b);
#endif

	return rust_gcd_even_odd(a, b);
}
EXPORT_SYMBOL_GPL(gcd);
