// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. The bodies are lib/math/reciprocal_div_rs.rs; what is left
 * here is the two C entry symbols, their EXPORT_SYMBOL() lines, and the
 * WARN() that the Rust cannot raise.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays. Moving
 * the definition itself into Rust changes the MODVERSIONS CRC.
 *
 * The WARN() stays in C deliberately. WARN() is not a function -- it plants a
 * bug-table entry carrying this file and line, which is what makes the
 * resulting splat name reciprocal_value_adv rather than some Rust shim. The
 * Rust body is only ever reached with the condition already checked.
 */

#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/types.h>

#include <linux/reciprocal_div.h>

/* lib/math/reciprocal_div_rs.rs */
struct reciprocal_value rust_reciprocal_value(u32 d);
struct reciprocal_value_adv rust_reciprocal_value_adv(u32 d, u8 prec);

/*
 * For a description of the algorithm please have a look at
 * include/linux/reciprocal_div.h
 */

struct reciprocal_value reciprocal_value(u32 d)
{
	return rust_reciprocal_value(d);
}
EXPORT_SYMBOL(reciprocal_value);

struct reciprocal_value_adv reciprocal_value_adv(u32 d, u8 prec)
{
	/* ceil(log2(d)) */
	u32 l = fls(d - 1);

	/* NOTE: mlow/mhigh could overflow u64 when l == 32. This case needs to
	 * be handled before calling "reciprocal_value_adv", please see the
	 * comment at include/linux/reciprocal_div.h.
	 */
	WARN(l == 32,
	     "ceil(log2(0x%08x)) == 32, %s doesn't support such divisor",
	     d, __func__);

	return rust_reciprocal_value_adv(d, prec);
}
EXPORT_SYMBOL(reciprocal_value_adv);
