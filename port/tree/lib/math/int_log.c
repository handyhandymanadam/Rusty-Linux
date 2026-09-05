// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Provides fixed-point logarithm operations.
 *
 * Copyright (C) 2006 Christoph Pfister (christophpfister@gmail.com)
 *
 * PORTED TO RUST. The table and the arithmetic are lib/math/int_log_rs.rs;
 * what is left here is the two C entry symbols, their EXPORT_SYMBOL() lines,
 * and the zero checks.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays. Moving
 * the definition itself into Rust changes the MODVERSIONS CRC.
 *
 * The WARN_ON(1) stays in C deliberately. WARN_ON is not a function; it
 * plants a bug-table entry carrying this file and line, and that is what
 * makes the splat name intlog2() rather than a Rust shim. The Rust body is
 * only ever entered with value != 0, which is also why it can use
 * leading_zeros() without a zero case.
 */

#include <linux/bug.h>
#include <linux/export.h>
#include <linux/int_log.h>
#include <linux/types.h>

/* lib/math/int_log_rs.rs */
unsigned int rust_intlog2(u32 value);
unsigned int rust_intlog10(u32 value);

/**
 *	intlog2 - computes log2(value) * 2^24
 *	@value: The value (must be != 0)
 *
 *	returns: log2(value) * 2^24
 *	wrong result if value = 0 (log2(0) is undefined)
 */
unsigned int intlog2(u32 value)
{
	if (unlikely(value == 0)) {
		WARN_ON(1);
		return 0;
	}

	return rust_intlog2(value);
}
EXPORT_SYMBOL(intlog2);

/**
 *	intlog10 - computes log10(value) * 2^24
 *	@value: The value (must be != 0)
 *
 *	returns: log10(value) * 2^24
 *	wrong result if value = 0 (log10(0) is undefined)
 */
unsigned int intlog10(u32 value)
{
	if (unlikely(value == 0)) {
		WARN_ON(1);
		return 0;
	}

	return rust_intlog10(value);
}
EXPORT_SYMBOL(intlog10);
