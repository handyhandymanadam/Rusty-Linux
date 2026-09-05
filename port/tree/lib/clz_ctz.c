// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/clz_ctz.c
 *
 * Copyright (C) 2013 Chanho Min <chanho.min@lge.com>
 *
 * The functions in this file aren't called directly, but are required by
 * GCC builtins such as __builtin_ctz, and therefore they can't be removed
 * despite appearing unreferenced in kernel source.
 *
 * __c[lt]z[sd]i2 can be overridden by linking arch-specific versions.
 *
 * PORTED TO RUST. The four bodies are lib/clz_ctz_rs.rs; what is left here
 * is the four C entry symbols, their __weak markers and their
 * EXPORT_SYMBOL() lines.
 *
 * THE __weak IS WHY THE WRAPPERS ARE NOT OPTIONAL HERE, quite apart from the
 * MODVERSIONS CRC argument in logs/c-entry-rule.md. The comment just above
 * says an architecture may override these by linking its own; a Rust
 * #[no_mangle] symbol is strong, so defining them there directly would
 * silently take that ability away from every architecture that uses it.
 */

#include <linux/export.h>
#include <linux/kernel.h>

/* lib/clz_ctz_rs.rs */
int rust_ctzsi2(int val);
int rust_clzsi2(int val);
int rust_clzdi2(u64 val);
int rust_ctzdi2(u64 val);

int __weak __ctzsi2(int val);
int __weak __attribute_const__ __ctzsi2(int val)
{
	return rust_ctzsi2(val);
}
EXPORT_SYMBOL(__ctzsi2);

int __weak __clzsi2(int val);
int __weak __attribute_const__ __clzsi2(int val)
{
	return rust_clzsi2(val);
}
EXPORT_SYMBOL(__clzsi2);

int __weak __clzdi2(u64 val);
int __weak __attribute_const__ __clzdi2(u64 val)
{
	return rust_clzdi2(val);
}
EXPORT_SYMBOL(__clzdi2);

int __weak __ctzdi2(u64 val);
int __weak __attribute_const__ __ctzdi2(u64 val)
{
	return rust_ctzdi2(val);
}
EXPORT_SYMBOL(__ctzdi2);
