// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. The body is lib/memweight_rs.rs, which counts every byte's
 * popcount instead of the C's three-phase aligned walk. That is a deliberate
 * divergence and the reasoning is in the Rust file: the total number of set
 * bits in a byte range does not depend on how the bytes are grouped, so the
 * endianness caveat the C is built around does not arise.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 *
 * THE BUG_ON STAYS HERE. It is observable behaviour -- it panics -- and
 * BUG_ON plants a bug-table entry naming this file and line, which is what
 * makes the splat say memweight(). The Rust body does not need the guard
 * (it indexes a slice, it cannot run off the end), but callers who trip it
 * today must still trip it.
 */

#include <linux/export.h>
#include <linux/bug.h>
#include <linux/bitmap.h>

/* lib/memweight_rs.rs */
size_t rust_memweight(const void *ptr, size_t bytes);

/**
 * memweight - count the total number of bits set in memory area
 * @ptr: pointer to the start of the area
 * @bytes: the size of the area
 */
size_t memweight(const void *ptr, size_t bytes)
{
	BUG_ON(bytes / sizeof(long) >= INT_MAX / BITS_PER_LONG);

	return rust_memweight(ptr, bytes);
}
EXPORT_SYMBOL(memweight);
