/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Deterministic stand-ins for kernel machinery this harness cannot link
 * for real (no vmlinux, no symbol table, no device tree, no clock
 * framework, no dcache/cred in a userspace binary). Linked into BOTH the
 * REF (pristine vsprintf.c, -Dstatic=) and RS (vsprintf_rs.o) test
 * binaries, so both sides observe the identical stub behavior -- what
 * this actually tests is pointer()'s DISPATCH (does the right handler run
 * for a given fmt suffix) and the surrounding buffer-copy/width logic, not
 * the real kernel behavior these stand in for. See vsprintf_rs.rs's own
 * module doc for which %p rows are deferred/untestable-in-userspace for
 * exactly this reason.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/siphash.h>
#include <linux/uuid.h>
#include <linux/string_helpers.h>
#include <linux/hex.h>

/* string_escape_mem's own documented contract: "writes as many characters
 * as it can to the given buffer, and returns the total size of the output
 * had the buffer been big enough" -- escaped_string()'s own logic (flags
 * parsed from fmt, len from spec.field_width, buf advanced by the return
 * value) is what's under test here, not string_escape_mem's real escaping
 * rules (already verified, port/test/string_helpers/). This stand-in
 * mirrors the truncate-and-report-full-size contract with a plain copy. */
int string_escape_mem(const char *src, size_t isz, char *dst, size_t osz,
		unsigned int flags, const char *only)
{
	size_t n = isz < osz ? isz : osz;
	if (n && dst)
		memcpy(dst, src, n);
	return (int)isz;
}

/* simple_strntoull's own two helpers (lib/kstrtox.c, now kstrtox_rs.rs).
 * simple_strntoull/simple_strtoXX stay unexercised by this harness's
 * corpus (their own independent follow-up port, per vsprintf_rs.rs's
 * module doc) -- these two only need to let simple_strntoull COMPILE and
 * LINK, not behave correctly.
 */
const char *_parse_integer_fixup_radix(const char *s, unsigned int *base)
{
	if (*base == 0)
		*base = 10;
	return s;
}
unsigned int _parse_integer_limit(const char *s, unsigned int base, unsigned long long *res,
				   size_t max_chars)
{
	*res = 0;
	return 0;
}

/* Real values, lib/hexdump.c. */
const char hex_asc[] = "0123456789abcdef";
const char hex_asc_upper[] = "0123456789ABCDEF";

/* Real values, lib/uuid.c -- uuid_string()'s own byte-order permutations,
 * genuinely exercised by this harness's corpus. */
const u8 guid_index[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
const u8 uuid_index[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

/* Deterministic (NOT the real siphash algorithm) stand-in, shared by both
 * arms -- see siphash.h's own comment for why this is a legitimate
 * simplification for THIS harness's purpose (ptr_to_id's hash-then-format
 * logic, not siphash's own already-separately-verified correctness). */
u64 siphash_1u64(u64 first, const siphash_key_t *key)
{
	u64 h = first ^ key->key[0];
	h = (h << 13) | (h >> 51);
	h ^= key->key[1];
	h *= 0x9E3779B97F4A7C15ULL;
	return h;
}
u64 siphash_1u32(u32 first, const siphash_key_t *key)
{
	return siphash_1u64((u64)first, key);
}

/* Small, deterministic {mask, name} tables -- real shape (`{0, NULL}`
 * sentinel-terminated, matching mm/debug.c's own), fabricated values
 * (flags_string's 'g'/'v' dispatch and format_flags's own bit-matching
 * logic are what's under test, not the real GFP_ or VM_ bit assignments). */
const struct trace_print_flags gfpflag_names[] = {
	{0x1, "GFP_A"},
	{0x2, "GFP_B"},
	{0x4, "GFP_C"},
	{0, 0},
};
const struct trace_print_flags vmaflag_names[] = {
	{0x1, "VM_A"},
	{0x2, "VM_B"},
	{0x4, "VM_C"},
	{0, 0},
};
const struct trace_print_flags pageflag_names[] = {
	{0, 0},
};

/* find_bit_rs.rs's real exported names (lib/find_bit.c) -- RS externs
 * these directly, matching the underscore-prefixed real symbols; REF's own
 * `for_each_set_bitrange()` (this harness's kernel.h shim) uses an
 * unprefixed `find_next_bit`/`find_next_zero_bit` pair with the same
 * logic, so both arms agree. Genuinely exercised (bitmap_list_string, in
 * scope). */
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	for (; start < nbits; start++)
		if ((addr[start / 64] >> (start % 64)) & 1)
			return start;
	return nbits;
}
unsigned long _find_next_zero_bit(const unsigned long *addr, unsigned long nbits, unsigned long start)
{
	for (; start < nbits; start++)
		if (!((addr[start / 64] >> (start % 64)) & 1))
			return start;
	return nbits;
}

int sprint_symbol(char *buffer, unsigned long address)
{
	return sprintf(buffer, "S:%lx", address);
}
int sprint_symbol_no_offset(char *buffer, unsigned long address)
{
	return sprintf(buffer, "s:%lx", address);
}
int sprint_symbol_build_id(char *buffer, unsigned long address)
{
	return sprintf(buffer, "Sb:%lx", address);
}
int sprint_backtrace(char *buffer, unsigned long address)
{
	return sprintf(buffer, "B:%lx", address);
}
int sprint_backtrace_build_id(char *buffer, unsigned long address)
{
	return sprintf(buffer, "Bb:%lx", address);
}

/* %pA is Rust-only by upstream's own doc comment ("Do *not* use it from
 * C") -- unreachable from either island's corpus, and never defined by
 * either the REF or "mine" arm (it lives in rust/kernel/print.rs in the
 * real kernel, not in vsprintf.c at all), so a shared stub belongs here
 * rather than in stubs_deferred.c (which only Island A links). */
char *rust_fmt_argument(char *buf, char *end, const void *ptr)
{
	fprintf(stderr, "test bug: reached rust_fmt_argument (out of this harness's scope)\n");
	abort();
}
