/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Island C: the real-va_list oracle. Compares REF's pristine vsnprintf()
 * against THIS PROJECT'S OWN retained-C vsnprintf() (port/tree/lib/
 * vsprintf.c, calling into vsprintf_rs.rs's vsprintf_rs_format_decode/
 * vsprintf_rs_number/vsprintf_rs_set_field_width/vsprintf_rs_set_precision/
 * vsprintf_rs_string/vsprintf_rs_convert_num_spec/vsprintf_rs_pointer),
 * using GENUINE va_list arguments -- the one thing Island A (pointer()
 * direct) and a hand-packed Island B cannot exercise: the actual
 * vsnprintf()-level call sites into the Rust bridge functions, including
 * the FORMAT_STATE_WIDTH/PRECISION "resume" path (`%*d`, `%.*s`) that only
 * a real va_list-driven caller reaches at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

extern int ref_vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args); /* ours, port/tree/lib/vsprintf.c */

extern _Bool no_hash_pointers, filled_random_ptr_key;
extern int debug_boot_weak_hash;
extern int ref_no_hash_pointers, ref_filled_random_ptr_key, ref_debug_boot_weak_hash;
extern struct { unsigned long long key[2]; } ptr_key, ref_ptr_key;

static unsigned long total, failed;

static int ref_snprintf_v(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = ref_vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return r;
}
static int mine_snprintf_v(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return r;
}

#define CHECK(label, fmt, ...) do { \
	char rbuf[256], mbuf[256]; \
	int rn, mn; \
	size_t sz; \
	for (sz = 0; sz <= 40; sz += (sz < 8 ? 1 : 9)) { \
		size_t cap = sz > 256 ? 256 : sz; \
		memset(rbuf, 'X', sizeof(rbuf)); \
		memset(mbuf, 'X', sizeof(mbuf)); \
		ref_no_hash_pointers = no_hash_pointers; \
		ref_filled_random_ptr_key = filled_random_ptr_key; \
		ref_debug_boot_weak_hash = debug_boot_weak_hash; \
		ref_ptr_key.key[0] = ptr_key.key[0]; \
		ref_ptr_key.key[1] = ptr_key.key[1]; \
		rn = ref_snprintf_v(rbuf, cap, fmt, ##__VA_ARGS__); \
		mn = mine_snprintf_v(mbuf, cap, fmt, ##__VA_ARGS__); \
		total++; \
		if (rn != mn) { \
			failed++; \
			printf("MISMATCH(len) %-14s fmt=%-10s size=%zu ref_n=%d mine_n=%d\n", label, fmt, sz, rn, mn); \
			continue; \
		} \
		if (memcmp(rbuf, mbuf, cap) != 0) { \
			failed++; \
			printf("MISMATCH(bytes) %-14s fmt=%-10s size=%zu ref=[%.*s] mine=[%.*s]\n", label, fmt, sz, (int)cap, rbuf, (int)cap, mbuf); \
		} \
	} \
} while (0)

int main(void)
{
	no_hash_pointers = 0;
	filled_random_ptr_key = 1;
	debug_boot_weak_hash = 0;
	ptr_key.key[0] = 0x0123456789abcdefULL;
	ptr_key.key[1] = 0xfedcba9876543210ULL;

	CHECK("plain-text", "hello world");
	CHECK("d", "%d", -12345);
	CHECK("u", "%u", 12345u);
	CHECK("x", "%x", 0xdeadbeefu);
	CHECK("X", "%X", 0xdeadbeefu);
	CHECK("o", "%o", 0755);
	CHECK("ld", "%ld", (long)-123456789L);
	CHECK("lld", "%lld", (long long)-123456789012345LL);
	CHECK("width", "%10d", 42);
	CHECK("left", "%-10d|", 42);
	CHECK("zero", "%010d", 42);
	CHECK("plus", "%+d", 42);
	CHECK("space", "% d", 42);
	CHECK("prec", "%.5d", 42);
	CHECK("prec0", "%.0d", 0);
	CHECK("hash-x", "%#x", 0x2au);
	CHECK("hash-o", "%#o", 052);
	CHECK("s", "%s", "hello");
	CHECK("s-prec", "%.3s", "hello");
	CHECK("c", "%c", 'Z');
	CHECK("pct", "100%%");
	CHECK("mixed", "[%5d/%-5s/%c/%%]", 7, "ab", 'q');

	/* FORMAT_STATE_WIDTH/PRECISION resume path -- vsprintf_rs_set_field_width/
	 * vsprintf_rs_set_precision, unreachable from Island A/B at all. */
	CHECK("star-width", "%*d", 8, 42);
	CHECK("star-width-neg", "%*d", -8, 42);
	CHECK("star-prec", "%.*s", 3, "hello");
	CHECK("star-both", "%*.*d", 10, 4, 7);

	/* %p family through the real vsnprintf() call site (va_arg(args,
	 * void*) -> vsprintf_rs_pointer, exactly production's own path). */
	{
		void *ptr = (void *)0x1234abcd5678ULL;
		CHECK("p-plain", "%p", ptr);
		CHECK("p-x", "%px", ptr);
		CHECK("p-M", "%pM", (unsigned char[]){0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
		CHECK("p-I4", "%pI4", (unsigned char[]){10, 0, 0, 1});
		CHECK("p-mixed", "value=%d ptr=%px name=%s", 7, ptr, "x");
	}

	printf("%lu cases, %lu mismatches\n", total, failed);
	return failed ? 1 : 0;
}
