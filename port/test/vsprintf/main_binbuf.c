/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Island B: the vbin_printf/bstr_printf packing+decode plumbing. Neither
 * Island A (pointer()-direct) nor Island C (real-va_list vsnprintf) touch
 * this at all: vbin_printf's own save_arg packing switch (PTR_ALIGN
 * arithmetic, the FORMAT_STATE_WIDTH/'p'-lookahead special case, and the
 * "process the %p suffix NOW, save_arg only for S/s/x/K/e" split) and
 * bstr_printf's own get_arg decode switch (the mirror-image PTR_ALIGN
 * arithmetic, and "pointer dereference was already processed, just
 * memcpy" path for every OTHER %p suffix) are real, live EXPORT_SYMBOL_GPL
 * plumbing (ftrace's binary trace event pipeline), not dead code.
 *
 * Design: pack REAL va_list arguments ONCE with pristine vbin_printf(),
 * then decode the SAME bin_buf with pristine bstr_printf() (ground truth)
 * and with OUR bstr_printf() (under test), and compare.
 *
 * Ground truth is pristine bstr_printf(), NOT vsnprintf() -- the two are
 * NOT interchangeable oracles here. bstr_printf()'s own "pointer
 * dereference was already processed, just memcpy" path
 * (lib/vsprintf.c:3362-3369) only advances `str`/`args` when `str < end`
 * (the C's own `if (str < end) { ... }` gate, faithfully reproduced in
 * vsprintf_rs.rs, see its own comment on the FORMAT_STATE_PTR case) -- so
 * once the output buffer is exhausted, bstr_printf() genuinely STOPS
 * accumulating the "would-be" length for these specific %p rows, unlike
 * vsnprintf() (which always calls pointer() itself and always computes the
 * full length regardless of buffer size). This is a real, documented
 * upstream quirk of bstr_printf() itself, not a bug -- comparing against
 * vsnprintf() as ground truth was this test's own first-draft mistake,
 * caught by the very first real run (every %p row whose packing shortcut
 * hits this path mismatched at cap=0, and only there).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

extern int ref_vbin_printf(uint32_t *bin_buf, size_t size, const char *fmt, va_list args);
extern int ref_bstr_printf(char *buf, size_t size, const char *fmt, const uint32_t *bin_buf);
extern int bstr_printf(char *buf, size_t size, const char *fmt, const uint32_t *bin_buf); /* ours */

extern _Bool no_hash_pointers, filled_random_ptr_key;
extern int debug_boot_weak_hash;
extern int ref_no_hash_pointers, ref_filled_random_ptr_key, ref_debug_boot_weak_hash;
extern struct { unsigned long long key[2]; } ptr_key, ref_ptr_key;

static unsigned long total, failed;

#define BIN_BUF_WORDS 64

static void run_pair(const char *label, const char *fmt, size_t cap, va_list args)
{
	char refbuf[256], outbuf[256];
	uint32_t bin_buf[BIN_BUF_WORDS];
	int rn, bn;

	memset(refbuf, 'X', sizeof(refbuf));
	memset(outbuf, 'X', sizeof(outbuf));
	memset(bin_buf, 0, sizeof(bin_buf));

	ref_no_hash_pointers = no_hash_pointers;
	ref_filled_random_ptr_key = filled_random_ptr_key;
	ref_debug_boot_weak_hash = debug_boot_weak_hash;
	ref_ptr_key.key[0] = ptr_key.key[0];
	ref_ptr_key.key[1] = ptr_key.key[1];

	/* Pack ONCE (real va_list, pristine vbin_printf); decode the SAME
	 * bin_buf with both bstr_printf implementations. */
	ref_vbin_printf(bin_buf, BIN_BUF_WORDS, fmt, args);

	rn = ref_bstr_printf(refbuf, cap, fmt, bin_buf);
	bn = bstr_printf(outbuf, cap, fmt, bin_buf);

	total++;
	if (rn != bn) {
		failed++;
		printf("MISMATCH(len) %-14s fmt=%-14s cap=%zu ref_n=%d bstr_n=%d\n", label, fmt, cap, rn, bn);
		return;
	}
	if (memcmp(refbuf, outbuf, cap) != 0) {
		failed++;
		printf("MISMATCH(bytes) %-14s fmt=%-14s cap=%zu ref=[%.*s] bstr=[%.*s]\n",
		       label, fmt, cap, (int)cap, refbuf, (int)cap, outbuf);
	}
}

#define VARIADIC_CALL(name) \
	static void name(const char *fmt, size_t cap, ...) \
	{ \
		va_list args; \
		va_start(args, cap); \
		run_pair(#name, fmt, cap, args); \
		va_end(args); \
	}

#define CHECK(name, fmt, ...) do { \
	size_t sz; \
	for (sz = 0; sz <= 40; sz += (sz < 8 ? 1 : 9)) { \
		size_t cap = sz > 256 ? 256 : sz; \
		name(fmt, cap, ##__VA_ARGS__); \
	} \
} while (0)

VARIADIC_CALL(call_plaintext)
VARIADIC_CALL(call_d)
VARIADIC_CALL(call_u)
VARIADIC_CALL(call_x)
VARIADIC_CALL(call_ld)
VARIADIC_CALL(call_lld)
VARIADIC_CALL(call_width)
VARIADIC_CALL(call_left)
VARIADIC_CALL(call_zero)
VARIADIC_CALL(call_prec)
VARIADIC_CALL(call_s)
VARIADIC_CALL(call_s_prec)
VARIADIC_CALL(call_c)
VARIADIC_CALL(call_pct)
VARIADIC_CALL(call_mixed)
VARIADIC_CALL(call_star_width)
VARIADIC_CALL(call_star_prec)
VARIADIC_CALL(call_p_plain)
VARIADIC_CALL(call_p_x)
VARIADIC_CALL(call_p_S)
VARIADIC_CALL(call_p_M)
VARIADIC_CALL(call_p_I4)
VARIADIC_CALL(call_p_h)
VARIADIC_CALL(call_p_mixed)
VARIADIC_CALL(call_p_R)

int main(void)
{
	no_hash_pointers = 0;
	filled_random_ptr_key = 1;
	debug_boot_weak_hash = 0;
	ptr_key.key[0] = 0x0123456789abcdefULL;
	ptr_key.key[1] = 0xfedcba9876543210ULL;

	CHECK(call_plaintext, "hello world, no specifiers at all");
	CHECK(call_d, "%d", -12345);
	CHECK(call_u, "%u", 12345u);
	CHECK(call_x, "%x", 0xdeadbeefu);
	CHECK(call_ld, "%ld", (long)-123456789L);
	CHECK(call_lld, "%lld", (long long)-123456789012345LL);
	CHECK(call_width, "%10d", 42);
	CHECK(call_left, "%-10d|", 42);
	CHECK(call_zero, "%010d", 42);
	CHECK(call_prec, "%.5d", 42);
	CHECK(call_s, "%s", "hello, world");
	CHECK(call_s_prec, "%.3s", "hello");
	CHECK(call_c, "%c", 'Z');
	CHECK(call_pct, "100%%");
	CHECK(call_mixed, "[%5d/%-5s/%c/%%]", 7, "ab", 'q');
	CHECK(call_star_width, "%*d", 8, 42);
	CHECK(call_star_prec, "%.*s", 3, "hello");

	/* %p family -- the 5 deferred-in-vbin_printf suffixes (S/s/x/K/e:
	 * save_arg(void*), processed at DECODE time by bstr_printf calling
	 * pointer()) vs everything else (processed DURING packing, "already
	 * processed" memcpy at decode time) -- both packing shapes covered. */
	{
		void *ptr = (void *)0x1234abcd5678ULL;
		unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
		unsigned char ip4[4] = {10, 0, 0, 1};
		unsigned char hexbuf[4] = {0xde, 0xad, 0xbe, 0xef};
		struct resource_test {
			unsigned long long start, end;
			const char *name;
			unsigned long flags, desc;
			void *parent, *sibling, *child;
		} res = {.start = 0x1000, .end = 0x1fff, .flags = 0x200};

		CHECK(call_p_plain, "%p", ptr);      /* deferred: save_arg(void*) */
		CHECK(call_p_x, "%px", ptr);         /* deferred: save_arg(void*) */
		CHECK(call_p_S, "%pS", ptr);         /* deferred: save_arg(void*) */
		CHECK(call_p_M, "%pM", mac);         /* processed during packing */
		CHECK(call_p_I4, "%pI4", ip4);       /* processed during packing */
		CHECK(call_p_h, "%4ph", hexbuf);     /* processed during packing */
		CHECK(call_p_mixed, "v=%d p=%px n=%s m=%pM", 7, ptr, "x", mac);
		CHECK(call_p_R, "%pR", &res);        /* processed during packing */
	}

	printf("%lu cases, %lu mismatches\n", total, failed);
	return failed ? 1 : 0;
}
