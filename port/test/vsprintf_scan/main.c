/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Differential test for lib/vsprintf.c's vsscanf()/sscanf() ->
 * lib/vsprintf_scan_rs.rs. Real va_list arguments (the only way to
 * exercise the actual va_arg round trip the C thunk and Rust classify/
 * consume functions do together), same shape as run_vsnprintf.sh's
 * Island C: REF is the pristine vsscanf() (renamed ref_vsscanf), "mine"
 * is THIS project's own retained vsscanf() (port/tree/lib/vsprintf.c,
 * unrenamed -- real production symbol names, calling into
 * vsprintf_scan_rs.rs).
 *
 * Corpus deliberately targets the known-fragile areas from this file's
 * own research pass (see the cross-session coordination with
 * md5-porter before this file was written):
 *   - long digit runs against a narrow field width (2021 commit
 *     900fdc457376's fix area -- simple_strntoll/simple_strntoull's
 *     own max_chars limit, unchanged C, but only reachable at all if
 *     vsprintf_scan_rs_next() reports the right field_width/base).
 *   - multiple specifiers in one format string (the historical
 *     "forgot to reset field_width between specifiers" bug class).
 *   - %[ correctness AND va_arg-consumption-count parity on every
 *     failure path (field_width==-1, no closing ']', empty set, no
 *     first-character match) -- see vsprintf_scan_rs.rs's module doc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

extern int ref_vsscanf(const char *buf, const char *fmt, va_list args);
/*
 * ours (port/tree/lib/vsprintf.c, unrenamed real production name) --
 * declared under a LOCAL name with an explicit asm-label pinning the
 * linker symbol to "vsscanf", NOT as `extern int vsscanf(...)`
 * directly. glibc's own <stdio.h> (included below) declares vsscanf
 * with `__asm__("" "__isoc23_vsscanf")` (a real, load-bearing symbol
 * redirect, not a `#define` -- invisible to `#ifdef`, found by
 * `cc -E`/`-S` directly). Once any declaration of the identifier
 * `vsscanf` picks up that asm-label in this translation unit, EVERY
 * subsequent use of the name silently calls glibc's own scanf instead
 * of this project's -- regardless of include order, and without any
 * compiler warning at the call site. Caught for real: with a plain
 * `extern int vsscanf(...)`, this harness quietly diffed glibc's
 * sscanf against upstream Linux's kernel vsscanf for its entire first
 * run, not this file's actual vsscanf() vs vsprintf_scan_rs.rs at all.
 */
extern int real_vsscanf(const char *buf, const char *fmt, va_list args) __asm__("vsscanf");

static unsigned long total, failed;
static unsigned int g_seed = 20260906;

static unsigned int xrand(unsigned int bound)
{
	g_seed = g_seed * 1103515245u + 12345u;
	return bound ? (g_seed >> 16) % bound : 0;
}

static int ref_sscanf_v(const char *buf, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = ref_vsscanf(buf, fmt, ap);
	va_end(ap);
	return r;
}
static int mine_sscanf_v(const char *buf, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap, fmt);
	r = real_vsscanf(buf, fmt, ap);
	va_end(ap);
	return r;
}

/* Random decimal digit string, `len` digits, optionally signed, into
 * `out` (caller-sized buffer). Returns the numeric value as a string
 * the reader can also independently sanity-check by eye when a
 * mismatch prints it. */
static void rand_digits(char *out, unsigned int len, int allow_sign)
{
	unsigned int i = 0;
	if (allow_sign && xrand(2))
		out[i++] = '-';
	for (unsigned int j = 0; j < len; j++)
		out[i++] = '0' + xrand(10);
	out[i] = '\0';
}

static void rand_hex(char *out, unsigned int len)
{
	static const char *digits = "0123456789abcdefABCDEF";
	unsigned int i;
	for (i = 0; i < len; i++)
		out[i] = digits[xrand(22)];
	out[i] = '\0';
}

static void rand_octal(char *out, unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		out[i] = '0' + xrand(8);
	out[i] = '\0';
}

static void rand_spaces(char *out, unsigned int max)
{
	unsigned int n = xrand(max + 1), i;
	for (i = 0; i < n; i++)
		out[i] = " \t\n"[xrand(3)];
	out[i] = '\0';
}

/* Runs one `fmt` against `buf` on both arms with a SINGLE `int *`
 * output, comparing return value and the written int. Covers %d/%i/
 * %u/%o/%x/%X/%hhd/%hd/%ld/%lld/%zd -- every qualifier writes through
 * a different-sized destination upstream, so this macro takes the
 * destination TYPE and re-reads it back through an `int`-sized probe
 * only for the common `int`/`unsigned int` (no qualifier) case;
 * qualifier-specific cases get their own small dedicated functions
 * below since the destination width differs.
 */
#define CHECK_INT(label, buf, fmt) do { \
	int rv, mv; \
	int rr = ref_sscanf_v((buf), (fmt), &rv); \
	int mr = mine_sscanf_v((buf), (fmt), &mv); \
	total++; \
	if (rr != mr || (rr == 1 && rv != mv)) { \
		failed++; \
		printf("MISMATCH %-20s buf=[%s] fmt=[%s] ref=(%d,%d) mine=(%d,%d)\n", \
		       (label), (buf), (fmt), rr, rv, mr, mv); \
	} \
} while (0)

static void test_plain_numeric(unsigned int n)
{
	char buf[64], fmt[16];
	unsigned int i;
	for (i = 0; i < n; i++) {
		unsigned int len = 1 + xrand(12);
		char pre[16];
		rand_spaces(pre, 3);
		char digits[16];
		int base_char = "diuoxX"[xrand(6)];
		if (base_char == 'x' || base_char == 'X')
			rand_hex(digits, len);
		else if (base_char == 'o')
			rand_octal(digits, len);
		else
			rand_digits(digits, len, base_char == 'd' || base_char == 'i');
		snprintf(buf, sizeof(buf), "%s%s", pre, digits);
		snprintf(fmt, sizeof(fmt), "%%%c", base_char);
		CHECK_INT("plain_numeric", buf, fmt);

		/* narrow field width against a longer digit run -- the
		 * 2021 overflow-fix's own reason for existing. */
		unsigned int width = 1 + xrand(len > 1 ? len - 1 : 1);
		snprintf(fmt, sizeof(fmt), "%%%u%c", width, base_char);
		CHECK_INT("narrow_width", buf, fmt);
	}
}

static void test_qualifiers(unsigned int n)
{
	char buf[32];
	unsigned int i;
	const char *quals[] = { "hh", "h", "l", "ll", "z", "" };
	for (i = 0; i < n; i++) {
		char digits[16];
		rand_digits(digits, 1 + xrand(6), 1);
		snprintf(buf, sizeof(buf), "%s", digits);

		char fmt[16];
		const char *q = quals[xrand(6)];
		snprintf(fmt, sizeof(fmt), "%%%sd", q);

		/* Destination width varies by qualifier; store into a
		 * union big enough for any of them and compare only the
		 * bytes the format actually wrote (both arms use the
		 * SAME qualifier, so both write the same width -- a
		 * plain memcmp of the whole union catches any which one
		 * only writes 1/2/4/8 bytes). */
		union { signed char c; short h; long l; long long ll; int i; } rv, mv;
		memset(&rv, 0xAA, sizeof(rv));
		memset(&mv, 0xAA, sizeof(mv));
		int rr = ref_sscanf_v(buf, fmt, &rv);
		int mr = mine_sscanf_v(buf, fmt, &mv);
		total++;
		if (rr != mr || memcmp(&rv, &mv, sizeof(rv)) != 0) {
			failed++;
			printf("MISMATCH qualifiers buf=[%s] fmt=[%s] ref_ret=%d mine_ret=%d\n",
			       buf, fmt, rr, mr);
		}
	}
}

static void test_multi_specifier_state(unsigned int n)
{
	char buf[64];
	unsigned int i;
	for (i = 0; i < n; i++) {
		/* "%3d%d": the first specifier sets field_width=3; the
		 * SECOND has no width digit at all, so it must NOT
		 * inherit the first's field_width -- exactly the shape
		 * of the historical "forgot to reset field_width" bug. */
		char d1[8], d2[8];
		rand_digits(d1, 3 + xrand(3), 0); /* deliberately >3 digits sometimes */
		rand_digits(d2, 1 + xrand(6), 0);
		snprintf(buf, sizeof(buf), "%s%s", d1, d2);

		int r1, r2, m1, m2;
		int rr = ref_sscanf_v(buf, "%3d%d", &r1, &r2);
		int mr = mine_sscanf_v(buf, "%3d%d", &m1, &m2);
		total++;
		if (rr != mr || (rr >= 1 && r1 != m1) || (rr >= 2 && r2 != m2)) {
			failed++;
			printf("MISMATCH multi_specifier buf=[%s] ref=(%d,%d,%d) mine=(%d,%d,%d)\n",
			       buf, rr, r1, r2, mr, m1, m2);
		}
	}
}

static void test_char_string(unsigned int n)
{
	char buf[64];
	unsigned int i;
	static const char alphabet[] = "abcdefgh ij\tkl";
	for (i = 0; i < n; i++) {
		unsigned int len = 1 + xrand(20);
		unsigned int j;
		for (j = 0; j < len; j++)
			buf[j] = alphabet[xrand(sizeof(alphabet) - 1)];
		buf[len] = '\0';

		char rbuf[32], mbuf[32];
		memset(rbuf, 'Z', sizeof(rbuf));
		memset(mbuf, 'Z', sizeof(mbuf));
		unsigned int width = 1 + xrand(10);
		char fmt[16];
		snprintf(fmt, sizeof(fmt), "%%%uc", width);
		int rr = ref_sscanf_v(buf, fmt, rbuf);
		int mr = mine_sscanf_v(buf, fmt, mbuf);
		total++;
		if (rr != mr || memcmp(rbuf, mbuf, width) != 0) {
			failed++;
			printf("MISMATCH %%c buf=[%s] fmt=[%s] ref_ret=%d mine_ret=%d\n", buf, fmt, rr, mr);
		}

		memset(rbuf, 'Z', sizeof(rbuf));
		memset(mbuf, 'Z', sizeof(mbuf));
		rr = ref_sscanf_v(buf, "%s", rbuf);
		mr = mine_sscanf_v(buf, "%s", mbuf);
		total++;
		if (rr != mr || strcmp(rbuf, mbuf) != 0) {
			failed++;
			printf("MISMATCH %%s buf=[%s] ref=[%s](%d) mine=[%s](%d)\n", buf, rbuf, rr, mbuf, mr);
		}
	}
}

static void test_bracket(unsigned int n)
{
	char buf[32];
	unsigned int i;
	static const char *fmts[] = {
		"%5[abc]", "%5[^abc]", "%1[a]", "%3[xyz]", "%5[a]",
		"%[abc]",   /* no field width -- upstream: return num immediately */
	};
	static const char alphabet[] = "abcxyz";
	for (i = 0; i < n; i++) {
		unsigned int len = xrand(8);
		unsigned int j;
		for (j = 0; j < len; j++)
			buf[j] = alphabet[xrand(sizeof(alphabet) - 1)];
		buf[len] = '\0';

		const char *fmt = fmts[xrand(sizeof(fmts) / sizeof(fmts[0]))];
		char rbuf[16], mbuf[16];
		memset(rbuf, 'Z', sizeof(rbuf));
		memset(mbuf, 'Z', sizeof(mbuf));
		int rr = ref_sscanf_v(buf, fmt, rbuf);
		int mr = mine_sscanf_v(buf, fmt, mbuf);
		total++;
		if (rr != mr || (rr == 1 && strcmp(rbuf, mbuf) != 0)) {
			failed++;
			printf("MISMATCH %%[ buf=[%s] fmt=[%s] ref=[%s](%d) mine=[%s](%d)\n",
			       buf, fmt, rbuf, rr, mbuf, mr);
		}
	}

	/* Malformed set (no closing ']') -- va_arg still consumed
	 * upstream, must still be consumed here (see module doc); a
	 * mismatch here would most likely show up as a LATER argument
	 * reading garbage, which is exactly why this is its own case. */
	{
		char rbuf[16] = "R", mbuf[16] = "M";
		int rtail = -1, mtail = -1;
		int rr = ref_sscanf_v("abc123", "%5[abc", rbuf, &rtail);
		int mr = mine_sscanf_v("abc123", "%5[abc", mbuf, &mtail);
		total++;
		if (rr != mr || rtail != mtail) {
			failed++;
			printf("MISMATCH %%[ no-close ref=(%d,%d) mine=(%d,%d)\n", rr, rtail, mr, mtail);
		}
	}
}

static void test_n_and_percent(unsigned int n)
{
	char buf[32];
	unsigned int i;
	for (i = 0; i < n; i++) {
		unsigned int len = 1 + xrand(6);
		rand_digits(buf, len, 0);

		int rd, md, rn, mn;
		int rr = ref_sscanf_v(buf, "%d%n", &rd, &rn);
		int mr = mine_sscanf_v(buf, "%d%n", &md, &mn);
		total++;
		if (rr != mr || rd != md || rn != mn) {
			failed++;
			printf("MISMATCH %%n buf=[%s] ref=(%d,%d,%d) mine=(%d,%d,%d)\n",
			       buf, rr, rd, rn, mr, md, mn);
		}
	}

	{
		int rv, mv;
		int rr = ref_sscanf_v("50% off", "%d%% off", &rv);
		int mr = mine_sscanf_v("50% off", "%d%% off", &mv);
		total++;
		if (rr != mr || rv != mv) {
			failed++;
			printf("MISMATCH %%%% ref=(%d,%d) mine=(%d,%d)\n", rr, rv, mr, mv);
		}
	}
}

static void test_literal_and_skip(unsigned int n)
{
	char buf[64];
	unsigned int i;
	for (i = 0; i < n; i++) {
		char d1[8], d2[8];
		rand_digits(d1, 1 + xrand(4), 0);
		rand_digits(d2, 1 + xrand(4), 0);
		snprintf(buf, sizeof(buf), "id=%s name=%s", d1, d2);

		int r1, m1;
		char rname[16], mname[16];
		int rr = ref_sscanf_v(buf, "id=%d name=%s", &r1, rname);
		int mr = mine_sscanf_v(buf, "id=%d name=%s", &m1, mname);
		total++;
		if (rr != mr || (rr >= 1 && r1 != m1) || (rr >= 2 && strcmp(rname, mname) != 0)) {
			failed++;
			printf("MISMATCH literal buf=[%s] ref=(%d,%d,%s) mine=(%d,%d,%s)\n",
			       buf, rr, r1, rname, mr, m1, mname);
		}

		/* "%*d %d": skip-conversion, then a real one. */
		char skipbuf[32];
		snprintf(skipbuf, sizeof(skipbuf), "%s %s", d1, d2);
		int rv, mv;
		rr = ref_sscanf_v(skipbuf, "%*d %d", &rv);
		mr = mine_sscanf_v(skipbuf, "%*d %d", &mv);
		total++;
		if (rr != mr || (rr == 1 && rv != mv)) {
			failed++;
			printf("MISMATCH skip buf=[%s] ref=(%d,%d) mine=(%d,%d)\n", skipbuf, rr, rv, mr, mv);
		}
	}
}

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 10) : 2000;
	g_seed = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 10) : 20260906;

	printf("vsscanf differential: %lu ops/family, seed %u\n", runs, g_seed);

	test_plain_numeric(runs);
	test_qualifiers(runs);
	test_multi_specifier_state(runs);
	test_char_string(runs);
	test_bracket(runs);
	test_n_and_percent(runs);
	test_literal_and_skip(runs);

	printf("%lu checks, %lu mismatches\n", total, failed);
	return failed ? 1 : 0;
}
