/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/cmdline/drv.c -- differential for lib/cmdline.c.
 *
 * The C arm is port/pristine/lib/cmdline.c with its four externals shimmed;
 * the Rust arm is port/tree/lib/cmdline_rs.rs generated at run time. Both see
 * the SAME shims, so what is compared is the two parsers.
 *
 * Every case runs on a fresh copy of the input, because next_arg() terminates
 * its argument IN PLACE -- the two arms would otherwise be fed different
 * bytes, and the second would "agree" with a string the first had chewed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int   c_get_option(char **str, int *pint);
char *c_get_options(const char *str, int nints, int *ints);
unsigned long long c_memparse(const char *ptr, char **retptr);
bool  c_parse_option_str(const char *str, const char *option);
char *c_next_arg(char *args, char **param, char **val);

int   get_option(char **str, int *pint);
char *get_options(const char *str, int nints, int *ints);
unsigned long long memparse(const char *ptr, char **retptr);
bool  parse_option_str(const char *str, const char *option);
char *next_arg(char *args, char **param, char **val);

static unsigned long cases, mism;

/* PROVE THE COMPARISON CAN DISAGREE. A differential that has never disagreed
 * is not known to work, and this one never has. With CMDLINE_PROVE_CAN_FAIL=1
 * the Rust arm is handed an input differing from the C arm's by one bit, so
 * the run MUST report mismatches; run.sh fails if it does not. It is the same
 * device as port/test/memneq/'s deliberately-mismatched fourth arm. */
static int poison;

static void maybe_poison(char *b)
{
	if (poison && *b)
		*b ^= 1;
}

static void bad(const char *what, const char *in)
{
	if (mism < 20)
		printf("MISMATCH %-16s on \"%s\"\n", what, in);
	mism++;
}

/* ---- get_option ------------------------------------------------------- */
static void t_get_option(const char *in)
{
	char a[128], b[128], *pa = a, *pb = b;
	int va = 0x5a5a5a5a, vb = 0x5a5a5a5a, ra, rb;

	memset(a, 0x7e, sizeof(a));
	memset(b, 0x7e, sizeof(b));
	snprintf(a, sizeof(a), "%s", in);
	snprintf(b, sizeof(b), "%s", in);
	maybe_poison(b);
	ra = c_get_option(&pa, &va);
	rb =   get_option(&pb, &vb);
	cases++;
	if (ra != rb || va != vb || (pa - a) != (pb - b))
		bad("get_option", in);

	/* pint == NULL is documented as validator mode. */
	pa = a; pb = b;
	ra = c_get_option(&pa, NULL);
	rb =   get_option(&pb, NULL);
	cases++;
	if (ra != rb || (pa - a) != (pb - b))
		bad("get_option/NULL", in);
}

/* ---- get_options ------------------------------------------------------ */
static void t_get_options(const char *in, int nints)
{
	int ia[24], ib[24];
	char *ea, *eb;
	char a[128], b[128];

	memset(a, 0x7e, sizeof(a));
	memset(b, 0x7e, sizeof(b));
	snprintf(a, sizeof(a), "%s", in);
	snprintf(b, sizeof(b), "%s", in);
	maybe_poison(b);
	memset(ia, 0x33, sizeof(ia));
	memset(ib, 0x33, sizeof(ib));
	ea = c_get_options(a, nints, ia);
	eb =   get_options(b, nints, ib);
	cases++;
	if ((ea - a) != (eb - b) || memcmp(ia, ib, sizeof(ia)))
		bad("get_options", in);
}

/* ---- memparse --------------------------------------------------------- */
static void t_memparse(const char *in)
{
	char *ea = NULL, *eb = NULL;
	unsigned long long ra, rb;

	ra = c_memparse(in, &ea);
	rb =   memparse(in, &eb);
	cases++;
	if (ra != rb || (ea - in) != (eb - in))
		bad("memparse", in);

	/* retptr == NULL must not fault. */
	cases++;
	if (c_memparse(in, NULL) != memparse(in, NULL))
		bad("memparse/NULL", in);
}

/* ---- parse_option_str ------------------------------------------------- */
static void t_parse_option_str(const char *in, const char *opt)
{
	cases++;
	if (c_parse_option_str(in, opt) != parse_option_str(in, opt))
		bad("parse_option_str", in);
}

/* ---- next_arg --------------------------------------------------------- */
static void t_next_arg(const char *in)
{
	char a[128], b[128];
	char *pa = NULL, *va = NULL, *ra;
	char *pb = NULL, *vb = NULL, *rb;

	/* THE WHOLE BUFFER IS COMPARED at the end, because next_arg() edits in
	 * place and those edits are the output. So both buffers start from the
	 * same known bytes -- without this the uninitialised tails differ and
	 * every case "mismatches". */
	memset(a, 0x7e, sizeof(a));
	memset(b, 0x7e, sizeof(b));
	snprintf(a, sizeof(a), "%s", in);
	snprintf(b, sizeof(b), "%s", in);
	maybe_poison(b);
	ra = c_next_arg(a, &pa, &va);
	rb =   next_arg(b, &pb, &vb);
	cases++;
	/* Compare what the caller can see: the two strings, the NULL-ness of
	 * the value, and the OFFSET of every returned pointer -- addresses
	 * differ between the two buffers by construction. */
	if ((ra - a) != (rb - b) ||
	    (pa - a) != (pb - b) ||
	    ((va == NULL) != (vb == NULL)) ||
	    (va && (va - a) != (vb - b)) ||
	    strcmp(pa, pb) ||
	    (va && strcmp(va, vb)) ||
	    strcmp(ra, rb) ||
	    memcmp(a, b, sizeof(a)))     /* the in-place edits themselves */
		bad("next_arg", in);
}

int main(void)
{
	static const char * const opts[] = {
		"", " ", "  ", "a", "-", "--", "-,", "-\"\"", ",", ",,",
		"0", "1", "42", "-1", "-42", "0x10", "0X10", "010", "9z",
		"1,2", "1,2,3", "1-3", "1-3,7", "3-1", "-1-3", "1--3",
		"1-", "-3", "1,-2,3", "0-9", "1-9,11-13", "2147483647",
		"2147483648", "4294967296", "-2147483648", "-2147483649",
		"1K", "1k", "1M", "1m", "1G", "1g", "1T", "1t", "1P", "1p",
		"1E", "1e", "64E", "8M,rest", "0x1000K", "12345678901234567890",
		"foo=bar", "foo=bar baz", "flag", "flag rest", "=v", "=v tail",
		"k=\"a b\"", "k=\"a b\" next", "\"q u\"=v", "\"q u\"=v tail",
		"\"unterminated", "a=\"b", "a=\"b\"c", "a=1    b=2",
		"a,bb,ccc", "abb", "a,,b", "quiet", "quiet,verbose",
		"x=\"\"", "\"\"", "\"\"=y", "a=b=c", "  lead", "trail  ",
	};
	static const char * const needles[] = { "a", "b", "bb", "ccc", "quiet",
						"verbose", "", "abb", "x" };
	unsigned int i, j;

	poison = getenv("CMDLINE_PROVE_CAN_FAIL") != NULL;

	for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
		t_get_option(opts[i]);
		t_memparse(opts[i]);
		t_next_arg(opts[i]);
		for (j = 0; j <= 12; j++)
			t_get_options(opts[i], j);
		for (j = 0; j < sizeof(needles) / sizeof(needles[0]); j++)
			t_parse_option_str(opts[i], needles[j]);
	}

	printf("cases=%lu mismatches=%lu\n", cases, mism);
	return mism != 0;
}
