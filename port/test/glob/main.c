/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential test: lib/glob.c's matcher (the oracle) against the Rust port.
 *
 * This is the "simple tests, fast, userspace" step of the loop in notes/GOALS.md
 * §3. It is not a harness and is not reusable apparatus -- it is one file,
 * built by one line of shell, that answers one question: do the two arms
 * agree on every input we can think of and a few million we cannot.
 *
 * Four stages, cheapest first:
 *   1  the in-tree lib/globtest.c corpus, verbatim
 *   2  exhaustive over a metacharacter-dense alphabet
 *   3  random fuzz, wider alphabet, longer inputs
 *   4  guard-page: the length-bounded entry point on a buffer with an
 *      unmapped page immediately after it, so an over-read is a SIGSEGV
 *      rather than a silent pass
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool ref_glob_match_str(char const *pat, char const *str, char const *str_end);
bool rust_glob_match_str(char const *pat, char const *str, char const *str_end);

static unsigned long checked, mismatches;

static void check(char const *pat, char const *str, char const *end,
		  char const *stage)
{
	bool a = ref_glob_match_str(pat, str, end);
	bool b = rust_glob_match_str(pat, str, end);

	checked++;
	if (a == b)
		return;

	if (mismatches < 20)
		fprintf(stderr, "MISMATCH [%s] pat=\"%s\" str=\"%s\" end=%s: C=%d rust=%d\n",
			stage, pat, str, end ? "set" : "NULL", a, b);
	mismatches++;
}

/* ---- 1. the in-tree corpus ------------------------------------------- */

#include "corpus_generated.h"

static unsigned long corpus_expect_fail;

static void stage_corpus(void)
{
	char const *p = glob_tests;
	unsigned long n = 0;

	while (*p) {
		bool expected = *p++ & 1;
		char const *pat = p;

		p += strlen(p) + 1;
		check(pat, p, NULL, "corpus");
		/* Also confirm the Rust agrees with the corpus, not merely
		 * with the C. If the C itself were wrong we would want to
		 * know that too. */
		if (rust_glob_match_str(pat, p, NULL) != expected) {
			fprintf(stderr, "CORPUS pat=\"%s\" str=\"%s\" expected %d\n",
				pat, p, expected);
			corpus_expect_fail++;
		}
		p += strlen(p) + 1;
		n++;
	}
	printf("  corpus       %lu cases\n", n);
}

/* ---- 2. exhaustive --------------------------------------------------- */

static char const pat_alpha[] = "ab*?[]!-\\";
static char const str_alpha[] = "ab]";

static void enumerate(char *buf, int len, int pos, char const *alpha,
		      void (*fn)(char const *))
{
	if (pos == len) {
		buf[len] = '\0';
		fn(buf);
		return;
	}
	for (char const *a = alpha; *a; a++) {
		buf[pos] = *a;
		enumerate(buf, len, pos + 1, alpha, fn);
	}
}

#define MAX_PAT 5
#define MAX_STR 4

static char cur_pat[MAX_PAT + 1];

static void with_str(char const *s)
{
	check(cur_pat, s, NULL, "exhaustive");
	check(cur_pat, s, s + strlen(s), "exhaustive-len");
}

static void with_pat(char const *p)
{
	char sbuf[MAX_STR + 1];

	strcpy(cur_pat, p);
	for (int sl = 0; sl <= MAX_STR; sl++)
		enumerate(sbuf, sl, 0, str_alpha, with_str);
}

static void stage_exhaustive(void)
{
	char pbuf[MAX_PAT + 1];
	unsigned long before = checked;

	for (int pl = 0; pl <= MAX_PAT; pl++)
		enumerate(pbuf, pl, 0, pat_alpha, with_pat);
	printf("  exhaustive   %lu cases  (patterns <=%d over \"%s\", strings <=%d over \"%s\")\n",
	       checked - before, MAX_PAT, pat_alpha, MAX_STR, str_alpha);
}

/* ---- 3. fuzz --------------------------------------------------------- */

static unsigned long rnd_state = 0x243f6a8885a308d3ULL;

static unsigned long rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 7;
	rnd_state ^= rnd_state << 17;
	return rnd_state;
}

static char const fuzz_alpha[] = "abc*?[]!-\\^.0";

static void stage_fuzz(unsigned long rounds)
{
	char pat[33], str[33];
	unsigned long before = checked;

	for (unsigned long i = 0; i < rounds; i++) {
		int pl = rnd() % 32, sl = rnd() % 32;
		int j;

		for (j = 0; j < pl; j++)
			pat[j] = fuzz_alpha[rnd() % (sizeof(fuzz_alpha) - 1)];
		pat[pl] = '\0';
		for (j = 0; j < sl; j++)
			str[j] = fuzz_alpha[rnd() % (sizeof(fuzz_alpha) - 1)];
		str[sl] = '\0';

		check(pat, str, NULL, "fuzz");
		check(pat, str, str + sl, "fuzz-len");
	}
	printf("  fuzz         %lu cases\n", checked - before);
}

/* ---- 4. guard page --------------------------------------------------- */

/*
 * The length-bounded entry point is the one that reads a buffer nobody
 * promised was NUL-terminated. Put the buffer flush against an unmapped
 * page: a single byte read past the end is then a SIGSEGV, not a value
 * that happens to be zero. A test that cannot fail proves nothing, so the
 * arrangement is checked by deliberately over-reading first.
 */
static char *guard_buf(size_t len, size_t *page_out)
{
	long ps = sysconf(_SC_PAGESIZE);
	char *m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (m == MAP_FAILED) {
		perror("mmap");
		exit(2);
	}
	if (mprotect(m + ps, ps, PROT_NONE) != 0) {
		perror("mprotect");
		exit(2);
	}
	*page_out = ps;
	return m + ps - len;	/* flush against the guard */
}

static void stage_guard(void)
{
	size_t ps;
	unsigned long before = checked;
	static char const *pats[] = {
		"*", "a*", "*a", "abc", "a?c", "[a-c]*", "*[!x]", "***abc",
		"*a*b*c*", "\\a*", "[", "[a", "a*b*c*d*e*f", "?????", NULL
	};

	for (int len = 0; len <= 24; len++) {
		char *b = guard_buf(len, &ps);
		char *pb;

		for (int j = 0; j < len; j++)
			b[j] = "abcabc"[j % 6];

		for (char const **p = pats; *p; p++) {
			/* string flush against the guard page */
			check(*p, b, b + len, "guard-str");

			/* and the pattern flush against one too, its NUL
			 * being the final readable byte */
			pb = guard_buf(strlen(*p) + 1, &ps);
			memcpy(pb, *p, strlen(*p) + 1);
			check(pb, b, b + len, "guard-pat");
			munmap(pb - (ps - strlen(*p) - 1), 2 * ps);
		}
		munmap(b - (ps - len), 2 * ps);
	}
	printf("  guard-page   %lu cases  (buffer flush against PROT_NONE)\n",
	       checked - before);
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
	unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 0) : 2000000;

	if (getenv("GLOB_PROVE_CAN_FAIL")) {
		/* notes/PRIOR-ART.md §5: a test that has never failed is not known
		 * to work. Read one byte past the guarded buffer and confirm
		 * the arrangement kills us. */
		size_t ps;
		char *b = guard_buf(4, &ps);
		volatile char x;

		memcpy(b, "abc", 4);
		fprintf(stderr, "prove-can-fail: reading b[4] past the guard\n");
		x = b[4];
		fprintf(stderr, "prove-can-fail: FAILED, read %d and survived\n", x);
		return 3;
	}

	printf("glob differential: lib/glob.c (oracle) vs rust_glob_match_str\n");
	stage_corpus();
	stage_exhaustive();
	stage_fuzz(rounds);
	stage_guard();

	printf("\n  checked      %lu\n", checked);
	printf("  mismatches   %lu\n", mismatches);
	printf("  corpus wrong %lu\n", corpus_expect_fail);

	if (mismatches || corpus_expect_fail) {
		printf("\nFAIL\n");
		return 1;
	}
	printf("\nPASS\n");
	return 0;
}
