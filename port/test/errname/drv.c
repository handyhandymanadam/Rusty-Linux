/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/errname/drv.c -- differential for lib/errname.c.
 *
 * Exhaustively compares every err value in [-1024, 1024] -- small enough
 * to just do all of it rather than sample.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- C arm (renamed) ---- */
const char *c_errname(int err);

/* ---- Rust arm ---- */
const char *errname(int err);

static unsigned long cases, mism;
static int poison;

static void bad(int err, const char *c, const char *r)
{
	if (mism < 20)
		printf("MISMATCH err=%d c=%s r=%s\n", err, c ? c : "(null)", r ? r : "(null)");
	mism++;
}

int main(void)
{
	if (getenv("ERRNAME_PROVE_CAN_FAIL"))
		poison = 1;

	for (int err = -1024; err <= 1024; err++) {
		const char *c = c_errname(err);
		const char *r = errname(err);
		cases++;

		if (poison && err == -5) {
			/* Prove the harness can disagree: corrupt what we
			 * compare the Rust answer against. */
			c = "not a real errno name";
		}

		if ((c == NULL) != (r == NULL)) {
			bad(err, c, r);
			continue;
		}
		if (c && strcmp(c, r) != 0)
			bad(err, c, r);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
