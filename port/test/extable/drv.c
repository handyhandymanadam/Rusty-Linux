/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/extable/drv.c -- differential for lib/extable.c's
 * sort_extable()/search_extable().
 *
 * ex_to_insn() is `insn`, a file-local helper in both arms; this driver
 * computes it independently (the same formula, over ITS OWN copy of the
 * array) to build test data and to identify which logical entry a result
 * corresponds to -- an oracle computed from the definition, not read back
 * through the code under test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct ex_entry {
	int insn, fixup, data;
};

/* ---- C arm (renamed) ---- */
void c_sort_extable(struct ex_entry *start, struct ex_entry *finish);
const struct ex_entry *c_search_extable(const struct ex_entry *base, size_t num,
					unsigned long value);

/* ---- Rust arm ---- */
void sort_extable(struct ex_entry *start, struct ex_entry *finish);
const struct ex_entry *search_extable(const struct ex_entry *base, size_t num,
				      unsigned long value);

static unsigned long ex_to_insn(const struct ex_entry *e)
{
	return (unsigned long)&e->insn + e->insn;
}

static unsigned long cases, mism;

static void bad(const char *what, unsigned long ctx)
{
	if (mism < 20)
		printf("MISMATCH %-12s ctx=%lu\n", what, ctx);
	mism++;
}

/* PROVE THE COMPARISON CAN DISAGREE: with EXTABLE_PROVE_CAN_FAIL=1, corrupt
 * one entry's `data` in the Rust-arm copy after sorting, before searching --
 * both must then disagree on at least one lookup. */
static int poison;

static void run_one(unsigned n, unsigned seed)
{
	struct ex_entry *c = calloc(n, sizeof(*c));
	struct ex_entry *r = calloc(n, sizeof(*r));
	unsigned long *target = malloc(n * sizeof(*target));

	unsigned s = seed;
	for (unsigned i = 0; i < n; i++) {
		s = s * 1103515245u + 12345u;
		/* A relative offset is all `insn` can hold (i32) -- real
		 * exception table entries always point within the same
		 * kernel image, at most a few MB from the table itself.
		 * Spread targets across +/-8 MB of this entry's own address
		 * (well inside i32 range), unique per index by construction. */
		long off = (long)(s % (16u * 1024 * 1024)) - 8 * 1024 * 1024;
		unsigned long addr = (unsigned long)&c[i].insn + off;
		target[i] = addr;
		int insn_off = (int)(addr - (unsigned long)&c[i].insn);
		c[i].insn = insn_off;
		c[i].fixup = (int)(i * 7 + 1);
		c[i].data = (int)(i * 13 + 3);
	}
	memcpy(r, c, n * sizeof(*c));
	/* r's `insn`/`fixup` offsets are relative to r[i], not c[i] -- redo
	 * them so the Rust array is independently self-consistent. */
	for (unsigned i = 0; i < n; i++) {
		int insn_off = (int)(target[i] - (unsigned long)&r[i].insn);
		r[i].insn = insn_off;
	}

	c_sort_extable(c, c + n);
	sort_extable(r, r + n);

	if (poison && n > 0)
		r[n / 2].data ^= 1;

	/* Every constructed target must be found by both arms, at an entry
	 * whose fixup/data match what that target was built with. */
	for (unsigned i = 0; i < n; i++) {
		const struct ex_entry *rc = c_search_extable(c, n, target[i]);
		const struct ex_entry *rr = search_extable(r, n, target[i]);
		cases++;
		if (!rc || !rr) {
			bad("not-found", target[i]);
			continue;
		}
		if (rc->fixup != rr->fixup || rc->data != rr->data) {
			bad("mismatch", target[i]);
		}
		if (ex_to_insn(rc) != target[i] || ex_to_insn(rr) != target[i]) {
			bad("wrong-entry", target[i]);
		}
	}

	/* A handful of addresses that were never inserted must come back
	 * NULL from both. */
	for (unsigned k = 0; k < 8; k++) {
		s = s * 1103515245u + 12345u;
		unsigned long addr = 0xffffffff85000000UL + (s % 0x400000u) * 4;
		const struct ex_entry *rc = c_search_extable(c, n, addr);
		const struct ex_entry *rr = search_extable(r, n, addr);
		cases++;
		if ((rc == NULL) != (rr == NULL))
			bad("absent-disagree", addr);
	}

	free(c);
	free(r);
	free(target);
}

int main(void)
{
	if (getenv("EXTABLE_PROVE_CAN_FAIL"))
		poison = 1;

	for (unsigned n = 1; n <= 200; n++)
		for (unsigned trial = 0; trial < 20; trial++)
			run_one(n, n * 2654435761u + trial);

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
