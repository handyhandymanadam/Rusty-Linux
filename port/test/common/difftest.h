/* SPDX-License-Identifier: GPL-2.0 */
/* Shared differential machinery: poisoned buffers with canaries, and the
 * comparisons every harness makes the same way.
 *
 * WHY THIS FILE EXISTS. The same reason port/test/common/shim/linux/kernel.h
 * exists: four harnesses grew their own <linux/kernel.h> and drifted 40-71
 * lines apart, and the fork that was missing a definition tested something
 * other than what the kernel builds. The comparison code has the same
 * exposure, and it is worse, because a harness whose comparison is subtly
 * weaker does not fail -- it PASSES, over less than it claims.
 *
 * WHAT IT GUARANTEES, so no harness has to remember:
 *
 *   - Every buffer carries PAD bytes of poison on BOTH sides, and the whole
 *     padded region is compared, so a port that writes one element further
 *     than the C fails here even when the logical result is identical.
 *   - The padding is then re-checked against the poison, because a stray
 *     write BOTH arms make is invisible to a comparison of the arms against
 *     each other.
 *   - The poison pattern varies with position, so a copy from the wrong
 *     offset cannot accidentally reproduce it.
 *   - Return values are compared as raw size_t. Two DIFFERENT zstd error
 *     codes are both "an error" and would pass a test that only asked
 *     isError(a) == isError(b); they must be equal.
 */
#ifndef PORT_TEST_COMMON_DIFFTEST_H
#define PORT_TEST_COMMON_DIFFTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define DT_PAD 64

struct dt_buf {
	unsigned char *base;	/* DT_PAD + len + DT_PAD */
	unsigned char *p;	/* the usable part */
	size_t len;
	size_t total;
	unsigned char tag;
};

static unsigned long dt_fails;
static unsigned long dt_checks;
static unsigned long dt_maxfails = 10;

static inline void dt_buf_init(struct dt_buf *b, size_t len, unsigned char tag)
{
	b->len = len;
	b->total = len + 2 * DT_PAD;
	b->base = malloc(b->total);
	if (!b->base) {
		fprintf(stderr, "difftest: out of memory\n");
		exit(2);
	}
	b->p = b->base + DT_PAD;
	b->tag = tag;
}

static inline unsigned char dt_poison_byte(unsigned char tag, size_t i)
{
	return (unsigned char)(tag ^ (i * 31u) ^ 0xA5u);
}

static inline void dt_buf_poison(struct dt_buf *b)
{
	size_t i;

	for (i = 0; i < b->total; i++)
		b->base[i] = dt_poison_byte(b->tag, i);
}

static inline int dt_pad_intact(const struct dt_buf *b, const char **where)
{
	size_t i;

	for (i = 0; i < b->total; i++) {
		if (i == DT_PAD)
			i = DT_PAD + b->len;
		if (i >= b->total)
			break;
		if (b->base[i] != dt_poison_byte(b->tag, i)) {
			*where = i < DT_PAD ? "before" : "after";
			return 0;
		}
	}
	return 1;
}

static inline void dt_fail(unsigned long run, const char *what, const char *detail)
{
	fprintf(stderr, "MISMATCH run %lu: %s: %s\n", run, what, detail);
	if (++dt_fails >= dt_maxfails) {
		fprintf(stderr, "too many mismatches, stopping\n");
		exit(1);
	}
}

static inline void dt_cmp_ret(unsigned long run, const char *what,
			      size_t a, size_t b)
{
	char d[160];

	dt_checks++;
	if (a == b)
		return;
	snprintf(d, sizeof d, "ret ref=%zu (0x%zx) rs=%zu (0x%zx)", a, a, b, b);
	dt_fail(run, what, d);
}

static inline void dt_cmp_u32(unsigned long run, const char *what,
			      const char *name, unsigned a, unsigned b)
{
	char d[128];

	dt_checks++;
	if (a == b)
		return;
	snprintf(d, sizeof d, "%s: ref=%u rs=%u", name, a, b);
	dt_fail(run, what, d);
}

static inline void dt_cmp_buf(unsigned long run, const char *what,
			      const char *name,
			      const struct dt_buf *a, const struct dt_buf *b)
{
	char d[224];
	const char *where;
	size_t i;

	dt_checks++;
	if (memcmp(a->base, b->base, a->total) != 0) {
		for (i = 0; i < a->total && a->base[i] == b->base[i]; i++)
			;
		snprintf(d, sizeof d,
			 "%s differs at byte %zd (relative to the usable start; "
			 "ref=0x%02x rs=0x%02x)",
			 name, (ptrdiff_t)i - DT_PAD, a->base[i], b->base[i]);
		dt_fail(run, what, d);
		return;
	}
	if (!dt_pad_intact(a, &where)) {
		snprintf(d, sizeof d, "%s: BOTH arms wrote the %s padding",
			 name, where);
		dt_fail(run, what, d);
	}
}

#endif /* PORT_TEST_COMMON_DIFFTEST_H */
