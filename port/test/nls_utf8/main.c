/* SPDX-License-Identifier: GPL-2.0 */
/* Exhaustive differential for fs/nls/nls_utf8.c: pristine C (ref_utf8.c) vs
 * nls_utf8_rs.rs through the SAME struct nls_table function pointers the
 * kernel uses. Both arms call the same pristine nls_base.c utf8<->utf32
 * helpers (not under test).
 *
 *  uni2char : all 65536 wchar_t x boundlen -2..8, output bytes + canaries
 *  char2uni : exhaustive over every k-byte input for k=1,2,3 (boundlen=k) and
 *             all 2^32 4-byte inputs (boundlen 4); plus boundlen 0 and 5,6
 *             on a strided sample. Bytes beyond boundlen are poison.
 *  table    : charset/alias/owner/next, both 256-byte identity tables
 * usage: main SHARD NSHARDS ; NLS_PROVE_CAN_FAIL=1 breaks the Rust arm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/init.h>
#include <linux/nls.h>
#undef wchar_t
#define wchar_t knls_wchar_t

int ref_init(void);
struct nls_table *ref_table(void);
extern struct nls_table nls_utf8_rs_table;
extern int register_calls;

static unsigned long long fails, checks;
static int poison, failfast;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

static void cmp_u2c(struct nls_table *c, struct nls_table *r, unsigned uni, int bl)
{
	unsigned char a[16], b[16];
	int ra, rb;

	memset(a, 0xA5, sizeof a); memset(b, 0xA5, sizeof b);
	ra = c->uni2char((wchar_t)uni, a, bl);
	rb = r->uni2char((wchar_t)uni, b, bl);
	if (poison && uni == 0x20ac && bl == 4) rb++;
	checks++;
	if (ra != rb || memcmp(a, b, sizeof a))
		FAIL("uni2char MISMATCH uni=%#x bl=%d c=%d rust=%d\n", uni, bl, ra, rb);
}

static void cmp_c2u(struct nls_table *c, struct nls_table *r, const unsigned char *in, int bl)
{
	wchar_t ua = 0xBEEF, ub = 0xBEEF;
	int ra = c->char2uni(in, bl, &ua);
	int rb = r->char2uni(in, bl, &ub);

	checks++;
	if (ra != rb || ua != ub)
		FAIL("char2uni MISMATCH in=%02x %02x %02x %02x bl=%d c=%d/%#x rust=%d/%#x\n",
		     in[0], in[1], in[2], in[3], bl, ra, ua, rb, ub);
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
	unsigned nsh = argc > 2 ? (unsigned)atoi(argv[2]) : 1;
	struct nls_table *c, *r = &nls_utf8_rs_table;
	unsigned long long i;
	unsigned uni;
	int bl, k;

	poison = getenv("NLS_PROVE_CAN_FAIL") != NULL;
	failfast = getenv("NLS_FAILFAST") != NULL;
	ref_init();
	c = ref_table();

	if (shard == 0) {		/* table + registration, once */
		int j;

		if (strcmp(c->charset, r->charset)) FAIL("charset differs\n");
		if (c->alias != r->alias) FAIL("alias differs\n");
		if (c->owner != r->owner) FAIL("owner differs\n");
		if (c->next != r->next) FAIL("next differs\n");
		for (j = 0; j < 256; j++)
			if (c->charset2lower[j] != r->charset2lower[j] ||
			    c->charset2upper[j] != r->charset2upper[j] ||
			    r->charset2lower[j] != j || r->charset2upper[j] != j)
				FAIL("identity[%d] differs\n", j);
		if (register_calls != 1) FAIL("register_nls called %d times\n", register_calls);
		checks += 260;
	}

	for (uni = shard; uni <= 0xffff; uni += nsh)
		for (bl = -2; bl <= 8; bl++)
			cmp_u2c(c, r, uni, bl);

	/* 1..3 byte inputs, exhaustive with boundlen == k */
	for (k = 1; k <= 3; k++) {
		unsigned long long lim = 1ULL << (8 * k);

		for (i = shard; i < lim; i += nsh) {
			unsigned char in[8] = { 0x80, 0x80, 0x80, 0x80, 0xC3, 0xC3, 0xC3, 0xC3 };
			int j;

			for (j = 0; j < k; j++) in[j] = (i >> (8 * j)) & 0xff;
			cmp_c2u(c, r, in, k);
		}
	}
	/* all 2^32 four-byte inputs, boundlen 4 */
	for (i = shard; i <= 0xffffffffULL; i += nsh) {
		unsigned char in[8] = { i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff,
					(i >> 24) & 0xff, 0xC3, 0xC3, 0xC3, 0xC3 };

		cmp_c2u(c, r, in, 4);
		if ((i & 0xffff) == 0 && fails && failfast) break;
		/* other lengths on a stride: 0, negative, 5, 6, and 1-3 with 4 real bytes present */
		if ((i % 8191) == 0) {
			cmp_c2u(c, r, in, 0); cmp_c2u(c, r, in, -1);
			cmp_c2u(c, r, in, 5); cmp_c2u(c, r, in, 6);
			cmp_c2u(c, r, in, 1); cmp_c2u(c, r, in, 2); cmp_c2u(c, r, in, 3);
		}
	}
	printf("shard %u/%u: %llu comparisons, %llu failure(s)\n", shard, nsh, checks, fails);
	return fails ? 1 : 0;
}
