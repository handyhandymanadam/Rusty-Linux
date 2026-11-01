/* SPDX-License-Identifier: GPL-2.0 */
/* Exhaustive differential for fs/nls/nls_{ascii,iso8859-1,cp437}.c: pristine C
 * (ref.c, the unmodified file) vs the Rust nls_<cs>_rs.rs through the SAME
 * struct nls_table function pointers the kernel uses.
 *
 *  uni2char : all 65536 wchar_t x boundlen -2..8: return value, output byte,
 *             and the 15 bytes around it (canaries untouched)
 *  char2uni : all 256 bytes x boundlen -1,0,1,2,8: return value + out wchar_t
 *             (pre-set to a poison so "not written" is compared too); bytes
 *             after the first are poison (the C reads exactly one)
 *  tables   : charset/alias/owner/next, charset2lower[256], charset2upper[256]
 *  Rust arm: table symbol RS_SYM. NLS_PROVE_CAN_FAIL=1 poisons the Rust result.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/init.h>
#include <linux/nls.h>
#undef wchar_t
#define wchar_t knls_wchar_t

struct nls_table *ref_table(void);
extern struct nls_table RS_SYM;

static unsigned long long fails, checks;
static int poison;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

int main(void)
{
	struct nls_table *c = ref_table(), *r = &RS_SYM;
	unsigned uni; int bl, j;

	poison = getenv("NLS_PROVE_CAN_FAIL") != NULL;
	if (!c->charset || !r->charset || strcmp(c->charset, r->charset)) FAIL("charset differs\n");
	if (c->alias != r->alias) FAIL("alias differs\n");
	if (c->owner != r->owner) FAIL("owner differs\n");
	if (c->next != r->next) FAIL("next differs\n");
	if (!r->uni2char || !r->char2uni || !r->charset2lower || !r->charset2upper) FAIL("null member\n");
	for (j = 0; j < 256; j++) {
		if (c->charset2lower[j] != r->charset2lower[j]) FAIL("lower[%d] c=%02x rust=%02x\n", j, c->charset2lower[j], r->charset2lower[j]);
		if (c->charset2upper[j] != r->charset2upper[j]) FAIL("upper[%d] c=%02x rust=%02x\n", j, c->charset2upper[j], r->charset2upper[j]);
		checks += 2;
	}
	checks += 4;

	for (uni = 0; uni <= 0xffff; uni++)
		for (bl = -2; bl <= 8; bl++) {
			unsigned char a[16], b[16];
			int ra, rb;

			memset(a, 0xA5, sizeof a); memset(b, 0xA5, sizeof b);
			ra = c->uni2char((wchar_t)uni, a + 4, bl);
			rb = r->uni2char((wchar_t)uni, b + 4, bl);
			if (poison && uni == 0x41 && bl == 4) rb++;
			checks++;
			if (ra != rb || memcmp(a, b, sizeof a))
				FAIL("uni2char MISMATCH uni=%#x bl=%d c=%d/%02x rust=%d/%02x\n", uni, bl, ra, a[4], rb, b[4]);
		}

	for (j = 0; j < 256; j++) {
		static const int bls[] = { -1, 0, 1, 2, 8 };
		unsigned k;

		for (k = 0; k < sizeof bls / sizeof *bls; k++) {
			unsigned char in[4] = { (unsigned char)j, 0xC3, 0xC3, 0xC3 };
			wchar_t ua = 0xBEEF, ub = 0xBEEF;
			int ra = c->char2uni(in, bls[k], &ua);
			int rb = r->char2uni(in, bls[k], &ub);

			checks++;
			if (ra != rb || ua != ub)
				FAIL("char2uni MISMATCH byte=%02x bl=%d c=%d/%#x rust=%d/%#x\n", j, bls[k], ra, ua, rb, ub);
		}
	}
	printf("%llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
