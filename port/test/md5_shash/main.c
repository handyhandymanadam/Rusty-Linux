/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/md5.c's state import/export + md5_zero_message_hash:
 * pristine C helpers vs md5_shash_rs.rs. See run.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <crypto/md5.h>

int c_export(const struct md5_ctx *, void *);
int c_import(struct md5_ctx *, const void *);
int c_export_core(const struct md5_ctx *, void *);
int c_import_core(struct md5_ctx *, const void *);
int crypto_md5_rs_export(const struct md5_ctx *, void *);
int crypto_md5_rs_import(struct md5_ctx *, const void *);
int crypto_md5_rs_export_core(const struct md5_ctx *, void *);
int crypto_md5_rs_import_core(struct md5_ctx *, const void *);
extern const u8 md5_zero_message_hash[MD5_DIGEST_SIZE];     /* Rust */
extern const u8 c_md5_zero_message_hash[MD5_DIGEST_SIZE];   /* pristine C */

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static void fill(void *p, size_t n) { unsigned char *b = p; while (n--) *b++ = (unsigned char)rnd(); }

static unsigned long long checks, fails;
static int poison_hook(int x) { (void)x; return getenv("MD5S_PROVE_CAN_FAIL") != NULL; }
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

static const uint64_t bc_edge[] = { 0, 1, 63, 64, 65, 127, 128, 255, 256, 0xffffffffULL,
	0x100000000ULL, 0xffffffffffffffc0ULL, 0xffffffffffffffbfULL, 0xffffffffffffffffULL,
	0xffffffffffffff00ULL, 0xfffffffffffffeffULL, 0x8000000000000000ULL };

static void one(uint64_t bc)
{
	struct md5_ctx a, ra, rb;
	unsigned char oc[96 + 16], or_[96 + 16], in[96 + 16];
	int off = (int)(rnd() & 7), j;
	unsigned char *pc = oc + 8 + off, *pr = or_ + 8 + off, *pin = in + 8 + off;
	int rc, rr;

	fill(&a, sizeof a);
	a.bytecount = bc;
	/* export: unaligned output, poisoned around */
	memset(oc, 0xA5, sizeof oc); memset(or_, 0xA5, sizeof or_);
	rc = c_export(&a, pc);
	rr = crypto_md5_rs_export(&a, pr);
	if (poison_hook(0)) oc[0]++;
	checks++;
	if (rc != rr || memcmp(oc, or_, sizeof oc)) FAIL("export MISMATCH bc=%#llx\n", (unsigned long long)bc);
	/* import: the exported blob, plus a random blob with an arbitrary trailing byte */
	for (j = 0; j < 3; j++) {
		if (j == 2) { fill(in, sizeof in); memcpy(pin + 16, &bc, 8); pin[88] = (unsigned char)(0xff - (rnd() & 3)); }
		else if (j == 0) { memset(in, 0xA5, sizeof in); memcpy(pin, pc, 89); }
		else { fill(in, sizeof in); }
		fill(&ra, sizeof ra); memcpy(&rb, &ra, sizeof ra);
		rc = c_import(&ra, pin); rr = crypto_md5_rs_import(&rb, pin);
		checks++;
		if (rc != rr || memcmp(&ra, &rb, sizeof ra)) FAIL("import MISMATCH bc=%#llx j=%d\n", (unsigned long long)bc, j);
	}
	/* round trip: import(export(c)) restores bytecount and everything */
	memset(&rb, 0, sizeof rb);
	crypto_md5_rs_import(&rb, pc);
	checks++;
	if (memcmp(&rb, &a, sizeof a)) FAIL("round trip differs bc=%#llx\n", (unsigned long long)bc);
	/* core variants */
	memset(oc, 0xA5, sizeof oc); memset(or_, 0xA5, sizeof or_);
	rc = c_export_core(&a, pc); rr = crypto_md5_rs_export_core(&a, pr);
	checks++;
	if (rc != rr || memcmp(oc, or_, sizeof oc)) FAIL("export_core MISMATCH\n");
	fill(in, sizeof in);
	fill(&ra, sizeof ra); memcpy(&rb, &ra, sizeof ra);
	rc = c_import_core(&ra, pin); rr = crypto_md5_rs_import_core(&rb, pin);
	checks++;
	if (rc != rr || memcmp(&ra, &rb, sizeof ra)) FAIL("import_core MISMATCH\n");
}

int main(int argc, char **argv)
{
	unsigned long long n = argc > 1 ? strtoull(argv[1], 0, 0) : 2000000, i;
	static const unsigned char want[16] = { 0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
		0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e };	/* md5(b"") per hashlib / RFC 1321 */
	unsigned e, x;

	if (memcmp(md5_zero_message_hash, c_md5_zero_message_hash, 16) ||
	    memcmp(md5_zero_message_hash, want, 16)) FAIL("md5_zero_message_hash differs\n");
	checks++;
	/* every edge bytecount x every partial remainder, then random */
	for (e = 0; e < sizeof bc_edge / sizeof *bc_edge; e++)
		for (x = 0; x < 256; x++)
			one(bc_edge[e] + x), one(bc_edge[e] - x);
	/* import wrap: every trailing byte value onto edge bytecounts, both arms */
	for (i = 0; i < n; i++)
		one((i & 1) ? rnd() : (rnd() & ~63ULL) + (rnd() & 63));
	printf("md5_shash: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
