/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/sha512.c's state import/export: pristine C helpers
 * vs sha512_shash_rs.rs, on struct sha384_ctx and struct sha512_ctx (both wrap
 * struct __sha512_ctx). See run.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <crypto/sha2.h>

#define CTXSZ	sizeof(struct __sha512_ctx)	/* 208 */
#define BUFOFF	offsetof(struct __sha512_ctx, buf)	/* 80 */
#define BLK	(CTXSZ + 1 + 16)

int c_export(const struct __sha512_ctx *, void *);
int c_import(struct __sha512_ctx *, const void *);
int c_export_core(const struct __sha512_ctx *, void *);
int c_import_core(struct __sha512_ctx *, const void *);
int crypto_sha512_rs_export(const struct __sha512_ctx *, void *);
int crypto_sha512_rs_import(struct __sha512_ctx *, const void *);
int crypto_sha512_rs_export_core(const struct __sha512_ctx *, void *);
int crypto_sha512_rs_import_core(struct __sha512_ctx *, const void *);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static void fill(void *p, size_t n) { unsigned char *b = p; while (n--) *b++ = (unsigned char)rnd(); }

static unsigned long long checks, fails;
static int poison_hook(int x) { (void)x; return getenv("SHA512S_PROVE_CAN_FAIL") != NULL; }
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

static const uint64_t bc_edge[] = { 0, 1, 63, 64, 65, 127, 128, 255, 256, 0xffffffffULL,
	0x100000000ULL, 0xffffffffffffff80ULL, 0xffffffffffffff7fULL, 127, 129, 191, 192, 0xffffffffffffffffULL,
	0xffffffffffffff00ULL, 0xfffffffffffffeffULL, 0x8000000000000000ULL };

/* ctx is the __sha512_ctx inside a sha384_ctx (kind 0) or sha512_ctx (kind 1) */
static void one(uint64_t bc, int kind)
{
	struct sha384_ctx a224, ra224, rb224;
	struct sha512_ctx a256, ra256, rb256;
	struct __sha512_ctx *a = kind ? &a256.ctx : &a224.ctx;
	struct __sha512_ctx *ra = kind ? &ra256.ctx : &ra224.ctx;
	struct __sha512_ctx *rb = kind ? &rb256.ctx : &rb224.ctx;
	unsigned char oc[BLK + 16], or_[BLK + 16], in[BLK + 16];
	int off = (int)(rnd() & 7), j;
	unsigned char *pc = oc + 8 + off, *pr = or_ + 8 + off, *pin = in + 8 + off;
	int rc, rr;

	fill(a, CTXSZ);
	a->bytecount_lo = bc;
	/* export: unaligned output, poisoned around */
	memset(oc, 0xA5, sizeof oc); memset(or_, 0xA5, sizeof or_);
	rc = c_export(a, pc);
	rr = crypto_sha512_rs_export(a, pr);
	if (poison_hook(0)) oc[0]++;
	checks++;
	if (rc != rr || memcmp(oc, or_, sizeof oc)) FAIL("export MISMATCH bc=%#llx kind=%d\n", (unsigned long long)bc, kind);
	/* import: the exported blob, plus random blobs with an arbitrary trailing byte */
	for (j = 0; j < 3; j++) {
		if (j == 2) { fill(in, sizeof in); memcpy(pin + 64, &bc, 8); pin[CTXSZ] = (unsigned char)(0xff - (rnd() & 3)); }
		else if (j == 0) { memset(in, 0xA5, sizeof in); memcpy(pin, pc, CTXSZ + 1); }
		else { fill(in, sizeof in); }
		fill(ra, CTXSZ); memcpy(rb, ra, CTXSZ);
		rc = c_import(ra, pin); rr = crypto_sha512_rs_import(rb, pin);
		checks++;
		if (rc != rr || memcmp(ra, rb, CTXSZ)) FAIL("import MISMATCH bc=%#llx j=%d kind=%d\n", (unsigned long long)bc, j, kind);
	}
	/* round trip (Rust export -> Rust import): restores bytecount and everything */
	memset(rb, 0, CTXSZ);
	crypto_sha512_rs_import(rb, pr);
	checks++;
	if (memcmp(rb, a, CTXSZ)) FAIL("round trip differs bc=%#llx kind=%d\n", (unsigned long long)bc, kind);
	/* cross: C export -> Rust import and Rust export -> C import */
	memset(rb, 0, CTXSZ); crypto_sha512_rs_import(rb, pc);
	memset(ra, 0, CTXSZ); c_import(ra, pr);
	checks++;
	if (memcmp(rb, a, CTXSZ) || memcmp(ra, a, CTXSZ)) FAIL("cross round trip differs bc=%#llx\n", (unsigned long long)bc);
	/* the exported blob's bytecount_lo is block-aligned and the last byte is bc % 128 */
	{
		uint64_t ebc; memcpy(&ebc, pr + 64, 8);
		checks++;
		if ((ebc & 127) || pr[CTXSZ] != (bc & 127) || ebc + pr[CTXSZ] != bc) FAIL("export format bc=%#llx\n", (unsigned long long)bc);
	}
	/* core variants */
	memset(oc, 0xA5, sizeof oc); memset(or_, 0xA5, sizeof or_);
	rc = c_export_core(a, pc); rr = crypto_sha512_rs_export_core(a, pr);
	checks++;
	if (rc != rr || memcmp(oc, or_, sizeof oc) || memcmp(pr, a, BUFOFF)) FAIL("export_core MISMATCH\n");
	fill(in, sizeof in);
	fill(ra, CTXSZ); memcpy(rb, ra, CTXSZ);
	rc = c_import_core(ra, pin); rr = crypto_sha512_rs_import_core(rb, pin);
	checks++;
	if (rc != rr || memcmp(ra, rb, CTXSZ) || memcmp(rb, pin, BUFOFF)) FAIL("import_core MISMATCH\n");
}

int main(int argc, char **argv)
{
	unsigned long long n = argc > 1 ? strtoull(argv[1], 0, 0) : 1000000, i;
	unsigned e, x;

	if (CTXSZ != 208 || BUFOFF != 80 || offsetof(struct __sha512_ctx, bytecount_lo) != 64 ||
	    offsetof(struct __sha512_ctx, bytecount_hi) != 72 ||
	    sizeof(struct sha384_ctx) != 208 || sizeof(struct sha512_ctx) != 208) FAIL("shim layout differs\n");
	/* every edge bytecount +- every partial remainder, both ctx types, then random */
	for (e = 0; e < sizeof bc_edge / sizeof *bc_edge; e++)
		for (x = 0; x < 256; x++) {
			one(bc_edge[e] + x, 0), one(bc_edge[e] - x, 1);
			one(bc_edge[e] + x, 1), one(bc_edge[e] - x, 0);
		}
	for (i = 0; i < n; i++)
		one((i & 1) ? rnd() : (rnd() & ~127ULL) + (rnd() & 127), (int)(i >> 1 & 1));
	printf("sha512_shash: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
