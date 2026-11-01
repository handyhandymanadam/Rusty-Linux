/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * port/test/arc4/drv.c -- differential for lib/crypto/arc4.c, PLUS an
 * independent oracle.
 *
 * Two things are checked:
 *   1. The Rust arm against well-known RC4 test vectors (key, plaintext,
 *      ciphertext) that predate this project and this codebase entirely --
 *      catches a bug the C and Rust could conceivably agree on by both
 *      being wrong the same way.
 *   2. The C arm against the Rust arm, across random keys/messages and
 *      lengths, including the empty message and single-byte key/message
 *      edges, plus a chained multi-call encrypt/decrypt sequence (arc4 is
 *      a stream cipher: state carries across calls, which is exactly what
 *      this session's panic-triage pass touched -- ctx.x/ctx.y bookkeeping
 *      between calls).
 *
 * NOT covered here: the deliberately-checked-not-wrapped bounds panic in
 * arc4_crypt() (see arc4_rs.rs's module doc) for a ctx.x/ctx.y corrupted
 * outside 0..=255 without going through arc4_setkey() first. That is a
 * caller-contract violation the C has the identical UB for; there is no
 * "correct" C answer to differential-test against for that case, only a
 * panic to prove happens (which a normal differential harness, run to
 * completion and compared, is the wrong shape for -- proving a panic needs
 * a subprocess/signal harness, more machinery than this file's job).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

struct arc4_ctx { u32 S[256]; u32 x, y; };

/* ---- C arm (renamed) ---- */
int c_arc4_setkey(struct arc4_ctx *ctx, const u8 *in_key, unsigned int key_len);
void c_arc4_crypt(struct arc4_ctx *ctx, u8 *out, const u8 *in, unsigned int len);

/* ---- Rust arm ---- */
int arc4_setkey(struct arc4_ctx *ctx, const u8 *in_key, unsigned int key_len);
void arc4_crypt(struct arc4_ctx *ctx, u8 *out, const u8 *in, unsigned int len);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static void cmp(const char *what, const u8 *a, const u8 *b, size_t n)
{
	cases++;
	if (poison)
		((u8 *)b)[0] ^= 0xff;
	if (n && memcmp(a, b, n) != 0)
		bad(what);
}

/* Independent oracle: (key, plaintext, ciphertext) -- the standard RC4 test
 * vectors, published long before this project (e.g. the "RC4" Wikipedia
 * article's worked examples), a wholly separate implementation lineage. */
struct vector {
	const char *key;
	const char *plaintext;
	const u8 ct[16];
	size_t ct_len;
};

static const struct vector vectors[] = {
	{ "Key", "Plaintext",
	  { 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 }, 9 },
	{ "Wiki", "pedia",
	  { 0x10, 0x21, 0xBF, 0x04, 0x20 }, 5 },
	{ "Secret", "Attack at dawn",
	  { 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52,
	    0x54, 0x4B, 0x9B, 0xF5 }, 14 },
};

static void run_oracle(void)
{
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		const struct vector *v = &vectors[i];
		struct arc4_ctx rc;
		u8 out_r[16];

		arc4_setkey(&rc, (const u8 *)v->key, (unsigned int)strlen(v->key));
		arc4_crypt(&rc, out_r, (const u8 *)v->plaintext, (unsigned int)v->ct_len);
		cmp("oracle-vector", v->ct, out_r, v->ct_len);
	}
}

static u8 *randbuf(size_t n, unsigned *seed)
{
	u8 *b = malloc(n ? n : 1);
	for (size_t i = 0; i < n; i++) {
		*seed = *seed * 1103515245u + 12345u;
		b[i] = (u8)(*seed >> 24);
	}
	return b;
}

static void run_one(unsigned long ctx_id, size_t len, size_t keylen)
{
	unsigned seed = (unsigned)ctx_id * 2654435761u + 1;
	u8 *key = randbuf(keylen ? keylen : 1, &seed);
	u8 *data = randbuf(len, &seed);
	u8 *out_c = malloc(len ? len : 1);
	u8 *out_r = malloc(len ? len : 1);
	struct arc4_ctx cc, rc;

	c_arc4_setkey(&cc, key, (unsigned int)keylen);
	arc4_setkey(&rc, key, (unsigned int)keylen);
	c_arc4_crypt(&cc, out_c, data, (unsigned int)len);
	arc4_crypt(&rc, out_r, data, (unsigned int)len);
	cmp("arc4_crypt-one-shot", out_c, out_r, len);

	/* Stream-cipher chaining: split the same message across several
	 * arc4_crypt() calls on the same key/context and confirm both arms
	 * still agree byte-for-byte -- this exercises the ctx.x/ctx.y
	 * bookkeeping between calls that this session's wrapping_add fixes
	 * touched, not just a single call's internal loop. */
	if (len >= 3) {
		struct arc4_ctx cc2, rc2;
		size_t a = len / 3, b = len / 3;
		size_t c = len - a - b;

		c_arc4_setkey(&cc2, key, (unsigned int)keylen);
		arc4_setkey(&rc2, key, (unsigned int)keylen);

		c_arc4_crypt(&cc2, out_c, data, (unsigned int)a);
		arc4_crypt(&rc2, out_r, data, (unsigned int)a);
		c_arc4_crypt(&cc2, out_c + a, data + a, (unsigned int)b);
		arc4_crypt(&rc2, out_r + a, data + a, (unsigned int)b);
		c_arc4_crypt(&cc2, out_c + a + b, data + a + b, (unsigned int)c);
		arc4_crypt(&rc2, out_r + a + b, data + a + b, (unsigned int)c);
		cmp("arc4_crypt-chained", out_c, out_r, len);
	}

	/* In-place, both arms: out aliases in, which arc4_crypt's own
	 * contract explicitly permits. */
	{
		u8 *buf_c = malloc(len ? len : 1);
		u8 *buf_r = malloc(len ? len : 1);
		struct arc4_ctx cc3, rc3;

		memcpy(buf_c, data, len);
		memcpy(buf_r, data, len);
		c_arc4_setkey(&cc3, key, (unsigned int)keylen);
		arc4_setkey(&rc3, key, (unsigned int)keylen);
		c_arc4_crypt(&cc3, buf_c, buf_c, (unsigned int)len);
		arc4_crypt(&rc3, buf_r, buf_r, (unsigned int)len);
		cmp("arc4_crypt-in-place", buf_c, buf_r, len);
		free(buf_c);
		free(buf_r);
	}

	free(key);
	free(data);
	free(out_c);
	free(out_r);
}

int main(void)
{
	if (getenv("ARC4_PROVE_CAN_FAIL"))
		poison = 1;

	run_oracle();

	unsigned long ctx = 0;
	size_t lens[] = {0, 1, 2, 3, 4, 15, 16, 17, 255, 256, 257, 1000};
	size_t keylens[] = {1, 2, 5, 16, 32, 100, 256};

	for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++)
		for (size_t ki = 0; ki < sizeof(keylens) / sizeof(keylens[0]); ki++)
			run_one(ctx++, lens[li], keylens[ki]);

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
