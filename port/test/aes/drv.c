/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/aes/drv.c -- differential for lib/crypto/aes.c, PLUS an
 * independent oracle.
 *
 * Two things are checked, not just the cross-arm agreement a mistranslation
 * shared by both languages could not distinguish:
 *   1. The Rust arm against known-good (key, plaintext, ciphertext) triples
 *      computed independently via Python's `cryptography` library (a
 *      different AES implementation entirely) -- catches a bug the C and
 *      Rust could conceivably agree on by both being wrong the same way.
 *   2. The C arm against the Rust arm, across random keys/messages and all
 *      three key sizes, plus encrypt(decrypt(x)) round-trips -- catches
 *      anything the fixed oracle vectors don't happen to exercise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

struct crypto_aes_ctx { u32 key_enc[60]; u32 key_dec[60]; u32 key_length; };

/* ---- C arm (renamed) ---- */
int c_aes_expandkey(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int key_len);
void c_aes_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void c_aes_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

/* ---- Rust arm ---- */
int aes_expandkey(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int key_len);
void aes_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void aes_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

/* Independent oracle: (key, plaintext, ciphertext), computed via Python's
 * cryptography library, a wholly separate AES implementation. */
struct vector {
	const u8 *key;
	unsigned int keylen;
	u8 pt[16];
	u8 ct[16];
};

static const u8 k128a[16] = { 0 };
static const u8 k128b[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
static const u8 k192a[24] = { 0 };
static const u8 k192b[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
static const u8 k256a[32] = { 0 };
static const u8 k256b[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

static const struct vector oracle[] = {
	{ k128a, 16, { 0 },
	  { 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e } },
	{ k128b, 16, { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
	  { 0x07, 0xfe, 0xef, 0x74, 0xe1, 0xd5, 0x03, 0x6e, 0x90, 0x0e, 0xee, 0x11, 0x8e, 0x94, 0x92, 0x93 } },
	{ k192a, 24, { 0 },
	  { 0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3, 0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7 } },
	{ k192b, 24, { 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73 },
	  { 0xb3, 0x97, 0x92, 0x89, 0x3c, 0xfb, 0xac, 0xf3, 0xdd, 0xfd, 0xf9, 0x3e, 0x2d, 0x4b, 0x87, 0x92 } },
	{ k256a, 32, { 0 },
	  { 0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87 } },
	{ k256b, 32, { 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 },
	  { 0xa9, 0x73, 0x87, 0x9d, 0xa7, 0x3d, 0x9a, 0x70, 0x58, 0xd6, 0x0f, 0xf2, 0x18, 0x92, 0xf7, 0xfe } },
};

static u8 *randbuf(size_t n, unsigned *seed)
{
	u8 *b = malloc(n ? n : 1);
	for (size_t i = 0; i < n; i++) {
		*seed = *seed * 1103515245u + 12345u;
		b[i] = (u8)(*seed >> 24);
	}
	return b;
}

int main(void)
{
	if (getenv("AES_PROVE_CAN_FAIL"))
		poison = 1;

	/* Part 1: Rust against the independent oracle. */
	for (size_t v = 0; v < sizeof(oracle) / sizeof(oracle[0]); v++) {
		struct crypto_aes_ctx ctx;
		u8 out[16];

		aes_expandkey(&ctx, oracle[v].key, oracle[v].keylen);
		aes_encrypt(&ctx, out, oracle[v].pt);
		cases++;
		if (poison && v == 0)
			out[0] ^= 0xff;
		if (memcmp(out, oracle[v].ct, 16) != 0)
			bad("aes_encrypt-vs-oracle");

		aes_decrypt(&ctx, out, oracle[v].ct);
		cases++;
		if (memcmp(out, oracle[v].pt, 16) != 0)
			bad("aes_decrypt-vs-oracle");
	}

	/* Part 2: C vs Rust, random keys/messages, all three key sizes,
	 * plus round-trips. */
	unsigned seed = 12345;
	unsigned int keylens[] = { 16, 24, 32 };
	for (int t = 0; t < 2000; t++) {
		unsigned int keylen = keylens[t % 3];
		u8 *key = randbuf(keylen, &seed);
		u8 *pt = randbuf(16, &seed);
		/* Zero-initialized, not left as stack garbage: AES-128/192
		 * leave trailing words of key_enc/key_dec unwritten by
		 * DESIGN (only AES-256 uses the full 60-word array), and
		 * neither arm is contracted to define them. Comparing
		 * uninitialized locals would occasionally "disagree" on
		 * bytes neither implementation wrote -- a test-harness bug,
		 * not a port one, caught by exactly this symptom: 2/8012
		 * failures, both traced to key_enc[52..] with AES-192, the
		 * one key size with unused trailing words. */
		struct crypto_aes_ctx cc = { 0 }, rc = { 0 };
		u8 ct_c[16], ct_r[16], dt_c[16], dt_r[16];

		c_aes_expandkey(&cc, key, keylen);
		aes_expandkey(&rc, key, keylen);
		cases++;
		if (memcmp(&cc, &rc, sizeof(cc)) != 0)
			bad("aes_expandkey-schedule");

		c_aes_encrypt(&cc, ct_c, pt);
		aes_encrypt(&rc, ct_r, pt);
		cases++;
		if (memcmp(ct_c, ct_r, 16) != 0)
			bad("aes_encrypt");

		c_aes_decrypt(&cc, dt_c, ct_c);
		aes_decrypt(&rc, dt_r, ct_r);
		cases++;
		if (memcmp(dt_c, dt_r, 16) != 0)
			bad("aes_decrypt");
		cases++;
		if (memcmp(dt_r, pt, 16) != 0)
			bad("aes_decrypt-roundtrip");

		free(key);
		free(pt);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
