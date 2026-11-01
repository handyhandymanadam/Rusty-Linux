/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * port/test/blake2s/drv.c -- differential for lib/crypto/blake2s.c, PLUS an
 * independent oracle.
 *
 * SCOPE: the portable algorithm only -- blake2s_compress_dispatch() below
 * stands in for the retained C's real dispatcher, calling the Rust's
 * rust_blake2s_compress_generic() directly, same shape as this project's
 * sha1/sha256/sha512 harnesses (logs/c-entry-rule.md's SIMD-dispatch
 * pattern). The real x86 SSSE3/AVX-512 dispatch is not exercised here;
 * b386c41's own commit message covers that verification (sabotaging the
 * Rust body and observing the interrupt-context KUnit case fail).
 *
 * Two things are checked:
 *   1. The Rust arm against BLAKE2s digests computed independently via
 *      Python's hashlib (a wholly separate implementation), covering the
 *      empty message, sub-block, exact-block, multi-block and keyed cases.
 *   2. The C arm (pristine lib/crypto/blake2s.c, renamed) against the Rust
 *      arm, across random messages/lengths/keys.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_HASH_SIZE 32

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[BLAKE2S_BLOCK_SIZE];
	unsigned int buflen;
	unsigned int outlen;
};

enum {
	IV0 = 0x6A09E667UL, IV1 = 0xBB67AE85UL, IV2 = 0x3C6EF372UL, IV3 = 0xA54FF53AUL,
	IV4 = 0x510E527FUL, IV5 = 0x9B05688CUL, IV6 = 0x1F83D9ABUL, IV7 = 0x5BE0CD19UL,
};

/* The reference init logic (include/crypto/blake2s.h's __blake2s_init()),
 * used identically to set up both arms' starting state -- not itself part
 * of what lib/crypto/blake2s.c defines or what this file differentially
 * tests; only blake2s_update()/blake2s_final() are. */
static void ref_init(struct blake2s_state *state, size_t outlen, const void *key, size_t keylen)
{
	state->h[0] = IV0 ^ (0x01010000 | (keylen << 8) | outlen);
	state->h[1] = IV1; state->h[2] = IV2; state->h[3] = IV3;
	state->h[4] = IV4; state->h[5] = IV5; state->h[6] = IV6; state->h[7] = IV7;
	state->t[0] = 0; state->t[1] = 0;
	state->f[0] = 0; state->f[1] = 0;
	state->buflen = 0;
	state->outlen = (unsigned int)outlen;
	if (keylen) {
		memcpy(state->buf, key, keylen);
		memset(state->buf + keylen, 0, BLAKE2S_BLOCK_SIZE - keylen);
		state->buflen = BLAKE2S_BLOCK_SIZE;
	}
}

/* ---- C arm (renamed) ---- */
void c_blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen);
void c_blake2s_final(struct blake2s_state *state, u8 *out);

/* ---- Rust arm ---- */
void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen);
void blake2s_final(struct blake2s_state *state, u8 *out);

/* Rust calls out to this (see blake2s_rs.rs's `extern "C"` block); stands
 * in for the retained C's real dispatcher -- see the header comment. */
void rust_blake2s_compress_generic(struct blake2s_state *state, const u8 *block,
				   size_t nblocks, u32 inc);
void blake2s_compress_dispatch(struct blake2s_state *state, const u8 *block,
			       size_t nblocks, u32 inc)
{
	rust_blake2s_compress_generic(state, block, nblocks, inc);
}

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static void cmp(const char *what, const void *a, const void *b, size_t n)
{
	cases++;
	if (poison)
		((u8 *)b)[0] ^= 0xff;
	if (memcmp(a, b, n) != 0)
		bad(what);
}

/* Independent oracle: BLAKE2s digests computed via Python's hashlib
 * (`hashlib.blake2s`), a wholly separate implementation lineage, at the
 * time this harness was written. Covers: empty, "abc", a well-known
 * pangram, exact-one-block (64), one-block-plus-one-byte (65),
 * multi-block (200), and two keyed cases. */
struct vector {
	const char *data;
	size_t datalen;
	size_t outlen;
	const u8 *key;
	size_t keylen;
	const u8 want[32];
};

static const u8 key32[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const u8 key16[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static char block64[64], block65[65], block200[200];

static const struct vector vectors[] = {
	{ "", 0, 32, NULL, 0,
	  { 0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
	    0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9 } },
	{ "abc", 3, 32, NULL, 0,
	  { 0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
	    0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82 } },
	{ "The quick brown fox jumps over the lazy dog", 43, 32, NULL, 0,
	  { 0x60, 0x6b, 0xee, 0xec, 0x74, 0x3c, 0xcb, 0xef, 0xf6, 0xcb, 0xcd, 0xf5, 0xd5, 0x30, 0x2a, 0xa8,
	    0x55, 0xc2, 0x56, 0xc2, 0x9b, 0x88, 0xc8, 0xed, 0x33, 0x1e, 0xa1, 0xa6, 0xbf, 0x3c, 0x88, 0x12 } },
	{ NULL, 64, 32, NULL, 0,
	  { 0xc1, 0x3e, 0xb2, 0x0b, 0x85, 0xb1, 0xd6, 0xa7, 0x2d, 0x52, 0xaf, 0x71, 0x74, 0x29, 0xfc, 0x54,
	    0xea, 0xcc, 0x63, 0xfe, 0xcd, 0xe1, 0x29, 0x5b, 0x26, 0xf0, 0xfa, 0x25, 0x1b, 0xdc, 0xf4, 0x0e } },
	{ NULL, 65, 32, NULL, 0,
	  { 0x77, 0xf5, 0x38, 0xc9, 0x70, 0x52, 0x1d, 0x7f, 0x5b, 0x94, 0xc5, 0xe8, 0xc8, 0x8b, 0x8c, 0xe3,
	    0x56, 0x61, 0xdf, 0xc6, 0xd6, 0x1b, 0x5b, 0xc8, 0x37, 0xda, 0x31, 0xe5, 0x43, 0xcc, 0x6b, 0x81 } },
	{ NULL, 200, 32, NULL, 0,
	  { 0x1b, 0x4e, 0x3b, 0x53, 0xc3, 0x53, 0xaa, 0x90, 0xe1, 0x48, 0xef, 0xe4, 0x69, 0x9c, 0x5f, 0x60,
	    0x66, 0x5a, 0x2c, 0xbc, 0x9a, 0xc6, 0x04, 0x41, 0xd3, 0x1d, 0x10, 0x7c, 0xa6, 0xee, 0x58, 0x6a } },
	{ "abc", 3, 32, key32, 32,
	  { 0xa2, 0x81, 0xf7, 0x25, 0x75, 0x49, 0x69, 0xa7, 0x02, 0xf6, 0xfe, 0x36, 0xfc, 0x59, 0x1b, 0x7d,
	    0xef, 0x86, 0x6e, 0x4b, 0x70, 0x17, 0x3e, 0xce, 0x40, 0x2f, 0xc0, 0x1c, 0x06, 0x4d, 0x6b, 0x65 } },
	{ NULL, 200, 16, key16, 16,
	  { 0xf3, 0xdf, 0x57, 0x52, 0x85, 0x95, 0xd7, 0x29, 0x5c, 0xe4, 0xfe, 0x4e, 0xcb, 0xc4, 0x48, 0x3e } },
};

static void run_oracle(void)
{
	memset(block64, 'x', sizeof(block64));
	memset(block65, 'x', sizeof(block65));
	memset(block200, 'x', sizeof(block200));

	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		const struct vector *v = &vectors[i];
		const char *data = v->data;
		if (!data)
			data = v->datalen == 64 ? block64 : v->datalen == 65 ? block65 : block200;

		struct blake2s_state rs;
		u8 out_r[32];

		ref_init(&rs, v->outlen, v->key, v->keylen);
		blake2s_update(&rs, (const u8 *)data, v->datalen);
		blake2s_final(&rs, out_r);
		cmp("oracle-vector", v->want, out_r, v->outlen);
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

static void run_one(unsigned long ctx, size_t len, size_t keylen, size_t outlen)
{
	unsigned seed = (unsigned)ctx * 2654435761u + 1;
	u8 *data = randbuf(len, &seed);
	u8 *key = keylen ? randbuf(keylen, &seed) : NULL;
	struct blake2s_state cs, rs;
	u8 out_c[32], out_r[32];

	ref_init(&cs, outlen, key, keylen);
	ref_init(&rs, outlen, key, keylen);
	c_blake2s_update(&cs, data, len);
	blake2s_update(&rs, data, len);
	c_blake2s_final(&cs, out_c);
	blake2s_final(&rs, out_r);
	cmp("blake2s-one-shot", out_c, out_r, outlen);

	/* Incremental, split three ways -- exercises the buflen bookkeeping
	 * this session's panic-triage pass touched (fill/inlen wrapping_sub)
	 * across call boundaries, not just within one blake2s_update() call. */
	if (len >= 3) {
		struct blake2s_state cs2, rs2;
		size_t a = len / 3, b = len / 3, c = len - a - b;

		ref_init(&cs2, outlen, key, keylen);
		ref_init(&rs2, outlen, key, keylen);
		c_blake2s_update(&cs2, data, a);
		blake2s_update(&rs2, data, a);
		c_blake2s_update(&cs2, data + a, b);
		blake2s_update(&rs2, data + a, b);
		c_blake2s_update(&cs2, data + a + b, c);
		blake2s_update(&rs2, data + a + b, c);
		c_blake2s_final(&cs2, out_c);
		blake2s_final(&rs2, out_r);
		cmp("blake2s-incremental", out_c, out_r, outlen);
	}

	free(data);
	free(key);
}

int main(void)
{
	if (getenv("BLAKE2S_PROVE_CAN_FAIL"))
		poison = 1;

	run_oracle();

	unsigned long ctx = 0;
	size_t lens[] = {0, 1, 2, 63, 64, 65, 66, 127, 128, 129, 191, 192, 193, 500};
	size_t keylens[] = {0, 1, 16, 32};
	size_t outlens[] = {1, 16, 32};

	for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++)
		for (size_t ki = 0; ki < sizeof(keylens) / sizeof(keylens[0]); ki++)
			for (size_t oi = 0; oi < sizeof(outlens) / sizeof(outlens[0]); oi++)
				run_one(ctx++, lens[li], keylens[ki], outlens[oi]);

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
