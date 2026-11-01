/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * port/test/chacha_block_generic/drv.c -- differential for
 * lib/crypto/chacha-block-generic.c, PLUS an independent oracle.
 *
 * This file is the "blake2s shape" (logs/c-entry-rule.md): the retained C
 * (port/tree/lib/crypto/chacha-block-generic.c) keeps the two real public
 * entry points and their WARN_ON_ONCE, dispatching to the Rust's
 * `rust_`-prefixed core. Following the same pattern this project's other
 * SIMD-dispatch-shaped harnesses (sha1/sha256/sha512) already use: this
 * driver stands in for the retained C's dispatcher itself, calling the
 * Rust's rust_chacha_block_generic()/rust_hchacha_block_generic() directly
 * -- what's being tested is the ALGORITHM, not the trivial dispatch glue,
 * which is a couple of lines already covered by every real boot.
 *
 * Two things are checked:
 *   1. The Rust arm against RFC 7539 section 2.3.2's published ChaCha20
 *      block-function test vector -- independent of this codebase and
 *      this project, predating both.
 *   2. The C arm (pristine lib/crypto/chacha-block-generic.c, renamed)
 *      against the Rust arm, across random states and both round counts
 *      (12 and 20).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define CHACHA_STATE_WORDS 16
#define CHACHA_BLOCK_SIZE 64
#define HCHACHA_OUT_WORDS 8

struct chacha_state { u32 x[CHACHA_STATE_WORDS]; };

/* ---- C arm (renamed) ---- */
void c_chacha_block_generic(struct chacha_state *state, u8 out[CHACHA_BLOCK_SIZE], int nrounds);
void c_hchacha_block_generic(const struct chacha_state *state, u32 out[HCHACHA_OUT_WORDS], int nrounds);

/* ---- Rust arm: the core the retained C's real dispatcher calls, called
 * directly here rather than through that dispatcher -- see the header
 * comment. ---- */
void rust_chacha_block_generic(struct chacha_state *state, u8 *out, int nrounds);
void rust_hchacha_block_generic(const struct chacha_state *state, u32 *out, int nrounds);

/* The Rust calls back into this for zeroization (module doc: "Zeroization
 * stays in C"). A plain memset is sufficient for a correctness harness --
 * the volatile-write security property it exists for in the real kernel is
 * not what this file is checking. */
void rust_chacha_zeroize_state(struct chacha_state *state)
{
	memset(state, 0, sizeof(*state));
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

/* Independent oracle: RFC 7539 section 2.3.2's ChaCha20 block function test
 * vector -- key = 0x00..0x1f, nonce = {0x00000009, 0x4a000000, 0x00000000}
 * (RFC's own field order), block counter = 1. Published well before this
 * project; a wholly separate lineage from this codebase. */
static void run_oracle(void)
{
	struct chacha_state state = { .x = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000,
	} };
	static const u8 want[CHACHA_BLOCK_SIZE] = {
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
		0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
		0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
		0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
		0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
	};
	u8 out[CHACHA_BLOCK_SIZE];

	rust_chacha_block_generic(&state, out, 20);
	cmp("oracle-rfc7539-block", want, out, CHACHA_BLOCK_SIZE);
}

static void randomize_state(struct chacha_state *s, unsigned *seed)
{
	for (int i = 0; i < CHACHA_STATE_WORDS; i++) {
		*seed = *seed * 1103515245u + 12345u;
		s->x[i] = *seed;
	}
}

static void run_one(unsigned long ctx, int nrounds)
{
	unsigned seed = (unsigned)ctx * 2654435761u + 1;
	struct chacha_state cs, rs;

	randomize_state(&cs, &seed);
	rs = cs;

	u8 out_c[CHACHA_BLOCK_SIZE], out_r[CHACHA_BLOCK_SIZE];
	c_chacha_block_generic(&cs, out_c, nrounds);
	rust_chacha_block_generic(&rs, out_r, nrounds);
	cmp("chacha_block_generic-out", out_c, out_r, CHACHA_BLOCK_SIZE);
	/* The block counter increment (state.x[12]++) is observable state,
	 * not just the keystream -- compare the whole state, not only the
	 * output block. */
	cmp("chacha_block_generic-state", &cs, &rs, sizeof(cs));

	u32 hout_c[HCHACHA_OUT_WORDS], hout_r[HCHACHA_OUT_WORDS];
	c_hchacha_block_generic(&cs, hout_c, nrounds);
	rust_hchacha_block_generic(&rs, hout_r, nrounds);
	cmp("hchacha_block_generic", hout_c, hout_r, sizeof(hout_c));
}

int main(void)
{
	if (getenv("CHACHA_PROVE_CAN_FAIL"))
		poison = 1;

	run_oracle();

	unsigned long ctx = 0;
	int rounds[] = {20, 12};
	for (size_t ri = 0; ri < sizeof(rounds) / sizeof(rounds[0]); ri++)
		for (unsigned long i = 0; i < 500; i++)
			run_one(ctx++, rounds[ri]);

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
