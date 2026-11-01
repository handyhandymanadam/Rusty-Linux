#pragma once
/* Minimal reproduction of include/crypto/chacha.h: only what
 * lib/crypto/chacha-block-generic.c itself references. Both arms (pristine
 * C and Rust) are checked against the SAME shim, so what's compared is the
 * two ports' logic, not this header. */
#include "../linux/types.h"
#include "../linux/unaligned.h"
#include "../linux/string.h"

#define CHACHA_BLOCK_SIZE	64
#define CHACHA_STATE_WORDS	16
#define HCHACHA_OUT_WORDS	8

struct chacha_state {
	u32 x[CHACHA_STATE_WORDS];
};

void chacha_block_generic(struct chacha_state *state,
			  u8 out[CHACHA_BLOCK_SIZE], int nrounds);
void hchacha_block_generic(const struct chacha_state *state,
			   u32 out[HCHACHA_OUT_WORDS], int nrounds);

static inline void chacha_zeroize_state(struct chacha_state *state)
{
	memzero_explicit(state, sizeof(*state));
}
