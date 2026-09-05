/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_CRYPTO_CHACHA_H
#define _SHIM_CRYPTO_CHACHA_H
#include <linux/types.h>
#include <string.h>
#define CHACHA_STATE_WORDS 16
#define CHACHA_BLOCK_SIZE 64
#define HCHACHA_OUT_WORDS 8
struct chacha_state { u32 x[CHACHA_STATE_WORDS]; };
static inline void chacha_zeroize_state(struct chacha_state *s)
{
	memset(s, 0, sizeof(*s));
}
void chacha_block_generic(struct chacha_state *state, u8 *out, int nrounds);
void hchacha_block_generic(const struct chacha_state *state, u32 *out, int nrounds);
#endif
