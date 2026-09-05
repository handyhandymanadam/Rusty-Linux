// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The "hash function" used as the core of the ChaCha stream cipher (RFC7539)
 *
 * Copyright (C) 2015 Martin Willi
 *
 * PORTED TO RUST. The permutation and both bodies are
 * lib/crypto/chacha_block_generic_rs.rs. What is left here is the two C
 * entry symbols, their EXPORT_SYMBOL() lines, the round-count WARN, and the
 * zeroization.
 *
 * THE ZEROIZATION STAYS IN C. chacha_zeroize_state() is memzero_explicit(),
 * whose entire purpose is to survive an optimiser that can prove the write
 * is dead. Rust has write_volatile, but reimplementing the barrier there
 * would be asserting something about codegen rather than relying on the
 * guarantee the kernel already provides. The Rust calls back down for it.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 */

#include <crypto/chacha.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/types.h>

/* lib/crypto/chacha_block_generic_rs.rs */
void rust_chacha_block_generic(struct chacha_state *state, u8 *out, int nrounds);
void rust_hchacha_block_generic(const struct chacha_state *state, u32 *out, int nrounds);

/* Called from lib/crypto/chacha_block_generic_rs.rs. */
void rust_chacha_zeroize_state(struct chacha_state *state);
void rust_chacha_zeroize_state(struct chacha_state *state)
{
	chacha_zeroize_state(state);
}

/**
 * chacha_block_generic - generate one keystream block and increment block counter
 * @state: input state matrix
 * @out: output keystream block
 * @nrounds: number of rounds (20 or 12; 20 is recommended)
 *
 * This is the ChaCha core, a function from 64-byte strings to 64-byte strings.
 * The caller has already converted the endianness of the input.  This function
 * also handles incrementing the block counter in the input matrix.
 */
void chacha_block_generic(struct chacha_state *state,
			  u8 out[CHACHA_BLOCK_SIZE], int nrounds)
{
	/* whitelist the allowed round counts */
	WARN_ON_ONCE(nrounds != 20 && nrounds != 12);

	rust_chacha_block_generic(state, out, nrounds);
}
EXPORT_SYMBOL(chacha_block_generic);

/**
 * hchacha_block_generic - abbreviated ChaCha core, for XChaCha
 * @state: input state matrix
 * @out: the output words
 * @nrounds: number of rounds (20 or 12; 20 is recommended)
 *
 * HChaCha is the ChaCha equivalent of HSalsa and is an intermediate step
 * towards XChaCha (see https://cr.yp.to/snuffle/xsalsa-20081128.pdf).  HChaCha
 * skips the final addition of the initial state, and outputs only certain words
 * of the state.  It should not be used for streaming directly.
 */
void hchacha_block_generic(const struct chacha_state *state,
			   u32 out[HCHACHA_OUT_WORDS], int nrounds)
{
	WARN_ON_ONCE(nrounds != 20 && nrounds != 12);

	rust_hchacha_block_generic(state, out, nrounds);
}
EXPORT_SYMBOL(hchacha_block_generic);
