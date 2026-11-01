#pragma once
/* Minimal reproduction of include/crypto/blake2s.h: only what
 * lib/crypto/blake2s.c itself references. Both arms (pristine C and Rust)
 * are checked against the SAME shim, so what's compared is the two ports'
 * logic, not this header. No CONFIG_CRYPTO_LIB_BLAKE2S_ARCH here -- the
 * pristine C arm takes the #else arm (blake2s_compress ==
 * blake2s_compress_generic) directly, same as the real kernel does
 * whenever SIMD is unavailable (module doc: "the generic compression is
 * REACHED on x86-64, not just on the fallback architectures"). */
#include "../linux/types.h"
#include "../linux/string.h"

enum blake2s_lengths {
	BLAKE2S_BLOCK_SIZE = 64,
	BLAKE2S_HASH_SIZE = 32,
	BLAKE2S_KEY_SIZE = 32,
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[BLAKE2S_BLOCK_SIZE];
	unsigned int buflen;
	unsigned int outlen;
};

enum blake2s_iv {
	BLAKE2S_IV0 = 0x6A09E667UL,
	BLAKE2S_IV1 = 0xBB67AE85UL,
	BLAKE2S_IV2 = 0x3C6EF372UL,
	BLAKE2S_IV3 = 0xA54FF53AUL,
	BLAKE2S_IV4 = 0x510E527FUL,
	BLAKE2S_IV5 = 0x9B05688CUL,
	BLAKE2S_IV6 = 0x1F83D9ABUL,
	BLAKE2S_IV7 = 0x5BE0CD19UL,
};

static inline void __blake2s_init(struct blake2s_state *state, size_t outlen,
				  const void *key, size_t keylen)
{
	state->h[0] = BLAKE2S_IV0 ^ (0x01010000 | keylen << 8 | outlen);
	state->h[1] = BLAKE2S_IV1;
	state->h[2] = BLAKE2S_IV2;
	state->h[3] = BLAKE2S_IV3;
	state->h[4] = BLAKE2S_IV4;
	state->h[5] = BLAKE2S_IV5;
	state->h[6] = BLAKE2S_IV6;
	state->h[7] = BLAKE2S_IV7;
	state->t[0] = 0;
	state->t[1] = 0;
	state->f[0] = 0;
	state->f[1] = 0;
	state->buflen = 0;
	state->outlen = outlen;
	if (keylen) {
		memcpy(state->buf, key, keylen);
		memset(&state->buf[keylen], 0, BLAKE2S_BLOCK_SIZE - keylen);
		state->buflen = BLAKE2S_BLOCK_SIZE;
	}
}

static inline void blake2s_init(struct blake2s_state *state, size_t outlen)
{
	__blake2s_init(state, outlen, NULL, 0);
}

static inline void blake2s_init_key(struct blake2s_state *state, size_t outlen,
				    const void *key, size_t keylen)
{
	__blake2s_init(state, outlen, key, keylen);
}

void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen);
void blake2s_final(struct blake2s_state *state, u8 *out);

static inline void blake2s(u8 *out, const u8 *in, const u8 *key,
			   size_t outlen, size_t inlen, size_t keylen)
{
	struct blake2s_state state;

	__blake2s_init(&state, outlen, key, keylen);
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, out);
}
