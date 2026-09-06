/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/sha512/drv.c -- differential for lib/crypto/sha512.c.
 *
 * SCOPE: the portable algorithm only. The C arm is compiled WITHOUT
 * CONFIG_CRYPTO_LIB_SHA512_ARCH, so it takes sha512_blocks_generic()
 * directly -- the same generic path the Rust arm's rust_sha512_blocks_generic()
 * implements. Neither arm exercises the real x86 static_call/SIMD dispatch;
 * that lives entirely in the retained C (lib/crypto/sha512.c). Unlike
 * blake2s.c, this cannot be checked by booting with a KUnit test:
 * CONFIG_CRYPTO_LIB_SHA512 (and so CONFIG_CRYPTO_LIB_SHA512_KUNIT_TEST) only
 * exists under config-full, and CONFIG_KUNIT is deliberately kept off
 * config-full (findings.md #11 -- it moves 2,146 unrelated exported-symbol
 * CRCs). lib/libtest.c's test_sha512() is this module's boot-time proof
 * caller instead.
 *
 * sha512_blocks_dispatch(), which the Rust calls, is provided directly below
 * as a thin call into rust_sha512_blocks_generic() -- there is no separate
 * C "dispatch" to stand in for in this harness.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint64_t u64;

struct sha512_block_state { u64 h[8]; };
struct __sha512_ctx {
	struct sha512_block_state state;
	u64 bytecount_lo, bytecount_hi;
	u8 buf[128];
};
struct sha384_ctx { struct __sha512_ctx ctx; };
struct sha512_ctx { struct __sha512_ctx ctx; };
struct __hmac_sha512_key { struct sha512_block_state istate, ostate; };
struct __hmac_sha512_ctx { struct __sha512_ctx sha_ctx; struct sha512_block_state ostate; };
struct hmac_sha384_key { struct __hmac_sha512_key key; };
struct hmac_sha384_ctx { struct __hmac_sha512_ctx ctx; };
struct hmac_sha512_key { struct __hmac_sha512_key key; };
struct hmac_sha512_ctx { struct __hmac_sha512_ctx ctx; };

/* The Rust probe declares `sha512_blocks_dispatch` as `extern "C"`,
 * expecting the retained C thunk to define it (see lib/crypto/sha512.c).
 * This harness has no such thunk in the loop -- it links straight to the
 * Rust's own generic body instead, since that IS the thing under test. */
extern void rust_sha512_blocks_generic(struct sha512_block_state *state, const u8 *data, size_t nblocks);
void sha512_blocks_dispatch(struct sha512_block_state *state, const u8 *data, size_t nblocks)
{
	rust_sha512_blocks_generic(state, data, nblocks);
}

/* ---- C arm (renamed) ---- */
void c_sha384_init(struct sha384_ctx *ctx);
void c_sha512_init(struct sha512_ctx *ctx);
void c___sha512_update(struct __sha512_ctx *ctx, const u8 *data, size_t len);
void c_sha384_final(struct sha384_ctx *ctx, u8 out[48]);
void c_sha512_final(struct sha512_ctx *ctx, u8 out[64]);
void c_sha384(const u8 *data, size_t len, u8 out[48]);
void c_sha512(const u8 *data, size_t len, u8 out[64]);
void c_hmac_sha384_preparekey(struct hmac_sha384_key *key, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha512_preparekey(struct hmac_sha512_key *key, const u8 *raw_key, size_t raw_key_len);
void c___hmac_sha512_init(struct __hmac_sha512_ctx *ctx, const struct __hmac_sha512_key *key);
void c_hmac_sha384_init_usingrawkey(struct hmac_sha384_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha512_init_usingrawkey(struct hmac_sha512_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha384_final(struct hmac_sha384_ctx *ctx, u8 out[48]);
void c_hmac_sha512_final(struct hmac_sha512_ctx *ctx, u8 out[64]);
void c_hmac_sha384(const struct hmac_sha384_key *key, const u8 *data, size_t data_len, u8 out[48]);
void c_hmac_sha512(const struct hmac_sha512_key *key, const u8 *data, size_t data_len, u8 out[64]);
void c_hmac_sha384_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[48]);
void c_hmac_sha512_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[64]);

/* ---- Rust arm ---- */
void sha384_init(struct sha384_ctx *ctx);
void sha512_init(struct sha512_ctx *ctx);
void __sha512_update(struct __sha512_ctx *ctx, const u8 *data, size_t len);
void sha384_final(struct sha384_ctx *ctx, u8 out[48]);
void sha512_final(struct sha512_ctx *ctx, u8 out[64]);
void sha384(const u8 *data, size_t len, u8 out[48]);
void sha512(const u8 *data, size_t len, u8 out[64]);
void hmac_sha384_preparekey(struct hmac_sha384_key *key, const u8 *raw_key, size_t raw_key_len);
void hmac_sha512_preparekey(struct hmac_sha512_key *key, const u8 *raw_key, size_t raw_key_len);
void __hmac_sha512_init(struct __hmac_sha512_ctx *ctx, const struct __hmac_sha512_key *key);
void hmac_sha384_init_usingrawkey(struct hmac_sha384_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_sha512_init_usingrawkey(struct hmac_sha512_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_sha384_final(struct hmac_sha384_ctx *ctx, u8 out[48]);
void hmac_sha512_final(struct hmac_sha512_ctx *ctx, u8 out[64]);
void hmac_sha384(const struct hmac_sha384_key *key, const u8 *data, size_t data_len, u8 out[48]);
void hmac_sha512(const struct hmac_sha512_key *key, const u8 *data, size_t data_len, u8 out[64]);
void hmac_sha384_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[48]);
void hmac_sha512_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[64]);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what, unsigned long ctx)
{
	if (mism < 20)
		printf("MISMATCH %-24s ctx=%lu\n", what, ctx);
	mism++;
}

static void cmp(const char *what, unsigned long ctx, const u8 *a, const u8 *b, size_t n)
{
	cases++;
	if (poison && ctx == 0)
		((u8 *)b)[0] ^= 0xff; /* prove-can-fail: corrupt one Rust result */
	if (memcmp(a, b, n) != 0)
		bad(what, ctx);
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

static void run_one(unsigned long ctx, size_t len, size_t keylen)
{
	unsigned seed = (unsigned)ctx * 2654435761u + 1;
	u8 *data = randbuf(len, &seed);
	u8 *key = randbuf(keylen, &seed);
	u8 out_c[64], out_r[64];

	/* One-shot, unkeyed. */
	c_sha384(data, len, out_c); sha384(data, len, out_r);
	cmp("sha384", ctx, out_c, out_r, 48);
	c_sha512(data, len, out_c); sha512(data, len, out_r);
	cmp("sha512", ctx, out_c, out_r, 64);

	/* Incremental, two chunks, to exercise the partial-block/carry paths. */
	{
		struct sha384_ctx cc, rc;
		c_sha384_init(&cc); sha384_init(&rc);
		size_t split = len / 3;
		c___sha512_update(&cc.ctx, data, split);
		__sha512_update(&rc.ctx, data, split);
		c___sha512_update(&cc.ctx, data + split, len - split);
		__sha512_update(&rc.ctx, data + split, len - split);
		c_sha384_final(&cc, out_c); sha384_final(&rc, out_r);
		cmp("sha384-incremental", ctx, out_c, out_r, 48);
	}

	/* HMAC, using a raw key (exercises preparekey's over-length-key path
	 * whenever keylen > SHA512_BLOCK_SIZE). */
	c_hmac_sha384_usingrawkey(key, keylen, data, len, out_c);
	hmac_sha384_usingrawkey(key, keylen, data, len, out_r);
	cmp("hmac_sha384_usingrawkey", ctx, out_c, out_r, 48);

	c_hmac_sha512_usingrawkey(key, keylen, data, len, out_c);
	hmac_sha512_usingrawkey(key, keylen, data, len, out_r);
	cmp("hmac_sha512_usingrawkey", ctx, out_c, out_r, 64);

	/* HMAC via preparekey + the ordinary key-object path. */
	{
		struct hmac_sha512_key ck, rk;
		c_hmac_sha512_preparekey(&ck, key, keylen);
		hmac_sha512_preparekey(&rk, key, keylen);
		c_hmac_sha512(&ck, data, len, out_c);
		hmac_sha512(&rk, data, len, out_r);
		cmp("hmac_sha512-preparekey", ctx, out_c, out_r, 64);
	}

	free(data);
	free(key);
}

int main(void)
{
	if (getenv("SHA512_PROVE_CAN_FAIL"))
		poison = 1;

	unsigned long ctx = 0;
	size_t lens[] = {0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 256, 383, 384, 1000};
	size_t keylens[] = {0, 1, 16, 63, 64, 65, 127, 128, 129, 200};

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
