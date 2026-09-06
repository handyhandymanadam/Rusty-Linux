/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/sha1/drv.c -- differential for lib/crypto/sha1.c.
 *
 * SCOPE: the portable algorithm only. The C arm is compiled WITHOUT
 * CONFIG_CRYPTO_LIB_SHA1_ARCH, so it takes sha1_blocks_generic() directly --
 * the same generic path the Rust arm's rust_sha1_blocks_generic()
 * implements. Neither arm exercises the real x86 static_call/SIMD dispatch.
 * CONFIG_CRYPTO_LIB_SHA1 is config-full only and CONFIG_KUNIT config-fast
 * only (findings.md #11), so lib/libtest.c's test_sha1() is this module's
 * boot-time proof caller instead -- see sha512_rs.rs's module doc for why.
 *
 * sha1_blocks_dispatch(), which the Rust calls, is provided below as a thin
 * call into rust_sha1_blocks_generic() -- there is no separate C "dispatch"
 * to stand in for in this harness.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

struct sha1_block_state { u32 h[5]; };
struct sha1_ctx { struct sha1_block_state state; u64 bytecount; u8 buf[64]; };
struct hmac_sha1_key { struct sha1_block_state istate, ostate; };
struct hmac_sha1_ctx { struct sha1_ctx sha_ctx; struct sha1_block_state ostate; };

extern void rust_sha1_blocks_generic(struct sha1_block_state *state, const u8 *data, size_t nblocks);
void sha1_blocks_dispatch(struct sha1_block_state *state, const u8 *data, size_t nblocks)
{
	rust_sha1_blocks_generic(state, data, nblocks);
}

/* ---- C arm (renamed) ---- */
void c_sha1_init_raw(u32 *buf);
void c_sha1_transform(u32 *digest, const char *data, u32 *array);
void c_sha1_init(struct sha1_ctx *ctx);
void c_sha1_update(struct sha1_ctx *ctx, const u8 *data, size_t len);
void c_sha1_final(struct sha1_ctx *ctx, u8 out[20]);
void c_sha1(const u8 *data, size_t len, u8 out[20]);
void c_hmac_sha1_preparekey(struct hmac_sha1_key *key, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha1_init(struct hmac_sha1_ctx *ctx, const struct hmac_sha1_key *key);
void c_hmac_sha1_init_usingrawkey(struct hmac_sha1_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha1_final(struct hmac_sha1_ctx *ctx, u8 out[20]);
void c_hmac_sha1(const struct hmac_sha1_key *key, const u8 *data, size_t data_len, u8 out[20]);
void c_hmac_sha1_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[20]);

/* ---- Rust arm ---- */
void sha1_init_raw(u32 *buf);
void sha1_transform(u32 *digest, const char *data, u32 *array);
void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const u8 *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, u8 out[20]);
void sha1(const u8 *data, size_t len, u8 out[20]);
void hmac_sha1_preparekey(struct hmac_sha1_key *key, const u8 *raw_key, size_t raw_key_len);
void hmac_sha1_init(struct hmac_sha1_ctx *ctx, const struct hmac_sha1_key *key);
void hmac_sha1_init_usingrawkey(struct hmac_sha1_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_sha1_final(struct hmac_sha1_ctx *ctx, u8 out[20]);
void hmac_sha1(const struct hmac_sha1_key *key, const u8 *data, size_t data_len, u8 out[20]);
void hmac_sha1_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[20]);

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
		((u8 *)b)[0] ^= 0xff;
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
	u8 out_c[20], out_r[20];

	c_sha1(data, len, out_c); sha1(data, len, out_r);
	cmp("sha1", ctx, out_c, out_r, 20);

	/* Incremental, split, to exercise partial-block/carry paths. */
	{
		struct sha1_ctx cc, rc;
		c_sha1_init(&cc); sha1_init(&rc);
		size_t split = len / 3;
		c_sha1_update(&cc, data, split);
		sha1_update(&rc, data, split);
		c_sha1_update(&cc, data + split, len - split);
		sha1_update(&rc, data + split, len - split);
		c_sha1_final(&cc, out_c); sha1_final(&rc, out_r);
		cmp("sha1-incremental", ctx, out_c, out_r, 20);
	}

	/* The legacy sha1_transform/sha1_init_raw entry points, on one block. */
	{
		u32 dig_c[5], dig_r[5];
		u32 ws_c[16], ws_r[16];
		u8 block[64];
		for (size_t i = 0; i < sizeof(block); i++)
			block[i] = (u8)(i * 7 + 3);
		c_sha1_init_raw(dig_c); sha1_init_raw(dig_r);
		cases++;
		if (memcmp(dig_c, dig_r, sizeof(dig_c)) != 0)
			bad("sha1_init_raw", ctx);
		c_sha1_transform(dig_c, (const char *)block, ws_c);
		sha1_transform(dig_r, (const char *)block, ws_r);
		cases++;
		if (memcmp(dig_c, dig_r, sizeof(dig_c)) != 0)
			bad("sha1_transform-digest", ctx);
		cases++;
		if (memcmp(ws_c, ws_r, sizeof(ws_c)) != 0)
			bad("sha1_transform-workspace", ctx);
	}

	c_hmac_sha1_usingrawkey(key, keylen, data, len, out_c);
	hmac_sha1_usingrawkey(key, keylen, data, len, out_r);
	cmp("hmac_sha1_usingrawkey", ctx, out_c, out_r, 20);

	{
		struct hmac_sha1_key ck, rk;
		c_hmac_sha1_preparekey(&ck, key, keylen);
		hmac_sha1_preparekey(&rk, key, keylen);
		c_hmac_sha1(&ck, data, len, out_c);
		hmac_sha1(&rk, data, len, out_r);
		cmp("hmac_sha1-preparekey", ctx, out_c, out_r, 20);
	}

	free(data);
	free(key);
}

int main(void)
{
	if (getenv("SHA1_PROVE_CAN_FAIL"))
		poison = 1;

	unsigned long ctx = 0;
	size_t lens[] = {0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 200, 1000};
	size_t keylens[] = {0, 1, 16, 63, 64, 65, 100, 200};

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
