/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/sha256/drv.c -- differential for lib/crypto/sha256.c.
 *
 * SCOPE: the portable algorithm only. The C arm is compiled WITHOUT
 * CONFIG_CRYPTO_LIB_SHA256_ARCH, so it takes sha256_blocks_generic()
 * directly, and sha256_finup_2x_arch()'s #ifndef fallback (always false --
 * meaning the sequential path is what's compared). Neither arm exercises
 * the real x86 static_call/static_branch dispatch; upstream's own
 * sha256_kunit (CONFIG_CRYPTO_LIB_SHA256_KUNIT_TEST, config-fast, real
 * boot) covers that, including sha256_finup_2x specifically -- see this
 * port's commit message for the boot results.
 *
 * sha256_blocks_dispatch()/sha256_finup_2x_dispatch()/
 * sha256_finup_2x_is_optimized_dispatch(), which the Rust calls, are
 * provided below as thin calls into the Rust's own generic bodies and a
 * fixed "not optimized" answer -- there is no separate C "dispatch" to
 * stand in for in this harness.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

struct sha256_block_state { u32 h[8]; };
struct __sha256_ctx { struct sha256_block_state state; u64 bytecount; u8 buf[64]; };
struct sha224_ctx { struct __sha256_ctx ctx; };
struct sha256_ctx { struct __sha256_ctx ctx; };
struct __hmac_sha256_key { struct sha256_block_state istate, ostate; };
struct __hmac_sha256_ctx { struct __sha256_ctx sha_ctx; struct sha256_block_state ostate; };
struct hmac_sha224_key { struct __hmac_sha256_key key; };
struct hmac_sha224_ctx { struct __hmac_sha256_ctx ctx; };
struct hmac_sha256_key { struct __hmac_sha256_key key; };
struct hmac_sha256_ctx { struct __hmac_sha256_ctx ctx; };

extern void rust_sha256_blocks_generic(struct sha256_block_state *state, const u8 *data, size_t nblocks);
void sha256_blocks_dispatch(struct sha256_block_state *state, const u8 *data, size_t nblocks)
{
	rust_sha256_blocks_generic(state, data, nblocks);
}
bool sha256_finup_2x_dispatch(const struct __sha256_ctx *ctx, const u8 *data1, const u8 *data2,
			      size_t len, u8 *out1, u8 *out2)
{
	(void)ctx; (void)data1; (void)data2; (void)len; (void)out1; (void)out2;
	return false;
}
bool sha256_finup_2x_is_optimized_dispatch(void)
{
	return false;
}

/* ---- C arm (renamed) ---- */
void c_sha224_init(struct sha224_ctx *ctx);
void c_sha256_init(struct sha256_ctx *ctx);
void c___sha256_update(struct __sha256_ctx *ctx, const u8 *data, size_t len);
void c_sha224_final(struct sha224_ctx *ctx, u8 out[28]);
void c_sha256_final(struct sha256_ctx *ctx, u8 out[32]);
void c_sha224(const u8 *data, size_t len, u8 out[28]);
void c_sha256(const u8 *data, size_t len, u8 out[32]);
void c_sha256_finup_2x(const struct sha256_ctx *ctx, const u8 *data1, const u8 *data2, size_t len, u8 out1[32], u8 out2[32]);
bool c_sha256_finup_2x_is_optimized(void);
void c_hmac_sha224_preparekey(struct hmac_sha224_key *key, const u8 *raw_key, size_t raw_key_len);
void c___hmac_sha256_init(struct __hmac_sha256_ctx *ctx, const struct __hmac_sha256_key *key);
void c_hmac_sha224_init_usingrawkey(struct hmac_sha224_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha224_final(struct hmac_sha224_ctx *ctx, u8 out[28]);
void c_hmac_sha224(const struct hmac_sha224_key *key, const u8 *data, size_t data_len, u8 out[28]);
void c_hmac_sha224_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[28]);
void c_hmac_sha256_preparekey(struct hmac_sha256_key *key, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha256_init_usingrawkey(struct hmac_sha256_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_sha256_final(struct hmac_sha256_ctx *ctx, u8 out[32]);
void c_hmac_sha256(const struct hmac_sha256_key *key, const u8 *data, size_t data_len, u8 out[32]);
void c_hmac_sha256_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[32]);

/* ---- Rust arm ---- */
void sha224_init(struct sha224_ctx *ctx);
void sha256_init(struct sha256_ctx *ctx);
void __sha256_update(struct __sha256_ctx *ctx, const u8 *data, size_t len);
void sha224_final(struct sha224_ctx *ctx, u8 out[28]);
void sha256_final(struct sha256_ctx *ctx, u8 out[32]);
void sha224(const u8 *data, size_t len, u8 out[28]);
void sha256(const u8 *data, size_t len, u8 out[32]);
void sha256_finup_2x(const struct sha256_ctx *ctx, const u8 *data1, const u8 *data2, size_t len, u8 out1[32], u8 out2[32]);
bool sha256_finup_2x_is_optimized(void);
void hmac_sha224_preparekey(struct hmac_sha224_key *key, const u8 *raw_key, size_t raw_key_len);
void __hmac_sha256_init(struct __hmac_sha256_ctx *ctx, const struct __hmac_sha256_key *key);
void hmac_sha224_init_usingrawkey(struct hmac_sha224_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_sha224_final(struct hmac_sha224_ctx *ctx, u8 out[28]);
void hmac_sha224(const struct hmac_sha224_key *key, const u8 *data, size_t data_len, u8 out[28]);
void hmac_sha224_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[28]);
void hmac_sha256_preparekey(struct hmac_sha256_key *key, const u8 *raw_key, size_t raw_key_len);
void hmac_sha256_init_usingrawkey(struct hmac_sha256_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_sha256_final(struct hmac_sha256_ctx *ctx, u8 out[32]);
void hmac_sha256(const struct hmac_sha256_key *key, const u8 *data, size_t data_len, u8 out[32]);
void hmac_sha256_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[32]);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what, unsigned long ctx)
{
	if (mism < 20)
		printf("MISMATCH %-28s ctx=%lu\n", what, ctx);
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
	u8 *data2 = randbuf(len, &seed);
	u8 *key = randbuf(keylen, &seed);
	u8 out_c[32], out_r[32], out2_c[32], out2_r[32];

	c_sha224(data, len, out_c); sha224(data, len, out_r);
	cmp("sha224", ctx, out_c, out_r, 28);
	c_sha256(data, len, out_c); sha256(data, len, out_r);
	cmp("sha256", ctx, out_c, out_r, 32);

	/* Incremental, split. */
	{
		struct sha256_ctx cc, rc;
		c_sha256_init(&cc); sha256_init(&rc);
		size_t split = len / 3;
		c___sha256_update(&cc.ctx, data, split);
		__sha256_update(&rc.ctx, data, split);
		c___sha256_update(&cc.ctx, data + split, len - split);
		__sha256_update(&rc.ctx, data + split, len - split);
		c_sha256_final(&cc, out_c); sha256_final(&rc, out_r);
		cmp("sha256-incremental", ctx, out_c, out_r, 32);
	}

	/* finup_2x: two independent digests from a shared (here: initial,
	 * NULL) prefix, and again from a non-trivial shared prefix context. */
	c_sha256_finup_2x(NULL, data, data2, len, out_c, out2_c);
	sha256_finup_2x(NULL, data, data2, len, out_r, out2_r);
	cmp("sha256_finup_2x-null-out1", ctx, out_c, out_r, 32);
	cmp("sha256_finup_2x-null-out2", ctx, out2_c, out2_r, 32);
	{
		struct sha256_ctx pc, pr;
		u8 prefix[16];
		for (size_t i = 0; i < sizeof(prefix); i++)
			prefix[i] = (u8)(i * 11 + 5);
		c_sha256_init(&pc); sha256_init(&pr);
		c___sha256_update(&pc.ctx, prefix, sizeof(prefix));
		__sha256_update(&pr.ctx, prefix, sizeof(prefix));
		c_sha256_finup_2x(&pc, data, data2, len, out_c, out2_c);
		sha256_finup_2x(&pr, data, data2, len, out_r, out2_r);
		cmp("sha256_finup_2x-prefix-out1", ctx, out_c, out_r, 32);
		cmp("sha256_finup_2x-prefix-out2", ctx, out2_c, out2_r, 32);
	}
	cases++;
	if (c_sha256_finup_2x_is_optimized() != sha256_finup_2x_is_optimized())
		bad("sha256_finup_2x_is_optimized", ctx);

	c_hmac_sha256_usingrawkey(key, keylen, data, len, out_c);
	hmac_sha256_usingrawkey(key, keylen, data, len, out_r);
	cmp("hmac_sha256_usingrawkey", ctx, out_c, out_r, 32);

	{
		struct hmac_sha256_key ck, rk;
		c_hmac_sha256_preparekey(&ck, key, keylen);
		hmac_sha256_preparekey(&rk, key, keylen);
		c_hmac_sha256(&ck, data, len, out_c);
		hmac_sha256(&rk, data, len, out_r);
		cmp("hmac_sha256-preparekey", ctx, out_c, out_r, 32);
	}

	c_hmac_sha224_usingrawkey(key, keylen, data, len, out_c);
	hmac_sha224_usingrawkey(key, keylen, data, len, out_r);
	cmp("hmac_sha224_usingrawkey", ctx, out_c, out_r, 28);

	free(data);
	free(data2);
	free(key);
}

int main(void)
{
	if (getenv("SHA256_PROVE_CAN_FAIL"))
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
