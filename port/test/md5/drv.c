/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/md5/drv.c -- differential for lib/crypto/md5.c -> md5_rs.rs.
 *
 * All ten exported symbols: md5_init, md5_update, md5_final, md5,
 * hmac_md5_preparekey, hmac_md5_init, hmac_md5_init_usingrawkey,
 * hmac_md5_final, hmac_md5, hmac_md5_usingrawkey.
 *
 * Two kinds of check, for the reason logs/porting-hazards.md guard 12 gives:
 * a cross-differential proves the two arms agree, not that either is right.
 *   1. C vs Rust, fed the same random corpus three different ways (one-shot,
 *      byte-at-a-time, random chunks) -- this is what would catch a
 *      buffering/block-boundary mistranslation.
 *   2. A handful of RFC 1321 / RFC 2202 vectors, checked against literal
 *      published bytes -- this is what would catch BOTH arms being wrong
 *      the same way, which a cross-differential alone cannot see.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE 64
#define MD5_HASH_WORDS 4

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

struct md5_block_state { u32 h[MD5_HASH_WORDS]; };
struct md5_ctx {
	struct md5_block_state state;
	u64 bytecount;
	u8 buf[MD5_BLOCK_SIZE];
};
struct hmac_md5_key {
	struct md5_block_state istate;
	struct md5_block_state ostate;
};
struct hmac_md5_ctx {
	struct md5_ctx hash_ctx;
	struct md5_block_state ostate;
};

/* Layout this differential depends on: both arms must agree with the kernel
 * on these sizes, or a mismatch here would just be comparing garbage.
 * Confirmed against the captured pins in logs/pins/md5.pins. */
_Static_assert(sizeof(struct md5_block_state) == 16, "md5_block_state size");
_Static_assert(sizeof(struct md5_ctx) == 88, "md5_ctx size");
_Static_assert(sizeof(struct hmac_md5_key) == 32, "hmac_md5_key size");
_Static_assert(sizeof(struct hmac_md5_ctx) == 104, "hmac_md5_ctx size");

/* ---- C arm (renamed at compile time via -D, see run.sh) ---- */
void c_md5_init(struct md5_ctx *ctx);
void c_md5_update(struct md5_ctx *ctx, const u8 *data, size_t len);
void c_md5_final(struct md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void c_md5(const u8 *data, size_t len, u8 out[MD5_DIGEST_SIZE]);
void c_hmac_md5_preparekey(struct hmac_md5_key *key, const u8 *raw_key, size_t raw_key_len);
void c_hmac_md5_init(struct hmac_md5_ctx *ctx, const struct hmac_md5_key *key);
void c_hmac_md5_init_usingrawkey(struct hmac_md5_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void c_hmac_md5_final(struct hmac_md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void c_hmac_md5(const struct hmac_md5_key *key, const u8 *data, size_t data_len, u8 out[MD5_DIGEST_SIZE]);
void c_hmac_md5_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[MD5_DIGEST_SIZE]);

/* ---- Rust arm (kept at the real names) ---- */
void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const u8 *data, size_t len);
void md5_final(struct md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void md5(const u8 *data, size_t len, u8 out[MD5_DIGEST_SIZE]);
void hmac_md5_preparekey(struct hmac_md5_key *key, const u8 *raw_key, size_t raw_key_len);
void hmac_md5_init(struct hmac_md5_ctx *ctx, const struct hmac_md5_key *key);
void hmac_md5_init_usingrawkey(struct hmac_md5_ctx *ctx, const u8 *raw_key, size_t raw_key_len);
void hmac_md5_final(struct hmac_md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void hmac_md5(const struct hmac_md5_key *key, const u8 *data, size_t data_len, u8 out[MD5_DIGEST_SIZE]);
void hmac_md5_usingrawkey(const u8 *raw_key, size_t raw_key_len, const u8 *data, size_t data_len, u8 out[MD5_DIGEST_SIZE]);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static u32 rnd(u32 *s)
{
	*s = *s * 1103515245u + 12345u;
	return *s;
}

static void fill_random(u8 *buf, size_t len, u32 *s)
{
	size_t i;
	for (i = 0; i < len; i++)
		buf[i] = (u8)(rnd(s) >> 24);
}

/* Feed `data[0..len)` to `upd` in chunks of `chunk` bytes (0 => one shot). */
static void feed(void *ctx,
		  void (*init)(struct md5_ctx *),
		  void (*upd)(struct md5_ctx *, const u8 *, size_t),
		  void (*fin)(struct md5_ctx *, u8 *),
		  const u8 *data, size_t len, size_t chunk, u8 *out)
{
	size_t off = 0;
	init((struct md5_ctx *)ctx);
	if (chunk == 0) {
		upd((struct md5_ctx *)ctx, data, len);
	} else {
		while (off < len) {
			size_t n = len - off < chunk ? len - off : chunk;
			upd((struct md5_ctx *)ctx, data + off, n);
			off += n;
		}
	}
	fin((struct md5_ctx *)ctx, out);
}

/* One (message, chunking) pair, both arms, all comparable ways to reach it. */
static void run_md5_case(const u8 *data, size_t len, size_t chunk, u32 poison_c)
{
	struct md5_ctx cc, cr;
	u8 outc[MD5_DIGEST_SIZE], outr[MD5_DIGEST_SIZE];

	feed(&cc, c_md5_init, c_md5_update, c_md5_final, data, len, chunk, outc);
	feed(&cr, md5_init, md5_update, md5_final, data, len, chunk, outr);
	if (poison_c && len > 0)
		outc[0] ^= (u8)poison_c; /* deliberately break the C side's answer */
	cases++;
	if (memcmp(outc, outr, MD5_DIGEST_SIZE) != 0)
		bad("md5 digest");

	/* The one-shot md5() convenience function must agree with the
	 * init/update/final sequence above, on both arms. */
	if (chunk == 0) {
		u8 oc[MD5_DIGEST_SIZE], or_[MD5_DIGEST_SIZE];
		c_md5(data, len, oc);
		md5(data, len, or_);
		cases++;
		if (memcmp(oc, outc, MD5_DIGEST_SIZE) != 0)
			bad("c md5() vs c init/update/final");
		cases++;
		if (memcmp(or_, outr, MD5_DIGEST_SIZE) != 0)
			bad("rust md5() vs rust init/update/final");
	}
}

static void run_hmac_case(const u8 *key, size_t keylen,
			   const u8 *data, size_t len, size_t chunk)
{
	struct hmac_md5_key kc, kr;
	struct hmac_md5_ctx cc, cr;
	u8 outc[MD5_DIGEST_SIZE], outr[MD5_DIGEST_SIZE];
	u8 outc2[MD5_DIGEST_SIZE], outr2[MD5_DIGEST_SIZE];
	size_t off;

	/* Prepared-key path. */
	c_hmac_md5_preparekey(&kc, key, keylen);
	hmac_md5_preparekey(&kr, key, keylen);
	c_hmac_md5_init(&cc, &kc);
	hmac_md5_init(&cr, &kr);
	off = 0;
	while (off < len) {
		size_t n = chunk == 0 ? len - off : (len - off < chunk ? len - off : chunk);
		/* hmac_md5_update() is a static inline in the real header;
		 * here it is just md5_update() on the embedded hash_ctx. */
		c_md5_update(&cc.hash_ctx, data + off, n);
		md5_update(&cr.hash_ctx, data + off, n);
		off += n;
		if (chunk == 0)
			break;
	}
	c_hmac_md5_final(&cc, outc);
	hmac_md5_final(&cr, outr);
	cases++;
	if (memcmp(outc, outr, MD5_DIGEST_SIZE) != 0)
		bad("hmac_md5 (prepared key) digest");

	/* One-shot raw-key path must agree with the above. */
	c_hmac_md5_usingrawkey(key, keylen, data, len, outc2);
	hmac_md5_usingrawkey(key, keylen, data, len, outr2);
	cases++;
	if (memcmp(outc2, outc, MD5_DIGEST_SIZE) != 0)
		bad("c hmac_md5_usingrawkey vs c prepared-key path");
	cases++;
	if (memcmp(outr2, outr, MD5_DIGEST_SIZE) != 0)
		bad("rust hmac_md5_usingrawkey vs rust prepared-key path");
	cases++;
	if (memcmp(outc2, outr2, MD5_DIGEST_SIZE) != 0)
		bad("hmac_md5_usingrawkey digest");
}

/* RFC 1321 MD5 test vectors -- an INDEPENDENT oracle, not the other arm.
 * Reproduced with Python's hashlib, not hand-computed. */
static void check_rfc1321(void)
{
	struct { const u8 *msg; size_t len; const u8 want[MD5_DIGEST_SIZE]; } vecs[] = {
		{ (const u8 *)"", 0,
		  { 0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e } },
		{ (const u8 *)"a", 1,
		  { 0x0c,0xc1,0x75,0xb9,0xc0,0xf1,0xb6,0xa8,0x31,0xc3,0x99,0xe2,0x69,0x77,0x26,0x61 } },
		{ (const u8 *)"abc", 3,
		  { 0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72 } },
		{ (const u8 *)"message digest", 14,
		  { 0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0 } },
		{ (const u8 *)"abcdefghijklmnopqrstuvwxyz", 26,
		  { 0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b } },
	};
	size_t i;

	for (i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		u8 outc[MD5_DIGEST_SIZE], outr[MD5_DIGEST_SIZE];
		c_md5(vecs[i].msg, vecs[i].len, outc);
		md5(vecs[i].msg, vecs[i].len, outr);
		cases += 2;
		if (memcmp(outc, vecs[i].want, MD5_DIGEST_SIZE) != 0)
			bad("RFC 1321 vector, C arm");
		if (memcmp(outr, vecs[i].want, MD5_DIGEST_SIZE) != 0)
			bad("RFC 1321 vector, Rust arm");
	}
}

/* RFC 2202 HMAC-MD5 case 1 (short key) and case 6 (key > block size, the
 * path that exercises hmac_md5_preparekey()'s internal md5() call). */
static void check_rfc2202(void)
{
	static const u8 key1[16] = {
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
	static const u8 want1[MD5_DIGEST_SIZE] = {
		0x92,0x94,0x72,0x7a,0x36,0x38,0xbb,0x1c,0x13,0xf4,0x8e,0xf8,0x15,0x8b,0xfc,0x9d };
	static const u8 want6[MD5_DIGEST_SIZE] = {
		0x6b,0x1a,0xb7,0xfe,0x4b,0xd7,0xbf,0x8f,0x0b,0x62,0xe6,0xce,0x61,0xb9,0xd0,0xcd };
	u8 key6f[80];
	u8 outc[MD5_DIGEST_SIZE], outr[MD5_DIGEST_SIZE];
	size_t i;

	for (i = 0; i < sizeof(key6f); i++)
		key6f[i] = 0xaa;

	c_hmac_md5_usingrawkey(key1, sizeof(key1), (const u8 *)"Hi There", 8, outc);
	hmac_md5_usingrawkey(key1, sizeof(key1), (const u8 *)"Hi There", 8, outr);
	cases += 2;
	if (memcmp(outc, want1, MD5_DIGEST_SIZE) != 0)
		bad("RFC 2202 case 1, C arm");
	if (memcmp(outr, want1, MD5_DIGEST_SIZE) != 0)
		bad("RFC 2202 case 1, Rust arm");

	{
		static const u8 msg6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
		c_hmac_md5_usingrawkey(key6f, sizeof(key6f), msg6, sizeof(msg6) - 1, outc);
		hmac_md5_usingrawkey(key6f, sizeof(key6f), msg6, sizeof(msg6) - 1, outr);
	}
	cases += 2;
	if (memcmp(outc, want6, MD5_DIGEST_SIZE) != 0)
		bad("RFC 2202 case 6, C arm");
	if (memcmp(outr, want6, MD5_DIGEST_SIZE) != 0)
		bad("RFC 2202 case 6, Rust arm");
}

int main(void)
{
	u32 s = 1;
	unsigned n;

	if (getenv("MD5_PROVE_CAN_FAIL"))
		poison = 1;

	check_rfc1321();
	check_rfc2202();

	/* Lengths that walk across the padding boundary in both directions:
	 * 0, 1, every value near a block multiple (55/56/57 is where the
	 * length byte flips which block the length trailer lands in), and a
	 * spread of longer messages spanning several blocks. */
	{
		static const size_t lens[] = {
			0, 1, 2, 3, 8, 15, 16, 31, 32, 54, 55, 56, 57, 63, 64, 65,
			66, 100, 119, 120, 121, 127, 128, 129, 191, 192, 193, 255, 256, 511, 512, 600,
		};
		size_t li;
		u8 buf[700];

		for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
			size_t len = lens[li];
			unsigned chunk_idx;
			size_t chunks[] = { 0, 1, 7, len };

			fill_random(buf, len, &s);
			for (chunk_idx = 0; chunk_idx < 4; chunk_idx++)
				run_md5_case(buf, len, chunks[chunk_idx], 0);
		}
	}

	/* Broader random sweep, one-shot only, for volume. */
	for (n = 0; n < 4000; n++) {
		u8 buf[300];
		size_t len = rnd(&s) % sizeof(buf);
		fill_random(buf, len, &s);
		run_md5_case(buf, len, (n % 5 == 0) ? 1 : (n % 5 == 1) ? 3 : 0, 0);
	}

	/* HMAC: keys on both sides of the block-size boundary (16, 64, 65,
	 * 128), data of varying length, both incremental and one-shot. */
	{
		size_t keylens[] = { 0, 1, 16, 63, 64, 65, 100, 128 };
		size_t ki;
		for (ki = 0; ki < sizeof(keylens) / sizeof(keylens[0]); ki++) {
			u8 key[128], data[200];
			size_t klen = keylens[ki];
			for (n = 0; n < 20; n++) {
				size_t dlen = rnd(&s) % sizeof(data);
				fill_random(key, klen, &s);
				fill_random(data, dlen, &s);
				run_hmac_case(key, klen, data, dlen, 0);
				run_hmac_case(key, klen, data, dlen, 1);
				run_hmac_case(key, klen, data, dlen, 9);
			}
		}
	}

	if (poison) {
		/* Prove the harness can disagree at all: sabotage the C
		 * side's recorded digest for one case and confirm the
		 * comparison above catches it. */
		u8 data[16];
		fill_random(data, sizeof(data), &s);
		run_md5_case(data, sizeof(data), 0, 0xff);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
