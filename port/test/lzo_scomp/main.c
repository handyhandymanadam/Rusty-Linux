/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/lzo[-rle].c's two helper bodies: pristine C (ref.c)
 * vs the Rust, both calling the SAME mock lzo1x functions (this file), which
 * record their arguments and return a programmed result. See run.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8;

int c_compress(const u8 *, unsigned, u8 *, unsigned *, void *);
int c_decompress(const u8 *, unsigned, u8 *, unsigned *);
int RS_COMPRESS(const u8 *, unsigned, u8 *, unsigned *, void *);
int RS_DECOMPRESS(const u8 *, unsigned, u8 *, unsigned *);

/* ---- the mock: records arguments, returns the programmed result ---- */
static int m_ret; static size_t m_out;
static struct { const unsigned char *src; size_t slen; unsigned char *dst; size_t in_dlen; void *ctx; int calls; int fn; } rec;
static int mock(int fn, const unsigned char *s, size_t sl, unsigned char *d, size_t *dl, void *c)
{
	rec.fn = fn;
	rec.src = s; rec.slen = sl; rec.dst = d; rec.in_dlen = *dl; rec.ctx = c; rec.calls++;
	if (m_ret == 0 || (m_ret & 1) == 0 /* some failing codes still write */) *dl = m_out;
	return m_ret;
}
int lzo1x_1_compress_safe(const unsigned char *s, size_t sl, unsigned char *d, size_t *dl, void *c) { return mock(1, s, sl, d, dl, c); }
int lzorle1x_1_compress_safe(const unsigned char *s, size_t sl, unsigned char *d, size_t *dl, void *c) { return mock(2, s, sl, d, dl, c); }
int lzo1x_decompress_safe(const unsigned char *s, size_t sl, unsigned char *d, size_t *dl) { return mock(3, s, sl, d, dl, NULL); }

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static unsigned long long checks, fails;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

struct res { int ret; unsigned dlen; typeof(rec) r; };

static const unsigned edge32[] = { 0, 1, 2, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu, 4096, 65536 };
static const int rets[] = { 0, -1, -2, -3, -4, -5, -6, -7, -8, -9, 1, 2, 3, 100, -100, 0x7fffffff, (int)0x80000000 };

int main(int argc, char **argv)
{
	unsigned long long n = argc > 1 ? strtoull(argv[1], 0, 0) : 500000, i;
	static u8 srcb[16], dstb[16];

	for (i = 0; i < n; i++) {
		int which = (int)(rnd() & 1);   /* 0 compress, 1 decompress */
		unsigned slen = (rnd() & 3) ? edge32[rnd() % (sizeof edge32 / sizeof *edge32)] : (unsigned)rnd();
		unsigned dl0 = (rnd() & 3) ? edge32[rnd() % (sizeof edge32 / sizeof *edge32)] : (unsigned)rnd();
		void *ctx = (void *)(uintptr_t)(rnd() | 1);
		struct res a, b;
		unsigned da = dl0, db = dl0;
		const u8 *sp = srcb + (rnd() & 7); u8 *dp = dstb + (rnd() & 7);

		m_ret = (rnd() & 1) ? 0 : rets[rnd() % (sizeof rets / sizeof *rets)];
		/* mocked out_len: usually < 2^32, sometimes above it (truncation) or SIZE_MAX */
		switch (rnd() & 3) { case 0: m_out = rnd() & 0xffff; break; case 1: m_out = (size_t)(unsigned)rnd(); break;
				    case 2: m_out = (size_t)rnd(); break; default: m_out = (size_t)-1; }

		memset(&rec, 0, sizeof rec);
		a.ret = which ? c_decompress(sp, slen, dp, &da) : c_compress(sp, slen, dp, &da, ctx);
		a.dlen = da; a.r = rec;
		memset(&rec, 0, sizeof rec);
		b.ret = which ? RS_DECOMPRESS(sp, slen, dp, &db) : RS_COMPRESS(sp, slen, dp, &db, ctx);
		b.dlen = db; b.r = rec;
		if (getenv("LZO_PROVE_CAN_FAIL")) b.dlen++;
		checks++;
		if (a.ret != b.ret || a.dlen != b.dlen || memcmp(&a.r, &b.r, sizeof a.r))
			FAIL("MISMATCH which=%d slen=%u dl0=%u ret=%d out=%#zx: C ret=%d dlen=%u | Rust ret=%d dlen=%u (in_dlen %zu/%zu calls %d/%d)\n",
			     which, slen, dl0, m_ret, m_out, a.ret, a.dlen, b.ret, b.dlen, a.r.in_dlen, b.r.in_dlen, a.r.calls, b.r.calls);
		/* spec points, independent of the C: exactly one call; any nonzero code -> -EINVAL and dlen untouched */
		if (a.r.calls != 1 || b.r.calls != 1) FAIL("calls != 1\n");
		/* the right library function: lzo1x_1 (1), lzorle1x_1 (2) or the decompressor (3) */
		if (b.r.fn != (which ? 3 : EXPECT_COMPRESS_FN)) FAIL("wrong library function called: %d\n", b.r.fn);
		if (m_ret != 0 && (b.ret != -22 || b.dlen != dl0)) FAIL("failure path wrong: ret=%d dlen=%u\n", b.ret, b.dlen);
		if (m_ret == 0 && (b.ret != 0 || b.dlen != (unsigned)m_out)) FAIL("success path wrong\n");
		if (b.r.in_dlen != dl0 || b.r.slen != slen) FAIL("args not widened faithfully\n");
	}
	printf("lzo_scomp: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
