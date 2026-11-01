/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the four UTF conversion functions of fs/nls/nls_base.c:
 * pristine C (c_* , sliced out of the pristine file) vs nls_base_rs.rs.
 *  utf8_to_utf32  : all 2^32 first-four-byte patterns x inlen -1..7 (bytes 5,6 derived)
 *  utf32_to_utf8  : every code point 0..0x1fffff x maxout -2..6, NULL out, strided rest of 2^32
 *  utf8s_to_utf16s / utf16s_to_utf8s : structured random strings (valid, corrupted, surrogate-heavy),
 *                   random inlen/maxout/endian (incl. out-of-range endian), output + canaries compared
 * usage: main SHARD NSHARDS ; NLS_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int c_utf8_to_utf32(const unsigned char *s, int inlen, unsigned *pu);
int c_utf32_to_utf8(unsigned u, unsigned char *s, int maxout);
int c_utf8s_to_utf16s(const unsigned char *s, int inlen, int endian, unsigned short *pwcs, int maxout);
int c_utf16s_to_utf8s(const unsigned short *pwcs, int inlen, int endian, unsigned char *s, int maxout);
int utf8_to_utf32(const unsigned char *s, int inlen, unsigned *pu);
int utf32_to_utf8(unsigned u, unsigned char *s, int maxout);
int utf8s_to_utf16s(const unsigned char *s, int inlen, int endian, unsigned short *pwcs, int maxout);
int utf16s_to_utf8s(const unsigned short *pwcs, int inlen, int endian, unsigned char *s, int maxout);

static unsigned long long fails, checks;
static int poison;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }

static void t8to32(unsigned x)
{
	unsigned char b[8];
	uint64_t h = (uint64_t)x * 0x9e3779b97f4a7c15ULL;
	b[0] = x; b[1] = x >> 8; b[2] = x >> 16; b[3] = x >> 24;
	b[4] = (h >> 40) & 3 ? 0x80 | ((h >> 20) & 0x3f) : (h >> 8);
	b[5] = (h >> 48) & 3 ? 0x80 | ((h >> 30) & 0x3f) : (h >> 16);
	b[6] = b[7] = 0xff;
	for (int n = -1; n <= 7; n++) {
		unsigned ua = 0xDEADBEEF, ub = 0xDEADBEEF;
		int ra = c_utf8_to_utf32(b, n, &ua), rb = utf8_to_utf32(b, n, &ub);
		if (poison && x == 0xA2C3 && n == 2) rb++;
		checks++;
		if (ra != rb || ua != ub)
			FAIL("8to32 MISMATCH %02x %02x %02x %02x %02x %02x n=%d c=%d/%#x rust=%d/%#x\n",
			     b[0], b[1], b[2], b[3], b[4], b[5], n, ra, ua, rb, ub);
	}
}

static void t32to8(unsigned u)
{
	for (int mo = -2; mo <= 6; mo++) {
		unsigned char a[12], b[12];
		memset(a, 0xA5, sizeof a); memset(b, 0xA5, sizeof b);
		int ra = c_utf32_to_utf8(u, a, mo), rb = utf32_to_utf8(u, b, mo);
		checks++;
		if (ra != rb || memcmp(a, b, sizeof a))
			FAIL("32to8 MISMATCH u=%#x mo=%d c=%d rust=%d\n", u, mo, ra, rb);
	}
	int ra = c_utf32_to_utf8(u, 0, 4), rb = utf32_to_utf8(u, 0, 4);
	checks++;
	if (ra != rb) FAIL("32to8 NULL MISMATCH u=%#x c=%d rust=%d\n", u, ra, rb);
}

static unsigned rcp(void)
{
	switch (rnd() % 8) {
	case 0: return rnd() % 0x80;
	case 1: return 0x80 + rnd() % 0x780;
	case 2: return 0x800 + rnd() % 0xf800;
	case 3: return 0xd7f0 + rnd() % 0x20;          /* around surrogates */
	case 4: return 0x10000 + rnd() % 0x100000;
	case 5: return 0x10ff00 + rnd() % 0x200;       /* around UNICODE_MAX */
	default: return rnd() % 0x110000;
	}
}

static int enc(unsigned u, unsigned char *p)    /* generic UTF-8 encoder (up to 6 bytes), independent of the code under test */
{
	if (u < 0x80) { p[0] = u; return 1; }
	if (u < 0x800) { p[0] = 0xC0 | u >> 6; p[1] = 0x80 | (u & 63); return 2; }
	if (u < 0x10000) { p[0] = 0xE0 | u >> 12; p[1] = 0x80 | (u >> 6 & 63); p[2] = 0x80 | (u & 63); return 3; }
	p[0] = 0xF0 | u >> 18; p[1] = 0x80 | (u >> 12 & 63); p[2] = 0x80 | (u >> 6 & 63); p[3] = 0x80 | (u & 63); return 4;
}

static void tstr8(void)
{
	unsigned char in[96]; unsigned short oa[64], ob[64];
	int len = 0, n = 1 + rnd() % 14;
	while (n-- && len < 80) {
		unsigned u = rcp();
		if (rnd() % 16 == 0) { in[len++] = rnd(); continue; }
		len += enc(u, in + len);
	}
	int k = rnd() % 5;
	while (k--) if (len) in[rnd() % len] ^= (rnd() % 3 == 0) ? 0xFF : (1u << (rnd() % 8));
	if (rnd() % 8 == 0 && len) in[rnd() % len] = 0;
	memset(in + len, 0xE7, sizeof in - len);
	int inlen = (rnd() % 4 == 0) ? (int)(rnd() % 100) - 4 : len + (int)(rnd() % 3) - 1;
	int mo = (rnd() % 3 == 0) ? (int)(rnd() % 6) - 1 : 40;
	int e = rnd() % 4;
	memset(oa, 0x5A, sizeof oa); memset(ob, 0x5A, sizeof ob);
	int ra = c_utf8s_to_utf16s(in, inlen, e, oa, mo), rb = utf8s_to_utf16s(in, inlen, e, ob, mo);
	checks++;
	if (ra != rb || memcmp(oa, ob, sizeof oa))
		FAIL("8s16 MISMATCH len=%d inlen=%d mo=%d e=%d c=%d rust=%d\n", len, inlen, mo, e, ra, rb);
}

static void tstr16(void)
{
	unsigned short in[48]; unsigned char oa[200], ob[200];
	int len = 1 + rnd() % 30;
	for (int i = 0; i < len; i++) {
		switch (rnd() % 7) {
		case 0: case 1: in[i] = rnd() % 0x80; break;
		case 2: in[i] = 0xd800 + rnd() % 0x400; break;      /* high */
		case 3: in[i] = 0xdc00 + rnd() % 0x400; break;      /* low */
		case 4: in[i] = rnd(); break;
		case 5: in[i] = 0x80 + rnd() % 0x780; break;
		default: in[i] = (rnd() % 20 == 0) ? 0 : 0x800 + rnd() % 0xd000; break;
		}
	}
	int e = rnd() % 4;
	if (e == 2) for (int i = 0; i < len; i++) in[i] = __builtin_bswap16(in[i]);
	for (int i = len; i < 48; i++) in[i] = 0xBEEF;
	int inlen = (rnd() % 4 == 0) ? (int)(rnd() % 50) - 3 : len + (int)(rnd() % 3) - 1;
	int mo = (rnd() % 2) ? (int)(rnd() % 20) - 1 : 190;
	memset(oa, 0x5A, sizeof oa); memset(ob, 0x5A, sizeof ob);
	int ra = c_utf16s_to_utf8s(in, inlen, e, oa, mo), rb = utf16s_to_utf8s(in, inlen, e, ob, mo);
	checks++;
	if (ra != rb || memcmp(oa, ob, sizeof oa))
		FAIL("16s8 MISMATCH len=%d inlen=%d mo=%d e=%d c=%d rust=%d\n", len, inlen, mo, e, ra, rb);
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	unsigned long long nrand = getenv("NLS_NRAND") ? strtoull(getenv("NLS_NRAND"), 0, 0) : 20000000ULL;
	poison = getenv("NLS_PROVE_CAN_FAIL") != 0;
	int failfast = getenv("NLS_FAILFAST") != 0;
	uint64_t lim = getenv("NLS_LIM8") ? strtoull(getenv("NLS_LIM8"), 0, 0) : (1ULL << 32);

	for (uint64_t x = shard; x < lim; x += nsh) {
		t8to32((unsigned)x);
		if (failfast && fails) goto done;
	}
	for (uint64_t u = shard; u < 0x200000; u += nsh) t32to8((unsigned)u);
	for (uint64_t u = 0x200000 + shard; u < (1ULL << 32); u += 4099ULL * nsh) t32to8((unsigned)u);
	rs = 0x1234567ULL * (shard + 1);
	for (unsigned long long i = 0; i < nrand; i++) { tstr8(); tstr16(); }
done:
	printf("shard %u/%u: %llu checks, %llu failures\n", shard, nsh, checks, fails);
	return fails != 0;
}
