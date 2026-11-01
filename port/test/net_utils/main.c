/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for net/core/utils.c address parsing: pristine C (c_*) vs utils_rs.rs. Strings are placed so
 * the byte after the last readable one is an unmapped guard page (an over-read by either arm faults).
 * Compared: return value, the dst bytes (16 + canary), and the *end offset. Both arms share one hex_to_bin().
 * usage: main SHARD ; NETU_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
uint32_t c_in_aton(const char *), in_aton(const char *);
int c_in4_pton(const char *, int, uint8_t *, int, const char **), in4_pton(const char *, int, uint8_t *, int, const char **);
int c_in6_pton(const char *, int, uint8_t *, int, const char **), in6_pton(const char *, int, uint8_t *, int, const char **);
int hex_to_bin(unsigned char ch) { if (ch >= '0' && ch <= '9') return ch - '0'; ch |= 0x20; if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10; return -1; }
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static char *page_end;
static const char alpha[] = "0123456789abcdefABCDEF:::...%\n xg-";
static int gen(char *o)           /* returns length, o is NUL terminated at o[len] */
{
	int n = 0, style = rnd() % 6;
	if (style == 0) { n = rnd() % 12; for (int i = 0; i < n; i++) o[i] = alpha[rnd() % (sizeof alpha - 1)]; }
	else if (style == 1) {         /* dotted quad */
		n = sprintf(o, "%u.%u.%u.%u", (unsigned)(rnd() % 300), (unsigned)(rnd() % 300), (unsigned)(rnd() % 260), (unsigned)(rnd() % 260));
		if (rnd() % 3 == 0) o[rnd() % n] = alpha[rnd() % (sizeof alpha - 1)];
		if (rnd() % 4 == 0) n += sprintf(o + n, "%c", "\n%:."[rnd() % 4]);
	} else {                      /* IPv6-ish */
		int groups = 1 + rnd() % 9, dc = rnd() % 3 == 0;
		for (int g = 0; g < groups; g++) {
			int len = rnd() % 6;
			for (int i = 0; i < len; i++) o[n++] = "0123456789abcdefABCDEF"[rnd() % 22];
			if (g + 1 < groups) { o[n++] = ':'; if (dc && g == (int)(rnd() % groups)) o[n++] = ':'; }
		}
		if (rnd() % 3 == 0) n += sprintf(o + n, ":%u.%u.%u.%u", (unsigned)(rnd() % 300), (unsigned)(rnd() % 256), (unsigned)(rnd() % 256), (unsigned)(rnd() % 256));
		if (rnd() % 5 == 0) n += sprintf(o + n, "%%eth%u", (unsigned)(rnd() % 10));
		if (rnd() % 8 == 0 && n) o[rnd() % n] = alpha[rnd() % (sizeof alpha - 1)];
	}
	o[n] = 0; return n;
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("NETU_N") ? atoll(getenv("NETU_N")) : 20000000LL;
	poison = getenv("NETU_PROVE_CAN_FAIL") != 0;
	long pg = sysconf(_SC_PAGESIZE);
	char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m + pg, pg, PROT_NONE);
	page_end = m + pg;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		char tmp[128];
		int len = gen(tmp);
		int nul = rnd() % 4 != 0;           /* NUL terminated, or exactly `len` bytes then the guard page */
		char *p = page_end - len - (nul ? 1 : 0);
		memcpy(p, tmp, len); if (nul) p[len] = 0;
		int srclen = nul ? ((rnd() % 3 == 0) ? -1 : (int)(rnd() % (len + 3))) : len;
		if (!nul && srclen < 0) srclen = len;
		if (nul && srclen > len + 1) srclen = len + 1;
		int delim = (int[]){ -1, '\n', '%', 0, ':', '.', 'x' }[rnd() % 7];
		if (nul && srclen >= 0 && srclen > len) srclen = len;
		uint8_t da[32], db[32]; const char *ea = (const char *)1, *eb = (const char *)1;
		memset(da, 0xA5, sizeof da); memset(db, 0xA5, sizeof db);
		int ra4 = c_in4_pton(p, srclen, da, delim, &ea), rb4 = in4_pton(p, srclen, db, delim, &eb);
		if (poison && len == 7) rb4 ^= 1;
		checks++;
		if (ra4 != rb4 || memcmp(da, db, sizeof da) || (ea - p) != (eb - p)) FAIL("in4 MISMATCH '%s' srclen=%d delim=%d c=%d/%ld rs=%d/%ld\n", tmp, srclen, delim, ra4, (long)(ea - p), rb4, (long)(eb - p));
		memset(da, 0xA5, sizeof da); memset(db, 0xA5, sizeof db); ea = eb = (const char *)1;
		int ra6 = c_in6_pton(p, srclen, da, delim, &ea), rb6 = in6_pton(p, srclen, db, delim, &eb);
		checks++;
		if (ra6 != rb6 || memcmp(da, db, sizeof da) || (ea - p) != (eb - p)) FAIL("in6 MISMATCH '%s' srclen=%d delim=%d c=%d/%ld rs=%d/%ld\n", tmp, srclen, delim, ra6, (long)(ea - p), rb6, (long)(eb - p));
		memset(da, 0xA5, sizeof da); memset(db, 0xA5, sizeof db);
		c_in4_pton(p, srclen, da, delim, 0); in4_pton(p, srclen, db, delim, 0);
		c_in6_pton(p, srclen, da + 8, delim, 0); in6_pton(p, srclen, db + 8, delim, 0);   /* NULL end pointer, overlapping buffers */
		if (nul) {
			checks++; if (c_in_aton(p) != in_aton(p)) FAIL("in_aton MISMATCH '%s'\n", tmp);
		}
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
