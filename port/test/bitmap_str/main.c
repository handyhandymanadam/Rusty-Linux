/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/bitmap-str.c parsers: pristine C (c_*) vs bitmap_str_rs.rs. Random list/hex strings (valid, malformed,
 * overflowing) at the END of a page before an unmapped guard page; return code and every mask word (+ canary) compared.
 * Both arms share the helper functions defined here (_parse_integer, strnchrnul, hex_to_bin, __bitmap_set/clear,
 * _find_next_bit), written independently of both, and the pristine lib/ctype.c table. usage: main SHARD ; BMS_PROVE_CAN_FAIL=1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
int c_bitmap_parselist(const char *, unsigned long *, int), bitmap_parselist(const char *, unsigned long *, int);
int c_bitmap_parse(const char *, unsigned int, unsigned long *, int), bitmap_parse(const char *, unsigned int, unsigned long *, int);

unsigned int _parse_integer(const char *s, unsigned int base, unsigned long long *p)
{
	unsigned long long res = 0; unsigned int rv = 0;
	while (1) {
		unsigned int c = *(const unsigned char *)s, val;
		if (c >= '0' && c <= '9') val = c - '0'; else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') val = (c | 0x20) - 'a' + 10; else break;
		if (val >= base) break;
		if (res & (~0ull << 60)) { if (res > (ULLONG_MAX - val) / base) rv |= 1U << 31; }
		res = res * base + val; rv++; s++;
	}
	*p = res; return rv;
}
int hex_to_bin(unsigned char ch) { if (ch >= '0' && ch <= '9') return ch - '0'; ch |= 0x20; if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10; return -1; }
char *strnchrnul(const char *s, size_t count, int c) { while (count-- && *s && *s != (char)c) s++; return (char *)s; }
void __bitmap_set(unsigned long *m, unsigned start, int len) { for (unsigned i = start; i < start + (unsigned)len; i++) m[i / 64] |= 1UL << (i % 64); }
void __bitmap_clear(unsigned long *m, unsigned start, int len) { for (unsigned i = start; i < start + (unsigned)len; i++) m[i / 64] &= ~(1UL << (i % 64)); }
unsigned long _find_next_bit(const unsigned long *a, unsigned long n, unsigned long s) { for (; s < n; s++) if (a[s / 64] >> (s & 63) & 1) return s; return n; }

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static char *page_end;
static int numtok(char *o)
{
	switch (rnd() % 8) {
	case 0: return sprintf(o, "N");
	case 1: return sprintf(o, "%llu", (unsigned long long)rnd() % 300);
	case 2: return sprintf(o, "%llu", (unsigned long long)rnd());          /* overflow */
	case 3: return sprintf(o, "%u", (unsigned)(0xffffffffu - rnd() % 3));
	default: return sprintf(o, "%llu", (unsigned long long)rnd() % 70);
	}
}
static int gen_list(char *o)
{
	int n = 0, items = rnd() % 5;
	for (int i = 0; i < items; i++) {
		if (rnd() % 8 == 0) { n += sprintf(o + n, "all"); }
		else {
			n += numtok(o + n);
			if (rnd() % 2) { o[n++] = '-'; n += numtok(o + n); }
			if (rnd() % 3 == 0) { o[n++] = ':'; n += numtok(o + n); o[n++] = '/'; n += numtok(o + n); }
		}
		if (i + 1 < items) o[n++] = ",; \n\t"[rnd() % 3 == 0 ? (rnd() % 4 + 1) : 0] ;
		if (rnd() % 4 == 0) o[n++] = ' ';
	}
	if (rnd() % 6 == 0 && n) o[rnd() % n] = "-:/,xN \n9,"[rnd() % 10];
	if (rnd() % 8 == 0) o[n++] = '\n';
	o[n] = 0; return n;
}
static int gen_hex(char *o)
{
	int n = 0, chunks = rnd() % 5;
	for (int c = 0; c < chunks; c++) {
		int len = 1 + rnd() % 10;
		for (int i = 0; i < len; i++) o[n++] = "0123456789abcdefABCDEF"[rnd() % 22];
		if (c + 1 < chunks) o[n++] = ",, "[rnd() % 3];
	}
	if (rnd() % 8 == 0 && n) o[rnd() % n] = "gz,\n -"[rnd() % 6];
	if (rnd() % 8 == 0) o[n++] = '\n';
	o[n] = 0; return n;
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("BMS_N") ? atoll(getenv("BMS_N")) : 10000000LL;
	poison = getenv("BMS_PROVE_CAN_FAIL") != 0;
	long pg = sysconf(_SC_PAGESIZE);
	char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m + pg, pg, PROT_NONE); page_end = m + pg;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		char tmp[256];
		int hex = rnd() & 1, len = hex ? gen_hex(tmp) : gen_list(tmp);
		char *p = page_end - len - 1; memcpy(p, tmp, len + 1);
		int nbits = (rnd() % 8 == 0) ? (int)(rnd() % 3) : (rnd() % 4 == 0 ? 64 * (rnd() % 4) : (int)(rnd() % 200));
		unsigned long a[6], b[6];
		memset(a, 0xA5, sizeof a); memset(b, 0xA5, sizeof b);
		unsigned buflen = (rnd() % 3 == 0) ? (unsigned)(rnd() % (len + 2)) : (rnd() % 2 ? UINT_MAX : (unsigned)len + 1);
		int ra, rb;
		if (hex) { ra = c_bitmap_parse(p, buflen, a, nbits); rb = bitmap_parse(p, buflen, b, nbits); }
		else { ra = c_bitmap_parselist(p, a, nbits); rb = bitmap_parselist(p, b, nbits); }
		if (poison && !hex && nbits == 0 && len == 0) rb++;
		checks++;
		if (ra != rb || memcmp(a, b, sizeof a)) FAIL("%s MISMATCH '%s' buflen=%u nbits=%d c=%d rs=%d mask c=%lx/%lx rs=%lx/%lx\n", hex ? "parse" : "parselist", tmp, buflen, nbits, ra, rb, a[0], a[1], b[0], b[1]);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
