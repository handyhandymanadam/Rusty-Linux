/* Differential: arch/x86/boot/string.c (the 16-bit setup copy; C original, symbols prefixed c_ by objcopy, `unsigned long`/`long`
 * rewritten to u32/s32 so they have the TARGET's 32 bits) against string_rs.rs (host_mock build, prefixed rs_). Every exported
 * function, return values, out parameters (endp offset, *res written or untouched), buffers, with every string copied to the END of a
 * page followed by a PROT_NONE page (a read past the NUL by either implementation crashes: same read extents).
 * Also an independent reference (u128 arithmetic) for kstrtoull / simple_strtoull for the cases where the C is exact (base <= 16).
 * Built and run by run-string-diff.sh. Exit status 0 = no difference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>

#define DECL(P) \
 int P##memcmp(const void*,const void*,size_t); int P##bcmp(const void*,const void*,size_t); int P##strcmp(const char*,const char*); \
 int P##strncmp(const char*,const char*,size_t); size_t P##strnlen(const char*,size_t); size_t P##strlen(const char*); \
 char *P##strstr(const char*,const char*); char *P##strchr(const char*,int); \
 unsigned long long P##simple_strtoull(const char*,char**,unsigned); int32_t P##simple_strtol(const char*,char**,unsigned); \
 int P##kstrtoull(const char*,unsigned,unsigned long long*); int P##boot_kstrtoul(const char*,unsigned,uint32_t*);
DECL(c_) DECL(rs_)

static unsigned long long checks, fails;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { if (fails++ < 20) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)
static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

/* guarded copies: the NUL is the last byte of the page, the next page is inaccessible */
static char *guard_page(void) {
	long ps = sysconf(_SC_PAGESIZE);
	char *p = mmap(0, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED || mprotect(p + ps, ps, PROT_NONE)) { perror("mmap"); exit(2); }
	return p;
}
static char *G[4];
static const char *gs(int k, const char *s) { size_t l = strlen(s) + 1; long ps = sysconf(_SC_PAGESIZE); char *d = G[k] + ps - l; memcpy(d, s, l); return d; }

/* ---- independent reference for the exact range (base <= 16): value of the longest valid digit prefix, or "too big" ---- */
struct ref { unsigned n; int big; unsigned long long v; };
static struct ref ref_parse(const unsigned char *s, unsigned base) {
	struct ref r = {0, 0, 0}; unsigned __int128 acc = 0;
	for (;; s++) {
		unsigned c = *s, v;
		if (c >= '0' && c <= '9') v = c - '0'; else if (c >= 'a' && c <= 'f') v = c - 'a' + 10; else if (c >= 'A' && c <= 'F') v = c - 'A' + 10; else break;
		if (v >= base) break;
		acc = acc * base + v; if (acc > ~0ULL) { r.big = 1; acc = (unsigned __int128)~0ULL + 1; }
		r.n++;
	}
	r.v = (unsigned long long)acc; return r;
}
static int ref_kstrtoull(const char *s, unsigned base, unsigned long long *res) {
	if (s[0] == '+') s++;
	if (base == 0) { if (s[0] == '0') base = ((s[1] | 0x20) == 'x' && isxdigit((unsigned char)s[2])) ? 16 : 8; else base = 10; }
	if (base == 16 && s[0] == '0' && (s[1] | 0x20) == 'x') s += 2;
	struct ref r = ref_parse((const unsigned char *)s, base);
	if (r.big) return -34;
	if (!r.n) return -22;
	s += r.n; if (*s == '\n') s++; if (*s) return -22;
	*res = r.v; return 0;
}

static void one_string(const char *src)
{
	const char *s = gs(0, src); size_t l = strlen(src);
	CHECK(c_strlen(s) == l && rs_strlen(s) == l, "strlen");
	for (size_t m = 0; m <= l + 2 && m < 12; m++) {
		const char *s2 = s; CHECK(c_strnlen(s2, m) == rs_strnlen(s2, m) && rs_strnlen(s2, m) == (l < m ? l : m), "strnlen %zu", m);
	}
	int cs[] = {0, 'x', 'X', '0', 'a', '-', '\n', 0x80, 0xff, 0x178, -128, -1, 0x30000, '+'};
	for (unsigned i = 0; i < sizeof cs / sizeof *cs; i++) {
		char *a = c_strchr(s, cs[i]), *b = rs_strchr(s, cs[i]);
		CHECK(a == b, "strchr %d on \"%s\"", cs[i], src);
	}
	unsigned bases[] = {0, 1, 2, 3, 8, 10, 16, 17, 36, 100, 0x10000, 0xffffffffu, 0x80000000u};
	for (unsigned i = 0; i < sizeof bases / sizeof *bases; i++) {
		unsigned b = bases[i];
		char *e1 = (char *)1, *e2 = (char *)1;
		unsigned long long v1 = c_simple_strtoull(s, &e1, b), v2 = rs_simple_strtoull(s, &e2, b);
		CHECK(v1 == v2 && e1 == e2, "simple_strtoull \"%s\" base %u: %llx/%llx end %ld/%ld", src, b, v1, v2, (long)(e1 - s), (long)(e2 - s));
		e1 = e2 = (char *)1;
		int32_t w1 = c_simple_strtol(s, &e1, b), w2 = rs_simple_strtol(s, &e2, b);
		CHECK(w1 == w2 && e1 == e2, "simple_strtol \"%s\" base %u: %d/%d", src, b, w1, w2);
		CHECK(c_simple_strtoull(s, 0, b) == rs_simple_strtoull(s, 0, b) && c_simple_strtol(s, 0, b) == rs_simple_strtol(s, 0, b), "strtox NULL endp");
		unsigned long long k1 = 0x1111, k2 = 0x1111, k3 = 0x1111; uint32_t u1 = 0x2222, u2 = 0x2222;
		int r1 = c_kstrtoull(s, b, &k1), r2 = rs_kstrtoull(s, b, &k2);
		CHECK(r1 == r2 && k1 == k2, "kstrtoull \"%s\" base %u: %d/%d %llx/%llx", src, b, r1, r2, k1, k2);
		if (b <= 16) { int r3 = ref_kstrtoull(src, b, &k3); CHECK(r3 == r1 && k3 == k1, "kstrtoull vs reference \"%s\" base %u: %d/%d", src, b, r1, r3); }
		r1 = c_boot_kstrtoul(s, b, &u1); r2 = rs_boot_kstrtoul(s, b, &u2);
		CHECK(r1 == r2 && u1 == u2, "boot_kstrtoul \"%s\" base %u: %d/%d %x/%x", src, b, r1, r2, u1, u2);
		if (b <= 16 && b != 0 && b != 1) { /* boot_kstrtoul against the reference: ERANGE iff the 64-bit value > 2^32-1, keeping the C's priority (kstrtoull errors first) */
			unsigned long long t; int rr = ref_kstrtoull(src, b, &t); if (rr == 0 && t > 0xffffffffULL) rr = -34;
			CHECK(rr == r1, "boot_kstrtoul vs reference \"%s\" base %u: %d/%d", src, b, r1, rr);
		}
	}
}

static void two_strings(const char *src, const char *srt)
{
	const char *s = gs(0, src), *t = gs(1, srt);
	int x = c_strcmp(s, t), y = rs_strcmp(s, t);
	CHECK(x == y, "strcmp \"%s\" \"%s\" %d/%d", src, srt, x, y);
	for (size_t m = 0; m < 7; m++) { int a = c_strncmp(s, t, m), b = rs_strncmp(s, t, m); CHECK(a == b, "strncmp \"%s\" \"%s\" %zu: %d/%d", src, srt, m, a, b); }
	char *p = c_strstr(s, t), *q = rs_strstr(s, t);
	CHECK(p == q, "strstr \"%s\" \"%s\"", src, srt);
	if (strlen(srt)) { char *z = strstr(src, srt); CHECK((z == 0) == (q == 0) && (!z || z - src == q - s), "strstr vs libc"); }
	/* memcmp/bcmp on the same bytes (also with the NUL and bytes >= 0x80): 0 or 1 only */
	size_t n = strlen(src) < strlen(srt) ? strlen(src) : strlen(srt);
	for (size_t m = 0; m <= n + 1 && m < 8; m++) {
		if (m > strlen(src) + 1 || m > strlen(srt) + 1) break;
		int a = c_memcmp(s, t, m), b = rs_memcmp(s, t, m), a2 = c_bcmp(s, t, m), b2 = rs_bcmp(s, t, m);
		CHECK(a == b && a2 == b2 && a == a2 && a == (memcmp(s, t, m) != 0), "memcmp \"%s\" \"%s\" %zu: %d/%d", src, srt, m, a, b);
	}
}

static const char alpha[] = "09/:aAfFgG`@xX+-\n \x80";   /* digits and their neighbours / :, hex letters and their neighbours ` g @ G, x, signs, whitespace, high byte */
#define NA (sizeof alpha - 1)

static void str_tests(void)
{
	char s[64], t[64];
	for (int len = 0; len <= 5; len++) {   /* every string of length 0..5 over the alphabet, single-string functions */
		size_t total = 1; for (int i = 0; i < len; i++) total *= NA;
		for (size_t k = 0; k < total; k++) {
			size_t kk = k; for (int i = 0; i < len; i++) { s[i] = alpha[kk % NA]; kk /= NA; } s[len] = 0;
			one_string(s);
		}
	}
	for (int l1 = 0; l1 <= 4; l1++) for (int l2 = 0; l2 <= 4; l2++) {   /* every pair of length 0..4 (<= 3 over the full alphabet, 4 over a reduced one) */
		size_t na = (l1 > 3 || l2 > 3) ? 7 : NA;
		size_t t1 = 1, t2 = 1; for (int i = 0; i < l1; i++) t1 *= na; for (int i = 0; i < l2; i++) t2 *= na;
		for (size_t a = 0; a < t1; a++) for (size_t b = 0; b < t2; b++) {
			size_t aa = a, bb = b;
			for (int i = 0; i < l1; i++) { s[i] = alpha[(aa % na) * (NA / na)]; aa /= na; } s[l1] = 0;
			for (int i = 0; i < l2; i++) { t[i] = alpha[(bb % na) * (NA / na)]; bb /= na; } t[l2] = 0;
			two_strings(s, t);
		}
	}
	/* the hand-picked overflow / prefix edges, and the 2^32 / 2^64 neighbourhood */
	static const char *edge[] = {"18446744073709551615", "18446744073709551616", "18446744073709551614", "1844674407370955161", "18446744073709551620", "18446744073709551615\n",
		"0xffffffffffffffff", "0x10000000000000000", "0xFFFFFFFFFFFFFFFF", "0XfffffffffffffffF\n", "01777777777777777777777", "02000000000000000000000",
		"1777777777777777777777", "2000000000000000000000", "+12", "++12", "+0x1f", "-12", "+-1", "0x", "0xg", "0x1g", "08", "0 ", "5\n", "5\n\n", "5\n ", "\n", "", "+", "-", "0", "00", "0X", "0x0", "0x00", "0b1", "+\n",
		"0x7fffffffffffffff", "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "-18446744073709551615", "-0", "-0x10",
		"1:", "1/", "a`", "A@", "fg", "FG", "1\x7f", "0x:", "0x/", "0:", ":1", "zzzz", "Z", "ffffffff", "FFFFFFFF", "100000000", "4294967295", "4294967296", "4294967297", "0xffffffff", "0x100000000", "037777777777", "040000000000", "-1", "-4294967295", "-4294967296", "-2147483648", "-2147483649", "2147483648", "0X1A",
		"1844674407370955161500", "99999999999999999999", "ffffffffffffffffff", "0000000000000000000000000000001", "0x0000000000000000000000000000001", "1\n\n", "1\t", " 1", "1 ", "1\r"};
	for (unsigned i = 0; i < sizeof edge / sizeof *edge; i++) one_string(edge[i]);
	for (int it = 0; it < 1500000; it++) {   /* random small-alphabet strings for strstr/strcmp */
		char u[64], v[8];
		int lu = rnd() % 40, lv = rnd() % 5;
		for (int i = 0; i < lu; i++) u[i] = "ab01"[rnd() % 4]; u[lu] = 0;
		for (int i = 0; i < lv; i++) v[i] = "ab01"[rnd() % 4]; v[lv] = 0;
		two_strings(u, v);
	}
	for (int it = 0; it < 1500000; it++) {   /* random strings with high bytes, whitespace, signs: strcmp/strncmp/strstr/memcmp ordering of bytes >= 0x80 */
		char u[24], v[24]; int lu = rnd() % 10, lv = rnd() % 10;
		for (int i = 0; i < lu; i++) { u[i] = (rnd() % 3 == 0) ? (char)(0x70 + rnd() % 0x20) : alpha[rnd() % NA]; } u[lu] = 0;
		if (rnd() % 2) { memcpy(v, u, lu + 1); lv = lu; if (lu && rnd() % 2) v[rnd() % lu] = (char)(rnd() % 255 + 1); v[lv] = 0; }
		else { for (int i = 0; i < lv; i++) v[i] = (rnd() % 3 == 0) ? (char)(0x70 + rnd() % 0x20) : alpha[rnd() % NA]; v[lv] = 0; }
		two_strings(u, v);
	}
	for (int it = 0; it < 2500000; it++) {     /* random numbers: strings of 1..26 digit chars (crosses 2^32 and 2^64), prefixes, junk, newline */
		char u[64]; int lu = 1 + rnd() % 26; int hex = rnd() & 1; int pre = rnd() % 6;
		int p = 0;
		if (pre == 1) u[p++] = '+'; if (pre == 2) u[p++] = '-'; if (pre == 3) { u[p++] = '0'; u[p++] = (rnd() & 1) ? 'x' : 'X'; } if (pre == 4) u[p++] = '0'; if (pre == 5) { u[p++] = '+'; u[p++] = '0'; u[p++] = 'x'; }
		const char *dig = hex ? "0123456789abcdefABCDEF" : "0123456789";
		int lead = rnd() % 4 ? 0 : 1 + rnd() % 6;   /* the top digits: all 9s / fs near a limit */
		for (int i = 0; i < lu; i++) u[p++] = (i < lead) ? (hex ? 'f' : '9') : dig[rnd() % (hex ? 22 : 10)];
		int post = rnd() % 16;
		if (post == 0) u[p++] = '\n'; else if (post == 1) { u[p++] = '\n'; u[p++] = '\n'; } else if (post == 2) u[p++] = "z:/`@g"[rnd() % 6]; else if (post == 3) u[p++] = ' '; else if (post == 4) u[p++] = (char)0x80 | (rnd() & 0x7f);
		u[p] = 0;
		one_string(u);
	}
	/* kstrtoull wrap quirk for bases > 16 (documented, the C wraps undetected when res < 2^60): identical in both */
	for (int it = 0; it < 300000; it++) {
		char u[40]; int lu = 1 + rnd() % 24; for (int i = 0; i < lu; i++) u[i] = "0123456789"[rnd() % 10]; u[lu] = 0;
		unsigned bb[] = {17, 20, 36, 100, 1000, 0x10000, 0x7fffffffu, 0xffffffffu}; unsigned b = bb[rnd() % 8];
		unsigned long long k1 = 0, k2 = 0; int r1 = c_kstrtoull(u, b, &k1), r2 = rs_kstrtoull(u, b, &k2);
		CHECK(r1 == r2 && k1 == k2, "kstrtoull big base \"%s\" %u: %d/%d", u, b, r1, r2);
	}
}

/* memcmp/bcmp at every length 0..40 and every differing position, both orderings (return is 0/1, never an ordering), guarded ends */
static void mem_tests(void)
{
	unsigned char a[64], b[64];
	for (size_t n = 0; n <= 40; n++) for (size_t pos = 0; pos <= n; pos++) for (int hi = 0; hi < 4; hi++) {
		for (int i = 0; i < 64; i++) a[i] = b[i] = (unsigned char)(i * 37 + 11 + (hi == 3 ? 0x80 : 0));
		if (pos < n) { b[pos] = hi == 0 ? a[pos] + 1 : hi == 1 ? a[pos] - 1 : a[pos] ^ 0x80; }
		long ps = sysconf(_SC_PAGESIZE);
		char *pa = G[2] + ps - n, *pb = G[3] + ps - n; memcpy(pa, a, n); memcpy(pb, b, n);
		int x = c_memcmp(pa, pb, n), y = rs_memcmp(pa, pb, n), x2 = c_bcmp(pa, pb, n), y2 = rs_bcmp(pa, pb, n);
		CHECK(x == y && x2 == y2 && x == x2 && x == (memcmp(pa, pb, n) != 0), "memcmp n=%zu pos=%zu hi=%d C=%d Rust=%d", n, pos, hi, x, y);
	}
	for (int it = 0; it < 2000000; it++) {
		size_t n = rnd() % 200; long ps = sysconf(_SC_PAGESIZE);
		char *pa = G[2] + ps - n, *pb = G[3] + ps - n;
		for (size_t i = 0; i < n; i++) pa[i] = pb[i] = (char)rnd();
		if (n && rnd() % 2) pb[rnd() % n] ^= (char)(1 << (rnd() % 8));
		int x = c_memcmp(pa, pb, n), y = rs_memcmp(pa, pb, n);
		CHECK(x == y && x == (memcmp(pa, pb, n) != 0), "random memcmp n=%zu", n);
	}
}

/* strnlen with maxlen below / at / above the length, strncmp counts around the NUL, exact-size (non-NUL-terminated at the end) buffers where the C reads: no read past maxlen+1 */
static void count_tests(void)
{
	for (int it = 0; it < 1500000; it++) {
		char u[40], v[40]; int lu = rnd() % 30; for (int i = 0; i < lu; i++) u[i] = "ab\x80\xff"[rnd() % 4]; u[lu] = 0;
		int lv = rnd() % 30; if (rnd() % 2) { memcpy(v, u, lu + 1); lv = lu; if (lu && rnd() % 2) v[rnd() % lu] = "ab\x80\xff"[rnd() % 4]; } else { for (int i = 0; i < lv; i++) v[i] = "ab\x80\xff"[rnd() % 4]; v[lv] = 0; }
		const char *s = gs(0, u), *t = gs(1, v);
		size_t m = rnd() % 34;
		CHECK(c_strnlen(s, m) == rs_strnlen(s, m) && rs_strnlen(s, m) == ((size_t)lu < m ? (size_t)lu : m), "strnlen %zu on len %d", m, lu);
		int a = c_strncmp(s, t, m), b = rs_strncmp(s, t, m); CHECK(a == b, "strncmp count %zu: %d/%d", m, a, b);
		/* strnlen with a buffer that has NO NUL at all but maxlen == its size - 1 reading one past is the C's quirk: tested with one spare byte */
		size_t sz = rnd() % 20; long ps = sysconf(_SC_PAGESIZE); char *pb = G[2] + ps - (sz + 1);
		for (size_t i = 0; i < sz; i++) pb[i] = 'q'; pb[sz] = 'z';   /* sz bytes + one byte that must be readable */
		CHECK(c_strnlen(pb, sz) == sz && rs_strnlen(pb, sz) == sz, "strnlen unterminated");
	}
}

int main(void)
{
	for (int i = 0; i < 4; i++) G[i] = guard_page();
	mem_tests();
	count_tests();
	str_tests();
	printf("checks=%llu failures=%llu\n", checks, fails);
	return fails != 0;
}
