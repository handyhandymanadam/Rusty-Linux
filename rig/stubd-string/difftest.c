// Differential test: the stub's ORIGINAL C string.o (symbols prefixed c_) against the Rust string_rs.o
// (symbols prefixed rs_), both objects as built for the stub, plus libc as a reference for mem*.
// Built and run by rig/stubd-string/run.sh. Exit status 0 = no difference found.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DECL(P) \
 void *P##memcpy(void*,const void*,size_t); void *P##memmove(void*,const void*,size_t); \
 void *P##memset(void*,int,size_t); int P##memcmp(const void*,const void*,size_t); \
 int P##bcmp(const void*,const void*,size_t); int P##strcmp(const char*,const char*); \
 int P##strncmp(const char*,const char*,size_t); size_t P##strnlen(const char*,size_t); \
 size_t P##strlen(const char*); char *P##strstr(const char*,const char*); char *P##strchr(const char*,int); \
 unsigned long long P##simple_strtoull(const char*,char**,unsigned); long P##simple_strtol(const char*,char**,unsigned); \
 int P##kstrtoull(const char*,unsigned,unsigned long long*); int P##boot_kstrtoul(const char*,unsigned,unsigned long*);
DECL(c_) DECL(rs_)

static unsigned c_warns, rs_warns;
void c_warn(const char *m)  { c_warns++;  if (strcmp(m, "Avoiding potentially unsafe overlapping memcpy()!")) abort(); }
void rs_warn(const char *m) { rs_warns++; if (strcmp(m, "Avoiding potentially unsafe overlapping memcpy()!")) abort(); }

static unsigned long long checks, fails;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { if (fails++ < 20) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

/* ---- memory functions ---- */
#define BUF 512
static void mem_tests(void)
{
	static unsigned char a[BUF], b[BUF], ref[BUF], base[BUF];
	for (int i = 0; i < BUF; i++) base[i] = (unsigned char)(i * 37 + 11);

	/* every size 0..96, every destination/source offset pair in a 160 byte window: overlap in all shapes */
	for (size_t n = 0; n <= 96; n++)
	for (int d = 0; d < 160; d++)
	for (int s = 0; s < 160; s++) {
		for (int fn = 0; fn < 2; fn++) {           /* 0 = memmove, 1 = memcpy */
			memcpy(a, base, BUF); memcpy(b, base, BUF); memcpy(ref, base, BUF);
			unsigned cw = c_warns, rw = rs_warns;
			void *ra, *rb;
			if (fn == 0) { ra = c_memmove(a + d, a + s, n); rb = rs_memmove(b + d, b + s, n); memmove(ref + d, ref + s, n); }
			else         { ra = c_memcpy(a + d, a + s, n);  rb = rs_memcpy(b + d, b + s, n);  memmove(ref + d, ref + s, n); }
			CHECK(ra == a + d && rb == b + d, "return value fn=%d n=%zu d=%d s=%d", fn, n, d, s);
			CHECK(!memcmp(a, b, BUF), "C vs Rust buffers differ fn=%d n=%zu d=%d s=%d", fn, n, d, s);
			CHECK(!memcmp(b, ref, BUF), "Rust vs libc memmove differ fn=%d n=%zu d=%d s=%d", fn, n, d, s);
			CHECK(c_warns - cw == rs_warns - rw, "warn count differs fn=%d n=%zu d=%d s=%d", fn, n, d, s);
			if (fn == 0) CHECK(c_warns == cw && rs_warns == rw, "memmove must not warn");
			else         CHECK(((c_warns - cw) == 1) == (d > s && (size_t)(d - s) < n), "memcpy warn rule n=%zu d=%d s=%d", n, d, s);
		}
	}
	/* larger sizes, random offsets (crosses the 8-byte rep movsq/movsb split many ways) */
	for (int it = 0; it < 200000; it++) {
		size_t n = rnd() % 300; int d = rnd() % (BUF - 300), s = rnd() % (BUF - 300);
		memcpy(a, base, BUF); memcpy(b, base, BUF); memcpy(ref, base, BUF);
		c_memmove(a + d, a + s, n); rs_memmove(b + d, b + s, n); memmove(ref + d, ref + s, n);
		CHECK(!memcmp(a, b, BUF) && !memcmp(b, ref, BUF), "random memmove n=%zu d=%d s=%d", n, d, s);
	}
	/* memset: every size, every offset, every byte value (c is an int: also values > 255 and negative) */
	int vals[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1a5, -1, -128, 0x12345678, (int)0x80000000};
	for (size_t n = 0; n <= 70; n++) for (int o = 0; o < 20; o++) for (unsigned v = 0; v < sizeof vals / sizeof *vals; v++) {
		memcpy(a, base, BUF); memcpy(b, base, BUF);
		void *ra = c_memset(a + o, vals[v], n), *rb = rs_memset(b + o, vals[v], n);
		memset(ref, 0, BUF); memcpy(ref, base, BUF); memset(ref + o, (unsigned char)vals[v], n);
		CHECK(ra == a + o && rb == b + o && !memcmp(a, b, BUF) && !memcmp(b, ref, BUF), "memset n=%zu o=%d v=%d", n, o, vals[v]);
	}
	/* memcmp/bcmp: return value too (the stub's returns only 0 or 1) */
	for (size_t n = 0; n <= 40; n++) for (size_t pos = 0; pos <= n; pos++) for (int hi = 0; hi < 3; hi++) {
		memcpy(a, base, BUF); memcpy(b, base, BUF);
		if (pos < n) b[pos] = hi == 0 ? a[pos] + 1 : hi == 1 ? a[pos] - 1 : a[pos] ^ 0x80;
		int x = c_memcmp(a, b, n), y = rs_memcmp(a, b, n), x2 = c_bcmp(a, b, n), y2 = rs_bcmp(a, b, n);
		CHECK(x == y && x2 == y2 && x == x2 && x == (memcmp(a, b, n) != 0), "memcmp n=%zu pos=%zu hi=%d C=%d Rust=%d", n, pos, hi, x, y);
	}
}

/* ---- string functions ---- */
static const char alpha[] = "0189aAfFgGxX+- \n\t\x80\xff";   /* digits, hex letters, non-hex letters, x, signs, whitespace, high bytes */
#define NA (sizeof alpha - 1)

static void one_string(const char *s)
{
	size_t l = strlen(s);
	CHECK(c_strlen(s) == l && rs_strlen(s) == l, "strlen");
	for (size_t m = 0; m <= l + 2 && m < 12; m++) CHECK(c_strnlen(s, m) == rs_strnlen(s, m), "strnlen %zu", m);
	int cs[] = {0, 'x', 'X', '0', 'a', '-', '\n', 0x80, 0xff, 0x178, -128, -1, 0x30000};
	for (unsigned i = 0; i < sizeof cs / sizeof *cs; i++) CHECK(c_strchr(s, cs[i]) == rs_strchr(s, cs[i]), "strchr %d on %s", cs[i], s);
	unsigned bases[] = {0, 1, 2, 8, 10, 16, 17, 36, 0xffffffffu};
	for (unsigned i = 0; i < sizeof bases / sizeof *bases; i++) {
		unsigned b = bases[i];
		char *e1 = (char *)1, *e2 = (char *)1;
		unsigned long long v1 = c_simple_strtoull(s, &e1, b), v2 = rs_simple_strtoull(s, &e2, b);
		CHECK(v1 == v2 && e1 == e2, "simple_strtoull \"%s\" base %u: %llx/%llx end %ld/%ld", s, b, v1, v2, (long)(e1 - s), (long)(e2 - s));
		e1 = e2 = (char *)1;
		long w1 = c_simple_strtol(s, &e1, b), w2 = rs_simple_strtol(s, &e2, b);
		CHECK(w1 == w2 && e1 == e2, "simple_strtol \"%s\" base %u", s, b);
		CHECK(c_simple_strtoull(s, 0, b) == rs_simple_strtoull(s, 0, b) && c_simple_strtol(s, 0, b) == rs_simple_strtol(s, 0, b), "strtox NULL endp");
		unsigned long long k1 = 0x1111, k2 = 0x1111; unsigned long u1 = 0x2222, u2 = 0x2222;
		int r1 = c_kstrtoull(s, b, &k1), r2 = rs_kstrtoull(s, b, &k2);
		CHECK(r1 == r2 && k1 == k2, "kstrtoull \"%s\" base %u: %d/%d %llx/%llx", s, b, r1, r2, k1, k2);
		r1 = c_boot_kstrtoul(s, b, &u1); r2 = rs_boot_kstrtoul(s, b, &u2);
		CHECK(r1 == r2 && u1 == u2, "boot_kstrtoul \"%s\" base %u", s, b);
	}
}

static void two_strings(const char *s, const char *t)
{
	int x = c_strcmp(s, t), y = rs_strcmp(s, t);
	CHECK(x == y, "strcmp \"%s\" \"%s\" %d/%d", s, t, x, y);
	for (size_t m = 0; m < 6; m++) CHECK(c_strncmp(s, t, m) == rs_strncmp(s, t, m), "strncmp \"%s\" \"%s\" %zu", s, t, m);
	CHECK(c_strstr(s, t) == rs_strstr(s, t), "strstr \"%s\" \"%s\"", s, t);
	if (strlen(t) && strlen(s) && !strstr(s, t)) { /* and against libc as a reference where well defined */ }
	else if (strlen(t)) CHECK(rs_strstr(s, t) == strstr(s, t), "strstr vs libc");
}

static void str_tests(void)
{
	char s[16], t[16];
	/* exhaustive: every string of length 0..5 over the alphabet, single-string functions */
	size_t idx[6];
	for (int len = 0; len <= 5; len++) {
		size_t total = 1; for (int i = 0; i < len; i++) total *= NA;
		for (size_t k = 0; k < total; k++) {
			size_t kk = k; for (int i = 0; i < len; i++) { s[i] = alpha[kk % NA]; kk /= NA; } s[len] = 0;
			one_string(s);
		}
	}
	/* exhaustive pairs of length 0..3 */
	for (int l1 = 0; l1 <= 3; l1++) for (int l2 = 0; l2 <= 3; l2++) {
		size_t t1 = 1, t2 = 1; for (int i = 0; i < l1; i++) t1 *= NA; for (int i = 0; i < l2; i++) t2 *= NA;
		for (size_t a = 0; a < t1; a++) for (size_t b = 0; b < t2; b++) {
			size_t aa = a, bb = b;
			for (int i = 0; i < l1; i++) { s[i] = alpha[aa % NA]; aa /= NA; } s[l1] = 0;
			for (int i = 0; i < l2; i++) { t[i] = alpha[bb % NA]; bb /= NA; } t[l2] = 0;
			two_strings(s, t);
		}
	}
	(void)idx;
	/* random longer strings over a small alphabet (so strstr/strcmp actually match) and number strings near overflow */
	static const char *edge[] = {"18446744073709551615", "18446744073709551616", "18446744073709551614", "1844674407370955161", "18446744073709551620",
		"0xffffffffffffffff", "0x10000000000000000", "0xFFFFFFFFFFFFFFFF", "0XfffffffffffffffF\n", "01777777777777777777777", "02000000000000000000000",
		"1777777777777777777777", "2000000000000000000000", "+12", "+0x1f", "-12", "+-1", "0x", "0xg", "0x1g", "08", "0 ", "5\n", "5\n\n", "5\n ", "\n", "",
		"0x7fffffffffffffff", "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "-18446744073709551615",
		"zzzz", "Z", "ffffffff", "FFFFFFFF", "100000000", "4294967296", "0X1A"};
	for (unsigned i = 0; i < sizeof edge / sizeof *edge; i++) one_string(edge[i]);
	for (int it = 0; it < 300000; it++) {
		char u[40], v[8];
		int lu = rnd() % 38, lv = rnd() % 5;
		for (int i = 0; i < lu; i++) u[i] = "ab01"[rnd() % 4]; u[lu] = 0;
		for (int i = 0; i < lv; i++) v[i] = "ab01"[rnd() % 4]; v[lv] = 0;
		two_strings(u, v);
	}
	for (int it = 0; it < 300000; it++) {     /* random numbers: all-digit strings of 1..24 chars (crosses the 2^64 limit), all bases */
		char u[40]; int lu = 1 + rnd() % 24; int hex = rnd() & 1; int pre = rnd() % 4;
		int p = 0;
		if (pre == 1) u[p++] = '+'; if (pre == 2) u[p++] = '-'; if (pre == 3) { u[p++] = '0'; u[p++] = (rnd() & 1) ? 'x' : 'X'; }
		for (int i = 0; i < lu; i++) u[p++] = (hex ? "0123456789abcdefABCDEF" : "0123456789")[rnd() % (hex ? 22 : 10)];
		if (rnd() % 8 == 0) u[p++] = '\n';
		if (rnd() % 16 == 0) u[p++] = 'z';
		u[p] = 0;
		one_string(u);
	}
}

int main(void)
{
	mem_tests();
	str_tests();
	printf("checks=%llu failures=%llu\n", checks, fails);
	return fails != 0;
}
