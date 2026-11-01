/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/parser.c: pristine C (c_*) vs parser_rs.rs, both against the same strto*() helpers defined here and the
 * pristine lib/ctype.c table. Random pattern tables, option strings (valid, near-miss, width/%% forms), substrings for the number
 * extractors, and wildcard pairs; token, every arg offset, results and return codes compared. Strings sit at the end of a page
 * before an unmapped guard page. usage: main SHARD ; PARSER_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint64_t u64;
struct match_token { int token; const char *pattern; };
typedef struct { char *from; char *to; } substring_t;
#define DECL(n, ...) int c_##n(__VA_ARGS__), n(__VA_ARGS__);
int c_match_token(char *, const struct match_token *, substring_t *), match_token(char *, const struct match_token *, substring_t *);
int c_match_int(substring_t *, int *), match_int(substring_t *, int *);
int c_match_uint(substring_t *, unsigned *), match_uint(substring_t *, unsigned *);
int c_match_u64(substring_t *, u64 *), match_u64(substring_t *, u64 *);
int c_match_octal(substring_t *, int *), match_octal(substring_t *, int *);
int c_match_hex(substring_t *, int *), match_hex(substring_t *, int *);
bool c_match_wildcard(const char *, const char *), match_wildcard(const char *, const char *);
size_t c_match_strlcpy(char *, const substring_t *, size_t), match_strlcpy(char *, const substring_t *, size_t);

static int nows(const char *s) { return !(*s == ' ' || (*s >= 9 && *s <= 13)); }
long simple_strtol(const char *cp, char **endp, unsigned base) { if (!nows(cp)) { if (endp) *endp = (char *)cp; return 0; } return strtol(cp, endp, base); }
unsigned long simple_strtoul(const char *cp, char **endp, unsigned base) { if (!nows(cp) || *cp == '-' || *cp == '+') { if (endp) *endp = (char *)cp; return 0; } return strtoul(cp, endp, base); }
int kstrtoull(const char *s, unsigned base, u64 *res) { char *e; if (!*s || !nows(s) || *s == '-') return -EINVAL; errno = 0; u64 v = strtoull(s, &e, base); if (errno) return -ERANGE; if (*e && !(e[0] == '\n' && !e[1])) return -EINVAL; if (e == s) return -EINVAL; *res = v; return 0; }
int kstrtouint(const char *s, unsigned base, unsigned *res) { u64 v; int r = kstrtoull(s, base, &v); if (r) return r; if (v != (unsigned)v) return -ERANGE; *res = v; return 0; }

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static char *page_end;
static char *put(const char *s) { size_t n = strlen(s) + 1; char *p = page_end - n; memcpy(p, s, n); return p; }
static char *put_at(const char *s, size_t back) { size_t n = strlen(s) + 1; char *p = page_end - back - n; memcpy(p, s, n); return p; }

static const char *pats[] = { "ro", "rw", "size=%d", "mode=%o", "uid=%u", "x=%x", "name=%s", "name=%3s", "tag=%%%s", "%%", "a=%d,b=%d", "a=%d,b=%d,c=%d,d=%d",
	"%4294967295s", "w=%0s", "k=%d%s", "%", "n=%q", "dev=%s:%d", "opt", "opt=%s", "=%d", "%d", "%s", "%12345678901234567890s", "n=%10s", "n=%12s", "%0010s" };
static const char *words[] = { "ro", "rw", "size=10", "size=-5", "size=0x1f", "size=", "mode=777", "mode=9", "uid=42", "x=ff", "x=0xFF", "x=g", "name=abc", "name=abcdef", "n=abcdefghijklmnopq", "n=0123456789abcdef0123", "n=ab", "name=",
	"tag=%x", "tag=%", "%", "a=1,b=2", "a=1,b=2,c=3,d=4", "k=5abc", "dev=sda:3", "opt", "opt=1", "12", "-3", "abc", "", "  7" };
static int gen_table(struct match_token *t, int *n)
{
	int k = 1 + rnd() % 6;
	for (int i = 0; i < k; i++) { t[i].token = 100 + i; t[i].pattern = pats[rnd() % (sizeof pats / sizeof *pats)]; }
	t[k].token = -1; t[k].pattern = NULL; *n = k; return k;
}
static void cmp_args(const char *what, const char *s, substring_t *a, substring_t *b, int ra, int rb)
{
	checks++;
	if (poison && ra == 101 && rb == 101) rb++;
	int bad = ra != rb;
	for (int i = 0; i < 3; i++) if ((a[i].from != b[i].from) || (a[i].to != b[i].to)) bad = 1;
	if (bad) FAIL("%s MISMATCH '%s' c=%d rs=%d\n", what, s, ra, rb);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("PARSER_N") ? atoll(getenv("PARSER_N")) : 5000000LL;
	poison = getenv("PARSER_PROVE_CAN_FAIL") != 0;
	long pg = sysconf(_SC_PAGESIZE);
	char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m + pg, pg, PROT_NONE); page_end = m + pg;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		struct match_token tab[8]; int k;
		gen_table(tab, &k);
		char *s = put(words[rnd() % (sizeof words / sizeof *words)]);
		substring_t a[3], b[3];
		memset(a, 0x55, sizeof a); memset(b, 0x55, sizeof b);
		int ra = c_match_token(s, tab, a), rb = match_token(s, tab, b);
		cmp_args("match_token", s, a, b, ra, rb);
		/* number extractors on a random substring of a digit-ish string */
		static const char *nums[] = { "123", "-45", "0x1f", "017", "99999999999", "-2147483648", "2147483648", "4294967295", "4294967296", "18446744073709551615", "18446744073709551616", "abc", "", "0", "12345678901234567890123", "1 2", "0xg", "2147483647", "-2147483649", "123456789012345678901234", "12345678901234567890123", "-2147483648 " };
		char *ns = put(nums[rnd() % (sizeof nums / sizeof *nums)]);
		substring_t sub = { ns, ns + strlen(ns) };
		if (rnd() % 4 == 0 && strlen(ns)) sub.to = ns + rnd() % (strlen(ns) + 1);
		int ia = 0x5555, ib = 0x5555; unsigned ua = 0x5555, ub = 0x5555; u64 xa = 0x5555, xb = 0x5555;
		int r1 = c_match_int(&sub, &ia), r2 = match_int(&sub, &ib);
		checks++; if (r1 != r2 || ia != ib) FAIL("match_int '%s' c=%d/%d rs=%d/%d\n", ns, r1, ia, r2, ib);
		r1 = c_match_octal(&sub, &ia); r2 = match_octal(&sub, &ib);
		checks++; if (r1 != r2 || ia != ib) FAIL("match_octal '%s'\n", ns);
		r1 = c_match_hex(&sub, &ia); r2 = match_hex(&sub, &ib);
		checks++; if (r1 != r2 || ia != ib) FAIL("match_hex '%s'\n", ns);
		r1 = c_match_uint(&sub, &ua); r2 = match_uint(&sub, &ub);
		checks++; if (r1 != r2 || ua != ub) FAIL("match_uint '%s'\n", ns);
		r1 = c_match_u64(&sub, &xa); r2 = match_u64(&sub, &xb);
		checks++; if (r1 != r2 || xa != xb) FAIL("match_u64 '%s'\n", ns);
		/* strlcpy */
		char da[16], db[16]; size_t sz = rnd() % 14;
		memset(da, 0xA5, sizeof da); memset(db, 0xA5, sizeof db);
		size_t q1 = c_match_strlcpy(da, &sub, sz), q2 = match_strlcpy(db, &sub, sz);
		checks++; if (q1 != q2 || memcmp(da, db, sizeof da)) FAIL("match_strlcpy '%s' sz=%zu\n", ns, sz);
		/* wildcard */
		char pbuf[12], sbuf[12]; int pl = rnd() % 8, sl = rnd() % 9;
		for (int i = 0; i < pl; i++) pbuf[i] = "ab*?"[rnd() % 4]; pbuf[pl] = 0;
		for (int i = 0; i < sl; i++) sbuf[i] = "abab"[rnd() % 4]; sbuf[sl] = 0;
		char *pp = put_at(pbuf, 0); char *ss = put_at(sbuf, 64);
		bool w1 = c_match_wildcard(pp, ss), w2 = match_wildcard(pp, ss);
		checks++; if (w1 != w2) FAIL("match_wildcard '%s' '%s' c=%d rs=%d\n", pbuf, sbuf, w1, w2);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
