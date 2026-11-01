/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/string.c (the 26 functions the Rust has): pristine C (c_*) vs string_rs.rs. Buffers sit at the END of a
 * page before an unmapped guard page (so an over-read by either arm faults); alphabet includes case pairs, NUL and bytes >= 0x80.
 * Pointer results are compared as offsets, mutated buffers byte for byte. usage: main SHARD ; STR_PROVE_CAN_FAIL=1 */
#include <stdio.h>
#include <stdlib.h>
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#define P(r, n, args) r c_##n args; r n args;
P(int, strncasecmp, (const char *, const char *, size_t)) P(int, strcasecmp, (const char *, const char *))
P(char *, strcpy, (char *, const char *)) P(char *, strncpy, (char *, const char *, size_t)) P(char *, stpcpy, (char *, const char *))
P(char *, strcat, (char *, const char *)) P(char *, strncat, (char *, const char *, size_t))
P(int, strcmp, (const char *, const char *)) P(int, strncmp, (const char *, const char *, size_t))
P(char *, strchr, (const char *, int)) P(char *, strchrnul, (const char *, int)) P(char *, strnchrnul, (const char *, size_t, int))
P(char *, strrchr, (const char *, int)) P(char *, strnchr, (const char *, size_t, int))
P(size_t, strlen, (const char *)) P(size_t, strnlen, (const char *, size_t)) P(size_t, strspn, (const char *, const char *)) P(size_t, strcspn, (const char *, const char *))
P(char *, strpbrk, (const char *, const char *)) P(char *, strsep, (char **, const char *))
P(int, memcmp, (const void *, const void *, size_t)) P(int, bcmp, (const void *, const void *, size_t))
P(void *, memscan, (void *, int, size_t)) P(char *, strstr, (const char *, const char *)) P(char *, strnstr, (const char *, const char *, size_t))
P(void *, memchr, (const void *, int, size_t)) P(void *, memchr_inv, (const void *, int, size_t))

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static char *page_end;
static const unsigned char alpha[] = { 'a', 'b', 'A', 'B', 'z', 'Z', ' ', '/', 0x80, 0xc3, 0xff, '\n' };
/* write a random string of length len (no NUL inside) followed by NUL, ending exactly at the end of the page (with `slack` extra bytes after NUL inside the page) */
static char *mkstr(int len, int nul, int *out_len, int slot)
{
	static char *slotp[4];
	char *p = page_end - 1024 * (slot + 1);        /* four disjoint areas, each ends at its own boundary; only slot 0 is at the page end */
	if (slot == 0) p = page_end - (len + (nul ? 1 : 0));
	for (int i = 0; i < len; i++) p[i] = alpha[rnd() % (rnd() % 3 ? 4 : sizeof alpha)];
	if (nul) p[len] = 0;
	slotp[slot] = p; *out_len = len;
	return p;
}
#define CMPI(w, a, b) do { checks++; if ((a) != (b)) FAIL("MISMATCH %s c=%d rs=%d\n", w, (int)(a), (int)(b)); } while (0)
#define CMPP(w, base, a, b) do { checks++; if (((a) ? (long)((char *)(a) - (base)) : -1) != ((b) ? (long)((char *)(b) - (base)) : -1)) FAIL("MISMATCH %s\n", w); } while (0)
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("STR_N") ? atoll(getenv("STR_N")) : 3000000LL;
	poison = getenv("STR_PROVE_CAN_FAIL") != 0;
	long pg = sysconf(_SC_PAGESIZE);
	char *m = mmap(0, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m + 3 * pg, pg, PROT_NONE); page_end = m + 3 * pg;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		int l1, l2, la, lb;
		int len1 = rnd() % 40, len2 = rnd() % 8;
		int nul1 = rnd() % 8 != 0;
		char *s1 = mkstr(len1, 1, &l1, 0);          /* NUL-terminated at page end */
		char *s2 = mkstr(len2, 1, &l2, 1);
		size_t cnt = rnd() % 50;
		int c = (int)(unsigned char)alpha[rnd() % sizeof alpha] | ((rnd() % 4 == 0) ? 0x100 : 0), z = (rnd() % 10 == 0) ? 0 : c;
		(void)nul1; (void)la; (void)lb;
		CMPI("strcmp", c_strcmp(s1, s2) , strcmp(s1, s2));
		CMPI("strncmp", c_strncmp(s1, s2, cnt), strncmp(s1, s2, cnt));
		CMPI("strcasecmp", c_strcasecmp(s1, s2), strcasecmp(s1, s2));
		CMPI("strncasecmp", c_strncasecmp(s1, s2, cnt), strncasecmp(s1, s2, cnt));
		CMPI("strlen", c_strlen(s1), strlen(s1));
		CMPI("strnlen", c_strnlen(s1, cnt), strnlen(s1, cnt));
		CMPI("strspn", c_strspn(s1, s2), strspn(s1, s2));
		CMPI("strcspn", c_strcspn(s1, s2), strcspn(s1, s2));
		CMPP("strchr", s1, c_strchr(s1, z), strchr(s1, z));
		CMPP("strchrnul", s1, c_strchrnul(s1, z), strchrnul(s1, z));
		CMPP("strnchrnul", s1, c_strnchrnul(s1, cnt, z), strnchrnul(s1, cnt, z));
		CMPP("strrchr", s1, c_strrchr(s1, z), strrchr(s1, z));
		CMPP("strnchr", s1, c_strnchr(s1, cnt, z), strnchr(s1, cnt, z));
		CMPP("strpbrk", s1, c_strpbrk(s1, s2), strpbrk(s1, s2));
		CMPP("strstr", s1, c_strstr(s1, s2), strstr(s1, s2));
				size_t mlen = cnt < (size_t)l1 + 1 ? cnt : (size_t)l1 + 1;           /* memory ops stay inside s1's bytes */
		CMPP("strnstr", s1, c_strnstr(s1, s2, mlen), strnstr(s1, s2, mlen));
		CMPP("memchr", s1, c_memchr(s1, z, mlen), memchr(s1, z, mlen));
		CMPP("memscan", s1, c_memscan(s1, z, mlen), memscan(s1, z, mlen));
		CMPP("memchr_inv", s1, c_memchr_inv(s1, z, mlen), memchr_inv(s1, z, mlen));
		/* memchr_inv on a long uniform run with one odd byte, at every alignment */
		{
			char *u = page_end - 3 * 1024 - 64 + (rnd() % 8); size_t ul = 17 + rnd() % 40; int vb = z & 0xff;
			for (size_t i = 0; i < ul; i++) u[i] = vb;
			if (rnd() % 2) u[rnd() % ul] = vb ^ (1 + rnd() % 255);
			CMPP("memchr_inv-run", u, c_memchr_inv(u, vb, ul), memchr_inv(u, vb, ul));
		}
		size_t clen = mlen < (size_t)l2 + 1 ? mlen : (size_t)l2 + 1;
		CMPI("memcmp", (c_memcmp(s1, s2, clen)), (memcmp(s1, s2, clen)));
		CMPI("bcmp", (c_bcmp(s1, s2, clen) != 0), (bcmp(s1, s2, clen) != 0));
		{       /* memcmp over 8..40 equal-prefixed bytes (the word-skip path) */
			char *x = page_end - 3 * 1024 - 256, *y = x + 100; size_t ml = rnd() % 41;
			for (size_t i = 0; i < ml; i++) x[i] = y[i] = alpha[rnd() % 4];
			if (ml && rnd() % 2) y[rnd() % ml] ^= 1 + rnd() % 255;
			int a = c_memcmp(x, y, ml), b = memcmp(x, y, ml);
			if (poison && it == 5) b++;
			CMPI("memcmp-long", a, b);
		}
		/* mutators into canary-filled buffers */
		char da[128], db[128];
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db);
		size_t pre = rnd() % 12;
		memcpy(da, s2, l2 + 1); memcpy(db, s2, l2 + 1);                        /* existing dest string */
		char *r1 = c_strcat(da, s1), *r2 = strcat(db, s1);
		checks++; if (r1 != da || r2 != db || memcmp(da, db, sizeof da) || strlen(da) != c_strlen(db)) FAIL("MISMATCH strcat\n");
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db); memcpy(da, s2, l2 + 1); memcpy(db, s2, l2 + 1);
		c_strncat(da, s1, cnt % 60); strncat(db, s1, cnt % 60);
		checks++; if (memcmp(da, db, sizeof da)) FAIL("MISMATCH strncat cnt=%zu\n", cnt % 60);
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db);
		c_strcpy(da + pre, s1); strcpy(db + pre, s1);
		checks++; if (memcmp(da, db, sizeof da)) FAIL("MISMATCH strcpy\n");
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db);
		char *e1 = c_stpcpy(da + pre, s1), *e2 = stpcpy(db + pre, s1);
		checks++; if ((e1 - da) != (e2 - db) || memcmp(da, db, sizeof da)) FAIL("MISMATCH stpcpy\n");
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db);
		c_strncpy(da + pre, s1, cnt); strncpy(db + pre, s1, cnt);
		checks++; if (memcmp(da, db, sizeof da)) FAIL("MISMATCH strncpy cnt=%zu\n", cnt);
		/* strsep on a writable copy */
		memset(da, 0x5A, sizeof da); memset(db, 0x5A, sizeof db);
		memcpy(da, s1, l1 + 1); memcpy(db, s1, l1 + 1);
		char *pa = (rnd() % 10 == 0) ? NULL : da, *pb = pa ? db : NULL;
		char *ra = c_strsep(&pa, s2), *rb = strsep(&pb, s2);
		checks++; if ((ra ? ra - da : -1) != (rb ? rb - db : -1) || (pa ? pa - da : -1) != (pb ? pb - db : -1) || memcmp(da, db, sizeof da)) FAIL("MISMATCH strsep\n");
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
