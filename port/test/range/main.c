/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for kernel/range.c: pristine C (c_*) vs range_rs.rs. Both call the same sort() (a stable insertion
 * sort defined here) and report the same pr_err through _printk/kshim_printk, which this file records.
 * Random small arrays (az 0..8, values 0..16 so overlaps are constant) and wide values; whole array + canary + message log compared.
 * usage: main SHARD NSHARDS ; RANGE_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
typedef uint64_t u64;
struct range { u64 start; u64 end; };
int c_add_range(struct range *, int, int, u64, u64);
int c_add_range_with_merge(struct range *, int, int, u64, u64);
void c_subtract_range(struct range *, int, u64, u64);
int c_clean_sort_range(struct range *, int);
void c_sort_range(struct range *, int);
int add_range(struct range *, int, int, u64, u64);
int add_range_with_merge(struct range *, int, int, u64, u64);
void subtract_range(struct range *, int, u64, u64);
int clean_sort_range(struct range *, int);
void sort_range(struct range *, int);

static char log_c[4096], log_r[4096]; static char *logp; static int poison;
static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
void kshim_printk(const char *func, const char *msg) { char b[128]; snprintf(b, sizeof b, "<3>"); strcat(logp, b); snprintf(b, sizeof b, msg, func); strcat(logp, b); }
int _printk(const char *fmt, ...) { va_list ap; char b[128]; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt + 2, ap); va_end(ap); strcat(logp, "<"); strncat(logp, fmt + 1, 1); strcat(logp, ">"); strcat(logp, b); va_end(ap); return 0; }
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int))
{
	char *p = base, tmp[64];
	(void)swap;
	for (size_t i = 1; i < num; i++) {
		memcpy(tmp, p + i * size, size);
		size_t j = i;
		while (j > 0 && (cmp(p + (j - 1) * size, tmp) > 0 || cmp(tmp, p + (j - 1) * size) < 0)) { memcpy(p + j * size, p + (j - 1) * size, size); j--; }
		memcpy(p + j * size, tmp, size);
	}
}
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static u64 val(int wide) { return wide ? (rnd() % 4 ? rnd() : (rnd() & 1 ? ~0ULL - rnd() % 4 : rnd() % 4)) : rnd() % 17; }

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("RANGE_N") ? atoll(getenv("RANGE_N")) : 30000000LL;
	poison = getenv("RANGE_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		struct range a[12], b[12];
		int az = rnd() % 9, wide = rnd() % 4 == 0, nr = az ? rnd() % (az + 1) : 0, op = rnd() % 5;
		for (int i = 0; i < 12; i++) {
			a[i].start = val(wide); a[i].end = (rnd() % 5 == 0) ? 0 : val(wide);
			if (i >= nr && rnd() % 3) { a[i].start = 0; a[i].end = 0; }
			if (i >= az) { a[i].start = 0xC0FFEE; a[i].end = 0xBEEF; }   /* canary beyond az */
		}
		memcpy(b, a, sizeof a);
		u64 s = val(wide), e = val(wide);
		int ra = 0, rb = 0;
		log_c[0] = log_r[0] = 0;
		logp = log_c;
		switch (op) {
		case 0: ra = c_add_range(a, az, nr, s, e); logp = log_r; rb = add_range(b, az, nr, s, e); break;
		case 1: ra = c_add_range_with_merge(a, az, nr, s, e); logp = log_r; rb = add_range_with_merge(b, az, nr, s, e); break;
		case 2: c_subtract_range(a, az, s, e); logp = log_r; subtract_range(b, az, s, e); break;
		case 3: ra = c_clean_sort_range(a, az); logp = log_r; rb = clean_sort_range(b, az); break;
		default: c_sort_range(a, nr); logp = log_r; sort_range(b, nr); break;
		}
		if (poison && op == 0 && s < e && nr < az) rb++;
		checks++;
		if (ra != rb || memcmp(a, b, sizeof a) || strcmp(log_c, log_r)) {
			FAIL("MISMATCH op=%d az=%d nr=%d s=%llu e=%llu c=%d rs=%d logs '%s' / '%s'\n", op, az, nr, (unsigned long long)s, (unsigned long long)e, ra, rb, log_c, log_r);
		}
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
