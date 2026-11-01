/* Shared environment for both sides: the printk log (one per side), BUG_ON capture, boot_params, max_pfn,
 * memparse (the REAL C, cut from the pristine lib/cmdline.c), simple_strtoull (a faithful re-implementation of
 * lib/vsprintf.c + lib/kstrtox.c: test support, not under test), and sort (the REAL pristine lib/sort.c, see
 * e820_sort.c; mode 1 swaps in a stable insertion sort to test tie-order independence). */
#include "e820_shim.h"
#include <stdarg.h>
#include <ctype.h>
jmp_buf g_bug_jmp; const char *g_bug_file; int g_bug_line; int g_bug_armed;
void bug_hit(const char *file, int line) { g_bug_file = file; g_bug_line = line; longjmp(g_bug_jmp, 1); }
struct boot_params boot_params; unsigned long max_pfn; unsigned long g_maxmem = 1UL << 46; u64 max_mem_size;

#define LOGMAX (1 << 22)
static char logbuf[2][LOGMAX]; static size_t loglen[2]; static int side;
void log_side(int s) { side = s; }
void log_reset(void) { loglen[0] = loglen[1] = 0; }
size_t log_len(int s) { return loglen[s]; }
const char *log_buf(int s) { return logbuf[s]; }
int _printk(const char *fmt, ...) {
	char tmp[1024]; va_list ap; va_start(ap, fmt);
	int n = vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
	/* a record: the whole string including the \001 level byte, then a \n separator */
	size_t k = n < 0 ? 0 : (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1;
	if (loglen[side] + k + 2 < LOGMAX) { memcpy(logbuf[side] + loglen[side], tmp, k); loglen[side] += k; logbuf[side][loglen[side]++] = '\x02'; }
	return n;
}
#include MEMPARSE_INC
static int dig(int c) { c = tolower(c); return isdigit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : 99; }
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base) {
	/* _parse_integer_fixup_radix */
	if (base == 0) {
		if (cp[0] == '0') { if (tolower(cp[1]) == 'x' && isxdigit((unsigned char)cp[2])) base = 16; else base = 8; }
		else base = 10;
	}
	if (base == 16 && cp[0] == '0' && tolower(cp[1]) == 'x') cp += 2;
	unsigned long long res = 0; unsigned rv = 0;
	while (1) {
		int v = dig((unsigned char)cp[rv]);
		if (v >= (int)base) break;
		res = res * base + v; rv++;       /* wraps, like _parse_integer (it only flags overflow) */
	}
	if (endp) *endp = (char *)cp + rv;
	return res;
}
void k_sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int));
int g_sort_mode; unsigned long g_sort_calls;
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int)) {
	g_sort_calls++;
	if (g_sort_mode == 0) { k_sort(base, num, size, cmp, swap); return; }
	/* stable insertion sort (tie order = input order) */
	char *b = base, tmp[64];
	for (size_t i = 1; i < num; i++) {
		memcpy(tmp, b + i * size, size); size_t j = i;
		while (j > 0 && cmp(b + (j - 1) * size, tmp) > 0) { memcpy(b + j * size, b + (j - 1) * size, size); j--; }
		memcpy(b + j * size, tmp, size);
	}
}
void set_bug_armed(int a) { g_bug_armed = a; }
int bug_setjmp_dummy(void) { return 0; }
const char *bug_file(void) { return g_bug_file; } int bug_line(void) { return g_bug_line; }
void set_boot_params(const unsigned char *p) { memcpy(&boot_params, p, sizeof boot_params); }
void set_max_pfn(unsigned long v) { max_pfn = v; } void set_maxmem(unsigned long v) { g_maxmem = v; }
void set_max_mem_size(u64 v) { max_mem_size = v; } u64 get_max_mem_size(void) { return max_mem_size; }
void set_sort_mode(int m) { g_sort_mode = m; }
/* run a parse function under a BUG_ON guard (a "%a-b+b" item with a == b reaches BUG_ON(old == new)) */
int run_parse(int (*f)(char *), char *p) { if (setjmp(g_bug_jmp)) return -99; return f(p); }
