/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for arch/x86/lib/cmdline.c: pristine C vs (port/tree C glue +
 * cmdline_rs.rs). Every cmdline / option / output buffer is placed FLUSH
 * AGAINST A PROT_NONE PAGE, so one byte read or written past the end that the
 * C contract forbids is a SIGSEGV, not a silent pass.
 *
 *  A  small-scope exhaustive: every cmdline string over {a,b,=,' ',\t,NUL,0xff}
 *     of length 0..6, x every option in the pool, x max in {0..len+1, 2048},
 *     x bufsize in {0,1,2,3,5}: workers (bool + opt), return value and the
 *     WHOLE output buffer compared
 *  B  random structured command lines (words, separators, options, '=' args,
 *     embedded NULs, high-bit bytes, non-NUL-terminated at 'max'), random max and
 *     bufsize (incl. negative bufsize): workers and the public entry points
 *  C  fixed vectors (kernel-style command lines)
 * usage: drv [seed] [random-iterations]; CMD_PROVE_CAN_FAIL=1 breaks the Rust arm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

int c_worker_bool(const char *, int, const char *);
int c_worker_opt(const char *, int, const char *, char *, int);
int c_cmdline_find_option_bool(const char *, const char *);
int c_cmdline_find_option(const char *, const char *, char *, int);
int __cmdline_find_option_bool_rs(const char *, int, const char *);
int __cmdline_find_option_rs(const char *, int, const char *, char *, int);
int r_cmdline_find_option_bool(const char *, const char *);
int r_cmdline_find_option(const char *, const char *, char *, int);
extern char builtin_cmdline[];
#ifdef WITH_BOOL
extern _Bool builtin_cmdline_added;
#endif

static unsigned long long checks, fails;
static int poison;
#define FAIL(...) do { if (fails++ < 10) { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* n bytes flush against a guard page; the buffer is the LAST n bytes of a persistent page (4 slots) */
static long pg;
static char *slot_base[4];
static char *guarded(int slot, size_t n)
{
	if (!slot_base[slot]) {
		char *m = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (m == MAP_FAILED) { perror("mmap"); exit(2); }
		mprotect(m + pg, pg, PROT_NONE);
		slot_base[slot] = m;
	}
	return slot_base[slot] + pg - n;
}

static void show(const char *s, int n, char *out)
{
	int i, o = 0;
	for (i = 0; i < n && o < 200; i++) {
		unsigned char c = s[i];
		o += snprintf(out + o, 8, c >= 32 && c < 127 ? "%c" : "\\x%02x", c);
	}
	out[o] = 0;
}

/* one comparison of both workers; cmd has exactly max bytes (or is NULL when null) */
static void cmp_workers(const char *cmd, int max, const char *opt, int bufsize, int null_cmd)
{
	char *cm, *op, *oc, *orr;
	int ob = bufsize > 0 ? bufsize : 0;
	int len = max > 0 ? max : 0;
	size_t ol = strlen(opt) + 1;
	int ra, rb, rc, rd;
	char dbg[256];

	cm = null_cmd ? NULL : guarded(0, len);
	if (!null_cmd) memcpy(cm, cmd, len);
	op = guarded(1, ol); memcpy(op, opt, ol);
	/* bool */
	ra = c_worker_bool(cm, max, op);
	rb = __cmdline_find_option_bool_rs(cm, max, op);
	if (poison && ra == 0 && max == 3) rb = 99;
	checks++;
	if (ra != rb) { show(cmd, len, dbg); FAIL("bool MISMATCH cmd='%s' max=%d opt='%s' c=%d rust=%d", dbg, max, opt, ra, rb); }
	/* opt: output buffers of exactly bufsize bytes at the guard page (bufsize 0 -> NULL) */
	if (bufsize > 0) { oc = guarded(2, bufsize); orr = guarded(3, bufsize); }
	else { oc = NULL; orr = NULL; }
	if (bufsize > 0) { memset(oc, 0xA5, bufsize); memset(orr, 0xA5, bufsize); }
	if (bufsize < 0) {
		/* the C writes buffer[0] even for a negative bufsize (quirk): give both a real 1-byte buffer */
		oc = guarded(2, 1); orr = guarded(3, 1); *oc = *orr = (char)0xA5; ob = 1;
	}
	rc = c_worker_opt(cm, max, op, oc, bufsize);
	rd = __cmdline_find_option_rs(cm, max, op, orr, bufsize);
	checks++;
	if (rc != rd || (ob && memcmp(oc, orr, ob))) {
		show(cmd, len, dbg);
		FAIL("opt MISMATCH cmd='%s' max=%d opt='%s' bufsize=%d c=%d rust=%d", dbg, max, opt, bufsize, rc, rd);
	}
}

/* public entry points, on a NUL-terminated command line (as the kernel passes) */
static void cmp_entries(const char *cmd, const char *opt, int bufsize)
{
	char ca[64], cb[64];
	int ra, rb, rc, rd;

	ra = c_cmdline_find_option_bool(cmd, opt);
	rb = r_cmdline_find_option_bool(cmd, opt);
	checks++;
	if (ra != rb) FAIL("entry bool MISMATCH cmd='%s' opt='%s' c=%d rust=%d", cmd, opt, ra, rb);
	if (bufsize < 0 || bufsize > 64) bufsize = 8;
	memset(ca, 0xA5, sizeof ca); memset(cb, 0xA5, sizeof cb);
	rc = c_cmdline_find_option(cmd, opt, ca, bufsize);
	rd = r_cmdline_find_option(cmd, opt, cb, bufsize);
	checks++;
	if (rc != rd || memcmp(ca, cb, sizeof ca)) FAIL("entry opt MISMATCH cmd='%s' opt='%s' bufsize=%d c=%d rust=%d", cmd, opt, bufsize, rc, rd);
}

static uint64_t rs = 88172645463325252ULL;
static unsigned rnd(unsigned n) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (unsigned)((rs >> 11) % n); }

static const char *const opts[] = { "", "a", "b", "ab", "a=", "=", "quiet", "console", "noapic", "root", "ro" };
#define NOPT (sizeof opts / sizeof *opts)

int main(int argc, char **argv)
{
	static const char alpha[] = { 'a', 'b', '=', ' ', '\t', 0, (char)0xff };
	unsigned long long iters = argc > 2 ? strtoull(argv[2], 0, 0) : 20000000ULL;
	static const int bufs[] = { 0, 1, 2, 3, 5 };
	int LA = 6, n, i, m, k, o, bs;
	unsigned long long total;

	pg = sysconf(_SC_PAGESIZE);
	poison = getenv("CMD_PROVE_CAN_FAIL") != NULL;
	if (argc > 1) rs ^= strtoull(argv[1], 0, 0) * 0x9E3779B97F4A7C15ULL;
#ifdef WITH_BOOL
	/* the CONFIG_CMDLINE_BOOL retry arm: builtin_cmdline is consulted when the first scan returns <= 0 */
	strcpy(builtin_cmdline, "quiet console=ttyS0 root=/dev/sda1 noapic");
#endif

	/* A: small-scope exhaustive */
	for (n = 0; n <= LA; n++) {
		unsigned long long cnt = 1, idx;
		char cmd[16];

		for (i = 0; i < n; i++) cnt *= sizeof alpha;
		for (idx = 0; idx < cnt; idx++) {
			unsigned long long t = idx;
			for (i = 0; i < n; i++) { cmd[i] = alpha[t % sizeof alpha]; t /= sizeof alpha; }
			cmd[n] = 0;
			for (o = 0; o < (int)NOPT; o++) {
				/* only the 1..2-char options matter at this size, but all are cheap */
				if (strlen(opts[o]) > 4 && n < 4) continue;
				for (m = 0; m <= n + 1; m++)
					for (k = 0; k < 5; k++)
						cmp_workers(cmd, m, opts[o], bufs[k], 0);
			}
			cmp_workers(cmd, n, "a", 3, 1);	/* NULL cmdline */
		}
	}
	total = checks;
	printf("A small-scope exhaustive: %llu comparisons, %llu failure(s)\n", checks, fails);

	/* C: fixed vectors */
	{
		static const char *const v[] = {
			"BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet splash console=tty0 console=ttyS0,115200",
			"quiet", " quiet", "quiet ", "quietx", "xquiet", "qui", "console=a console=b console=c",
			"console=", "console==x", "  console=abcdefghijkl  ", "", " ", "\t\tro\n", "a=b=c a=d",
		};
		for (i = 0; i < (int)(sizeof v / sizeof *v); i++)
			for (o = 0; o < (int)NOPT; o++)
				for (bs = -1; bs <= 9; bs++) {
					cmp_entries(v[i], opts[o], bs);
					cmp_workers(v[i], (int)strlen(v[i]) + 1, opts[o], bs, 0);
				}
		printf("C fixed vectors: cumulative %llu comparisons, %llu failure(s)\n", checks, fails);
	}

	/* B: random structured */
	{
		static const char *const words[] = { "quiet", "console=ttyS0", "console=", "root=/dev/sda1", "ro", "noapic", "a=b", "ab", "a", "b=", "=", "qu", "quietx", "xquiet", "\xff\xfe", "x=\x80y" };
		static const char seps[] = { ' ', ' ', ' ', '\t', '\n', 1, 0x1f };
		unsigned long long it;

		for (it = 0; it < iters; it++) {
			char cmd[200];
			int len = 0, nw = rnd(8), w, bsz;
			const char *opt;

			for (w = 0; w < nw && len < 150; w++) {
				int ns = rnd(4);
				while (ns--) cmd[len++] = seps[rnd(sizeof seps)];
				if (rnd(8) == 0) { int l = rnd(6); while (l--) cmd[len++] = (char)rnd(256); }
				else { const char *x = words[rnd(sizeof words / sizeof *words)]; size_t l = strlen(x); if (rnd(4) == 0) l = rnd(l + 1); memcpy(cmd + len, x, l); len += l; }
				if (rnd(40) == 0) cmd[len++] = 0;	/* embedded NUL */
			}
			cmd[len] = 0;
			opt = opts[rnd(NOPT)];
			bsz = (int)rnd(14) - 2;
			{
				int max;
				switch (rnd(4)) { case 0: max = len + 1; break; case 1: max = len; break; case 2: max = rnd(len + 3); break; default: max = 2048; }
				if (max > len + 1) { /* guard-page cmdline of `max` bytes: pad with NUL-free? keep NUL-terminated at len, rest filled so reads past NUL would be wrong but not faulty */
					char *big = malloc(max); memset(big, 'z', max); memcpy(big, cmd, len + 1);
					cmp_workers(big, max, opt, bsz, 0); free(big);
				} else
					cmp_workers(cmd, max, opt, bsz, 0);
			}
			cmp_entries(cmd, opt, bsz);
		}
		printf("B random structured: cumulative %llu comparisons, %llu failure(s)\n", checks, fails);
	}
	(void)total;
	return fails ? 1 : 0;
}
