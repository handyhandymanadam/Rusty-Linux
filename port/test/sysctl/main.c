/* sysctl differential: the pristine text engine of the integer handlers (ARM_REF: ref.c extracted from the pristine file) against sysctl_rs.rs plus the glue wrappers (ARM_RS). The
 * handlers run on exact-size heap buffers (read: output buffers of 0..40 bytes; write: generated text) over random tables: int / uint / ulong arrays of 1..5 elements, NULL data,
 * zero maxlen, min/max parameters, non-zero file positions under the three sysctl_writes_strict modes, small PAGE_SIZE values to force the clamp, HZ values 100..1000. The text has signs,
 * decimal / hex / octal numbers, overflowing and 21+ digit numbers, junk suffixes and every kind of separator incl. 0xA0. Prints every return value, *lenp, *ppos, the data and the output
 * buffer.   usage: t SHARD (env SY_N, SY_PROVE) */
#include "refshim.h"
size_t page_size_g = 4096; int hz_g = 1000, warns; struct task cur_ = { "tsk" }; struct task *current = &cur_; enum sysctl_writes_mode sysctl_writes_strict = SYSCTL_WRITES_STRICT;
#include SRCFILE
#ifdef ARM_RS
#define proc_skip_spaces rust_sysctl_skip_spaces
#endif
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static char *gen(size_t *outlen)
{
	static const char *nums[] = { "0", "1", "7", "10", "255", "2147483647", "2147483648", "4294967295", "4294967296", "9223372036854775807", "18446744073709551615", "18446744073709551616",
	    "0x1f", "0X7fffffff", "017", "08", "00", "123456789012345678901", "1234567890123456789012", "99999999999999999999", "0x", "0xg" };
	static const char seps[][3] = { " ", "\t", "\n", "\v", "\f", "\r", "\xa0", "  ", " \n", ",", "", "-" };
	static const char *junk[] = { "", "", "", "a", ".", "x", "\xff", "\n\n", " \t " , "0", "z9" };
	char *b = malloc(400); size_t n = 0; int toks = rnd(6), k;
	if (rnd(6) == 0) { n += snprintf(b + n, 20, "%s", seps[rnd(9)]); }
	for (k = 0; k < toks; k++) {
		const char *t = nums[rnd(sizeof nums / sizeof nums[0])];
		if (rnd(4) == 0) b[n++] = '-';
		if (rnd(8) == 0) { b[n++] = '+'; }
		if (rnd(10) == 0) { unsigned d = 1 + rnd(30); while (d--) b[n++] = '1' + rnd(9); } else n += snprintf(b + n, 40, "%s", t);
		n += snprintf(b + n, 20, "%s", junk[rnd(rnd(3) ? 3 : 11)]);
		if (k + 1 < toks || rnd(2)) n += snprintf(b + n, 20, "%s", seps[rnd(rnd(4) ? 3 : 12)]);
	}
	*outlen = n; { char *e = malloc(n ? n : 1); memcpy(e, b, n); free(b); return e; }
}
static void dumpbuf(const unsigned char *b, size_t n) { size_t i; printf(" buf=["); for (i = 0; i < n; i++) printf("%02x", b[i]); printf("]"); }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("SY_N") ? atol(getenv("SY_N")) : 60000; int prove = getenv("SY_PROVE") != NULL; long i; static int pc;
	static const size_t pages[] = { 4096, 4096, 4096, 8, 16, 24, 33, 64 }; static const int hzs[] = { 100, 250, 300, 1000, 1000 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < n; i++) {
		int kind = rnd(10), write = rnd(2), maxlen, rc; unsigned long ul[6]; unsigned ui[6]; int in[6]; struct ctl_table t; void *data = NULL; size_t len, bs; loff_t pos; unsigned char *buf; int cnt = 1 + rnd(5);
		int conv_k = rnd(4); int mn = (int)rnd(20) - 10, mx = (int)rnd(40) + 5; unsigned umn = rnd(10), umx = rnd(40) + 5; unsigned long lmn = rnd(10), lmx = rnd(100000) + 5; static const int ed[] = { 0, 1, 7, 10, 255 };
		if (rnd(2)) { mn = -ed[rnd(5)]; mx = ed[rnd(5)]; umn = ed[rnd(5)]; umx = ed[rnd(5)]; lmn = ed[rnd(5)]; lmx = ed[rnd(5)]; } struct do_proc_dointvec_minmax_conv_param ip = { rnd(3) ? &mn : NULL, rnd(3) ? &mx : NULL };
		struct do_proc_douintvec_minmax_conv_param up = { rnd(3) ? &umn : NULL, rnd(3) ? &umx : NULL }; int j;
		page_size_g = pages[rnd(8)]; hz_g = hzs[rnd(5)]; sysctl_writes_strict = (enum sysctl_writes_mode)((int)rnd(3) - 1); warns = 0; pos = rnd(5) == 0 ? 1 + rnd(4) : 0;
		if (kind >= 7) {   /* the primitives on their own: skip_spaces / skip_char, get_long with every kind of permitted-trailer list and trailer out-parameter, put_long / put_char */
			size_t sz, sz0; char *tx = gen(&sz), *p = tx; unsigned long lv = 0x1234; bool ng = rnd(2); char tr = 0x55; static const char tra[] = { '-', ',', '\n' }, trb[] = { ',', '\n', 0 };
			const char *perm; unsigned plen;
			sz0 = sz; if (rnd(5) == 0 && sz > 1) sz -= 1 + rnd(2);
			printf("%ld P%d sz=%zu", i, kind, sz);
			if (kind == 7) {
				if (rnd(2)) proc_skip_spaces(&p, &sz); else proc_skip_char(&p, &sz, rnd(2) ? '\n' : (rnd(2) ? ' ' : '1'));
				printf(" -> off=%td sz=%zu", p - tx, sz);
			} else if (kind == 8) {
				int sel = rnd(4); perm = sel == 0 ? proc_wspace_sep : sel == 1 ? tra : sel == 2 ? trb : tra; plen = sel == 0 ? sizeof(proc_wspace_sep) : sel == 3 ? 0 : 3;
				rc = proc_get_long(&p, &sz, &lv, &ng, perm, plen, rnd(2) ? &tr : NULL); if (prove && pc++ == 3) rc++;
				printf(" sel=%d -> rc=%d off=%td sz=%zu lv=%lu neg=%d tr=%d", sel, rc, p - tx, sz, lv, ng, tr);
			} else {
				size_t bsz = rnd(26); unsigned char *ob = calloc(bsz ? bsz : 1, 1); void *op = ob; size_t left = bsz; int m = rnd(3);
				for (j = 0; j < 3; j++) { if (m == 0 || j == 1) proc_put_long(&op, &left, rnd(2) ? (unsigned long)rnd64() : rnd(1000), rnd(3) == 0); else proc_put_char(&op, &left, (char)('a' + j)); }
				printf(" bsz=%zu -> left=%zu used=%td", bsz, left, (unsigned char *)op - ob); dumpbuf(ob, bsz); free(ob);
			}
			printf("\n"); free(tx); continue;
		}
		for (j = 0; j < 6; j++) { in[j] = rnd(3) ? (int)rnd(30) - 10 : (int)rnd64(); ui[j] = rnd(3) ? rnd(30) : (unsigned)rnd64(); ul[j] = rnd(3) ? rnd(30) : (unsigned long)rnd64(); }
		t.procname = "p"; t.extra1 = rnd(3) ? &lmn : NULL; t.extra2 = rnd(3) ? &lmx : NULL;
		if (write) { buf = (unsigned char *)gen(&len); bs = len; } else { bs = rnd(41); buf = calloc(bs ? bs : 1, 1); len = bs; if (rnd(5) == 0) len = bs + rnd(3); if (len > bs) len = bs; }
		if (len == 0 && rnd(2)) len = 0;
		printf("%ld K%d w=%d pg=%zu hz=%d wm=%d pos=%lld len=%zu cnt=%d", i, kind, write, page_size_g, hz_g, (int)sysctl_writes_strict, pos, len, cnt);
		if (kind <= 1) {   /* int array with plain / min-max / jiffies conversions */
			t.data = rnd(15) ? in : NULL; t.maxlen = rnd(12) ? cnt * (int)sizeof(int) : 0; if (rnd(10) == 0) t.maxlen += rnd(7);
			rc = __do_proc_dointvec(t.data, &t, write, buf, &len, &pos, conv_k == 0 ? NULL : conv_k == 1 ? do_proc_dointvec_minmax_conv : conv_k == 2 ? do_proc_dointvec_jiffies_conv : do_proc_dointvec_conv, conv_k == 1 ? (void *)&ip : NULL);
			for (j = 0; j < 6; j++) printf(" i%d", in[j]);
		} else if (kind <= 3) {   /* unsigned int */
			t.data = rnd(15) ? ui : NULL; t.maxlen = rnd(8) ? (rnd(5) ? 1 : cnt) * (int)sizeof(unsigned) : 0;
			rc = __do_proc_douintvec(t.data, &t, write, buf, &len, &pos, conv_k == 1 ? do_proc_douintvec_minmax_conv : conv_k == 2 ? NULL : do_proc_douintvec_conv, conv_k == 1 ? (void *)&up : NULL);
			for (j = 0; j < 6; j++) printf(" u%u", ui[j]);
		} else {   /* unsigned long with the two multipliers */
			t.data = rnd(15) ? ul : NULL; t.maxlen = rnd(12) ? cnt * (int)sizeof(unsigned long) : 0;
			rc = __do_proc_doulongvec_minmax(t.data, &t, write, buf, &len, &pos, rnd(2) ? 1UL : (unsigned long)hz_g, rnd(2) ? 1UL : 1000UL);
			for (j = 0; j < 6; j++) printf(" l%lu", ul[j]);
		}
		if (prove && pc++ == 3) rc++;
		printf(" -> rc=%d len=%zu pos=%lld warns=%d", rc, len, pos, warns); if (!write) dumpbuf(buf, bs);
		printf("\n"); free(buf);
	}
	return 0;
}
