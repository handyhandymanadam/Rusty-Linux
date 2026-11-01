/* Differential: arch/x86/boot/cmdline.c (C original, renamed c_cmdline_find_option[_bool]) against cmdline_rs.rs (host_mock build),
 * one memory model: mem[] is a flat 1.06 MiB buffer addressed seg*16 + offset (set_fs() loads the segment, rdfs8(off) reads one byte).
 * Per scenario (cmdline_ptr, option, bufsize, command-line bytes written at linear cmdline_ptr, all random) both implementations of
 * both functions run on identical memory; compared: return value, the entire output buffer (0x5a pre-filled, guards before/after,
 * bytes after the NUL included) and the EVENT SEQUENCE (set_fs(seg), each fs read offset, in order). Model checks that need no
 * reference implementation: every read offset == start + i and < 0x10000; nothing written outside buffer[0..max(bufsize,1)); the
 * 0 / -1 conventions; and an independent word-based reference (below) must agree with the C on return values and the buffer.
 * Plus a directed table with hand-derived expected values (incl. the C's quirks). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
int c_cmdline_find_option(u32, const char *, char *, int);
int c_cmdline_find_option_bool(u32, const char *);
int __cmdline_find_option(u32, const char *, char *, int);
int __cmdline_find_option_bool(u32, const char *);

#define MEMSZ 0x110000u
#define WIN 0x10000u
#define LOGMAX (WIN + 64)
static u8 mem[MEMSZ + 64];
static int which;            /* 0 = C, 1 = Rust */
static u32 lg[2][LOGMAX]; static int ln[2]; static u16 fsr; static long viol;
static void push(u32 v) { if (ln[which] < LOGMAX) lg[which][ln[which]++] = v; else viol++; }
void mock_set_fs(u16 s) { fsr = s; push(0x80000000u | s); }
u8 mock_rdfs8(u32 off) {
	push(off);
	if (off >= WIN) viol++;
	u32 lin = ((u32)fsr << 4) + off;
	if (lin >= MEMSZ) { viol++; return 0xa5; }
	return mem[lin];
}

static uint64_t rs_;
static uint64_t rnd(void) { rs_ ^= rs_ << 13; rs_ ^= rs_ >> 7; rs_ ^= rs_ << 17; return rs_; }
static int pick(int n) { return (int)(rnd() % (uint64_t)n); }

/* ---------- independent reference (word based) ---------- */
/* find_option: words are maximal runs of bytes > ' ' inside [start, end) where end = first NUL or the window end; a word w that
 * starts with option '=' is a match; the LAST match wins; value = rest of the word; len = its length; the buffer receives the first
 * min(len, bufsize-1) value bytes of EVERY match in order (stale tail of earlier longer values stays), NUL at min(len, bufsize-1). */
static int ref_find(const u8 *m, u32 start, const char *opt, u8 *buf, int bufsize) {
	u32 end = start; while (end < WIN && m[end]) end++;
	size_t ol = strlen(opt); int len = -1; u8 *wr = buf;
	u32 i = start;
	while (i < end) {
		while (i < end && m[i] <= ' ') i++;
		if (i >= end) break;
		u32 ws = i; while (i < end && m[i] > ' ') i++;
		u32 wl = i - ws;
		if (wl > ol && memcmp(m + ws, opt, ol) == 0 && m[ws + ol] == '=') {
			len = (int)(wl - ol - 1); wr = buf;
			int lim = bufsize - 1; int n = len < lim ? len : (lim > 0 ? lim : 0);
			for (int k = 0; k < n; k++) *wr++ = m[ws + ol + 1 + k];
		}
	}
	if (bufsize) *wr = 0;
	return len;
}
/* find_option_bool: the first word equal to option, terminated inside the window by whitespace or NUL, returns its 1-based position
 * (from the first byte read). The C's quirk is part of the reference: while an option is being compared a whitespace byte is NOT a word
 * end but a MISMATCH (no myisspace test in st_wordcmp), so a word that is a proper prefix of option followed by whitespace swallows the
 * next word (it goes to st_wordskip): "debu debug" does not find "debug". */
static int ref_bool(const u8 *m, u32 start, const char *opt) {
	u32 i = start;
	for (;;) {
		while (i < WIN && m[i] && m[i] <= ' ') i++;
		if (i >= WIN || m[i] == 0) return 0;
		u32 ws = i; size_t k = 0; int skip = 0;
		for (;;) {
			u8 c = m[i];
			if (opt[k] == 0) { if (c == 0 || c <= ' ') return (int)(ws - start + 1); skip = 1; i++; break; }
			if (c == 0) return 0;
			int ok = (c == (u8)opt[k]); k++; i++;
			if (!ok) { skip = 1; break; }
			if (i >= WIN) return 0;
		}
		if (skip) {
			for (;;) { if (i >= WIN) return 0; u8 c = m[i++]; if (c == 0) return 0; if (c <= ' ') break; }
		}
	}
}

/* ---------- scenario generation ---------- */
static const char *VOC[] = { "debug", "quiet", "vga", "console", "earlyprintk", "forcepae", "edd", "nokaslr", "ro", "root", "ttyS0", "panic",
	"loglevel", "initrd", "noapic", "a", "ab", "abc", "x=", "=", "vga=ask", "console=ttyS0", "earlyprintk=serial,ttyS0,115200", "edd=off", "" };
#define NVOC (sizeof VOC / sizeof *VOC)
static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyzABCxyz0123456789=,.:/_-+\"'\\!#~%";
static int rchar(void) {   /* a random command-line byte, mostly word chars */
	int k = pick(100);
	if (k < 80) return ALPHA[pick(sizeof ALPHA - 1)];
	if (k < 86) return 0x80 + pick(128);                 /* >= 0x80: not whitespace for the C (u8 compare) */
	if (k < 90) return 0x21;                              /* first non-space */
	if (k < 94) return 1 + pick(31);                      /* control chars: whitespace for the C */
	return "=\"="[pick(3)];
}
static int sep(u8 *o) {
	int k = pick(100);
	if (k < 70) { o[0] = ' '; return 1; }
	if (k < 78) { o[0] = '\t'; return 1; }
	if (k < 84) { o[0] = '\n'; return 1; }
	if (k < 90) { o[0] = ' '; o[1] = ' '; return 2; }
	if (k < 95) { o[0] = 1 + pick(32); return 1; }
	o[0] = ' '; o[1] = '\t'; o[2] = 0x20; return 3;
}
static char OPT[40];
static void gen_opt(void) {
	int k = pick(100); size_t n = 0;
	if (k < 38) { strcpy(OPT, VOC[pick(NVOC)]); return; }
	if (k < 50) { strcpy(OPT, VOC[pick(NVOC)]); n = strlen(OPT); if (n && pick(2)) OPT[n - 1 - pick(n > 1 ? 1 : 0)] = 0; return; }
	if (k < 56) { OPT[0] = 0; return; }
	n = pick(7);
	for (size_t i = 0; i < n; i++) { int ch = pick(8) ? "abc=\"d,e"[pick(8)] : rchar(); OPT[i] = (char)(ch ? ch : 'a'); }
	if (k > 94 && n) OPT[pick(n)] = (char)(1 + pick(32));   /* option containing a whitespace byte */
	OPT[n] = 0;
}
static int word(u8 *o) {   /* one token built around OPT */
	int k = pick(100), n = 0; size_t ol = strlen(OPT);
	if (k < 14) { memcpy(o, OPT, ol); return (int)ol; }                                  /* the option itself */
	if (k < 36) { memcpy(o, OPT, ol); n = (int)ol; o[n++] = '='; int vl = pick(5) ? pick(14) : pick(120); for (int i = 0; i < vl; i++) o[n++] = (u8)rchar(); return n; }
	if (k < 44) { memcpy(o, OPT, ol); n = (int)ol; o[n++] = '='; return n; }               /* empty value */
	if (k < 52) { if (ol) { memcpy(o, OPT, ol - 1 - pick(ol > 1 ? 1 : 0)); n = (int)ol - 1; if (n < 0) n = 0; return n ? n : 1; } }
	if (k < 62) { memcpy(o, OPT, ol); n = (int)ol; int e = 1 + pick(3); for (int i = 0; i < e; i++) o[n++] = (u8)rchar(); return n; } /* option as a prefix of a longer word */
	if (k < 66) { o[0] = '"'; memcpy(o + 1, OPT, ol); n = (int)ol + 1; if (pick(2)) o[n++] = '='; return n; }   /* quote handling does not exist */
	if (k < 70) { memcpy(o, OPT, ol); n = (int)ol; o[n++] = '='; o[n++] = '='; o[n++] = (u8)rchar(); return n; }
	if (k < 80) { int wl = 1 + pick(10); for (int i = 0; i < wl; i++) o[n++] = (u8)rchar(); return n; }
	{ const char *v = VOC[pick(NVOC)]; n = (int)strlen(v); memcpy(o, v, n); if (!n) { o[0] = 'z'; n = 1; } if (pick(3) == 0) o[n++] = '='; return n; }
}
static u8 LINE[WIN + 4096];
static int gen_line(int maxlen, int target) {   /* up to ~target bytes, never more than maxlen */
	int n = 0;
	if (pick(4) == 0) n += sep(LINE + n);
	while (n < target) {
		u8 w[512]; int wl = word(w);
		if (n + wl > maxlen) break;
		memcpy(LINE + n, w, wl); n += wl;
		if (pick(10) == 0 && n < target) continue;      /* adjacent words: no separator (a longer word) */
		u8 s[4]; int sl = sep(s); if (n + sl > maxlen) break;
		memcpy(LINE + n, s, sl); n += sl;
	}
	if (n > 0 && pick(3) == 0) while (n > 0 && LINE[n - 1] <= ' ') n--;   /* option at the very end, no trailing space */
	return n;
}

static long stat_[64]; enum { S_N, S_FOUND, S_NOTFOUND, S_TRUNC, S_BUF0, S_BUF1, S_BUF2, S_NEGBUF, S_PTR0, S_PTRUNAL, S_PTRHI, S_PTRTOP, S_LIMIT_OPT, S_LIMIT_BOOL,
	S_BOOL_FOUND, S_BOOL_0, S_BOOL_NEG, S_EMPTYVAL, S_REPEAT, S_NOTERM, S_LONG, S_QUIRK, S_STALE, S_EV };
static long mism, ndirected;
static void fail(const char *w, long i, u32 ptr, int bufsize, const u8 *line, int ll, int a, int b) {
	if (mism < 6) {
		fprintf(stderr, "MISMATCH %s scenario %ld ptr=%#x bufsize=%d opt=\"", w, i, ptr, bufsize);
		for (char *p = OPT; *p; p++) fprintf(stderr, (u8)*p >= 32 && (u8)*p < 127 ? "%c" : "\\x%02x", (u8)*p);
		fprintf(stderr, "\" ret %d vs %d line(%d)=\"", a, b, ll);
		for (int k = 0; k < ll && k < 160; k++) fprintf(stderr, line[k] >= 32 && line[k] < 127 ? "%c" : "\\x%02x", line[k]);
		fprintf(stderr, "\"\n");
	}
	mism++;
}

#define BUFN 1200
static u8 ba[3][BUFN];   /* [0] C, [1] Rust, [2] reference */
#define BOFF 16

static int expect_cases(void);

int main(int argc, char **argv) {
	long N = argc > 1 ? atol(argv[1]) : 200000; rs_ = (argc > 2 ? atoll(argv[2]) : 1) * 0x9e3779b97f4a7c15ULL + 88172645463325252ULL; for (int i = 0; i < 20; i++) rnd();
	int dm = expect_cases();   /* directed table first */
	long nev_total = 0;
	for (long it = 0; it < N; it++) {
		stat_[S_N]++;
		/* pointer */
		u32 ptr; int pk = pick(100);
		if (pk < 30) ptr = 0x10000 + ((u32)pick(0xe0000) & ~0xfu);
		else if (pk < 55) ptr = 0x10000 + (u32)pick(0xe0000);
		else if (pk < 62) ptr = 0x20000;                 /* where QEMU/SeaBIOS puts it */
		else if (pk < 70) ptr = (u32)pick(0x400);       /* tiny: segment 0..0x3f */
		else if (pk < 78) ptr = 0xfff00 + (u32)pick(0x100);   /* last paragraphs below 1 MiB */
		else if (pk < 82) ptr = 0xffff0 - (u32)pick(0x40);
		else if (pk < 87) ptr = 0x100000 + (u32)pick(0x1000);   /* >= 1 MiB (boot.h refuses; the function itself takes it: segment truncates) */
		else if (pk < 89) ptr = 0xfffffff0u + (u32)pick(16);
		else if (pk < 91) ptr = (u32)rnd();
		else if (pk < 93) ptr = 0;
		else ptr = 0x90000 + (u32)pick(0x20000);
		if (ptr == 0) stat_[S_PTR0]++;
		if (ptr & 0xf) stat_[S_PTRUNAL]++;
		if (ptr >= 0x100000) stat_[S_PTRHI]++;
		if (ptr >= 0xfff00 && ptr < 0x100000) stat_[S_PTRTOP]++;
		u32 seg = (ptr >> 4) & 0xffff, start = ptr & 0xf, lin0 = seg * 16 + start;
		u32 maxlen = WIN - start;
		gen_opt();
		/* contents */
		int pol = pick(1000), ll; int islong = 0, noterm = 0;
		if (pol < 6) { ll = gen_line(maxlen, (int)maxlen); islong = 1; while (ll < (int)maxlen) LINE[ll++] = (u8)"abc= x"[pick(6)]; if (pick(2)) { int p = (int)maxlen - 1 - pick(60); if (p > 0) { LINE[p] = ' '; } } noterm = 1; }
		else if (pol < 9) { ll = gen_line(maxlen, (int)maxlen); islong = 1; while (ll < (int)maxlen - 1) LINE[ll++] = (u8)("abc= x"[pick(6)]); }
		else if (pol < 14) { ll = gen_line(maxlen, 2047); }                  /* COMMAND_LINE_SIZE */
		else if (pol < 20) { ll = gen_line(maxlen, 600); }
		else if (pol < 25) { ll = 0; }
		else { ll = gen_line(maxlen, pick(4) ? pick(80) : pick(300)); }
		if (ll > (int)maxlen) ll = (int)maxlen;
		if (islong) stat_[S_LONG]++;
		/* when the line is shorter than the window: NUL (usually) then junk after it that must never be read */
		memcpy(mem + lin0, LINE, ll);
		if (ll < (int)maxlen) { mem[lin0 + ll] = 0; if (pick(3) == 0) for (int k = 1; k < 20 && ll + k < (int)maxlen; k++) mem[lin0 + ll + k] = "debug vga=x"[pick(11)]; }
		else noterm = 1;
		if (noterm) stat_[S_NOTERM]++;
		if (pick(40) == 0 && ll > 4) mem[lin0 + pick(ll)] = 0;   /* a NUL in the middle: the scan stops there */
		/* buffer + size */
		static const int BS[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 511, 512, 1023, 1024 };
		int bufsize = pick(8) ? (pick(3) ? BS[pick(24)] : pick(1025)) : (pick(3) ? pick(12) : 1024);
		if (pick(80) == 0) bufsize = -1 - pick(3);   /* out of contract: only buffer[0] may be written */
		if (bufsize == 0) stat_[S_BUF0]++; if (bufsize == 1) stat_[S_BUF1]++; if (bufsize == 2) stat_[S_BUF2]++; if (bufsize < 0) stat_[S_NEGBUF]++;
		u8 fillk = pick(10) ? 0x5a : (u8)rnd();
		for (int w = 0; w < 3; w++) memset(ba[w], fillk, BUFN);
		if (fillk != 0x5a) for (int k = 0; k < BUFN; k++) { u8 r = (u8)(rnd() >> 8); for (int w = 0; w < 3; w++) ba[w][k] = r; }
		u8 snap[BUFN]; memcpy(snap, ba[0], BUFN);
		/* find_option */
		int ret[3];
		for (which = 0; which < 2; which++) {
			ln[which] = 0; fsr = 0xdead;
			char *b = (char *)ba[which] + BOFF;
			ret[which] = which == 0 ? c_cmdline_find_option(ptr, OPT, b, bufsize) : __cmdline_find_option(ptr, OPT, b, bufsize);
		}
		/* reference runs on the window base (index = offset): mem + seg*16 */
		memcpy(ba[2], snap, BUFN);
		ret[2] = ptr ? ref_find(mem + seg * 16, start, OPT, ba[2] + BOFF, bufsize) : (ba[2][0] = snap[0], -1);
		long ok = 1;
		if (ret[0] != ret[1]) { fail("find_option ret C/Rust", it, ptr, bufsize, LINE, ll, ret[0], ret[1]); ok = 0; }
		if (memcmp(ba[0], ba[1], BUFN)) { fail("find_option buffer C/Rust", it, ptr, bufsize, LINE, ll, ret[0], ret[1]); ok = 0; }
		if (ln[0] != ln[1] || memcmp(lg[0], lg[1], sizeof(u32) * ln[0])) { fail("find_option events C/Rust", it, ptr, bufsize, LINE, ll, ln[0], ln[1]); ok = 0; }
		if (ret[0] != ret[2]) { fail("find_option ret C/reference", it, ptr, bufsize, LINE, ll, ret[0], ret[2]); ok = 0; }
		if (memcmp(ba[0], ba[2], BUFN)) { fail("find_option buffer C/reference", it, ptr, bufsize, LINE, ll, ret[0], ret[2]); ok = 0; }
		/* model checks on the event sequence (C's) */
		if (ptr == 0) { if (ln[0] != 0 || ret[0] != -1) { fail("ptr 0", it, ptr, bufsize, LINE, ll, ln[0], ret[0]); ok = 0; } }
		else {
			if (ln[0] < 1 || lg[0][0] != (0x80000000u | seg)) { fail("set_fs value", it, ptr, bufsize, LINE, ll, (int)lg[0][0], (int)seg); ok = 0; }
			for (int k = 1; k < ln[0]; k++) if (lg[0][k] != start + (u32)(k - 1) || lg[0][k] >= WIN) { fail("read offsets not start+i / >= window", it, ptr, bufsize, LINE, ll, k, (int)lg[0][k]); ok = 0; break; }
			if (ln[0] - 1 > (int)(WIN - start)) { fail("too many reads", it, ptr, bufsize, LINE, ll, ln[0], 0); ok = 0; }
			if (ln[0] - 1 == (int)(WIN - start)) stat_[S_LIMIT_OPT]++;
		}
		nev_total += ln[0];
		for (int k = 0; k < BUFN; k++) {   /* writes confined */
			int lo = BOFF, hi = BOFF + (bufsize > 0 ? bufsize : 1);
			if (bufsize == 0) hi = lo;
			if ((k < lo || k >= hi) && ba[0][k] != snap[k]) { fail("write outside buffer", it, ptr, bufsize, LINE, ll, k, 0); ok = 0; break; }
		}
		if (ret[0] >= 0) { stat_[S_FOUND]++; if (ret[0] == 0) stat_[S_EMPTYVAL]++; if (bufsize > 0 && ret[0] > bufsize - 1) stat_[S_TRUNC]++; } else if (ptr) stat_[S_NOTFOUND]++;
		if (bufsize > 0 && ret[0] >= 0 && ba[0][BOFF + (ret[0] < bufsize - 1 ? ret[0] : bufsize - 1)] != 0) { fail("no NUL at min(len,bufsize-1)", it, ptr, bufsize, LINE, ll, ret[0], 0); ok = 0; }
		/* stale bytes after the NUL: a bigger earlier value left bytes behind */
		if (ret[0] >= 0 && bufsize > ret[0] + 1) { for (int k = BOFF + ret[0] + 1; k < BOFF + bufsize; k++) if (ba[0][k] != snap[k]) { stat_[S_STALE]++; break; } }
		/* find_option_bool */
		int rb[3]; for (which = 0; which < 2; which++) { ln[which] = 0; fsr = 0xdead; rb[which] = which == 0 ? c_cmdline_find_option_bool(ptr, OPT) : __cmdline_find_option_bool(ptr, OPT); }
		rb[2] = ptr ? ref_bool(mem + seg * 16, start, OPT) : -1;
		if (rb[0] != rb[1]) { fail("bool ret C/Rust", it, ptr, 0, LINE, ll, rb[0], rb[1]); ok = 0; }
		if (ln[0] != ln[1] || memcmp(lg[0], lg[1], sizeof(u32) * ln[0])) { fail("bool events C/Rust", it, ptr, 0, LINE, ll, ln[0], ln[1]); ok = 0; }
		if (rb[0] != rb[2]) { fail("bool ret C/reference", it, ptr, 0, LINE, ll, rb[0], rb[2]); ok = 0; }
		if (ptr == 0) { if (ln[0] != 0 || rb[0] != -1) { fail("bool ptr 0", it, ptr, 0, LINE, ll, ln[0], rb[0]); ok = 0; } }
		else {
			for (int k = 1; k < ln[0]; k++) if (lg[0][k] != start + (u32)(k - 1) || lg[0][k] >= WIN) { fail("bool read offsets", it, ptr, 0, LINE, ll, k, (int)lg[0][k]); ok = 0; break; }
			if (ln[0] - 1 == (int)(WIN - start)) stat_[S_LIMIT_BOOL]++;
			if (rb[0] > ln[0] - 1) { fail("bool pos beyond reads", it, ptr, 0, LINE, ll, rb[0], ln[0]); ok = 0; }
		}
		if (rb[0] > 0) stat_[S_BOOL_FOUND]++; else if (rb[0] == 0) stat_[S_BOOL_0]++; else stat_[S_BOOL_NEG]++;
		nev_total += ln[0];
		if (viol) { fail("model violation (offset >= 0x10000 / event overflow / read outside memory)", it, ptr, bufsize, LINE, ll, (int)viol, 0); viol = 0; ok = 0; }
		(void)ok;
	}
	printf("scenarios=%ld directed=%d events=%ld mismatches=%ld\n", N, dm, nev_total, mism);
	printf("  find_option: found=%ld (empty value %ld, truncated %ld, stale bytes after NUL %ld) not-found=%ld | bufsize 0:%ld 1:%ld 2:%ld negative:%ld\n",
	       stat_[S_FOUND], stat_[S_EMPTYVAL], stat_[S_TRUNC], stat_[S_STALE], stat_[S_NOTFOUND], stat_[S_BUF0], stat_[S_BUF1], stat_[S_BUF2], stat_[S_NEGBUF]);
	printf("  bool: found=%ld zero=%ld (-1: %ld) | ptr==0:%ld unaligned:%ld >=1MiB:%ld in last 256 B below 1MiB:%ld | long-window lines:%ld no-NUL:%ld | window-end reads: opt %ld bool %ld\n",
	       stat_[S_BOOL_FOUND], stat_[S_BOOL_0], stat_[S_BOOL_NEG], stat_[S_PTR0], stat_[S_PTRUNAL], stat_[S_PTRHI], stat_[S_PTRTOP], stat_[S_LONG], stat_[S_NOTERM], stat_[S_LIMIT_OPT], stat_[S_LIMIT_BOOL]);
	return mism != 0;
}

/* ---------- directed table: hand-derived expectations, checked on C, Rust and the reference ---------- */
struct dc { const char *line; const char *opt; int bs; int val_len; const char *val; int bool_pos; const char *why; };
static const struct dc DC[] = {
	/* line               opt      bs  len val     bool  why */
	{ "debug",             "debug", 16, -1, "",      1,  "bool: whole line, position 1" },
	{ "debugfoo",          "debug", 16, -1, "",      0,  "bool: option is a prefix of a longer word: no match" },
	{ "foo debug",         "debug", 16, -1, "",      5,  "bool: second word, position 5" },
	{ "foo  debug",        "debug", 16, -1, "",      6,  "bool: two spaces" },
	{ "foo\tdebug",        "debug", 16, -1, "",      5,  "bool: tab separates" },
	{ "foo\ndebug",        "debug", 16, -1, "",      5,  "bool: newline separates" },
	{ "foo debug bar",     "debug", 16, -1, "",      5,  "bool: in the middle" },
	{ "debu debug",        "debug", 16, -1, "",      0,  "bool QUIRK: proper-prefix word + space: the space is a mismatch and the next word is skipped" },
	{ "debu  debug",       "debug", 16, -1, "",      7,  "bool: with two spaces the second one ends the skip" },
	{ "de debug",          "debug", 16, -1, "",      0,  "bool QUIRK (same)" },
	{ "xyz debug",         "debug", 16, -1, "",      5,  "bool: a mismatching word is skipped normally" },
	{ "\"debug\"",         "debug", 16, -1, "",      0,  "no quote handling: the word is \"debug\" with quotes" },
	{ "x=\"debug foo\"",   "debug", 16, -1, "",      0,  "quote does not group: word x=\"debug no match, word foo\" no match" },
	{ "a \"b debug\" c",   "debug", 16, -1, "",      0,  "bool: word debug\" (quote attached) is not debug" },
	{ "a \"b debug c",     "debug", 16, -1, "",      6,  "unterminated quote: debug is a plain word at position 6 (counting from 1: a=1 space=2 \"=3 b=4 space=5 d=6)" },
	{ "",                  "debug", 16, -1, "",      0,  "empty command line" },
	{ "   ",               "debug", 16, -1, "",      0,  "only spaces" },
	{ "vga=ask",           "vga",   16,  3, "ask",   0,  "value option" },
	{ "vga=",              "vga",   16,  0, "",      0,  "empty value" },
	{ "vga",               "vga",   16, -1, "",      1,  "no '=': not a value option; as a bool it is found" },
	{ "vgax=1",            "vga",   16, -1, "",      0,  "longer name" },
	{ "vg=1",              "vga",   16, -1, "",      0,  "shorter name" },
	{ "vga=a vga=bcd",     "vga",   16,  3, "bcd",   0,  "repeated: the last wins" },
	{ "vga=bcd vga=a",     "vga",   16,  1, "a",     0,  "repeated: the last wins; stale 'cd' stays after the NUL" },
	{ "vga=abc",           "vga",    2,  3, "a",     0,  "truncated to bufsize-1, full length returned" },
	{ "vga=abc",           "vga",    1,  3, "",      0,  "bufsize 1: only the NUL" },
	{ "vga=abc",           "vga",    0,  3, "",      0,  "bufsize 0: nothing written (buffer untouched); the length is still returned" },
	{ "console=ttyS0,115200n8 quiet", "console", 64, 14, "ttyS0,115200n8", 0, "setup's own use (console=)" },
	{ "console=ttyS0 quiet", "quiet", 16, -1, "",   15,  "bool: console=ttyS0 is 13 bytes, a space, quiet starts at position 15" },
	{ "a=b=c",             "a",     16,  3, "b=c",   0,  "value may contain '='" },
	{ "a=b=c",             "a=b",   16,  1, "c",     0,  "option name containing '='" },
	{ "=x",                "",      16,  1, "x",     0,  "empty option name matches a word starting with '='" },
	{ "\"vga=ask\"",       "vga",   16, -1, "",      0,  "value option: quote is part of the word" },
	{ "vga=\"ask\"",       "vga",   16,  5, "\"ask\"", 0, "value keeps its quotes" },
	{ "vga=a\200b",        "vga",   16,  3, "a\200b", 0, "byte >= 0x80 is not whitespace" },
	{ "vga=a\001b",        "vga",   16,  1, "a",     0,  "control byte is whitespace: ends the value" },
	{ "vga=\001abc",       "vga",   16,  0, "",      0,  "(same, empty value)" },
};
static int expect_cases(void) {
	int bad = 0, n = 0;
	for (size_t i = 0; i < sizeof DC / sizeof *DC; i++) {
		const struct dc *d = &DC[i];
		/* hand-derived expectations that depend on the table: recompute special rows */
		int el = d->val_len; const char *ev = d->val; int ebool = d->bool_pos;
		u32 ptr = 0x20000 + (u32)(i % 16);   /* also unaligned */
		for (int w = 0; w < 2; w++) {
			which = w; memset(mem, 0xee, 0x30000); size_t L = strlen(d->line);
			/* the C string has no embedded NUL: \200 etc handled by octal in the literals */
			memcpy(mem + ptr, d->line, L); mem[ptr + L] = 0;
			u8 b[64]; memset(b, 0x5a, sizeof b); ln[w] = 0;
			int r = w ? __cmdline_find_option(ptr, d->opt, (char *)b, d->bs) : c_cmdline_find_option(ptr, d->opt, (char *)b, d->bs);
			int rb = w ? __cmdline_find_option_bool(ptr, d->opt) : c_cmdline_find_option_bool(ptr, d->opt);
			int vl = (int)strlen(ev);
			int okv = r == el && (d->bs <= 0 || memcmp(b, ev, (size_t)(vl < d->bs - 1 ? vl : d->bs - 1)) == 0);
			if (d->bs > 0 && el >= 0 && !(d->bs == 1 && b[0] == 0) && !(b[(vl < d->bs - 1 ? vl : d->bs - 1)] == 0)) okv = 0;
			if (d->bs > 0 && el < 0 && b[0] != 0) okv = 0;
			if (d->bs == 0 && b[0] != 0x5a) okv = 0;
			if (!okv || rb != ebool) { fprintf(stderr, "DIRECTED FAIL (%s) line=\"%s\" opt=\"%s\": find_option %d (want %d, buf \"%s\") bool %d (want %d) -- %s\n", w ? "Rust" : "C", d->line, d->opt, r, el, (char *)b, rb, ebool, d->why); bad++; }
			n++;
		}
	}
	mism += bad;
	return n;
}
