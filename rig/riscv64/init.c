/* Freestanding riscv64 (rv64, asm-generic syscall numbers, same as arm64) Linux init replicating rig/init markers. No libc. */
typedef unsigned long u64;
typedef long i64;

static i64 sc(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e)
{
	register i64 a7 __asm__("a7") = n;
	register i64 a0 __asm__("a0") = a;
	register i64 a1 __asm__("a1") = b;
	register i64 a2 __asm__("a2") = c;
	register i64 a3 __asm__("a3") = d;
	register i64 a4 __asm__("a4") = e;
	__asm__ volatile("ecall" : "+r"(a0)
			 : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4) : "memory");
	return a0;
}
#define S(n, a, b, c, d, e) sc(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e))

__asm__(".globl _start\n_start:\n mv a0, sp\n andi sp, a0, -16\n mv s0, zero\n call cmain\n1: j 1b\n");

void *memcpy(void *d, const void *s, u64 n)
{
	char *dd = d; const char *ss = s;
	while (n--) *dd++ = *ss++;
	return d;
}
void *memset(void *d, int c, u64 n)
{
	char *dd = d;
	while (n--) *dd++ = (char)c;
	return d;
}

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void put(const char *s) { S(64, 1, s, slen(s), 0, 0); }
static void putn(const char *s, u64 n) { S(64, 1, s, n, 0, 0); }
static void putu(u64 v)
{
	char b[24]; int i = 24;
	do { b[--i] = '0' + v % 10; v /= 10; } while (v);
	putn(b + i, 24 - i);
}
static int starts(const char *s, const char *p)
{
	while (*p) if (*s++ != *p++) return 0;
	return 1;
}
static const char *find(const char *s, const char *p)
{
	for (; *s; s++) if (starts(s, p)) return s;
	return 0;
}
static const char *findlast(const char *s, const char *p)
{
	const char *r = 0;
	for (; *s; s++) if (starts(s, p)) r = s;
	return r;
}
static char lc(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
static int cihas(const char *s, const char *p) /* p lowercase */
{
	for (; *s; s++) {
		const char *a = s, *b = p;
		while (*b && lc(*a) == *b) { a++; b++; }
		if (!*b) return 1;
	}
	return 0;
}
/* "pre" digits* "post" anywhere in s; returns pointer after the digits or 0 */
static int match_num(const char *s, const char *pre, const char *post)
{
	for (; *s; s++) {
		if (!starts(s, pre)) continue;
		const char *q = s + slen(pre);
		while (*q >= '0' && *q <= '9') q++;
		if (starts(q, post)) return 1;
	}
	return 0;
}

#define LOGSZ (1 << 20)
#define MAXL 65536
static char logbuf[LOGSZ + 1];
static const char *raw[MAXL], *txt[MAXL];
static int nl;

/* strip "<N>" and "[ time] " */
static const char *strip(const char *s, int *had_ts)
{
	*had_ts = 0;
	if (*s == '<') { const char *p = s; while (*p && *p != '>') p++; if (*p) s = p + 1; }
	if (*s == '[') {
		const char *p = s; while (*p && *p != ']') p++;
		if (*p) { s = p + 1; if (*s == ' ') s++; *had_ts = 1; }
	}
	return s;
}

static int count_has(const char *p) { int n = 0; for (int i = 0; i < nl; i++) if (find(txt[i], p)) n++; return n; }

static void logs(const char *name, const char *tag)
{
	for (int i = 0; i < nl; i++)
		if (find(raw[i], tag)) { put("RIG: "); put(name); put("-log "); put(txt[i]); put("\n"); }
}
static int any_num(const char *pre, const char *post)
{
	for (int i = 0; i < nl; i++) if (match_num(txt[i], pre, post)) return 1;
	return 0;
}
static int any_pair(const char *pre, const char *post)
{
	for (int i = 0; i < nl; i++) {
		const char *p = find(txt[i], pre);
		if (p && find(p + slen(pre), post)) return 1;
	}
	return 0;
}
static void verdict(const char *name, int pass, int fail)
{
	put("RIG: "); put(name);
	if (pass) put(" PASS\n");
	else if (fail) put(" FAIL -- the self-test reported failures\n");
	else put(" ABSENT -- no self-test line in the ring buffer\n");
}

/* buffered line reader over a file */
static char rb[65536];
static int rfd; static i64 rpos, rlen; static int reof;
static char *rline(void)
{
	static char ln[512];
	int n = 0, any = 0;
	for (;;) {
		if (rpos >= rlen) {
			if (reof) break;
			rlen = S(63, rfd, rb, sizeof rb, 0, 0); rpos = 0;
			if (rlen <= 0) { rlen = 0; reof = 1; break; }
		}
		char c = rb[rpos++]; any = 1;
		if (c == '\n') { ln[n] = 0; return ln; }
		if (n < (int)sizeof ln - 1) ln[n++] = c;
	}
	if (!any) return 0;
	ln[n] = 0; return ln;
}
static int ropen(const char *path)
{
	int fd = (int)S(56, -100, path, 0, 0, 0);
	if (fd < 0) return -1;
	rfd = fd; rpos = rlen = 0; reof = 0;
	return fd;
}

static const char *skip_ex[] = { "rust_helper_", "rust_do_trace_", "rust_fmt_argument",
				 "rust_begin_unwind", "rust_build_error", 0 };

static int is_rust_name(const char *n)
{
	if (!starts(n, "rust_")) return 0;
	for (const char *p = n + 5; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) return 0;
	for (int i = 0; skip_ex[i]; i++) if (starts(n, skip_ex[i])) return 0;
	return 1;
}

static void mk(const char *p) { S(34, -100, p, 0755, 0, 0); }
static void mnt(const char *src, const char *dst, const char *fs) { S(40, src, dst, fs, 0, 0); }

int cmain(void)
{
	mk("/dev"); mk("/proc"); mk("/sys");
	mnt("dev", "/dev", "devtmpfs");
	mnt("proc", "/proc", "proc");
	mnt("sysfs", "/sys", "sysfs");
	int c = (int)S(56, -100, "/dev/console", 2, 0, 0);
	if (c >= 0) { for (int i = 0; i < 3; i++) if (c != i) S(24, c, i, 0, 0, 0); }

	put("RIG: init running\n");
	put("RIG: version ");
	if (ropen("/proc/version") >= 0) {
		char *l = rline();
		if (l) put(l);
		S(57, rfd, 0, 0, 0, 0);
	}
	put("\n");

	/* /proc entry count */
	u64 cnt = 0;
	int d = (int)S(56, -100, "/proc", 0x10000 /* O_DIRECTORY = 0200000 on riscv; 0x4000 is arm64 */, 0, 0);
	if (d >= 0) {
		static char db[8192] __attribute__((aligned(8)));
		i64 n;
		while ((n = S(61, d, db, sizeof db, 0, 0)) > 0) {
			for (i64 o = 0; o < n;) {
				const char *nm = db + o + 19;
				unsigned short rl = *(unsigned short *)(db + o + 16);
				if (!(nm[0] == '.' && (!nm[1] || (nm[1] == '.' && !nm[2])))) cnt++;
				if (!rl) break;
				o += rl;
			}
		}
		S(57, d, 0, 0, 0, 0);
	}
	static char un[390];
	S(160, un, 0, 0, 0, 0);
	put("RIG: userspace HELLO "); putu(cnt); put(" "); put(un + 65 * 4); put("\n");

	/* ring buffer */
	i64 n = S(116, 3, logbuf, LOGSZ, 0, 0);
	if (n < 0) n = 0;
	logbuf[n] = 0;
	for (i64 i = 0; i < n && nl < MAXL;) {
		char *s = logbuf + i;
		while (i < n && logbuf[i] != '\n') i++;
		logbuf[i++] = 0;
		int ts;
		raw[nl] = s; txt[nl] = strip(s, &ts); nl++;
	}

	int rust = 0;
	for (int i = 0; i < nl; i++)
		if (cihas(raw[i], "rust_print") || cihas(raw[i], "rust printing macros sample")) rust = 1;
	if (rust) {
		put("RIG: rust-ran YES\n");
		int k = 0;
		for (int i = 0; i < nl && k < 5; i++)
			if (cihas(raw[i], "rust")) { put(raw[i]); put("\n"); k++; }
	} else put("RIG: rust-ran NO\n");

	put("RIG: ported rust_* bodies in kallsyms:\n");
	u64 klines = 0; int have_ks = 0;
	if (ropen("/proc/kallsyms") >= 0) {
		have_ks = 1;
		static char last[128];
		u64 N = 0; char *l;
		while ((l = rline())) {
			klines++;
			u64 len = slen(l);
			if (!len || l[len - 1] == ']') continue; /* module symbol: not matched */
			char *nm = l + len;
			while (nm > l && nm[-1] != ' ') nm--;
			if (nm == l || !is_rust_name(nm)) continue;
			if (slen(nm) >= sizeof last) continue;
			if (find(last, nm) && slen(last) == slen(nm) && starts(last, nm)) continue;
			if (N >= 2000) continue;
			memcpy(last, nm, slen(nm) + 1);
			put("RIG:  "); put(nm); put("\n"); N++;
		}
		S(57, rfd, 0, 0, 0, 0);
		if (!N) put("RIG:  NONE -- no ported body is in this kernel\n");
		put("RIG: ported rust_* bodies: "); putu(N); put("\n");
	} else put("RIG:  no /proc/kallsyms\n");

	/* glob / math / lib */
	logs("glob", "glob:");
	verdict("glob", any_num("glob: ", " self-tests passed, 0 failed"),
		any_pair("glob: ", "self-tests passed"));
	logs("math", "mathtest:");
	verdict("math", any_num("mathtest: ", " self-tests passed, 0 failed"),
		any_pair("mathtest: ", "self-tests passed"));
	logs("lib", "libtest:");
	verdict("lib", any_num("libtest: ", " self-tests passed, 0 failed"),
		any_pair("libtest: ", "self-tests passed"));
	logs("hexdump", "test_hexdump:");
	{
		int p = 0;
		for (int i = 0; i < nl; i++) if (match_num(txt[i], "test_hexdump: all ", " tests passed")) p = 1;
		verdict("hexdump", p, count_has("test_hexdump: failed") > 0);
	}
	/* xarray */
	logs("xarray", "XArray:");
	{
		int got = 0; u64 a = 0, b = 0;
		for (int i = 0; i < nl; i++) {
			const char *p = find(txt[i], "XArray: ");
			if (!p) continue;
			p += 8;
			if (!(*p >= '0' && *p <= '9')) continue;
			u64 x = 0; while (*p >= '0' && *p <= '9') x = x * 10 + (*p++ - '0');
			if (!starts(p, " of ")) continue;
			p += 4;
			if (!(*p >= '0' && *p <= '9')) continue;
			u64 y = 0; while (*p >= '0' && *p <= '9') y = y * 10 + (*p++ - '0');
			if (!starts(p, " tests passed")) continue;
			got = 1; a = x; b = y;
		}
		if (!got) put("RIG: xarray ABSENT -- no self-test line in the ring buffer\n");
		else if (a == b && a > 0) put("RIG: xarray PASS\n");
		else { put("RIG: xarray FAIL -- the self-test reported failures ("); putu(a); put(" "); putu(b); put(")\n"); }
	}

	/* kunit */
	int kok = 0, kno = 0;
	for (int i = 0; i < nl; i++) {
		int ts; const char *t = strip(raw[i], &ts);
		if (!ts) continue;
		const char *p = 0;
		int isno = 0;
		if (starts(t, "ok ")) p = t + 3;
		else if (starts(t, "not ok ")) { p = t + 7; isno = 1; }
		if (!p || !(*p >= '0' && *p <= '9')) continue;
		while (*p >= '0' && *p <= '9') p++;
		if (*p != ' ') continue;
		if (isno) { kno++; put("RIG: kunit-log "); put(t); put("\n"); } else kok++;
	}
	for (int i = 0; i < nl; i++) {
		const char *h = findlast(raw[i], "# ");
		if (!h) continue;
		const char *q = h + 2, *e = q;
		while ((*e >= 'a' && *e <= 'z') || (*e >= '0' && *e <= '9') || *e == '_') e++;
		if (!starts(e, ": pass:")) continue;
		put("RIG: kunit-log "); putn(q, e - q); put(" "); put(e + 2); put("\n");
	}
	if (!kok && !kno) put("RIG: kunit ABSENT -- no TAP lines in the ring buffer\n");
	else if (kno) { put("RIG: kunit FAIL -- "); putu(kno); put(" suite(s) failed, "); putu(kok); put(" passed\n"); }
	else { put("RIG: kunit PASS -- "); putu(kok); put(" suite(s), 0 failed\n"); }

	if (have_ks) { put("RIG: kallsyms "); putu(klines); put(" symbols\n"); }
	put("RIG: done\n");
	S(81, 0, 0, 0, 0, 0);
	S(142, 0xfee1dead, 672274793, 0x4321fedc, 0, 0);
	for (;;) S(73 /* ppoll(NULL,0,NULL): blocks forever */, 0, 0, 0, 0, 0);
}
