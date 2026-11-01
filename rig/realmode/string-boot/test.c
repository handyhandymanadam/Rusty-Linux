/* In-guest differential of the REAL 16-bit objects: arch/x86/boot/string.o (C, symbols c_*) against string_rs.o (Rust, symbols rs_*), both linked into
 * this image and run in real mode under QEMU (rig/realmode/string-boot/run.sh). Random inputs generated in the guest (xorshift32); every exported function
 * compared (return value, endp offset, *res written/untouched, 64-bit values), plus directed vectors with hand-derived expected values for BOTH. Prints to COM1. */
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef unsigned long long u64; typedef __SIZE_TYPE__ size_t;
#define DECL(P) \
 int P##memcmp(const void*,const void*,size_t); int P##bcmp(const void*,const void*,size_t); int P##strcmp(const char*,const char*); \
 int P##strncmp(const char*,const char*,size_t); size_t P##strnlen(const char*,size_t); size_t P##strlen(const char*); \
 char *P##strstr(const char*,const char*); char *P##strchr(const char*,int); \
 u64 P##simple_strtoull(const char*,char**,unsigned); long P##simple_strtol(const char*,char**,unsigned); \
 int P##kstrtoull(const char*,unsigned,u64*); int P##boot_kstrtoul(const char*,unsigned,unsigned long*);
DECL(c_) DECL(rs_)

static inline void outb(u8 v, u16 p) { asm volatile("outb %0,%1" : : "a"(v), "dN"(p)); }
static inline u8 inb(u16 p) { u8 v; asm volatile("inb %1,%0" : "=a"(v) : "dN"(p)); return v; }
static void putc_(char c) { while (!(inb(0x3fd) & 0x20)) { } outb(c, 0x3f8); }
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void puthex(u32 v) { for (int i = 28; i >= 0; i -= 4) putc_("0123456789abcdef"[(v >> i) & 15]); }
static void putdec(unsigned v) { char b[12]; int n = 0; do { b[n++] = '0' + v % 10; v /= 10; } while (v); while (n) putc_(b[--n]); }
static void putstr_hex(const char *s) { puts_("\""); for (; *s; s++) { if (*s >= 0x20 && *s < 0x7f) putc_(*s); else { putc_('\\'); putc_('x'); putc_("0123456789abcdef"[(u8)*s >> 4]); putc_("0123456789abcdef"[*s & 15]); } } puts_("\""); }

static u32 rs_state = 0x2545f491;
static u32 rnd(void) { rs_state ^= rs_state << 13; rs_state ^= rs_state >> 17; rs_state ^= rs_state << 5; return rs_state; }
static unsigned long long checks, fails;
#define CHECK(cond, what, a, b) do { checks++; if (!(cond)) { if (fails++ < 12) { puts_("FAIL "); puts_(what); puts_(" "); putstr_hex(a); puts_(" "); putstr_hex(b); puts_("\n"); } } } while (0)

static char buf1[96], buf2[96];

static void one_string(const char *s)
{
	size_t l = c_strlen(s);
	CHECK(l == rs_strlen(s), "strlen", s, "");
	for (size_t m = 0; m < 6; m++) CHECK(c_strnlen(s, m) == rs_strnlen(s, m) && rs_strnlen(s, m) == (l < m ? l : m), "strnlen", s, "");
	static const int cs[] = {0, 'x', '0', 'a', '-', '\n', 0x80, 0xff, 0x178, -1};
	for (unsigned i = 0; i < sizeof cs / sizeof *cs; i++) CHECK(c_strchr(s, cs[i]) == rs_strchr(s, cs[i]), "strchr", s, "");
	static const unsigned bases[] = {0, 2, 8, 10, 16, 17, 36, 0xffffffffu};
	for (unsigned i = 0; i < sizeof bases / sizeof *bases; i++) {
		unsigned b = bases[i];
		char *e1 = (char *)1, *e2 = (char *)1;
		u64 v1 = c_simple_strtoull(s, &e1, b), v2 = rs_simple_strtoull(s, &e2, b);
		CHECK(v1 == v2 && e1 == e2, "simple_strtoull", s, "");
		e1 = e2 = (char *)1;
		long w1 = c_simple_strtol(s, &e1, b), w2 = rs_simple_strtol(s, &e2, b);
		CHECK(w1 == w2 && e1 == e2, "simple_strtol", s, "");
		u64 k1 = 0x1111, k2 = 0x1111; unsigned long u1 = 0x2222, u2 = 0x2222;
		int r1 = c_kstrtoull(s, b, &k1), r2 = rs_kstrtoull(s, b, &k2);
		CHECK(r1 == r2 && k1 == k2, "kstrtoull", s, "");
		r1 = c_boot_kstrtoul(s, b, &u1); r2 = rs_boot_kstrtoul(s, b, &u2);
		CHECK(r1 == r2 && u1 == u2, "boot_kstrtoul", s, "");
	}
}

static void two_strings(const char *s, const char *t)
{
	CHECK(c_strcmp(s, t) == rs_strcmp(s, t), "strcmp", s, t);
	for (size_t m = 0; m < 6; m++) CHECK(c_strncmp(s, t, m) == rs_strncmp(s, t, m), "strncmp", s, t);
	CHECK(c_strstr(s, t) == rs_strstr(s, t), "strstr", s, t);
	for (size_t m = 0; m < 8; m++) {
		int a = c_memcmp(s, t, m), b = rs_memcmp(s, t, m), a2 = c_bcmp(s, t, m), b2 = rs_bcmp(s, t, m);
		CHECK(a == b && a2 == b2 && a == a2 && (a == 0 || a == 1), "memcmp", s, t);
	}
}

/* directed: expected values derived by hand (not from either implementation) */
struct vec { const char *s; unsigned base; int ret; u64 val; };
static const struct vec vecs[] = {
	{"0", 0, 0, 0}, {"12", 0, 0, 12}, {"012", 0, 0, 10}, {"0x1f", 0, 0, 31}, {"0X1F\n", 0, 0, 31}, {"+7", 10, 0, 7}, {"7\n", 10, 0, 7},
	{"18446744073709551615", 10, 0, 0xffffffffffffffffULL}, {"18446744073709551616", 10, -34, 0}, {"0xffffffffffffffff", 16, 0, 0xffffffffffffffffULL},
	{"0x10000000000000000", 16, -34, 0}, {"", 10, -22, 0}, {"-1", 10, -22, 0}, {"0x", 16, -22, 0}, {"0xg", 0, -22, 0}, {"08", 0, -22, 0}, {"7 ", 10, -22, 0},
	{"7\n\n", 10, -22, 0}, {"1777777777777777777777", 8, 0, 0xffffffffffffffffULL}, {"2000000000000000000000", 8, -34, 0}, {"4294967296", 10, 0, 4294967296ULL},
	{"zz", 36, -22, 0}, {"101", 2, 0, 5}, {"9", 8, -22, 0}, {"FfFf", 16, 0, 0xffff},
};

int main(void)
{
	for (unsigned i = 0; i < sizeof vecs / sizeof *vecs; i++) {
		const struct vec *v = &vecs[i];
		u64 k1 = 0x77, k2 = 0x77;
		int r1 = c_kstrtoull(v->s, v->base, &k1), r2 = rs_kstrtoull(v->s, v->base, &k2);
		u64 want = v->ret == 0 ? v->val : 0x77;
		CHECK(r1 == v->ret && r2 == v->ret && k1 == want && k2 == want, "directed kstrtoull", v->s, "");
	}
	{ unsigned long u = 5; CHECK(c_boot_kstrtoul("4294967295", 10, &u) == 0 && u == 0xffffffffUL, "directed ul max C", "", ""); u = 5;
	  CHECK(rs_boot_kstrtoul("4294967295", 10, &u) == 0 && u == 0xffffffffUL, "directed ul max R", "", ""); u = 5;
	  CHECK(c_boot_kstrtoul("4294967296", 10, &u) == -34 && u == 5 && rs_boot_kstrtoul("4294967296", 10, &u) == -34 && u == 5, "directed ul ERANGE", "", "");
	  CHECK(c_simple_strtol("-5", 0, 10) == -5 && rs_simple_strtol("-5", 0, 10) == -5 && rs_simple_strtol("+5", 0, 10) == 0, "directed strtol", "", ""); }
	CHECK(c_strcmp("a\x80", "a") == 0x80 && rs_strcmp("a\x80", "a") == 0x80 && c_strcmp("a", "a\xff") == -255 && rs_strcmp("a", "a\xff") == -255, "directed strcmp unsigned", "", "");
	CHECK(c_strncmp("a\x80", "a\x7f", 5) == 1 && rs_strncmp("a\x80", "a\x7f", 5) == 1 && c_strncmp("ab", "ac", 1) == 0 && rs_strncmp("ab", "ac", 1) == 0, "directed strncmp", "", "");
	CHECK(c_memcmp("ab\x80", "ab\x7f", 3) == 1 && rs_memcmp("ab\x80", "ab\x7f", 3) == 1 && c_memcmp("x", "y", 0) == 0 && rs_memcmp("x", "y", 0) == 0, "directed memcmp", "", "");
	{ const char *h = "xxabcabcd"; CHECK(c_strstr(h, "abcd") == h + 5 && rs_strstr(h, "abcd") == h + 5 && rs_strstr(h, "") == h && rs_strstr(h, "zz") == 0, "directed strstr", "", ""); }
	puts_("directed vectors: checks="); putdec((unsigned)checks); puts_(" failures="); putdec((unsigned)fails); puts_("\n");

	static const char alpha[] = "09/:aAfFgG`@xX+-\n \x80";
	for (int it = 0; it < 120000; it++) {      /* numbers: 1..26 digit chars, prefixes, junk */
		char *u = buf1; int lu = 1 + rnd() % 26, hex = rnd() & 1, pre = rnd() % 6, p = 0;
		if (pre == 1) u[p++] = '+'; if (pre == 2) u[p++] = '-'; if (pre == 3) { u[p++] = '0'; u[p++] = (rnd() & 1) ? 'x' : 'X'; } if (pre == 4) u[p++] = '0'; if (pre == 5) { u[p++] = '+'; u[p++] = '0'; u[p++] = 'x'; }
		const char *dig = hex ? "0123456789abcdefABCDEF" : "0123456789";
		int lead = rnd() % 4 ? 0 : 1 + rnd() % 6;
		for (int i = 0; i < lu; i++) u[p++] = (i < lead) ? (hex ? 'f' : '9') : dig[rnd() % (hex ? 22 : 10)];
		int post = rnd() % 16;
		if (post == 0) u[p++] = '\n'; else if (post == 1) { u[p++] = '\n'; u[p++] = '\n'; } else if (post == 2) u[p++] = "z:/`@g"[rnd() % 6]; else if (post == 3) u[p++] = ' '; else if (post == 4) u[p++] = (char)(0x80 | (rnd() & 0x7f));
		u[p] = 0;
		one_string(u);
	}
	for (int it = 0; it < 60000; it++) {      /* short strings over the full alphabet */
		int l = rnd() % 6; for (int i = 0; i < l; i++) buf1[i] = alpha[rnd() % (sizeof alpha - 1)]; buf1[l] = 0;
		one_string(buf1);
	}
	for (int it = 0; it < 150000; it++) {     /* pairs: equal prefix, differing byte (incl >= 0x80), substring needles */
		int lu = rnd() % 20, lv;
		for (int i = 0; i < lu; i++) buf1[i] = (rnd() % 3 == 0) ? (char)(0x70 + rnd() % 0x20) : "ab01"[rnd() % 4]; buf1[lu] = 0;
		if (rnd() % 2) { for (int i = 0; i <= lu; i++) buf2[i] = buf1[i]; lv = lu; if (lu && rnd() % 2) buf2[rnd() % lu] = (char)(rnd() % 255 + 1); }
		else if (rnd() % 2 && lu) { int a = rnd() % lu, b = a + rnd() % (lu - a + 1); lv = 0; for (int i = a; i < b; i++) buf2[lv++] = buf1[i]; buf2[lv] = 0; }
		else { lv = rnd() % 5; for (int i = 0; i < lv; i++) buf2[i] = "ab01"[rnd() % 4]; buf2[lv] = 0; }
		two_strings(buf1, buf2);
	}
	for (int it = 0; it < 4000; it++) {       /* memcmp lengths 0..70 with a single differing byte anywhere */
		int n = rnd() % 70; for (int i = 0; i < n; i++) buf1[i] = buf2[i] = (char)rnd();
		if (n && rnd() % 2) buf2[rnd() % n] ^= (char)(1 << (rnd() % 8));
		int a = c_memcmp(buf1, buf2, n), b = rs_memcmp(buf1, buf2, n);
		CHECK(a == b, "memcmp rnd", "", "");
	}
	puts_("string-boot: checks="); putdec((unsigned)checks); puts_(" failures="); putdec((unsigned)fails); puts_(fails ? " FAIL\n" : " PASS\n");
	return fails ? 0x11 : 0x10;
}
