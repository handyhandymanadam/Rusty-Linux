/* Differential: arch/x86/boot/early_serial_console.c (C original: c_console_init / c_early_serial_base) against
 * early_serial_console_rs.rs (host_mock build: console_init / early_serial_base), driven by ONE environment model:
 *  - port I/O through pio_ops: a model UART block at `ubase` (8 registers; DLAB: with LCR bit 7 set, offsets 0/1 read/write the divisor
 *    latch DLL/DLH, otherwise RBR/THR and IER; LCR/MCR/SCR plain; LSR returns a scenario-chosen value that may vary per read); every other
 *    port reads as a hash-noise byte (usually 0xff = "no device") and swallows writes. The initial divisor (any 16-bit value, 0 included),
 *    LCR and the DLAB state are scenario-chosen. Ports are u16 exactly as io.h (so port+reg wraps at 64 KiB).
 *  - cmdline_find_option(): mock returning random option strings (earlyprintk= / console=) with the real function's contract
 *    (-1 absent, else the FULL length, the buffer gets min(len,bufsize-1) bytes + NUL; the bytes after the NUL up to bufsize-1 are
 *    scenario-chosen "stack garbage" (identical for both implementations, so the indeterminate-read divergence of the Rust's zero-init
 *    does not matter here; it is in logs/test-gaps.md), the last buffer byte is a NUL so a parse can never leave the buffer).
 *  - strncmp / simple_strtoull / memcmp: the REAL arch/x86/boot/string.c (u32 `unsigned long`), memcmp with libc semantics (LLVM turns
 *    equality-only strncmp(x, "lit", n) into memcmp in the Rust target build; here as well).
 * Compared per scenario between C and Rust: the EVENT SEQUENCE (every port read with its returned value, every port write, every
 * cmdline_find_option call (option, bufsize), every simple_strtoull call (the string it parses, base)), the final early_serial_base,
 * the final model UART state, and whether a #DE (SIGFPE) happened (probe_baud with divisor 0), and where. Plus a directed table with hand-derived
 * expected results (port, divisor written to DLL/DLH, trap) checked on BOTH implementations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
struct port_io_ops pio_ops;
void c_console_init(void); void console_init(void);
int c_early_serial_base, early_serial_base;
unsigned long long sc_simple_strtoull(const char *, char **, unsigned int);
int sc_strncmp(const char *, const char *, size_t);

/* ------------------------------------------------------------------ environment model */
#define LOGMAX 256
enum { EV_R = 1, EV_W, EV_FIND, EV_STRTOULL, EV_TRAP };
struct ev { u32 k, a, b; };
static struct ev lg[2][LOGMAX]; static int ln[2]; static int which; static long overflow;
static void push(u32 k, u32 a, u32 b) { if (ln[which] < LOGMAX) { lg[which][ln[which]].k = k; lg[which][ln[which]].a = a; lg[which][ln[which]].b = b; ln[which]++; } else overflow++; }

struct sc {
	int e_present, c_present; char e_val[200], c_val[200]; u8 pad[64];
	u16 ubase; u16 div0; u8 lcr0, lsr_mode, noise_mode; u32 nseed;
};
static struct sc S;
struct uart { u8 lcr, ier, fcr, mcr, scr, dll, dlh, lsrn; u32 nreads; };
static struct uart U[2];
static u32 hash(u32 x) { x ^= x >> 16; x *= 0x7feb352d; x ^= x >> 15; x *= 0x846ca68b; x ^= x >> 16; return x; }
static u8 model_in(u16 port) {
	struct uart *u = &U[which]; u8 v;
	u16 off = (u16)(port - S.ubase);
	if (off < 8) {
		switch (off) {
		case 0: v = (u->lcr & 0x80) ? u->dll : (u8)hash(S.nseed + u->nreads); break;
		case 1: v = (u->lcr & 0x80) ? u->dlh : u->ier; break;
		case 2: v = 0x01; break;
		case 3: v = u->lcr; break;
		case 4: v = u->mcr; break;
		case 5: v = S.lsr_mode == 0 ? 0x60 : S.lsr_mode == 1 ? 0x00 : (u8)hash(S.nseed ^ (u->lsrn++ * 7919u)); break;
		case 6: v = 0xb0; break;
		default: v = u->scr; break;
		}
	} else v = S.noise_mode == 0 ? 0xff : S.noise_mode == 1 ? 0x00 : (u8)hash(S.nseed + port * 31u + u->nreads);
	u->nreads++;
	push(EV_R, port, v);
	return v;
}
static void model_out(u8 v, u16 port) {
	struct uart *u = &U[which]; u16 off = (u16)(port - S.ubase);
	push(EV_W, port, v);
	if (off >= 8) return;
	switch (off) {
	case 0: if (u->lcr & 0x80) u->dll = v; break;
	case 1: if (u->lcr & 0x80) u->dlh = v; else u->ier = v; break;
	case 2: u->fcr = v; break;
	case 3: u->lcr = v; break;
	case 4: u->mcr = v; break;
	case 7: u->scr = v; break;
	}
}
static void model_outw(u16 v, u16 port) { (void)v; (void)port; abort(); }
static u32 fnv(const char *s, size_t n) { u32 h = 2166136261u; while (n--) h = (h ^ (u8)*s++) * 16777619u; return h; }

int mock_cmdline_find_option(const char *option, char *buf, int bufsize) {
	int id = !strcmp(option, "earlyprintk") ? 1 : !strcmp(option, "console") ? 2 : 99;
	push(EV_FIND, id, (u32)bufsize);
	const char *v = id == 1 ? S.e_val : S.c_val; int present = id == 1 ? S.e_present : S.c_present;
	if (id == 99) abort();
	if (!present) return -1;
	int len = (int)strlen(v), n = len < bufsize - 1 ? len : bufsize - 1;
	memcpy(buf, v, n); buf[n] = 0;
	for (int i = n + 1; i < bufsize - 1; i++) buf[i] = S.pad[i & 63];
	if (n + 1 < bufsize) buf[bufsize - 1] = 0;
	return len;
}
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base) {
	push(EV_STRTOULL, fnv(cp, strnlen(cp, 80)), base);
	return sc_simple_strtoull(cp, endp, base);
}
int strncmp(const char *a, const char *b, size_t n) { return sc_strncmp(a, b, n); }
int memcmp(const void *a, const void *b, size_t n) {
	const u8 *x = a, *y = b; for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1; return 0;
}

static sigjmp_buf jb; static volatile int trapped;
static void on_fpe(int s) { (void)s; siglongjmp(jb, 1); }
static void run(int w) {
	which = w; ln[w] = 0; memset(&U[w], 0, sizeof U[w]);
	U[w].lcr = S.lcr0; U[w].dll = S.div0 & 0xff; U[w].dlh = S.div0 >> 8;
	int *base = w ? &early_serial_base : &c_early_serial_base; *base = 0;
	trapped = 0;
	if (sigsetjmp(jb, 1) == 0) { if (w) console_init(); else c_console_init(); }
	else { trapped = 1; push(EV_TRAP, 0, 0); }
}

/* ------------------------------------------------------------------ generators */
static u64 rs_; static u64 rnd(void) { rs_ ^= rs_ << 13; rs_ ^= rs_ >> 7; rs_ ^= rs_ << 17; return rs_; }
static int pick(int n) { return (int)(rnd() % (u64)n); }
static void cat(char *d, const char *s) { size_t l = strlen(d); if (l + strlen(s) < 199) strcpy(d + l, s); }
static const char *PFX_E[] = { "serial", "serial", "serial", "ttyS0", "ttyS1", "ttyS", "ttyS2", "", "seria", "SERIAL", "serial0", "xserial", "uart,io,", "0x3f8", ",", "ttyS1,", "tty" };
static const char *PFX_C[] = { "uart8250,io,", "uart8250,io,", "uart,io,", "uart,io,", "uart8250,io", "uart,io", "uart8250,mmio,", "uart,", "ttyS0", "UART,io,", "uart8250,io,,", "" };
static const char *PORTS[] = { "0x3f8", "0x2f8", "0x", "0xg", "0X3F8", "0", "1016", "01770", "0x0", "0xffff", "0x10000", "0xffffffff", "0x1234", "ttyS0", "ttyS1", "0x3f8z", "0x2e8", "00", "0x00003f8", "3f8", "0xfff8", "0xfffd", "-1", " 0x3f8", "0x3F8", "" };
static const char *BAUDS[] = { "115200", "9600", "38400", "57600", "19200", "1200", "300", "0", "00", "0x1c200", "0x80000000", "0xffffffff", "4294967296", "4294967297", "200000", "115201", "57601", "1", "2", "3", "junk", "", "n8", "115200n8", "9600n8r", "0x", "0xg", "1e5", "-1", "2147483648", "18446744073709551615", "18446744073709551617", "65535", "65536", "115200000", "0115200" };
static void junk(char *d) { int n = pick(5); for (int i = 0; i < n; i++) { char c[2] = { 0, 0 }; c[0] = (char)(1 + pick(254)); if (c[0] == 0) c[0] = 'a'; cat(d, c); } }
static void gen_val(char *d, int console) {
	d[0] = 0;
	int mode = pick(10);
	if (mode == 0) { int n = pick(40); for (int i = 0; i < n; i++) { static const char A[] = "0123456789abcdefxX,sertialtyS uar8250io"; char c[2] = { A[pick(sizeof A - 1)], 0 }; cat(d, c); } return; }
	if (mode == 1) { int n = pick(150); for (int i = 0; i < n; i++) { char c[2] = { (char)(1 + pick(255)), 0 }; if (!c[0]) c[0] = 'z'; cat(d, c); } return; }
	cat(d, console ? PFX_C[pick(12)] : PFX_E[pick(17)]);
	if (pick(4)) { if (pick(8) == 0) cat(d, ",,"); else if (pick(8) == 0) cat(d, " "); else if (pick(2) || !console) cat(d, ","); }
	if (pick(5)) cat(d, PORTS[pick(26)]);
	else { char t[24]; snprintf(t, sizeof t, "0x%x", (unsigned)rnd() & (pick(2) ? 0xffff : 0xfff)); cat(d, t); }
	if (pick(5) == 0) junk(d);
	if (pick(6)) { cat(d, pick(8) ? "," : ""); cat(d, BAUDS[pick(36)]); }
	else { char t[24]; snprintf(t, sizeof t, ",%u", (unsigned)(rnd() & (pick(2) ? 0xfffff : 0xffffffffu))); cat(d, t); }
	if (pick(6) == 0) junk(d);
	if (pick(12) == 0) { int n = pick(60); for (int i = 0; i < n; i++) { char c[2] = { (char)('0' + pick(10)), 0 }; cat(d, c); } }
}
static u16 numeric_port_guess(const char *v) { const char *p = strstr(v, "0x"); if (p) return (u16)strtoul(p, 0, 16); return 0x3f8; }
static void gen(void) {
	memset(&S, 0, sizeof S);
	int m = pick(10);
	S.e_present = m < 7 ? 1 : pick(3) == 0 ? 0 : 1;   /* mostly earlyprintk present */
	S.c_present = m < 5 ? 1 : (m < 9 ? pick(2) : 0);
	gen_val(S.e_val, 0); gen_val(S.c_val, 1);
	if (pick(30) == 0) S.e_val[0] = 0;
	if (pick(30) == 0) S.c_val[0] = 0;
	if (pick(2)) { for (int i = 0; i < 64; i++) S.pad[i] = 0; }
	else for (int i = 0; i < 64; i++) S.pad[i] = (u8)(pick(3) == 0 ? 0 : pick(4) == 0 ? ',' : '0' + pick(10));
	int u = pick(10);
	S.ubase = u < 3 ? 0x3f8 : u < 5 ? 0x2f8 : u < 7 ? numeric_port_guess(pick(2) ? S.e_val : S.c_val) : u < 8 ? (u16)rnd() : u < 9 ? 0 : 0xfff8;
	int d = pick(12);
	S.div0 = d == 0 ? 0 : d == 1 ? 1 : d == 2 ? 12 : d == 3 ? 0xffff : d == 4 ? 0x100 : d == 5 ? 0xff : d == 6 ? (u16)(1 + pick(20)) : d == 7 ? (u16)(0x8000 + pick(256)) : (u16)rnd();
	if (pick(6) == 0) S.div0 = 0;
	S.lcr0 = pick(3) == 0 ? (u8)rnd() : pick(2) ? 0x03 : pick(2) ? 0x00 : 0x83;
	S.lsr_mode = pick(3); S.noise_mode = pick(3); S.nseed = (u32)rnd();
}

/* ------------------------------------------------------------------ compare */
static long total, trapcases, probecases, inited, mism, finds, eqevents, portev, trapboth;
static int same(void) {
	if (ln[0] != ln[1]) return 0;
	if (memcmp(lg[0], lg[1], sizeof(struct ev) * ln[0])) return 0;
	if (c_early_serial_base != early_serial_base) return 0;
	if (memcmp(&U[0], &U[1], sizeof(struct uart))) return 0;
	return 1;
}
static void dump(const char *tag) {
	fprintf(stderr, "---- %s: e=%d '%s' c=%d '%s' ubase=%#x div0=%#x lcr0=%#x lsr=%d noise=%d\n", tag, S.e_present, S.e_val, S.c_present, S.c_val, S.ubase, S.div0, S.lcr0, S.lsr_mode, S.noise_mode);
	for (int w = 0; w < 2; w++) { fprintf(stderr, " %s: base=%#x n=%d:", w ? "Rust" : "C   ", w ? early_serial_base : c_early_serial_base, ln[w]); for (int i = 0; i < ln[w] && i < 40; i++) fprintf(stderr, " %u:%x/%x", lg[w][i].k, lg[w][i].a, lg[w][i].b); fprintf(stderr, "\n"); }
}
static void one(void) {
	run(0); int t0 = trapped; run(1); int t1 = trapped;
	total++; if (t0 || t1) trapcases += t0; if (t0 && t1) trapboth++; if (c_early_serial_base) inited++;
	for (int i = 0; i < ln[0]; i++) if (lg[0][i].k == EV_R || lg[0][i].k == EV_W) portev++;
	for (int i = 0; i < ln[0]; i++) if (lg[0][i].k == EV_FIND) finds++;
	for (int i = 0; i < ln[0]; i++) if (lg[0][i].k == EV_R && lg[0][i].a != 0 && 0) probecases++;
	if (t0 != t1 || !same()) { if (mism++ < 5) dump("MISMATCH"); }
}

/* ------------------------------------------------------------------ directed (hand-derived) */
struct dir { const char *e, *c; u16 ubase; u16 div0; int exp_port; int exp_div; int trap; const char *why; };
static const struct dir D[] = {
 { "serial,0x3f8,115200", 0, 0x3f8, 12, 0x3f8, 1, 0, "115200/115200" },
 { "serial,0x2f8,38400", 0, 0x2f8, 12, 0x2f8, 3, 0, "115200/38400 = 3" },
 { "ttyS0,115200", 0, 0x3f8, 12, 0x3f8, 1, 0, "ttyS0 -> 0x3f8" },
 { "ttyS1,57600", 0, 0x2f8, 12, 0x2f8, 2, 0, "ttyS1 -> 0x2f8" },
 { "ttyS1", 0, 0x2f8, 1, 0x2f8, 12, 0, "default baud 9600" },
 { "serial", 0, 0x3f8, 1, 0x3f8, 12, 0, "default port, default baud" },
 { "serial,", 0, 0x3f8, 1, 0x3f8, 12, 0, "pos 7, empty rest" },
 { "serial,0x", 0, 0x3f8, 1, 0x3f8, 12, 0, "0x without digits -> port 0 -> default 0x3f8" },
 { "serial,0x0,9600", 0, 0x3f8, 1, 0x3f8, 12, 0, "port 0 -> default" },
 { "serial,ttyS1,1200", 0, 0x2f8, 1, 0x2f8, 96, 0, "115200/1200 = 96" },
 { "serial,0x2e8,300", 0, 0x2e8, 1, 0x2e8, 384, 0, "115200/300" },
 { "serial,0x3f8z,9600", 0, 0x3f8, 1, 0x3f8, 12, 0, "junk after port: baud parse fails -> 9600" },
 { "ttyS", 0, 0x3f8, 1, 0x3f8, 12, 0, "arg[5] is the pad (0 here)" },
 { "ttyS9,4800", 0, 0x3f8, 1, 0x3f8, 24, 0, "ttyS9: idx 0" },
 { "ttyS0,0", 0, 0x3f8, 1, 0x3f8, 12, 0, "baud 0 -> 9600" },
 { "ttyS0,200000", 0, 0x3f8, 1, 0x3f8, 0, 0, "115200/200000 = 0" },
 { "ttyS0,4294967297", 0, 0x3f8, 1, 0x3f8, 0xc200, 0, "baud (int)1 -> 115200 = 0x1c200, low 16 bits" },
 { "ttyS0,0x100000000", 0, 0x3f8, 1, 0x3f8, 12, 0, "(int) 2^32 = 0 -> 9600" },
 { "ttyS0,0xffffffff", 0, 0x3f8, 1, 0x3f8, 0x3e00, 0, "baud -1 -> -115200 = 0xfffe3e00" },
 { "ttyS0,0x80000000", 0, 0x3f8, 1, 0x3f8, 0, 0, "INT_MIN: 115200 / INT_MIN = 0" },
 { "ttyS0,011", 0, 0x3f8, 1, 0x3f8, 12800, 0, "octal 9 -> 115200/9 = 12800" },
 { "0x3f8,115200", 0, 0x3f8, 1, 0, 0, 0, "no 'serial' prefix: pos 0 != 7, port stays 0" },
 { "vga", 0, 0x3f8, 1, 0, 0, 0, "no port" },
 { "serial,0x10000,1", 0, 0x0000, 1, 0x10000, 0xc200, 0, "port 0x10000: regs at u16 0..7" },
 { "serial,0xffff,115200", 0, 0xffff, 1, 0xffff, 1, 0, "base 0xffff: LCR at u16 port 2, IER at 0, DLL 0xffff" },
 { 0, "uart8250,io,0x3f8,115200n8", 0x3f8, 12, 0x3f8, 1, 0, "console: 115200n8 parses to 115200" },
 { 0, "uart,io,0x2f8,57600", 0x2f8, 12, 0x2f8, 2, 0, "uart,io" },
 { 0, "uart,io,1016,115200", 0x3f8, 12, 0x3f8, 1, 0, "decimal port 1016 = 0x3f8" },
 { 0, "uart,io,01770,115200", 0x3f8, 12, 0x3f8, 1, 0, "octal port 01770 = 0x3f8" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 12, 0x3f8, 12, 0, "probe_baud: divisor 12 -> 9600 -> 12" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 1, 0x3f8, 1, 0, "probe_baud: divisor 1 -> 115200 -> 1" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 3, 0x3f8, 3, 0, "probe_baud: divisor 3 -> 38400 -> 3" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 7, 0x3f8, 7, 0, "probe_baud: 115200/7 = 16457 (rem 1); 115200/16457 = 7 (16457*7 = 115199)" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 40000, 0x3f8, 57600, 0, "probe_baud: 115200/40000 = 2 -> 115200/2 = 57600 (not a round trip)" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 0x100, 0x3f8, 0x100, 0, "probe_baud: 450 -> 256" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 0xffff, 0x3f8, 0xc200, 0, "probe_baud: 115200/65535 = 1 -> 0x1c200" },
 { 0, "uart8250,io,0x3f8", 0x3f8, 0, 0, 0, 1, "probe_baud: divisor 0 -> #DE" },
 { 0, "uart,io,0x3f8,", 0x3f8, 0, 0x3f8, 12, 0, "comma, empty baud -> 9600 (no probe, so no trap)" },
 { 0, "uart,io,0x3f8,0", 0x3f8, 0, 0x3f8, 12, 0, "baud 0 -> 9600" },
 { 0, "uart,io,0", 0x0000, 12, 0, 0, 0, "port 0: probe_baud(0) runs, init skipped" },
 { 0, "uart,io,zz", 0x0000, 12, 0, 0, 0, "no digits: port 0, probe_baud(0)" },
 { 0, "uart,io,0", 0x0000, 0, 0, 0, 1, "port 0 + divisor 0: #DE inside probe_baud even though no init follows" },
 { 0, "uart8250,mmio,0xfe000000,115200n8", 0x3f8, 12, 0, 0, 0, "mmio: not handled" },
 { 0, "UART,io,0x3f8,9600", 0x3f8, 12, 0, 0, 0, "case matters" },
 { 0, "uart,io", 0x3f8, 12, 0, 0, 0, "prefix needs the second comma" },
 { "ttyS1,9600", "uart,io,0x3f8,19200", 0x2f8, 1, 0x2f8, 12, 0, "earlyprintk wins, console not parsed" },
 { "vga", "uart,io,0x2f8,19200", 0x2f8, 1, 0x2f8, 6, 0, "earlyprintk gave no port -> console parsed" },
};
static int directed(void) {
	int bad = 0;
	for (size_t i = 0; i < sizeof D / sizeof D[0]; i++) {
		const struct dir *d = &D[i];
		memset(&S, 0, sizeof S);
		if (d->e) { S.e_present = 1; strcpy(S.e_val, d->e); }
		if (d->c) { S.c_present = 1; strcpy(S.c_val, d->c); }
		S.ubase = d->ubase; S.div0 = d->div0; S.lcr0 = 0x03; S.lsr_mode = 0; S.noise_mode = 0;
		for (int w = 0; w < 2; w++) {
			run(w);
			int port = w ? early_serial_base : c_early_serial_base;
			u16 dv = (u16)(U[w].dll | (U[w].dlh << 8));
			int ok = trapped == d->trap && port == d->exp_port && (!d->exp_port || dv == (u16)d->exp_div) && (!d->exp_port || U[w].lcr == 0x03);
			if (!ok) { bad++; fprintf(stderr, "DIRECTED FAIL %s #%zu (%s): trap=%d port=%#x divisor=%#x lcr=%#x, expected trap=%d port=%#x div=%#x\n", w ? "Rust" : "C", i, d->why, trapped, port, dv, U[w].lcr, d->trap, d->exp_port, d->exp_div & 0xffff); }
		}
		one();   /* and the lockstep on the same input */
	}
	printf("directed: %zu cases x (C, Rust): %s\n", sizeof D / sizeof D[0], bad ? "FAILURES" : "all as hand-derived");
	return bad;
}

int main(int argc, char **argv) {
	long N = argc > 1 ? atol(argv[1]) : 1000000; rs_ = argc > 2 ? strtoull(argv[2], 0, 0) * 0x9e3779b97f4a7c15ull + 1 : 88172645463325252ull;
	pio_ops.f_inb = model_in; pio_ops.f_outb = model_out; pio_ops.f_outw = model_outw;
	struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_fpe; sigaction(SIGFPE, &sa, 0);
	int bad = directed();
	long totsave = total; mism = 0;
	for (long i = 0; i < N; i++) { gen(); one(); }
	long writes = 0, reads = 0;
	printf("scenarios=%ld (+%ld directed) mismatches=%ld  C-inits=%ld #DE(C)=%ld (both=%ld) cmdline-lookups=%ld port-accesses(C)=%ld\n", N, totsave, mism, inited, trapcases, trapboth, finds, portev);
	(void)writes; (void)reads;
	if (overflow) printf("log overflow %ld\n", overflow);
	return (mism || bad || overflow) ? 1 : 0;
}
