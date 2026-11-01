/* Lockstep differential: C pm.c (as c_go_to_protected_mode; the 4 asm statements and the two `(u32)&x` address conversions replaced by
 * calls to mock hooks by run-pm-diff.sh, nothing else touched) vs Rust pm_rs.rs (go_to_protected_mode, --cfg host_mock). One scenario =
 * random header fields (realmode_swtch, code32_start), ds, the 32-bit addresses of boot_gdt and boot_params (incl. values near 2^32 so
 * `(u32)&x + (ds() << 4)` wraps), and enable_a20()'s result. Both runs log every event as text: port writes (value, port), cli, lcallw
 * (the far pointer read from the header), enable_a20 call, puts (message bytes), die, lidtl (the 6 bytes it reads), lgdtl (the 6 bytes it
 * reads), the 40 bytes of boot_gdt + its 16-byte alignment, protected_mode_jump (both arguments). The streams must be identical, and each is
 * also checked against an independent model of the C source's semantics written here (expected GDT values from the REAL kernel macros). */
#define PM_DIFF_HARNESS
#include "boot.h"
#include <asm/desc_defs.h>
#include <asm/segment.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
void c_go_to_protected_mode(void); void go_to_protected_mode(void);
struct boot_params boot_params;
static uint64_t rs;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs*0x2545F4914F6CDD1DULL;}
static char lg[16384]; static size_t ln;
static jmp_buf jb;
static u16 s_ds; static u32 s_agdt, s_abp; static int s_a20r;
#define LOG(...) (ln += snprintf(lg + ln, sizeof lg - ln, __VA_ARGS__))
static void hex(const u8 *p, int n){ for(int i=0;i<n;i++) LOG("%02x", p[i]); }
static void m_outb(u8 v, u16 port){ LOG("out %02x->%04x\n", v, port); }
static u8 m_inb(u16 port){ LOG("in %04x\n", port); return 0; }
void mock_cli(void){ LOG("cli\n"); }
void mock_lcallw(u32 far){ LOG("lcallw %08x\n", far); }
void mock_lgdt(const void *p){ u8 b[6]; memcpy(b,p,6); LOG("lgdt "); hex(b,6); LOG("\n"); }
void mock_lidt(const void *p){ u8 b[6]; memcpy(b,p,6); LOG("lidt "); hex(b,6); LOG("\n"); }
u16 mock_ds(void){ return s_ds; }
u32 mock_addr_boot_gdt(const void *p){ LOG("addr_gdt align16=%d tab=", ((uintptr_t)p & 15) == 0); hex(p, 40); LOG("\n"); return s_agdt; }
u32 mock_addr_boot_params(const void *p){ LOG("addr_bp %d\n", p == (const void *)&boot_params); return s_abp; }
int mock_enable_a20(void){ LOG("a20 -> %d\n", s_a20r); return s_a20r; }
void mock_puts(const char *s){ LOG("puts "); hex((const u8*)s, strlen(s) + 1); LOG("\n"); }
void __attribute__((noreturn)) mock_die(void){ LOG("die\n"); longjmp(jb, 1); }
void __attribute__((noreturn)) mock_protected_mode_jump(u32 e, u32 b){ LOG("jump %08x %08x\n", e, b); longjmp(jb, 1); }
struct port_io_ops pio_ops = { m_inb, m_outb, 0 };

static char exp_[16384]; static size_t en;
#define EX(...) (en += snprintf(exp_ + en, sizeof exp_ - en, __VA_ARGS__))
static void exhex(const u8 *p, int n){ for(int i=0;i<n;i++) EX("%02x", p[i]); }
static void model(void){
	u64 t[5] = { 0, 0, GDT_ENTRY(DESC_CODE32, 0, 0xfffff), GDT_ENTRY(DESC_DATA32, 0, 0xfffff), GDT_ENTRY(DESC_TSS32, 4096, 103) };
	en = 0;
	if (boot_params.hdr.realmode_swtch) EX("lcallw %08x\n", boot_params.hdr.realmode_swtch);
	else { EX("cli\nout 80->0070\nout 00->0080\n"); }
	EX("a20 -> %d\n", s_a20r);
	if (s_a20r) { static const char m[] = "A20 gate not responding, unable to boot...\n"; EX("puts "); exhex((const u8*)m, sizeof m); EX("\ndie\n"); return; }
	EX("out 00->00f0\nout 00->0080\nout 00->00f1\nout 00->0080\nout ff->00a1\nout 00->0080\nout fb->0021\nout 00->0080\n");
	EX("lidt 000000000000\n");
	EX("addr_gdt align16=1 tab="); exhex((const u8*)t, 40); EX("\n");
	u32 p = s_agdt + ((u32)s_ds << 4); u8 g[6] = { 0x27, 0, p, p >> 8, p >> 16, p >> 24 };
	EX("lgdt "); exhex(g, 6); EX("\n");
	EX("addr_bp 1\njump %08x %08x\n", boot_params.hdr.code32_start, s_abp + ((u32)s_ds << 4));
}
static u32 rnd32(void){
	switch (rnd() % 6) { case 0: return rnd() % 0x10000; case 1: return 0xffffffffu - rnd() % 0x200000; case 2: return 0; case 3: return rnd() % 0x100000; default: return (u32)rnd(); }
}
int main(int argc, char **argv){
	long n = argc > 1 ? atol(argv[1]) : 1000000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 88172645463325252ULL;
	long mism = 0, fails = 0, a20bad = 0, hook = 0, wrap = 0; 
	for (long i = 0; i < n; i++) {
		static const u16 sp[] = {0, 1, 0x1000, 0x8000, 0xffff, 0xf000, 0x0fff, 0x9000};
		s_ds = rnd() % 4 == 0 ? sp[rnd() % 8] : (u16)rnd();
		s_agdt = rnd32(); s_abp = rnd32();
		switch (rnd() % 4) { case 0: s_a20r = -1; break; case 1: s_a20r = (int)rnd(); break; default: s_a20r = 0; }
		memset(&boot_params, 0, sizeof boot_params);
		boot_params.hdr.realmode_swtch = rnd() % 2 ? 0 : (rnd() % 3 ? (u32)rnd() : 0x10000020u);
		boot_params.hdr.code32_start = rnd() % 4 ? (u32)rnd() : 0x100000;
		model();
		char *res[2];
		for (int w = 0; w < 2; w++) {
			ln = 0; lg[0] = 0;
			if (setjmp(jb) == 0) { if (w == 0) c_go_to_protected_mode(); else go_to_protected_mode(); }
			res[w] = strdup(lg);
		}
		int bad = 0;
		if (strcmp(res[0], res[1])) { bad = 1; mism++; }
		if (strcmp(res[0], exp_)) { bad = 1; fails++; }
		if (bad && mism + fails <= 3) { printf("scenario %ld ds=%04x agdt=%08x abp=%08x a20=%d swtch=%08x\n--C--\n%s--Rust--\n%s--model--\n%s\n", i, s_ds, s_agdt, s_abp, s_a20r, boot_params.hdr.realmode_swtch, res[0], res[1], exp_); }
		hook += boot_params.hdr.realmode_swtch != 0; a20bad += s_a20r != 0; wrap += ((u64)s_agdt + ((u32)s_ds << 4)) > 0xffffffffu;
		free(res[0]); free(res[1]);
	}
	printf("scenarios=%ld  C-vs-Rust mismatches=%ld  model mismatches=%ld  (hook=%ld a20-fail=%ld gdt-ptr-u32-wraps=%ld)\n", n, mism, fails, hook, a20bad, wrap);
	return mism || fails;
}
