/* Lockstep differential: C main.c (c_main, run-main-diff.sh: only renames) vs Rust main_rs.rs (rs_main, --cfg host_mock). One scenario = random setup header (0x7b bytes, with
 * edge-biased loadflags / heap_end_ptr / setup_move_size / cmd_line_ptr), the old-style command line words at ds:0x20 (magic, offset), ds, the live esp (32-bit, incl. wrap
 * near 0 and the boundary of the heap clamp), cpu.level, cmdline_find_option_bool's and validate_cpu's results, the BIOS (random output registers per call), fs/gs. Both runs
 * log every effect as text: pio_ops slots exercised afterwards (inb/outb/outw), initregs, intcall (number, ALL 44 ireg bytes, whether oreg is NULL), puts (message bytes),
 * console_init, __cmdline_find_option_bool (cmd_line_ptr, option string), validate_cpu, die, detect_memory, set_video, query_apm_bios/query_edd (variant), go_to_protected_mode.
 * Then the final boot_params (4096 bytes), HEAP and heap_end. C and Rust streams must be identical, and each must equal an independent model written from main.c's text.
 * Build variant (V_X64, V_APM, V_EDD) mirrors the CONFIG switches the C was compiled with. */
#include <asm/bootparam.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
extern struct boot_params c_boot_params, boot_params;
extern struct port_io_ops c_pio_ops, pio_ops;
extern char *c_HEAP, *c_heap_end, *HEAP, *heap_end;
void c_main(void); void rs_main(void);
struct setup_header hdr;                 /* header.S's hdr */
struct { int level; int family; int model; u32 flags[22]; } cpu;
char _end[8192];                         /* setup.ld's _end: the initial HEAP / heap_end value */

/* ---- layout facts the Rust hard-codes, checked against the REAL uapi header ---- */
_Static_assert(sizeof(struct boot_params) == 4096, "boot_params size");
_Static_assert(offsetof(struct boot_params, hdr) == 0x1f1, "hdr offset");
_Static_assert(sizeof(struct setup_header) == 0x7b, "sizeof(hdr)");
_Static_assert(offsetof(struct boot_params, ist_info) == 0x60, "ist_info");
_Static_assert(offsetof(struct boot_params, kbd_status) == 0x1eb, "kbd_status");
_Static_assert(offsetof(struct boot_params, hdr.loadflags) == 0x211, "loadflags");
_Static_assert(offsetof(struct boot_params, hdr.setup_move_size) == 0x212, "setup_move_size");
_Static_assert(offsetof(struct boot_params, hdr.heap_end_ptr) == 0x224, "heap_end_ptr");
_Static_assert(offsetof(struct boot_params, hdr.cmd_line_ptr) == 0x228, "cmd_line_ptr");
_Static_assert(offsetof(struct ist_info, signature) == 0 && offsetof(struct ist_info, command) == 4 && offsetof(struct ist_info, event) == 8 && offsetof(struct ist_info, perf_level) == 12, "ist_info fields");
_Static_assert(CAN_USE_HEAP == 0x80, "CAN_USE_HEAP");
_Static_assert(sizeof(struct ist_info) == 16, "ist_info size");

static uint64_t rs;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs*0x2545F4914F6CDD1DULL;}
static uint64_t ors;                     /* BIOS output-register stream: reseeded per run */
static uint64_t ornd(void){ors^=ors<<13;ors^=ors>>7;ors^=ors<<17;return ors*0x2545F4914F6CDD1DULL;}
static char lg[1 << 17]; static size_t ln; static char exp_[1 << 17]; static size_t en;
static char *dst; static size_t *dn; static size_t dcap;
#define LOG(...) (*dn += snprintf(dst + *dn, dcap - *dn, __VA_ARGS__))
static void sel_log(void) { dst = lg; dn = &ln; dcap = sizeof lg; }
static void sel_exp(void) { dst = exp_; dn = &en; dcap = sizeof exp_; }
static void hex(const u8 *p, int n){ for(int i=0;i<n;i++) LOG("%02x", p[i]); }
static jmp_buf jb;
static u16 s_ds, s_fs, s_gs; static u32 s_esp; static int s_find, s_valid; static u16 s_old[2]; static u64 s_seed;

u16 mock_ds(void){ return s_ds; }
unsigned mock_esp(void){ return s_esp; }
void *mock_oldcmd(void){ return s_old; }
u8 mock_inb(u16 port){ u8 v = (u8)(port ^ 0x5a); LOG("inb %04x -> %02x\n", port, v); return v; }
void mock_outb(u8 v, u16 port){ LOG("outb %02x %04x\n", v, port); }
void mock_outw(u16 v, u16 port){ LOG("outw %04x %04x\n", v, port); }
struct biosregs_h { u32 w[11]; };
void mock_initregs(void *r){ u32 *w = r; memset(w, 0, 44); w[10] = 1; w[8] = (u32)s_gs | ((u32)s_fs << 16); w[9] = (u32)s_ds | ((u32)s_ds << 16); LOG("initregs ds=%04x\n", s_ds); }
void mock_intcall(u8 n, const void *ireg, void *oreg){
	LOG("intcall %02x ireg=", n); hex(ireg, 44); LOG(" oreg=%s\n", oreg ? "ptr" : "NULL");
	if (oreg) { u32 w[11]; for (int i = 0; i < 11; i++) w[i] = (u32)ornd(); memcpy(oreg, w, 44); LOG("  -> "); hex((u8 *)w, 44); LOG("\n"); }
}
void mock_puts(const char *s){ LOG("puts "); hex((const u8 *)s, strlen(s) + 1); LOG("\n"); }
void mock_console_init(void){ LOG("console_init\n"); }
int mock_cmdline_find_option_bool(unsigned long p, const char *o){ LOG("find %08lx %s -> %d\n", p, o, s_find); return s_find; }
int mock_validate_cpu(void){ LOG("validate_cpu -> %d\n", s_valid); return s_valid; }
void mock_detect_memory(void){ LOG("detect_memory\n"); }
void mock_set_video(void){ LOG("set_video\n"); }
void mock_query_apm_bios(void){ LOG("query_apm_bios\n"); }
void mock_query_edd(void){ LOG("query_edd\n"); }
void __attribute__((noreturn)) mock_die(void){ LOG("die\n"); longjmp(jb, 1); }
void __attribute__((noreturn)) mock_go_to_protected_mode(void){ LOG("go_to_protected_mode\n"); longjmp(jb, 1); }

static const char M_EARLY[] = "early console in setup code\n", M_ANC[] = "WARNING: Ancient bootloader, some functionality may be limited!\n", M_CPU[] = "Unable to boot - please use a kernel appropriate for your CPU.\n";
static u8 EXPBP[4096]; static char *EXHEAP, *EXHE;
static void mput(const char *m, size_t n){ LOG("puts "); hex((const u8 *)m, n); LOG("\n"); }
static u32 *mk_regs(u32 *w){ memset(w, 0, 44); w[10] = 1; w[8] = (u32)s_gs | ((u32)s_fs << 16); w[9] = (u32)s_ds | ((u32)s_ds << 16); return w; }
static void m_initregs(void){ LOG("initregs ds=%04x\n", s_ds); }
static void m_intcall(int n, u32 *w, int hasoreg, u32 *o){
	LOG("intcall %02x ireg=", n); hex((u8 *)w, 44); LOG(" oreg=%s\n", hasoreg ? "ptr" : "NULL");
	if (hasoreg) { for (int i = 0; i < 11; i++) o[i] = (u32)ornd(); LOG("  -> "); hex((u8 *)o, 44); LOG("\n"); }
}
/* independent model of main.c */
static void model(void){
	memset(EXPBP, 0, sizeof EXPBP); EXHEAP = EXHE = _end;
	memcpy(EXPBP + 0x1f1, &hdr, 0x7b);
	u32 cl; memcpy(&cl, EXPBP + 0x228, 4);
	if (cl == 0 && s_old[0] == 0xA33F) {
		u32 seg = (s_old[1] < *(u16 *)(EXPBP + 0x212)) ? s_ds : 0x9000;
		cl = (seg << 4) + s_old[1];                       /* int arithmetic, no wrap */
		memcpy(EXPBP + 0x228, &cl, 4);
	}
	LOG("console_init\n");
	int dbg;
	if (cl >= 0x100000) dbg = -1; else { LOG("find %08x debug -> %d\n", cl, s_find); dbg = s_find; }
	if (dbg) mput(M_EARLY, sizeof M_EARLY);
	if (EXPBP[0x211] & 0x80) {
		u32 he = (u32)*(u16 *)(EXPBP + 0x224) + 0x200, se = s_esp - 1024u;
		u32 f = he < se ? he : se;                          /* min(), unsigned 32-bit */
		EXHE = (char *)(uintptr_t)f;
	} else mput(M_ANC, sizeof M_ANC);
	LOG("validate_cpu -> %d\n", s_valid);
	if (s_valid) { mput(M_CPU, sizeof M_CPU); LOG("die\n"); return; }
	u32 w[11], o[11];
	if (V_X64) { m_initregs(); mk_regs(w); w[7] = 0xec00; w[4] = 2; m_intcall(0x15, w, 0, 0); }
	LOG("detect_memory\n");
	m_initregs(); mk_regs(w); w[7] = 0x0200; m_intcall(0x16, w, 1, o);
	EXPBP[0x1eb] = (u8)o[7];
	w[7] = 0x0305; m_intcall(0x16, w, 0, 0);
	if (cpu.level >= 6) {
		m_initregs(); mk_regs(w); w[7] = 0xe980; w[5] = 0x47534943; m_intcall(0x15, w, 1, o);
		memcpy(EXPBP + 0x60, &o[7], 4); memcpy(EXPBP + 0x64, &o[4], 4); memcpy(EXPBP + 0x68, &o[6], 4); memcpy(EXPBP + 0x6c, &o[5], 4);
	}
	if (V_APM) LOG("query_apm_bios\n");
	if (V_EDD) LOG("query_edd\n");
	LOG("set_video\ngo_to_protected_mode\n");
}
static void probe_pio(struct port_io_ops *p){
	LOG("pio %d%d%d\n", p->f_inb != 0, p->f_outb != 0, p->f_outw != 0);
	if (p->f_inb) p->f_inb(0x1234); if (p->f_outb) p->f_outb(0xab, 0x0077); if (p->f_outw) p->f_outw(0xbeef, 0x03f8);
}
static void final_state(const struct boot_params *bp, char *h, char *he){
	LOG("bp(nonzero bytes) "); for (int i = 0; i < 4096; i++) if (((const u8 *)bp)[i]) LOG("%x:%02x ", i, ((const u8 *)bp)[i]); LOG("\nHEAP %ld heap_end %ld\n", (long)(h - _end), (long)(he - _end));
}
static u32 pick(u32 *v, int n){ return v[rnd() % n]; }
int main(int argc, char **argv){
	long n = argc > 1 ? atol(argv[1]) : 100000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 88172645463325252ULL;
	long mism = 0, fails = 0, cnt_old = 0, cnt_oldseg = 0, cnt_heap = 0, cnt_clamp = 0, cnt_wrap = 0, cnt_big = 0, cnt_anc = 0, cnt_val = 0, cnt_ist = 0, cnt_dbg = 0;
	for (long i = 0; i < n; i++) {
		u8 h[0x7b]; for (int k = 0; k < 0x7b; k++) h[k] = (u8)rnd();
		memcpy(&hdr, h, 0x7b);
		static const u16 edge16[] = {0, 1, 2, 0x1ff, 0x200, 0xfe00, 0xfdff, 0xffff, 0x8000, 0x7fff, 0x9000, 0xa000, 0xfffe, 0xfe01};
		u16 hp = rnd() % 3 ? edge16[rnd() % 14] : (u16)rnd();
		u16 smv = rnd() % 3 ? edge16[rnd() % 14] : (u16)rnd();
		hdr.heap_end_ptr = hp; hdr.setup_move_size = smv;
		hdr.loadflags = (u8)rnd(); if (rnd() % 2) hdr.loadflags |= 0x80; else hdr.loadflags &= 0x7f;
		static const u32 clv[] = {1, 0x7fff, 0xfffff, 0x100000, 0x100001, 0xfffff0, 0xffffffffu, 0x20000, 0x99fb0, 0x10000};
		switch (rnd() % 4) { case 0: case 1: hdr.cmd_line_ptr = 0; break; case 2: hdr.cmd_line_ptr = clv[rnd() % 10]; break; default: hdr.cmd_line_ptr = (u32)rnd(); }
		s_old[0] = rnd() % 4 ? 0xA33F : (rnd() % 2 ? 0xA33E : (u16)rnd());
		u16 sm = smv;
		switch (rnd() % 6) { case 0: s_old[1] = sm; break; case 1: s_old[1] = sm - 1; break; case 2: s_old[1] = sm + 1; break; case 3: s_old[1] = 0xffff; break; case 4: s_old[1] = 0; break; default: s_old[1] = (u16)rnd(); }
		static const u16 dsv[] = {0, 1, 0x1000, 0x8000, 0xffff, 0xf000, 0x0fff, 0x9000, 0xf001, 0xfffe};
		s_ds = rnd() % 3 == 0 ? dsv[rnd() % 10] : (u16)rnd(); s_fs = (u16)rnd(); s_gs = (u16)rnd();
		u32 he = (u32)hp + 0x200;
		switch (rnd() % 8) {
		case 0: s_esp = rnd() % 2048; break;                       /* wraps below STACK_SIZE */
		case 1: s_esp = he + 1024 + (rnd() % 7) - 3; break;        /* clamp boundary */
		case 2: s_esp = 0xffffffffu - rnd() % 8; break;
		case 3: s_esp = 1024 + (rnd() % 5) - 2; break;
		case 4: s_esp = (u16)rnd(); break;
		case 5: s_esp = 0xfff0 - (rnd() % 64); break;
		default: s_esp = (u32)rnd(); }
		switch (rnd() % 8) { case 0: cpu.level = -1 - (int)(rnd() % 3); break; case 1: cpu.level = 5; break; case 2: cpu.level = 6; break; case 3: cpu.level = 64; break; case 4: cpu.level = (int)(0x80000000u | (u32)rnd()); break; default: cpu.level = (int)(rnd() % 70); }
		switch (rnd() % 4) { case 0: s_find = 0; break; case 1: s_find = 1; break; case 2: s_find = -1; break; default: s_find = (int)rnd(); }
		switch (rnd() % 5) { case 0: case 1: case 2: s_valid = 0; break; case 3: s_valid = 1; break; default: s_valid = (int)rnd(); }
		s_seed = rnd();
		const char *res[2]; char *keep[2];
		for (int w = 0; w < 2; w++) {
			sel_log(); ln = 0; lg[0] = 0; ors = s_seed | 1;
			if (w == 0) { memset(&c_boot_params, 0, sizeof c_boot_params); memset(&c_pio_ops, 0, sizeof c_pio_ops); c_HEAP = c_heap_end = _end; }
			else { memset(&boot_params, 0, sizeof boot_params); memset(&pio_ops, 0, sizeof pio_ops); HEAP = heap_end = _end; }
			if (setjmp(jb) == 0) { if (w == 0) c_main(); else rs_main(); }
			probe_pio(w == 0 ? &c_pio_ops : &pio_ops);
			final_state(w == 0 ? &c_boot_params : &boot_params, w == 0 ? c_HEAP : HEAP, w == 0 ? c_heap_end : heap_end);
			keep[w] = strdup(lg); res[w] = keep[w];
		}
		sel_exp(); en = 0; exp_[0] = 0; ors = s_seed | 1;
		model();
		{ struct port_io_ops fake = { mock_inb, mock_outb, mock_outw }; probe_pio(&fake); }
		struct boot_params ebp; memcpy(&ebp, EXPBP, 4096); final_state(&ebp, EXHEAP, EXHE);
		int bad = 0;
		if (strcmp(res[0], res[1])) { bad = 1; mism++; }
		if (strcmp(res[0], exp_)) { bad = 1; fails++; }
		if (bad && mism + fails <= 3) {
			printf("scenario %ld ds=%04x esp=%08x level=%d find=%d valid=%d old=%04x,%04x hp=%04x smv=%04x lf=%02x cl=%08x\n", i, s_ds, s_esp, cpu.level, s_find, s_valid, s_old[0], s_old[1], hp, smv, hdr.loadflags, hdr.cmd_line_ptr);
			for (int w = 0; w < 2; w++) { printf("--%s--\n", w ? "Rust" : "C"); for (const char *p = res[w]; *p;) { const char *q = strchr(p, '\n'); int l = q ? (int)(q - p) : (int)strlen(p); if (l > 150) l = 150; printf("%.*s\n", l, p); p = q ? q + 1 : p + strlen(p); } }
			printf("--model--\n"); for (const char *p = exp_; *p;) { const char *q = strchr(p, '\n'); int l = q ? (int)(q - p) : (int)strlen(p); if (l > 150) l = 150; printf("%.*s\n", l, p); p = q ? q + 1 : p + strlen(p); }
		}
		cnt_old += hdr.cmd_line_ptr == 0 && s_old[0] == 0xA33F; cnt_oldseg += hdr.cmd_line_ptr == 0 && s_old[0] == 0xA33F && s_old[1] < smv;
		cnt_heap += !!(hdr.loadflags & 0x80); cnt_anc += !(hdr.loadflags & 0x80);
		cnt_clamp += (hdr.loadflags & 0x80) && (u32)hp + 0x200 > s_esp - 1024u; cnt_wrap += (hdr.loadflags & 0x80) && s_esp < 1024;
		cnt_big += hdr.cmd_line_ptr >= 0x100000; cnt_val += s_valid != 0; cnt_ist += !s_valid && cpu.level >= 6; cnt_dbg += s_find != 0;
		free(keep[0]); free(keep[1]);
	}
	printf("scenarios=%ld  C-vs-Rust mismatches=%ld  model mismatches=%ld  (old-cmdline=%ld (offset<move_size: %ld) heap=%ld clamp-active=%ld esp<1024-wrap=%ld no-heap(WARNING)=%ld cmdline>=1MiB=%ld validate-fail=%ld ist-queried=%ld find-true=%ld)\n",
	       n, mism, fails, cnt_old, cnt_oldseg, cnt_heap, cnt_clamp, cnt_wrap, cnt_anc, cnt_big, cnt_val, cnt_ist, cnt_dbg);
	return mism || fails;
}
