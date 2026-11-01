// Differential test for misc.c's extract_kernel() (with parse_mem_encrypt() and early_sev_detect()): ORIGINAL C (pristine misc.c, prefix c_)
// against misc_rs.rs (prefix rs_). Every callee is a recording fake (same fake for both sides); compared per random case: return value,
// the full event log (every call with its arguments, every __putstr/error text), the 4096 bytes of boot_params afterwards, the console
// state variables, the heap limits (relative to the heap base). Built/run by rig/stubg/run-extract.sh.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/mman.h>

typedef uint8_t u8; typedef uint16_t u16;
struct port_io_ops { u8 (*f_inb)(u16); void (*f_outb)(u8, u16); void (*f_outw)(u16, u16); };
static char ev[1 << 16];
#define EV(...) do { size_t l = strlen(ev); snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)
static jmp_buf jb;
static uint64_t ph; static unsigned long pn;
static u8 fake_inb(u16 port) { ph = (ph ^ (0x10000000u | port)) * 1099511628211ULL; pn++; return 0x60; }
static void fake_outb(u8 v, u16 port) { if (port == 0x3f8 && v) { size_t l = strlen(ev); if (l < sizeof ev - 2) { ev[l] = v == '\n' ? '~' : v; ev[l + 1] = 0; } } ph = (ph ^ (0x20000000u | ((uint32_t)port << 8) | v)) * 1099511628211ULL; pn++; }
static void fake_outw(u16 v, u16 port) { }
static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

/* the case plan (read by the fakes) */
static struct { int serial; int on, off; uint64_t rsdp; unsigned probe; int use_choose; unsigned long new_out, new_virt; int unacc; unsigned long entry; int call_cb; } plan;
struct port_io_ops rs_pio_ops; extern struct port_io_ops c_pio_ops;
int rs_early_serial_base, c_early_serial_base;
static unsigned char shared_input_data[64];
unsigned int shared_input_len, shared_output_len;
unsigned long *shared_tramp;

#define FAKES(P) \
void *P##memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); } \
void *P##memmove(void *a, const void *b, size_t n) { return memmove(a, b, n); } \
void *P##memset(void *a, int c, size_t n) { return memset(a, c, n); } \
void P##error(char *m) { EV("ERR{%s}", m); longjmp(jb, 1); } \
int P##cmdline_find_option_bool(const char *o) { EV("CMD(%s)", o); return !strcmp(o, "mem_encrypt=on") ? plan.on : !strcmp(o, "mem_encrypt=off") ? plan.off : 0; } \
void P##console_init(void) { EV("CONSOLE"); P##pio_ops.f_inb = fake_inb; P##pio_ops.f_outb = fake_outb; P##pio_ops.f_outw = fake_outw; P##early_serial_base = plan.serial; } \
void P##early_tdx_detect(void) { EV("TDX"); } \
uint64_t P##get_rsdp_addr(void) { EV("RSDP"); return plan.rsdp; } \
unsigned P##rust_preboot_probe(unsigned seed) { EV("PROBE(%x)", seed); return plan.probe; } \
void P##choose_random_location(unsigned long in, unsigned long insz, unsigned long *out, unsigned long osz, unsigned long *virt) { \
	EV("CHOOSE(in=%s sz=%lx out=%lx osz=%lx virt=%lx)", in == (unsigned long)shared_input_data ? "data" : "?", insz, *out, osz, *virt); \
	if (plan.use_choose) { *out = plan.new_out; *virt = plan.new_virt; } } \
_Bool P##init_unaccepted_memory(void) { EV("UNACC?"); return plan.unacc; } \
void P##accept_memory(uint64_t st, unsigned long sz) { EV("ACCEPT(%lx,%lx)", (unsigned long)st, sz); } \
void P##cleanup_exception_handling(void) { EV("CLEANUP"); } \
unsigned long P##decompress_kernel(unsigned char *o, unsigned long v, void (*cb)(char *)) { \
	EV("DECOMP(out=%lx virt=%lx)", (unsigned long)o, v); \
	if (plan.call_cb) { { jmp_buf save; memcpy(save, jb, sizeof jb); if (!setjmp(jb)) cb("cb-msg"); memcpy(jb, save, sizeof jb); } } return plan.entry; }
FAKES(c_) FAKES(rs_)

/* shared data both sides see (aliases: addresses printed in verbose mode are then equal) */
extern unsigned char c_input_data[] __attribute__((alias("shared_input_data")));
extern unsigned char rs_input_data[] __attribute__((alias("shared_input_data")));
extern unsigned int c_input_len __attribute__((alias("shared_input_len")));
extern unsigned int rs_input_len __attribute__((alias("shared_input_len")));
extern unsigned int c_output_len __attribute__((alias("shared_output_len")));
extern unsigned int rs_output_len __attribute__((alias("shared_output_len")));
extern unsigned long *c_trampoline_32bit __attribute__((alias("shared_tramp")));
extern unsigned long *rs_trampoline_32bit __attribute__((alias("shared_tramp")));
uint64_t c_sev_status, rs_sev_status;
int rs_spurious_nmi_count; extern int c_spurious_nmi_count;
long rs_free_mem_ptr, rs_free_mem_end_ptr; extern long c_free_mem_ptr, c_free_mem_end_ptr;
extern void *c_boot_params_ptr; void *rs_boot_params_ptr;
unsigned char rs_boot_heap[1 << 22];
/* from the C ref wrapper */
void *c_ref_extract_kernel(void *, unsigned char *); void c_ref_sanitize(void *); long c_ref_heap_base(void);
void c_ref_video(int *, int *, char **, int *);
extern void *rs_extract_kernel(void *, unsigned char *);
extern int rs_misc_lines, rs_misc_cols, rs_misc_vidport; extern char *rs_misc_vidmem;
void rs_misc_sanitize_boot_params(void *bp) { c_ref_sanitize(bp); }
extern const unsigned long rs_misc_boot_heap_size;
const unsigned long rs_kernel_total_size = 0x9000UL; extern const unsigned long c_kernel_total_size;

struct res { void *ret; char ev[sizeof ev]; uint64_t ph; unsigned long pn; unsigned char vga[0x10000]; unsigned char bp[4096]; int lines, cols, vidport; long vidmem; long fm, fe; int pio_ok; int bpp_ok; };
static void snap(struct res *r, void *bpbuf, int rust, void *ret)
{
	strcpy(r->ev, ev); r->ph = ph; r->pn = pn; memcpy(r->vga, (void *)0xb0000, 0x10000); r->ret = ret; memcpy(r->bp, bpbuf, 4096);
	if (rust) { r->lines = rs_misc_lines; r->cols = rs_misc_cols; r->vidport = rs_misc_vidport; r->vidmem = (long)rs_misc_vidmem;
		r->fm = rs_free_mem_ptr ? rs_free_mem_ptr - (long)rs_boot_heap : 0; r->fe = rs_free_mem_end_ptr ? rs_free_mem_end_ptr - (long)rs_boot_heap : 0;
		r->pio_ok = 1; r->bpp_ok = rs_boot_params_ptr == bpbuf; }
	else { char *vm; c_ref_video(&r->lines, &r->cols, &vm, &r->vidport); r->vidmem = (long)vm;
		r->fm = c_free_mem_ptr ? c_free_mem_ptr - c_ref_heap_base() : 0; r->fe = c_free_mem_end_ptr ? c_free_mem_end_ptr - c_ref_heap_base() : 0;
		r->pio_ok = 1; r->bpp_ok = c_boot_params_ptr == bpbuf; }
}
int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 100000;
	if (c_kernel_total_size != rs_kernel_total_size) { puts("kernel_total_size constant mismatch"); return 2; } unsigned long fails = 0, errs = 0, okc = 0, withcb = 0;
	static unsigned char init[4096], bp[4096], vinit[0x10000]; static struct res rc, rr;
	if (mmap((void *)0xb0000, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED) { puts("mmap 0xb0000 failed"); return 2; }
	unsigned char *outs[] = { (unsigned char *)0x1000000, (unsigned char *)0x1000000, (unsigned char *)0x3000000, (unsigned char *)0x1001000, (unsigned char *)0x200000, (unsigned char *)0x7fff00000000UL };
	unsigned long virts[] = { 0x1000000, 0x1000000, 0x3000000, 0x1200000, 0x1000800, 0x3ff00000, 0x3fe00000, 0x1fe00000, 0x20000000, 0x40000000 };
	char hm[16][96]; unsigned long hc[16] = {0}; int nh = 0;
	for (long i = 0; i < n; i++) {
		for (int k = 0; k < 4096; k += 8) *(uint64_t *)(init + k) = rnd();
		for (int k = 0; k < 0x10000; k += 8) *(uint64_t *)(vinit + k) = rnd();
		if (rnd() % 2) init[0x1ef] = 0;  /* sentinel clear half the time (else the sanitize copy branch runs) */
		init[5] = rnd() % 3 == 0 ? 7 : init[5]; if (rnd() % 8 == 0) init[5] = 7;
		{ unsigned L = rnd() % 10 == 0 ? 0 : 1 + rnd() % 30, C = rnd() % 10 == 0 ? 0 : 1 + rnd() % 80; /* sane screen_info (a bootloader's), VGA window is 64 KiB */
		  init[0xe] = L; init[7] = C; init[0] = C ? rnd() % C : 0; init[1] = L ? rnd() % L : 0; }
		plan.serial = rnd() % 3 ? 0x3f8 : 0; plan.on = rnd() % 3; plan.off = rnd() % 3; plan.rsdp = rnd(); plan.probe = rnd() % 16 ? 0x3074c5e8u : (unsigned)rnd();
		plan.use_choose = rnd() % 2; plan.new_out = (unsigned long)outs[rnd() % 6]; plan.new_virt = virts[rnd() % 10];
		plan.unacc = rnd() % 2; plan.entry = rnd() % 4 ? rnd() % 0x2000000 : 0; plan.call_cb = rnd() % 5 == 0;
		shared_output_len = rnd() % 4 ? (unsigned)(rnd() % 0x2000000) : (unsigned)(0xc30000 + (rnd() % 3) * 0x200000 - 8 + rnd() % 16);
		if (rnd() % 10 == 0) shared_output_len = (unsigned)((1 + rnd() % 16) * 0x200000);  /* exact multiples of MIN_KERNEL_ALIGN: ALIGN() must not round up */
		if (rnd() % 12 == 0) shared_output_len = 0x1ff00000u + (unsigned)(rnd() % 0x300000);  /* around the 512 MiB / 1 GiB image limits */
		shared_input_len = rnd() % 0x400000; shared_tramp = (unsigned long *)(rnd() % 2 ? 0 : rnd() & 0xfffff000);
		c_sev_status = rs_sev_status = rnd() % 2 ? rnd() : (rnd() & ~2ULL);
		c_spurious_nmi_count = rs_spurious_nmi_count = rnd() % 4 == 0 ? rnd() % 100 : 0;
		unsigned char *out = outs[rnd() % 6]; if (out == (unsigned char *)0x7fff00000000UL) out = (unsigned char *)0x1000000;
		for (int side = 0; side < 2; side++) {
			memcpy(bp, init, 4096); c_free_mem_ptr = c_free_mem_end_ptr = rs_free_mem_ptr = rs_free_mem_end_ptr = 0; ev[0] = 0; ph = 14695981039346656037ULL; pn = 0; memcpy((void *)0xb0000, vinit, 0x10000); c_early_serial_base = rs_early_serial_base = 0; void *ret = (void *)-1;
			if (side == 0) { c_pio_ops.f_inb = 0; c_pio_ops.f_outb = 0; c_pio_ops.f_outw = 0; if (!setjmp(jb)) ret = c_ref_extract_kernel(bp, out); snap(&rc, bp, 0, ret); }
			else { rs_pio_ops.f_inb = 0; rs_pio_ops.f_outb = 0; rs_pio_ops.f_outw = 0; if (!setjmp(jb)) ret = rs_extract_kernel(bp, out); snap(&rr, bp, 1, ret); }
		}
		withcb += plan.call_cb;
		if (strstr(rc.ev, "ERR{") && !strstr(rc.ev, "cb-msg")) errs++; else okc++;
		{ const char *e = strstr(rc.ev, "ERR{"); if (e && !strstr(rc.ev, "cb-msg")) { char m[96] = ""; sscanf(e, "ERR{%95[^}]", m); int k; for (k = 0; k < nh; k++) if (!strcmp(hm[k], m)) break; if (k == nh && nh < 16) strcpy(hm[nh++], m); if (k < 16) hc[k]++; } }
		if (rc.ret != rr.ret || strcmp(rc.ev, rr.ev) || memcmp(rc.bp, rr.bp, 4096) || rc.lines != rr.lines || rc.cols != rr.cols || rc.vidport != rr.vidport || rc.vidmem != rr.vidmem
		    || rc.ph != rr.ph || rc.pn != rr.pn || memcmp(rc.vga, rr.vga, 0x10000) || rc.fm != rr.fm || rc.fe != rr.fe || rc.pio_ok != rr.pio_ok || rc.bpp_ok != rr.bpp_ok) {
			fails++; if (fails < 4) printf("DIFF case %ld: ret %p/%p lines %d/%d cols %d/%d vid %lx/%lx port %x/%x heap %lx,%lx/%lx,%lx pio %d/%d bpp %d/%d bp %d\n C : %s\n RS: %s\n", i, rc.ret, rr.ret, rc.lines, rr.lines, rc.cols, rr.cols, rc.vidmem, rr.vidmem, rc.vidport, rr.vidport, rc.fm, rc.fe, rr.fm, rr.fe, rc.pio_ok, rr.pio_ok, rc.bpp_ok, rr.bpp_ok, memcmp(rc.bp, rr.bp, 4096) != 0, rc.ev, rr.ev);
			if (fails < 4) printf(" port-hash %d/%d count %lu/%lu vga-differs %d\n", rc.ph == rr.ph, 1, rc.pn, rr.pn, memcmp(rc.vga, rr.vga, 0x10000) != 0);
			if (fails < 4 && memcmp(rc.vga, rr.vga, 0x10000)) { int k = 0, nd = 0, first = -1; for (k = 0; k < 0x10000; k++) if (rc.vga[k] != rr.vga[k]) { if (first < 0) first = k; nd++; } printf(" vga first diff at +%#x (%d bytes differ) C=%02x RS=%02x; screen_info x,y,mode=%d,%d,%d\n", first, nd, (unsigned char)rc.vga[first], (unsigned char)rr.vga[first], init[0], init[1], init[5]); }
		}
	}
	for (int k = 0; k < nh; k++) printf("  error() reached %7lu times: %s\n", hc[k], hm[k]);
	printf("extract_kernel: %ld cases: %lu reached the kernel jump, %lu stopped by error(); %lu used the error callback\nchecks=%ld differences=%lu\n", n, okc, errs, withcb, n, fails);
	return fails != 0;
}
