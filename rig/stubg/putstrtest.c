// Differential test for misc.c's output functions (__putstr, __putnum/__puthex/__putdec, scroll, serial_putchar): the ORIGINAL C
// (pristine misc.c, prefix c_) against misc_rs.rs (prefix rs_). Port I/O goes through pio_ops fakes that log every
// inb()/outb() and return a pseudo-random LSR; compared: the I/O event log, the VGA buffer, boot_params orig_x/orig_y.
// Built/run by rig/stubg/run-putstr.sh.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint16_t u16;
struct port_io_ops { u8 (*f_inb)(u16); void (*f_outb)(u8, u16); void (*f_outw)(u16, u16); };
static uint64_t evh; static unsigned long nev; static uint64_t lsr_state; static int stuck;
static void EVT(uint32_t e) { evh = (evh ^ e) * 1099511628211ULL; nev++; }
static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static u8 fake_inb(u16 port) { lsr_state = lsr_state * 6364136223846793005ULL + 1442695040888963407ULL; u8 v = (stuck || (lsr_state >> 33) % 3 == 0) ? 0x00 : 0x60; EVT(0x10000000u | port); return v; }
static void fake_outb(u8 v, u16 port) { EVT(0x20000000u | ((uint32_t)port << 8) | v); }
static void fake_outw(u16 v, u16 port) { }
extern struct port_io_ops c_pio_ops; struct port_io_ops rs_pio_ops = { fake_inb, fake_outb, fake_outw };
int c_early_serial_base, rs_early_serial_base;
void *c_memmove(void *a, const void *b, size_t n) { return memmove(a, b, n); }
void *rs_memmove(void *a, const void *b, size_t n) { return memmove(a, b, n); }
void *c_memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); }
void *rs_memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); }
void *c_memset(void *a, int c, size_t n) { return memset(a, c, n); }
/* C ref (wrapper) */
void c___putstr(const char *); void c___puthex(unsigned long); void c___putdec(unsigned long);
void c_ref_set_video(int, int, char *, int);
extern void *c_boot_params_ptr;
/* Rust */
void rs___putstr(const char *); void rs___puthex(unsigned long); void rs___putdec(unsigned long);
extern int rs_misc_lines, rs_misc_cols, rs_misc_vidport; extern char *rs_misc_vidmem; void *rs_boot_params_ptr;

#define VID 8192
struct out { uint64_t evh; unsigned long nev; char vga[VID]; unsigned char ox, oy; };
static struct out oc, orr;

static void run(int rust, const char *init_vga, int lines, int cols, int vidport, int serial, unsigned ox, unsigned oy, int kind, const char *str, unsigned long val, struct out *o)
{
	static unsigned char bp[4096]; static char vga[VID];
	memset(bp, 0, sizeof bp); bp[0] = ox; bp[1] = oy; memcpy(vga, init_vga, VID);
	nev = 0; evh = 14695981039346656037ULL; lsr_state = 12345;
	if (rust) { rs_early_serial_base = serial; rs_misc_lines = lines; rs_misc_cols = cols; rs_misc_vidmem = vga; rs_misc_vidport = vidport; rs_boot_params_ptr = bp; }
	else { c_early_serial_base = serial; c_ref_set_video(lines, cols, vga, vidport); c_boot_params_ptr = bp; }
	if (kind == 0) (rust ? rs___putstr : c___putstr)(str);
	else if (kind == 1) (rust ? rs___puthex : c___puthex)(val);
	else (rust ? rs___putdec : c___putdec)(val);
	o->evh = evh; o->nev = nev; memcpy(o->vga, vga, VID); o->ox = bp[0]; o->oy = bp[1];
}
int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 100000; unsigned long fails = 0, checks = 0, nl = 0, scrolls = 0;
	char init[VID], str[300];
	c_pio_ops.f_inb = fake_inb; c_pio_ops.f_outb = fake_outb; c_pio_ops.f_outw = fake_outw;
	for (long i = 0; i < n; i++) {
		for (int k = 0; k < VID; k++) init[k] = rnd();
		int lines = 1 + rnd() % 30, cols = 1 + rnd() % 90, vidport = rnd() % 4 ? 0x3d4 : 0x3b4, serial = rnd() % 2 ? 0x3f8 : 0;
		unsigned m = rnd() % 16; if (m == 0) lines = 0; else if (m == 1) cols = 0;
		if (lines * cols * 2 > VID) { lines = 8; cols = 40; }
		unsigned ox = rnd() % (cols ? cols : 1), oy = rnd() % (lines ? lines : 1);
		if (rnd() % 10 == 0) { ox = rnd() % 256 % (cols ? cols : 1); oy = lines ? lines - 1 : 0; }
		stuck = rnd() % 100 == 0;
		int kind = rnd() % 6 == 0 ? 1 + rnd() % 2 : 0;
		int len = rnd() % 200; for (int k = 0; k < len; k++) { unsigned r = rnd() % 8; str[k] = r == 0 ? '\n' : r == 1 ? '\r' : 1 + rnd() % 126; }
		if (stuck) len = rnd() % 4;
		str[len] = 0;
		unsigned long val = rnd() >> (rnd() % 64); if (rnd() % 8 == 0) val = rnd() % 20;
		run(0, init, lines, cols, vidport, serial, ox, oy, kind, str, val, &oc);
		run(1, init, lines, cols, vidport, serial, ox, oy, kind, str, val, &orr);
		checks++; nl += strchr(str, '\n') != NULL;
		if (oc.nev != orr.nev || oc.evh != orr.evh || memcmp(oc.vga, orr.vga, VID) || oc.ox != orr.ox || oc.oy != orr.oy) {
			fails++; if (fails < 5) printf("DIFF case %ld kind %d lines %d cols %d serial %x ox %u oy %u: events %lu/%lu vga %d xy %u,%u / %u,%u\n", i, kind, lines, cols, serial, ox, oy, oc.nev, orr.nev, memcmp(oc.vga, orr.vga, VID) != 0, oc.ox, oc.oy, orr.ox, orr.oy);
		}
	}
	printf("putstr/puthex/putdec: %lu cases (%lu with newlines)\nchecks=%lu differences=%lu\n", checks, nl, checks, fails);
	return fails != 0;
}
