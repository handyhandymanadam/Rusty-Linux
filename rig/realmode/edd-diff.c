/* Lockstep differential: C edd.c (run-edd-diff.sh: renames + ONE mechanical edit, see there) vs Rust edd_rs.rs (--cfg host_mock).
 * One scenario = random boot_params header fields (loadflags, heap_end_ptr near the MBR buffer's end, cmd_line_ptr incl. >= 1 MiB), ds, the answers of
 * cmdline_find_option("edd") / _bool("quiet"), and a BIOS with up to 16 drives (EDD present or not, wrong magic, CHS ok/fail, sector size 0/512/2048/odd,
 * MBR read ok/fail, MBR signature bytes, 0xAA55 magic present or not). Both runs log every effect: initregs, intcall (number, ALL 44 ireg bytes, the BIOS output),
 * the cmdline mocks, printf text; then the final boot_params (nonzero bytes) and the heap area behind _end (nonzero bytes). The two logs must be identical. */
#include <asm/bootparam.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
struct port_io_ops pio_ops;
struct boot_params c_boot_params, boot_params;
void c_query_edd(void); void query_edd(void);
char host_end[196608] __attribute__((aligned(65536)));
#define host_heap host_end
#define _end host_end   /* the C and the harness name the heap base `_end` (-D_end=host_end in the runner is the same array) */
char *HEAP, *heap_end;
struct setup_header hdr;

/* layout facts the Rust hard-codes (EDD offsets of the 32-bit target: values taken from the real headers compiled -m32) */
_Static_assert(sizeof(struct boot_params) == 4096, "boot_params");
_Static_assert(offsetof(struct boot_params, eddbuf) == 0xd00 && offsetof(struct boot_params, edd_mbr_sig_buffer) == 0x290, "edd offsets");
_Static_assert(offsetof(struct boot_params, eddbuf_entries) == 0x1e9 && offsetof(struct boot_params, edd_mbr_sig_buf_entries) == 0x1ea, "edd counters");
_Static_assert(offsetof(struct boot_params, hdr.loadflags) == 0x211 && offsetof(struct boot_params, hdr.heap_end_ptr) == 0x224 && offsetof(struct boot_params, hdr.cmd_line_ptr) == 0x228, "hdr");

static uint64_t rs, ors;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs*0x2545F4914F6CDD1DULL;}
static uint64_t ornd(void){ors^=ors<<13;ors^=ors>>7;ors^=ors<<17;return ors*0x2545F4914F6CDD1DULL;}
static char lg[1 << 22]; static size_t ln;
#define LOG(...) (ln += snprintf(lg + ln, sizeof lg - ln, __VA_ARGS__))
static void hex(const u8 *p, int n){ for(int i=0;i<n;i++) LOG("%02x", p[i]); }

/* scenario state */
static u16 s_ds; static int s_quiet; static char s_edd[40]; static int s_edd_ret;
struct drv { int present, badmagic, legfail, mbrfail, magic_ok; u16 bps; u8 ver; u8 sig[4]; };
static struct drv drv[16]; static u64 s_seed;

u16 mock_ds(void){ return s_ds; }
size_t mock_heap_limit(size_t v){ return (size_t)_end - 0x5200 + v; }   /* heap_end_ptr in "target _end == 0x5200" coordinates */
u8 mock_inb(u16 p){ return (u8)p; } void mock_outb(u8 v, u16 p){ (void)v; (void)p; } void mock_outw(u16 v, u16 p){ (void)v; (void)p; }
void initregs(void *r){ u32 *w = r; memset(w, 0, 44); w[10] = 1; w[8] = 0; w[9] = (u32)s_ds | ((u32)s_ds << 16); LOG("initregs ds=%04x\n", s_ds); }
/* a pointer the BIOS gets as a truncated 16-bit offset: rebuild it near the caller's frame (stack) or from _end (64 KiB aligned) */
static u8 *near_stack(u16 off){ uintptr_t fa = (uintptr_t)__builtin_frame_address(0); uintptr_t c = (fa & ~(uintptr_t)0xffff) | off; if (c > fa + 0x8000) c -= 0x10000; else if (c + 0x8000 < fa) c += 0x10000; return (u8 *)c; }
void intcall(u8 n, const void *ireg, void *oreg){
	const u32 *w = ireg; u32 o[11];
	LOG("intcall %02x ireg=", n); hex(ireg, 44); LOG(" oreg=%s\n", oreg ? "ptr" : "NULL");
	for (int i = 0; i < 11; i++) o[i] = (u32)ornd();
	u8 ah = (w[7] >> 8) & 0xff, dl = w[5] & 0xff; u16 ax = w[7] & 0xffff, bx = w[4] & 0xffff;
	int d = dl - 0x80; int ok = n == 0x13 && d >= 0 && d < 16;
	if (n == 0x13 && ah == 0x41) {
		int c = !(ok && drv[d].present && bx == 0x55AA);
		o[10] = (o[10] & ~1u) | c;
		if (!c) { o[4] = (o[4] & ~0xffffu) | (drv[d].badmagic ? 0x1234 : 0xAA55); o[7] = (o[7] & ~0xff00u) | ((u32)drv[d].ver << 8); }
	} else if (n == 0x13 && ah == 0x48) {
		u8 *p = near_stack((u16)w[1]); u16 len; memcpy(&len, p, 2);
		for (int i = 2; i < 74; i++) p[i] = (u8)ornd();
		if (ok) memcpy(p + 24, &drv[d].bps, 2);
		LOG("  params len=%u written at si=%04x\n", len, (u16)w[1]);
	} else if (n == 0x13 && ah == 0x08) {
		o[10] = (o[10] & ~1u) | (ok ? drv[d].legfail : 1);
	} else if (n == 0x13 && ax == 0x0201) {
		int c = !ok || drv[d].mbrfail; o[10] = (o[10] & ~1u) | c;
		if (!c) { u8 *p = (u8 *)_end + bx; for (int i = 0; i < 512; i++) p[i] = (u8)ornd(); memcpy(p + 0x1b8, drv[d].sig, 4); u16 m = drv[d].magic_ok ? 0xAA55 : (u16)ornd(); if (m == 0xAA55 && !drv[d].magic_ok) m ^= 1; memcpy(p + 510, &m, 2); LOG("  mbr read at _end+%04x\n", bx); }
	}
	if (oreg) { memcpy(oreg, o, 44); LOG("  -> "); hex((u8 *)o, 44); LOG("\n"); }
}
int mock_printf(const char *f, ...){ char b[512]; va_list a; va_start(a, f); int n = vsnprintf(b, sizeof b, f, a); va_end(a); LOG("printf "); hex((u8 *)b, n); LOG("\n"); return n; }
int __cmdline_find_option(unsigned long p, const char *opt, char *buf, int sz){
	LOG("find_option %08lx %s bufsize=%d -> ", p, opt, sz);
	int r = s_edd_ret;
	if (r > 0 && sz > 0) { int l = (int)strlen(s_edd); if (l > sz - 1) l = sz - 1; memcpy(buf, s_edd, l); buf[l] = 0; r = l ? l : 0; }
	if (r <= 0 && sz > 0 && s_edd_ret == 0) buf[0] = 0;
	LOG("%d\n", r); return r;
}
int __cmdline_find_option_bool(unsigned long p, const char *opt){ LOG("find_bool %08lx %s -> %d\n", p, opt, s_quiet); return s_quiet; }

static void final_state(const struct boot_params *bp){
	LOG("bp(nonzero) "); for (int i = 0; i < 4096; i++) if (((const u8 *)bp)[i]) LOG("%x:%02x ", i, ((const u8 *)bp)[i]);
	LOG("\nheap(nonzero) "); for (int i = 0; i < 0x10100; i++) if (_end[i]) LOG("%x:%02x ", i, (u8)_end[i]); LOG("\n");
}
int main(int argc, char **argv){
	long n = argc > 1 ? atol(argv[1]) : 100000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 88172645463325252ULL;
	long mism = 0, c_skip = 0, c_off = 0, c_on = 0, c_sig = 0, c_badmagic = 0, c_noheap = 0, c_small = 0, c_cap = 0, c_big = 0, c_quiet = 0, c_oddss = 0, c_read = 0, c_nodrv = 0;
	if ((uintptr_t)host_heap >= (1ULL << 32) || ((uintptr_t)host_heap & 0xffff)) { printf("harness: _end must be host_heap, 64 KiB aligned, below 4 GiB (-no-pie, --defsym)\n"); return 2; }
	for (long i = 0; i < n; i++) {
		static const char *args[] = {"skipmbr", "skip", "off", "on", "", "junk", "SKIP", "skipmbrx", "of", "onn", "0123456", "0123456789abcdef"};
		static const u16 bpsv[] = {0, 512, 512, 512, 2048, 4096, 1, 3, 255, 513, 1024, 0x8000, 0xffff, 0x400, 100, 7, 0x1001};
		memset(&hdr, 0, sizeof hdr);
		memset(drv, 0, sizeof drv);
		int np = rnd() % 4 == 0 ? 0 : (int)(rnd() % 17);
		for (int d = 0; d < 16; d++) {
			drv[d].present = d < np ? (rnd() % 5 != 0) : (rnd() % 4 == 0);
			drv[d].badmagic = rnd() % 8 == 0; drv[d].legfail = rnd() % 3 == 0; drv[d].mbrfail = rnd() % 5 == 0; drv[d].magic_ok = rnd() % 4 != 0;
			drv[d].bps = rnd() % 3 ? 512 : bpsv[rnd() % 17]; drv[d].ver = (u8)rnd(); for (int k = 0; k < 4; k++) drv[d].sig[k] = (u8)rnd();
		}
		s_ds = rnd() % 3 ? (u16)rnd() : (u16[]){0, 1, 0x1000, 0x9000, 0xffff, 0x0200, 0x0fff}[rnd() % 7];
		s_quiet = (int[]){0, 0, 0, 1, -1, 7}[rnd() % 6];
		strcpy(s_edd, args[rnd() % 12]); s_edd_ret = rnd() % 5 == 0 ? 0 : (rnd() % 12 == 0 ? -1 : (int)strlen(s_edd) + (rnd() % 3 == 0 ? 0 : 0));
		if (s_edd_ret > 0 && s_edd[0] == 0) s_edd_ret = 1;
		u8 lf = (u8)rnd(); if (rnd() % 5) lf |= 0x80; else lf &= 0x7f;
		u32 cl = (u32[]){0x20000, 0x20000, 0x1000, 0xfffff, 0x100000, 0x100001, 0xffffffffu, 0, (u32)rnd()}[rnd() % 9];
		s_seed = rnd();
		/* heap_end_ptr in target coordinates: probe around the buffer end (_end == 0x5200 + diff + sector size) */
		u32 ssz = drv[0].bps ? drv[0].bps : 512; u32 ref = 0x5200 + ssz + (u32)(rnd() % 520);
		u16 hep = rnd() % 4 == 0 ? (u16)rnd() : (u16)(ref + (int)(rnd() % 7) - 3 + (rnd() % 2 ? 0 : 512));
		if (rnd() % 8 == 0) hep = (u16[]){0, 1, 0xfe00, 0xffff, 0x5200, 0x5400, 0x5600}[rnd() % 7];
		const char *res[2]; char *keep[2];
		for (int w = 0; w < 2; w++) {
			ln = 0; lg[0] = 0; ors = s_seed | 1;
			struct boot_params *bp = w == 0 ? &c_boot_params : &boot_params;
			memset(bp, 0, sizeof *bp); memset(host_heap, 0, sizeof host_heap);
			bp->hdr.loadflags = lf; bp->hdr.heap_end_ptr = hep; bp->hdr.cmd_line_ptr = cl;
			if (w == 0) c_query_edd(); else query_edd();
			final_state(bp);
			keep[w] = strdup(lg); res[w] = keep[w];
		}
		int bad = strcmp(res[0], res[1]) != 0;
		if (bad) { mism++; if (mism <= 3) { printf("scenario %ld DIFFERS ds=%04x quiet=%d edd=%s ret=%d lf=%02x hep=%04x cl=%08x np=%d\n", i, s_ds, s_quiet, s_edd, s_edd_ret, lf, hep, cl, np);
			const char *a = res[0], *b = res[1]; size_t k = 0; while (a[k] && a[k] == b[k]) k++; size_t st = k > 200 ? k - 200 : 0;
			printf("-- C at %zu: %.400s\n-- R at %zu: %.400s\n", k, a + st, k, b + st); } }
		/* coverage of the arms (from the C log) */
		const char *L = res[0];
		int quiet = s_quiet; c_quiet += quiet != 0; c_big += cl >= 0x100000;
		int did_probe = strstr(L, "printf 50726f62") != NULL;
		if (s_edd_ret > 0 && !strcmp(s_edd, "skipmbr")) c_skip++; if (s_edd_ret > 0 && !strcmp(s_edd, "skip")) c_skip++;
		if (s_edd_ret > 0 && !strcmp(s_edd, "off")) c_off++; if (s_edd_ret > 0 && !strcmp(s_edd, "on")) c_on++;
		if (!(lf & 0x80)) c_noheap++;
		c_read += strstr(L, "mbr read at") != NULL; c_nodrv += (!did_probe && !quiet) ? 1 : 0;
		int sigs = 0; for (const char *p = L; (p = strstr(p, "mbr read at")); p++) sigs++; c_sig += sigs > 0;
		c_badmagic += strstr(L, "edd_mbr_sig_buf_entries") ? 0 : 0;
		c_small += (lf & 0x80) && !strstr(L, "mbr read at") && !strstr(L, "skip");
		int ne = 0; for (const char *p = L; (p = strstr(p, "intcall 13 ireg=")); p++) { ne++; } c_cap += ne > 6 * 3;
		for (int d = 0; d < 16; d++) c_oddss += drv[d].bps && drv[d].bps != 512 && (drv[d].bps & (drv[d].bps - 1));
		free(keep[0]); free(keep[1]);
	}
	printf("scenarios=%ld  C-vs-Rust mismatches=%ld  (skip-arg=%ld off=%ld on=%ld quiet-true=%ld cmdline>=1MiB=%ld no-CAN_USE_HEAP=%ld MBR-read-happened=%ld scenarios-with-MBR-read=%ld heap-too-small(no read, heap ok)=%ld many-calls=%ld odd-sector-size-drives=%ld)\n",
	       n, mism, c_skip, c_off, c_on, c_quiet, c_big, c_noheap, c_read, c_sig, c_small, c_cap, c_oddss);
	return mism != 0;
}
