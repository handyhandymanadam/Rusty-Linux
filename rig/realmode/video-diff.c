/* Lockstep differential of the five video ports: ALL-C (video.c video-mode.c video-vga.c video-vesa.c video-bios.c, original text, every exported symbol prefixed c_ by -D) vs ALL-Rust
 * (video*_rs.rs built as ONE crate with --cfg host_mock), each side run in a forked child (the C and Rust statics -- probed[], saved, video_segment -- start fresh per scenario).
 * A scenario: initial vid_mode (vga= value: ASK, NORMAL, EXTENDED, CURRENT, 0x0f00..0x0f08, BIOS 0x1xx, VESA 0x2xx, menu positions, resolutions, RECALC bit, junk), a keyboard script, the
 * heap size, the BIOS data area (cols/rows/font), the video memory contents, a BIOS model (adapter CGA/EGA/VGA, VBE absent/present with a random general-info block and mode list, per-mode
 * attributes, modes that fail, top bit dirty), and random port reads. Every effect is logged by both sides: initregs, intcall (number, all 44 ireg bytes, oreg NULL or not, the BIOS answer), port in/out,
 * set_fs, rdfs, copy_from_fs/to_fs (segment, offset, length, data hash), the blank-fill block, puts/putchar/printf/sprintf text, getchar. Afterwards: boot_params, video memory, the heap,
 * the globals and every card (name, nmodes, unsafe, xmode range, mode list contents). The two logs must be identical. */
#include <asm/bootparam.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef unsigned int addr_t;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
struct port_io_ops pio_ops;
struct boot_params c_boot_params, boot_params;
struct card_info { const char *card_name; int (*set_mode)(void *); int (*probe)(void); void *modes; int nmodes; int unsafe; u16 xmode_first, xmode_n; };
struct mode_info { u16 mode, x, y, depth; };
extern struct card_info __start_videocards_c[], __stop_videocards_c[], __start_videocards_rs[], __stop_videocards_rs[];
extern int c_adapter, c_force_x, c_force_y, c_do_restore, c_graphic_mode, adapter, force_x, force_y, do_restore, graphic_mode;
void c_set_video(void); void set_video(void);
extern u8 c_vginfo[256], c_vminfo[256], vginfo[256], vminfo[256];
char host_end[1 << 17] __attribute__((aligned(65536)));
char *HEAP, *heap_end;
struct setup_header hdr;
#define MEMSZ 0x120000
static u8 mem[MEMSZ];

_Static_assert(offsetof(struct boot_params, screen_info) == 0 && sizeof(struct boot_params) == 4096, "bp");
_Static_assert(offsetof(struct boot_params, edid_info) == 0x140 && sizeof(struct edid_info) == 128 && offsetof(struct boot_params, hdr.vid_mode) == 0x1fa, "edid/vid_mode");
#define SI(f) offsetof(struct screen_info, f)
_Static_assert(SI(orig_x) == 0 && SI(orig_y) == 1 && SI(orig_video_page) == 4 && SI(orig_video_mode) == 6 && SI(orig_video_cols) == 7 && SI(flags) == 8 && SI(orig_video_ega_bx) == 10 && SI(orig_video_lines) == 14 && SI(orig_video_isVGA) == 15 && SI(orig_video_points) == 16, "si1");
_Static_assert(SI(lfb_width) == 18 && SI(lfb_height) == 20 && SI(lfb_depth) == 22 && SI(lfb_base) == 24 && SI(lfb_size) == 28 && SI(lfb_linelength) == 36 && SI(red_size) == 38 && SI(red_pos) == 39 && SI(green_size) == 40 && SI(green_pos) == 41, "si2");
_Static_assert(SI(blue_size) == 42 && SI(blue_pos) == 43 && SI(rsvd_size) == 44 && SI(rsvd_pos) == 45 && SI(vesapm_seg) == 46 && SI(vesapm_off) == 48 && SI(pages) == 50 && SI(vesa_attributes) == 52, "si3");
_Static_assert(VIDEO_FLAGS_NOCURSOR == 1 && VIDEO_TYPE_VLFB == 0x23, "si const");

static uint64_t rs, ors;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs*0x2545F4914F6CDD1DULL;}
static uint64_t ornd(void){ors^=ors<<13;ors^=ors>>7;ors^=ors<<17;return ors*0x2545F4914F6CDD1DULL;}
static char *lg; static size_t ln; static const size_t LGMAX = 1 << 23;
#define LOG(...) do { if (ln < LGMAX - 4096) ln += snprintf(lg + ln, 4096, __VA_ARGS__); } while (0)
static void hex(const u8 *p, int n){ for(int i=0;i<n;i++) LOG("%02x", p[i]); }

/* ---- scenario ---- */
static u16 s_ds, s_fs; static int s_side;
static int s_adapter;           /* 0 CGA/MDA, 1 EGA, 2 VGA */
static int s_vbe, s_vbever, s_vbesig_ok, s_total_mem, s_caps, s_nvbemodes; static u16 s_vbemodes[300]; static u16 s_vbe_seg, s_vbe_off;
static int s_texty, s_gfx;
static int s_curmode, s_dirty_top, s_failmask_seed, s_nofail; static u8 s_page;
static int s_curch, s_curcl, s_curx, s_cury;
static u8 s_keys[64]; static int s_nkeys, s_ki, s_tkeys[64], s_ntk, s_ti;
static u64 s_seed;

u16 mock_ds(void){ return s_ds; }
void mock_set_fs(u16 s){ s_fs = s; LOG("set_fs %04x\n", s); }
static u32 lin(u32 a){ return (((u32)s_fs << 4) + a) % MEMSZ; }
u8 mock_rdfs8(addr_t a){ u8 v = mem[lin(a)]; LOG("rdfs8 %04x:%x -> %02x\n", s_fs, a, v); return v; }
u16 mock_rdfs16(addr_t a){ u16 v = mem[lin(a)] | (mem[lin(a + 1)] << 8); LOG("rdfs16 %04x:%x -> %04x\n", s_fs, a, v); return v; }
static u32 hash(const u8 *p, size_t n){ u32 h = 2166136261u; for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u; return h; }
void mock_copy_from_fs(void *dst, addr_t src, size_t len){ LOG("copy_from_fs %04x:%x len=%zu\n", s_fs, src, len); for (size_t i = 0; i < len; i++) ((u8 *)dst)[i] = mem[lin(src + i)]; }
void mock_copy_to_fs(addr_t dst, void *src, size_t len){ LOG("copy_to_fs %04x:%x len=%zu data=%08x\n", s_fs, dst, len, hash(src, len)); for (size_t i = 0; i < len; i++) mem[lin(dst + i)] = ((u8 *)src)[i]; }
/* the C asm block / the Rust asm block: pushw es; movw seg,es; shrw cx; jnc 1f; stosw; 1: rep stosl; popw es with ax = 0x0720 (eax = 0x07200720); 16-bit cx/di */
void mock_blank_fill_c(u16 seg, u32 *dst, u32 *npad){
	u32 di = *dst & 0xffff, cx = *npad & 0xffff, carry = cx & 1; cx >>= 1; u32 base = (u32)seg << 4;
	LOG("blank_fill seg=%04x edi=%08x ecx=%08x\n", seg, *dst, *npad);
	if (carry) { u32 o = (base + di) % MEMSZ; mem[o] = 0x20; mem[(o + 1) % MEMSZ] = 0x07; di = (di + 2) & 0xffff; }
	while (cx--) { for (int k = 0; k < 4; k++) mem[(base + ((di + k) & 0xffff)) % MEMSZ] = (k & 1) ? 0x07 : 0x20; di = (di + 4) & 0xffff; }
	*dst = (*dst & 0xffff0000u) | di; *npad = *npad & 0xffff0000u;
}
void mock_blank_fill_hook(u16 seg, u32 dst, u32 npad, u32 *out){ mock_blank_fill_c(seg, &dst, &npad); out[0] = dst; out[1] = npad; }

u8 mock_inb(u16 p){ u8 v = (p & 1) && p != 0x3cd ? ((ornd() & 3) ? 0 : (u8)ornd()) : (u8)ornd(); LOG("inb %04x -> %02x\n", p, v); return v; }
void mock_outb(u8 v, u16 p){ LOG("outb %02x %04x\n", v, p); }
void mock_outw(u16 v, u16 p){ LOG("outw %04x %04x\n", v, p); }
void initregs(void *r){ u32 *w = r; memset(w, 0, 44); w[10] = 1; w[8] = 0; w[9] = (u32)s_ds | ((u32)s_ds << 16); LOG("initregs ds=%04x\n", s_ds); }

void mock_puts(const char *s){ LOG("puts "); hex((const u8 *)s, strlen(s)); LOG("\n"); }
void mock_putchar(int c){ LOG("putchar %d\n", c); }
int mock_getchar(void){ int k = s_ki < s_nkeys ? s_keys[s_ki++] : '\r'; LOG("getchar -> %d\n", k); return k; }
void mock_kbd_flush(void){ LOG("kbd_flush\n"); }
int mock_getchar_timeout(void){ int k = s_ti < s_ntk ? s_tkeys[s_ti++] : 0; LOG("getchar_timeout -> %d\n", k); return k; }
int mock_printf(const char *f, ...){ char b[512]; va_list a; va_start(a, f); int n = vsnprintf(b, sizeof b, f, a); va_end(a); LOG("printf "); hex((u8 *)b, n); LOG("\n"); return n; }
int mock_sprintf(char *buf, const char *f, ...){ va_list a; va_start(a, f); int n = vsprintf(buf, f, a); va_end(a); LOG("sprintf "); hex((u8 *)buf, n); LOG("\n"); return n; }

static int name_of(u16 off){ if (off == (u16)(uintptr_t)c_vginfo || off == (u16)(uintptr_t)vginfo) return 1; if (off == (u16)(uintptr_t)c_vminfo || off == (u16)(uintptr_t)vminfo) return 2;
	if (off == (u16)(uintptr_t)&c_boot_params.edid_info || off == (u16)(uintptr_t)&boot_params.edid_info) return 3; return 0; }
static u8 *resolve(u16 off, size_t need){   /* which static buffer does a truncated 16-bit offset name? */
	u8 *c[6] = { c_vginfo, c_vminfo, vginfo, vminfo, (u8 *)&c_boot_params.edid_info, (u8 *)&boot_params.edid_info };
	size_t sz[6] = { 256, 256, 256, 256, 128, 128 };
	for (int i = 0; i < 6; i++) if ((u16)(uintptr_t)c[i] == off) { (void)need; (void)sz; return c[i]; }
	LOG("BIOS: unresolved buffer offset %04x\n", off); return NULL;
}
static u16 vm_attr(u16 mode){ if (s_texty) return 0x05; if (s_gfx && (mode & 1)) return 0x99; u32 h = (u32)(s_seed >> 8) * 2654435761u + mode * 40503u; switch ((h >> 8) % 8) { case 0: case 1: return 0x05 | (u16)((h >> 20) & 0x200); case 2: return 0x99; case 3: return 0x9b; case 4: return 0x15; case 5: return 0x19; case 6: return (u16)h; default: return 0x0d; } }
static int mode_fails(u8 m){ return !s_nofail && ((hash(&m, 1) ^ (u32)s_failmask_seed) % 5 == 0); }
void intcall(u8 n, const void *ireg, void *oreg){
	const u32 *w = ireg; u32 o[11];
	{ u32 t[11]; memcpy(t, ireg, 44); int id = name_of((u16)(t[0] & 0xffff)); if (id) t[0] = (t[0] & ~0xffffu) | (0xb000u + id);   /* buffer addresses differ between the C and Rust builds: log a name */
	  LOG("intcall %02x ireg=", n); hex((u8 *)t, 44); LOG(" oreg=%s\n", oreg ? "ptr" : "NULL"); }
	for (int i = 0; i < 11; i++) o[i] = (u32)ornd();
	o[10] &= ~1u;
	u16 ax = w[7] & 0xffff, bx = w[4] & 0xffff, cx = w[6] & 0xffff, di = w[0] & 0xffff; u8 ah = ax >> 8, al = ax & 0xff, bl = bx & 0xff;
	if (n == 0x10) {
		if (ah == 0x03) { o[5] = (o[5] & ~0xffffu) | (s_cury << 8) | s_curx; o[6] = (o[6] & ~0xffffu) | (s_curch << 8) | s_curcl; }
		else if (ah == 0x0f) { o[7] = (o[7] & ~0xffffu) | (80 << 8) | (u8)(s_curmode | (s_dirty_top ? 0x80 : 0)); o[4] = (o[4] & ~0xff00u) | ((u32)s_page << 8); }
		else if (ah == 0x00 && ax < 0x80) {   /* set mode */
			if (!mode_fails(al)) s_curmode = al & 0x7f; else if (rnd() % 2) s_curmode = (int)(ornd() & 0x7f);
		}
		else if (ax == 0x1200 && bl == 0x10) { if (s_adapter == 0) o[4] = (o[4] & ~0xffffu) | 0x0010 | (bx & 0xff00); else o[4] = (o[4] & ~0xffffu) | (u16)(0x0003 | ((ornd() & 0xff) << 8)); }
		else if (ax == 0x1a00) { if (s_adapter == 2) o[7] = (o[7] & ~0xffu) | 0x1a; else if ((o[7] & 0xff) == 0x1a) o[7] ^= 1; }
		else if (ax == 0x4f00) {
			u8 *p = resolve(di, 256);
			if (p && s_vbe) { memset(p, 0, 256); u32 sig = s_vbesig_ok ? 0x41534556u : (u32)ornd(); memcpy(p, &sig, 4); u16 v = s_vbever; memcpy(p + 4, &v, 2); u32 caps = s_caps; memcpy(p + 10, &caps, 4); memcpy(p + 14, &s_vbe_off, 2); memcpy(p + 16, &s_vbe_seg, 2); u16 tm = s_total_mem; memcpy(p + 18, &tm, 2); o[7] = (o[7] & ~0xffffu) | 0x004f; }
			else o[7] = (o[7] & ~0xffffu) | (u16)(0x014f);
		}
		else if (ax == 0x4f01) {
			u8 *p = resolve(di, 256);
			if (p && s_vbe && !((cx ^ s_failmask_seed) % 7 == 0)) { u16 at = vm_attr(cx); u32 h = (u32)(s_seed >> 4) + cx * 7919u; u8 q[256]; memset(q, 0, 256); memcpy(q, &at, 2);
				u16 hr = 320 + (h % 20) * 64, vr = 200 + ((h >> 5) % 12) * 50; if (!s_texty || (h % 5 == 0)) { if (h % 9 == 0) hr = 0; if ((h >> 3) % 11 == 0) vr = 0; if (h % 7 == 0) hr = vr = 0; } memcpy(q + 18, &hr, 2); memcpy(q + 20, &vr, 2); q[24] = (h & 0x100) ? 1 : (u8)(h >> 9); q[25] = s_gfx ? (u8[]){8, 8, 15, 8}[(h >> 12) % 4] : (u8[]){8, 15, 16, 24, 32, 4}[(h >> 12) % 6]; q[27] = (u8[]){4, 6, 4, 6, 3, 0}[(h >> 3) % 6]; q[29] = (u8)(h >> 14);
				for (int k = 31; k < 40; k++) q[k] = (u8)(h >> k); u16 ls = hr * q[25] / 8; memcpy(q + 16, &ls, 2); u32 lfb = 0xe0000000u + (h & 0xff0000); memcpy(q + 40, &lfb, 4); if ((h >> 7) % 8 == 0) memcpy(p, q, 24); else memcpy(p, q, 50); o[7] = (o[7] & ~0xffffu) | 0x004f; }
			else o[7] = (o[7] & ~0xffffu) | 0x0100;
		}
		else if (ax == 0x4f02) { u16 vm = bx & 0x1ff; o[7] = (o[7] & ~0xffffu) | ((s_vbe && !mode_fails((u8)vm)) ? 0x004f : 0x0100); }
		else if (ax == 0x4f08) { o[7] = (o[7] & ~0xffffu) | ((ornd() & 3) ? 0x004f : 0x014f); o[4] = (o[4] & ~0xff00u) | ((ornd() & 1) ? 0x0800 : 0x0600); }
		else if (ax == 0x4f0a) { o[7] = (o[7] & ~0xffffu) | ((ornd() & 3) ? 0x004f : 0x024f); }
		else if (ax == 0x4f15) { o[7] = (o[7] & ~0xffffu) | ((ornd() & 3) ? 0x004f : 0x014f);
			if (bx == 1 && (o[7] & 0xffff) == 0x004f) { u8 *p = resolve(di, 128); if (p) for (int k = 0; k < 128; k++) p[k] = (u8)ornd(); } }
	}
	if (oreg) { memcpy(oreg, o, 44); LOG("  -> "); hex((u8 *)o, 44); LOG("\n"); }
}

static void dump_cards(struct card_info *b, struct card_info *e, int *ad, int *fx, int *fy, int *dr, int *gm){
	LOG("globals adapter=%d force_x=%d force_y=%d do_restore=%d graphic_mode=%d\n", *ad, *fx, *fy, *dr, *gm);
	for (struct card_info *c = b; c < e; c++) {
		LOG("card %s nmodes=%d unsafe=%d xmode=%04x+%04x modes=%s heapoff=%ld probe=%d set_mode=%d\n", c->card_name, c->nmodes, c->unsafe, c->xmode_first, c->xmode_n, c->modes ? "set" : "null",
		    ((char *)c->modes >= host_end && (char *)c->modes < host_end + sizeof host_end) ? (long)((char *)c->modes - host_end) : -1L, c->probe != 0, c->set_mode != 0);
		if (c->modes) for (int i = 0; i < c->nmodes && i < 300; i++) { struct mode_info *m = (struct mode_info *)c->modes + i; LOG("  mode %04x %u %u %u\n", m->mode, m->x, m->y, m->depth); }
	}
}
static void run_side(int w){
	memset(w == 0 ? (void *)&c_boot_params : (void *)&boot_params, 0, 4096);
	struct boot_params *bp = w == 0 ? &c_boot_params : &boot_params;
	bp->hdr.vid_mode = (u16)(s_seed >> 20 & 0xffff);   /* overwritten by the caller below */
}
static u16 s_vid;
static u32 s_heapsz;
static void side(int w, char *out){
	lg = out; ln = 0; lg[0] = 0; ors = s_seed | 1; s_ki = s_ti = 0;
	struct boot_params *bp = w == 0 ? &c_boot_params : &boot_params;
	memset(bp, 0, sizeof *bp); bp->hdr.vid_mode = s_vid;
	memset(host_end, 0, sizeof host_end); HEAP = host_end; heap_end = host_end + s_heapsz;
	s_fs = 0xdead;
	if (w == 0) c_set_video(); else set_video();
	LOG("bp(nonzero) "); for (int i = 0; i < 4096; i++) if (((u8 *)bp)[i]) LOG("%x:%02x ", i, ((u8 *)bp)[i]);
	LOG("\nmem(nonzero) "); for (int i = 0; i < MEMSZ; i++) if (mem[i]) { /* only the regions the code can touch */ if (i >= 0xb0000 && i < 0xc0000) LOG("%x:%02x ", i, mem[i]); }
	LOG("\nheap(nonzero) "); for (int i = 0; i < (int)sizeof host_end; i++) if (host_end[i]) LOG("%x:%02x ", i, (u8)host_end[i]);
	LOG("\nHEAP=%ld heap_end=%ld\n", (long)(HEAP - host_end), (long)(heap_end - host_end));
	if (w == 0) dump_cards(__start_videocards_c, __stop_videocards_c, &c_adapter, &c_force_x, &c_force_y, &c_do_restore, &c_graphic_mode);
	else dump_cards(__start_videocards_rs, __stop_videocards_rs, &adapter, &force_x, &force_y, &do_restore, &graphic_mode);
	LOG("end\n");
}
int main(int argc, char **argv){
	long n = argc > 1 ? atol(argv[1]) : 20000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 88172645463325252ULL; long mism = 0;
	if ((uintptr_t)host_end >= (1ULL << 32) || ((uintptr_t)host_end & 0xffff)) { printf("harness: host_end must be below 4 GiB and 64 KiB aligned\n"); return 2; }
	pio_ops.f_inb = mock_inb; pio_ops.f_outb = mock_outb; pio_ops.f_outw = mock_outw;
	char *shm = mmap(0, 2 * LGMAX, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	long cov[16] = {0};
	for (long i = 0; i < n; i++) {
		s_seed = rnd(); s_ds = rnd() % 3 ? 0x1000 : (u16)rnd();
		s_adapter = (int)(rnd() % 3); if (rnd() % 3 == 0) s_adapter = 2;
		s_vbe = rnd() % 2; s_vbever = rnd() % 5 ? 0x0300 : (int[]){0x0101, 0x0102, 0x0200, 0x0100, 0xffff}[rnd() % 5]; s_vbesig_ok = rnd() % 8 != 0; s_total_mem = (int)(rnd() % 4096); s_caps = (int)rnd();
		s_nvbemodes = rnd() % 4 == 0 ? (int)(rnd() % 290) : (int)(rnd() % 14); for (int k = 0; k < s_nvbemodes; k++) s_vbemodes[k] = rnd() % 4 ? (u16)(0x100 + rnd() % 0x80) : (u16)rnd(); 
		for (int k = 0; k < s_nvbemodes; k++) if (s_vbemodes[k] == 0xffff) s_vbemodes[k] = 0x101;
		s_texty = rnd() % 6 == 0; s_gfx = rnd() % 4 == 0;
		if (s_texty) { s_vbe = 1; s_vbever = 0x0300; s_vbesig_ok = 1; s_nvbemodes = 10 + (int)(rnd() % 8); for (int k = 0; k < s_nvbemodes; k++) s_vbemodes[k] = (u16)(0x100 + k + (rnd() % 3 == 0 ? 0 : 0)); s_nofail = 1; }
		s_vbe_seg = rnd() % 2 ? 0xc000 : (u16)rnd(); s_vbe_off = (u16)(rnd() & 0xfff0) | 0; if (rnd() % 8 == 0) s_vbe_off = 0xfff0;
		s_curmode = (int[]){3, 3, 7, 1, 0x12, 0x13, 0x55}[rnd() % 7]; s_dirty_top = rnd() % 4 == 0; s_failmask_seed = (int)rnd(); s_nofail = rnd() % 3 == 0; if (s_texty) s_nofail = 1; s_page = (u8)rnd();
		s_curx = rnd() % 80; s_cury = rnd() % 50; s_curch = (rnd() % 4) == 0 ? (int)(rnd() & 0xff) : (int)(rnd() % 14); s_curcl = (int)(rnd() % 16);
		memset(mem, 0, sizeof mem);
		for (int k = 0; k < 0x200; k++) mem[0x400 + k] = (u8)rnd();
		u16 cols = rnd() % 3 ? 80 : (u16)rnd(); mem[0x44a] = cols & 0xff; mem[0x44b] = cols >> 8; mem[0x484] = rnd() % 3 ? (u8)(rnd() % 2 ? 24 : 49) : (u8)rnd(); mem[0x485] = rnd() % 3 ? 16 : (u8)rnd();
		for (int k = 0xb8000; k < 0xb8000 + 4000; k++) mem[k] = (u8)rnd(); for (int k = 0xb0000; k < 0xb0000 + 4000; k++) mem[k] = (u8)rnd();
		for (int k = 0; k < s_nvbemodes; k++) { u32 a = (((u32)s_vbe_seg << 4) + s_vbe_off + 2 * k) % MEMSZ; mem[a] = s_vbemodes[k] & 0xff; mem[(a + 1) % MEMSZ] = s_vbemodes[k] >> 8; }
		{ u32 a = (((u32)s_vbe_seg << 4) + s_vbe_off + 2 * s_nvbemodes) % MEMSZ; mem[a] = 0xff; mem[(a + 1) % MEMSZ] = 0xff; }
		static const u16 vids[] = {0xfffd, 0xfffd, 0xfffd, 0xffff, 0xfffe, 0x0f04, 0x0f00, 0x0f01, 0x0f02, 0x0f03, 0x0f05, 0x0f06, 0x0f07, 0x0f08, 0x0f09, 0x0100, 0x0103, 0x0114, 0x017f, 0x0180, 0x0200, 0x0201, 0x0211, 0x0301, 0x1950, 0x2b50, 0x3c50, 0x0000, 0x0001, 0x0002, 0x0003, 0x0005, 0x000a, 0x8f01, 0x8f00, 0x8f02, 0x8f05, 0x8f06, 0x8f07, 0x8100, 0x8f04, 0xfffc, 0x1000};
		s_vid = rnd() % 5 == 0 ? (u16)rnd() : vids[rnd() % (sizeof vids / sizeof vids[0])];
		if ((s_texty || s_gfx) && rnd() % 2) s_vid = rnd() % 2 ? 0xfffd : (rnd() % 2 ? (u16)(0x200 + (rnd() % 20)) : (u16)(7 + rnd() % 14));
		/* keys: menu paths */
		s_nkeys = 0; s_ntk = 0; int kind = rnd() % 8;
		static const char *scripts[] = {"\r", "\r", "1\r", "scan\r", "scan\r1\r", "\b\b0a\r", "zz9\b\bf\r", "f f\r", "ABCDE\r", "x\r", "scan\rscan\rff\r", "ffff\r", "0f01\r", "?\r", "\b\r", "1\r\r", " \r", "3\r"};
		const char *sc = scripts[rnd() % (sizeof scripts / sizeof scripts[0])];
		for (const char *p = sc; *p; p++) s_keys[s_nkeys++] = (u8)*p; if (kind == 0) { s_keys[s_nkeys++] = 'q'; s_keys[s_nkeys++] = '\r'; }
		if (rnd() % 2) s_tkeys[s_ntk++] = '\r'; else { int t = rnd() % 4; if (t == 0) s_tkeys[s_ntk++] = ' '; else if (t == 1) s_tkeys[s_ntk++] = 0; else { s_tkeys[s_ntk++] = 'x'; s_tkeys[s_ntk++] = 0; } }
		s_heapsz = (u32)(rnd() % 6 == 0 ? rnd() % 700 : (rnd() % 6 == 0 ? 4160 + rnd() % 64 : 1 + rnd() % 40000));
		if (rnd() % 6 == 0) { u32 cx8 = (u8)(mem[0x44a]); s_heapsz = cx8 * 25 * 2 + 512 + (int)(rnd() % 3) - 1; }
		if (s_heapsz > sizeof host_end - 64) s_heapsz = sizeof host_end - 64;
		u8 mem0[MEMSZ]; (void)mem0;
		static u8 memsave[MEMSZ]; memcpy(memsave, mem, MEMSZ);
		char *o[2] = { shm, shm + LGMAX };
		for (int w = 0; w < 2; w++) {
			pid_t pid = fork();
			if (pid == 0) { side(w, o[w]); _exit(0); }
			int st; waitpid(pid, &st, 0); if (!WIFEXITED(st)) { snprintf(o[w], 200, "CHILD DIED status=%d\n", st); }
		}
		if (strcmp(o[0], o[1])) { mism++; if (mism <= 3) { printf("scenario %ld DIFFERS vid=%04x adapter=%d vbe=%d heap=%u keys=%s\n", i, s_vid, s_adapter, s_vbe, s_heapsz, sc);
			const char *a = o[0], *b = o[1]; size_t k = 0; while (a[k] && a[k] == b[k]) k++;
			size_t ls = k; while (ls > 0 && a[ls - 1] != '\n') ls--; size_t back = ls; for (int q = 0; q < 6 && back > 0; q++) { back--; while (back > 0 && a[back - 1] != '\n') back--; }
			printf("-- common tail:\n%.*s", (int)(ls - back), a + back); printf("-- C line: %.300s\n", a + ls); printf("-- R line: %.300s\n", b + ls); } }
		const char *L = o[0];
		cov[0] += s_vid == 0xfffd; cov[1] += strstr(L, "puts 4d6f64653a") != NULL;   /* "Mode:" menu header */
		cov[2] += strstr(L, "printf 556e646566696e6564") != NULL;                    /* Undefined video mode */
		cov[3] += strstr(L, "blank_fill") != NULL; cov[4] += strstr(L, "copy_to_fs") != NULL; cov[5] += strstr(L, "ireg=") && strstr(L, " intcall 10 ireg=00000000") != NULL;
		cov[6] += strstr(L, "intcall 10 ireg=") && strstr(L, "00004f01") != NULL; cov[7] += strstr(L, "card VESA nmodes=0") == NULL && strstr(L, "card VESA") != NULL;
		cov[8] += strstr(L, "card BIOS nmodes=0") == NULL && strstr(L, "card BIOS") != NULL; cov[9] += (s_vid & 0x8000) != 0; cov[10] += strstr(L, "outw") != NULL;
		cov[11] += strstr(L, "copy_from_fs") != NULL; cov[12] += strstr(L, "mode 0") != NULL;
		cov[13] += s_vbe && s_vbesig_ok && s_vbever >= 0x102;
	}
	printf("scenarios=%ld  C-vs-Rust mismatches=%ld  (ask=%ld menu-drawn=%ld undefined-mode=%ld blank-fill=%ld copy_to_fs=%ld vbe-4f01=%ld vesa-modes=%ld bios-modes=%ld recalc=%ld outw=%ld copy_from_fs=%ld vbe-usable=%ld)\n",
	       n, mism, cov[0], cov[1], cov[2], cov[3], cov[4], cov[6], cov[7], cov[8], cov[9], cov[10], cov[11], cov[13]);
	return mism != 0;
}
