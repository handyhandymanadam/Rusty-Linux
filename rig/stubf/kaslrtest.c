// Differential test for kaslr.c: the ORIGINAL C kaslr.o (prefix c_; a copy of the source whose ONLY changes are the four hardware
// leaf calls rdtsc()/rdrand_long()/inb()/outb() of arch/x86/lib/kaslr.c renamed to kaslr_hw_*, see run-kaslr.sh) against the Rust
// kaslr_rs.o (prefix rs_, built with --cfg=stubf_fake_hw) + kaslr_cfg.o. Both are fed IDENTICAL random inputs and identical fake
// hardware answers, each in its own fork()ed child (kaslr.c keeps state in statics). Compared per case: *output, *virt_addr,
// the loadflags byte, and the full event log (every __putstr/warn/error/malloc/free/has_cpuflag/hw call with its arguments).
// Then the exported lib/cmdline.c and ctype functions are compared on random strings, and kaslr_get_random_long() directly.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

typedef unsigned long ul;
static char ev[16384];
#define EV(...) do { size_t l = strlen(ev); if (l < sizeof ev - 200) snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)

struct res { int status; ul output, virt; unsigned char lf; char ev[16384]; };
/* ---------------- per-case fake state (copied into each child by fork) ---------------- */
static ul f_cmdline;               /* get_cmd_line_ptr() */
static int f_nokaslr, f_rdrand_cpu, f_tsc_cpu, f_rdrand_ok, f_malloc_null, f_soft_reserve, f_l5;
static uint64_t f_rdrand_val, f_tsc_val;
static unsigned char f_inb[32]; static int f_inb_n;
static int f_imm_n; struct mv { uint64_t start, size; };
static struct mv f_imm[8];
static char malloc_buf[4096 + 64];
static int cur_which; struct res; static struct res *shm; static int inb_k;

#define FAKES(P) \
void *P##boot_params_ptr; \
struct mv P##immovable_mem[8]; \
unsigned int P##__pgtable_l5_enabled; \
void P##__putstr(const char *s) { EV("[%s]", s); } \
void P##warn(const char *m) { EV("warn(%s);", m); } \
void P##error(char *m) { EV("error(%s);", m); shm[cur_which].status = 42; shm[cur_which].output = shm[cur_which].virt = 0; shm[cur_which].lf = 0; strcpy(shm[cur_which].ev, ev); _exit(42); } \
ul P##get_cmd_line_ptr(void) { EV("cmdline;"); return f_cmdline; } \
int P##cmdline_find_option_bool(const char *o) { EV("optbool(%s);", o); return f_nokaslr && !strcmp(o, "nokaslr"); } \
void *P##malloc(int n) { EV("malloc(%d);", n); if (f_malloc_null || n > 4096) return NULL; return malloc_buf; } \
void P##free(void *p) { EV("free(%d);", p == malloc_buf); } \
bool P##has_cpuflag(int f) { EV("cpuflag(%d);", f); return f == 158 ? f_rdrand_cpu : f == 4 ? f_tsc_cpu : 0; } \
int P##count_immovable_mem_regions(void) { EV("immovable(%d);", f_imm_n); memcpy(P##immovable_mem, f_imm, sizeof f_imm); return f_imm_n; } \
bool P##__efi_soft_reserve_enabled(void) { EV("softres;"); return f_soft_reserve; } \
bool P##kaslr_hw_rdrand_long(unsigned long *v) { EV("rdrand;"); *v = f_rdrand_val; return f_rdrand_ok; } \
uint64_t P##kaslr_hw_rdtsc(void) { EV("rdtsc;"); return f_tsc_val; } \
unsigned char P##kaslr_hw_inb(unsigned short port) { int k = inb_k++; unsigned char v = (k % 3 == 0) ? ((k / 3 < f_inb_n) ? (f_inb[0] | 0x40) : (f_inb[0] & ~0x40)) : f_inb[1 + k % 3]; EV("inb(%x)=%02x;", port, v); return v; } \
void P##kaslr_hw_outb(unsigned char v, unsigned short port) { EV("outb(%02x,%x);", v, port); } \
size_t P##strnlen(const char *s, size_t n) { return strnlen(s, n); } \
size_t P##strlen(const char *s) { return strlen(s); } \
int P##strcmp(const char *a, const char *b) { return strcmp(a, b); } \
int P##strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); } \
char *P##strstr(const char *a, const char *b) { return strstr(a, b); } \
char *P##strchr(const char *s, int c) { return strchr(s, c); } \
void *P##memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); } \
void *P##memset(void *a, int c, size_t n) { return memset(a, c, n); } \
int P##memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); } \
unsigned long long P##simple_strtoull(const char *s, char **e, unsigned base) { return strtoull(s, e, base); } \
long P##simple_strtol(const char *s, char **e, unsigned base) { return strtol(s, e, base); }
FAKES(c_) FAKES(rs_)
/* MAXMEM in the C is (1UL << MAX_PHYSMEM_BITS) with pgtable_l5_enabled(): the C reads __pgtable_l5_enabled. */

void c_choose_random_location(ul, ul, ul *, ul, ul *); void rs_choose_random_location(ul, ul, ul *, ul, ul *);
ul c_kaslr_get_random_long(const char *); ul rs_kaslr_get_random_long(const char *);
char *c_skip_spaces(const char *); char *rs_skip_spaces(const char *);
unsigned long long c_memparse(const char *, char **); unsigned long long rs_memparse(const char *, char **);
char *c_next_arg(char *, char **, char **); char *rs_next_arg(char *, char **, char **);
int c_get_option(char **, int *); int rs_get_option(char **, int *);
char *c_get_options(const char *, int, int *); char *rs_get_options(const char *, int, int *);
bool c_parse_option_str(const char *, const char *); bool rs_parse_option_str(const char *, const char *);
extern const unsigned char c__ctype[256], rs__ctype[256];

static uint64_t s = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static uint64_t rr(uint64_t n) { return rnd() % n; }
static unsigned long checks, fails;
#define W32(p, o, v) (*(uint32_t *)((char *)(p) + (o)) = (v))
#define W64(p, o, v) (*(uint64_t *)((char *)(p) + (o)) = (v))


static void run_case(int which, ul bpaddr, ul in, ul insz, ul out, ul outsz)
{
	pid_t p = fork();
	if (p == 0) {
		struct res *r = &shm[which]; cur_which = which; inb_k = 0;
		ev[0] = 0; ul o = out, v = 0xdeadbeef;
		void *bp = (void *)bpaddr;
		if (which == 0) { c_boot_params_ptr = bp; c_choose_random_location(in, insz, &o, outsz, &v); }
		else { rs_boot_params_ptr = bp; rs_choose_random_location(in, insz, &o, outsz, &v); }
		r->status = 0; r->output = o; r->virt = v; r->lf = *((unsigned char *)bp + 529); strcpy(r->ev, ev);
		_exit(0);
	}
	int st; waitpid(p, &st, 0);
	if (!WIFEXITED(st)) { shm[which].status = 1000 + WTERMSIG(st); strcpy(shm[which].ev, "(killed by a signal)"); }
}
/* the child's ev is its own copy: error() exits with 42 BEFORE the result is stored, so it writes shm itself: do it in error() */

static const char *tokens[] = {
	"nokaslr", "mem=512M", "mem=4G", "mem=16G", "mem=nopentium", "mem=0", "mem=1", "mem=3G", "memmap=exactmap", "memmap=64M$4G",
	"memmap=1G#0x40000000", "memmap=100M@2G", "memmap=2G", "memmap=1G!0x100000000", "memmap=512M$0x30000000,128M$1G", "memmap=zz", "memmap=",
	"memmap", "hugepagesz=1G", "hugepages=2", "hugepagesz=2M", "hugepages=100", "hugepagesz=1G", "hugepagesz=1g", "hugepages=0x3", "foo=bar", "quiet", "root=/dev/x",
	"--", "console=ttyS0", "\"mem=256M\"", "\"a b\"=c", "x=\"y z\"", "memmap=16M$0x200000", "memmap=32M$0x4000000", "memmap=8M#64M", "mem=2T",
	"memmap=1K$8M", "memmap=1P", "memmap=1G@4G,64M$8G", "mem_x=1", "xhugepagesy=1", "mem= 1G" };

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 20000;
	shm = mmap(NULL, sizeof(struct res) * 2, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	char *arena = mmap((void *)0x300000000UL, 1 << 26, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (arena == MAP_FAILED) { puts("mmap failed"); return 2; }
	/* direct checks first: the lib/ctype and lib/cmdline exports */
	for (int i = 0; i < 256; i++) { checks++; if (c__ctype[i] != rs__ctype[i]) { fails++; printf("DIFF _ctype[%d]\n", i); } }
	static const char alpha[] = "0123456789abcdefxXkKmMgGtTpPeE ,-=\"'\t_@#$!zQ";
	for (long i = 0; i < n * 20; i++) {
		char a[64], b[64], cp[64]; int len = rr(30); for (int k = 0; k < len; k++) a[k] = alpha[rr(sizeof alpha - 1)]; a[len] = 0;
		memset(b, 0, 64); memset(cp, 0, 64); strcpy(b, a); strcpy(cp, a);
		checks++; if (c_skip_spaces(a) - a != rs_skip_spaces(a) - a) { fails++; printf("DIFF skip_spaces '%s'\n", a); }
		char *e1, *e2; unsigned long long m1 = c_memparse(a, &e1), m2 = rs_memparse(a, &e2);
		checks++; if (m1 != m2 || e1 - a != e2 - a) { fails++; printf("DIFF memparse '%s' %llx/%llx\n", a, m1, m2); }
		char *p1, *v1, *p2, *v2; char *n1 = c_next_arg(b, &p1, &v1), *n2 = rs_next_arg(cp, &p2, &v2);
		checks++; if (n1 - b != n2 - cp || p1 - b != p2 - cp || (v1 ? v1 - b : -1) != (v2 ? v2 - cp : -1) || memcmp(b, cp, 64)) { fails++; printf("DIFF next_arg '%s'\n", a); }
		int i1[8] = { 9, 9, 9, 9, 9, 9, 9, 9 }, i2[8] = { 9, 9, 9, 9, 9, 9, 9, 9 }; char *o1 = a, *o2 = a;
		int g1 = c_get_option(&o1, i1), g2 = rs_get_option(&o2, i2);
		checks++; if (g1 != g2 || o1 != o2 || memcmp(i1, i2, sizeof i1)) { fails++; printf("DIFF get_option '%s'\n", a); }
		int j1[8] = { 9, 9, 9, 9, 9, 9, 9, 9 }, j2[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
		char *q1 = c_get_options(a, 5, j1), *q2 = rs_get_options(a, 5, j2);
		checks++; if (q1 != q2 || memcmp(j1, j2, sizeof j1)) { fails++; printf("DIFF get_options '%s'\n", a); }
		char opt[8]; int ol = 1 + rr(3); for (int k = 0; k < ol; k++) opt[k] = alpha[rr(sizeof alpha - 1)]; opt[ol] = 0;
		checks++; if (c_parse_option_str(a, opt) != rs_parse_option_str(a, opt)) { fails++; printf("DIFF parse_option_str '%s' '%s'\n", a, opt); }
	}
	/* kaslr_get_random_long directly, all hardware combinations */
	for (long i = 0; i < n; i++) {
		memset(arena, 0, 4096); for (int k = 0; k < 4096; k += 8) W64(arena, k, rnd());
		f_rdrand_cpu = rr(2); f_tsc_cpu = rr(2); f_rdrand_ok = rr(2); f_rdrand_val = rnd(); f_tsc_val = rnd();
		f_inb_n = rr(4); /* number of polls that report 'not ready' */ for (int k = 0; k < 32; k++) f_inb[k] = rr(256);
		const char *purpose = rr(4) ? (rr(2) ? "Physical" : "Virtual") : NULL;
		c_boot_params_ptr = rs_boot_params_ptr = arena;
		inb_k = 0; ev[0] = 0; ul r1 = c_kaslr_get_random_long(purpose); static char e1[16384]; strcpy(e1, ev);
		inb_k = 0; ev[0] = 0; ul r2 = rs_kaslr_get_random_long(purpose);
		checks++; if (r1 != r2 || strcmp(e1, ev)) { fails++; if (fails < 8) printf("DIFF kaslr_get_random_long case %ld: %lx vs %lx\n C: %s\n RS: %s\n", i, r1, r2, e1, ev); }
	}
	/* choose_random_location */
	unsigned long nerr = 0, nwarn_nokaslr = 0, nmoved = 0, nsuitable = 0;
	for (long i = 0; i < n; i++) {
		memset(arena, 0, 1 << 25);
		char *bp = arena + 0x100000; char *cmd = arena + 0x200000; char *sd1 = arena + 0x300000, *sd2 = arena + 0x340000, *kho = arena + 0x380000;
		char *efimap = arena + 0x400000; char *scratch = arena + 0x500000;
		/* kernel placement */
		ul out = (16UL << 20) + (rr(2048) << 21);                    /* 16 MiB .. 4 GiB, 2 MiB aligned */
		if (rr(8) == 0) out = (rr(64) + 1) << 21;
		ul outsz = (24UL << 20) + rr(4096) * 4096 * 4; if (rr(10) == 0) outsz = (1UL << 20) + rr(64) * 4096;
		ul in = out + (rr(40) << 20), insz = (4UL << 20) + rr(64) * 65536;
		W32(bp, 608, (uint32_t)(outsz + rr(8) * 4096));                    /* hdr.init_size */
		W32(bp, 536, rr(3) ? 0 : (uint32_t)(rr(1 << 20) << 12)); W32(bp, 540, rr(3) ? 0 : (uint32_t)(rr(1 << 14) << 12)); /* ramdisk */
		W32(bp, 192, rr(5) ? 0 : (uint32_t)rr(4)); W32(bp, 196, rr(5) ? 0 : (uint32_t)rr(2));
		/* e820 */
		int ne = rr(14); *(unsigned char *)(bp + 488) = ne;
		for (int k = 0; k < ne; k++) {
			char *e = bp + 720 + 20 * k; uint64_t a = rr(40) << 28, z = (rr(60) + 1) << 24;
			if (rr(3) == 0) a = (rr(2000) << 20); if (rr(4) == 0) { a = 0; z = 0x9f000; }
			W64(e, 0, a); W64(e, 8, z); W32(e, 16, rr(6) ? 1 : 1 + rr(7));
		}
		/* command line */
		int usecmd = rr(6) != 0; f_cmdline = usecmd ? (ul)cmd : 0; f_nokaslr = 0;
		if (usecmd) {
			cmd[0] = 0; int nt = rr(7); size_t l = 0;
			if (rr(8) == 0) { strcpy(cmd, "   "); l = 3; }
			for (int k = 0; k < nt; k++) { const char *t = tokens[rr(sizeof tokens / sizeof *tokens)]; if (!strcmp(t, "nokaslr") && rr(6)) continue; if (!strcmp(t, "nokaslr")) f_nokaslr = 1; l += sprintf(cmd + l, "%s%s", rr(5) ? " " : "  ", t); }
		}
		/* setup_data list: indirect + KHO + junk */
		uint64_t head = 0; int nsd = rr(4);
		if (nsd >= 1) { W64(sd1, 0, 0); W32(sd1, 8, rr(3) ? 1 : (1u << 31)); W32(sd1, 12, 16 + rr(4096)); if (*(uint32_t *)(sd1 + 8) == (1u << 31)) { W32(sd1, 16, rr(4) ? 1 : (1u << 31)); W64(sd1, 24, rr(1 << 16) << 12); W64(sd1, 32, (rr(40) << 24) + (rr(8) << 12)); } head = (uint64_t)sd1; }
		if (nsd >= 2) { W64(sd2, 0, head); W32(sd2, 8, rr(3) == 0 ? 10 : 2); W32(sd2, 12, 0x40); head = (uint64_t)sd2;
			if (*(uint32_t *)(sd2 + 8) == 10) { W64(sd2, 16 + 16, (uint64_t)scratch); W64(sd2, 16 + 24, 16 * (rr(5))); for (int k = 0; k < 4; k++) { W64(scratch, 16 * k, (rr(30) + 1) << 27); W64(scratch, 16 * k + 8, (rr(8) + 1) << 25); } } }
		W64(bp, 592, rr(5) ? head : 0);
		/* EFI memory map */
		int es = rr(4); const char *sig = es == 0 ? "EL64" : es == 1 ? "EL32" : es == 2 ? "EL6\0" : "\0\0\0\0";
		memcpy(bp + 448, sig, 4);
		uint32_t dsz = rr(2) ? 48 : 40 + 8 * rr(3); uint32_t nd = rr(10);
		W32(bp, 456, dsz); W32(bp, 464, (uint32_t)(uintptr_t)efimap); W32(bp, 476, (uint32_t)((uintptr_t)efimap >> 32)); W32(bp, 468, nd * dsz + (rr(4) == 0 ? rr(dsz) : 0));
		for (uint32_t k = 0; k < nd; k++) {
			char *d = efimap + (size_t)k * dsz; W32(d, 0, rr(3) ? 7 : (rr(3) ? 15 : rr(16))); W64(d, 8, (rr(70) << 27)); W64(d, 24, (rr(40) + 1) << 14);
			uint64_t at = 0; if (rr(6) == 0) at |= 0x10000; if (rr(6) == 0) at |= 0x40000; if (rr(3) == 0) at |= 0x8000000000000000ULL; W64(d, 32, at);
		}
		f_soft_reserve = rr(2);
		/* two extra generators so that EXACT adjacency / equality cases happen (random 64-bit numbers never touch):
		 * mode 2 = everything on a 2 MiB grid in the first 400 MB; mode 3 = 1 GiB-aligned RAM and hugepagesz=1G hugepages=N */
		int mode = rr(5);
		if (mode == 2 || mode == 3) {
			memset(bp + 720, 0, 20 * 32); f_nokaslr = 0;
			if (mode == 2) {
				out = (8 + rr(60)) << 21; outsz = (1 + rr(20)) << 21; in = out + (rr(8) << 21); insz = (1 + rr(8)) << 21;
				W32(bp, 608, (uint32_t)outsz); W32(bp, 536, (uint32_t)(rr(100) << 21)); W32(bp, 540, (uint32_t)(rr(6) << 21));
				ne = 1 + rr(8); *(unsigned char *)(bp + 488) = ne;
				for (int k = 0; k < ne; k++) { char *e = bp + 720 + 20 * k; W64(e, 0, (uint64_t)rr(100) << 21); W64(e, 8, (uint64_t)(1 + rr(40)) << 21); W32(e, 16, rr(8) ? 1 : 2); }
				if (usecmd) { cmd[0] = 0; size_t l = 0; int nt = rr(4);
					for (int k = 0; k < nt; k++) { if (rr(2)) l += sprintf(cmd + l, " memmap=%luM$%luM", (unsigned long)(1 + rr(12)) * 2, (unsigned long)rr(100) * 2);
						else l += sprintf(cmd + l, " mem=%luM", (unsigned long)(2 + rr(200)) * 2); } }
				memset(sd1, 0, 64); head = 0;
				if (rr(2)) { W64(sd1, 0, 0); W32(sd1, 8, 1u << 31); W32(sd1, 12, 0); W32(sd1, 16, 1); W64(sd1, 24, (uint64_t)(rr(6) << 21)); W64(sd1, 32, (uint64_t)rr(100) << 21); head = (uint64_t)sd1; }
				W64(bp, 592, head);
				nd = rr(6); W32(bp, 456, 48); W32(bp, 468, nd * 48);
				for (uint32_t k = 0; k < nd; k++) { char *d = efimap + (size_t)k * 48; memset(d, 0, 48); W32(d, 0, rr(4) ? 7 : 15); W64(d, 8, (uint64_t)rr(100) << 21); W64(d, 24, (uint64_t)(1 + rr(40)) << 9); }
				for (int k = 0; k < 8; k++) { f_imm[k].start = (uint64_t)rr(100) << 21; f_imm[k].size = (uint64_t)(1 + rr(30)) << 21; }
			} else {
				out = (8 + rr(8)) << 21; outsz = (12UL + rr(20)) << 21; in = out + (rr(8) << 21); insz = (1 + rr(8)) << 21; W32(bp, 608, (uint32_t)outsz);
				W32(bp, 536, 0); W32(bp, 540, 0); W64(bp, 592, 0);
				ne = 1 + rr(3); *(unsigned char *)(bp + 488) = ne;
				for (int k = 0; k < ne; k++) { char *e = bp + 720 + 20 * k; W64(e, 0, rr(2) ? ((uint64_t)(1 + rr(5)) << 30) - outsz : ((uint64_t)rr(6) << 30) + (rr(3) ? 0 : (uint64_t)rr(3) << 21)); /* start = 1 GiB boundary - image: pud_start == start + image_size */ W64(e, 8, ((uint64_t)(1 + rr(4)) << 30) + (rr(3) == 0 ? outsz : rr(3) ? 0 : (uint64_t)rr(3) << 21)); /* size = n GiB + image: region end == pud_end + image_size */ W32(e, 16, 1); }
				usecmd = 1; f_cmdline = (ul)cmd; cmd[0] = 0; size_t l = 0;
				l += sprintf(cmd + l, " hugepagesz=%s", rr(6) ? "1G" : "2M"); if (rr(5) == 0) l += sprintf(cmd + l, " hugepagesz=1G");
				l += sprintf(cmd + l, " hugepages=%d", (int)(1 + rr(5)));
				if (rr(3) == 0) l += sprintf(cmd + l, " hugepagesz=1G hugepages=%d", (int)(1 + rr(4)));
				memcpy(bp + 448, "\0\0\0\0", 4);
			}
		}
		/* hardware */
		f_rdrand_cpu = rr(2); f_tsc_cpu = rr(2); f_rdrand_ok = rr(3) != 0; f_rdrand_val = rnd(); f_tsc_val = rnd();
		f_inb_n = rr(4); /* number of polls that report 'not ready' */ for (int k = 0; k < 32; k++) f_inb[k] = rr(256);
		f_malloc_null = rr(200) == 0; f_l5 = rr(2); c___pgtable_l5_enabled = rs___pgtable_l5_enabled = f_l5;
		f_imm_n = rr(3) == 0 ? rr(5) : 0; for (int k = 0; k < 8; k++) { f_imm[k].start = (rr(60) << 26); f_imm[k].size = (rr(30) + 1) << 24; }
		/* run both */
		run_case(0, (ul)bp, in, insz, out, outsz); run_case(1, (ul)bp, in, insz, out, outsz);
		checks++;
		if (shm[0].status != shm[1].status || shm[0].output != shm[1].output || shm[0].virt != shm[1].virt || shm[0].lf != shm[1].lf || strcmp(shm[0].ev, shm[1].ev)) {
			fails++; if (fails < 8) printf("DIFF choose_random_location case %ld in=%lx out=%lx outsz=%lx\n C : st=%d out=%lx virt=%lx lf=%x %s\n RS: st=%d out=%lx virt=%lx lf=%x %s\n", i, in, out, outsz,
				shm[0].status, shm[0].output, shm[0].virt, shm[0].lf, shm[0].ev, shm[1].status, shm[1].output, shm[1].virt, shm[1].lf, shm[1].ev);
		}
		if (shm[0].status == 42) nerr++; else if (strstr(shm[0].ev, "nokaslr);") && strstr(shm[0].ev, "warn(KASLR disabled")) nwarn_nokaslr++;
		else if (shm[0].output != out) nmoved++; else if (strstr(shm[0].ev, "warn(Physical KASLR disabled")) nsuitable++;
	}
	printf("choose_random_location outcomes (C side): moved=%lu no-suitable-region=%lu nokaslr=%lu error=%lu of %ld\n", nmoved, nsuitable, nwarn_nokaslr, nerr, n);
	printf("kaslrtest: checks=%lu failures=%lu\n", checks, fails);
	return fails != 0;
}
