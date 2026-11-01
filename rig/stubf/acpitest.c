// Differential test for acpi.c: ORIGINAL C acpi.o (prefix c_) vs Rust acpi_rs.o (prefix rs_). Built/run by run-acpi.sh.
// get_rsdp_addr(): boot_params->acpi_rsdp_addr, the EFI branch (recording fakes of efi_*), the BIOS scan of the EBDA window and of
// the E0000h-FFFFFh window (a test-only 1 MiB arena at 0x10000; both objects were built with the EBDA pointer at 0x1040E instead
// of the real 0x40E, which a userspace process cannot map). count_immovable_mem_regions(): random RSDP/RSDT/XSDT/SRAT trees in
// real memory (arenas below and above 4 GiB), "acpi=" / "acpi_rsdp=" command-line fakes. Compared: return value, immovable_mem[],
// every __putstr/warn/error/efi_* event. error() longjmps out of the call (the real one halts).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>
#include <sys/mman.h>

typedef struct { uint8_t b[16]; } __attribute__((aligned(4))) guid;
struct mv { uint64_t start, size; };
static char ev[16384];
static jmp_buf jb;
#define EV(...) do { size_t l = strlen(ev); snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)
/* fake answers */
static int f_type, f_conf, f_sys_zero; static unsigned long f_cpa; static unsigned f_clen;
static unsigned long f_v20, f_v10;               /* what the vendor-table search returns for the 2.0 / 1.0 GUID */
static const char *f_acpi, *f_acpi_rsdp;        /* NULL = option absent */

#define FAKES(P) \
void *P##boot_params_ptr; \
void P##__putstr(const char *s) { EV("[%s]", s); } \
int P##efi_get_type(void *bp) { EV("type;"); return f_type; } \
unsigned long P##efi_get_system_table(void *bp) { EV("systab;"); return f_sys_zero ? 0 : 0x1000; } \
int P##efi_get_conf_table(void *bp, unsigned long *pa, unsigned *len) { EV("conf;"); if (f_conf) return f_conf; *pa = f_cpa; *len = f_clen; return 0; } \
unsigned long P##efi_find_vendor_table(void *bp, unsigned long pa, unsigned len, guid g) { \
	EV("find(%lx,%u,", pa, len); for (int i = 0; i < 16; i++) EV("%02x", g.b[i]); EV(");"); return g.b[0] == 0x71 ? f_v20 : f_v10; } \
void P##error(char *m) { EV("error(%s);", m); longjmp(jb, 1); } \
void P##warn(const char *m) { EV("warn(%s);", m); } \
int P##cmdline_find_option(const char *opt, char *buf, int sz) { \
	const char *v = !strcmp(opt, "acpi") ? f_acpi : !strcmp(opt, "acpi_rsdp") ? f_acpi_rsdp : NULL; \
	EV("opt(%s,%d);", opt, sz); if (!v) return -1; int n = strlen(v); int c = n < sz - 1 ? n : sz - 1; memcpy(buf, v, c); buf[c] = 0; return n; } \
int P##boot_kstrtoul(const char *s, unsigned base, unsigned long *res) { \
	char *e; EV("kstrtoul(%s,%u);", s, base); if (!*s) return -22; unsigned long v = strtoul(s, &e, base); if (*e) return -22; *res = v; return 0; } \
int P##strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); } \
int P##memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
FAKES(c_) FAKES(rs_)

uint64_t c_get_rsdp_addr(void), rs_get_rsdp_addr(void);
int c_count_immovable_mem_regions(void), rs_count_immovable_mem_regions(void);
extern struct mv c_immovable_mem[], rs_immovable_mem[];

static uint64_t s = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static unsigned long checks, fails;
static char *lo, *hi, *low1m;
#define IMM_N (IMM_ENTRIES)

static void put_rsdp(char *p, int good, int rev, uint64_t xsdt, uint32_t rsdt)
{
	memset(p, 0, 36);
	memcpy(p, rnd() % 16 ? "RSD PTR " : "RSD PTX ", 8);
	p[15] = rev; *(uint32_t *)(p + 16) = rsdt; *(uint32_t *)(p + 20) = 36; *(uint64_t *)(p + 24) = xsdt;
	uint8_t sum = 0; for (int i = 0; i < 20; i++) sum += p[i]; p[8] = -sum;
	if (rev >= 2) { sum = 0; for (int i = 0; i < 36; i++) sum += p[i]; p[32] = -sum; }
	if (!good) { if (rnd() & 1) p[8] ^= 1 << (rnd() % 8); else if (rev >= 2) p[32] ^= 1 << (rnd() % 8); else p[9] ^= 4; }
}

static void check(const char *what, long i, const char *ec, long rc, const char *er, long rr)
{
	checks++;
	if (rc != rr || strcmp(ec, er)) { fails++; if (fails < 8) printf("DIFF %s case %ld\n C : %s r=%lx\n RS: %s r=%lx\n", what, i, ec, rc, er, rr); }
}

#define NSUB 150
int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 100000;
	low1m = mmap((void *)0x10000, 0x100000 + 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	lo = mmap((void *)0x20000000, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	hi = mmap((void *)0x123400000000UL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (low1m == MAP_FAILED || lo == MAP_FAILED || hi == MAP_FAILED) { puts("mmap failed"); return 2; }
	char *bp = lo + 0xf0000; c_boot_params_ptr = rs_boot_params_ptr = bp;
	char ec[16384]; long rc, rr;

	/* ---- get_rsdp_addr ---- */
	for (long i = 0; i < n; i++) {
		memset(low1m, 0, 0x100000); memset(bp, 0, 4096);
		/* EBDA pointer word (test address 0x1040E) and windows */
		uint16_t ebda = rnd() % 4 ? (0x9000 + rnd() % 0x6000) : (rnd() % 0x41); /* 0x9xxx*16.. or tiny (eaddr <= 0x400 -> window skipped) */
		*(uint16_t *)(low1m + (0x1040E - 0x10000)) = ebda;
		uint32_t eaddr = (uint32_t)ebda << 4;
		int nr = rnd() % 4;
		for (int k = 0; k < nr; k++) {
			uint32_t a;
			if (rnd() % 2 && eaddr > 0x400 && eaddr + 1024 <= 0xFFFF0) a = eaddr + 16 * (rnd() % 66); /* inside / just past the 1 KiB window */
			else a = 0xE0000 + 16 * (rnd() % 0x2010);                                                  /* hi window, possibly past its end */
			if (a + 64 > 0x111000) continue;
			if (a < 0x10000) continue;
			put_rsdp((char *)(uintptr_t)a, rnd() % 3, 1 + rnd() % 3, rnd(), rnd());
		}
		if (rnd() % 3 == 0) *(uint64_t *)(bp + 112) = 0x1234 + rnd() % 4096;
		f_type = rnd() % 3; f_conf = (rnd() % 4 == 0) ? -22 : 0; f_sys_zero = rnd() % 5 == 0;
		f_cpa = rnd() % 5 ? 0x2000 : 0; f_clen = rnd() % 8;
		f_v20 = rnd() % 3 ? 0x5000 + rnd() % 100 : 0; f_v10 = rnd() % 3 ? 0x6000 + rnd() % 100 : 0;
		/* NB: with real addresses the BIOS windows are scanned in the arena */
		ev[0] = 0; rc = -1; if (!setjmp(jb)) rc = c_get_rsdp_addr(); strcpy(ec, ev);
		ev[0] = 0; rr = -1; if (!setjmp(jb)) rr = rs_get_rsdp_addr();
		check("get_rsdp_addr", i, ec, rc, ev, rr);
	}

#ifdef HOTREMOVE
	/* ---- count_immovable_mem_regions ---- */
	static const char *acpis[] = { NULL, "off", "rsdt", "of", "offx", "rsd", "rsdtt", "copy_dsdt", "force", "strict" };
	static const char *rsdps[] = { NULL, "0", "zz", "12345678901234567890", "", "0x", "-1x", "00000", "1234567890123456789" /* 19 chars: too long */ };
	for (long i = 0; i < n; i++) {
		memset(lo, 0, 1 << 20); memset(hi, 0, 1 << 20); memset(bp, 0, 4096);
		memset(c_immovable_mem, 0xAA, sizeof(struct mv) * IMM_ENTRIES); memset(rs_immovable_mem, 0xAA, sizeof(struct mv) * IMM_ENTRIES);
		/* SRAT at lo+0x1000 (or hi) */
		char *srat = (rnd() % 4 == 0) ? hi + 0x1000 : lo + 0x1000;
		int fill = rnd() % 6 == 0;   /* 'fill' mode: only usable memory-affinity entries, around the MAX_NUMNODES*2 limit */
		int nsub = fill ? IMM_ENTRIES - 2 + rnd() % 5 : rnd() % 8 == 0 ? IMM_ENTRIES + rnd() % 6 : rnd() % 20;
		char *w = srat + 48; int cnt_good = 0;
		for (int k = 0; k < nsub; k++) {
			int ty = rnd() % 3 ? 1 : rnd() % 4, len = ty == 1 ? 40 : 2 + rnd() % 30;
			if (rnd() % 40 == 0) len = 0;
			if (rnd() % 30 == 0 && ty == 1) len = 40 + rnd() % 10;
			if (fill) { ty = 1; len = 40; }
			if (w + 64 > srat + 0x10000 - 64) break;
			w[0] = ty; w[1] = len;
			*(uint64_t *)(w + 8) = rnd(); *(uint64_t *)(w + 16) = rnd() % 5 ? rnd() : 0; *(uint32_t *)(w + 28) = rnd() % 3 ? 1 : (rnd() % 2 ? 3 : 0);
			if (fill) { *(uint64_t *)(w + 16) = 1 + rnd() % 100; *(uint32_t *)(w + 28) = 1; }
			if (len == 0) { w += 2; } else w += len;
			(void)cnt_good;
		}
		uint32_t slen = (uint32_t)(w - srat); if (rnd() % 20 == 0) slen = rnd() % 60;
		memcpy(srat, "SRAT", 4); *(uint32_t *)(srat + 4) = slen;
		/* root table */
		int use_x = rnd() % 2; char *root = use_x ? (rnd() % 2 ? hi + 0x40000 : lo + 0x40000) : lo + 0x40000;
		memcpy(root, use_x ? "XSDT" : "RSDT", 4);
		int nent = 1 + rnd() % 5, sidx = rnd() % nent;
		int esz = use_x ? 8 : 4;
		*(uint32_t *)(root + 4) = 36 + nent * esz - (rnd() % 20 == 0 ? 3 : 0);
		if (rnd() % 25 == 0) *(uint32_t *)(root + 4) = rnd() % 50;
		for (int k = 0; k < nent; k++) {
			uint64_t t = (k == sidx && rnd() % 16) ? (uint64_t)(uintptr_t)srat : (uint64_t)(uintptr_t)(lo + 0x80000 + 64 * k);
			if (k != sidx || (rnd() % 8 == 0)) { memcpy(lo + 0x80000 + 64 * k, "FACP", 4); if (rnd() % 6 == 0) t = 0; }
			if (!use_x && (t >> 32)) t = (uint64_t)(uintptr_t)(lo + 0x80000);
			if (use_x) *(uint64_t *)(root + 36 + 8 * k) = t; else *(uint32_t *)(root + 36 + 4 * k) = (uint32_t)t;
		}
		/* RSDP */
		char *rsdp = lo + 0x100;
		int rev = 1 + rnd() % 3;
		memcpy(lo + 0x60000, "XSDT", 4); *(uint32_t *)(lo + 0x60004) = 36; /* a valid, empty XSDT for the RSDT-only case */
		uint64_t xs = use_x ? (uint64_t)(uintptr_t)root : (rnd() % 2 ? (uint64_t)(uintptr_t)(lo + 0x60000) : 0);
		memcpy(lo + 0x70000, "RSDT", 4); *(uint32_t *)(lo + 0x70004) = 36; /* valid, empty RSDT for the XSDT case */
		uint32_t rs = use_x ? (rnd() % 2 ? (uint32_t)(uintptr_t)(lo + 0x70000) : 0) : (uint32_t)(uintptr_t)root;
		put_rsdp(rsdp, 1, rev, xs, rs);
		if (rnd() % 10 == 0) *(uint32_t *)(rsdp + 16) = 0;
		*(uint64_t *)(bp + 112) = rnd() % 12 ? (uint64_t)(uintptr_t)rsdp : 0;
		f_acpi = rnd() % 3 ? NULL : acpis[rnd() % 10];
		f_acpi_rsdp = rnd() % 3 == 0 ? rsdps[rnd() % 9] : NULL;
		static char rb[32];
		if (f_acpi_rsdp && rnd() % 2) { snprintf(rb, sizeof rb, "%lx", (unsigned long)(uintptr_t)rsdp); f_acpi_rsdp = rb; }
		ev[0] = 0; rc = c_count_immovable_mem_regions(); strcpy(ec, ev);
		ev[0] = 0; rr = rs_count_immovable_mem_regions();
		check("count_immovable", i, ec, rc, ev, rr);
		checks++; if (memcmp(c_immovable_mem, rs_immovable_mem, sizeof(struct mv) * IMM_ENTRIES)) { fails++; if (fails < 8) printf("DIFF immovable_mem[] case %ld\n", i); }
		static long hist[8]; hist[rc < 0 ? 0 : rc > 6 ? 7 : rc]++;
		if (i == n - 1) { printf("count_immovable result histogram (0..6, 7=more):"); for (int k = 0; k < 8; k++) printf(" %ld", hist[k]); puts(""); }
	}
#endif
	printf("acpitest: checks=%lu failures=%lu\n", checks, fails);
	return fails != 0;
}
