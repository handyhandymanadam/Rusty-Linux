// Differential test for efi.c: ORIGINAL C efi.o (prefix c_) vs Rust efi_rs.o (prefix rs_). Random boot_params with
// EFI info, system tables (32/64-bit), config tables, kexec setup_data lists; compares return values, out
// parameters and every __putstr() call. Built/run by rig/stubf/run-efi.sh. Memory is real userspace memory; the
// "physical addresses" are pointers split into lo/hi 32 bits.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>

typedef struct { uint8_t b[16]; } __attribute__((aligned(4))) guid;
static char ev[8192];
#define EV(...) do { size_t l = strlen(ev); snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)
#define FAKES(P) \
void P##__putstr(const char *s) { EV("[%s]", s); } \
int P##strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); } \
int P##memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); } \
void *P##memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); }
FAKES(c_) FAKES(rs_)

int c_efi_get_type(void *); int rs_efi_get_type(void *);
unsigned long c_efi_get_system_table(void *); unsigned long rs_efi_get_system_table(void *);
int c_efi_get_conf_table(void *, unsigned long *, unsigned *); int rs_efi_get_conf_table(void *, unsigned long *, unsigned *);
unsigned long c_efi_find_vendor_table(void *, unsigned long, unsigned, guid); unsigned long rs_efi_find_vendor_table(void *, unsigned long, unsigned, guid);

static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static unsigned long checks, fails;

#define W32(p, o, v) (*(uint32_t *)((char *)(p) + (o)) = (v))
#define W64(p, o, v) (*(uint64_t *)((char *)(p) + (o)) = (v))
static const char *sigs[] = { "EL64", "EL32", "EL6\0", "EL63", "el64", "EL3", "\0L64", "EL64" };

static void report(const char *what, int i, const char *ec, const char *er) { fails++; printf("DIFF %s case %d\n C : %s\n RS: %s\n", what, i, ec, er); }

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 200000;
	/* one arena ABOVE 4 GiB so that the *_hi halves of every address are non-zero */
	char *arena = mmap((void *)0x123400000000UL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (arena == MAP_FAILED || (uintptr_t)arena >> 32 == 0) { puts("mmap high failed"); return 2; }
	char *bp = arena, *st = arena + 4096, *ct = arena + 8192, *sd = arena + 12288, *sd2 = arena + 16384;
	guid g[3]; for (int k = 0; k < 3; k++) for (int j = 0; j < 16; j++) g[k].b[j] = rnd();
	for (long i = 0; i < n; i++) {
		memset(bp, 0, 4096); memset(st, 0, 256); memset(ct, 0, 24 * 8); memset(sd, 0, 4096); memset(sd2, 0, 4096);
		/* efi_info at 0x1c0 */
		const char *sg = sigs[rnd() % 8]; memcpy(bp + 0x1c0, sg, 4);
		int tables_in_st = rnd() % 5 != 0;
		uint64_t sa = (uint64_t)(uintptr_t)st;
		if (rnd() % 8 == 0) sa = 0;
		W32(bp, 0x1c4, (uint32_t)sa); W32(bp, 0x1d8, (uint32_t)(sa >> 32));
		/* config tables: 64-bit layout 24 bytes/entry, 32-bit 20 bytes/entry */
		int is32 = !memcmp(sg, "EL32", 4); int nent = rnd() % 6;
		for (int e = 0; e < nent; e++) {
			char *p = ct + e * (is32 ? 20 : 24);
			guid *gg = &g[rnd() % 3];
			if (rnd() % 3 == 0) { guid t = g[0]; t.b[rnd() % 16] ^= 1u << (rnd() % 8); *gg = t; } /* differs from g[0] in ONE bit */
			memcpy(p, gg, 16);
			if (is32) W32(p, 16, (uint32_t)rnd()); else W64(p, 16, rnd());
		}
		uint64_t cta = (uint64_t)(uintptr_t)ct;
		if (is32) { W32(st, 64, nent); W32(st, 68, (uint32_t)cta); }
		else { W32(st, 104, nent); W64(st, 112, tables_in_st ? cta : 0); }
		/* kexec setup_data: list of 0..3 nodes, maybe one SETUP_EFI(4) */
		int nn = rnd() % 4; uint64_t head = 0; char *nodes[2] = { sd, sd2 };
		if (nn > 2) nn = 2;
		for (int k = nn - 1; k >= 0; k--) {
			char *p = nodes[k];
			W64(p, 0, head); W32(p, 8, (rnd() % 2) ? 4 : (uint32_t)(rnd() % 5)); W32(p, 12, 0x100);
			W64(p + 16, 16, rnd() % 3 ? (uint64_t)(uintptr_t)ct : 0); /* esd->tables */
			head = (uint64_t)(uintptr_t)p;
		}
		W64(bp, 0x250, head);
		if (rnd() % 20 == 0) W32(bp, 0x1c4, 0); /* systab lo 0 but hi maybe not */

		int w;
		for (w = 0; w < 1; w++) {
			char ec[8192], er[8192]; long rc, rr;
			/* efi_get_type */
			ev[0] = 0; rc = c_efi_get_type(bp); strcpy(ec, ev); ev[0] = 0; rr = rs_efi_get_type(bp);
			checks++; if (rc != rr || strcmp(ec, ev)) report("get_type", i, ec, ev);
			ev[0] = 0; rc = c_efi_get_system_table(bp); strcpy(ec, ev); ev[0] = 0; rr = rs_efi_get_system_table(bp);
			checks++; if (rc != rr || strcmp(ec, ev)) report("get_system_table", i, ec, ev);
			/* conf table: also NULL out-pointer cases */
			unsigned long pa_c = 0x1111, pa_r = 0x1111; unsigned ln_c = 0x2222, ln_r = 0x2222;
			int mode = rnd() % 10; /* 0: NULL pa, 1: NULL len, else normal */
			ev[0] = 0; rc = c_efi_get_conf_table(bp, mode == 0 ? NULL : &pa_c, mode == 1 ? NULL : &ln_c); strcpy(ec, ev);
			ev[0] = 0; rr = rs_efi_get_conf_table(bp, mode == 0 ? NULL : &pa_r, mode == 1 ? NULL : &ln_r);
			checks++; if (rc != rr || pa_c != pa_r || ln_c != ln_r || strcmp(ec, ev)) report("get_conf_table", i, ec, ev);
			/* find vendor table over the real table, and over a random length (may run past: keep within 8) */
			unsigned len = rnd() % 8; if (len > (unsigned)nent) len = nent;
			guid want = g[rnd() % 3]; if (rnd() % 3 == 0) want = g[0], want.b[rnd() % 16] ^= 1u << (rnd() % 8);
			unsigned long cpa = (unsigned long)(uintptr_t)ct;
			ev[0] = 0; rc = c_efi_find_vendor_table(bp, cpa, len, want); strcpy(ec, ev);
			ev[0] = 0; rr = rs_efi_find_vendor_table(bp, cpa, len, want);
			checks++; if (rc != rr || strcmp(ec, ev)) report("find_vendor", i, ec, ev);
		}
	}
	printf("efitest: checks=%lu failures=%lu\n", checks, fails);
	return fails != 0;
}
