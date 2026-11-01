// Differential test for mem.c: the ORIGINAL C mem.o (prefix c_) vs the Rust mem_rs.o (prefix rs_), built for a
// config with CONFIG_UNACCEPTED_MEMORY + INTEL_TDX_GUEST + AMD_MEM_ENCRYPT. Every C helper they call is
// replaced by a recording fake; the two event logs, return values and the unaccepted_table global must match for
// every combination of fake answers. Built and run by rig/stubd-string/run-mem.sh.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <cpuid.h>
#include <setjmp.h>

typedef struct { uint8_t b[16]; } __attribute__((aligned(4))) guid;
struct table { uint32_t version, unit_size; uint64_t phys_base, size; };

static int fake_cpuid;
static char ev[2048];
static jmp_buf jb;
/* fake answers */
static int f_type, f_conf; static unsigned long f_pa = 0x1234; static unsigned f_len = 7;
static struct table tbl; static int f_tblmode;           /* 0 NULL, 1 version 1, 2 version 3 */
static uint32_t f_ebx, f_ecx, f_edx, f_eax = 0x77; static int f_tdxok, f_snp;

#define EV(...) do { size_t l = strlen(ev); snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)

#define FAKES(P) \
void *P##boot_params_ptr = (void *)0xb007; \
struct table *P##unaccepted_table; \
int P##efi_get_type(void *bp) { EV("type(%p);", bp); return f_type; } \
int P##efi_get_conf_table(void *bp, unsigned long *pa, unsigned *len) { EV("conf(%p);", bp); if (f_conf) return f_conf; *pa = f_pa; *len = f_len; return 0; } \
unsigned long P##efi_find_vendor_table(void *bp, unsigned long pa, unsigned len, guid g) { \
	EV("find(%p,%lx,%u,", bp, pa, len); for (int i = 0; i < 16; i++) EV("%02x", g.b[i]); EV(");"); \
	return f_tblmode == 0 ? 0 : (unsigned long)&tbl; } \
void P##cpuid_count(uint32_t id, uint32_t cnt, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) { EV("cpuid(%x,%x);", id, cnt); if (fake_cpuid) { *a = f_eax; *b = f_ebx; *c = f_ecx; *d = f_edx; } else __cpuid_count(id, cnt, *a, *b, *c, *d); } \
void P##warn(const char *m) { EV("warn(%s);", m); } \
void P##error(char *m) { EV("error(%s);", m); longjmp(jb, 1); } \
void P##panic(const char *fmt, ...) { EV("panic(%s);", fmt); longjmp(jb, 1); } \
bool P##tdx_accept_memory(uint64_t s, uint64_t e) { EV("tdx_accept(%lx,%lx);", (unsigned long)s, (unsigned long)e); return f_tdxok; } \
void P##snp_accept_memory(uint64_t s, uint64_t e) { EV("snp_accept(%lx,%lx);", (unsigned long)s, (unsigned long)e); } \
bool P##early_is_sevsnp_guest(void) { EV("is_snp;"); return f_snp; }
FAKES(c_) FAKES(rs_)
/* the C compares the TDX signature with memcmp(); libc's is equivalent for equality */
int c_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
/* the C also references these (via inline helpers / headers); harmless if unused */

bool c_init_unaccepted_memory(void); bool rs_init_unaccepted_memory(void);
void c_arch_accept_memory(uint64_t, uint64_t); void rs_arch_accept_memory(uint64_t, uint64_t);

static unsigned long checks, fails;

/* argv[1] = which CPUID signature the fake CPU reports (the C caches the TDX probe in a static, so each
 * signature needs a fresh process; run-mem.sh runs 0..6). */
int main(int argc, char **argv)
{
	int sel = argc > 1 ? atoi(argv[1]) : 0;
	/* ebx, edx, ecx: 0 = exactly "IntelTDX    ", others near misses */
	uint32_t E = 0x65746e49 /* "Inte" */, D = 0x5844546c /* "lTDX" */, C = 0x20202020 /* "    " */;
	uint32_t sigs[][3] = { {E, D, C}, {E, D, C + 1}, {0, 0, 0}, {E, C, D}, {E + 1, D, C}, {E, D + 0x100, C} };
	f_ebx = sigs[sel][0]; f_edx = sigs[sel][1]; f_ecx = sigs[sel][2];
	static char ec[4096]; static bool rc; static void *tc;

	if (sel == 0) {
		/* init_unaccepted_memory: efi type x conf result x table mode (NULL / version 1 / version 3) */
		for (f_type = 0; f_type <= 2; f_type++)
		for (f_conf = 0; f_conf >= -2; f_conf--)
		for (f_tblmode = 0; f_tblmode <= 2; f_tblmode++) {
			tbl.version = f_tblmode == 1 ? 1 : 3;
			for (int w = 0; w < 2; w++) {
				ev[0] = 0; c_unaccepted_table = rs_unaccepted_table = (void *)0x55; bool r = false;
				if (!setjmp(jb)) r = w ? rs_init_unaccepted_memory() : c_init_unaccepted_memory();
				void *t = w ? (void *)rs_unaccepted_table : (void *)c_unaccepted_table;
				if (!w) { strcpy(ec, ev); rc = r; tc = t; }
				else { checks++; if (strcmp(ec, ev) || rc != r || tc != t) { fails++; printf("DIFF init type=%d conf=%d tbl=%d\n C : %s r=%d t=%p\n RS: %s r=%d t=%p\n", f_type, f_conf, f_tblmode, ec, rc, tc, ev, r, t); } }
			}
		}
		/* one visible line so a human can see the GUID the Rust sent */
		f_type = 0; f_conf = 0; f_tblmode = 1; ev[0] = 0; tbl.version = 1; (void)rs_init_unaccepted_memory();
		printf("sample (Rust, version-1 table): %s\n", ev);
	}
	/* arch_accept_memory. The C object executes CPUID inline (asm/cpuid/api.h cpuid_count()), the Rust calls
	 * cpuid_count() (cpuflags_rs.rs), so a fake CPUID can only be given to the Rust. Two parts:
	 * (1) sel == 6, REAL cpuid for both (this host is not a TDX guest): C and Rust must behave identically;
	 * (2) fake cpuid, Rust only, against the behaviour read off mem.c: the exact signature "IntelTDX    "
	 *     (ebx,edx,ecx = "Inte","lTDX","    ") selects TDX; any near miss does not; the probe is cached. */
	if (sel == 6) {
		fake_cpuid = 0;
		for (f_tdxok = 0; f_tdxok < 2; f_tdxok++) for (f_snp = 0; f_snp < 2; f_snp++)
		for (int w = 0; w < 2; w++) {
			char all[4096] = "";
			for (int rep = 0; rep < 2; rep++) {
				ev[0] = 0;
				if (!setjmp(jb)) { if (w) rs_arch_accept_memory(0x1000, 0x2000); else c_arch_accept_memory(0x1000, 0x2000); EV("returned;"); }
				/* the C's inline cpuid logs nothing, the Rust's call logs "cpuid(21,0);" once: drop it for the comparison */
				char *p = strstr(ev, "cpuid(21,0);"); if (p) memmove(p, p + 12, strlen(p + 12) + 1);
				strcat(all, ev); strcat(all, "|");
			}
			if (!w) strcpy(ec, all);
			else { checks++; if (strcmp(ec, all)) { fails++; printf("DIFF accept(real cpuid) tdxok=%d snp=%d\n C : %s\n RS: %s\n", f_tdxok, f_snp, ec, all); } }
		}
	}
	if (sel < 6) {
		fake_cpuid = 1;
		for (f_tdxok = 0; f_tdxok < 2; f_tdxok++) for (f_snp = 0; f_snp < 2; f_snp++) {
			char want[4096] = "", got[4096] = "";
			for (int rep = 0; rep < 2; rep++) {
				ev[0] = 0;
				if (!setjmp(jb)) { rs_arch_accept_memory(0x1000, 0x2000); EV("returned;"); }
				strcat(got, ev); strcat(got, "|");
			}
			/* expected, from mem.c: first call probes (cpuid), later calls use the cached answer */
			for (int rep = 0; rep < 2; rep++) {
				if (rep == 0 && !(f_tdxok == 0 && f_snp == 0 && 0)) { /* probe only on the very first call of the process */ }
			}
			const char *cp = "cpuid(21,0);";
			static int first = 1;
			char pre[16] = ""; if (first) strcpy(pre, cp);
			const char *err = "error(Cannot accept memory: unknown platform\n);", *pan = "panic(TDX: Failed to accept memory\n);";
			if (sel == 0) {
				/* TDX guest */
				snprintf(want, sizeof want, "%stdx_accept(1000,2000);%s|tdx_accept(1000,2000);%s|", pre, f_tdxok ? "returned;" : pan, f_tdxok ? "returned;" : pan);
			} else {
				snprintf(want, sizeof want, "%sis_snp;%s|is_snp;%s|", pre, f_snp ? "snp_accept(1000,2000);returned;" : err, f_snp ? "snp_accept(1000,2000);returned;" : err);
			}
			first = 0;
			checks++;
			if (strcmp(want, got)) { fails++; printf("DIFF accept(fake cpuid sig=%d) tdxok=%d snp=%d\n want: %s\n got : %s\n", sel, f_tdxok, f_snp, want, got); }
		}
	}
	printf("memtest sig=%d checks=%lu failures=%lu\n", sel, checks, fails);
	return fails != 0;
}
