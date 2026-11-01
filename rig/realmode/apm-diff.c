/* Lockstep differential: C apm.c (run-apm-diff.sh: renames only) vs Rust apm_rs.rs (--cfg host_mock). One scenario = a BIOS whose INT 15h/AH=53h answers are random but
 * biased into every arm (CF, signature 'PM', CX bit 1, the connect's CF and its fields, the second installation check). Both runs log initregs and every intcall (number, ALL 44
 * ireg bytes, oreg NULL or not, the BIOS answer), the return value and the final boot_params (nonzero bytes). Logs must be identical. */
#include <asm/bootparam.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
struct port_io_ops pio_ops;
struct boot_params c_boot_params, boot_params;
int c_query_apm_bios(void); int query_apm_bios(void);
char host_end[4096] __attribute__((aligned(65536))); char *HEAP, *heap_end;
_Static_assert(offsetof(struct boot_params, apm_bios_info) == 0x40 && sizeof(struct apm_bios_info) == 20, "apm_bios_info");
_Static_assert(offsetof(struct apm_bios_info, version) == 0 && offsetof(struct apm_bios_info, cseg) == 2 && offsetof(struct apm_bios_info, offset) == 4 && offsetof(struct apm_bios_info, cseg_16) == 8 && offsetof(struct apm_bios_info, dseg) == 10 && offsetof(struct apm_bios_info, flags) == 12 && offsetof(struct apm_bios_info, cseg_len) == 14 && offsetof(struct apm_bios_info, cseg_16_len) == 16 && offsetof(struct apm_bios_info, dseg_len) == 18, "apm fields");
static uint64_t rs, ors;
static uint64_t rnd(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs*0x2545F4914F6CDD1DULL;}
static uint64_t ornd(void){ors^=ors<<13;ors^=ors>>7;ors^=ors<<17;return ors*0x2545F4914F6CDD1DULL;}
static char lg[1 << 18]; static size_t ln;
#define LOG(...) (ln += snprintf(lg + ln, sizeof lg - ln, __VA_ARGS__))
static void hex(const u8 *p, int n){ for(int i=0;i<n;i++) LOG("%02x", p[i]); }
static u16 s_ds; static int p_cf1, p_sig1, p_cx1, p_cf2, p_cf3, p_sig3; static u64 s_seed;
u16 mock_ds(void){ return s_ds; } u8 mock_inb(u16 p){ return (u8)p; } void mock_outb(u8 v, u16 p){ (void)v;(void)p; } void mock_outw(u16 v, u16 p){ (void)v;(void)p; }
void initregs(void *r){ u32 *w = r; memset(w, 0, 44); w[10] = 1; w[8] = 0; w[9] = (u32)s_ds | ((u32)s_ds << 16); LOG("initregs ds=%04x\n", s_ds); }
static int ncall;
void intcall(u8 n, const void *ireg, void *oreg){
	const u32 *w = ireg; u32 o[11];
	LOG("intcall %02x ireg=", n); hex(ireg, 44); LOG(" oreg=%s\n", oreg ? "ptr" : "NULL");
	for (int i = 0; i < 11; i++) o[i] = (u32)ornd();
	u8 al = w[7] & 0xff; int phase = al == 0 ? (ncall == 0 ? 1 : 3) : (al == 3 ? 2 : 0);
	int cf = 0, sig = 1, cx = 1;
	if (phase == 1) { cf = p_cf1; sig = p_sig1; cx = p_cx1; } else if (phase == 2) cf = p_cf2; else if (phase == 3) { cf = p_cf3; sig = p_sig3; }
	ncall++;
	o[10] = (o[10] & ~1u) | cf;
	if (phase == 1 || phase == 3) { o[4] = (o[4] & ~0xffffu) | (sig ? 0x504d : (u32)(ornd() & 0xffff)); if (phase == 1) o[6] = (o[6] & ~2u) | (cx ? 2 : 0); }
	if (oreg) { memcpy(oreg, o, 44); LOG("  -> "); hex((u8 *)o, 44); LOG("\n"); }
}
int main(int argc, char **argv){
	long n = argc > 1 ? atol(argv[1]) : 100000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 88172645463325252ULL; long mism = 0; long arm[8] = {0};
	for (long i = 0; i < n; i++) {
		s_ds = rnd() % 2 ? (u16)rnd() : 0x1000;
		p_cf1 = rnd() % 5 == 0; p_sig1 = rnd() % 5 != 0; p_cx1 = rnd() % 5 != 0; p_cf2 = rnd() % 4 == 0; p_cf3 = rnd() % 4 == 0; p_sig3 = rnd() % 4 != 0; s_seed = rnd();
		const char *res[2]; char *keep[2]; int rets[2];
		for (int w = 0; w < 2; w++) {
			ln = 0; lg[0] = 0; ors = s_seed | 1; ncall = 0;
			struct boot_params *bp = w == 0 ? &c_boot_params : &boot_params; memset(bp, 0x5a, sizeof *bp);
			rets[w] = w == 0 ? c_query_apm_bios() : query_apm_bios();
			LOG("ret %d\nbp(!=5a) ", rets[w]); for (int k = 0; k < 4096; k++) if (((u8 *)bp)[k] != 0x5a) LOG("%x:%02x ", k, ((u8 *)bp)[k]); LOG("\n");
			keep[w] = strdup(lg); res[w] = keep[w];
		}
		if (strcmp(res[0], res[1])) { mism++; if (mism <= 3) { printf("scenario %ld DIFFERS\n--C--\n%.1500s\n--R--\n%.1500s\n", i, res[0], res[1]); } }
		arm[0] += rets[0] == 0; arm[1] += rets[0] == -1; arm[2] += p_cf1; arm[3] += !p_cf1 && !p_sig1; arm[4] += !p_cf1 && p_sig1 && !p_cx1; arm[5] += !p_cf1 && p_sig1 && p_cx1 && p_cf2; arm[6] += !p_cf1 && p_sig1 && p_cx1 && !p_cf2 && (p_cf3 || !p_sig3); 
		free(keep[0]); free(keep[1]);
	}
	printf("scenarios=%ld  C-vs-Rust mismatches=%ld  (ret0=%ld ret-1=%ld; arms: cf1=%ld sig1-bad=%ld no-32bit=%ld connect-cf=%ld recheck-fail=%ld)\n", n, mism, arm[0], arm[1], arm[2], arm[3], arm[4], arm[5], arm[6]);
	return mism != 0;
}
