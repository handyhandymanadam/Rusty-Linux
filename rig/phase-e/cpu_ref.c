/* Reference for common.c: the REAL C of the functions common_rs.rs replaces (cpu_gen.py cuts it out of port/pristine), compiled against cpu_shim.h,
 * plus the recorded stubs both sides call and the accessors the Rust harness (cpu_cmp.rs) uses. Build flags: -DREG_N=<entries of the cpu_dev
 * registration array> -DCONFIG_PROCESSOR_SELECT_V=0|1 */
#include "cpu_shim.h"
#ifndef REG_N
#define REG_N 5
#endif
#define STR2(x) #x
#define STR(x) STR2(x)
extern char __start_onceflags[], __stop_onceflags[];

/* ---- recorded log: every printk, taint, stub call, cpuid call, in order ---- */
static char g_log[1 << 20]; static size_t g_loglen;
static void logf(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	if (g_loglen < sizeof g_log - 4096) g_loglen += vsnprintf(g_log + g_loglen, sizeof g_log - g_loglen, fmt, ap);
	va_end(ap);
}
int _printk(const char *fmt, ...)
{
	char buf[1024]; va_list ap; va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
	logf("printk[%d]<%s>\n", (int)(fmt[0] == 1), buf[0] == 1 ? buf + 1 : buf);   /* the level byte is part of the text: <3...> */
	return 0;
}
void test_warn_alt(void) { logf("WARN alternatives_patched\n"); }
void x86_force_cap_warn(void) { test_warn_alt(); }
void add_taint(unsigned flag, enum lockdep_ok ok) { logf("add_taint %u %d\n", flag, (int)ok); }

/* ---- the CPU the harness makes up: CPUID answers ---- */
struct fakecpu { u64 seed; u32 max_basic; u32 max_ext; u32 vendor[3]; u32 sig; u32 ebx1; u32 edx1_clflush; u32 leaf7_eax; u32 leaf80_08_eax; int density; };
static struct fakecpu g_cpu;
static u64 mix64(u64 x) { x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x; }
static u32 rnd32(u64 seed, u32 op, u32 count, int k, int density)
{
	u64 a = mix64(seed ^ ((u64)op << 20) ^ ((u64)count << 8) ^ (u64)k * 0x9e3779b97f4a7c15ULL), b = mix64(a + 1);
	u32 v = (u32)a;
	for (int i = 0; i < density; i++) v &= (u32)b >> i | (u32)(b >> 32) << (32 - i);   /* sparser words for higher density */
	return v;
}
void test_cpuid(u32 op, u32 count, u32 *out)
{
	struct fakecpu *f = &g_cpu;
	for (int k = 0; k < 4; k++) out[k] = rnd32(f->seed, op, count, k, f->density);
	if (op == 0) { out[0] = f->max_basic; out[1] = f->vendor[0]; out[3] = f->vendor[1]; out[2] = f->vendor[2]; }
	else if (op == 1) { out[0] = f->sig; out[1] = f->ebx1; out[3] = (out[3] & ~(1u << 19)) | f->edx1_clflush; }
	else if (op == 7 && count == 0) out[0] = f->leaf7_eax;
	else if (op == 0x80000000u) out[0] = f->max_ext;
	else if (op == 0x80000008u) out[0] = f->leaf80_08_eax;
	logf("cpuid %08x/%u -> %08x %08x %08x %08x\n", op, count, out[0], out[1], out[2], out[3]);
}

/* ---- recorded stubs: each mixes the whole struct (except the two scratch fields it writes) into the scratch fields ---- */
static u64 mixc(const struct cpuinfo_x86 *c, u64 salt)
{
	struct cpuinfo_x86 t = *c; memset(t.x86_model_id, 0, 8); t.loops_per_jiffy = 0;
	const u8 *p = (const u8 *)&t; u64 h = 1469598103934665603ULL ^ salt;
	for (size_t i = 0; i < sizeof t; i++) h = (h ^ p[i]) * 1099511628211ULL;
	return h;
}
static void stub(struct cpuinfo_x86 *c, const char *name, u64 salt)
{
	u64 h = mixc(c, salt); logf("stub %s mix=%016llx\n", name, (unsigned long long)h);
	memcpy(c->x86_model_id, &h, 8); c->loops_per_jiffy ^= h >> 7;
}
void init_scattered_cpuid_features(struct cpuinfo_x86 *c) { stub(c, "scattered", 1); c->x86_capability[CPUID_LNX_1] |= (u32)g_cpu.seed & 0x01300000; c->x86_capability[CPUID_LNX_2] |= (u32)(mixc(c, 2) & 0x0e00ffff); }
void cpu_init_topology(struct cpuinfo_x86 *c) { stub(c, "topology", 3); memcpy(&c->topo, c->x86_model_id, 8); }
void intel_unlock_cpuid_leafs(struct cpuinfo_x86 *c) { stub(c, "unlock", 4); }
void sld_setup(struct cpuinfo_x86 *c) { stub(c, "sld", 5); }
void mca_bsp_init(struct cpuinfo_x86 *c) { stub(c, "mca", 6); }
void cpu_detect_cache_sizes(struct cpuinfo_x86 *c) { stub(c, "cachesizes", 7); }
void check_cpufeature_deps(struct cpuinfo_x86 *c) { stub(c, "deps", 8); }
void cpu_set_bug_bits(struct cpuinfo_x86 *c);
void clear_cpu_cap(struct cpuinfo_x86 *c, unsigned int bit)
{
	logf("clear_cpu_cap %u\n", bit); c->x86_capability[bit / 32] &= ~(1u << (bit % 32));
	if (bit == X86_FEATURE_XSAVE) c->x86_capability[CPUID_D_1_EAX] &= ~7u;   /* a made-up dependent feature chain */
}
void setup_clear_cpu_cap(unsigned int bit)
{
	logf("setup_clear_cpu_cap %u\n", bit); boot_cpu_data.x86_capability[bit / 32] &= ~(1u << (bit % 32)); cpu_caps_cleared[bit / 32] |= 1u << (bit % 32);
}
static void early_init_stub(struct cpuinfo_x86 *c) { stub(c, "c_early_init", 11); c->x86_capability[CPUID_LNX_3] ^= 0x10; }
static void bsp_init_stub(struct cpuinfo_x86 *c) { stub(c, "c_bsp_init", 12); c->x86_capability[CPUID_LNX_4] ^= 0x4; }
static void init_stub(struct cpuinfo_x86 *c) { (void)c; }

/* ---- command line options: a table the harness sets ---- */
struct opt { char name[32]; int present; char value[200]; };
static struct opt g_opts[16]; static int g_nopts;
char boot_command_line[2048];
int cmdline_find_option_bool(const char *cmdline, const char *option)
{
	(void)cmdline;
	for (int i = 0; i < g_nopts; i++) if (!strcmp(g_opts[i].name, option)) { logf("find_option_bool %s -> %d\n", option, g_opts[i].present); return g_opts[i].present; }
	logf("find_option_bool %s -> 0\n", option); return 0;
}
int cmdline_find_option(const char *cmdline, const char *option, char *buffer, int bufsize)
{
	(void)cmdline;
	for (int i = 0; i < g_nopts; i++) if (!strcmp(g_opts[i].name, option) && g_opts[i].present) {
		size_t n = strlen(g_opts[i].value); if (n > (size_t)bufsize - 1) n = bufsize - 1;
		memcpy(buffer, g_opts[i].value, n); buffer[n] = 0; logf("find_option %s -> %zu '%s'\n", option, n, buffer); return (int)n;
	}
	logf("find_option %s -> -1\n", option); return -1;
}
int kstrtouint(const char *s, unsigned int base, unsigned int *res)   /* lib/kstrtox.c semantics for base 10: optional '+', digits, optional one trailing '\n' */
{
	(void)base; unsigned long long v = 0; int any = 0;
	if (*s == '+') s++;
	for (; *s >= '0' && *s <= '9'; s++) { any = 1; if (v > (~0ULL - 9) / 10) return -34; v = v * 10 + (*s - '0'); }
	if (*s == '\n') s++;
	if (*s || !any) return -22;
	if (v != (unsigned int)v) return -34;
	*res = (unsigned int)v; return 0;
}

/* ---- the globals ---- */
struct cpuinfo_x86 boot_cpu_data;
__u32 cpu_caps_cleared[NCAPINTS + NBUGINTS] __aligned(sizeof(unsigned long));
__u32 cpu_caps_set[NCAPINTS + NBUGINTS] __aligned(sizeof(unsigned long));
unsigned int __pgtable_l5_enabled;
int alternatives_patched;
static void identify_cpu_without_cpuid(struct cpuinfo_x86 *c) { (void)c; }   /* never called: cpuid_feature() is true on x86-64 */

/* the vendors (cpu_dev of intel.c, amd.c, hygon.c, centaur.c, zhaoxin.c: idents, vendor numbers; callbacks are stubs, NULL where the file has none) */
#define DEV(nm, id0, id1, vend, early, bsp) { .c_vendor = nm, .c_ident = { id0, id1 }, .c_early_init = early, .c_bsp_init = bsp, .c_init = init_stub, .c_x86_vendor = vend }
static const struct cpu_dev dev_intel = DEV("Intel", "GenuineIntel", NULL, X86_VENDOR_INTEL, early_init_stub, bsp_init_stub);
static const struct cpu_dev dev_amd = DEV("AMD", "AuthenticAMD", NULL, X86_VENDOR_AMD, early_init_stub, bsp_init_stub);
static const struct cpu_dev dev_hygon = DEV("Hygon", "HygonGenuine", NULL, X86_VENDOR_HYGON, early_init_stub, NULL);
static const struct cpu_dev dev_centaur = DEV("Centaur", "CentaurHauls", NULL, X86_VENDOR_CENTAUR, early_init_stub, NULL);
static const struct cpu_dev dev_zhaoxin = DEV("zhaoxin", "  Shanghai  ", NULL, X86_VENDOR_ZHAOXIN, NULL, bsp_init_stub);
static const struct cpu_dev dev_two = DEV("Two", "TwoIdentsInc", "OrAnotherOne", X86_VENDOR_CYRIX, NULL, NULL);   /* c_ident[1] (AMD's old second ident) */
static const struct cpu_dev *const all_devs[] = { &dev_intel, &dev_amd, &dev_hygon, &dev_centaur, &dev_zhaoxin, &dev_two, NULL };
#define NDEVS_ALL 7
const struct cpu_dev *reg[REG_N + 1];    /* the registration array: __x86_cpu_dev_start .. __x86_cpu_dev_end (REG_N entries) */
__asm__(".globl __x86_cpu_dev_start\n.set __x86_cpu_dev_start, reg\n.globl __x86_cpu_dev_end\n.set __x86_cpu_dev_end, reg+8*" STR(REG_N));

#ifdef NOSLDMCA    /* config-fast: no CONFIG_X86_BUS_LOCK_DETECT, no CONFIG_X86_MCE: sld_setup() and mca_bsp_init() are empty inlines */
#define sld_setup(c) ((void)0)
#define mca_bsp_init(c) ((void)0)
#endif
#include CAPFLAGS
#include PRELUDE
#include MATCHINC
#include CPUINC

static u64 g_arch_msr;
u64 test_rdmsr(u32 msr) { logf("rdmsr %x -> %llx\n", msr, (unsigned long long)g_arch_msr); return g_arch_msr; }
void c_set_arch(u64 v) { g_arch_msr = v; }
void c_bugbits(struct cpuinfo_x86 *c) { cpu_set_bug_bits(c); }
/* every entry of the three real tables: vendor, family, model, steppings mask, driver_data (what the harness picks real CPUs from) */
int c_table_entries(int which, u32 *out, int max)
{
	const struct x86_cpu_id *t = which == 0 ? cpu_vuln_whitelist : which == 1 ? cpu_vuln_blacklist : cpu_latest_microcode; int n = 0;
	for (; t->flags & X86_CPU_ID_FLAG_ENTRY_VALID && n < max; t++, n++) { out[6 * n] = t->vendor; out[6 * n + 1] = t->family; out[6 * n + 2] = t->model; out[6 * n + 3] = t->steppings; out[6 * n + 4] = t->type; out[6 * n + 5] = (u32)t->driver_data; }
	return n;
}
size_t c_xci_size(void) { return sizeof(struct x86_cpu_id); }

/* ---- accessors for the harness ---- */
size_t c_sizeof(void) { return sizeof(struct cpuinfo_x86); }
size_t c_reg_n(void) { return REG_N; }
void *c_boot(void) { return &boot_cpu_data; }
void *c_caps_set(void) { return cpu_caps_set; }
void *c_caps_cleared(void) { return cpu_caps_cleared; }
void *c_l5(void) { return &__pgtable_l5_enabled; }
void *c_altp(void) { return &alternatives_patched; }
const void *c_devs_ptr(void) { return cpu_devs; }
void c_log_reset(void) { g_loglen = 0; g_log[0] = 0; }
const char *c_log(void) { return g_log; }
size_t c_loglen(void) { return g_loglen; }
void c_set_opts(const char *names, const int *present, const char *values, int n)   /* names/values: n fixed-width records of 32 / 200 bytes */
{
	g_nopts = n; for (int i = 0; i < n; i++) { memcpy(g_opts[i].name, names + 32 * i, 32); g_opts[i].present = present[i]; memcpy(g_opts[i].value, values + 200 * i, 200); }
}
void c_set_cpu(u64 seed, u32 max_basic, u32 max_ext, const u32 *vendor, u32 sig, u32 ebx1, u32 clflush_bit, u32 leaf7_eax, u32 l8_08_eax, int density)
{
	g_cpu = (struct fakecpu){ seed, max_basic, max_ext, { vendor[0], vendor[1], vendor[2] }, sig, ebx1, clflush_bit ? (1u << 19) : 0, leaf7_eax, l8_08_eax, density };
}
void c_set_reg(const int *which)   /* which[i]: index into all_devs (NDEVS_ALL-1 = NULL entry) for each of the REG_N registration slots */
{
	for (int i = 0; i < REG_N; i++) reg[i] = all_devs[which[i]];
	reg[REG_N] = (void *)0x1;   /* never read: one past the end */
}
void c_reset_state(int this_idx, const int *devs_idx)   /* this_cpu = all_devs[this_idx] or &default_cpu (-1); cpu_devs[i] = all_devs[devs_idx[i]] (>= NDEVS_ALL-1: NULL) */
{
	this_cpu = this_idx < 0 ? &default_cpu : all_devs[this_idx];
	for (int i = 0; i < X86_VENDOR_NUM + 4; i++) cpu_devs[i] = devs_idx[i] < 0 || devs_idx[i] >= NDEVS_ALL - 1 ? NULL : all_devs[devs_idx[i]];
	for (size_t k = 0; k < (size_t)((char *)__stop_onceflags - (char *)__start_onceflags); k++) ((char *)__start_onceflags)[k] = 0;
}
int c_this_idx(void)
{
	if (this_cpu == &default_cpu) return -1;
	for (int i = 0; i < NDEVS_ALL - 1; i++) if (this_cpu == all_devs[i]) return i;
	return -2;
}
int c_dev_idx(const struct cpu_dev *d) { if (!d) return -9; for (int i = 0; i < NDEVS_ALL - 1; i++) if (d == all_devs[i]) return i; return -2; }
const unsigned char *c_once_flags(size_t *n) { *n = (char *)__stop_onceflags - (char *)__start_onceflags; return (const unsigned char *)__start_onceflags; }

void c_cpu_detect(struct cpuinfo_x86 *c) { cpu_detect(c); }
void c_get_cpu_vendor(struct cpuinfo_x86 *c) { get_cpu_vendor(c); }
void c_get_cpu_cap(struct cpuinfo_x86 *c) { get_cpu_cap(c); }
void c_get_cpu_address_sizes(struct cpuinfo_x86 *c) { get_cpu_address_sizes(c); }
void c_filter(struct cpuinfo_x86 *c, int warn) { filter_cpuid_features(c, warn); }
void c_apply_forced_caps(struct cpuinfo_x86 *c) { apply_forced_caps(c); }
void c_init_cpu_devs(void) { init_cpu_devs(); }
void c_early_cpu_init(void) { early_cpu_init(); }
void c_early_identify_cpu(struct cpuinfo_x86 *c) { early_identify_cpu(c); }
int c_parse_set_clear(char *arg, int set) { return parse_set_clear_cpuid(arg, set); }
void c_cpu_parse_early_param(void) { cpu_parse_early_param(); }
