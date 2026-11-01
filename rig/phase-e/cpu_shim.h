/* Userspace stand-ins for what the C cut out of port/pristine/arch/x86/kernel/cpu/common.c needs (rig/phase-e/cpu_gen.py). The feature numbers
 * are the kernel's own header (asm/cpufeatures.h, included verbatim via -I); `struct cpuinfo_x86` is the kernel's definition with the
 * topology struct replaced by a byte array of the same size; every other number is checked: the offsets by the _Static_asserts below (which
 * are the values common_rs.rs's consts_check.py compares against the kernel), the CPUID mock and the stubs only need to be the same for both
 * sides. Nothing here is trusted: a wrong value shows as a C != Rust mismatch or as an assertion. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32;
typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64; typedef unsigned long kernel_ulong_t;
#define __init
#define __initconst
#define __initdata
#define __ro_after_init
#define __maybe_unused __attribute__((unused))
#define __always_inline inline __attribute__((always_inline))
#define __aligned(x) __attribute__((aligned(x)))
#define __noreturn
#define unlikely(x) (x)
#define likely(x) (x)
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define IS_ENABLED(x) (x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CONFIG_X86_64 1
#ifndef CONFIG_PROCESSOR_SELECT_V
#define CONFIG_PROCESSOR_SELECT_V 0
#endif
#if CONFIG_PROCESSOR_SELECT_V
#define CONFIG_PROCESSOR_SELECT 1
#endif
#define CONFIG_CPU_SUP_INTEL 1
#define USE_EARLY_PGTABLE_L5
#include <asm/cpufeatures.h>
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (63 - (h))))
#define _LINUX_BITS_H
#include <asm/msr-index.h>
u64 test_rdmsr(u32 msr);
#define rdmsrq(msr, val) ((val) = test_rdmsr(msr))

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_HYGON 9
#define X86_VENDOR_ZHAOXIN 10
#define X86_VENDOR_VORTEX 11
#define X86_VENDOR_NUM 12
#define X86_VENDOR_UNKNOWN 0xff
#define CPUID_LEAF_MWAIT 0x05
#define CPUID_LEAF_DCA 0x09
#define CPUID_LEAF_XSTATE 0x0d
#define TAINT_CPU_OUT_OF_SPEC 2
enum lockdep_ok { LOCKDEP_STILL_OK, LOCKDEP_NOW_UNRELIABLE };
enum cpuid_leafs {
	CPUID_1_EDX = 0, CPUID_8000_0001_EDX, CPUID_8086_0001_EDX, CPUID_LNX_1, CPUID_1_ECX, CPUID_C000_0001_EDX, CPUID_8000_0001_ECX, CPUID_LNX_2, CPUID_LNX_3,
	CPUID_7_0_EBX, CPUID_D_1_EAX, CPUID_LNX_4, CPUID_7_1_EAX, CPUID_8000_0008_EBX, CPUID_6_EAX, CPUID_8000_000A_EDX, CPUID_7_ECX, CPUID_8000_0007_EBX,
	CPUID_7_EDX, CPUID_8000_001F_EAX, CPUID_8000_0021_EAX, CPUID_LNX_5, NR_CPUID_WORDS,
};
_Static_assert(NR_CPUID_WORDS == NCAPINTS, "NCAPINTS");

/* struct cpuinfo_topology (asm/processor.h) */
struct cpuinfo_topology {
	u32 apicid, initial_apicid, pkg_id, die_id, cu_id, core_id, logical_pkg_id, logical_die_id, logical_core_id, amd_node_id, llc_id, l2c_id;
	union { u32 cpu_type; struct { u32 intel_native_model_id : 24; u32 intel_type : 8; }; struct { u32 amd_num_processors : 16, amd_power_eff_ranking : 8, amd_native_model_id : 4, amd_type : 4; }; };
};
_Static_assert(sizeof(struct cpuinfo_topology) == 52, "topo");
/* the kernel's `struct cpuinfo_x86` (asm/processor.h), x86-64, VMX_FEATURE_NAMES, no randomisation; `topo` is 52 bytes (struct cpuinfo_topology) */
struct cpuinfo_x86 {
	union { struct { __u8 x86_model; __u8 x86; __u8 x86_vendor; __u8 x86_reserved; }; __u32 x86_vfm; };
	__u8 x86_stepping;
	int x86_tlbsize;
	__u32 vmx_capability[5];
	__u8 x86_virt_bits;
	__u8 x86_phys_bits;
	__u32 extended_cpuid_level;
	int cpuid_level;
	union { __u32 x86_capability[NCAPINTS + NBUGINTS]; unsigned long x86_capability_alignment; };
	char x86_vendor_id[16];
	char x86_model_id[64];
	struct cpuinfo_topology topo;
	unsigned int x86_cache_size;
	int x86_cache_alignment;
	int x86_cache_max_rmid;
	int x86_cache_occ_scale;
	int x86_cache_mbm_width_offset;
	int x86_power;
	unsigned long loops_per_jiffy;
	u64 ppin;
	u16 x86_clflush_size;
	u16 booted_cores;
	u16 cpu_index;
	bool smt_active;
	u32 microcode;
	u8 x86_cache_bits;
	unsigned initialized : 1;
};
_Static_assert(offsetof(struct cpuinfo_x86, x86_virt_bits) == 0x20 && offsetof(struct cpuinfo_x86, cpuid_level) == 0x28 &&
	       offsetof(struct cpuinfo_x86, x86_capability) == 0x30 && offsetof(struct cpuinfo_x86, x86_vendor_id) == 0x90 &&
	       offsetof(struct cpuinfo_x86, x86_cache_alignment) == 0x118 && offsetof(struct cpuinfo_x86, x86_power) == 0x128 &&
	       offsetof(struct cpuinfo_x86, x86_clflush_size) == 0x140 && offsetof(struct cpuinfo_x86, cpu_index) == 0x144 &&
	       offsetof(struct cpuinfo_x86, x86_cache_bits) == 0x14c, "cpuinfo_x86 layout");

struct cpu_dev {
	const char *c_vendor;
	const char *c_ident[2];
	void (*c_early_init)(struct cpuinfo_x86 *);
	void (*c_bsp_init)(struct cpuinfo_x86 *);
	void (*c_init)(struct cpuinfo_x86 *);
	void (*c_identify)(struct cpuinfo_x86 *);
	void (*c_detect_tlb)(struct cpuinfo_x86 *);
	int c_x86_vendor;
};
_Static_assert(sizeof(struct cpu_dev) == 72 && offsetof(struct cpu_dev, c_x86_vendor) == 64, "cpu_dev layout");

extern const struct cpu_dev *const __x86_cpu_dev_start[], *const __x86_cpu_dev_end[];
extern struct cpuinfo_x86 boot_cpu_data;
extern __u32 cpu_caps_cleared[NCAPINTS + NBUGINTS];
extern __u32 cpu_caps_set[NCAPINTS + NBUGINTS];
extern const char * const x86_cap_flags[NCAPINTS * 32];
extern const char * const x86_bug_flags[NBUGINTS * 32];
extern char boot_command_line[2048];
extern unsigned int __pgtable_l5_enabled;
extern int alternatives_patched;
#define pgtable_l5_enabled() (__pgtable_l5_enabled != 0)

/* set_bit / test_bit on the unsigned-long words, as the kernel's (the x86 `lock bts` is the plain OR here) */
static inline void set_bit(long nr, unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
static inline bool arch_test_bit(unsigned long nr, const unsigned long *addr) { return (addr[nr / 64] >> (nr % 64)) & 1; }
/* cpufeaturemasks.h of build-full / build-fast (REQUIRED features: FPU PSE MSR PAE CX8 PGE CMOV FXSR XMM XMM2 LM NOPL ALWAYS CPUID); cpu_cmp.sh compares with the generated header */
#define REQUIRED_MASK0 0x0700a169U
#define REQUIRED_MASK1 0x20000000U
#define REQUIRED_MASK3 0x02300000U
#define REQUIRED_MASK_BIT_SET(x) ((((x) >> 5) == 0 ? REQUIRED_MASK0 : ((x) >> 5) == 1 ? REQUIRED_MASK1 : ((x) >> 5) == 3 ? REQUIRED_MASK3 : 0) & (1U << ((x) & 31)))
#define test_cpu_cap(c, bit) arch_test_bit(bit, (unsigned long *)((c)->x86_capability))
#define cpu_has(c, bit) (__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 : test_cpu_cap(c, bit))
#define boot_cpu_has(bit) cpu_has(&boot_cpu_data, bit)
/* SEV_SNP is a DISABLED feature in both configs (no KVM_AMD_SEV): cpu_feature_enabled() of it is the constant 0 */
#define cpu_feature_enabled(bit) ((bit) == X86_FEATURE_SEV_SNP ? 0 : boot_cpu_has(bit))
#define LOCKDEP_STILL_OK_ LOCKDEP_STILL_OK
#define set_cpu_cap(c, bit) set_bit(bit, (unsigned long *)((c)->x86_capability))
void setup_clear_cpu_cap(unsigned int bit);
void clear_cpu_cap(struct cpuinfo_x86 *c, unsigned int bit);
void check_cpufeature_deps(struct cpuinfo_x86 *c);
void test_warn_alt(void);
#define WARN_ON(x) ({ int __w = !!(x); if (__w) test_warn_alt(); __w; })
#define setup_force_cpu_cap(bit) do { if (!boot_cpu_has(bit)) WARN_ON(alternatives_patched); set_cpu_cap(&boot_cpu_data, bit); set_bit(bit, (unsigned long *)cpu_caps_set); } while (0)
#define setup_force_cpu_bug(bit) setup_force_cpu_cap(bit)

/* printk: recorded (the Rust side's _printk is the same function); levels as include/linux/kern_levels.h */
int _printk(const char *fmt, ...);
#define KERN_SOH "\001"
#define KERN_ERR KERN_SOH "3"
#define KERN_WARNING KERN_SOH "4"
#define KERN_INFO KERN_SOH "6"
#define KERN_CONT KERN_SOH "c"
#define pr_err(fmt, ...) _printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) _printk(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) _printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_cont(fmt, ...) _printk(KERN_CONT fmt, ##__VA_ARGS__)
/* include/linux/once_lite.h: DO_ONCE_LITE_IF, the flag in section .data..once (here a named section the harness can clear) */
#define pr_err_once(fmt, ...) ({ static bool __already_done __attribute__((section("onceflags"), used)); bool __ret = !__already_done; if (__ret) { __already_done = true; pr_err(fmt, ##__VA_ARGS__); } __ret; })
void add_taint(unsigned flag, enum lockdep_ok lockdep_ok);

/* CPUID: recorded; answers from the harness (asm/cpuid/api.h) */
void test_cpuid(u32 op, u32 count, u32 *out);
static inline void __cpuid(u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) { u32 o[4]; test_cpuid(*eax, *ecx, o); *eax = o[0]; *ebx = o[1]; *ecx = o[2]; *edx = o[3]; }
static inline void cpuid(u32 op, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) { *eax = op; *ecx = 0; __cpuid(eax, ebx, ecx, edx); }
static inline void cpuid_count(u32 op, int count, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) { *eax = op; *ecx = count; __cpuid(eax, ebx, ecx, edx); }
static inline u32 cpuid_eax(u32 op) { u32 a, b, c, d; cpuid(op, &a, &b, &c, &d); return a; }
static inline u32 cpuid_edx(u32 op) { u32 a, b, c, d; cpuid(op, &a, &b, &c, &d); return d; }
unsigned int x86_family(unsigned int sig); unsigned int x86_model(unsigned int sig); unsigned int x86_stepping(unsigned int sig);
static inline bool cpuid_feature(void) { return true; }


/* the callees that are not part of the port: recorded stubs that mix the whole struct (so an order or stale-field difference shows) */
void init_scattered_cpuid_features(struct cpuinfo_x86 *c);
void cpu_init_topology(struct cpuinfo_x86 *c);
void intel_unlock_cpuid_leafs(struct cpuinfo_x86 *c);
void sld_setup(struct cpuinfo_x86 *c);
void mca_bsp_init(struct cpuinfo_x86 *c);
void cpu_detect_cache_sizes(struct cpuinfo_x86 *c);
int cmdline_find_option_bool(const char *cmdline, const char *option);
int cmdline_find_option(const char *cmdline, const char *option, char *buffer, int bufsize);
int kstrtouint(const char *s, unsigned int base, unsigned int *res);
/* `strsep` and `strcmp` are libc's, which are the kernel's semantics */
