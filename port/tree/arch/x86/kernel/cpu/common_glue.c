/* SPDX-License-Identifier: GPL-2.0-only */
/* arch/x86/kernel/cpu/common.c with the CPUID decode group and the early identification removed (common_rs.rs holds them); the statics those functions share with the rest
 * (default_cpu, this_cpu, cpu_devs and the three x86_cpu_id tables) are global with hidden visibility. `#line` keeps upstream's file name and line numbers. */
#line 1 "arch/x86/kernel/cpu/common.c"
// SPDX-License-Identifier: GPL-2.0-only
/* cpu_feature_enabled() cannot be used this early */
#define USE_EARLY_PGTABLE_L5

#include <linux/memblock.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/sched/mm.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/smt.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kgdb.h>
#include <linux/mem_encrypt.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/io.h>
#include <linux/syscore_ops.h>
#include <linux/pgtable.h>
#include <linux/stackprotector.h>
#include <linux/utsname.h>
#include <linux/efi.h>

#include <asm/alternative.h>
#include <asm/cmdline.h>
#include <asm/cpuid/api.h>
#include <asm/perf_event.h>
#include <asm/mmu_context.h>
#include <asm/doublefault.h>
#include <asm/archrandom.h>
#include <asm/hypervisor.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/debugreg.h>
#include <asm/sections.h>
#include <asm/vsyscall.h>
#include <linux/topology.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>
#include <asm/proto.h>
#include <asm/setup.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/mtrr.h>
#include <asm/hwcap2.h>
#include <linux/numa.h>
#include <asm/numa.h>
#include <asm/asm.h>
#include <asm/bugs.h>
#include <asm/cpu.h>
#include <asm/mce.h>
#include <asm/msr.h>
#include <asm/cacheinfo.h>
#include <asm/memtype.h>
#include <asm/microcode.h>
#include <asm/intel-family.h>
#include <asm/cpu_device_id.h>
#include <asm/fred.h>
#include <asm/uv/uv.h>
#include <asm/ia32.h>
#include <asm/set_memory.h>
#include <asm/traps.h>
#include <asm/sev.h>
#include <asm/tdx.h>
#include <asm/posted_intr.h>
#include <asm/runtime-const.h>

#include "cpu.h"

DEFINE_PER_CPU_READ_MOSTLY(struct cpuinfo_x86, cpu_info);
EXPORT_PER_CPU_SYMBOL(cpu_info);

/* Used for modules: built-in code uses runtime constants */
unsigned long USER_PTR_MAX;
EXPORT_SYMBOL(USER_PTR_MAX);

u32 elf_hwcap2 __read_mostly;

/* Number of siblings per CPU package */
unsigned int __max_threads_per_core __ro_after_init = 1;
EXPORT_SYMBOL(__max_threads_per_core);

unsigned int __max_dies_per_package __ro_after_init = 1;
EXPORT_SYMBOL(__max_dies_per_package);

unsigned int __max_logical_packages __ro_after_init = 1;
EXPORT_SYMBOL(__max_logical_packages);

unsigned int __num_cores_per_package __ro_after_init = 1;
EXPORT_SYMBOL(__num_cores_per_package);

unsigned int __num_threads_per_package __ro_after_init = 1;
EXPORT_SYMBOL(__num_threads_per_package);

static struct ppin_info {
	int	feature;
	int	msr_ppin_ctl;
	int	msr_ppin;
} ppin_info[] = {
	[X86_VENDOR_INTEL] = {
		.feature = X86_FEATURE_INTEL_PPIN,
		.msr_ppin_ctl = MSR_PPIN_CTL,
		.msr_ppin = MSR_PPIN
	},
	[X86_VENDOR_AMD] = {
		.feature = X86_FEATURE_AMD_PPIN,
		.msr_ppin_ctl = MSR_AMD_PPIN_CTL,
		.msr_ppin = MSR_AMD_PPIN
	},
};

static const struct x86_cpu_id ppin_cpuids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_AMD_PPIN, &ppin_info[X86_VENDOR_AMD]),
	X86_MATCH_FEATURE(X86_FEATURE_INTEL_PPIN, &ppin_info[X86_VENDOR_INTEL]),

	/* Legacy models without CPUID enumeration */
	X86_MATCH_VFM(INTEL_IVYBRIDGE_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_HASWELL_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_BROADWELL_D, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_BROADWELL_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_SKYLAKE_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_ICELAKE_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_ICELAKE_D, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_SAPPHIRERAPIDS_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_EMERALDRAPIDS_X, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_XEON_PHI_KNL, &ppin_info[X86_VENDOR_INTEL]),
	X86_MATCH_VFM(INTEL_XEON_PHI_KNM, &ppin_info[X86_VENDOR_INTEL]),

	{}
};

static void ppin_init(struct cpuinfo_x86 *c)
{
	const struct x86_cpu_id *id;
	unsigned long long val;
	struct ppin_info *info;

	id = x86_match_cpu(ppin_cpuids);
	if (!id)
		return;

	/*
	 * Testing the presence of the MSR is not enough. Need to check
	 * that the PPIN_CTL allows reading of the PPIN.
	 */
	info = (struct ppin_info *)id->driver_data;

	if (rdmsrq_safe(info->msr_ppin_ctl, &val))
		goto clear_ppin;

	if ((val & 3UL) == 1UL) {
		/* PPIN locked in disabled mode */
		goto clear_ppin;
	}

	/* If PPIN is disabled, try to enable */
	if (!(val & 2UL)) {
		wrmsrq_safe(info->msr_ppin_ctl,  val | 2UL);
		rdmsrq_safe(info->msr_ppin_ctl, &val);
	}

	/* Is the enable bit set? */
	if (val & 2UL) {
		c->ppin = native_rdmsrq(info->msr_ppin);
		set_cpu_cap(c, info->feature);
		return;
	}

clear_ppin:
	setup_clear_cpu_cap(info->feature);
}

static void default_init(struct cpuinfo_x86 *c)
{
#ifdef CONFIG_X86_64
	cpu_detect_cache_sizes(c);
#else
	/* Not much we can do here... */
	/* Check if at least it has cpuid */
	if (c->cpuid_level == -1) {
		/* No cpuid. It must be an ancient CPU */
		if (c->x86 == 4)
			strcpy(c->x86_model_id, "486");
		else if (c->x86 == 3)
			strcpy(c->x86_model_id, "386");
	}
#endif
}

const struct cpu_dev default_cpu __attribute__((visibility("hidden"))) = {
	.c_init		= default_init,
	.c_vendor	= "Unknown",
	.c_x86_vendor	= X86_VENDOR_UNKNOWN,
};

const struct cpu_dev *this_cpu __attribute__((visibility("hidden"))) = &default_cpu;

DEFINE_PER_CPU_PAGE_ALIGNED(struct gdt_page, gdt_page) = { .gdt = {
#ifdef CONFIG_X86_64
	/*
	 * We need valid kernel segments for data and code in long mode too
	 * IRET will check the segment types  kkeil 2000/10/28
	 * Also sysret mandates a special GDT layout
	 *
	 * TLS descriptors are currently at a different place compared to i386.
	 * Hopefully nobody expects them at a fixed place (Wine?)
	 */
	[GDT_ENTRY_KERNEL32_CS]		= GDT_ENTRY_INIT(DESC_CODE32, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(DESC_CODE64, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(DESC_DATA64, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER32_CS]	= GDT_ENTRY_INIT(DESC_CODE32 | DESC_USER, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(DESC_DATA64 | DESC_USER, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(DESC_CODE64 | DESC_USER, 0, 0xfffff),
#else
	[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(DESC_CODE32, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(DESC_DATA32, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(DESC_CODE32 | DESC_USER, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(DESC_DATA32 | DESC_USER, 0, 0xfffff),
	/*
	 * Segments used for calling PnP BIOS have byte granularity.
	 * They code segments and data segments have fixed 64k limits,
	 * the transfer segment sizes are set at run time.
	 */
	[GDT_ENTRY_PNPBIOS_CS32]	= GDT_ENTRY_INIT(DESC_CODE32_BIOS, 0, 0xffff),
	[GDT_ENTRY_PNPBIOS_CS16]	= GDT_ENTRY_INIT(DESC_CODE16, 0, 0xffff),
	[GDT_ENTRY_PNPBIOS_DS]		= GDT_ENTRY_INIT(DESC_DATA16, 0, 0xffff),
	[GDT_ENTRY_PNPBIOS_TS1]		= GDT_ENTRY_INIT(DESC_DATA16, 0, 0),
	[GDT_ENTRY_PNPBIOS_TS2]		= GDT_ENTRY_INIT(DESC_DATA16, 0, 0),
	/*
	 * The APM segments have byte granularity and their bases
	 * are set at run time.  All have 64k limits.
	 */
	[GDT_ENTRY_APMBIOS_BASE]	= GDT_ENTRY_INIT(DESC_CODE32_BIOS, 0, 0xffff),
	[GDT_ENTRY_APMBIOS_BASE+1]	= GDT_ENTRY_INIT(DESC_CODE16, 0, 0xffff),
	[GDT_ENTRY_APMBIOS_BASE+2]	= GDT_ENTRY_INIT(DESC_DATA32_BIOS, 0, 0xffff),

	[GDT_ENTRY_ESPFIX_SS]		= GDT_ENTRY_INIT(DESC_DATA32, 0, 0xfffff),
	[GDT_ENTRY_PERCPU]		= GDT_ENTRY_INIT(DESC_DATA32, 0, 0xfffff),
#endif
} };
EXPORT_PER_CPU_SYMBOL_GPL(gdt_page);
SYM_PIC_ALIAS(gdt_page);

#ifdef CONFIG_X86_64
static int __init x86_nopcid_setup(char *s)
{
	/* nopcid doesn't accept parameters */
	if (s)
		return -EINVAL;

	/* do not emit a message if the feature is not present */
	if (!boot_cpu_has(X86_FEATURE_PCID))
		return 0;

	setup_clear_cpu_cap(X86_FEATURE_PCID);
	pr_info("nopcid: PCID feature disabled\n");
	return 0;
}
early_param("nopcid", x86_nopcid_setup);
#endif

static int __init x86_noinvpcid_setup(char *s)
{
	/* noinvpcid doesn't accept parameters */
	if (s)
		return -EINVAL;

	/* do not emit a message if the feature is not present */
	if (!boot_cpu_has(X86_FEATURE_INVPCID))
		return 0;

	setup_clear_cpu_cap(X86_FEATURE_INVPCID);
	pr_info("noinvpcid: INVPCID feature disabled\n");
	return 0;
}
early_param("noinvpcid", x86_noinvpcid_setup);

/* Standard macro to see if a specific flag is changeable */
static inline bool flag_is_changeable_p(unsigned long flag)
{
	unsigned long f1, f2;

	if (!IS_ENABLED(CONFIG_X86_32))
		return true;

	/*
	 * Cyrix and IDT cpus allow disabling of CPUID
	 * so the code below may return different results
	 * when it is executed before and after enabling
	 * the CPUID. Add "volatile" to not allow gcc to
	 * optimize the subsequent calls to this function.
	 */
	asm volatile ("pushfl		\n\t"
		      "pushfl		\n\t"
		      "popl %0		\n\t"
		      "movl %0, %1	\n\t"
		      "xorl %2, %0	\n\t"
		      "pushl %0		\n\t"
		      "popfl		\n\t"
		      "pushfl		\n\t"
		      "popl %0		\n\t"
		      "popfl		\n\t"

		      : "=&r" (f1), "=&r" (f2)
		      : "ir" (flag));

	return (f1 ^ f2) & flag;
}

#ifdef CONFIG_X86_32
static int cachesize_override = -1;
static int disable_x86_serial_nr = 1;

static int __init cachesize_setup(char *str)
{
	get_option(&str, &cachesize_override);
	return 1;
}
__setup("cachesize=", cachesize_setup);

/* Probe for the CPUID instruction */
bool cpuid_feature(void)
{
	return flag_is_changeable_p(X86_EFLAGS_ID);
}

static void squash_the_stupid_serial_number(struct cpuinfo_x86 *c)
{
	unsigned long lo, hi;

	if (!cpu_has(c, X86_FEATURE_PN) || !disable_x86_serial_nr)
		return;

	/* Disable processor serial number: */

	rdmsr(MSR_IA32_BBL_CR_CTL, lo, hi);
	lo |= 0x200000;
	wrmsr(MSR_IA32_BBL_CR_CTL, lo, hi);

	pr_notice("CPU serial number disabled.\n");
	clear_cpu_cap(c, X86_FEATURE_PN);

	/* Disabling the serial number may affect the cpuid level */
	c->cpuid_level = cpuid_eax(0);
}

static int __init x86_serial_nr_setup(char *s)
{
	disable_x86_serial_nr = 0;
	return 1;
}
__setup("serialnumber", x86_serial_nr_setup);
#else
static inline void squash_the_stupid_serial_number(struct cpuinfo_x86 *c)
{
}
#endif

static __always_inline void setup_smep(struct cpuinfo_x86 *c)
{
	if (cpu_has(c, X86_FEATURE_SMEP))
		cr4_set_bits(X86_CR4_SMEP);
}

static __always_inline void setup_smap(struct cpuinfo_x86 *c)
{
	unsigned long eflags = native_save_fl();

	/* This should have been cleared long ago */
	BUG_ON(eflags & X86_EFLAGS_AC);

	if (cpu_has(c, X86_FEATURE_SMAP))
		cr4_set_bits(X86_CR4_SMAP);
}

static __always_inline void setup_umip(struct cpuinfo_x86 *c)
{
	/* Check the boot processor, plus build option for UMIP. */
	if (!cpu_feature_enabled(X86_FEATURE_UMIP))
		goto out;

	/* Check the current processor's cpuid bits. */
	if (!cpu_has(c, X86_FEATURE_UMIP))
		goto out;

	cr4_set_bits(X86_CR4_UMIP);

	pr_info_once("x86/cpu: User Mode Instruction Prevention (UMIP) activated\n");

	return;

out:
	/*
	 * Make sure UMIP is disabled in case it was enabled in a
	 * previous boot (e.g., via kexec).
	 */
	cr4_clear_bits(X86_CR4_UMIP);
}

/* These bits should not change their value after CPU init is finished. */
static const unsigned long cr4_pinned_mask = X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_UMIP |
					     X86_CR4_FSGSBASE | X86_CR4_CET;
static DEFINE_STATIC_KEY_FALSE_RO(cr_pinning);
static unsigned long cr4_pinned_bits __ro_after_init;

void native_write_cr0(unsigned long val)
{
	unsigned long bits_missing = 0;

set_register:
	asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & X86_CR0_WP) != X86_CR0_WP)) {
			bits_missing = X86_CR0_WP;
			val |= bits_missing;
			goto set_register;
		}
		/* Warn after we've set the missing bits. */
		WARN_ONCE(bits_missing, "CR0 WP bit went missing!?\n");
	}
}
EXPORT_SYMBOL(native_write_cr0);

void __no_profile native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
#if IS_MODULE(CONFIG_LKDTM)
EXPORT_SYMBOL_GPL(native_write_cr4);
#endif

void cr4_update_irqsoff(unsigned long set, unsigned long clear)
{
	unsigned long newval, cr4 = this_cpu_read(cpu_tlbstate.cr4);

	lockdep_assert_irqs_disabled();

	newval = (cr4 & ~clear) | set;
	if (newval != cr4) {
		this_cpu_write(cpu_tlbstate.cr4, newval);
		__write_cr4(newval);
	}
}
EXPORT_SYMBOL(cr4_update_irqsoff);

/* Read the CR4 shadow. */
unsigned long cr4_read_shadow(void)
{
	return this_cpu_read(cpu_tlbstate.cr4);
}
EXPORT_SYMBOL_GPL(cr4_read_shadow);

void cr4_init(void)
{
	unsigned long cr4 = __read_cr4();

	if (boot_cpu_has(X86_FEATURE_PCID))
		cr4 |= X86_CR4_PCIDE;
	if (static_branch_likely(&cr_pinning))
		cr4 = (cr4 & ~cr4_pinned_mask) | cr4_pinned_bits;

	__write_cr4(cr4);

	/* Initialize cr4 shadow for this CPU. */
	this_cpu_write(cpu_tlbstate.cr4, cr4);
}

/*
 * Once CPU feature detection is finished (and boot params have been
 * parsed), record any of the sensitive CR bits that are set, and
 * enable CR pinning.
 */
static void __init setup_cr_pinning(void)
{
	cr4_pinned_bits = this_cpu_read(cpu_tlbstate.cr4) & cr4_pinned_mask;
	static_key_enable(&cr_pinning.key);
}

static __init int x86_nofsgsbase_setup(char *arg)
{
	/* Require an exact match without trailing characters. */
	if (strlen(arg))
		return 0;

	/* Do not emit a message if the feature is not present. */
	if (!boot_cpu_has(X86_FEATURE_FSGSBASE))
		return 1;

	setup_clear_cpu_cap(X86_FEATURE_FSGSBASE);
	pr_info("FSGSBASE disabled via kernel command line\n");
	return 1;
}
__setup("nofsgsbase", x86_nofsgsbase_setup);

/*
 * Protection Keys are not available in 32-bit mode.
 */
static bool pku_disabled;

static __always_inline void setup_pku(struct cpuinfo_x86 *c)
{
	if (c == &boot_cpu_data) {
		if (pku_disabled || !cpu_feature_enabled(X86_FEATURE_PKU))
			return;
		/*
		 * Setting CR4.PKE will cause the X86_FEATURE_OSPKE cpuid
		 * bit to be set.  Enforce it.
		 */
		setup_force_cpu_cap(X86_FEATURE_OSPKE);

	} else if (!cpu_feature_enabled(X86_FEATURE_OSPKE)) {
		return;
	}

	cr4_set_bits(X86_CR4_PKE);
	/* Load the default PKRU value */
	pkru_write_default();
}

#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
static __init int setup_disable_pku(char *arg)
{
	/*
	 * Do not clear the X86_FEATURE_PKU bit.  All of the
	 * runtime checks are against OSPKE so clearing the
	 * bit does nothing.
	 *
	 * This way, we will see "pku" in cpuinfo, but not
	 * "ospke", which is exactly what we want.  It shows
	 * that the CPU has PKU, but the OS has not enabled it.
	 * This happens to be exactly how a system would look
	 * if we disabled the config option.
	 */
	pr_info("x86: 'nopku' specified, disabling Memory Protection Keys\n");
	pku_disabled = true;
	return 1;
}
__setup("nopku", setup_disable_pku);
#endif

#ifdef CONFIG_X86_KERNEL_IBT

__noendbr u64 ibt_save(bool disable)
{
	u64 msr = 0;

	if (cpu_feature_enabled(X86_FEATURE_IBT)) {
		rdmsrq(MSR_IA32_S_CET, msr);
		if (disable)
			wrmsrq(MSR_IA32_S_CET, msr & ~CET_ENDBR_EN);
	}

	return msr;
}

__noendbr void ibt_restore(u64 save)
{
	u64 msr;

	if (cpu_feature_enabled(X86_FEATURE_IBT)) {
		rdmsrq(MSR_IA32_S_CET, msr);
		msr &= ~CET_ENDBR_EN;
		msr |= (save & CET_ENDBR_EN);
		wrmsrq(MSR_IA32_S_CET, msr);
	}
}

#endif

static __always_inline void setup_cet(struct cpuinfo_x86 *c)
{
	bool user_shstk, kernel_ibt;

	if (!IS_ENABLED(CONFIG_X86_CET))
		return;

	kernel_ibt = HAS_KERNEL_IBT && cpu_feature_enabled(X86_FEATURE_IBT);
	user_shstk = cpu_feature_enabled(X86_FEATURE_SHSTK) &&
		     IS_ENABLED(CONFIG_X86_USER_SHADOW_STACK);

	if (!kernel_ibt && !user_shstk)
		return;

	if (user_shstk)
		set_cpu_cap(c, X86_FEATURE_USER_SHSTK);

	if (kernel_ibt)
		wrmsrq(MSR_IA32_S_CET, CET_ENDBR_EN);
	else
		wrmsrq(MSR_IA32_S_CET, 0);

	cr4_set_bits(X86_CR4_CET);

	if (kernel_ibt && ibt_selftest()) {
		pr_err("IBT selftest: Failed!\n");
		wrmsrq(MSR_IA32_S_CET, 0);
		setup_clear_cpu_cap(X86_FEATURE_IBT);
	}
}

__noendbr void cet_disable(void)
{
	if (!(cpu_feature_enabled(X86_FEATURE_IBT) ||
	      cpu_feature_enabled(X86_FEATURE_SHSTK)))
		return;

	wrmsrq(MSR_IA32_S_CET, 0);
	wrmsrq(MSR_IA32_U_CET, 0);
}

/* filter_cpuid_features() lives in common_rs.rs (global, hidden); identify_cpu() calls it */
void filter_cpuid_features(struct cpuinfo_x86 *c, bool warn);
void apply_forced_caps(struct cpuinfo_x86 *c);
#line 680 "arch/x86/kernel/cpu/common.c"

/*
 * Naming convention should be: <Name> [(<Codename>)]
 * This table only is used unless init_<vendor>() below doesn't set it;
 * in particular, if CPUID levels 0x80000002..4 are supported, this
 * isn't used
 */

/* Look up CPU names by table lookup. */
static const char *table_lookup_model(struct cpuinfo_x86 *c)
{
#ifdef CONFIG_X86_32
	const struct legacy_cpu_model_info *info;

	if (c->x86_model >= 16)
		return NULL;	/* Range check */

	if (!this_cpu)
		return NULL;

	info = this_cpu->legacy_models;

	while (info->family) {
		if (info->family == c->x86)
			return info->model_names[c->x86_model];
		info++;
	}
#endif
	return NULL;		/* Not found */
}

/* Aligned to unsigned long to avoid split lock in atomic bitmap ops */
__u32 cpu_caps_cleared[NCAPINTS + NBUGINTS] __aligned(sizeof(unsigned long));
__u32 cpu_caps_set[NCAPINTS + NBUGINTS] __aligned(sizeof(unsigned long));

#ifdef CONFIG_X86_32
/* The 32-bit entry code needs to find cpu_entry_area. */
DEFINE_PER_CPU(struct cpu_entry_area *, cpu_entry_area);
#endif

/* Load the original GDT from the per-cpu structure */
void load_direct_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_rw(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}
EXPORT_SYMBOL_GPL(load_direct_gdt);

/* Load a fixmap remapping of the per-cpu GDT */
void load_fixmap_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_ro(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}
EXPORT_SYMBOL_GPL(load_fixmap_gdt);

/**
 * switch_gdt_and_percpu_base - Switch to direct GDT and runtime per CPU base
 * @cpu:	The CPU number for which this is invoked
 *
 * Invoked during early boot to switch from early GDT and early per CPU to
 * the direct GDT and the runtime per CPU area. On 32-bit the percpu base
 * switch is implicit by loading the direct GDT. On 64bit this requires
 * to update GSBASE.
 */
void __init switch_gdt_and_percpu_base(int cpu)
{
	load_direct_gdt(cpu);

#ifdef CONFIG_X86_64
	/*
	 * No need to load %gs. It is already correct.
	 *
	 * Writing %gs on 64bit would zero GSBASE which would make any per
	 * CPU operation up to the point of the wrmsrq() fault.
	 *
	 * Set GSBASE to the new offset. Until the wrmsrq() happens the
	 * early mapping is still valid. That means the GSBASE update will
	 * lose any prior per CPU data which was not copied over in
	 * setup_per_cpu_areas().
	 *
	 * This works even with stackprotector enabled because the
	 * per CPU stack canary is 0 in both per CPU areas.
	 */
	wrmsrq(MSR_GS_BASE, cpu_kernelmode_gs_base(cpu));
#else
	/*
	 * %fs is already set to __KERNEL_PERCPU, but after switching GDT
	 * it is required to load FS again so that the 'hidden' part is
	 * updated from the new GDT. Up to this point the early per CPU
	 * translation is active. Any content of the early per CPU data
	 * which was not copied over in setup_per_cpu_areas() is lost.
	 */
	loadsegment(fs, __KERNEL_PERCPU);
#endif
}

const struct cpu_dev *cpu_devs[X86_VENDOR_NUM] __attribute__((visibility("hidden"))) = {};

static void get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;
	char *p, *q, *s;

	if (c->extended_cpuid_level < 0x80000004)
		return;

	v = (unsigned int *)c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;

	/* Trim whitespace */
	p = q = s = &c->x86_model_id[0];

	while (*p == ' ')
		p++;

	while (*p) {
		/* Note the last non-whitespace index */
		if (!isspace(*p))
			s = q;

		*q++ = *p++;
	}

	*(s + 1) = '\0';
}

void cpu_detect_cache_sizes(struct cpuinfo_x86 *c)
{
	unsigned int n, dummy, ebx, ecx, edx, l2size;

	n = c->extended_cpuid_level;

	if (n >= 0x80000005) {
		cpuid(0x80000005, &dummy, &ebx, &ecx, &edx);
		c->x86_cache_size = (ecx>>24) + (edx>>24);
#ifdef CONFIG_X86_64
		/* On K8 L1 TLB is inclusive, so don't count it */
		c->x86_tlbsize = 0;
#endif
	}

	if (n < 0x80000006)	/* Some chips just has a large L1. */
		return;

	cpuid(0x80000006, &dummy, &ebx, &ecx, &edx);
	l2size = ecx >> 16;

#ifdef CONFIG_X86_64
	c->x86_tlbsize += ((ebx >> 16) & 0xfff) + (ebx & 0xfff);
#else
	/* do processor-specific cache resizing */
	if (this_cpu->legacy_cache_size)
		l2size = this_cpu->legacy_cache_size(c, l2size);

	/* Allow user to override all this if necessary. */
	if (cachesize_override != -1)
		l2size = cachesize_override;

	if (l2size == 0)
		return;		/* Again, no L2 cache is possible */
#endif

	c->x86_cache_size = l2size;
}

u16 __read_mostly tlb_lli_4k;
u16 __read_mostly tlb_lli_2m;
u16 __read_mostly tlb_lli_4m;
u16 __read_mostly tlb_lld_4k;
u16 __read_mostly tlb_lld_2m;
u16 __read_mostly tlb_lld_4m;
u16 __read_mostly tlb_lld_1g;

static void cpu_detect_tlb(struct cpuinfo_x86 *c)
{
	if (this_cpu->c_detect_tlb)
		this_cpu->c_detect_tlb(c);

	pr_info("Last level iTLB entries: 4KB %d, 2MB %d, 4MB %d\n",
		tlb_lli_4k, tlb_lli_2m, tlb_lli_4m);

	pr_info("Last level dTLB entries: 4KB %d, 2MB %d, 4MB %d, 1GB %d\n",
		tlb_lld_4k, tlb_lld_2m, tlb_lld_4m, tlb_lld_1g);
}

/* get_cpu_vendor(), cpu_detect(), apply_forced_caps(), init_speculation_control(), get_cpu_cap(), get_cpu_address_sizes() live in common_rs.rs */
#line 1093 "arch/x86/kernel/cpu/common.c"

static void identify_cpu_without_cpuid(struct cpuinfo_x86 *c)
{
	int i;

	/*
	 * First of all, decide if this is a 486 or higher
	 * It's a 486 if we can modify the AC flag
	 */
	if (flag_is_changeable_p(X86_EFLAGS_AC))
		c->x86 = 4;
	else
		c->x86 = 3;

	for (i = 0; i < X86_VENDOR_NUM; i++)
		if (cpu_devs[i] && cpu_devs[i]->c_identify) {
			c->x86_vendor_id[0] = 0;
			cpu_devs[i]->c_identify(c);
			if (c->x86_vendor_id[0]) {
				get_cpu_vendor(c);
				break;
			}
		}
}

#define NO_SPECULATION		BIT(0)
#define NO_MELTDOWN		BIT(1)
#define NO_SSB			BIT(2)
#define NO_L1TF			BIT(3)
#define NO_MDS			BIT(4)
#define MSBDS_ONLY		BIT(5)
#define NO_SWAPGS		BIT(6)
#define NO_ITLB_MULTIHIT	BIT(7)
#define NO_SPECTRE_V2		BIT(8)
#define NO_MMIO			BIT(9)
#define NO_EIBRS_PBRSB		BIT(10)
#define NO_BHI			BIT(11)

#define VULNWL(vendor, family, model, whitelist)	\
	X86_MATCH_VENDOR_FAM_MODEL(vendor, family, model, whitelist)

#define VULNWL_INTEL(vfm, whitelist)		\
	X86_MATCH_VFM(vfm, whitelist)

#define VULNWL_AMD(family, whitelist)		\
	VULNWL(AMD, family, X86_MODEL_ANY, whitelist)

#define VULNWL_HYGON(family, whitelist)		\
	VULNWL(HYGON, family, X86_MODEL_ANY, whitelist)

const __initconst struct x86_cpu_id cpu_vuln_whitelist[] __attribute__((visibility("hidden"))) = {
	VULNWL(ANY,	4, X86_MODEL_ANY,	NO_SPECULATION),
	VULNWL(CENTAUR,	5, X86_MODEL_ANY,	NO_SPECULATION),
	VULNWL(INTEL,	5, X86_MODEL_ANY,	NO_SPECULATION),
	VULNWL(NSC,	5, X86_MODEL_ANY,	NO_SPECULATION),
	VULNWL(VORTEX,	5, X86_MODEL_ANY,	NO_SPECULATION),
	VULNWL(VORTEX,	6, X86_MODEL_ANY,	NO_SPECULATION),

	/* Intel Family 6 */
	VULNWL_INTEL(INTEL_TIGERLAKE,		NO_MMIO),
	VULNWL_INTEL(INTEL_TIGERLAKE_L,		NO_MMIO),
	VULNWL_INTEL(INTEL_ALDERLAKE,		NO_MMIO),
	VULNWL_INTEL(INTEL_ALDERLAKE_L,		NO_MMIO),

	VULNWL_INTEL(INTEL_ATOM_SALTWELL,	NO_SPECULATION | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_SALTWELL_TABLET, NO_SPECULATION | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_SALTWELL_MID,	NO_SPECULATION | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_BONNELL,	NO_SPECULATION | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_BONNELL_MID,	NO_SPECULATION | NO_ITLB_MULTIHIT),

	VULNWL_INTEL(INTEL_ATOM_SILVERMONT,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_SILVERMONT_D,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_SILVERMONT_MID,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_ATOM_AIRMONT,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_XEON_PHI_KNL,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),
	VULNWL_INTEL(INTEL_XEON_PHI_KNM,	NO_SSB | NO_L1TF | MSBDS_ONLY | NO_SWAPGS | NO_ITLB_MULTIHIT),

	VULNWL_INTEL(INTEL_CORE_YONAH,		NO_SSB),

	VULNWL_INTEL(INTEL_ATOM_SILVERMONT_MID2,NO_SSB | NO_L1TF | NO_SWAPGS | NO_ITLB_MULTIHIT | MSBDS_ONLY),
	VULNWL_INTEL(INTEL_ATOM_AIRMONT_NP,	NO_SSB | NO_L1TF | NO_SWAPGS | NO_ITLB_MULTIHIT),

	VULNWL_INTEL(INTEL_ATOM_GOLDMONT,	NO_MDS | NO_L1TF | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO),
	VULNWL_INTEL(INTEL_ATOM_GOLDMONT_D,	NO_MDS | NO_L1TF | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO),
	VULNWL_INTEL(INTEL_ATOM_GOLDMONT_PLUS,	NO_MDS | NO_L1TF | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_EIBRS_PBRSB),

	/*
	 * Technically, swapgs isn't serializing on AMD (despite it previously
	 * being documented as such in the APM).  But according to AMD, %gs is
	 * updated non-speculatively, and the issuing of %gs-relative memory
	 * operands will be blocked until the %gs update completes, which is
	 * good enough for our purposes.
	 */

	VULNWL_INTEL(INTEL_ATOM_TREMONT,	NO_EIBRS_PBRSB),
	VULNWL_INTEL(INTEL_ATOM_TREMONT_L,	NO_EIBRS_PBRSB),
	VULNWL_INTEL(INTEL_ATOM_TREMONT_D,	NO_ITLB_MULTIHIT | NO_EIBRS_PBRSB),

	/* AMD Family 0xf - 0x12 */
	VULNWL_AMD(0x0f,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_BHI),
	VULNWL_AMD(0x10,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_BHI),
	VULNWL_AMD(0x11,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_BHI),
	VULNWL_AMD(0x12,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_BHI),

	/* FAMILY_ANY must be last, otherwise 0x0f - 0x12 matches won't work */
	VULNWL_AMD(X86_FAMILY_ANY,	NO_MELTDOWN | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_EIBRS_PBRSB | NO_BHI),
	VULNWL_HYGON(X86_FAMILY_ANY,	NO_MELTDOWN | NO_L1TF | NO_MDS | NO_SWAPGS | NO_ITLB_MULTIHIT | NO_MMIO | NO_EIBRS_PBRSB | NO_BHI),

	/* Zhaoxin Family 7 */
	VULNWL(CENTAUR,	7, X86_MODEL_ANY,	NO_SPECTRE_V2 | NO_SWAPGS | NO_MMIO | NO_BHI),
	VULNWL(ZHAOXIN,	7, X86_MODEL_ANY,	NO_SPECTRE_V2 | NO_SWAPGS | NO_MMIO | NO_BHI),
	{}
};

#define VULNBL(vendor, family, model, blacklist)	\
	X86_MATCH_VENDOR_FAM_MODEL(vendor, family, model, blacklist)

#define VULNBL_INTEL_STEPS(vfm, max_stepping, issues)		   \
	X86_MATCH_VFM_STEPS(vfm, X86_STEP_MIN, max_stepping, issues)

#define VULNBL_INTEL_TYPE(vfm, cpu_type, issues)	\
	X86_MATCH_VFM_CPU_TYPE(vfm, INTEL_CPU_TYPE_##cpu_type, issues)

#define VULNBL_AMD(family, blacklist)		\
	VULNBL(AMD, family, X86_MODEL_ANY, blacklist)

#define VULNBL_HYGON(family, blacklist)		\
	VULNBL(HYGON, family, X86_MODEL_ANY, blacklist)

#define SRBDS		BIT(0)
/* CPU is affected by X86_BUG_MMIO_STALE_DATA */
#define MMIO		BIT(1)
/* CPU is affected by Shared Buffers Data Sampling (SBDS), a variant of X86_BUG_MMIO_STALE_DATA */
#define MMIO_SBDS	BIT(2)
/* CPU is affected by RETbleed, speculating where you would not expect it */
#define RETBLEED	BIT(3)
/* CPU is affected by SMT (cross-thread) return predictions */
#define SMT_RSB		BIT(4)
/* CPU is affected by SRSO */
#define SRSO		BIT(5)
/* CPU is affected by GDS */
#define GDS		BIT(6)
/* CPU is affected by Register File Data Sampling */
#define RFDS		BIT(7)
/* CPU is affected by Indirect Target Selection */
#define ITS		BIT(8)
/* CPU is affected by Indirect Target Selection, but guest-host isolation is not affected */
#define ITS_NATIVE_ONLY	BIT(9)
/* CPU is affected by Transient Scheduler Attacks */
#define TSA		BIT(10)
/* CPU is affected by VMSCAPE */
#define VMSCAPE		BIT(11)

const struct x86_cpu_id cpu_vuln_blacklist[] __attribute__((visibility("hidden"))) __initconst = {
	VULNBL_INTEL_STEPS(INTEL_SANDYBRIDGE_X,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SANDYBRIDGE,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_IVYBRIDGE_X,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_IVYBRIDGE,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_HASWELL,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_HASWELL_L,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_HASWELL_G,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_HASWELL_X,	     X86_STEP_MAX,	MMIO | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_BROADWELL_D,	     X86_STEP_MAX,	MMIO | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_BROADWELL_X,	     X86_STEP_MAX,	MMIO | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_BROADWELL_G,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_BROADWELL,	     X86_STEP_MAX,	SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SKYLAKE_X,		      0x5,	MMIO | RETBLEED | GDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SKYLAKE_X,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SKYLAKE_L,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SKYLAKE,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_KABYLAKE_L,		      0xb,	MMIO | RETBLEED | GDS | SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_KABYLAKE_L,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | SRBDS | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_KABYLAKE,		      0xc,	MMIO | RETBLEED | GDS | SRBDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_KABYLAKE,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | SRBDS | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_CANNONLAKE_L,	     X86_STEP_MAX,	RETBLEED | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ICELAKE_L,	     X86_STEP_MAX,	MMIO | MMIO_SBDS | RETBLEED | GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_STEPS(INTEL_ICELAKE_D,	     X86_STEP_MAX,	MMIO | GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_STEPS(INTEL_ICELAKE_X,	     X86_STEP_MAX,	MMIO | GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_STEPS(INTEL_COMETLAKE,	     X86_STEP_MAX,	MMIO | MMIO_SBDS | RETBLEED | GDS | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_COMETLAKE_L,		      0x0,	MMIO | RETBLEED | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_COMETLAKE_L,	     X86_STEP_MAX,	MMIO | MMIO_SBDS | RETBLEED | GDS | ITS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_TIGERLAKE_L,	     X86_STEP_MAX,	GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_STEPS(INTEL_TIGERLAKE,	     X86_STEP_MAX,	GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_STEPS(INTEL_LAKEFIELD,	     X86_STEP_MAX,	MMIO | MMIO_SBDS | RETBLEED),
	VULNBL_INTEL_STEPS(INTEL_ROCKETLAKE,	     X86_STEP_MAX,	MMIO | RETBLEED | GDS | ITS | ITS_NATIVE_ONLY),
	VULNBL_INTEL_TYPE(INTEL_ALDERLAKE,		     ATOM,	RFDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ALDERLAKE,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ALDERLAKE_L,	     X86_STEP_MAX,	RFDS | VMSCAPE),
	VULNBL_INTEL_TYPE(INTEL_RAPTORLAKE,		     ATOM,	RFDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_RAPTORLAKE,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_RAPTORLAKE_P,	     X86_STEP_MAX,	RFDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_RAPTORLAKE_S,	     X86_STEP_MAX,	RFDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_METEORLAKE_L,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ARROWLAKE_H,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ARROWLAKE,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ARROWLAKE_U,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_LUNARLAKE_M,	     X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_SAPPHIRERAPIDS_X,   X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_GRANITERAPIDS_X,    X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_EMERALDRAPIDS_X,    X86_STEP_MAX,	VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ATOM_GRACEMONT,     X86_STEP_MAX,	RFDS | VMSCAPE),
	VULNBL_INTEL_STEPS(INTEL_ATOM_TREMONT,	     X86_STEP_MAX,	MMIO | MMIO_SBDS | RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_TREMONT_D,     X86_STEP_MAX,	MMIO | RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_TREMONT_L,     X86_STEP_MAX,	MMIO | MMIO_SBDS | RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_GOLDMONT,      X86_STEP_MAX,	RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_GOLDMONT_D,    X86_STEP_MAX,	RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_GOLDMONT_PLUS, X86_STEP_MAX,	RFDS),
	VULNBL_INTEL_STEPS(INTEL_ATOM_CRESTMONT_X,   X86_STEP_MAX,	VMSCAPE),

	VULNBL_AMD(0x15, RETBLEED),
	VULNBL_AMD(0x16, RETBLEED),
	VULNBL_AMD(0x17, RETBLEED | SMT_RSB | SRSO | VMSCAPE),
	VULNBL_HYGON(0x18, RETBLEED | SMT_RSB | SRSO | VMSCAPE),
	VULNBL_AMD(0x19, SRSO | TSA | VMSCAPE),
	VULNBL_AMD(0x1a, SRSO | VMSCAPE),
	{}
};

/* cpu_matches() lives in common_rs.rs */
#line 1317 "arch/x86/kernel/cpu/common.c"

u64 x86_read_arch_cap_msr(void)
{
	u64 x86_arch_cap_msr = 0;

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrq(MSR_IA32_ARCH_CAPABILITIES, x86_arch_cap_msr);

	return x86_arch_cap_msr;
}

/* arch_cap_mmio_immune(), vulnerable_to_rfds(), vulnerable_to_its() live in common_rs.rs */
#line 1378 "arch/x86/kernel/cpu/common.c"

struct x86_cpu_id cpu_latest_microcode[] __attribute__((visibility("hidden"))) = {
#include "microcode/intel-ucode-defs.h"
	{}
};

/* cpu_has_old_microcode() and cpu_set_bug_bits() live in common_rs.rs */
#line 1588 "arch/x86/kernel/cpu/common.c"

/* detect_nopl(), parse_set_clear_cpuid(), cpu_parse_early_param(), early_identify_cpu(), init_cpu_devs(), early_cpu_init() live in common_rs.rs */
#line 1856 "arch/x86/kernel/cpu/common.c"

static bool detect_null_seg_behavior(void)
{
	/*
	 * Empirically, writing zero to a segment selector on AMD does
	 * not clear the base, whereas writing zero to a segment
	 * selector on Intel does clear the base.  Intel's behavior
	 * allows slightly faster context switches in the common case
	 * where GS is unused by the prev and next threads.
	 *
	 * Since neither vendor documents this anywhere that I can see,
	 * detect it directly instead of hard-coding the choice by
	 * vendor.
	 *
	 * I've designated AMD's behavior as the "bug" because it's
	 * counterintuitive and less friendly.
	 */

	unsigned long old_base, tmp;
	rdmsrq(MSR_FS_BASE, old_base);
	wrmsrq(MSR_FS_BASE, 1);
	loadsegment(fs, 0);
	rdmsrq(MSR_FS_BASE, tmp);
	wrmsrq(MSR_FS_BASE, old_base);
	return tmp == 0;
}

void check_null_seg_clears_base(struct cpuinfo_x86 *c)
{
	/* BUG_NULL_SEG is only relevant with 64bit userspace */
	if (!IS_ENABLED(CONFIG_X86_64))
		return;

	if (cpu_has(c, X86_FEATURE_NULL_SEL_CLR_BASE))
		return;

	/*
	 * CPUID bit above wasn't set. If this kernel is still running
	 * as a HV guest, then the HV has decided not to advertize
	 * that CPUID bit for whatever reason.	For example, one
	 * member of the migration pool might be vulnerable.  Which
	 * means, the bug is present: set the BUG flag and return.
	 */
	if (cpu_has(c, X86_FEATURE_HYPERVISOR)) {
		set_cpu_bug(c, X86_BUG_NULL_SEG);
		return;
	}

	/*
	 * Zen2 CPUs also have this behaviour, but no CPUID bit.
	 * 0x18 is the respective family for Hygon.
	 */
	if ((c->x86 == 0x17 || c->x86 == 0x18) &&
	    detect_null_seg_behavior())
		return;

	/* All the remaining ones are affected */
	set_cpu_bug(c, X86_BUG_NULL_SEG);
}

static void generic_identify(struct cpuinfo_x86 *c)
{
	c->extended_cpuid_level = 0;

	if (!cpuid_feature())
		identify_cpu_without_cpuid(c);

	/* cyrix could have cpuid enabled via c_identify()*/
	if (!cpuid_feature())
		return;

	cpu_detect(c);

	get_cpu_vendor(c);
	intel_unlock_cpuid_leafs(c);
	get_cpu_cap(c);

	get_cpu_address_sizes(c);

	get_model_name(c); /* Default name */

	/*
	 * ESPFIX is a strange bug.  All real CPUs have it.  Paravirt
	 * systems that run Linux at CPL > 0 may or may not have the
	 * issue, but, even if they have the issue, there's absolutely
	 * nothing we can do about it because we can't use the real IRET
	 * instruction.
	 *
	 * NB: For the time being, only 32-bit kernels support
	 * X86_BUG_ESPFIX as such.  64-bit kernels directly choose
	 * whether to apply espfix using paravirt hooks.  If any
	 * non-paravirt system ever shows up that does *not* have the
	 * ESPFIX issue, we can change this.
	 */
#ifdef CONFIG_X86_32
	set_cpu_bug(c, X86_BUG_ESPFIX);
#endif
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
static void identify_cpu(struct cpuinfo_x86 *c)
{
	int i;

	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = 0;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_stepping = 0;	/* So far unknown... */
	c->x86_vendor_id[0] = '\0'; /* Unset */
	c->x86_model_id[0] = '\0';  /* Unset */
#ifdef CONFIG_X86_64
	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;
#else
	c->cpuid_level = -1;	/* CPUID not detected */
	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;
#endif
	c->x86_cache_alignment = c->x86_clflush_size;
	memset(&c->x86_capability, 0, sizeof(c->x86_capability));
#ifdef CONFIG_X86_VMX_FEATURE_NAMES
	memset(&c->vmx_capability, 0, sizeof(c->vmx_capability));
#endif

	generic_identify(c);

	cpu_parse_topology(c);

	if (this_cpu->c_identify)
		this_cpu->c_identify(c);

	/* Clear/Set all flags overridden by options, after probe */
	apply_forced_caps(c);

	/*
	 * Set default APIC and TSC_DEADLINE MSR fencing flag. AMD and
	 * Hygon will clear it in ->c_init() below.
	 */
	set_cpu_cap(c, X86_FEATURE_APIC_MSRS_FENCE);

	/*
	 * Vendor-specific initialization.  In this section we
	 * canonicalize the feature flags, meaning if there are
	 * features a certain CPU supports which CPUID doesn't
	 * tell us, CPUID claiming incorrect flags, or other bugs,
	 * we handle them here.
	 *
	 * At the end of this section, c->x86_capability better
	 * indicate the features this CPU genuinely supports!
	 */
	if (this_cpu->c_init)
		this_cpu->c_init(c);

	bus_lock_init();

	/* Disable the PN if appropriate */
	squash_the_stupid_serial_number(c);

	/* Set up SMEP/SMAP/UMIP */
	setup_smep(c);
	setup_smap(c);
	setup_umip(c);

	/*
	 * The vendor-specific functions might have changed features.
	 * Now we do "generic changes."
	 */

	/* Filter out anything that depends on CPUID levels we don't have */
	filter_cpuid_features(c, true);

	/* Check for unmet dependencies based on the CPUID dependency table */
	check_cpufeature_deps(c);

	/* If the model name is still unset, do table lookup. */
	if (!c->x86_model_id[0]) {
		const char *p;
		p = table_lookup_model(c);
		if (p)
			strcpy(c->x86_model_id, p);
		else
			/* Last resort... */
			sprintf(c->x86_model_id, "%02x/%02x",
				c->x86, c->x86_model);
	}

	x86_init_rdrand(c);
	setup_pku(c);
	setup_cet(c);

	/*
	 * Clear/Set all flags overridden by options, need do it
	 * before following smp all cpus cap AND.
	 */
	apply_forced_caps(c);

	/*
	 * On SMP, boot_cpu_data holds the common feature set between
	 * all CPUs; so make sure that we indicate which features are
	 * common between the CPUs.  The first time this routine gets
	 * executed, c == &boot_cpu_data.
	 */
	if (c != &boot_cpu_data) {
		/* AND the already accumulated flags with these */
		for (i = 0; i < NCAPINTS; i++)
			boot_cpu_data.x86_capability[i] &= c->x86_capability[i];

		/* OR, i.e. replicate the bug flags */
		for (i = NCAPINTS; i < NCAPINTS + NBUGINTS; i++)
			c->x86_capability[i] |= boot_cpu_data.x86_capability[i];
	}

	ppin_init(c);

	/* Init Machine Check Exception if available. */
	mcheck_cpu_init(c);

	numa_add_cpu(smp_processor_id());
}

/*
 * Set up the CPU state needed to execute SYSENTER/SYSEXIT instructions
 * on 32-bit kernels:
 */
#ifdef CONFIG_X86_32
void enable_sep_cpu(void)
{
	struct tss_struct *tss;
	int cpu;

	if (!boot_cpu_has(X86_FEATURE_SEP))
		return;

	cpu = get_cpu();
	tss = &per_cpu(cpu_tss_rw, cpu);

	/*
	 * We cache MSR_IA32_SYSENTER_CS's value in the TSS's ss1 field --
	 * see the big comment in struct x86_hw_tss's definition.
	 */

	tss->x86_tss.ss1 = __KERNEL_CS;
	wrmsrq(MSR_IA32_SYSENTER_CS, tss->x86_tss.ss1);
	wrmsrq(MSR_IA32_SYSENTER_ESP, (unsigned long)(cpu_entry_stack(cpu) + 1));
	wrmsrq(MSR_IA32_SYSENTER_EIP, (unsigned long)entry_SYSENTER_32);

	put_cpu();
}
#endif

static __init void identify_boot_cpu(void)
{
	identify_cpu(&boot_cpu_data);
	if (HAS_KERNEL_IBT && cpu_feature_enabled(X86_FEATURE_IBT))
		pr_info("CET detected: Indirect Branch Tracking enabled\n");
#ifdef CONFIG_X86_32
	enable_sep_cpu();
#endif
	cpu_detect_tlb(&boot_cpu_data);
	setup_cr_pinning();

	tsx_init();
	tdx_init();
	lkgs_init();
}

void identify_secondary_cpu(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	/* Copy boot_cpu_data only on the first bringup */
	if (!c->initialized)
		*c = boot_cpu_data;
	c->cpu_index = cpu;

	identify_cpu(c);
#ifdef CONFIG_X86_32
	enable_sep_cpu();
#endif
	x86_spec_ctrl_setup_ap();
	update_srbds_msr();
	if (boot_cpu_has_bug(X86_BUG_GDS))
		update_gds_msr();

	tsx_ap_init();
	c->initialized = true;
}

void print_cpu_info(struct cpuinfo_x86 *c)
{
	const char *vendor = NULL;

	if (c->x86_vendor < X86_VENDOR_NUM) {
		vendor = this_cpu->c_vendor;
	} else {
		if (c->cpuid_level >= 0)
			vendor = c->x86_vendor_id;
	}

	if (vendor && !strstr(c->x86_model_id, vendor))
		pr_cont("%s ", vendor);

	if (c->x86_model_id[0])
		pr_cont("%s", c->x86_model_id);
	else
		pr_cont("%d86", c->x86);

	pr_cont(" (family: 0x%x, model: 0x%x", c->x86, c->x86_model);

	if (c->x86_stepping || c->cpuid_level >= 0)
		pr_cont(", stepping: 0x%x)\n", c->x86_stepping);
	else
		pr_cont(")\n");
}

/*
 * clearcpuid= and setcpuid= were already parsed in cpu_parse_early_param().
 * These dummy functions prevent them from becoming an environment variable for
 * init.
 */

static __init int setup_clearcpuid(char *arg)
{
	return 1;
}
__setup("clearcpuid=", setup_clearcpuid);

static __init int setup_setcpuid(char *arg)
{
	return 1;
}
__setup("setcpuid=", setup_setcpuid);

DEFINE_PER_CPU_CACHE_HOT(struct task_struct *, current_task) = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);
EXPORT_PER_CPU_SYMBOL(const_current_task);

DEFINE_PER_CPU_CACHE_HOT(int, __preempt_count) = INIT_PREEMPT_COUNT;
EXPORT_PER_CPU_SYMBOL(__preempt_count);

DEFINE_PER_CPU_CACHE_HOT(unsigned long, cpu_current_top_of_stack) = TOP_OF_INIT_STACK;

#ifdef CONFIG_X86_64
/*
 * Note: Do not make this dependant on CONFIG_MITIGATION_CALL_DEPTH_TRACKING
 * so that this space is reserved in the hot cache section even when the
 * mitigation is disabled.
 */
DEFINE_PER_CPU_CACHE_HOT(u64, __x86_call_depth);
EXPORT_PER_CPU_SYMBOL(__x86_call_depth);

static void wrmsrq_cstar(unsigned long val)
{
	/*
	 * Intel CPUs do not support 32-bit SYSCALL. Writing to MSR_CSTAR
	 * is so far ignored by the CPU, but raises a #VE trap in a TDX
	 * guest. Avoid the pointless write on all Intel CPUs.
	 */
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		wrmsrq(MSR_CSTAR, val);
}

static inline void idt_syscall_init(void)
{
	wrmsrq(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);

	if (ia32_enabled()) {
		wrmsrq_cstar((unsigned long)entry_SYSCALL_compat);
		/*
		 * This only works on Intel CPUs.
		 * On AMD CPUs these MSRs are 32-bit, CPU truncates MSR_IA32_SYSENTER_EIP.
		 * This does not cause SYSENTER to jump to the wrong location, because
		 * AMD doesn't allow SYSENTER in long mode (either 32- or 64-bit).
		 */
		wrmsrq_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
		wrmsrq_safe(MSR_IA32_SYSENTER_ESP,
			    (unsigned long)(cpu_entry_stack(smp_processor_id()) + 1));
		wrmsrq_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);
	} else {
		wrmsrq_cstar((unsigned long)entry_SYSCALL32_ignore);
		wrmsrq_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
		wrmsrq_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
		wrmsrq_safe(MSR_IA32_SYSENTER_EIP, 0ULL);
	}

	/*
	 * Flags to clear on syscall; clear as much as possible
	 * to minimize user space-kernel interference.
	 */
	wrmsrq(MSR_SYSCALL_MASK,
	       X86_EFLAGS_CF|X86_EFLAGS_PF|X86_EFLAGS_AF|
	       X86_EFLAGS_ZF|X86_EFLAGS_SF|X86_EFLAGS_TF|
	       X86_EFLAGS_IF|X86_EFLAGS_DF|X86_EFLAGS_OF|
	       X86_EFLAGS_IOPL|X86_EFLAGS_NT|X86_EFLAGS_RF|
	       X86_EFLAGS_AC|X86_EFLAGS_ID);
}

/* May not be marked __init: used by software suspend */
void syscall_init(void)
{
	/* The default user and kernel segments */
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);

	/*
	 * Except the IA32_STAR MSR, there is NO need to setup SYSCALL and
	 * SYSENTER MSRs for FRED, because FRED uses the ring 3 FRED
	 * entrypoint for SYSCALL and SYSENTER, and ERETU is the only legit
	 * instruction to return to ring 3 (both sysexit and sysret cause
	 * #UD when FRED is enabled).
	 */
	if (!cpu_feature_enabled(X86_FEATURE_FRED))
		idt_syscall_init();
}
#endif /* CONFIG_X86_64 */

#ifdef CONFIG_STACKPROTECTOR
DEFINE_PER_CPU_CACHE_HOT(unsigned long, __stack_chk_guard);
#ifndef CONFIG_SMP
EXPORT_PER_CPU_SYMBOL(__stack_chk_guard);
#endif
#endif

static void initialize_debug_regs(void)
{
	/* Control register first -- to make sure everything is disabled. */
	set_debugreg(DR7_FIXED_1, 7);
	set_debugreg(DR6_RESERVED, 6);
	/* dr5 and dr4 don't exist */
	set_debugreg(0, 3);
	set_debugreg(0, 2);
	set_debugreg(0, 1);
	set_debugreg(0, 0);
}

#ifdef CONFIG_KGDB
/*
 * Restore debug regs if using kgdbwait and you have a kernel debugger
 * connection established.
 */
static void dbg_restore_debug_regs(void)
{
	if (unlikely(kgdb_connected && arch_kgdb_ops.correct_hw_break))
		arch_kgdb_ops.correct_hw_break();
}
#else /* ! CONFIG_KGDB */
#define dbg_restore_debug_regs()
#endif /* ! CONFIG_KGDB */

static inline void setup_getcpu(int cpu)
{
	unsigned long cpudata = vdso_encode_cpunode(cpu, early_cpu_to_node(cpu));
	struct desc_struct d = { };

	if (boot_cpu_has(X86_FEATURE_RDTSCP) || boot_cpu_has(X86_FEATURE_RDPID))
		wrmsrq(MSR_TSC_AUX, cpudata);

	/* Store CPU and node number in limit. */
	d.limit0 = cpudata;
	d.limit1 = cpudata >> 16;

	d.type = 5;		/* RO data, expand down, accessed */
	d.dpl = 3;		/* Visible to user code */
	d.s = 1;		/* Not a system segment */
	d.p = 1;		/* Present */
	d.d = 1;		/* 32-bit */

	write_gdt_entry(get_cpu_gdt_rw(cpu), GDT_ENTRY_CPUNODE, &d, DESCTYPE_S);
}

#ifdef CONFIG_X86_64
static inline void tss_setup_ist(struct tss_struct *tss)
{
	/* Set up the per-CPU TSS IST stacks */
	tss->x86_tss.ist[IST_INDEX_DF] = __this_cpu_ist_top_va(DF);
	tss->x86_tss.ist[IST_INDEX_NMI] = __this_cpu_ist_top_va(NMI);
	tss->x86_tss.ist[IST_INDEX_DB] = __this_cpu_ist_top_va(DB);
	tss->x86_tss.ist[IST_INDEX_MCE] = __this_cpu_ist_top_va(MCE);
	/* Only mapped when SEV-ES is active */
	tss->x86_tss.ist[IST_INDEX_VC] = __this_cpu_ist_top_va(VC);
}
#else /* CONFIG_X86_64 */
static inline void tss_setup_ist(struct tss_struct *tss) { }
#endif /* !CONFIG_X86_64 */

static inline void tss_setup_io_bitmap(struct tss_struct *tss)
{
	tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET_INVALID;

#ifdef CONFIG_X86_IOPL_IOPERM
	tss->io_bitmap.prev_max = 0;
	tss->io_bitmap.prev_sequence = 0;
	memset(tss->io_bitmap.bitmap, 0xff, sizeof(tss->io_bitmap.bitmap));
	/*
	 * Invalidate the extra array entry past the end of the all
	 * permission bitmap as required by the hardware.
	 */
	tss->io_bitmap.mapall[IO_BITMAP_LONGS] = ~0UL;
#endif
}

/*
 * Setup everything needed to handle exceptions from the IDT, including the IST
 * exceptions which use paranoid_entry().
 */
void cpu_init_exception_handling(bool boot_cpu)
{
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);
	int cpu = raw_smp_processor_id();

	/* paranoid_entry() gets the CPU number from the GDT */
	setup_getcpu(cpu);

	/* For IDT mode, IST vectors need to be set in TSS. */
	if (!cpu_feature_enabled(X86_FEATURE_FRED))
		tss_setup_ist(tss);
	tss_setup_io_bitmap(tss);
	set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);

	load_TR_desc();

	/* GHCB needs to be setup to handle #VC. */
	setup_ghcb();

	/*
	 * On CPUs with FSGSBASE support, paranoid_entry() uses
	 * ALTERNATIVE-patched RDGSBASE/WRGSBASE instructions. Secondary CPUs
	 * boot after alternatives are patched globally, so early exceptions
	 * execute patched code that depends on FSGSBASE. Enable the feature
	 * before any exceptions occur.
	 */
	if (cpu_feature_enabled(X86_FEATURE_FSGSBASE)) {
		cr4_set_bits(X86_CR4_FSGSBASE);
		elf_hwcap2 |= HWCAP2_FSGSBASE;
	}

	if (cpu_feature_enabled(X86_FEATURE_FRED)) {
		/* The boot CPU has enabled FRED during early boot */
		if (!boot_cpu)
			cpu_init_fred_exceptions();

		cpu_init_fred_rsps();
	} else {
		load_current_idt();
	}
}

void __init cpu_init_replace_early_idt(void)
{
	if (cpu_feature_enabled(X86_FEATURE_FRED))
		cpu_init_fred_exceptions();
	else
		idt_setup_early_pf();
}

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT.  We
 * reload it nevertheless, this function acts as a 'CPU state barrier',
 * nothing should get across.
 */
void cpu_init(void)
{
	struct task_struct *cur = current;
	int cpu = raw_smp_processor_id();

#ifdef CONFIG_NUMA
	if (this_cpu_read(numa_node) == 0 &&
	    early_cpu_to_node(cpu) != NUMA_NO_NODE)
		set_numa_node(early_cpu_to_node(cpu));
#endif
	pr_debug("Initializing CPU#%d\n", cpu);

	if (IS_ENABLED(CONFIG_X86_64) || cpu_feature_enabled(X86_FEATURE_VME) ||
	    boot_cpu_has(X86_FEATURE_TSC) || boot_cpu_has(X86_FEATURE_DE))
		cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	if (IS_ENABLED(CONFIG_X86_64)) {
		loadsegment(fs, 0);
		memset(cur->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);
		syscall_init();

		wrmsrq(MSR_FS_BASE, 0);
		wrmsrq(MSR_KERNEL_GS_BASE, 0);
		barrier();

		x2apic_setup();

		intel_posted_msi_init();
	}

	mmgrab(&init_mm);
	cur->active_mm = &init_mm;
	BUG_ON(cur->mm);
	initialize_tlbstate_and_flush();
	enter_lazy_tlb(&init_mm, cur);

	/*
	 * sp0 points to the entry trampoline stack regardless of what task
	 * is running.
	 */
	load_sp0((unsigned long)(cpu_entry_stack(cpu) + 1));

	load_mm_ldt(&init_mm);

	initialize_debug_regs();
	dbg_restore_debug_regs();

	doublefault_init_cpu_tss();

	if (is_uv_system())
		uv_cpu_init();

	load_fixmap_gdt(cpu);
}

#ifdef CONFIG_MICROCODE_LATE_LOADING
/**
 * store_cpu_caps() - Store a snapshot of CPU capabilities
 * @curr_info: Pointer where to store it
 *
 * Returns: None
 */
void store_cpu_caps(struct cpuinfo_x86 *curr_info)
{
	/* Reload CPUID max function as it might've changed. */
	curr_info->cpuid_level = cpuid_eax(0);

	/* Copy all capability leafs and pick up the synthetic ones. */
	memcpy(&curr_info->x86_capability, &boot_cpu_data.x86_capability,
	       sizeof(curr_info->x86_capability));

	/* Get the hardware CPUID leafs */
	get_cpu_cap(curr_info);
}

/**
 * microcode_check() - Check if any CPU capabilities changed after an update.
 * @prev_info:	CPU capabilities stored before an update.
 *
 * The microcode loader calls this upon late microcode load to recheck features,
 * only when microcode has been updated. Caller holds and CPU hotplug lock.
 *
 * Return: None
 */
void microcode_check(struct cpuinfo_x86 *prev_info)
{
	struct cpuinfo_x86 curr_info;

	perf_check_microcode();

	amd_check_microcode();

	store_cpu_caps(&curr_info);

	if (!memcmp(&prev_info->x86_capability, &curr_info.x86_capability,
		    sizeof(prev_info->x86_capability)))
		return;

	pr_warn("x86/CPU: CPU features have changed after loading microcode, but might not take effect.\n");
	pr_warn("x86/CPU: Please consider either early loading through initrd/built-in or a potential BIOS update.\n");
}
#endif

/*
 * Invoked from core CPU hotplug code after hotplug operations
 */
void arch_smt_update(void)
{
	/* Handle the speculative execution misfeatures */
	cpu_bugs_smt_update();
	/* Check whether IPI broadcasting can be enabled */
	apic_smt_update();
}

void __init arch_cpu_finalize_init(void)
{
	struct cpuinfo_x86 *c = this_cpu_ptr(&cpu_info);

	identify_boot_cpu();

	select_idle_routine();

	/*
	 * identify_boot_cpu() initialized SMT support information, let the
	 * core code know.
	 */
	cpu_smt_set_num_threads(__max_threads_per_core, __max_threads_per_core);

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

	cpu_select_mitigations();

	arch_smt_update();

	if (IS_ENABLED(CONFIG_X86_32)) {
		/*
		 * Check whether this is a real i386 which is not longer
		 * supported and fixup the utsname.
		 */
		if (boot_cpu_data.x86 < 4)
			panic("Kernel requires i486+ for 'invlpg' and other features");

		init_utsname()->machine[1] =
			'0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	}

	/*
	 * Must be before alternatives because it might set or clear
	 * feature bits.
	 */
	fpu__init_system();
	fpu__init_cpu();

	/*
	 * This needs to follow the FPU initializtion, since EFI depends on it.
	 */
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();

	/*
	 * Ensure that access to the per CPU representation has the initial
	 * boot CPU configuration.
	 */
	*c = boot_cpu_data;
	c->initialized = true;

	alternative_instructions();

	if (IS_ENABLED(CONFIG_X86_64)) {
		USER_PTR_MAX = TASK_SIZE_MAX;

		/*
		 * Enable this when LAM is gated on LASS support
		if (cpu_feature_enabled(X86_FEATURE_LAM))
			USER_PTR_MAX = (1ul << 63) - PAGE_SIZE;
		 */
		runtime_const_init(ptr, USER_PTR_MAX);

		/*
		 * Make sure the first 2MB area is not mapped by huge pages
		 * There are typically fixed size MTRRs in there and overlapping
		 * MTRRs into large pages causes slow downs.
		 *
		 * Right now we don't do that with gbpages because there seems
		 * very little benefit for that case.
		 */
		if (!direct_gbpages)
			set_memory_4k((unsigned long)__va(0), 1);
	} else {
		fpu__init_check_bugs();
	}

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed. It
	 * must be called after late_time_init() so that Hyper-V x86/x64
	 * hypercalls work when the SWIOTLB bounce buffers are decrypted.
	 */
	mem_encrypt_init();
}

/* Control TLB flushing methods */
static int __init tlbi_setup(char *str)
{
	if (!strcmp(str, "ipi"))
		setup_clear_cpu_cap(X86_FEATURE_INVLPGB);

	return 1;
}
__setup("tlbi=", tlbi_setup);


/* The WARN_ON(alternatives_patched) of setup_force_cpu_cap(), called by the Rust arm (common_rs.rs) when a feature is first forced after the alternatives were patched. */
#line 2636 "arch/x86/kernel/cpu/common.c"
void x86_force_cap_warn(void);
void x86_force_cap_warn(void)
{
	WARN_ON(alternatives_patched);
}
