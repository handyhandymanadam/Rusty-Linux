// SPDX-License-Identifier: GPL-2.0

//! Scattered CPUID feature bits -- the Rust behind `arch/x86/kernel/cpu/scattered.c`.
//!
//! Ported from `arch/x86/kernel/cpu/scattered.c` (6.18.49): `init_scattered_cpuid_features()`, called from `get_cpu_cap()` for
//! every CPU (boot CPU and each secondary CPU while it identifies itself) to set the `x86_capability` bits whose CPUID leaf is
//! not in the architecturally scattered words: for each row of `cpuid_bits[]` it checks the leaf is valid
//! (`cpuid_eax(level & 0xffff0000)` in `[level, level | 0xffff]`), executes `CPUID(level, sub_leaf)` and sets the feature if the
//! register's bit is set. The 36 rows, with their `X86_FEATURE_*` values, are the C table; every feature number carries a
//! `// C:` tag that `rig/phase-e/consts_check.py` compiles against the kernel's own headers.
//!
//! Like `common_rs.rs` (which calls this) `struct cpuinfo_x86` is not mirrored: its `x86_capability` array is at a fixed byte
//! offset (`CI_CAP`, checked the same way) and `set_cpu_cap()` is the atomic OR of one bit. No panic path, no allocation, no lock.
//! Not exported (no CRC). `CONFIG_PARAVIRT_XXL` (CPUID goes through paravirt ops) and `CONFIG_RANDSTRUCT` are refused.
//!
//! Replaces: arch/x86/kernel/cpu/scattered.c

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(CONFIG_PARAVIRT_XXL)]
compile_error!("scattered_rs.rs: cpuid() is paravirtualised under PARAVIRT_XXL; port that path first");
#[cfg(CONFIG_RANDSTRUCT)]
compile_error!("scattered_rs.rs: struct cpuinfo_x86 is __randomize_layout; the offset is fixed");
#[cfg(CONFIG_X86_32)]
compile_error!("scattered_rs.rs: x86-64 only");

// C-HEADERS: asm/cpufeatures.h asm/processor.h
/// `offsetof(struct cpuinfo_x86, x86_capability)` (the same value `common_rs.rs` uses).
const CI_CAP: usize = 48; // C: offsetof(struct cpuinfo_x86, x86_capability)
/// `enum cpuid_regs_idx`.
const CPUID_EAX: usize = 0; // C: CPUID_EAX
const CPUID_EBX: usize = 1; // C: CPUID_EBX
const CPUID_ECX: usize = 2; // C: CPUID_ECX
const CPUID_EDX: usize = 3; // C: CPUID_EDX
const X86_FEATURE_APERFMPERF: u16 = 124; // C: X86_FEATURE_APERFMPERF
const X86_FEATURE_EPB: u16 = 227; // C: X86_FEATURE_EPB
const X86_FEATURE_INTEL_PPIN: u16 = 238; // C: X86_FEATURE_INTEL_PPIN
const X86_FEATURE_MSR_IMM: u16 = 688; // C: X86_FEATURE_MSR_IMM
const X86_FEATURE_APX: u16 = 681; // C: X86_FEATURE_APX
const X86_FEATURE_RRSBA_CTRL: u16 = 363; // C: X86_FEATURE_RRSBA_CTRL
const X86_FEATURE_BHI_CTRL: u16 = 674; // C: X86_FEATURE_BHI_CTRL
const X86_FEATURE_CQM_LLC: u16 = 352; // C: X86_FEATURE_CQM_LLC
const X86_FEATURE_CQM_OCCUP_LLC: u16 = 353; // C: X86_FEATURE_CQM_OCCUP_LLC
const X86_FEATURE_CQM_MBM_TOTAL: u16 = 354; // C: X86_FEATURE_CQM_MBM_TOTAL
const X86_FEATURE_CQM_MBM_LOCAL: u16 = 355; // C: X86_FEATURE_CQM_MBM_LOCAL
const X86_FEATURE_CAT_L3: u16 = 228; // C: X86_FEATURE_CAT_L3
const X86_FEATURE_CAT_L2: u16 = 229; // C: X86_FEATURE_CAT_L2
const X86_FEATURE_CDP_L3: u16 = 230; // C: X86_FEATURE_CDP_L3
const X86_FEATURE_CDP_L2: u16 = 239; // C: X86_FEATURE_CDP_L2
const X86_FEATURE_MBA: u16 = 242; // C: X86_FEATURE_MBA
const X86_FEATURE_PER_THREAD_MBA: u16 = 359; // C: X86_FEATURE_PER_THREAD_MBA
const X86_FEATURE_SGX1: u16 = 360; // C: X86_FEATURE_SGX1
const X86_FEATURE_SGX2: u16 = 361; // C: X86_FEATURE_SGX2
const X86_FEATURE_SGX_EDECCSSA: u16 = 370; // C: X86_FEATURE_SGX_EDECCSSA
const X86_FEATURE_HW_PSTATE: u16 = 232; // C: X86_FEATURE_HW_PSTATE
const X86_FEATURE_CPB: u16 = 226; // C: X86_FEATURE_CPB
const X86_FEATURE_PROC_FEEDBACK: u16 = 233; // C: X86_FEATURE_PROC_FEEDBACK
const X86_FEATURE_AMD_FAST_CPPC: u16 = 677; // C: X86_FEATURE_AMD_FAST_CPPC
const X86_FEATURE_COHERENCY_SFW_NO: u16 = 260; // C: X86_FEATURE_COHERENCY_SFW_NO
const X86_FEATURE_SMBA: u16 = 373; // C: X86_FEATURE_SMBA
const X86_FEATURE_BMEC: u16 = 374; // C: X86_FEATURE_BMEC
const X86_FEATURE_ABMC: u16 = 687; // C: X86_FEATURE_ABMC
const X86_FEATURE_TSA_SQ_NO: u16 = 683; // C: X86_FEATURE_TSA_SQ_NO
const X86_FEATURE_TSA_L1_NO: u16 = 684; // C: X86_FEATURE_TSA_L1_NO
const X86_FEATURE_AMD_WORKLOAD_CLASS: u16 = 679; // C: X86_FEATURE_AMD_WORKLOAD_CLASS
const X86_FEATURE_PERFMON_V2: u16 = 244; // C: X86_FEATURE_PERFMON_V2
const X86_FEATURE_AMD_LBR_V2: u16 = 113; // C: X86_FEATURE_AMD_LBR_V2
const X86_FEATURE_AMD_LBR_PMC_FREEZE: u16 = 672; // C: X86_FEATURE_AMD_LBR_PMC_FREEZE
const X86_FEATURE_AMD_HTR_CORES: u16 = 678; // C: X86_FEATURE_AMD_HTR_CORES

/// `struct cpuid_bit`.
struct CpuidBit {
    feature: u16,
    reg: usize,
    bit: u8,
    level: u32,
    sub_leaf: u32,
}

/// `cpuid_bits[]` (without the all-zero terminator).
static CPUID_BITS: [CpuidBit; 36] = [
    CpuidBit { feature: X86_FEATURE_APERFMPERF, reg: CPUID_ECX, bit: 0, level: 0x00000006, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_EPB, reg: CPUID_ECX, bit: 3, level: 0x00000006, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_INTEL_PPIN, reg: CPUID_EBX, bit: 0, level: 0x00000007, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_MSR_IMM, reg: CPUID_ECX, bit: 5, level: 0x00000007, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_APX, reg: CPUID_EDX, bit: 21, level: 0x00000007, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_RRSBA_CTRL, reg: CPUID_EDX, bit: 2, level: 0x00000007, sub_leaf: 2 },
    CpuidBit { feature: X86_FEATURE_BHI_CTRL, reg: CPUID_EDX, bit: 4, level: 0x00000007, sub_leaf: 2 },
    CpuidBit { feature: X86_FEATURE_CQM_LLC, reg: CPUID_EDX, bit: 1, level: 0x0000000f, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_CQM_OCCUP_LLC, reg: CPUID_EDX, bit: 0, level: 0x0000000f, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_CQM_MBM_TOTAL, reg: CPUID_EDX, bit: 1, level: 0x0000000f, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_CQM_MBM_LOCAL, reg: CPUID_EDX, bit: 2, level: 0x0000000f, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_CAT_L3, reg: CPUID_EBX, bit: 1, level: 0x00000010, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_CAT_L2, reg: CPUID_EBX, bit: 2, level: 0x00000010, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_CDP_L3, reg: CPUID_ECX, bit: 2, level: 0x00000010, sub_leaf: 1 },
    CpuidBit { feature: X86_FEATURE_CDP_L2, reg: CPUID_ECX, bit: 2, level: 0x00000010, sub_leaf: 2 },
    CpuidBit { feature: X86_FEATURE_MBA, reg: CPUID_EBX, bit: 3, level: 0x00000010, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_PER_THREAD_MBA, reg: CPUID_ECX, bit: 0, level: 0x00000010, sub_leaf: 3 },
    CpuidBit { feature: X86_FEATURE_SGX1, reg: CPUID_EAX, bit: 0, level: 0x00000012, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_SGX2, reg: CPUID_EAX, bit: 1, level: 0x00000012, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_SGX_EDECCSSA, reg: CPUID_EAX, bit: 11, level: 0x00000012, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_HW_PSTATE, reg: CPUID_EDX, bit: 7, level: 0x80000007, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_CPB, reg: CPUID_EDX, bit: 9, level: 0x80000007, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_PROC_FEEDBACK, reg: CPUID_EDX, bit: 11, level: 0x80000007, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_AMD_FAST_CPPC, reg: CPUID_EDX, bit: 15, level: 0x80000007, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_MBA, reg: CPUID_EBX, bit: 6, level: 0x80000008, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_COHERENCY_SFW_NO, reg: CPUID_EBX, bit: 31, level: 0x8000001f, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_SMBA, reg: CPUID_EBX, bit: 2, level: 0x80000020, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_BMEC, reg: CPUID_EBX, bit: 3, level: 0x80000020, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_ABMC, reg: CPUID_EBX, bit: 5, level: 0x80000020, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_TSA_SQ_NO, reg: CPUID_ECX, bit: 1, level: 0x80000021, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_TSA_L1_NO, reg: CPUID_ECX, bit: 2, level: 0x80000021, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_AMD_WORKLOAD_CLASS, reg: CPUID_EAX, bit: 22, level: 0x80000021, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_PERFMON_V2, reg: CPUID_EAX, bit: 0, level: 0x80000022, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_AMD_LBR_V2, reg: CPUID_EAX, bit: 1, level: 0x80000022, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_AMD_LBR_PMC_FREEZE, reg: CPUID_EAX, bit: 2, level: 0x80000022, sub_leaf: 0 },
    CpuidBit { feature: X86_FEATURE_AMD_HTR_CORES, reg: CPUID_EAX, bit: 30, level: 0x80000026, sub_leaf: 0 },
];

/// `cpuid_count(op, count, ...)`: `[eax, ebx, ecx, edx]`.
#[cfg(not(userspace_test))]
#[inline(always)]
fn cpuid_count(op: u32, count: u32) -> [u32; 4] {
    // SAFETY: CPUID is always available in 64-bit mode (the intrinsic is a safe fn in newer toolchains).
    #[allow(unused_unsafe)]
    let r = unsafe { core::arch::x86_64::__cpuid_count(op, count) };
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// Userspace test (`port/test/x86_scattered/run.sh`): the harness answers.
#[cfg(userspace_test)]
fn cpuid_count(op: u32, count: u32) -> [u32; 4] {
    extern "C" {
        fn test_cpuid(op: u32, count: u32, out: *mut u32);
    }
    let mut o = [0u32; 4];
    // SAFETY: the harness writes four words.
    unsafe { test_cpuid(op, count, o.as_mut_ptr()) };
    o
}

/// `set_cpu_cap(c, bit)`: atomic OR of the bit into `c->x86_capability` (an array of `u32`, `unsigned long`-aligned).
///
/// # Safety
/// `c` points at a `struct cpuinfo_x86`; `bit` is inside `x86_capability`.
#[inline(always)]
unsafe fn set_cpu_cap(c: *mut u8, bit: u32) {
    // SAFETY: caller contract; the word holding the bit is inside the array (whole unsigned longs).
    unsafe {
        (*c.add(CI_CAP).add(((bit / 64) as usize).wrapping_mul(8)).cast::<AtomicU64>()).fetch_or(1u64 << (bit % 64), Ordering::SeqCst)
    };
}

/// `init_scattered_cpuid_features()`.
///
/// # Safety
/// `c` points at the `struct cpuinfo_x86` of the CPU being identified.
#[no_mangle]
pub unsafe extern "C" fn init_scattered_cpuid_features(c: *mut u8) {
    for cb in CPUID_BITS.iter() {
        /* Verify that the level is valid */
        let max_level = cpuid_count(cb.level & 0xffff0000, 0)[CPUID_EAX];
        if max_level < cb.level || max_level > (cb.level | 0xffff) {
            continue;
        }

        let regs = cpuid_count(cb.level, cb.sub_leaf);

        if regs[cb.reg] & (1u32 << cb.bit) != 0 {
            // SAFETY: `c` per the caller; every feature number is below NCAPINTS * 32.
            unsafe { set_cpu_cap(c, cb.feature as u32) };
        }
    }
}
