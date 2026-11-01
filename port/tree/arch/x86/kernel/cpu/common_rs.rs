// SPDX-License-Identifier: GPL-2.0-only

//! Rust part of `arch/x86/kernel/cpu/common.c`: the CPUID decode group and the early boot-CPU identification.
//!
//! In Rust (x86-64, `CONFIG_RUST=y`): `cpu_detect`, `get_cpu_vendor`, `get_cpu_cap` (with `init_speculation_control` and
//! `apply_forced_caps`), `get_cpu_address_sizes`, `filter_cpuid_features`, `detect_nopl`, `parse_set_clear_cpuid`,
//! `cpu_parse_early_param`, `early_identify_cpu`, `init_cpu_devs`, `early_cpu_init`, and `cpu_set_bug_bits` with its helpers (`cpu_matches`,
//! `arch_cap_mmio_immune`, `vulnerable_to_rfds`, `vulnerable_to_its`, `cpu_has_old_microcode`). The rest of the file stays C in
//! `common_glue.c`: per-CPU data, `cpu_init()`, `identify_cpu()`, the control-register and syscall setup, the three `x86_cpu_id` tables
//! (`cpu_vuln_whitelist`, `cpu_vuln_blacklist`, `cpu_latest_microcode`: header-macro data) and `x86_read_arch_cap_msr()` (`rdmsrq`, also called from
//! bugs.c, apic.c and tsx.c). The reasons for each cut are in the `common.c` record of `logs/hooks.md`.
//!
//! Runs on the boot CPU before SMP bring-up (`early_cpu_init`, `early_identify_cpu`, the command-line parsing, `init_cpu_devs`) and, for the
//! pure decode functions (`cpu_detect`, `get_cpu_vendor`, `get_cpu_cap`, `get_cpu_address_sizes`, `filter_cpuid_features`,
//! `apply_forced_caps`), also on every secondary CPU while it identifies itself, before its per-CPU state is complete. They keep no
//! state of their own: they read CPUID and write the `struct cpuinfo_x86` they are handed (the CPU's own), the C file's
//! `this_cpu` pointer (a write of one value that every CPU computes identically) and the `cpu_caps_set` / `cpu_caps_cleared` words.
//! No panic path (raw pointers, `wrapping_*`), no allocation, no lock.
//!
//! `struct cpuinfo_x86` is not mirrored: its layout depends on the configuration (`NCAPINTS`, `CONFIG_X86_VMX_FEATURE_NAMES`, the
//! topology struct), so the fields are read and written by byte offset, and each offset is a constant tagged `// C:` that
//! `rig/phase-e/consts_check.py` compiles against the kernel's own headers.
//!
//! Messages are the C's, byte for byte (`rig/phase-e/msgs_check.py`).
//!
//! Replaces (x86-64 only): the functions above in arch/x86/kernel/cpu/common.c

use core::ffi::c_char;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(CONFIG_PARAVIRT_XXL)]
compile_error!("cpu/common_rs.rs: cpuid() is paravirtualised under PARAVIRT_XXL; port that path first");
#[cfg(CONFIG_FUNCTION_TRACER)]
compile_error!("cpu/common_rs.rs: upstream builds common.c without -pg because secondary CPUs run this code before ftrace is usable; Rust functions would be patchable");
#[cfg(CONFIG_X86_32)]
compile_error!("cpu/common_rs.rs: x86-64 only");
#[cfg(not(CONFIG_X86_VMX_FEATURE_NAMES))]
compile_error!("cpu/common_rs.rs: the cpuinfo_x86 offsets were taken with CONFIG_X86_VMX_FEATURE_NAMES=y (vmx_capability[] present)");
#[cfg(CONFIG_RANDSTRUCT)]
compile_error!("cpu/common_rs.rs: struct cpuinfo_x86 is __randomize_layout; the offsets are fixed");

// C-HEADERS: linux/types.h asm/processor.h asm/cpufeature.h asm/cpufeatures.h asm/cpuid/types.h linux/panic.h asm/cpufeaturemasks.h asm/msr-index.h src:arch/x86/kernel/cpu/cpu.h linux/mod_devicetable.h
/// `NCAPINTS` (asm/cpufeatures.h).
const NCAPINTS: usize = 22; // C: NCAPINTS
/// `NBUGINTS`.
const NBUGINTS: usize = 2; // C: NBUGINTS
/// `X86_VENDOR_NUM`.
const X86_VENDOR_NUM: usize = 12; // C: X86_VENDOR_NUM
/// `X86_VENDOR_UNKNOWN`.
const X86_VENDOR_UNKNOWN: u8 = 0xff; // C: X86_VENDOR_UNKNOWN
/// `offsetof(struct cpuinfo_x86, x86_model)`.
const CI_MODEL: usize = 0; // C: offsetof(struct cpuinfo_x86, x86_model)
/// `offsetof(struct cpuinfo_x86, x86)` (family).
const CI_FAMILY: usize = 1; // C: offsetof(struct cpuinfo_x86, x86)
/// `offsetof(struct cpuinfo_x86, x86_vendor)`.
const CI_VENDOR: usize = 2; // C: offsetof(struct cpuinfo_x86, x86_vendor)
/// `offsetof(struct cpuinfo_x86, x86_stepping)`.
const CI_STEPPING: usize = 4; // C: offsetof(struct cpuinfo_x86, x86_stepping)
/// `offsetof(struct cpuinfo_x86, x86_virt_bits)`.
const CI_VIRT_BITS: usize = 32; // C: offsetof(struct cpuinfo_x86, x86_virt_bits)
/// `offsetof(struct cpuinfo_x86, x86_phys_bits)`.
const CI_PHYS_BITS: usize = 33; // C: offsetof(struct cpuinfo_x86, x86_phys_bits)
/// `offsetof(struct cpuinfo_x86, extended_cpuid_level)`.
const CI_EXT_LEVEL: usize = 36; // C: offsetof(struct cpuinfo_x86, extended_cpuid_level)
/// `offsetof(struct cpuinfo_x86, cpuid_level)`.
const CI_LEVEL: usize = 40; // C: offsetof(struct cpuinfo_x86, cpuid_level)
/// `offsetof(struct cpuinfo_x86, x86_capability)`.
const CI_CAP: usize = 48; // C: offsetof(struct cpuinfo_x86, x86_capability)
/// `offsetof(struct cpuinfo_x86, x86_vendor_id)`.
const CI_VENDOR_ID: usize = 144; // C: offsetof(struct cpuinfo_x86, x86_vendor_id)
/// `offsetof(struct cpuinfo_x86, x86_cache_alignment)`.
const CI_CACHE_ALIGN: usize = 280; // C: offsetof(struct cpuinfo_x86, x86_cache_alignment)
/// `offsetof(struct cpuinfo_x86, x86_power)`.
const CI_POWER: usize = 296; // C: offsetof(struct cpuinfo_x86, x86_power)
/// `offsetof(struct cpuinfo_x86, x86_clflush_size)`.
const CI_CLFLUSH: usize = 320; // C: offsetof(struct cpuinfo_x86, x86_clflush_size)
/// `offsetof(struct cpuinfo_x86, cpu_index)`.
const CI_CPU_INDEX: usize = 324; // C: offsetof(struct cpuinfo_x86, cpu_index)
/// `offsetof(struct cpuinfo_x86, x86_cache_bits)`.
const CI_CACHE_BITS: usize = 332; // C: offsetof(struct cpuinfo_x86, x86_cache_bits)
/// `offsetof(struct cpu_dev, c_vendor)` (only the `CONFIG_PROCESSOR_SELECT` list prints it).
#[allow(dead_code)]
const CD_VENDOR: usize = 0; // C: offsetof(struct cpu_dev, c_vendor)
/// `offsetof(struct cpu_dev, c_ident)`.
const CD_IDENT: usize = 8; // C: offsetof(struct cpu_dev, c_ident)
/// `offsetof(struct cpu_dev, c_early_init)`.
const CD_EARLY_INIT: usize = 24; // C: offsetof(struct cpu_dev, c_early_init)
/// `offsetof(struct cpu_dev, c_bsp_init)`.
const CD_BSP_INIT: usize = 32; // C: offsetof(struct cpu_dev, c_bsp_init)
/// `offsetof(struct cpu_dev, c_x86_vendor)`.
const CD_X86_VENDOR: usize = 64; // C: offsetof(struct cpu_dev, c_x86_vendor)
/// `sizeof(struct cpu_dev)`.
const CD_SIZE: usize = 72; // C: sizeof(struct cpu_dev)
/// `CPUID_1_EDX`: the `x86_capability[]` word of each CPUID register (enum cpuid_leafs, asm/cpufeature.h).
const CPUID_1_EDX: usize = 0; // C: CPUID_1_EDX
/// `CPUID_8000_0001_EDX`.
const CPUID_8000_0001_EDX: usize = 1; // C: CPUID_8000_0001_EDX
/// `CPUID_8000_0001_ECX`.
const CPUID_8000_0001_ECX: usize = 6; // C: CPUID_8000_0001_ECX
/// `CPUID_1_ECX`.
const CPUID_1_ECX: usize = 4; // C: CPUID_1_ECX
/// `CPUID_7_0_EBX`.
const CPUID_7_0_EBX: usize = 9; // C: CPUID_7_0_EBX
/// `CPUID_D_1_EAX`.
const CPUID_D_1_EAX: usize = 10; // C: CPUID_D_1_EAX
/// `CPUID_7_1_EAX`.
const CPUID_7_1_EAX: usize = 12; // C: CPUID_7_1_EAX
/// `CPUID_8000_0008_EBX`.
const CPUID_8000_0008_EBX: usize = 13; // C: CPUID_8000_0008_EBX
/// `CPUID_6_EAX`.
const CPUID_6_EAX: usize = 14; // C: CPUID_6_EAX
/// `CPUID_8000_000A_EDX`.
const CPUID_8000_000A_EDX: usize = 15; // C: CPUID_8000_000A_EDX
/// `CPUID_7_ECX`.
const CPUID_7_ECX: usize = 16; // C: CPUID_7_ECX
/// `CPUID_8000_0007_EBX`.
const CPUID_8000_0007_EBX: usize = 17; // C: CPUID_8000_0007_EBX
/// `CPUID_7_EDX`.
const CPUID_7_EDX: usize = 18; // C: CPUID_7_EDX
/// `CPUID_8000_001F_EAX`.
const CPUID_8000_001F_EAX: usize = 19; // C: CPUID_8000_001F_EAX
/// `CPUID_8000_0021_EAX`.
const CPUID_8000_0021_EAX: usize = 20; // C: CPUID_8000_0021_EAX
/// `X86_FEATURE_CPUID` (a required feature on x86-64: `cpu_has()` of it is the constant 1).
const X86_FEATURE_CPUID: u32 = 3 * 32 + 25; // C: X86_FEATURE_CPUID
/// `X86_FEATURE_ALWAYS`.
const X86_FEATURE_ALWAYS: u32 = 3 * 32 + 21; // C: X86_FEATURE_ALWAYS
/// `X86_FEATURE_NOPL`.
const X86_FEATURE_NOPL: u32 = 3 * 32 + 20; // C: X86_FEATURE_NOPL
/// `X86_FEATURE_LA57`.
const X86_FEATURE_LA57: u32 = 16 * 32 + 16; // C: X86_FEATURE_LA57
/// `X86_FEATURE_FRED`.
const X86_FEATURE_FRED: u32 = 12 * 32 + 17; // C: X86_FEATURE_FRED
/// `X86_FEATURE_USER_SHSTK`.
const X86_FEATURE_USER_SHSTK: u32 = 11 * 32 + 23; // C: X86_FEATURE_USER_SHSTK
/// `X86_FEATURE_XSAVE`.
const X86_FEATURE_XSAVE: u32 = 4 * 32 + 26; // C: X86_FEATURE_XSAVE
/// `X86_FEATURE_XSAVEOPT`.
const X86_FEATURE_XSAVEOPT: u32 = 10 * 32; // C: X86_FEATURE_XSAVEOPT
/// `X86_FEATURE_XSAVES`.
const X86_FEATURE_XSAVES: u32 = 10 * 32 + 3; // C: X86_FEATURE_XSAVES
/// `X86_FEATURE_MWAIT`.
const X86_FEATURE_MWAIT: u32 = 4 * 32 + 3; // C: X86_FEATURE_MWAIT
/// `X86_FEATURE_DCA`.
const X86_FEATURE_DCA: u32 = 4 * 32 + 18; // C: X86_FEATURE_DCA
/// `X86_FEATURE_SPEC_CTRL`.
const X86_FEATURE_SPEC_CTRL: u32 = 18 * 32 + 26; // C: X86_FEATURE_SPEC_CTRL
/// `X86_FEATURE_INTEL_STIBP`.
const X86_FEATURE_INTEL_STIBP: u32 = 18 * 32 + 27; // C: X86_FEATURE_INTEL_STIBP
/// `X86_FEATURE_SPEC_CTRL_SSBD`.
const X86_FEATURE_SPEC_CTRL_SSBD: u32 = 18 * 32 + 31; // C: X86_FEATURE_SPEC_CTRL_SSBD
/// `X86_FEATURE_VIRT_SSBD`.
const X86_FEATURE_VIRT_SSBD: u32 = 13 * 32 + 25; // C: X86_FEATURE_VIRT_SSBD
/// `X86_FEATURE_AMD_IBRS`.
const X86_FEATURE_AMD_IBRS: u32 = 13 * 32 + 14; // C: X86_FEATURE_AMD_IBRS
/// `X86_FEATURE_AMD_IBPB`.
const X86_FEATURE_AMD_IBPB: u32 = 13 * 32 + 12; // C: X86_FEATURE_AMD_IBPB
/// `X86_FEATURE_AMD_STIBP`.
const X86_FEATURE_AMD_STIBP: u32 = 13 * 32 + 15; // C: X86_FEATURE_AMD_STIBP
/// `X86_FEATURE_AMD_SSBD`.
const X86_FEATURE_AMD_SSBD: u32 = 13 * 32 + 24; // C: X86_FEATURE_AMD_SSBD
/// `X86_FEATURE_IBRS`.
const X86_FEATURE_IBRS: u32 = 7 * 32 + 25; // C: X86_FEATURE_IBRS
/// `X86_FEATURE_IBPB`.
const X86_FEATURE_IBPB: u32 = 7 * 32 + 26; // C: X86_FEATURE_IBPB
/// `X86_FEATURE_STIBP`.
const X86_FEATURE_STIBP: u32 = 7 * 32 + 27; // C: X86_FEATURE_STIBP
/// `X86_FEATURE_SSBD`.
const X86_FEATURE_SSBD: u32 = 7 * 32 + 17; // C: X86_FEATURE_SSBD
/// `X86_FEATURE_MSR_SPEC_CTRL`.
const X86_FEATURE_MSR_SPEC_CTRL: u32 = 7 * 32 + 16; // C: X86_FEATURE_MSR_SPEC_CTRL
/// `CPUID_LEAF_MWAIT`.
const CPUID_LEAF_MWAIT: u32 = 0x05; // C: CPUID_LEAF_MWAIT
/// `CPUID_LEAF_DCA`.
const CPUID_LEAF_DCA: u32 = 0x09; // C: CPUID_LEAF_DCA
/// `CPUID_LEAF_XSTATE`.
const CPUID_LEAF_XSTATE: u32 = 0x0d; // C: CPUID_LEAF_XSTATE
/// `TAINT_CPU_OUT_OF_SPEC`.
const TAINT_CPU_OUT_OF_SPEC: u32 = 2; // C: TAINT_CPU_OUT_OF_SPEC
/// `LOCKDEP_STILL_OK` (enum lockdep_ok).
const LOCKDEP_STILL_OK: u32 = 0; // C: LOCKDEP_STILL_OK
/// `REQUIRED_MASK_BIT_SET(X86_FEATURE_CPUID)`: `cpu_has(c, X86_FEATURE_CPUID)` is the constant 1 (cpufeaturemasks.h).
const CPUID_IS_REQUIRED: u64 = 1; // C: !!REQUIRED_MASK_BIT_SET(X86_FEATURE_CPUID)

/// `X86_VENDOR_INTEL`.
const X86_VENDOR_INTEL: u8 = 0; // C: X86_VENDOR_INTEL
/// `X86_VENDOR_AMD`.
const X86_VENDOR_AMD: u8 = 2; // C: X86_VENDOR_AMD
/// `offsetof(struct cpuinfo_x86, microcode)`.
const CI_MICROCODE: usize = 0x148; // C: offsetof(struct cpuinfo_x86, microcode)
/// `offsetof(struct x86_cpu_id, driver_data)`.
const XCI_DRIVER_DATA: usize = 16; // C: offsetof(struct x86_cpu_id, driver_data)
/// `X86_FEATURE_HYPERVISOR`.
const X86_FEATURE_HYPERVISOR: u32 = 4 * 32 + 31; // C: X86_FEATURE_HYPERVISOR
/// `X86_FEATURE_AMD_SSB_NO`.
const X86_FEATURE_AMD_SSB_NO: u32 = 13 * 32 + 26; // C: X86_FEATURE_AMD_SSB_NO
/// `X86_FEATURE_AUTOIBRS`.
const X86_FEATURE_AUTOIBRS: u32 = 20 * 32 + 8; // C: X86_FEATURE_AUTOIBRS
/// `X86_FEATURE_IBRS_ENHANCED`.
const X86_FEATURE_IBRS_ENHANCED: u32 = 7 * 32 + 30; // C: X86_FEATURE_IBRS_ENHANCED
/// `X86_FEATURE_SEV_SNP` (a DISABLED feature without `CONFIG_KVM_AMD_SEV`: `cpu_feature_enabled()` of it is the constant 0).
#[cfg(CONFIG_KVM_AMD_SEV)]
const X86_FEATURE_SEV_SNP: u32 = 19 * 32 + 4; // C: X86_FEATURE_SEV_SNP
/// `X86_FEATURE_RTM`.
const X86_FEATURE_RTM: u32 = 9 * 32 + 11; // C: X86_FEATURE_RTM
/// `X86_FEATURE_RDRAND`.
const X86_FEATURE_RDRAND: u32 = 4 * 32 + 30; // C: X86_FEATURE_RDRAND
/// `X86_FEATURE_RDSEED`.
const X86_FEATURE_RDSEED: u32 = 9 * 32 + 18; // C: X86_FEATURE_RDSEED
/// `X86_FEATURE_BTC_NO`.
const X86_FEATURE_BTC_NO: u32 = 13 * 32 + 29; // C: X86_FEATURE_BTC_NO
/// `X86_FEATURE_SRSO_NO`.
const X86_FEATURE_SRSO_NO: u32 = 20 * 32 + 29; // C: X86_FEATURE_SRSO_NO
/// `X86_FEATURE_AVX`.
const X86_FEATURE_AVX: u32 = 4 * 32 + 28; // C: X86_FEATURE_AVX
/// `X86_FEATURE_BHI_CTRL`.
const X86_FEATURE_BHI_CTRL: u32 = 21 * 32 + 2; // C: X86_FEATURE_BHI_CTRL
/// `X86_FEATURE_AMD_IBPB_RET`.
const X86_FEATURE_AMD_IBPB_RET: u32 = 13 * 32 + 30; // C: X86_FEATURE_AMD_IBPB_RET
/// `X86_FEATURE_TSA_SQ_NO`.
const X86_FEATURE_TSA_SQ_NO: u32 = 21 * 32 + 11; // C: X86_FEATURE_TSA_SQ_NO
/// `X86_FEATURE_TSA_L1_NO`.
const X86_FEATURE_TSA_L1_NO: u32 = 21 * 32 + 12; // C: X86_FEATURE_TSA_L1_NO
/// `X86_FEATURE_ZEN`.
const X86_FEATURE_ZEN: u32 = 7 * 32 + 28; // C: X86_FEATURE_ZEN
/// `X86_BUG_OLD_MICROCODE`.
const X86_BUG_OLD_MICROCODE: u32 = 23 * 32 + 6; // C: X86_BUG_OLD_MICROCODE
/// `X86_BUG_ITLB_MULTIHIT`.
const X86_BUG_ITLB_MULTIHIT: u32 = 22 * 32 + 23; // C: X86_BUG_ITLB_MULTIHIT
/// `X86_BUG_SPECTRE_V1`.
const X86_BUG_SPECTRE_V1: u32 = 22 * 32 + 15; // C: X86_BUG_SPECTRE_V1
/// `X86_BUG_SPECTRE_V2`.
const X86_BUG_SPECTRE_V2: u32 = 22 * 32 + 16; // C: X86_BUG_SPECTRE_V2
/// `X86_BUG_SPECTRE_V2_USER`.
const X86_BUG_SPECTRE_V2_USER: u32 = 23 * 32 + 5; // C: X86_BUG_SPECTRE_V2_USER
/// `X86_BUG_SPEC_STORE_BYPASS`.
const X86_BUG_SPEC_STORE_BYPASS: u32 = 22 * 32 + 17; // C: X86_BUG_SPEC_STORE_BYPASS
/// `X86_BUG_EIBRS_PBRSB`.
const X86_BUG_EIBRS_PBRSB: u32 = 22 * 32 + 28; // C: X86_BUG_EIBRS_PBRSB
/// `X86_BUG_MDS`.
const X86_BUG_MDS: u32 = 22 * 32 + 19; // C: X86_BUG_MDS
/// `X86_BUG_MSBDS_ONLY`.
const X86_BUG_MSBDS_ONLY: u32 = 22 * 32 + 20; // C: X86_BUG_MSBDS_ONLY
/// `X86_BUG_SWAPGS`.
const X86_BUG_SWAPGS: u32 = 22 * 32 + 21; // C: X86_BUG_SWAPGS
/// `X86_BUG_TAA`.
const X86_BUG_TAA: u32 = 22 * 32 + 22; // C: X86_BUG_TAA
/// `X86_BUG_SRBDS`.
const X86_BUG_SRBDS: u32 = 22 * 32 + 24; // C: X86_BUG_SRBDS
/// `X86_BUG_MMIO_STALE_DATA`.
const X86_BUG_MMIO_STALE_DATA: u32 = 22 * 32 + 25; // C: X86_BUG_MMIO_STALE_DATA
/// `X86_BUG_RETBLEED`.
const X86_BUG_RETBLEED: u32 = 22 * 32 + 27; // C: X86_BUG_RETBLEED
/// `X86_BUG_SMT_RSB`.
const X86_BUG_SMT_RSB: u32 = 22 * 32 + 29; // C: X86_BUG_SMT_RSB
/// `X86_BUG_SRSO`.
const X86_BUG_SRSO: u32 = 23 * 32 + 0; // C: X86_BUG_SRSO
/// `X86_BUG_GDS`.
const X86_BUG_GDS: u32 = 22 * 32 + 30; // C: X86_BUG_GDS
/// `X86_BUG_RFDS`.
const X86_BUG_RFDS: u32 = 23 * 32 + 2; // C: X86_BUG_RFDS
/// `X86_BUG_BHI`.
const X86_BUG_BHI: u32 = 23 * 32 + 3; // C: X86_BUG_BHI
/// `X86_BUG_IBPB_NO_RET`.
const X86_BUG_IBPB_NO_RET: u32 = 23 * 32 + 4; // C: X86_BUG_IBPB_NO_RET
/// `X86_BUG_ITS`.
const X86_BUG_ITS: u32 = 23 * 32 + 7; // C: X86_BUG_ITS
/// `X86_BUG_ITS_NATIVE_ONLY`.
const X86_BUG_ITS_NATIVE_ONLY: u32 = 23 * 32 + 8; // C: X86_BUG_ITS_NATIVE_ONLY
/// `X86_BUG_TSA`.
const X86_BUG_TSA: u32 = 23 * 32 + 9; // C: X86_BUG_TSA
/// `X86_BUG_VMSCAPE`.
const X86_BUG_VMSCAPE: u32 = 23 * 32 + 10; // C: X86_BUG_VMSCAPE
/// `X86_BUG_CPU_MELTDOWN`.
const X86_BUG_CPU_MELTDOWN: u32 = 22 * 32 + 14; // C: X86_BUG_CPU_MELTDOWN
/// `X86_BUG_L1TF`.
const X86_BUG_L1TF: u32 = 22 * 32 + 18; // C: X86_BUG_L1TF
/// `ARCH_CAP_RDCL_NO` (IA32_ARCH_CAPABILITIES bit 0).
const ARCH_CAP_RDCL_NO: u64 = 1; // C: ARCH_CAP_RDCL_NO
/// `ARCH_CAP_IBRS_ALL`.
const ARCH_CAP_IBRS_ALL: u64 = 2; // C: ARCH_CAP_IBRS_ALL
/// `ARCH_CAP_RSBA`.
const ARCH_CAP_RSBA: u64 = 4; // C: ARCH_CAP_RSBA
/// `ARCH_CAP_SSB_NO`.
const ARCH_CAP_SSB_NO: u64 = 16; // C: ARCH_CAP_SSB_NO
/// `ARCH_CAP_MDS_NO`.
const ARCH_CAP_MDS_NO: u64 = 32; // C: ARCH_CAP_MDS_NO
/// `ARCH_CAP_PSCHANGE_MC_NO`.
const ARCH_CAP_PSCHANGE_MC_NO: u64 = 64; // C: ARCH_CAP_PSCHANGE_MC_NO
/// `ARCH_CAP_TSX_CTRL_MSR`.
const ARCH_CAP_TSX_CTRL_MSR: u64 = 128; // C: ARCH_CAP_TSX_CTRL_MSR
/// `ARCH_CAP_TAA_NO`.
const ARCH_CAP_TAA_NO: u64 = 256; // C: ARCH_CAP_TAA_NO
/// `ARCH_CAP_SBDR_SSDP_NO`.
const ARCH_CAP_SBDR_SSDP_NO: u64 = 0x2000; // C: ARCH_CAP_SBDR_SSDP_NO
/// `ARCH_CAP_FBSDP_NO`.
const ARCH_CAP_FBSDP_NO: u64 = 0x4000; // C: ARCH_CAP_FBSDP_NO
/// `ARCH_CAP_PSDP_NO`.
const ARCH_CAP_PSDP_NO: u64 = 0x8000; // C: ARCH_CAP_PSDP_NO
/// `ARCH_CAP_PBRSB_NO`.
const ARCH_CAP_PBRSB_NO: u64 = 0x1000000; // C: ARCH_CAP_PBRSB_NO
/// `ARCH_CAP_GDS_NO`.
const ARCH_CAP_GDS_NO: u64 = 0x4000000; // C: ARCH_CAP_GDS_NO
/// `ARCH_CAP_RFDS_NO`.
const ARCH_CAP_RFDS_NO: u64 = 0x8000000; // C: ARCH_CAP_RFDS_NO
/// `ARCH_CAP_RFDS_CLEAR`.
const ARCH_CAP_RFDS_CLEAR: u64 = 0x10000000; // C: ARCH_CAP_RFDS_CLEAR
/// `ARCH_CAP_ITS_NO`.
const ARCH_CAP_ITS_NO: u64 = 0x4000000000000000; // C: ARCH_CAP_ITS_NO
// The vulnerability flags of the C file (`#define NO_SPECULATION BIT(0)` ... `VMSCAPE BIT(11)`): macros of common.c itself, so no `C:` tag;
// `rig/phase-e/cpu_cmp.sh` compares every use against the real C compiled from the pristine file.
/// `NO_SPECULATION`.
const NO_SPECULATION: u64 = 1 << 0;
/// `NO_MELTDOWN`.
const NO_MELTDOWN: u64 = 1 << 1;
/// `NO_SSB`.
const NO_SSB: u64 = 1 << 2;
/// `NO_L1TF`.
const NO_L1TF: u64 = 1 << 3;
/// `NO_MDS`.
const NO_MDS: u64 = 1 << 4;
/// `MSBDS_ONLY`.
const MSBDS_ONLY: u64 = 1 << 5;
/// `NO_SWAPGS`.
const NO_SWAPGS: u64 = 1 << 6;
/// `NO_ITLB_MULTIHIT`.
const NO_ITLB_MULTIHIT: u64 = 1 << 7;
/// `NO_SPECTRE_V2`.
const NO_SPECTRE_V2: u64 = 1 << 8;
/// `NO_EIBRS_PBRSB`.
const NO_EIBRS_PBRSB: u64 = 1 << 10;
/// `NO_BHI`.
const NO_BHI: u64 = 1 << 11;
/// `SRBDS`.
const SRBDS: u64 = 1 << 0;
/// `MMIO`.
const MMIO: u64 = 1 << 1;
/// `MMIO_SBDS`.
const MMIO_SBDS: u64 = 1 << 2;
/// `RETBLEED`.
const RETBLEED: u64 = 1 << 3;
/// `SMT_RSB`.
const SMT_RSB: u64 = 1 << 4;
/// `SRSO`.
const SRSO: u64 = 1 << 5;
/// `GDS`.
const GDS: u64 = 1 << 6;
/// `RFDS`.
const RFDS: u64 = 1 << 7;
/// `ITS`.
const ITS: u64 = 1 << 8;
/// `ITS_NATIVE_ONLY`.
const ITS_NATIVE_ONLY: u64 = 1 << 9;
/// `TSA`.
const TSA: u64 = 1 << 10;
/// `VMSCAPE`.
const VMSCAPE: u64 = 1 << 11;

/// Number of `u32` words of `x86_capability[]` (capabilities + bugs).
const CAP_WORDS: usize = NCAPINTS + NBUGINTS;

type CpuFn = Option<unsafe extern "C" fn(*mut u8)>;

extern "C" {
    static mut boot_cpu_data: u8;
    static mut cpu_caps_set: [u32; 0];
    static mut cpu_caps_cleared: [u32; 0];
    static x86_cap_flags: [*const c_char; 0];
    static x86_bug_flags: [*const c_char; 0];
    static boot_command_line: [c_char; 0];
    static __pgtable_l5_enabled: u32;
    static alternatives_patched: i32;
    static __x86_cpu_dev_start: [*const u8; 0];
    static __x86_cpu_dev_end: [*const u8; 0];
    // The three statics of common.c that the Rust reads and writes; `common_glue.c` makes them global (hidden), no initialiser change.
    static mut cpu_devs: [*const u8; 0];
    static mut this_cpu: *const u8;
    static default_cpu: u8;
    /// The three `x86_cpu_id` tables of common.c (global, hidden, in the glue) and the C helpers the bug-bit code calls.
    static cpu_vuln_whitelist: [u8; 0];
    static cpu_vuln_blacklist: [u8; 0];
    static cpu_latest_microcode: [u8; 0];
    fn x86_match_cpu(table: *const u8) -> *const u8;
    fn x86_read_arch_cap_msr() -> u64;
    fn x86_family(sig: u32) -> u32;
    fn x86_model(sig: u32) -> u32;
    fn x86_stepping(sig: u32) -> u32;
    fn init_scattered_cpuid_features(c: *mut u8);
    fn cpu_init_topology(c: *mut u8);
    fn check_cpufeature_deps(c: *mut u8);
    fn setup_clear_cpu_cap(feature: u32);
    fn clear_cpu_cap(c: *mut u8, feature: u32);
    #[cfg(CONFIG_CPU_SUP_INTEL)]
    fn intel_unlock_cpuid_leafs(c: *mut u8);
    #[cfg(CONFIG_X86_BUS_LOCK_DETECT)]
    fn sld_setup(c: *mut u8);
    #[cfg(CONFIG_X86_MCE)]
    fn mca_bsp_init(c: *mut u8);
    /// `WARN_ON(1)` of `setup_force_cpu_cap()` (glue).
    fn x86_force_cap_warn();
    fn strcmp(a: *const c_char, b: *const c_char) -> i32;
    fn strsep(s: *mut *mut c_char, delim: *const c_char) -> *mut c_char;
    fn kstrtouint(s: *const c_char, base: u32, res: *mut u32) -> i32;
    fn cmdline_find_option_bool(cmdline: *const c_char, option: *const c_char) -> i32;
    fn cmdline_find_option(cmdline: *const c_char, option: *const c_char, buffer: *mut c_char, bufsize: i32) -> i32;
    fn add_taint(flag: u32, lockdep_ok: u32);
    fn _printk(fmt: *const c_char, ...) -> i32;
}

// ---- CPUID ---------------------------------------------------------------------------------------------------------------------

/// `cpuid_count(op, count, ...)` (asm/cpuid/api.h): `eax = op; ecx = count;` then the instruction; `[eax, ebx, ecx, edx]`.
#[cfg(not(userspace_test))]
#[inline(always)]
fn cpuid_count(op: u32, count: u32) -> [u32; 4] {
    // SAFETY: CPUID is always available in 64-bit mode (the intrinsic is a safe fn in newer toolchains).
    #[allow(unused_unsafe)]
    let r = unsafe { core::arch::x86_64::__cpuid_count(op, count) };
    [r.eax, r.ebx, r.ecx, r.edx]
}
/// Userspace test: the harness answers.
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
/// `cpuid(op, ...)`: subleaf 0.
#[inline(always)]
fn cpuid(op: u32) -> [u32; 4] {
    cpuid_count(op, 0)
}

// ---- field access by byte offset -----------------------------------------------------------------------------------------------

/// Read a `T` at byte offset `off` of the `struct cpuinfo_x86` at `c`.
///
/// # Safety
/// `c` points at a `struct cpuinfo_x86` and `off` is the offset of a field of type `T`.
#[inline(always)]
unsafe fn rd<T: Copy>(c: *const u8, off: usize) -> T {
    // SAFETY: caller contract.
    unsafe { c.add(off).cast::<T>().read_unaligned() }
}
/// Write a `T` at byte offset `off` of the `struct cpuinfo_x86` at `c`.
///
/// # Safety
/// As [`rd`], and `c` is writable.
#[inline(always)]
unsafe fn wr<T>(c: *mut u8, off: usize, v: T) {
    // SAFETY: caller contract.
    unsafe { c.add(off).cast::<T>().write_unaligned(v) }
}
/// `c->x86_capability[i]`.
///
/// # Safety
/// `c` is a `struct cpuinfo_x86`, `i < CAP_WORDS`.
#[inline(always)]
unsafe fn cap_word(c: *const u8, i: usize) -> u32 {
    // SAFETY: caller contract.
    unsafe { rd::<u32>(c, CI_CAP + i.wrapping_mul(4)) }
}
/// `c->x86_capability[i] = v`.
///
/// # Safety
/// As [`cap_word`], writable.
#[inline(always)]
unsafe fn set_cap_word(c: *mut u8, i: usize, v: u32) {
    // SAFETY: caller contract.
    unsafe { wr::<u32>(c, CI_CAP + i.wrapping_mul(4), v) }
}
/// `cpu_has(c, bit)` for a bit that is not a required feature: `test_bit(bit, c->x86_capability)`.
///
/// # Safety
/// `c` is a `struct cpuinfo_x86`, `bit < 32 * CAP_WORDS`.
#[inline(always)]
unsafe fn cpu_has(c: *const u8, bit: u32) -> bool {
    // SAFETY: caller contract.
    unsafe { (cap_word(c, (bit / 32) as usize) >> (bit % 32)) & 1 != 0 }
}
/// `set_bit(bit, words)` on a `u32` array whose start is aligned to `unsigned long` (`lock orq` on the word holding the bit).
///
/// # Safety
/// `words` is 8-byte aligned and covers `bit`.
#[inline(always)]
unsafe fn set_bit(bit: u32, words: *mut u8) {
    // SAFETY: caller contract; the word is inside the array (CAP_WORDS u32 = whole unsigned longs).
    unsafe { (*words.add(((bit / 64) as usize).wrapping_mul(8)).cast::<AtomicU64>()).fetch_or(1u64 << (bit % 64), Ordering::SeqCst) };
}
/// `set_cpu_cap(c, bit)`.
///
/// # Safety
/// `c` is a `struct cpuinfo_x86`.
#[inline(always)]
unsafe fn set_cpu_cap(c: *mut u8, bit: u32) {
    // SAFETY: caller contract.
    unsafe { set_bit(bit, c.add(CI_CAP)) }
}
/// `setup_force_cpu_cap(bit)` (asm/cpufeature.h): warn if the feature is new after the alternatives were patched, then set the bit
/// in `boot_cpu_data` and in `cpu_caps_set`. For a required feature the C's `boot_cpu_has()` is the constant 1, so no warning.
///
/// # Safety
/// Boot CPU, early.
unsafe fn setup_force_cpu_cap(bit: u32, required: bool) {
    // SAFETY: the kernel's own globals.
    unsafe {
        let b = (&raw mut boot_cpu_data) as *mut u8;
        if !required && !cpu_has(b, bit) && alternatives_patched != 0 {
            x86_force_cap_warn();
        }
        set_cpu_cap(b, bit);
        set_bit(bit, (&raw mut cpu_caps_set) as *mut u8);
    }
}

// ---- cpu_detect, get_cpu_vendor ------------------------------------------------------------------------------------------------

/// `cpu_detect()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86`.
pub(crate) unsafe fn cpu_detect_impl(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe {
        /* Get vendor name */
        let r = cpuid(0x0000_0000);
        wr::<u32>(c, CI_LEVEL, r[0]);
        wr::<u32>(c, CI_VENDOR_ID, r[1]);
        wr::<u32>(c, CI_VENDOR_ID + 8, r[2]);
        wr::<u32>(c, CI_VENDOR_ID + 4, r[3]);

        wr::<u8>(c, CI_FAMILY, 4);
        /* Intel-defined flags: level 0x00000001 */
        if rd::<i32>(c, CI_LEVEL) >= 0x0000_0001 {
            let r = cpuid(0x0000_0001);
            let (tfms, misc, cap0) = (r[0], r[1], r[3]);
            wr::<u8>(c, CI_FAMILY, x86_family(tfms) as u8);
            wr::<u8>(c, CI_MODEL, x86_model(tfms) as u8);
            wr::<u8>(c, CI_STEPPING, x86_stepping(tfms) as u8);

            if cap0 & (1 << 19) != 0 {
                let sz = (((misc >> 8) & 0xff).wrapping_mul(8)) as u16;
                wr::<u16>(c, CI_CLFLUSH, sz);
                wr::<i32>(c, CI_CACHE_ALIGN, sz as i32);
            }
        }
    }
}

/// `pr_err_once()`'s once flag (`.data..once`).
#[cfg_attr(not(userspace_test), link_section = ".data..once")]
static mut VENDOR_ALREADY_DONE: bool = false;

/// `get_cpu_vendor()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86` whose `x86_vendor_id` is NUL terminated.
pub(crate) unsafe fn get_cpu_vendor_impl(c: *mut u8) {
    // SAFETY: caller contract; `cpu_devs` has X86_VENDOR_NUM entries.
    unsafe {
        let v = c.add(CI_VENDOR_ID) as *const c_char;
        let mut i = 0usize;
        while i < X86_VENDOR_NUM {
            let d = (&raw const cpu_devs as *const *const u8).add(i).read();
            if d.is_null() {
                break;
            }
            let id0 = d.add(CD_IDENT).cast::<*const c_char>().read();
            let id1 = d.add(CD_IDENT + 8).cast::<*const c_char>().read();
            if strcmp(v, id0) == 0 || (!id1.is_null() && strcmp(v, id1) == 0) {
                this_cpu = d;
                wr::<u8>(c, CI_VENDOR, d.add(CD_X86_VENDOR).cast::<i32>().read() as u8);
                return;
            }
            i = i.wrapping_add(1);
        }

        if !VENDOR_ALREADY_DONE {
            VENDOR_ALREADY_DONE = true;
            _printk(c"\x013CPU: vendor_id '%s' unknown, using generic init.\nCPU: Your system may be unstable.\n".as_ptr(), v);
        }

        wr::<u8>(c, CI_VENDOR, X86_VENDOR_UNKNOWN);
        this_cpu = &raw const default_cpu;
    }
}

// ---- get_cpu_cap -----------------------------------------------------------------------------------------------------------------

/// `apply_forced_caps()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86`.
pub(crate) unsafe fn apply_forced_caps_impl(c: *mut u8) {
    // SAFETY: caller contract; the two arrays have CAP_WORDS words.
    unsafe {
        let (cleared, set) = ((&raw const cpu_caps_cleared) as *const u32, (&raw const cpu_caps_set) as *const u32);
        let mut i = 0usize;
        while i < CAP_WORDS {
            let w = cap_word(c, i) & !cleared.add(i).read();
            set_cap_word(c, i, w | set.add(i).read());
            i = i.wrapping_add(1);
        }
    }
}

/// `init_speculation_control()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86`.
unsafe fn init_speculation_control(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe {
        /*
         * The Intel SPEC_CTRL CPUID bit implies IBRS and IBPB support,
         * and they also have a different bit for STIBP support. Also,
         * a hypervisor might have set the individual AMD bits even on
         * Intel CPUs, for finer-grained selection of what's available.
         */
        if cpu_has(c, X86_FEATURE_SPEC_CTRL) {
            set_cpu_cap(c, X86_FEATURE_IBRS);
            set_cpu_cap(c, X86_FEATURE_IBPB);
            set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
        }

        if cpu_has(c, X86_FEATURE_INTEL_STIBP) {
            set_cpu_cap(c, X86_FEATURE_STIBP);
        }

        if cpu_has(c, X86_FEATURE_SPEC_CTRL_SSBD) || cpu_has(c, X86_FEATURE_VIRT_SSBD) {
            set_cpu_cap(c, X86_FEATURE_SSBD);
        }

        if cpu_has(c, X86_FEATURE_AMD_IBRS) {
            set_cpu_cap(c, X86_FEATURE_IBRS);
            set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
        }

        if cpu_has(c, X86_FEATURE_AMD_IBPB) {
            set_cpu_cap(c, X86_FEATURE_IBPB);
        }

        if cpu_has(c, X86_FEATURE_AMD_STIBP) {
            set_cpu_cap(c, X86_FEATURE_STIBP);
            set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
        }

        if cpu_has(c, X86_FEATURE_AMD_SSBD) {
            set_cpu_cap(c, X86_FEATURE_SSBD);
            set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
            clear_cpu_cap(c, X86_FEATURE_VIRT_SSBD);
        }
    }
}

/// `get_cpu_cap()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86` whose `cpuid_level` is set.
pub(crate) unsafe fn get_cpu_cap_impl(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe {
        let level = rd::<i32>(c, CI_LEVEL);

        /* Intel-defined flags: level 0x00000001 */
        if level >= 0x0000_0001 {
            let r = cpuid(0x0000_0001);
            set_cap_word(c, CPUID_1_ECX, r[2]);
            set_cap_word(c, CPUID_1_EDX, r[3]);
        }

        /* Thermal and Power Management Leaf: level 0x00000006 (eax) */
        if level >= 0x0000_0006 {
            set_cap_word(c, CPUID_6_EAX, cpuid(0x0000_0006)[0]);
        }

        /* Additional Intel-defined flags: level 0x00000007 */
        if level >= 0x0000_0007 {
            let r = cpuid_count(0x0000_0007, 0);
            set_cap_word(c, CPUID_7_0_EBX, r[1]);
            set_cap_word(c, CPUID_7_ECX, r[2]);
            set_cap_word(c, CPUID_7_EDX, r[3]);

            /* Check valid sub-leaf index before accessing it */
            if r[0] >= 1 {
                let r1 = cpuid_count(0x0000_0007, 1);
                set_cap_word(c, CPUID_7_1_EAX, r1[0]);
            }
        }

        /* Extended state features: level 0x0000000d */
        if level >= 0x0000_000d {
            set_cap_word(c, CPUID_D_1_EAX, cpuid_count(0x0000_000d, 1)[0]);
        }

        /*
         * Check if extended CPUID leaves are implemented: Max extended
         * CPUID leaf must be in the 0x80000001-0x8000ffff range.
         */
        let eax = cpuid(0x8000_0000)[0];
        let ext = if (eax & 0xffff_0000) == 0x8000_0000 { eax } else { 0 };
        wr::<u32>(c, CI_EXT_LEVEL, ext);

        if ext >= 0x8000_0001 {
            let r = cpuid(0x8000_0001);
            set_cap_word(c, CPUID_8000_0001_ECX, r[2]);
            set_cap_word(c, CPUID_8000_0001_EDX, r[3]);
        }

        if ext >= 0x8000_0007 {
            let r = cpuid(0x8000_0007);
            set_cap_word(c, CPUID_8000_0007_EBX, r[1]);
            wr::<i32>(c, CI_POWER, r[3] as i32);
        }

        if ext >= 0x8000_0008 {
            set_cap_word(c, CPUID_8000_0008_EBX, cpuid(0x8000_0008)[1]);
        }

        if ext >= 0x8000_000a {
            set_cap_word(c, CPUID_8000_000A_EDX, cpuid(0x8000_000a)[3]);
        }

        if ext >= 0x8000_001f {
            set_cap_word(c, CPUID_8000_001F_EAX, cpuid(0x8000_001f)[0]);
        }

        if ext >= 0x8000_0021 {
            set_cap_word(c, CPUID_8000_0021_EAX, cpuid(0x8000_0021)[0]);
        }

        init_scattered_cpuid_features(c);
        init_speculation_control(c);

        /*
         * Clear/Set all flags overridden by options, after probe.
         * This needs to happen each time we re-probe, which may happen
         * several times during CPU initialization.
         */
        apply_forced_caps_impl(c);
    }
}

// ---- get_cpu_address_sizes, filter_cpuid_features -------------------------------------------------------------------------------

/// `get_cpu_address_sizes()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86` whose `extended_cpuid_level` is set.
pub(crate) unsafe fn get_cpu_address_sizes_impl(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe {
        // `!cpu_has(c, X86_FEATURE_CPUID)` is the constant false (a required feature, CPUID_IS_REQUIRED).
        if rd::<u32>(c, CI_EXT_LEVEL) < 0x8000_0008 {
            wr::<u16>(c, CI_CLFLUSH, 64);
            wr::<u8>(c, CI_PHYS_BITS, 36);
            wr::<u8>(c, CI_VIRT_BITS, 48);
        } else {
            let eax = cpuid(0x8000_0008)[0];

            wr::<u8>(c, CI_VIRT_BITS, ((eax >> 8) & 0xff) as u8);
            wr::<u8>(c, CI_PHYS_BITS, (eax & 0xff) as u8);

            /* Provide a sane default if not enumerated: */
            if rd::<u16>(c, CI_CLFLUSH) == 0 {
                wr::<u16>(c, CI_CLFLUSH, 32);
            }
        }

        let phys = rd::<u8>(c, CI_PHYS_BITS);
        wr::<u8>(c, CI_CACHE_BITS, phys);
        let cl = rd::<u16>(c, CI_CLFLUSH);
        wr::<i32>(c, CI_CACHE_ALIGN, cl as i32);
    }
}

/// `cpuid_dependent_features[]`: feature, CPUID level (`struct cpuid_dependent_feature`).
static CPUID_DEPENDENT_FEATURES: [(u32, u32); 3] = [
    (X86_FEATURE_MWAIT, CPUID_LEAF_MWAIT),
    (X86_FEATURE_DCA, CPUID_LEAF_DCA),
    (X86_FEATURE_XSAVE, CPUID_LEAF_XSTATE),
];

/// `filter_cpuid_features()`.
///
/// # Safety
/// `c` is a writable `struct cpuinfo_x86` with `cpuid_level` and `extended_cpuid_level` set.
pub(crate) unsafe fn filter_cpuid_features_impl(c: *mut u8, warn: bool) {
    // SAFETY: caller contract.
    unsafe {
        let mut k = 0usize;
        while k < CPUID_DEPENDENT_FEATURES.len() {
            let (feature, level) = CPUID_DEPENDENT_FEATURES[k];
            k = k.wrapping_add(1);

            if !cpu_has(c, feature) {
                continue;
            }
            /*
             * Note: cpuid_level is set to -1 if unavailable, but
             * extended_extended_level is set to 0 if unavailable
             * and the legitimate extended levels are all negative
             * when signed; hence the weird messing around with
             * signs here...
             */
            let unavailable = if (level as i32) < 0 {
                level > rd::<u32>(c, CI_EXT_LEVEL)
            } else {
                (level as i32) > rd::<i32>(c, CI_LEVEL)
            };
            if !unavailable {
                continue;
            }

            clear_cpu_cap(c, feature);
            if !warn {
                continue;
            }

            _printk(c"\x014CPU: CPU feature %s disabled, no CPUID level 0x%x\n".as_ptr(), x86_cap_flags.as_ptr().add(feature as usize).read(), level);
        }
    }
}

// ---- cpu_set_bug_bits ----------------------------------------------------------------------------------------------------------

/// `cpu_matches()`: the entry of `table` matching the boot CPU, and its `driver_data` has a bit of `which`.
///
/// # Safety
/// `table` is a `{}`-terminated `struct x86_cpu_id` table.
unsafe fn cpu_matches(table: *const u8, which: u64) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let m = x86_match_cpu(table);
        !m.is_null() && (m.add(XCI_DRIVER_DATA).cast::<u64>().read() & which) != 0
    }
}

/// `arch_cap_mmio_immune()`.
fn arch_cap_mmio_immune(m: u64) -> bool {
    (m & ARCH_CAP_FBSDP_NO != 0) && (m & ARCH_CAP_PSDP_NO != 0) && (m & ARCH_CAP_SBDR_SSDP_NO != 0)
}

/// `boot_cpu_has(bit)` for a bit that is not a required feature.
///
/// # Safety
/// Boot CPU, early.
unsafe fn boot_cpu_has(bit: u32) -> bool {
    // SAFETY: the kernel's own global.
    unsafe { cpu_has((&raw const boot_cpu_data) as *const u8, bit) }
}

/// `vulnerable_to_rfds()`.
///
/// # Safety
/// Boot CPU, early.
unsafe fn vulnerable_to_rfds(m: u64) -> bool {
    /* The "immunity" bit trumps everything else: */
    if m & ARCH_CAP_RFDS_NO != 0 {
        return false;
    }

    /*
     * VMMs set ARCH_CAP_RFDS_CLEAR for processors not in the blacklist to
     * indicate that mitigation is needed because guest is running on a
     * vulnerable hardware or may migrate to such hardware:
     */
    if m & ARCH_CAP_RFDS_CLEAR != 0 {
        return true;
    }

    /* Only consult the blacklist when there is no enumeration: */
    // SAFETY: boot CPU; the table is the glue's.
    unsafe { cpu_matches((&raw const cpu_vuln_blacklist) as *const u8, RFDS) }
}

/// `vulnerable_to_its()`.
///
/// # Safety
/// Boot CPU, early.
unsafe fn vulnerable_to_its(m: u64) -> bool {
    // SAFETY: boot CPU; the table is the glue's.
    unsafe {
        /* The "immunity" bit trumps everything else: */
        if m & ARCH_CAP_ITS_NO != 0 {
            return false;
        }
        if rd::<u8>((&raw const boot_cpu_data) as *const u8, CI_VENDOR) != X86_VENDOR_INTEL {
            return false;
        }

        /* None of the affected CPUs have BHI_CTRL */
        if boot_cpu_has(X86_FEATURE_BHI_CTRL) {
            return false;
        }

        /*
         * If a VMM did not expose ITS_NO, assume that a guest could
         * be running on a vulnerable hardware or may migrate to such
         * hardware.
         */
        if boot_cpu_has(X86_FEATURE_HYPERVISOR) {
            return true;
        }

        cpu_matches((&raw const cpu_vuln_blacklist) as *const u8, ITS)
    }
}

/// `cpu_has_old_microcode()`.
///
/// # Safety
/// Boot CPU, early.
unsafe fn cpu_has_old_microcode() -> bool {
    // SAFETY: boot CPU; the table is the glue's.
    unsafe {
        let b = (&raw const boot_cpu_data) as *const u8;
        let m = x86_match_cpu((&raw const cpu_latest_microcode) as *const u8);

        /* Give unknown CPUs a pass: */
        if m.is_null() {
            /* Intel CPUs should be in the list. Warn if not: */
            if rd::<u8>(b, CI_VENDOR) == X86_VENDOR_INTEL {
                _printk(c"\x016x86/CPU: Model not found in latest microcode list\n".as_ptr());
            }
            return false;
        }

        /*
         * Hosts usually lie to guests with a super high microcode
         * version. Just ignore what hosts tell guests:
         */
        if boot_cpu_has(X86_FEATURE_HYPERVISOR) {
            return false;
        }

        /* Consider all debug microcode to be old: */
        let ucode = rd::<u32>(b, CI_MICROCODE);
        if ucode & (1 << 31) != 0 {
            return true;
        }

        /* Give new microcode a pass: */
        if ucode as u64 >= m.add(XCI_DRIVER_DATA).cast::<u64>().read() {
            return false;
        }

        /* Uh oh, too old: */
        true
    }
}

/// `cpu_set_bug_bits()`: which of the CPU vulnerability bugs this boot CPU has (a boot-CPU-only `__init` function).
///
/// # Safety
/// `c` is `boot_cpu_data`; boot CPU, early.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn cpu_set_bug_bits_impl(c: *mut u8) {
    // SAFETY: boot CPU; the tables are the glue's.
    unsafe {
        let m = x86_read_arch_cap_msr();
        let (wl, bl) = ((&raw const cpu_vuln_whitelist) as *const u8, (&raw const cpu_vuln_blacklist) as *const u8);
        let cv = c as *const u8;

        if cpu_has_old_microcode() {
            _printk(c"\x014x86/CPU: Running old microcode\n".as_ptr());
            setup_force_cpu_cap(X86_BUG_OLD_MICROCODE, false);
            add_taint(TAINT_CPU_OUT_OF_SPEC, LOCKDEP_STILL_OK);
        }

        /* Set ITLB_MULTIHIT bug if cpu is not in the whitelist and not mitigated */
        if !cpu_matches(wl, NO_ITLB_MULTIHIT) && (m & ARCH_CAP_PSCHANGE_MC_NO) == 0 {
            setup_force_cpu_cap(X86_BUG_ITLB_MULTIHIT, false);
        }

        if cpu_matches(wl, NO_SPECULATION) {
            return;
        }

        setup_force_cpu_cap(X86_BUG_SPECTRE_V1, false);

        if !cpu_matches(wl, NO_SPECTRE_V2) {
            setup_force_cpu_cap(X86_BUG_SPECTRE_V2, false);
            setup_force_cpu_cap(X86_BUG_SPECTRE_V2_USER, false);
        }

        if !cpu_matches(wl, NO_SSB) && (m & ARCH_CAP_SSB_NO) == 0 && !cpu_has(cv, X86_FEATURE_AMD_SSB_NO) {
            setup_force_cpu_cap(X86_BUG_SPEC_STORE_BYPASS, false);
        }

        /*
         * AMD's AutoIBRS is equivalent to Intel's eIBRS - use the Intel feature
         * flag and protect from vendor-specific bugs via the whitelist.
         *
         * Don't use AutoIBRS when SNP is enabled because it degrades host
         * userspace indirect branch performance.
         */
        if (m & ARCH_CAP_IBRS_ALL) != 0 || (cpu_has(cv, X86_FEATURE_AUTOIBRS) && !cpu_feature_enabled_sev_snp()) {
            setup_force_cpu_cap(X86_FEATURE_IBRS_ENHANCED, false);
            if !cpu_matches(wl, NO_EIBRS_PBRSB) && (m & ARCH_CAP_PBRSB_NO) == 0 {
                setup_force_cpu_cap(X86_BUG_EIBRS_PBRSB, false);
            }
        }

        if !cpu_matches(wl, NO_MDS) && (m & ARCH_CAP_MDS_NO) == 0 {
            setup_force_cpu_cap(X86_BUG_MDS, false);
            if cpu_matches(wl, MSBDS_ONLY) {
                setup_force_cpu_cap(X86_BUG_MSBDS_ONLY, false);
            }
        }

        if !cpu_matches(wl, NO_SWAPGS) {
            setup_force_cpu_cap(X86_BUG_SWAPGS, false);
        }

        /*
         * When the CPU is not mitigated for TAA (TAA_NO=0) set TAA bug when:
         *	- TSX is supported or
         *	- TSX_CTRL is present
         *
         * TSX_CTRL check is needed for cases when TSX could be disabled before
         * the kernel boot e.g. kexec.
         * TSX_CTRL check alone is not sufficient for cases when the microcode
         * update is not present or running as guest that don't get TSX_CTRL.
         */
        if (m & ARCH_CAP_TAA_NO) == 0 && (cpu_has(cv, X86_FEATURE_RTM) || (m & ARCH_CAP_TSX_CTRL_MSR) != 0) {
            setup_force_cpu_cap(X86_BUG_TAA, false);
        }

        /*
         * SRBDS affects CPUs which support RDRAND or RDSEED and are listed
         * in the vulnerability blacklist.
         *
         * Some of the implications and mitigation of Shared Buffers Data
         * Sampling (SBDS) are similar to SRBDS. Give SBDS same treatment as
         * SRBDS.
         */
        if (cpu_has(cv, X86_FEATURE_RDRAND) || cpu_has(cv, X86_FEATURE_RDSEED)) && cpu_matches(bl, SRBDS | MMIO_SBDS) {
            setup_force_cpu_cap(X86_BUG_SRBDS, false);
        }

        /*
         * Processor MMIO Stale Data bug enumeration
         *
         * Affected CPU list is generally enough to enumerate the vulnerability,
         * but for virtualization case check for ARCH_CAP MSR bits also, VMM may
         * not want the guest to enumerate the bug.
         */
        if !arch_cap_mmio_immune(m) && cpu_matches(bl, MMIO) {
            setup_force_cpu_cap(X86_BUG_MMIO_STALE_DATA, false);
        }

        if !cpu_has(cv, X86_FEATURE_BTC_NO) && (cpu_matches(bl, RETBLEED) || (m & ARCH_CAP_RSBA) != 0) {
            setup_force_cpu_cap(X86_BUG_RETBLEED, false);
        }

        if cpu_matches(bl, SMT_RSB) {
            setup_force_cpu_cap(X86_BUG_SMT_RSB, false);
        }

        if !cpu_has(cv, X86_FEATURE_SRSO_NO) && cpu_matches(bl, SRSO) {
            setup_force_cpu_cap(X86_BUG_SRSO, false);
        }

        /*
         * Check if CPU is vulnerable to GDS. If running in a virtual machine on
         * an affected processor, the VMM may have disabled the use of GATHER by
         * disabling AVX2. The only way to do this in HW is to clear XCR0[2],
         * which means that AVX will be disabled.
         */
        if cpu_matches(bl, GDS) && (m & ARCH_CAP_GDS_NO) == 0 && boot_cpu_has(X86_FEATURE_AVX) {
            setup_force_cpu_cap(X86_BUG_GDS, false);
        }

        if vulnerable_to_rfds(m) {
            setup_force_cpu_cap(X86_BUG_RFDS, false);
        }

        /*
         * Intel parts with eIBRS are vulnerable to BHI attacks. Parts with
         * BHI_NO still need to use the BHI mitigation to prevent Intra-mode
         * attacks.  When virtualized, eIBRS could be hidden, assume vulnerable.
         */
        if !cpu_matches(wl, NO_BHI) && (boot_cpu_has(X86_FEATURE_IBRS_ENHANCED) || boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
            setup_force_cpu_cap(X86_BUG_BHI, false);
        }

        if cpu_has(cv, X86_FEATURE_AMD_IBPB) && !cpu_has(cv, X86_FEATURE_AMD_IBPB_RET) {
            setup_force_cpu_cap(X86_BUG_IBPB_NO_RET, false);
        }

        if vulnerable_to_its(m) {
            setup_force_cpu_cap(X86_BUG_ITS, false);
            if cpu_matches(bl, ITS_NATIVE_ONLY) {
                setup_force_cpu_cap(X86_BUG_ITS_NATIVE_ONLY, false);
            }
        }

        if rd::<u8>(cv, CI_VENDOR) == X86_VENDOR_AMD && (!cpu_has(cv, X86_FEATURE_TSA_SQ_NO) || !cpu_has(cv, X86_FEATURE_TSA_L1_NO)) {
            /* Enable bug on Zen guests to allow for live migration. */
            if cpu_matches(bl, TSA) || (cpu_has(cv, X86_FEATURE_HYPERVISOR) && cpu_has(cv, X86_FEATURE_ZEN)) {
                setup_force_cpu_cap(X86_BUG_TSA, false);
            }
        }

        /*
         * Set the bug only on bare-metal. A nested hypervisor should already be
         * deploying IBPB to isolate itself from nested guests.
         */
        if cpu_matches(bl, VMSCAPE) && !boot_cpu_has(X86_FEATURE_HYPERVISOR) {
            setup_force_cpu_cap(X86_BUG_VMSCAPE, false);
        }

        if cpu_matches(wl, NO_MELTDOWN) {
            return;
        }

        /* Rogue Data Cache Load? No! */
        if (m & ARCH_CAP_RDCL_NO) != 0 {
            return;
        }

        setup_force_cpu_cap(X86_BUG_CPU_MELTDOWN, false);

        if cpu_matches(wl, NO_L1TF) {
            return;
        }

        setup_force_cpu_cap(X86_BUG_L1TF, false);
    }
}

/// `cpu_feature_enabled(X86_FEATURE_SEV_SNP)`: the constant 0 without `CONFIG_KVM_AMD_SEV` (the feature is a DISABLED one then).
///
/// # Safety
/// Boot CPU, early.
#[cfg(not(CONFIG_KVM_AMD_SEV))]
#[inline(always)]
unsafe fn cpu_feature_enabled_sev_snp() -> bool {
    false
}
/// `cpu_feature_enabled(X86_FEATURE_SEV_SNP)`: the run-time test of `boot_cpu_data` (`static_cpu_has()` falls back to it before the
/// alternatives are patched, and this runs before).
///
/// # Safety
/// Boot CPU, early.
#[cfg(CONFIG_KVM_AMD_SEV)]
#[inline(always)]
unsafe fn cpu_feature_enabled_sev_snp() -> bool {
    // SAFETY: boot CPU.
    unsafe { boot_cpu_has(X86_FEATURE_SEV_SNP) }
}

// ---- command line ----------------------------------------------------------------------------------------------------------------

/// `setup_clear_cpu_cap(bit)` / `setup_force_cpu_cap(bit)` selected by `set`; `bit` is a run-time value.
///
/// # Safety
/// Boot CPU, early.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
unsafe fn force_or_clear(bit: u32, set: bool) {
    // SAFETY: boot CPU.
    unsafe {
        if set {
            setup_force_cpu_cap(bit, false);
        } else {
            setup_clear_cpu_cap(bit);
        }
    }
}

/// `parse_set_clear_cpuid()`: `clearcpuid=` / `setcpuid=` (a comma-separated list of feature numbers or names). Returns the number of
/// flags changed (the C returns it as `bool`; the caller only tests non-zero).
///
/// # Safety
/// `arg` is a writable NUL-terminated string (it is cut at the commas).
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn parse_set_clear_cpuid(arg: *mut c_char, set: bool) -> bool {
    // SAFETY: caller contract; the flag tables have NCAPINTS*32 / NBUGINTS*32 entries.
    unsafe {
        let mut arg = arg;
        let mut taint: i32 = 0;

        while !arg.is_null() {
            let mut found = false;
            let mut bit: u32 = 0;

            let opt = strsep(&mut arg, c",".as_ptr());

            /*
             * Handle naked numbers first for feature flags which don't
             * have names. It doesn't make sense for a bug not to have a
             * name so don't handle bug flags here.
             */
            if kstrtouint(opt, 10, &mut bit) == 0 {
                if bit < (NCAPINTS * 32) as u32 {
                    if set {
                        _printk(c"\x014setcpuid: force-enabling CPU feature flag:".as_ptr());
                    } else {
                        _printk(c"\x014clearcpuid: force-disabling CPU feature flag:".as_ptr());
                    }
                    force_or_clear(bit, set);
                    /* empty-string, i.e., ""-defined feature flags */
                    let name = x86_cap_flags.as_ptr().add(bit as usize).read();
                    if name.is_null() {
                        _printk(c"\x01c %d:%d\n".as_ptr(), (bit >> 5) as i32, (bit & 31) as i32);
                    } else {
                        _printk(c"\x01c %s\n".as_ptr(), name);
                    }

                    taint = taint.wrapping_add(1);
                }
                /*
                 * The assumption is that there are no feature names with only
                 * numbers in the name thus go to the next argument.
                 */
                continue;
            }

            bit = 0;
            while bit < (32 * (NCAPINTS + NBUGINTS)) as u32 {
                let (flag, kind): (*const c_char, *const c_char) = if bit < (32 * NCAPINTS) as u32 {
                    (x86_cap_flags.as_ptr().add(bit as usize).read(), c"feature".as_ptr())
                } else {
                    (x86_bug_flags.as_ptr().add((bit - (32 * NCAPINTS) as u32) as usize).read(), c"bug".as_ptr())
                };

                if flag.is_null() {
                    bit = bit.wrapping_add(1);
                    continue;
                }

                if strcmp(flag, opt) != 0 {
                    bit = bit.wrapping_add(1);
                    continue;
                }

                if set {
                    _printk(c"\x014setcpuid: force-enabling CPU %s flag: %s\n".as_ptr(), kind, flag);
                } else {
                    _printk(c"\x014clearcpuid: force-disabling CPU %s flag: %s\n".as_ptr(), kind, flag);
                }
                force_or_clear(bit, set);
                taint = taint.wrapping_add(1);
                found = true;
                break;
            }

            if !found {
                _printk(c"\x014%s: unknown CPU flag: %s".as_ptr(), if set { c"setcpuid".as_ptr() } else { c"clearcpuid".as_ptr() }, opt);
            }
        }

        taint != 0
    }
}

/// `cpu_parse_early_param()`: the options that must be known before `parse_early_param()` runs.
///
/// # Safety
/// Boot CPU, early; `boot_command_line` is set.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn cpu_parse_early_param() {
    // SAFETY: boot CPU.
    unsafe {
        let mut cpuid_taint = false;
        let mut arg: [c_char; 128] = [0; 128];
        let cmd = (&raw const boot_command_line) as *const c_char;

        if cmdline_find_option_bool(cmd, c"noxsave".as_ptr()) != 0 {
            setup_clear_cpu_cap(X86_FEATURE_XSAVE);
        }

        if cmdline_find_option_bool(cmd, c"noxsaveopt".as_ptr()) != 0 {
            setup_clear_cpu_cap(X86_FEATURE_XSAVEOPT);
        }

        if cmdline_find_option_bool(cmd, c"noxsaves".as_ptr()) != 0 {
            setup_clear_cpu_cap(X86_FEATURE_XSAVES);
        }

        if cmdline_find_option_bool(cmd, c"nousershstk".as_ptr()) != 0 {
            setup_clear_cpu_cap(X86_FEATURE_USER_SHSTK);
        }

        /* Minimize the gap between FRED is available and available but disabled. */
        let arglen = cmdline_find_option(cmd, c"fred".as_ptr(), arg.as_mut_ptr(), 128);
        // `strncmp(arg, "on", 2)`: the first two bytes are 'o', 'n'
        if arglen != 2 || arg[0] != b'o' as c_char || arg[1] != b'n' as c_char {
            setup_clear_cpu_cap(X86_FEATURE_FRED);
        }

        let arglen = cmdline_find_option(cmd, c"clearcpuid".as_ptr(), arg.as_mut_ptr(), 128);
        if arglen > 0 {
            cpuid_taint |= parse_set_clear_cpuid(arg.as_mut_ptr(), false);
        }

        let arglen = cmdline_find_option(cmd, c"setcpuid".as_ptr(), arg.as_mut_ptr(), 128);
        if arglen > 0 {
            cpuid_taint |= parse_set_clear_cpuid(arg.as_mut_ptr(), true);
        }

        if cpuid_taint {
            _printk(c"\x014!!! setcpuid=/clearcpuid= in use, this is for TESTING ONLY, may break things horribly. Tainting kernel.\n".as_ptr());
            add_taint(TAINT_CPU_OUT_OF_SPEC, LOCKDEP_STILL_OK);
        }
    }
}

// ---- early identification ------------------------------------------------------------------------------------------------------

/// `detect_nopl()`: on x86-64 force the NOPL capability.
///
/// # Safety
/// Boot CPU, early.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn detect_nopl() {
    // SAFETY: boot CPU. NOPL is a required feature (no warning arm).
    unsafe { setup_force_cpu_cap(X86_FEATURE_NOPL, true) };
}

/// `early_identify_cpu()`: do minimum CPU detection early. Fields really needed: vendor, cpuid_level, family, model, mask, cache
/// alignment. WARNING (upstream): only called on the boot CPU.
///
/// # Safety
/// `c` is `boot_cpu_data`; boot CPU, early. On x86-64 `cpuid_feature()` is the constant true, so the no-CPUID arms of the C are not here.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn early_identify_cpu_impl(c: *mut u8) {
    // SAFETY: boot CPU.
    unsafe {
        let mut i = 0usize;
        while i < CAP_WORDS {
            set_cap_word(c, i, 0);
            i = i.wrapping_add(1);
        }
        wr::<u32>(c, CI_EXT_LEVEL, 0);

        /* cyrix could have cpuid enabled via c_identify()*/
        cpu_detect_impl(c);
        get_cpu_vendor_impl(c);
        #[cfg(CONFIG_CPU_SUP_INTEL)]
        intel_unlock_cpuid_leafs(c);
        get_cpu_cap_impl(c);
        setup_force_cpu_cap(X86_FEATURE_CPUID, true);
        get_cpu_address_sizes_impl(c);
        cpu_parse_early_param();

        cpu_init_topology(c);

        let early: CpuFn = this_cpu.add(CD_EARLY_INIT).cast::<CpuFn>().read();
        if let Some(f) = early {
            f(c);
        }

        wr::<u16>(c, CI_CPU_INDEX, 0);
        filter_cpuid_features_impl(c, false);
        check_cpufeature_deps(c);

        let bsp: CpuFn = this_cpu.add(CD_BSP_INIT).cast::<CpuFn>().read();
        if let Some(f) = bsp {
            f(c);
        }

        setup_force_cpu_cap(X86_FEATURE_ALWAYS, true);

        cpu_set_bug_bits_impl(c);

        #[cfg(CONFIG_X86_BUS_LOCK_DETECT)]
        sld_setup(c);

        /*
         * Later in the boot process pgtable_l5_enabled() relies on
         * cpu_feature_enabled(X86_FEATURE_LA57). If 5-level paging is not
         * enabled by this point we need to clear the feature bit to avoid
         * false-positives at the later stage.
         *
         * pgtable_l5_enabled() can be false here for several reasons:
         *  - 5-level paging is disabled compile-time;
         *  - it's 32-bit kernel;
         *  - machine doesn't support 5-level paging;
         *  - user specified 'no5lvl' in kernel command line.
         */
        if __pgtable_l5_enabled == 0 {
            setup_clear_cpu_cap(X86_FEATURE_LA57);
        }

        detect_nopl();
        #[cfg(CONFIG_X86_MCE)]
        mca_bsp_init(c);
    }
}

/// `init_cpu_devs()`: collect the registered `cpu_dev`s.
///
/// # Safety
/// Boot CPU, early.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn init_cpu_devs_impl() {
    // SAFETY: boot CPU; the linker-provided section bounds.
    unsafe {
        let (start, end) = ((&raw const __x86_cpu_dev_start) as *const *const u8, (&raw const __x86_cpu_dev_end) as *const *const u8);
        let mut cdev = start;
        let mut count = 0usize;
        while cdev < end {
            let cpudev = cdev.read();

            if count >= X86_VENDOR_NUM {
                break;
            }
            (&raw mut cpu_devs as *mut *const u8).add(count).write(cpudev);
            count = count.wrapping_add(1);
            cdev = cdev.add(1);
        }
    }
}

/// `early_cpu_init()`.
///
/// # Safety
/// Boot CPU, early.
#[cfg_attr(not(userspace_test), link_section = ".init.text")]
pub(crate) unsafe fn early_cpu_init_impl() {
    // SAFETY: boot CPU.
    unsafe {
        #[cfg(CONFIG_PROCESSOR_SELECT)]
        _printk(c"\x016KERNEL supported cpus:\n".as_ptr());

        init_cpu_devs_impl();

        #[cfg(CONFIG_PROCESSOR_SELECT)]
        {
            let mut i = 0usize;
            while i < X86_VENDOR_NUM && !(&raw const cpu_devs as *const *const u8).add(i).read().is_null() {
                let d = (&raw const cpu_devs as *const *const u8).add(i).read();
                let mut j = 0usize;
                while j < 2 {
                    let id = d.add(CD_IDENT).cast::<*const c_char>().add(j).read();
                    if !id.is_null() {
                        _printk(c"\x016  %s %s\n".as_ptr(), d.add(CD_VENDOR).cast::<*const c_char>().read(), id);
                    }
                    j = j.wrapping_add(1);
                }
                i = i.wrapping_add(1);
            }
        }

        early_identify_cpu_impl((&raw mut boot_cpu_data) as *mut u8);
    }
}

// ---- userspace test hooks ----------------------------------------------------------------------------------------------------------

/// Userspace test only: `pr_err_once()`'s flag, to reset and to read.
///
/// # Safety
/// Single-threaded test harness.
#[cfg(userspace_test)]
pub(crate) unsafe fn test_once(set: Option<bool>) -> bool {
    // SAFETY: harness.
    unsafe {
        if let Some(v) = set {
            VENDOR_ALREADY_DONE = v;
        }
        VENDOR_ALREADY_DONE
    }
}

// ---- C entry points ------------------------------------------------------------------------------------------------------------

// The statics of common.c that became global so that the C kept in common_glue.c and the Rust here both reach them were already hidden
// there; these Rust definitions replace `static` functions the C still calls (identify_cpu, generic_identify, store_cpu_caps), hidden so
// that after the final link they are local again like the C (`/proc/kallsyms` letter `t`).
#[cfg(not(userspace_test))]
core::arch::global_asm!(".hidden filter_cpuid_features", ".hidden apply_forced_caps");

/// `cpu_detect(c)`.
///
/// # Safety
/// As [`cpu_detect_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn cpu_detect(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe { cpu_detect_impl(c) };
}
/// `get_cpu_vendor(c)`.
///
/// # Safety
/// As [`get_cpu_vendor_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn get_cpu_vendor(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe { get_cpu_vendor_impl(c) };
}
/// `get_cpu_cap(c)`.
///
/// # Safety
/// As [`get_cpu_cap_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn get_cpu_cap(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe { get_cpu_cap_impl(c) };
}
/// `get_cpu_address_sizes(c)`.
///
/// # Safety
/// As [`get_cpu_address_sizes_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn get_cpu_address_sizes(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe { get_cpu_address_sizes_impl(c) };
}
/// `filter_cpuid_features(c, warn)` (was `static`; called by `identify_cpu()` in the glue).
///
/// # Safety
/// As [`filter_cpuid_features_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn filter_cpuid_features(c: *mut u8, warn: bool) {
    // SAFETY: caller contract.
    unsafe { filter_cpuid_features_impl(c, warn) };
}
/// `apply_forced_caps(c)` (was `static`; called by `generic_identify()`, `identify_cpu()` in the glue).
///
/// # Safety
/// As [`apply_forced_caps_impl`].
#[cfg(not(userspace_test))]
#[no_mangle]
pub unsafe extern "C" fn apply_forced_caps(c: *mut u8) {
    // SAFETY: caller contract.
    unsafe { apply_forced_caps_impl(c) };
}
/// `init_cpu_devs()`.
///
/// # Safety
/// Boot CPU, early.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn init_cpu_devs() {
    // SAFETY: caller contract.
    unsafe { init_cpu_devs_impl() };
}
/// `early_cpu_init()`.
///
/// # Safety
/// Boot CPU, early.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn early_cpu_init() {
    // SAFETY: caller contract.
    unsafe { early_cpu_init_impl() };
}

const _: () = assert!(CD_SIZE == 72 && CPUID_IS_REQUIRED == 1 && CAP_WORDS == 24);
