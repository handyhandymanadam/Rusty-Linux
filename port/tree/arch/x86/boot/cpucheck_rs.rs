// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/cpucheck.c (16-bit real-mode setup): check that the CPU has
//! the obligatory features. Exports `check_cpu()` and `check_knl_erratum()` like the C.
//!
//! `cpu` / `cpu_vendor` / `get_cpuflags()` / `has_eflag()` still live in cpuflags.c (C) and are
//! used through `extern "C"` with the C's `struct cpu_features` layout (level, family, model: int;
//! flags: u32[NCAPINTS]). The numbers (required masks, NCAPINTS, feature bits, MSR numbers, the
//! minimum family, CONFIG_X86_64/PAE) are generated at build time from the same headers the C
//! uses (cpucheck_gen.rs.in -> cpucheck_gen.rs, see the Makefile).
//!
//! Messages are byte-identical to the C (every "\n" included): "WARNING: Forcing PAE in CPU
//! flags\n", "WARNING: PAE disabled. Use parameter 'forcepae' to enable at your own risk!\n" and the
//! three-line Xeon Phi erratum text. (The C header says "this code should not contain any
//! messages"; it does, via puts().)
//!
//! Deliberate divergences from the C: (1) the Transmeta `cpuid` is a volatile asm! (the C's is a
//! non-volatile asm that the compiler may move across the surrounding wrmsr asms; same
//! instruction, same register constraints: eax in/out, edx out, ecx/ebx clobbered); (2) the C's
//! 32-bit `has_eflag()` is called only when CONFIG_X86_64 is off (it is a constant `true` in the
//! C header on x86-64). Under `--cfg host_mock` (host test build only) the msr / cpuid / puts /
//! cmdline accesses are routed to extern hooks -- never set for the target build.
//!
//! TEST-GAP: the AMD SSE-enable, VIA C3 CX8, Transmeta cpuid-mask and Pentium M forcepae branches
//! need real CPUs (AMD K7/K8 without SSE, VIA C3, Crusoe, Pentium M model 9/13): QEMU cannot
//! present them, so they run only in the host lockstep differential against mocked
//! msr/cpuid/get_cpuflags (rig/realmode/run-cpu-diff.sh). The Xeon Phi (KNL) erratum message
//! exists only in 32-bit non-PAE builds, which this tree does not build: host differential only.
//! Real `rdmsr`/`wrmsr` behaviour (#GP on absent MSRs) is not covered anywhere.
#![allow(dead_code, non_upper_case_globals)]

use core::arch::asm;
use core::ffi::{c_char, c_int};
use core::ptr::{addr_of, addr_of_mut};

include!(concat!(env!("RM_GEN_DIR"), "/cpucheck_gen.rs"));

/// `struct cpu_features` (cpuflags.h).
#[repr(C)]
pub struct CpuFeatures {
    pub level: c_int,
    pub family: c_int,
    pub model: c_int,
    pub flags: [u32; RM_NCAPINTS],
}

extern "C" {
    /// cpuflags.c
    static mut cpu: CpuFeatures;
    static cpu_vendor: [u32; 3];
    fn get_cpuflags();
    #[cfg(not(host_mock))]
    fn has_eflag(mask: u32) -> bool;
    #[cfg(host_mock)]
    #[link_name = "mock_has_eflag"]
    fn has_eflag(mask: u32) -> bool;

    #[cfg_attr(host_mock, link_name = "mock_puts")]
    fn puts(s: *const c_char);
}

#[cfg(not(host_mock))]
extern "C" {
    /// boot.h: `boot_params.hdr.cmd_line_ptr`; cmdline.c
    static boot_params: [u8; 4096];
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
}
#[cfg(host_mock)]
extern "C" {
    fn mock_cmdline_find_option_bool(option: *const c_char) -> c_int;
    fn mock_cpuid1(level: u32, edx: *mut u32) -> u32;
    fn mock_rdmsr(reg: u32, l: *mut u32, h: *mut u32);
    fn mock_wrmsr(reg: u32, l: u32, h: u32);
}

/// boot.h's inline `cmdline_find_option_bool()`: -1 if the command line is inaccessible
/// (cmd_line_ptr >= 1 MiB; offsetof(struct boot_params, hdr.cmd_line_ptr) == 0x228).
#[cfg(not(host_mock))]
#[inline(always)]
unsafe fn cmdline_find_option_bool(option: *const c_char) -> c_int {
    // SAFETY: boot_params is the zero page; the field is u32 at 0x228 (naturally aligned).
    unsafe {
        let p = (addr_of!(boot_params) as *const u8).add(0x228) as *const u32;
        let cmd_line_ptr = p.read();
        if cmd_line_ptr >= 0x100000 {
            return -1;
        }
        __cmdline_find_option_bool(cmd_line_ptr, option)
    }
}
#[cfg(host_mock)]
#[inline(always)]
unsafe fn cmdline_find_option_bool(option: *const c_char) -> c_int {
    unsafe { mock_cmdline_find_option_bool(option) }
}

/// boot_rdmsr(): `rdmsr` with ecx = reg -> (eax, edx).
#[cfg(not(host_mock))]
#[inline(always)]
unsafe fn boot_rdmsr(reg: u32) -> (u32, u32) {
    let (l, h): (u32, u32);
    unsafe { asm!("rdmsr", in("ecx") reg, out("eax") l, out("edx") h, options(nostack, preserves_flags)) };
    (l, h)
}
/// boot_wrmsr(): `wrmsr` with ecx = reg, eax = l, edx = h; memory clobbered (default).
#[cfg(not(host_mock))]
#[inline(always)]
unsafe fn boot_wrmsr(reg: u32, l: u32, h: u32) {
    unsafe { asm!("wrmsr", in("ecx") reg, in("eax") l, in("edx") h, options(nostack, preserves_flags)) };
}
#[cfg(host_mock)]
#[inline(always)]
unsafe fn boot_rdmsr(reg: u32) -> (u32, u32) {
    let (mut l, mut h) = (0u32, 0u32);
    unsafe { mock_rdmsr(reg, &mut l, &mut h) };
    (l, h)
}
#[cfg(host_mock)]
#[inline(always)]
unsafe fn boot_wrmsr(reg: u32, l: u32, h: u32) {
    unsafe { mock_wrmsr(reg, l, h) }
}

/// `asm("cpuid" : "+a"(level), "=d"(edx) : : "ecx", "ebx")`: returns edx, level (eax) is dropped.
#[cfg(not(host_mock))]
#[inline(always)]
unsafe fn cpuid_level1_edx(level: u32) -> u32 {
    let edx: u32;
    unsafe {
        asm!("cpuid", inout("eax") level => _, out("edx") edx, out("ecx") _, out("ebx") _,
             options(nostack, nomem, preserves_flags));
    }
    edx
}
#[cfg(host_mock)]
#[inline(always)]
unsafe fn cpuid_level1_edx(level: u32) -> u32 {
    let mut edx = 0u32;
    unsafe { mock_cpuid1(level, &mut edx) };
    edx
}

const req_level: c_int = RM_CONFIG_X86_MINIMUM_CPU_FAMILY;

static req_flags: [u32; RM_NCAPINTS] = {
    let mut a = [0u32; RM_NCAPINTS];
    a[0] = RM_REQUIRED_MASK0;
    a[1] = RM_REQUIRED_MASK1;
    // 2, 3: REQUIRED_MASK2/3 not implemented in this file
    a[4] = RM_REQUIRED_MASK4;
    // 5: not implemented
    a[6] = RM_REQUIRED_MASK6;
    // 7..15: not implemented
    a[16] = RM_REQUIRED_MASK16;
    a
};

/// `static u32 err_flags[NCAPINTS];` (plain .bss).
#[link_section = ".bss"]
static mut err_flags: [u32; RM_NCAPINTS] = [0; RM_NCAPINTS];

const fn a32(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((d as u32) << 24) + ((c as u32) << 16) + ((b as u32) << 8) + (a as u32)
}

#[inline(always)]
unsafe fn vendor_is(a: u32, b: u32, c: u32) -> bool {
    unsafe { cpu_vendor[0] == a && cpu_vendor[1] == b && cpu_vendor[2] == c }
}
#[inline(always)]
unsafe fn is_amd() -> bool {
    unsafe { vendor_is(a32(b'A', b'u', b't', b'h'), a32(b'e', b'n', b't', b'i'), a32(b'c', b'A', b'M', b'D')) }
}
#[inline(always)]
unsafe fn is_centaur() -> bool {
    unsafe { vendor_is(a32(b'C', b'e', b'n', b't'), a32(b'a', b'u', b'r', b'H'), a32(b'a', b'u', b'l', b's')) }
}
#[inline(always)]
unsafe fn is_transmeta() -> bool {
    unsafe { vendor_is(a32(b'G', b'e', b'n', b'u'), a32(b'i', b'n', b'e', b'T'), a32(b'M', b'x', b'8', b'6')) }
}
#[inline(always)]
unsafe fn is_intel() -> bool {
    unsafe { vendor_is(a32(b'G', b'e', b'n', b'u'), a32(b'i', b'n', b'e', b'I'), a32(b'n', b't', b'e', b'l')) }
}

#[inline(always)]
unsafe fn flags_ptr() -> *mut [u32; RM_NCAPINTS] {
    unsafe { addr_of_mut!(cpu.flags) }
}
#[inline(always)]
unsafe fn test_bit(nr: u32) -> bool {
    unsafe { ((*flags_ptr())[(nr >> 5) as usize] >> (nr & 31)) & 1 != 0 }
}
#[inline(always)]
unsafe fn set_bit(nr: u32) {
    unsafe { (*flags_ptr())[(nr >> 5) as usize] |= 1u32 << (nr & 31) }
}

/// Returns a bitmask of which words we have error bits in.
unsafe fn check_cpuflags() -> c_int {
    let mut err: u32 = 0;
    unsafe {
        let ef = addr_of_mut!(err_flags) as *mut u32;
        let fl = flags_ptr() as *const u32;
        let mut i = 0usize;
        while i < RM_NCAPINTS {
            let e = req_flags[i] & !*fl.add(i);
            *ef.add(i) = e;
            if e != 0 {
                err |= 1u32 << i;
            }
            i += 1;
        }
    }
    err as c_int
}

#[inline(always)]
unsafe fn flags0() -> u32 {
    unsafe { (*flags_ptr())[0] }
}

/// Returns -1 on error. `*cpu_level_ptr` = current CPU level (64 for x86-64), `*req_level_ptr` =
/// required level, `*err_flags_ptr` = the missing-flags array if flags are missing, else NULL.
#[no_mangle]
pub unsafe extern "C" fn check_cpu(
    cpu_level_ptr: *mut c_int,
    req_level_ptr: *mut c_int,
    err_flags_ptr: *mut *mut u32,
) -> c_int {
    unsafe {
        let mut err: c_int;

        core::ptr::write_bytes(flags_ptr() as *mut u32, 0, RM_NCAPINTS);
        cpu.level = 3;

        if IS_X86_64 || has_eflag(RM_X86_EFLAGS_AC) {
            cpu.level = 4;
        }

        get_cpuflags();
        err = check_cpuflags();

        if test_bit(RM_X86_FEATURE_LM) {
            cpu.level = 64;
        }

        let ef0 = || *(addr_of!(err_flags) as *const u32);
        if err == 0x01 && (ef0() & !((1u32 << RM_X86_FEATURE_XMM) | (1u32 << RM_X86_FEATURE_XMM2))) == 0 && is_amd() {
            // AMD missing only SSE+SSE2: try to turn them on
            let (mut l, h) = boot_rdmsr(RM_MSR_K7_HWCR);
            l &= !(1u32 << 15);
            boot_wrmsr(RM_MSR_K7_HWCR, l, h);

            get_cpuflags(); // Make sure it really did something
            err = check_cpuflags();
        } else if err == 0x01 && (ef0() & !(1u32 << RM_X86_FEATURE_CX8)) == 0 && is_centaur() && cpu.model >= 6 {
            // VIA C3: might have to enable CX8 explicitly
            let (mut l, h) = boot_rdmsr(RM_MSR_VIA_FCR);
            l |= (1 << 1) | (1 << 7);
            boot_wrmsr(RM_MSR_VIA_FCR, l, h);

            set_bit(RM_X86_FEATURE_CX8);
            err = check_cpuflags();
        } else if err == 0x01 && is_transmeta() {
            // Transmeta might have masked feature bits in word 0
            let (l, h) = boot_rdmsr(0x80860004);
            boot_wrmsr(0x80860004, !0u32, h);
            (*flags_ptr())[0] = cpuid_level1_edx(1);
            boot_wrmsr(0x80860004, l, h);

            err = check_cpuflags();
        } else if err == 0x01
            && (ef0() & !(1u32 << RM_X86_FEATURE_PAE)) == 0
            && is_intel()
            && cpu.level == 6
            && (cpu.model == 9 || cpu.model == 13)
        {
            // PAE is disabled on this Pentium M but can be forced
            if cmdline_find_option_bool(b"forcepae\0".as_ptr() as *const c_char) != 0 {
                puts(b"WARNING: Forcing PAE in CPU flags\n\0".as_ptr() as *const c_char);
                set_bit(RM_X86_FEATURE_PAE);
                err = check_cpuflags();
            } else {
                puts(b"WARNING: PAE disabled. Use parameter 'forcepae' to enable at your own risk!\n\0".as_ptr()
                    as *const c_char);
            }
        }
        if err == 0 {
            err = check_knl_erratum();
        }

        if !err_flags_ptr.is_null() {
            *err_flags_ptr = if err != 0 { addr_of_mut!(err_flags) as *mut u32 } else { core::ptr::null_mut() };
        }
        if !cpu_level_ptr.is_null() {
            *cpu_level_ptr = cpu.level;
        }
        if !req_level_ptr.is_null() {
            *req_level_ptr = req_level;
        }

        if cpu.level < req_level || err != 0 { -1 } else { 0 }
    }
}

#[no_mangle]
pub unsafe extern "C" fn check_knl_erratum() -> c_int {
    unsafe {
        // First check for the affected model/family:
        if !is_intel() || cpu.family != 6 || cpu.model != 0x57 /*INTEL_XEON_PHI_KNL*/ {
            return 0;
        }

        // This erratum affects the Accessed/Dirty bits, and can cause stray bits to be set in
        // !Present PTEs. We have enough bits in our 64-bit PTEs (real 64-bit mode or PAE), but not
        // in 32-bit PTEs: refuse to run on 32-bit non-PAE kernels.
        if IS_X86_64 || IS_X86_PAE {
            return 0;
        }

        puts(
            b"This 32-bit kernel can not run on this Xeon Phi x200\nprocessor due to a processor erratum.  Use a 64-bit\nkernel, or enable PAE in this 32-bit kernel.\n\n\0"
                .as_ptr() as *const c_char,
        );
        -1
    }
}
