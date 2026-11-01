// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/cpuflags.c in the 16-bit real-mode setup (code16, -Zregparm=3).
//! Exports exactly what the C object of this build exports: the data `cpu` (struct cpu_features) and
//! `cpu_vendor[3]`, and the functions `get_cpuflags()` and `cpuid_count()`. (`has_cpuflag()` is not
//! part of the real-mode object -- it lives in compressed/cpuflags.c, the 64-bit stub, which keeps its
//! own Rust version compressed/cpuflags_rs.rs; this file does not touch the stub.) `has_eflag()` is
//! exported only for CONFIG_X86_32 (`--cfg rm_x86_32`, set by the Makefile from CONFIG_X86_32); on an
//! x86-64 configuration cpuflags.h makes it an inline `return true`, and so does this file.
//!
//! Why a second file and not one source for both targets: the stub's version is accepted and built for
//! x86-64 (`core::arch::x86_64`, a 64-bit cr0, `mov` from 64-bit registers) and its build is not to be
//! disturbed; this one needs 32-bit operands in code16, 32-bit-only has_eflag and the i386 target's
//! asm! register rules. Sharing would mean cfg-forking nearly every statement. The algorithm text is
//! the same as the stub's; both are checked against the C original by their own rigs.
//!
//! Layout: `struct cpu_features` = int level, family, model; u32 flags[NCAPINTS] (12 + 4*22 bytes, from
//! the same headers as the C via cpucheck_gen.rs; cpucheck_rs.rs / cpu_rs.rs still reach `cpu` as
//! extern "C"). The data is placed in plain `.bss` (setup.ld collects `*(.bss)` only, not `.bss.<name>`).
//!
//! Algorithm, statement by statement the C's get_cpuflags(): once-only (`loaded_flags`), has_fpu() (cr0
//! EM/TS cleared, fninit/fnstsw/fnstcw, fsw == 0 && (fcw & 0x103f) == 0x3f -> FPU bit), if has_eflag(ID):
//! leaf 0 (max level, vendor ebx/edx/ecx stored into cpu_vendor[0]/[2]/[1] via the C's argument order),
//! leaf 1 if 1 <= max <= 0xffff (level = family nibble, family = level, model = model nibble plus, only
//! for level >= 6, the extended-model nibble << 4; NOTE the C does not add the extended family),
//! leaf 7 sub 0 if max >= 7 (ecx -> flags[16]), leaf 0x80000000 and, if 0x80000001 <= max <= 0x8000ffff,
//! leaf 0x80000001 (ecx -> flags[6], edx -> flags[1]).
//! No message strings exist in the C or here.
//!
//! Deliberate divergences: none in behaviour. `cpuid` is an asm! with ebx as an output operand
//! (allowed on this i386 non-PIC target; the object has no push/pop of ebx beyond the C's own); has_eflag's mask is a register operand ("ri" in
//! the C; the callers pass a constant). The loaded_flags flag is `static mut bool` as the C's `static bool`.
//! Under `--cfg host_mock` (host tests only) cr0 / fpu / eflags / cpuid go to extern hooks.
//!
//! TEST-GAP: real hardware: cr0 EM/TS handling and the x87 probe run for real only on the host CPU
//! (KVM: always has an FPU, cr0 EM/TS clear); an FPU-less CPU, CPUs with CPUID absent (386/early 486:
//! has_eflag(ID) false, 32-bit builds only) and the real pushfd/popfd toggle only run in the host
//! differential against a mocked model (rig/realmode/run-cpuflags-diff.sh) plus the instruction-level
//! compare of the object. TCG CPUs exercise the vendor/family/model/leaf-7/0x80000001 paths.
#![allow(dead_code, non_upper_case_globals)]

#[cfg(not(host_mock))]
use core::arch::asm;
use core::ffi::c_int;

include!(concat!(env!("RM_GEN_DIR"), "/cpucheck_gen.rs"));

// The generated config (CONFIG_X86_64) and the --cfg the Makefile derives from CONFIG_X86_32 must agree.
const _: () = assert!(IS_X86_64 != cfg!(rm_x86_32));

/// `struct cpu_features` (cpuflags.h).
#[repr(C)]
pub struct CpuFeatures {
    pub level: c_int,  // family, or 64 for x86-64
    pub family: c_int, // family, always
    pub model: c_int,
    pub flags: [u32; RM_NCAPINTS],
}

// struct cpu_features: three ints then NCAPINTS u32, no padding (cpucheck_rs.rs / cpu_rs.rs and the C stub rely on it).
const _: () = assert!(core::mem::size_of::<CpuFeatures>() == 12 + 4 * RM_NCAPINTS);

#[no_mangle]
#[link_section = ".bss"]
pub static mut cpu: CpuFeatures = CpuFeatures { level: 0, family: 0, model: 0, flags: [0; RM_NCAPINTS] };
#[no_mangle]
#[link_section = ".bss"]
pub static mut cpu_vendor: [u32; 3] = [0; 3];

#[link_section = ".bss"]
#[cfg_attr(host_mock, export_name = "rs_loaded_flags")]
static mut LOADED_FLAGS: bool = false;

#[cfg(host_mock)]
extern "C" {
    fn mock_read_cr0() -> u32;
    fn mock_write_cr0(v: u32);
    fn mock_fpu(fsw: *mut u16, fcw: *mut u16);
    fn mock_eflags_get() -> u32;
    fn mock_eflags_set(v: u32);
    fn mock_cpuid(id: u32, count: u32, a: *mut u32, b: *mut u32, c: *mut u32, d: *mut u32);
}

// TEST-GAP: the FPU-absent result and the cr0 EM/TS rewrite never happen on KVM/TCG (always an FPU, EM/TS clear); host model only.
unsafe fn has_fpu() -> bool {
    let mut fcw: u16 = !0;
    let mut fsw: u16 = !0;
    let mut cr0: u32;

    // SAFETY: ring 0 in real mode setup (the C did the same `mov %cr0`).
    #[cfg(not(host_mock))]
    unsafe {
        asm!("mov {0:e}, cr0", out(reg) cr0, options(nostack, nomem, preserves_flags))
    };
    #[cfg(host_mock)]
    {
        cr0 = unsafe { mock_read_cr0() };
    }
    if cr0 & (RM_X86_CR0_EM | RM_X86_CR0_TS) != 0 {
        cr0 &= !(RM_X86_CR0_EM | RM_X86_CR0_TS);
        // SAFETY: clears EM/TS exactly as the C does so the x87 probe below can run.
        #[cfg(not(host_mock))]
        unsafe {
            asm!("mov cr0, {0:e}", in(reg) cr0, options(nostack, nomem, preserves_flags))
        };
        #[cfg(host_mock)]
        unsafe {
            mock_write_cr0(cr0)
        };
    }

    // SAFETY: stores the x87 status/control words into the two locals (the C's "+m" operands).
    #[cfg(not(host_mock))]
    unsafe {
        asm!(
            "fninit",
            "fnstsw word ptr [{fsw:e}]",
            "fnstcw word ptr [{fcw:e}]",
            fsw = in(reg) &mut fsw,
            fcw = in(reg) &mut fcw,
            options(nostack, preserves_flags)
        )
    };
    #[cfg(host_mock)]
    unsafe {
        mock_fpu(&mut fsw, &mut fcw)
    };

    // read back through volatile loads: the asm above wrote them behind the compiler's back
    // SAFETY: both are live locals.
    let (fsw, fcw) = unsafe { (core::ptr::read_volatile(&fsw), core::ptr::read_volatile(&fcw)) };
    fsw == 0 && (fcw & 0x103f) == 0x003f
}

/// 32-bit configurations only (CONFIG_X86_32): can EFLAGS bits in `mask` be toggled? (pushfd/popfd
/// round trip; the original flags are restored.) With `--cfg host_mock` the asm is its step-by-step
/// equivalent on a modelled EFLAGS: f0 = flags; flags = f0 ^ mask; f1 = flags; flags = f0.
// TEST-GAP: not built in this x86-64 tree; the real pushfd/popfd toggle (and CPUID-less CPUs) are covered only by the host model and the object compare.
#[cfg(rm_x86_32)]
#[no_mangle]
pub unsafe extern "C" fn has_eflag(mask: u32) -> bool {
    let f0: u32;
    let f1: u32;
    #[cfg(not(host_mock))]
    // SAFETY: balanced pushes/pops on the setup stack; ends with the caller's flags restored.
    unsafe {
        asm!(
            "pushfd",
            "pushfd",
            "pop {f0:e}",
            "mov {f1:e}, {f0:e}",
            "xor {f1:e}, {m:e}",
            "push {f1:e}",
            "popfd",
            "pushfd",
            "pop {f1:e}",
            "popfd",
            f0 = out(reg) f0, f1 = out(reg) f1, m = in(reg) mask,
        )
    };
    #[cfg(host_mock)]
    unsafe {
        f0 = mock_eflags_get();
        mock_eflags_set(f0 ^ mask);
        f1 = mock_eflags_get();
        mock_eflags_set(f0);
    }
    ((f0 ^ f1) & mask) != 0
}
/// x86-64 configurations: cpuflags.h's `static inline bool has_eflag(unsigned long) { return true; }`.
#[cfg(not(rm_x86_32))]
#[inline(always)]
unsafe fn has_eflag(_mask: u32) -> bool {
    true
}

/// `void cpuid_count(u32 id, u32 count, u32 *a, u32 *b, u32 *c, u32 *d)`: outputs stored in the order
/// a, b, c, d.
///
/// # Safety
/// The four pointers must be valid for a u32 write (they may alias).
// TEST-GAP: the asm operand wiring (eax=id, ecx=count) is seen by the boots and the disassembly only; the host rig mocks at the asm boundary.
#[no_mangle]
pub unsafe extern "C" fn cpuid_count(id: u32, count: u32, a: *mut u32, b: *mut u32, c: *mut u32, d: *mut u32) {
    let (ra, rb, rc, rd): (u32, u32, u32, u32);
    #[cfg(not(host_mock))]
    // SAFETY: CPUID (ebx is an output; the compiler saves it as callee-saved as in the C object).
    unsafe {
        let t: u32;
        asm!(
            "cpuid",
            inout("eax") id => ra, out("ebx") t, inout("ecx") count => rc, out("edx") rd,
            options(nostack, nomem, preserves_flags)
        );
        rb = t;
    }
    #[cfg(host_mock)]
    {
        let (mut x, mut y, mut z, mut w) = (0u32, 0u32, 0u32, 0u32);
        unsafe { mock_cpuid(id, count, &mut x, &mut y, &mut z, &mut w) };
        ra = x;
        rb = y;
        rc = z;
        rd = w;
    }
    // SAFETY: caller contract.
    unsafe {
        *a = ra;
        *b = rb;
        *c = rc;
        *d = rd;
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_cpuflags() {
    let mut ignored: u32 = 0;
    let mut max_intel_level: u32 = 0;
    let mut max_amd_level: u32 = 0;
    let mut tfms: u32 = 0;
    let ig = &raw mut ignored;
    // SAFETY: single-threaded real-mode setup; these statics are only touched here.
    let (loaded, cp, vend) =
        unsafe { (&mut *(&raw mut LOADED_FLAGS), &mut *(&raw mut cpu), &mut *(&raw mut cpu_vendor)) };

    if *loaded {
        return;
    }
    *loaded = true;

    // SAFETY: has_fpu() contract.
    if unsafe { has_fpu() } {
        // set_bit(X86_FEATURE_FPU, cpu.flags)
        cp.flags[(RM_X86_FEATURE_FPU >> 5) as usize] |= 1 << (RM_X86_FEATURE_FPU & 31);
    }

    // SAFETY (all cpuid_count calls below): every pointer is to a live local / field of the statics.
    unsafe {
        if has_eflag(RM_X86_EFLAGS_ID) {
            cpuid_count(0x0, 0, &raw mut max_intel_level, &raw mut vend[0], &raw mut vend[2], &raw mut vend[1]);

            if max_intel_level >= 0x0000_0001 && max_intel_level <= 0x0000_ffff {
                cpuid_count(0x1, 0, &raw mut tfms, ig, &raw mut cp.flags[4], &raw mut cp.flags[0]);
                cp.level = ((tfms >> 8) & 15) as c_int;
                cp.family = cp.level;
                cp.model = ((tfms >> 4) & 15) as c_int;
                if cp.level >= 6 {
                    cp.model += (((tfms >> 16) & 0xf) << 4) as c_int;
                }
            }

            if max_intel_level >= 0x0000_0007 {
                cpuid_count(0x0000_0007, 0, ig, ig, &raw mut cp.flags[16], ig);
            }

            cpuid_count(0x8000_0000, 0, &raw mut max_amd_level, ig, ig, ig);

            if max_amd_level >= 0x8000_0001 && max_amd_level <= 0x8000_ffff {
                cpuid_count(0x8000_0001, 0, ig, ig, &raw mut cp.flags[6], &raw mut cp.flags[1]);
            }
        }
    }
}
