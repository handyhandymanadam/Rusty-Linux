// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/cpuflags.c, which #includes
//! ../cpuflags.c (shared with the 16-bit setup; that file stays C, untouched).
//!
//! Exports what the C object did: `cpu`, `cpu_vendor`, `get_cpuflags()`,
//! `cpuid_count()` (called from C in tdx.c and mem.c) and `has_cpuflag()`.
//! 64-bit only: the C's has_eflag() is the inline `return true` there.

use core::arch::asm;
use core::ffi::c_int;

/// NCAPINTS of asm/cpufeatures.h in 6.18 (the C struct is sized by it).
const NCAPINTS: usize = 22;
const X86_FEATURE_FPU: c_int = 0;
const X86_CR0_EM: u64 = 1 << 2;
const X86_CR0_TS: u64 = 1 << 3;

#[repr(C)]
pub struct CpuFeatures {
    level: c_int,  // family, or 64 for x86-64
    family: c_int, // family, always
    model: c_int,
    flags: [u32; NCAPINTS],
}

#[no_mangle]
pub static mut cpu: CpuFeatures = CpuFeatures { level: 0, family: 0, model: 0, flags: [0; NCAPINTS] };
#[no_mangle]
pub static mut cpu_vendor: [u32; 3] = [0; 3];

static mut LOADED_FLAGS: bool = false;

unsafe fn has_fpu() -> bool {
    let mut fcw: u16 = !0;
    let mut fsw: u16 = !0;
    let mut cr0: u64;

    // SAFETY: ring 0 in the boot stub (the C did the same `mov %cr0`).
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nostack)) };
    if cr0 & (X86_CR0_EM | X86_CR0_TS) != 0 {
        cr0 &= !(X86_CR0_EM | X86_CR0_TS);
        // SAFETY: ring 0; clears EM/TS exactly as the C does so the x87 probe below can run.
        unsafe { asm!("mov cr0, {}", in(reg) cr0, options(nostack)) };
    }

    // SAFETY: stores the x87 status/control words into the two locals (the C's "+m" operands).
    unsafe {
        asm!(
            "fninit",
            "fnstsw word ptr [{fsw}]",
            "fnstcw word ptr [{fcw}]",
            fsw = in(reg) &mut fsw,
            fcw = in(reg) &mut fcw,
            options(nostack)
        )
    };

    fsw == 0 && (fcw & 0x103f) == 0x003f
}

/// `void cpuid_count(u32 id, u32 count, u32 *a, u32 *b, u32 *c, u32 *d)`
///
/// # Safety
/// The four pointers must be valid for a u32 write (they may alias).
#[no_mangle]
pub unsafe extern "C" fn cpuid_count(id: u32, count: u32, a: *mut u32, b: *mut u32, c: *mut u32, d: *mut u32) {
    // (safe fn in the pinned core: CPUID exists on every x86-64 CPU; the wrapper saves/restores rbx)
    let r = core::arch::x86_64::__cpuid_count(id, count);
    // SAFETY: caller contract. Written in the C's order a, b, c, d.
    unsafe {
        *a = r.eax;
        *b = r.ebx;
        *c = r.ecx;
        *d = r.edx;
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_cpuflags() {
    let mut ignored: u32 = 0;
    let mut max_intel_level: u32 = 0;
    let mut max_amd_level: u32 = 0;
    let mut tfms: u32 = 0;
    let ig = &raw mut ignored;
    // SAFETY: single-threaded boot stub; these statics are only touched here and in has_cpuflag().
    let (loaded, cp, vend) = unsafe { (&mut *(&raw mut LOADED_FLAGS), &mut *(&raw mut cpu), &mut *(&raw mut cpu_vendor)) };

    if *loaded {
        return;
    }
    *loaded = true;

    // SAFETY: has_fpu() contract (ring 0).
    if unsafe { has_fpu() } {
        // set_bit(X86_FEATURE_FPU, cpu.flags): bit 0 of word 0
        cp.flags[(X86_FEATURE_FPU >> 5) as usize] |= 1 << (X86_FEATURE_FPU & 31);
    }

    // has_eflag(X86_EFLAGS_ID) is `true` on 64-bit.
    // SAFETY (all cpuid_count calls below): every pointer is to a live local / field of the statics.
    unsafe {
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

#[no_mangle]
pub unsafe extern "C" fn has_cpuflag(flag: c_int) -> bool {
    // SAFETY: same contract as get_cpuflags().
    unsafe { get_cpuflags() };
    // test_bit(flag, cpu.flags): bit (flag & 31) of u32 word (flag >> 5) counted from cpu.flags,
    // not bounds-checked, as in the C (callers pass X86_FEATURE_* < NCAPINTS * 32).
    // SAFETY: reads a u32 of the static `cpu` (or, for an out-of-range flag, past it, as the C would).
    let w = unsafe { ((&raw const cpu.flags) as *const u32).offset((flag >> 5) as isize).read() };
    (w >> (flag & 31)) & 1 != 0
}
