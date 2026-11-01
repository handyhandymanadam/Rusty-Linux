// SPDX-License-Identifier: GPL-2.0

//! Rust replacement for `arch/x86/kernel/platform-quirks.c` (all of it): `x86_early_init_platform_quirks()`,
//! `x86_pnpbios_disabled()` and, under `CONFIG_PNPBIOS`, `arch_pnpbios_disabled()`.
//!
//! The whole file is a straight port: no part stays C. It runs once, on the boot CPU, from
//! `x86_64_start_reservations()` (head64_rs.rs) before `start_kernel()`: no locks, no allocation, interrupts off.
//!
//! The one thing it shares with the rest of the kernel is `struct x86_platform_ops x86_platform` (declared
//! `extern` as a byte object here and addressed by offset, like `boot_params` in head64_rs.rs). The offsets
//! are the C struct's geometry and are checked against the kernel's own headers (RAISE 6) by
//! `rig/phase-e/layout-check.c` (`_Static_assert`s, compiled in-tree on both configs).
//!
//! No panic path: no arithmetic, no indexing, nothing here can panic; `rig/uaccess-panic-check.sh` and the `nm`
//! check in logs/hooks.md confirm the object has no `panic*` undefined symbol.
//!
//! Replaces: arch/x86/kernel/platform-quirks.c

// --- layout of the C structs this file reads or writes (checked by rig/phase-e/layout-check.c and consts_check.py) ---
// C-HEADERS: linux/types.h asm/x86_init.h asm/bootparam.h uapi/asm/bootparam.h
/// `offsetof(struct x86_platform_ops, legacy)`.
const XP_LEGACY: usize = 88; // C: offsetof(struct x86_platform_ops, legacy)
/// `offsetof(struct x86_platform_ops, set_legacy_features)`.
const XP_SET_LEGACY_FEATURES: usize = 112; // C: offsetof(struct x86_platform_ops, set_legacy_features)
/// `offsetof(struct x86_legacy_features, i8042)`.
const LF_I8042: usize = 0; // C: offsetof(struct x86_legacy_features, i8042)
/// `offsetof(struct x86_legacy_features, rtc)`.
const LF_RTC: usize = 4; // C: offsetof(struct x86_legacy_features, rtc)
/// `offsetof(struct x86_legacy_features, warm_reset)`.
const LF_WARM_RESET: usize = 8; // C: offsetof(struct x86_legacy_features, warm_reset)
/// `offsetof(struct x86_legacy_features, reserve_bios_regions)`.
const LF_RESERVE_BIOS_REGIONS: usize = 16; // C: offsetof(struct x86_legacy_features, reserve_bios_regions)
/// `offsetof(struct x86_legacy_features, devices.pnpbios)`.
const LF_PNPBIOS: usize = 20; // C: offsetof(struct x86_legacy_features, devices.pnpbios)
/// `offsetof(struct boot_params, hdr.hardware_subarch)`.
const BP_HDR_HARDWARE_SUBARCH: usize = 0x23c; // C: offsetof(struct boot_params, hdr.hardware_subarch)

/// `X86_LEGACY_I8042_PLATFORM_ABSENT`.
const I8042_PLATFORM_ABSENT: i32 = 0; // C: X86_LEGACY_I8042_PLATFORM_ABSENT
/// `X86_LEGACY_I8042_EXPECTED_PRESENT`.
const I8042_EXPECTED_PRESENT: i32 = 2; // C: X86_LEGACY_I8042_EXPECTED_PRESENT
/// `X86_SUBARCH_PC`.
const X86_SUBARCH_PC: u32 = 0; // C: X86_SUBARCH_PC
/// `X86_SUBARCH_XEN`.
const X86_SUBARCH_XEN: u32 = 2; // C: X86_SUBARCH_XEN
/// `X86_SUBARCH_INTEL_MID`.
const X86_SUBARCH_INTEL_MID: u32 = 3; // C: X86_SUBARCH_INTEL_MID
/// `X86_SUBARCH_CE4100`.
const X86_SUBARCH_CE4100: u32 = 4; // C: X86_SUBARCH_CE4100

#[cfg(not(userspace_test))]
extern "C" {
    static mut x86_platform: u8;
    static boot_params: u8;
}

/// The five fields `x86_early_init_platform_quirks()` writes, in `struct x86_legacy_features`
/// (`no_vga` is not touched by the C and is not here).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Legacy {
    /// `i8042` (`enum x86_legacy_i8042_state`).
    pub i8042: i32,
    /// `rtc`.
    pub rtc: i32,
    /// `warm_reset`.
    pub warm_reset: i32,
    /// `reserve_bios_regions`.
    pub reserve_bios_regions: i32,
    /// `devices.pnpbios`.
    pub pnpbios: i32,
}

/// The defaults and the per-`hardware_subarch` overrides, exactly the C's assignments and `switch`.
#[inline(always)]
pub fn plan(hardware_subarch: u32) -> Legacy {
    let mut l = Legacy { i8042: I8042_EXPECTED_PRESENT, rtc: 1, warm_reset: 1, reserve_bios_regions: 0, pnpbios: 1 };
    match hardware_subarch {
        X86_SUBARCH_PC => l.reserve_bios_regions = 1,
        X86_SUBARCH_XEN => {
            l.pnpbios = 0;
            l.rtc = 0;
        }
        X86_SUBARCH_INTEL_MID | X86_SUBARCH_CE4100 => {
            l.pnpbios = 0;
            l.rtc = 0;
            l.i8042 = I8042_PLATFORM_ABSENT;
        }
        _ => {}
    }
    l
}

/// The body of `x86_early_init_platform_quirks()` over `struct x86_platform_ops *xp`: write the plan into
/// `xp->legacy`, then call `xp->set_legacy_features` if set.
/// The stores are in the C's order (i8042, rtc, warm_reset, reserve_bios_regions, pnpbios; the `switch`
/// then overwrites some of them): the final bytes are what matter, no other CPU runs.
///
/// # Safety
/// `xp` points at a `struct x86_platform_ops`.
#[inline(always)]
pub unsafe fn apply(xp: *mut u8, hardware_subarch: u32) {
    let l = plan(hardware_subarch);
    // SAFETY: the offsets are the C struct's (layout-check.c); the object is the kernel's own, aligned.
    unsafe {
        let legacy = xp.add(XP_LEGACY);
        legacy.add(LF_I8042).cast::<i32>().write(l.i8042);
        legacy.add(LF_RTC).cast::<i32>().write(l.rtc);
        legacy.add(LF_WARM_RESET).cast::<i32>().write(l.warm_reset);
        legacy.add(LF_RESERVE_BIOS_REGIONS).cast::<i32>().write(l.reserve_bios_regions);
        legacy.add(LF_PNPBIOS).cast::<i32>().write(l.pnpbios);
        let cb = xp.add(XP_SET_LEGACY_FEATURES).cast::<Option<unsafe extern "C" fn()>>().read();
        if let Some(f) = cb {
            // the kernel's own callback (`x86_platform.set_legacy_features`)
            f();
        }
    }
}

/// `x86_early_init_platform_quirks()`: legacy-device defaults for the platform in `boot_params.hdr.hardware_subarch`.
///
/// # Safety
/// Early boot, single CPU, after `boot_params` is copied (`copy_bootdata`).
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn x86_early_init_platform_quirks() {
    // SAFETY: plain reads/writes of the kernel's own objects at the C struct offsets.
    unsafe {
        let subarch = (&raw const boot_params).add(BP_HDR_HARDWARE_SUBARCH).cast::<u32>().read();
        apply((&raw mut x86_platform).cast(), subarch);
    }
}

/// `x86_platform.legacy.devices.pnpbios == 0`.
#[inline(always)]
pub fn pnpbios_disabled(pnpbios: i32) -> bool {
    pnpbios == 0
}

/// `x86_pnpbios_disabled()`.
///
/// # Safety
/// Reads `x86_platform`.
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn x86_pnpbios_disabled() -> bool {
    // SAFETY: plain read.
    unsafe { pnpbios_disabled((&raw const x86_platform).add(XP_LEGACY + LF_PNPBIOS).cast::<i32>().read()) }
}

/// `arch_pnpbios_disabled()` (`CONFIG_PNPBIOS`, which depends on `X86_32`: never built with this file, kept for fidelity).
///
/// # Safety
/// As `x86_pnpbios_disabled`.
#[cfg(all(not(userspace_test), CONFIG_PNPBIOS))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn arch_pnpbios_disabled() -> bool {
    // SAFETY: as the callee.
    unsafe { x86_pnpbios_disabled() }
}
