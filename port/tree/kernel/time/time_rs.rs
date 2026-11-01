// SPDX-License-Identifier: GPL-2.0

//! Jiffies / time conversions -- the Rust behind most of `kernel/time/time.c`.
//!
//! Ported from `kernel/time/time.c` (6.18.49): `jiffies_to_msecs/usecs`, `mktime64`, `ns_to_kernel_old_timeval`,
//! `set_normalized_timespec64`, `ns_to_timespec64`, `__msecs_to_jiffies`, `__usecs_to_jiffies`, `timespec64_to_jiffies`,
//! `jiffies_to_timespec64`, `jiffies_to_clock_t`, `clock_t_to_jiffies`, `jiffies64_to_nsecs/msecs`, `nsecs_to_jiffies64`,
//! `nsecs_to_jiffies` and `timespec64_add_safe`. In C (`time_glue.c`): everything with `SYSCALL_DEFINE`, `__user` copies
//! and the clock-setting path, plus `jiffies_64_to_clock_t` (`notrace`: the tracer calls it, so it must stay out of any
//! patchable function entry) and `nsec_to_clock_t`.
//!
//! The C file's results depend on `CONFIG_HZ` through preprocessor arms and the generated `timeconst.h`. x86 offers four
//! values; each is a `cfg(CONFIG_HZ = "...")` arm below holding the constants `kernel/time/timeconst.bc` generates for it
//! (taken from running that script; `port/test/time/run.sh` regenerates them with the real `bc` and runs the pristine C
//! against this file at all four HZ). The C arm chosen by `#if` is the `if CONST` here; the other arm still has to compile.
//! 64-bit only (`BITS_PER_LONG == 64`: the 32-bit `HZ_TO_MSEC_MUL32` arm is not ported).
//!
//! Every export is `#[inline(never)]`: when `nsecs_to_jiffies()` inlines `nsecs_to_jiffies64()`, `gendwarfksyms` hands the second symbol the
//! first one's fingerprint (both listed in one run: 0x542b4a64 for both; alone it is right), a MODVERSIONS CRC silently wrong.
//! None of the exports has a guard, WARN or static key, so no C entry stays: `kernel::kabi_export!` carries each export
//! and its contract (C fingerprints taken from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: kernel/time/time.c (the conversions)

use core::ffi::{c_int, c_long};

#[cfg(not(target_pointer_width = "64"))]
compile_error!("time_rs.rs: 64-bit only");

// ---- CONFIG_HZ-dependent constants (include/generated/timeconst.h, kernel/time/timeconst.bc) ----
#[cfg(CONFIG_HZ = "100")]
mod hz {
    pub(crate) const HZ: i64 = 100;
    pub(crate) const MSEC_TO_HZ_MUL32: u64 = 0xCCCCCCCD;
    pub(crate) const MSEC_TO_HZ_ADJ32: u64 = 0x733333333;
    pub(crate) const MSEC_TO_HZ_SHR32: u32 = 35;
    pub(crate) const HZ_TO_MSEC_NUM: u64 = 10;
    pub(crate) const HZ_TO_MSEC_DEN: u64 = 1;
    pub(crate) const USEC_TO_HZ_MUL32: u64 = 0xD1B71759;
    pub(crate) const USEC_TO_HZ_ADJ32: u64 = 0x1FFF2E48E8A7;
    pub(crate) const USEC_TO_HZ_SHR32: u32 = 45;
    pub(crate) const HZ_TO_USEC_NUM: u64 = 10000;
    pub(crate) const HZ_TO_USEC_DEN: u64 = 1;
    pub(crate) const HZ_TO_NSEC_NUM: u64 = 10000000;
    pub(crate) const HZ_TO_NSEC_DEN: u64 = 1;
    pub(crate) const SHIFT_HZ: u32 = 7;
}
#[cfg(CONFIG_HZ = "250")]
mod hz {
    pub(crate) const HZ: i64 = 250;
    pub(crate) const MSEC_TO_HZ_MUL32: u64 = 0x80000000;
    pub(crate) const MSEC_TO_HZ_ADJ32: u64 = 0x180000000;
    pub(crate) const MSEC_TO_HZ_SHR32: u32 = 33;
    pub(crate) const HZ_TO_MSEC_NUM: u64 = 4;
    pub(crate) const HZ_TO_MSEC_DEN: u64 = 1;
    pub(crate) const USEC_TO_HZ_MUL32: u64 = 0x83126E98;
    pub(crate) const USEC_TO_HZ_ADJ32: u64 = 0x7FF7CED9168;
    pub(crate) const USEC_TO_HZ_SHR32: u32 = 43;
    pub(crate) const HZ_TO_USEC_NUM: u64 = 4000;
    pub(crate) const HZ_TO_USEC_DEN: u64 = 1;
    pub(crate) const HZ_TO_NSEC_NUM: u64 = 4000000;
    pub(crate) const HZ_TO_NSEC_DEN: u64 = 1;
    pub(crate) const SHIFT_HZ: u32 = 8;
}
#[cfg(CONFIG_HZ = "300")]
mod hz {
    pub(crate) const HZ: i64 = 300;
    pub(crate) const MSEC_TO_HZ_MUL32: u64 = 0x9999999A;
    pub(crate) const MSEC_TO_HZ_ADJ32: u64 = 0x1CCCCCCCC;
    pub(crate) const MSEC_TO_HZ_SHR32: u32 = 33;
    pub(crate) const HZ_TO_MSEC_NUM: u64 = 10;
    pub(crate) const HZ_TO_MSEC_DEN: u64 = 3;
    pub(crate) const USEC_TO_HZ_MUL32: u64 = 0x9D495183;
    pub(crate) const USEC_TO_HZ_ADJ32: u64 = 0x7FFCB923A29;
    pub(crate) const USEC_TO_HZ_SHR32: u32 = 43;
    pub(crate) const HZ_TO_USEC_NUM: u64 = 10000;
    pub(crate) const HZ_TO_USEC_DEN: u64 = 3;
    pub(crate) const HZ_TO_NSEC_NUM: u64 = 10000000;
    pub(crate) const HZ_TO_NSEC_DEN: u64 = 3;
    pub(crate) const SHIFT_HZ: u32 = 8;
}
#[cfg(CONFIG_HZ = "1000")]
mod hz {
    pub(crate) const HZ: i64 = 1000;
    pub(crate) const MSEC_TO_HZ_MUL32: u64 = 0x80000000;
    pub(crate) const MSEC_TO_HZ_ADJ32: u64 = 0x0;
    pub(crate) const MSEC_TO_HZ_SHR32: u32 = 31;
    pub(crate) const HZ_TO_MSEC_NUM: u64 = 1;
    pub(crate) const HZ_TO_MSEC_DEN: u64 = 1;
    pub(crate) const USEC_TO_HZ_MUL32: u64 = 0x83126E98;
    pub(crate) const USEC_TO_HZ_ADJ32: u64 = 0x1FF7CED9168;
    pub(crate) const USEC_TO_HZ_SHR32: u32 = 41;
    pub(crate) const HZ_TO_USEC_NUM: u64 = 1000;
    pub(crate) const HZ_TO_USEC_DEN: u64 = 1;
    pub(crate) const HZ_TO_NSEC_NUM: u64 = 1000000;
    pub(crate) const HZ_TO_NSEC_DEN: u64 = 1;
    pub(crate) const SHIFT_HZ: u32 = 10;
}
#[cfg(not(any(CONFIG_HZ = "100", CONFIG_HZ = "250", CONFIG_HZ = "300", CONFIG_HZ = "1000")))]
compile_error!("time_rs.rs: CONFIG_HZ must be 100, 250, 300 or 1000 (the values x86 offers)");

use hz::*;

const MSEC_PER_SEC: i64 = 1000;
const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_SEC: i64 = 1_000_000_000;
const USER_HZ: i64 = 100;
const LONG_MAX: i64 = i64::MAX;
const TIME64_MAX: i64 = i64::MAX;
/// `MAX_JIFFY_OFFSET`.
const MAX_JIFFY_OFFSET: u64 = ((LONG_MAX >> 1) - 1) as u64;
/// `TICK_NSEC`.
const TICK_NSEC: i64 = (NSEC_PER_SEC + HZ / 2) / HZ;

/// `SEC_JIFFIE_SC` with the `#if !(...0x80000000)` bump of `include/linux/jiffies.h`.
const SEC_JIFFIE_SC: u32 = {
    let sc = 31 - SHIFT_HZ;
    if ((((NSEC_PER_SEC << 2) / TICK_NSEC) << (sc - 2)) & 0x80000000) == 0 {
        32 - SHIFT_HZ
    } else {
        sc
    }
};
const NSEC_JIFFIE_SC: u32 = SEC_JIFFIE_SC + 29;
const SEC_CONVERSION: u64 = ((((NSEC_PER_SEC as u64) << SEC_JIFFIE_SC) + TICK_NSEC as u64 - 1) / TICK_NSEC as u64) as u64;
const NSEC_CONVERSION: u64 = (((1u64 << NSEC_JIFFIE_SC) + TICK_NSEC as u64 - 1) / TICK_NSEC as u64) as u64;

/// `SH_DIV(NOM, DEN, LSH)`.
const fn sh_div(nom: i64, den: i64, lsh: u32) -> i64 {
    ((nom / den) << lsh) + ((((nom % den) << lsh) + den / 2) / den)
}

/// `MAX_SEC_IN_JIFFIES` (the 64-bit arm).
const MAX_SEC_IN_JIFFIES: i64 = sh_div(((MAX_JIFFY_OFFSET as i64) >> SEC_JIFFIE_SC) * TICK_NSEC, NSEC_PER_SEC, 1) - 1;

/// `struct timespec64`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec64 {
    tv_sec: i64,
    tv_nsec: c_long,
}

/// `struct __kernel_old_timeval`.
#[repr(C)]
pub struct KernelOldTimeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#__kernel_old_timeval",
    "structure_type __kernel_old_timeval { member t#__kernel_long_t tv_sec data_member_location(0) , member t#__kernel_long_t tv_usec data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "s#timespec64",
    "structure_type timespec64 { member t#time64_t tv_sec data_member_location(0) , member base_type long byte_size(8) encoding(5) tv_nsec data_member_location(8) } byte_size(16)");
kernel::kabi_rule!("type_string", "t#clock_t",
    "typedef_type clock_t { t#__kernel_clock_t }");
kernel::kabi_rule!("type_string", "t#__kernel_clock_t",
    "typedef_type __kernel_clock_t { t#__kernel_long_t }");
kernel::kabi_rule!("type_string", "t#__kernel_long_t",
    "typedef_type __kernel_long_t { base_type long byte_size(8) encoding(5) }");
kernel::kabi_rule!("type_string", "t#__s64",
    "typedef_type __s64 { base_type long long byte_size(8) encoding(5) }");
kernel::kabi_rule!("type_string", "t#s64",
    "typedef_type s64 { t#__s64 }");
kernel::kabi_rule!("type_string", "t#time64_t",
    "typedef_type time64_t { t#__s64 }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");

kernel::kabi_export! {
    jiffies_to_msecs,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned long byte_size(8) encoding(7) } j ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `jiffies_to_msecs()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn jiffies_to_msecs(j: u64) -> u32 {
    if HZ <= MSEC_PER_SEC && MSEC_PER_SEC % HZ == 0 {
        ((MSEC_PER_SEC / HZ) as u64).wrapping_mul(j) as u32
    } else {
        /* DIV_ROUND_UP(j * HZ_TO_MSEC_NUM, HZ_TO_MSEC_DEN) */
        (j.wrapping_mul(HZ_TO_MSEC_NUM).wrapping_add(HZ_TO_MSEC_DEN - 1) / HZ_TO_MSEC_DEN) as u32
    }
}

kernel::kabi_export! {
    jiffies_to_usecs,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned long byte_size(8) encoding(7) } j ) -> base_type unsigned int byte_size(4) encoding(7)",
}
/// `jiffies_to_usecs()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn jiffies_to_usecs(j: u64) -> u32 {
    if USEC_PER_SEC % HZ == 0 {
        ((USEC_PER_SEC / HZ) as u64).wrapping_mul(j) as u32
    } else {
        (j.wrapping_mul(HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN) as u32
    }
}

kernel::kabi_export! {
    mktime64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } year0 , formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } mon0 , formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } day , formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } hour , formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } min , formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } sec ) -> t#time64_t",
}
/// `mktime64()`: Gregorian date to seconds since 1970-01-01 00:00:00.
#[no_mangle]
#[inline(never)]
pub extern "C" fn mktime64(year0: u32, mon0: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    let mut mon = mon0;
    let mut year = year0;

    /* 1..12 -> 11,12,1..10 */
    mon = mon.wrapping_sub(2);
    if 0 >= mon as i32 {
        mon = mon.wrapping_add(12); /* Puts Feb last since it has leap day */
        year = year.wrapping_sub(1);
    }

    ((((((year / 4)
        .wrapping_sub(year / 100)
        .wrapping_add(year / 400)
        .wrapping_add(367u32.wrapping_mul(mon) / 12)
        .wrapping_add(day) as i64)
        .wrapping_add(year.wrapping_mul(365) as i64)
        .wrapping_sub(719499))
    .wrapping_mul(24)
    .wrapping_add(hour as i64)) /* now have hours - midnight tomorrow handled here */
    .wrapping_mul(60)
    .wrapping_add(min as i64)) /* now have minutes */
    .wrapping_mul(60))
    .wrapping_add(sec as i64) /* finally seconds */
}

kernel::kabi_export! {
    ns_to_kernel_old_timeval,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#s64 nsec ) -> s#__kernel_old_timeval",
}
/// `ns_to_kernel_old_timeval()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn ns_to_kernel_old_timeval(nsec: i64) -> KernelOldTimeval {
    let ts = ns_to_timespec64(nsec);

    KernelOldTimeval { tv_sec: ts.tv_sec, tv_usec: ts.tv_nsec / 1000 }
}

kernel::kabi_export! {
    set_normalized_timespec64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timespec64 } ts , formal_parameter t#time64_t sec , formal_parameter t#s64 nsec ) -> base_type void",
}
/// `set_normalized_timespec64()`: store `sec`/`nsec` with `0 <= tv_nsec < NSEC_PER_SEC`.
///
/// # Safety
/// `ts` writable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn set_normalized_timespec64(ts: *mut Timespec64, sec: i64, nsec: i64) {
    let mut sec = sec;
    let mut nsec = nsec;

    while nsec >= NSEC_PER_SEC {
        /*
         * The following asm() prevents the compiler from
         * optimising this loop into a modulo operation. See
         * also __iter_div_u64_rem() in include/linux/time.h
         */
        unsafe { core::arch::asm!("/* {0} */", inout(reg) nsec, options(nomem, nostack, preserves_flags)) };
        nsec -= NSEC_PER_SEC;
        sec = sec.wrapping_add(1);
    }
    while nsec < 0 {
        unsafe { core::arch::asm!("/* {0} */", inout(reg) nsec, options(nomem, nostack, preserves_flags)) };
        nsec += NSEC_PER_SEC;
        sec = sec.wrapping_sub(1);
    }
    unsafe {
        (*ts).tv_sec = sec;
        (*ts).tv_nsec = nsec;
    }
}

kernel::kabi_export! {
    ns_to_timespec64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#s64 nsec ) -> s#timespec64",
}
/// `ns_to_timespec64()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn ns_to_timespec64(nsec: i64) -> Timespec64 {
    let mut ts = Timespec64 { tv_sec: 0, tv_nsec: 0 };

    if nsec > 0 {
        ts.tv_sec = ((nsec as u64) / NSEC_PER_SEC as u64) as i64;
        ts.tv_nsec = ((nsec as u64) % NSEC_PER_SEC as u64) as u32 as c_long;
    } else if nsec < 0 {
        /*
         * With negative times, tv_sec points to the earlier
         * second, and tv_nsec counts the nanoseconds since
         * then, so tv_nsec is always a positive number.
         */
        let n = (nsec.wrapping_neg().wrapping_sub(1)) as u64;
        let q = (n / NSEC_PER_SEC as u64) as i64;
        let rem = (n % NSEC_PER_SEC as u64) as u32;
        ts.tv_sec = q.wrapping_neg().wrapping_sub(1);
        ts.tv_nsec = (NSEC_PER_SEC as u32).wrapping_sub(rem).wrapping_sub(1) as c_long;
    }

    ts
}

/// `_msecs_to_jiffies()` (header inline).
#[inline(always)]
fn _msecs_to_jiffies(m: u32) -> u64 {
    if HZ <= MSEC_PER_SEC && MSEC_PER_SEC % HZ == 0 {
        ((m as i64 + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ)) as u64
    } else {
        /* HZ > MSEC_PER_SEC is not offered; the third arm is the generic one */
        (MSEC_TO_HZ_MUL32.wrapping_mul(m as u64).wrapping_add(MSEC_TO_HZ_ADJ32)) >> MSEC_TO_HZ_SHR32
    }
}

kernel::kabi_export! {
    __msecs_to_jiffies,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } m ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `__msecs_to_jiffies()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn __msecs_to_jiffies(m: u32) -> u64 {
    /*
     * Negative value, means infinite timeout:
     */
    if (m as i32) < 0 {
        return MAX_JIFFY_OFFSET;
    }
    _msecs_to_jiffies(m)
}

/// `_usecs_to_jiffies()` (header inline).
#[inline(always)]
fn _usecs_to_jiffies(u: u32) -> u64 {
    if USEC_PER_SEC % HZ == 0 {
        ((u as i64 + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ)) as u64
    } else {
        (USEC_TO_HZ_MUL32.wrapping_mul(u as u64).wrapping_add(USEC_TO_HZ_ADJ32)) >> USEC_TO_HZ_SHR32
    }
}

kernel::kabi_export! {
    __usecs_to_jiffies,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned int byte_size(4) encoding(7) } u ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `__usecs_to_jiffies()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn __usecs_to_jiffies(u: u32) -> u64 {
    if u > jiffies_to_usecs(MAX_JIFFY_OFFSET) {
        return MAX_JIFFY_OFFSET;
    }
    _usecs_to_jiffies(u)
}

kernel::kabi_export! {
    timespec64_to_jiffies,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#timespec64 } } value ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `timespec64_to_jiffies()`.
///
/// # Safety
/// `value` readable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn timespec64_to_jiffies(value: *const Timespec64) -> u64 {
    let mut sec: u64 = unsafe { (*value).tv_sec } as u64;
    let mut nsec: i64 = unsafe { (*value).tv_nsec }.wrapping_add(TICK_NSEC).wrapping_sub(1);

    if sec >= MAX_SEC_IN_JIFFIES as u64 {
        sec = MAX_SEC_IN_JIFFIES as u64;
        nsec = 0;
    }
    (sec.wrapping_mul(SEC_CONVERSION)
        .wrapping_add(((nsec as u64).wrapping_mul(NSEC_CONVERSION)) >> (NSEC_JIFFIE_SC - SEC_JIFFIE_SC)))
        >> SEC_JIFFIE_SC
}

kernel::kabi_export! {
    jiffies_to_timespec64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { base_type unsigned long byte_size(8) encoding(7) } jiffies , formal_parameter pointer_type { s#timespec64 } value ) -> base_type void",
}
/// `jiffies_to_timespec64()`.
///
/// # Safety
/// `value` writable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn jiffies_to_timespec64(jiffies: u64, value: *mut Timespec64) {
    /*
     * Convert jiffies to nanoseconds and separate with
     * one divide.
     */
    let ns = jiffies.wrapping_mul(TICK_NSEC as u64);
    unsafe {
        (*value).tv_sec = (ns / NSEC_PER_SEC as u64) as i64;
        (*value).tv_nsec = (ns % NSEC_PER_SEC as u64) as u32 as c_long;
    }
}

kernel::kabi_export! {
    jiffies_to_clock_t,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) x ) -> t#clock_t",
}
/// `jiffies_to_clock_t()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn jiffies_to_clock_t(x: u64) -> c_long {
    if TICK_NSEC % (NSEC_PER_SEC / USER_HZ) == 0 {
        if HZ < USER_HZ {
            x.wrapping_mul((USER_HZ / HZ) as u64) as c_long
        } else {
            (x / (HZ / USER_HZ) as u64) as c_long
        }
    } else {
        (x.wrapping_mul(TICK_NSEC as u64) / (NSEC_PER_SEC / USER_HZ) as u64) as c_long
    }
}

kernel::kabi_export! {
    clock_t_to_jiffies,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) x ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `clock_t_to_jiffies()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn clock_t_to_jiffies(x: u64) -> u64 {
    if HZ % USER_HZ == 0 {
        if x >= !0u64 / (HZ / USER_HZ) as u64 {
            return !0u64;
        }
        x * (HZ / USER_HZ) as u64
    } else {
        /* Don't worry about loss of precision here .. */
        if x >= !0u64 / HZ as u64 * USER_HZ as u64 {
            return !0u64;
        }

        /* .. but do try to contain it here */
        x.wrapping_mul(HZ as u64) / USER_HZ as u64
    }
}

kernel::kabi_export! {
    jiffies64_to_nsecs,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#u64 j ) -> t#u64",
}
/// `jiffies64_to_nsecs()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn jiffies64_to_nsecs(j: u64) -> u64 {
    if NSEC_PER_SEC % HZ == 0 {
        ((NSEC_PER_SEC / HZ) as u64).wrapping_mul(j)
    } else {
        j.wrapping_mul(HZ_TO_NSEC_NUM) / HZ_TO_NSEC_DEN
    }
}

kernel::kabi_export! {
    jiffies64_to_msecs,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { t#u64 } j ) -> t#u64",
}
/// `jiffies64_to_msecs()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn jiffies64_to_msecs(j: u64) -> u64 {
    if HZ <= MSEC_PER_SEC && MSEC_PER_SEC % HZ == 0 {
        ((MSEC_PER_SEC / HZ) as u64).wrapping_mul(j)
    } else {
        j.wrapping_mul(HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN
    }
}

kernel::kabi_export! {
    nsecs_to_jiffies64,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#u64 n ) -> t#u64",
}
/// `nsecs_to_jiffies64()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nsecs_to_jiffies64(n: u64) -> u64 {
    if NSEC_PER_SEC % HZ == 0 {
        /* Common case, HZ = 100, 128, 200, 250, 256, 500, 512, 1000 etc. */
        n / (NSEC_PER_SEC / HZ) as u64
    } else {
        /*
         * Generic case - optimized for cases where HZ is a multiple of 3.
         * overflow after 64.99 years, exact for HZ = 60, 72, 90, 120 etc.
         */
        n.wrapping_mul(9) / ((9u64 * NSEC_PER_SEC as u64 + HZ as u64 / 2) / HZ as u64)
    }
}

kernel::kabi_export! {
    nsecs_to_jiffies,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#u64 n ) -> base_type unsigned long byte_size(8) encoding(7)",
}
/// `nsecs_to_jiffies()`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nsecs_to_jiffies(n: u64) -> u64 {
    nsecs_to_jiffies64(n)
}

kernel::kabi_export! {
    timespec64_add_safe,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter const_type { s#timespec64 } lhs , formal_parameter const_type { s#timespec64 } rhs ) -> s#timespec64",
}
/// `timespec64_add_safe()`: add two timespecs, saturating at `TIME64_MAX`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn timespec64_add_safe(lhs: Timespec64, rhs: Timespec64) -> Timespec64 {
    let mut res = Timespec64 { tv_sec: 0, tv_nsec: 0 };

    unsafe {
        set_normalized_timespec64(
            &mut res,
            (lhs.tv_sec as u64).wrapping_add(rhs.tv_sec as u64) as i64,
            lhs.tv_nsec.wrapping_add(rhs.tv_nsec),
        )
    };

    if res.tv_sec < lhs.tv_sec || res.tv_sec < rhs.tv_sec {
        res.tv_sec = TIME64_MAX;
        res.tv_nsec = 0;
    }

    res
}

#[allow(dead_code)]
const _UNUSED: c_int = 0;
