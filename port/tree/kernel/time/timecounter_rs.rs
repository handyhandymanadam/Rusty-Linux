// SPDX-License-Identifier: GPL-2.0+

//! Cycle counter to nanosecond conversion -- the Rust behind `kernel/time/timecounter.c`.
//!
//! Ported from `kernel/time/timecounter.c` (6.18.49). Three exported functions over
//! `struct timecounter` / `struct cyclecounter` (the caller -- NIC PTP drivers -- owns
//! both). `cyclecounter_cyc2ns()` is a `static inline` in `include/linux/timecounter.h`;
//! it is mirrored here ([`cyc2ns`]), the header copy stays for C callers.
//!
//! No `EXPORT_SYMBOL_GPL` keeps a C entry: none of the three has a guard, WARN or static
//! key, so `kernel::kabi_export!` carries each export and its MODVERSIONS contract (the
//! C definitions' gendwarfksyms text; CRCs 0xf6f0b662, 0x8bd8892f, 0xbf022f77).
//!
//! Arithmetic is the C's modulo 2^64. A `shift` of 64 or more is undefined in C; here it is
//! masked to 6 bits (`wrapping_shr/shl`), which is what the x86 shift instruction does.
//!
//! Replaces: kernel/time/timecounter.c

/// Mirrors `struct cyclecounter` (`include/linux/timecounter.h`).
#[repr(C)]
pub struct CycleCounter {
    read: Option<unsafe extern "C" fn(*mut CycleCounter) -> u64>,
    mask: u64,
    mult: u32,
    shift: u32,
}

/// Mirrors `struct timecounter` (`include/linux/timecounter.h`).
#[repr(C)]
pub struct TimeCounter {
    cc: *mut CycleCounter,
    cycle_last: u64,
    nsec: u64,
    mask: u64,
    frac: u64,
}

/// `cyclecounter_cyc2ns()`.
#[inline(always)]
unsafe fn cyc2ns(cc: *const CycleCounter, cycles: u64, mask: u64, frac: &mut u64) -> u64 {
    let mut ns = cycles;

    ns = ns.wrapping_mul(unsafe { (*cc).mult } as u64).wrapping_add(*frac);
    *frac = ns & mask;
    ns.wrapping_shr(unsafe { (*cc).shift })
}

// Types the contracts below refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#cyclecounter",
    "structure_type cyclecounter { member pointer_type { subroutine_type ( formal_parameter pointer_type { s#cyclecounter } ) -> t#u64 } read data_member_location(0) , member t#u64 mask data_member_location(8) , member t#u32 mult data_member_location(16) , member t#u32 shift data_member_location(20) } byte_size(24)");
kernel::kabi_rule!("type_string", "s#timecounter",
    "structure_type timecounter { member pointer_type { s#cyclecounter } cc data_member_location(0) , member t#u64 cycle_last data_member_location(8) , member t#u64 nsec data_member_location(16) , member t#u64 mask data_member_location(24) , member t#u64 frac data_member_location(32) } byte_size(40)");
kernel::kabi_rule!("type_string", "t#__u32",
    "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u32",
    "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u64",
    "typedef_type u64 { t#__u64 }");

kernel::kabi_export! {
    timecounter_init,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timecounter } tc , formal_parameter pointer_type { s#cyclecounter } cc , formal_parameter t#u64 start_tstamp ) -> base_type void",
}

/// `timecounter_init()`: start a time counter at `start_tstamp`.
///
/// # Safety
/// `tc` writable; `cc` valid with a callable `read`.
#[no_mangle]
pub unsafe extern "C" fn timecounter_init(tc: *mut TimeCounter, cc: *mut CycleCounter, start_tstamp: u64) {
    let tc = unsafe { &mut *tc };
    tc.cc = cc;
    tc.cycle_last = unsafe { ((*cc).read.unwrap_unchecked())(cc) };
    tc.nsec = start_tstamp;
    tc.mask = 1u64.wrapping_shl(unsafe { (*cc).shift }).wrapping_sub(1);
    tc.frac = 0;
}

/// `timecounter_read_delta()`: nanoseconds since the last call.
unsafe fn timecounter_read_delta(tc: &mut TimeCounter) -> u64 {
    /* read cycle counter: */
    let cycle_now = unsafe { ((*tc.cc).read.unwrap_unchecked())(tc.cc) };

    /* calculate the delta since the last timecounter_read_delta(): */
    let cycle_delta = cycle_now.wrapping_sub(tc.cycle_last) & unsafe { (*tc.cc).mask };

    /* convert to nanoseconds: */
    let ns_offset = unsafe { cyc2ns(tc.cc, cycle_delta, tc.mask, &mut tc.frac) };

    /* update time stamp of timecounter_read_delta() call: */
    tc.cycle_last = cycle_now;

    ns_offset
}

kernel::kabi_export! {
    timecounter_read,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#timecounter } tc ) -> t#u64",
}

/// `timecounter_read()`: current time in nanoseconds.
///
/// # Safety
/// `tc` initialised by `timecounter_init()`.
#[no_mangle]
pub unsafe extern "C" fn timecounter_read(tc: *mut TimeCounter) -> u64 {
    let tc = unsafe { &mut *tc };

    /* increment time by nanoseconds since last call */
    let mut nsec = unsafe { timecounter_read_delta(tc) };
    nsec = nsec.wrapping_add(tc.nsec);
    tc.nsec = nsec;

    nsec
}

/// `cc_cyc2ns_backwards()`.
unsafe fn cc_cyc2ns_backwards(cc: *const CycleCounter, cycles: u64, _mask: u64, frac: u64) -> u64 {
    let ns = cycles;

    ns.wrapping_mul(unsafe { (*cc).mult } as u64)
        .wrapping_sub(frac)
        .wrapping_shr(unsafe { (*cc).shift })
}

kernel::kabi_export! {
    timecounter_cyc2time,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#timecounter } } tc , formal_parameter t#u64 cycle_tstamp ) -> t#u64",
}

/// `timecounter_cyc2time()`: convert a cycle time stamp to nanoseconds.
///
/// # Safety
/// `tc` initialised by `timecounter_init()`.
#[no_mangle]
pub unsafe extern "C" fn timecounter_cyc2time(tc: *const TimeCounter, cycle_tstamp: u64) -> u64 {
    let tc = unsafe { &*tc };
    let cc = tc.cc;
    let cc_mask = unsafe { (*cc).mask };
    let mut delta = cycle_tstamp.wrapping_sub(tc.cycle_last) & cc_mask;
    let mut nsec = tc.nsec;
    let mut frac = tc.frac;

    /*
     * Instead of always treating cycle_tstamp as more recent
     * than tc->cycle_last, detect when it is too far in the
     * future and treat it as old time stamp instead.
     */
    if delta > cc_mask / 2 {
        delta = tc.cycle_last.wrapping_sub(cycle_tstamp) & cc_mask;
        nsec = nsec.wrapping_sub(unsafe { cc_cyc2ns_backwards(cc, delta, tc.mask, frac) });
    } else {
        nsec = nsec.wrapping_add(unsafe { cyc2ns(cc, delta, tc.mask, &mut frac) });
    }

    nsec
}
