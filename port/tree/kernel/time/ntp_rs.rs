// SPDX-License-Identifier: GPL-2.0

//! The NTP discipline arithmetic of `kernel/time/ntp.c` -- the Rust behind it.
//!
//! Ported from `kernel/time/ntp.c` (6.18.49, without `CONFIG_NTP_PPS`): the tick-length bookkeeping (`ntp_update_frequency()`), the phase/frequency-lock loop
//! (`ntp_update_offset_fll()`, `ntp_update_offset()`), `__ntp_clear()`, the per-second step with leap-second state machine (`second_overflow()`), `ntp_get_next_leap()`
//! and the `adjtimex()` handler (`process_adj_status()`, `process_adjtimex_modes()`, `ntp_adjtimex()`). In C (`ntp_glue.c`): the per-timekeeper state array and its initial
//! values, the exports, the CMOS / RTC sync timer, the `ntp_tick_adj=` parameter, `ntp_init()`, and wrappers for `ktime_get_ntp_seconds()`, `pr_notice()` and the audit
//! hooks. The kernel is built with `-fwrapv`, so every arithmetic operation here wraps. Every numeric constant is checked against the headers by `static_assert`s in the glue.
//!
//! The PPS variant (`CONFIG_NTP_PPS`) is not ported: with it the structure has more fields, and the C file is built as upstream has it.
//!
//! Replaces: kernel/time/ntp.c (the discipline arithmetic)

use core::ffi::{c_int, c_long, c_uint, c_ulong};

const NTP_SCALE_SHIFT: u32 = 32;
const SHIFT_PLL: u32 = 2;
const SHIFT_FLL: u32 = 2;
const SHIFT_USEC: u32 = 16;
const MAXTC: i64 = 10;
const MINSEC: c_long = 256;
const MAXSEC: c_long = 2048;
const MAXPHASE: c_long = 500_000_000;
const MAXFREQ: c_long = 500_000;
const MAXFREQ_SCALED: i64 = (MAXFREQ as i64) << NTP_SCALE_SHIFT;
const NTP_PHASE_LIMIT: c_long = (MAXPHASE / 1000) << 5;
const PPM_SCALE: i64 = 1000i64 << (NTP_SCALE_SHIFT - SHIFT_USEC);
const PPM_SCALE_INV_SHIFT: u32 = 19;
const PPM_SCALE_INV: i64 = (1i64 << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / PPM_SCALE + 1;
const USEC_PER_SEC: c_long = 1_000_000;
const NSEC_PER_USEC: i64 = 1000;
const USER_HZ: u64 = 100;
const SECS_PER_DAY: i64 = 86400;
const MAX_TICKADJ: i64 = 500;
const MAX_TAI_OFFSET: i64 = 100_000;
const TIME64_MAX: i64 = i64::MAX;

const STA_PLL: c_int = 0x0001;
const STA_FLL: c_int = 0x0008;
const STA_INS: c_int = 0x0010;
const STA_DEL: c_int = 0x0020;
const STA_UNSYNC: c_int = 0x0040;
const STA_FREQHOLD: c_int = 0x0080;
const STA_CLOCKERR: c_int = 0x1000;
const STA_NANO: c_int = 0x2000;
const STA_MODE: c_int = 0x4000;
const STA_RONLY: c_int = 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x4000 | 0x8000;

const TIME_OK: c_int = 0;
const TIME_INS: c_int = 1;
const TIME_DEL: c_int = 2;
const TIME_OOP: c_int = 3;
const TIME_WAIT: c_int = 4;
const TIME_ERROR: c_int = 5;

const ADJ_OFFSET: c_uint = 0x0001;
const ADJ_FREQUENCY: c_uint = 0x0002;
const ADJ_MAXERROR: c_uint = 0x0004;
const ADJ_ESTERROR: c_uint = 0x0008;
const ADJ_STATUS: c_uint = 0x0010;
const ADJ_TIMECONST: c_uint = 0x0020;
const ADJ_TAI: c_uint = 0x0080;
const ADJ_MICRO: c_uint = 0x1000;
const ADJ_NANO: c_uint = 0x2000;
const ADJ_TICK: c_uint = 0x4000;
const ADJ_ADJTIME: c_uint = 0x8000;
const ADJ_OFFSET_READONLY: c_uint = 0x2000;

// audit kinds understood by rust_nt_audit()
const AU_OFFSET: c_int = 0;
const AU_FREQ: c_int = 1;
const AU_STATUS: c_int = 2;
const AU_TAI: c_int = 3;
const AU_TICK: c_int = 4;
const AU_ADJUST: c_int = 5;

/// Mirrors `struct ntp_data` without `CONFIG_NTP_PPS`.
#[repr(C)]
pub struct NtpData {
    tick_usec: c_ulong,
    tick_length: u64,
    tick_length_base: u64,
    time_state: c_int,
    time_status: c_int,
    time_offset: i64,
    time_constant: c_long,
    time_maxerror: c_long,
    time_esterror: c_long,
    time_freq: i64,
    time_reftime: i64,
    time_adjust: c_long,
    ntp_tick_adj: i64,
    ntp_next_leap_sec: i64,
}

/// Mirrors `struct __kernel_timex`.
#[repr(C)]
pub struct Timex {
    modes: c_uint,
    _pad0: c_int,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: c_int,
    _pad1: c_int,
    constant: i64,
    precision: i64,
    tolerance: i64,
    time_sec: i64,
    time_usec: i64,
    tick: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: c_int,
    _pad2: c_int,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
    tai: c_int,
    _pad3: [c_int; 11],
}

/// Mirrors `struct timespec64`.
#[repr(C)]
pub struct Ts64 {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    /// `NTP_INTERVAL_FREQ` (= HZ), a configuration value.
    static rust_nt_hz: c_int;
    fn rust_nt_ntp_seconds(tkid: c_uint) -> c_long;
    fn rust_nt_notice_ins();
    fn rust_nt_notice_del();
    fn rust_nt_audit(ad: *mut core::ffi::c_void, kind: c_int, is_new: bool, val: i64);
}

#[inline]
fn hz() -> i64 {
    unsafe { rust_nt_hz as i64 }
}

/// `shift_right()`: shifts a possibly negative value toward zero.
#[inline]
fn shift_right(x: i64, s: u32) -> i64 {
    if x < 0 {
        x.wrapping_neg().wrapping_shr(s).wrapping_neg()
    } else {
        x >> s
    }
}

/// `ntp_update_frequency()`.
fn update_frequency(n: &mut NtpData) {
    let tick_usec = n.tick_usec as u64;
    let mut second_length = (tick_usec.wrapping_mul(NSEC_PER_USEC as u64).wrapping_mul(USER_HZ)) << NTP_SCALE_SHIFT;
    second_length = second_length.wrapping_add(n.ntp_tick_adj as u64);
    second_length = second_length.wrapping_add(n.time_freq as u64);
    let new_base = second_length / (hz() as u64);
    n.tick_length = n.tick_length.wrapping_add(new_base.wrapping_sub(n.tick_length_base));
    n.tick_length_base = new_base;
}

/// `ntp_update_offset_fll()`.
fn update_offset_fll(n: &mut NtpData, offset64: i64, secs: c_long) -> i64 {
    n.time_status &= !STA_MODE;
    if secs < MINSEC {
        return 0;
    }
    if n.time_status & STA_FLL == 0 && secs <= MAXSEC {
        return 0;
    }
    n.time_status |= STA_MODE;
    (offset64 << (NTP_SCALE_SHIFT - SHIFT_FLL)).wrapping_div(secs)
}

/// `ntp_update_offset()`.
fn update_offset(n: &mut NtpData, tkid: c_uint, mut offset: c_long) {
    if n.time_status & STA_PLL == 0 {
        return;
    }
    if n.time_status & STA_NANO == 0 {
        // Make sure the multiplication below won't overflow.
        offset = offset.clamp(-USEC_PER_SEC, USEC_PER_SEC);
        offset = offset.wrapping_mul(NSEC_PER_USEC as c_long);
    }
    // Scale the phase adjustment and clamp to the operating range.
    offset = offset.clamp(-MAXPHASE, MAXPHASE);

    let real_secs = unsafe { rust_nt_ntp_seconds(tkid) };
    let mut secs: c_long = real_secs.wrapping_sub(n.time_reftime);
    if n.time_status & STA_FREQHOLD != 0 {
        secs = 0;
    }
    n.time_reftime = real_secs;

    let offset64 = offset as i64;
    let mut freq_adj = update_offset_fll(n, offset64, secs);

    // Clamp update interval to reduce PLL gain with low sampling rate.
    let lim = 1i64 << (SHIFT_PLL as i64 + 1 + n.time_constant);
    if secs > lim as c_long {
        secs = lim as c_long;
    }
    freq_adj = freq_adj.wrapping_add((offset64.wrapping_mul(secs as i64)) << (NTP_SCALE_SHIFT as i64 - 2 * (SHIFT_PLL as i64 + 2 + n.time_constant)));
    freq_adj = freq_adj.wrapping_add(n.time_freq).min(MAXFREQ_SCALED);
    n.time_freq = freq_adj.max(-MAXFREQ_SCALED);
    n.time_offset = (offset64 << NTP_SCALE_SHIFT).wrapping_div(hz());
}

/// `__ntp_clear()`.
fn clear(n: &mut NtpData) {
    n.time_adjust = 0;
    n.time_status |= STA_UNSYNC;
    n.time_maxerror = NTP_PHASE_LIMIT;
    n.time_esterror = NTP_PHASE_LIMIT;
    update_frequency(n);
    n.tick_length = n.tick_length_base;
    n.time_offset = 0;
    n.ntp_next_leap_sec = TIME64_MAX;
}

/// Body of `__ntp_clear()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ntp_clear(n: *mut NtpData) {
    clear(unsafe { &mut *n })
}

/// Body of `ntp_get_next_leap()` for the core timekeeper: the leap time, or `None`-as-`false`.
#[no_mangle]
pub unsafe extern "C" fn rust_ntp_next_leap(n: *const NtpData, out: *mut i64) -> bool {
    let n = unsafe { &*n };
    if n.time_state == TIME_INS && n.time_status & STA_INS != 0 {
        unsafe { *out = n.ntp_next_leap_sec };
        return true;
    }
    false
}

/// Body of `second_overflow()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ntp_second_overflow(n: *mut NtpData, secs: i64) -> c_int {
    let n = unsafe { &mut *n };
    let mut leap = 0;
    match n.time_state {
        TIME_OK => {
            if n.time_status & STA_INS != 0 {
                n.time_state = TIME_INS;
                let rem = secs % SECS_PER_DAY;
                n.ntp_next_leap_sec = secs.wrapping_add(SECS_PER_DAY).wrapping_sub(rem);
            } else if n.time_status & STA_DEL != 0 {
                n.time_state = TIME_DEL;
                let rem = secs.wrapping_add(1) % SECS_PER_DAY;
                n.ntp_next_leap_sec = secs.wrapping_add(SECS_PER_DAY).wrapping_sub(rem);
            }
        }
        TIME_INS => {
            if n.time_status & STA_INS == 0 {
                n.ntp_next_leap_sec = TIME64_MAX;
                n.time_state = TIME_OK;
            } else if secs == n.ntp_next_leap_sec {
                leap = -1;
                n.time_state = TIME_OOP;
                unsafe { rust_nt_notice_ins() };
            }
        }
        TIME_DEL => {
            if n.time_status & STA_DEL == 0 {
                n.ntp_next_leap_sec = TIME64_MAX;
                n.time_state = TIME_OK;
            } else if secs == n.ntp_next_leap_sec {
                leap = 1;
                n.ntp_next_leap_sec = TIME64_MAX;
                n.time_state = TIME_WAIT;
                unsafe { rust_nt_notice_del() };
            }
        }
        TIME_OOP => {
            n.ntp_next_leap_sec = TIME64_MAX;
            n.time_state = TIME_WAIT;
        }
        TIME_WAIT => {
            if n.time_status & (STA_INS | STA_DEL) == 0 {
                n.time_state = TIME_OK;
            }
        }
        _ => {}
    }

    // Bump the maxerror field.
    n.time_maxerror = n.time_maxerror.wrapping_add(MAXFREQ / NSEC_PER_USEC as c_long);
    if n.time_maxerror > NTP_PHASE_LIMIT {
        n.time_maxerror = NTP_PHASE_LIMIT;
        n.time_status |= STA_UNSYNC;
    }

    // Compute the phase adjustment for the next second.
    n.tick_length = n.tick_length_base;
    let delta = shift_right(n.time_offset, SHIFT_PLL + n.time_constant as u32);
    n.time_offset = n.time_offset.wrapping_sub(delta);
    n.tick_length = n.tick_length.wrapping_add(delta as u64);

    if n.time_adjust == 0 {
        return leap;
    }
    let max_tickadj_scaled: i64 = ((MAX_TICKADJ * NSEC_PER_USEC) << NTP_SCALE_SHIFT) / hz();
    if n.time_adjust as i64 > MAX_TICKADJ {
        n.time_adjust -= MAX_TICKADJ as c_long;
        n.tick_length = n.tick_length.wrapping_add(max_tickadj_scaled as u64);
        return leap;
    }
    if (n.time_adjust as i64) < -MAX_TICKADJ {
        n.time_adjust += MAX_TICKADJ as c_long;
        n.tick_length = n.tick_length.wrapping_sub(max_tickadj_scaled as u64);
        return leap;
    }
    let step = ((n.time_adjust as i64).wrapping_mul(NSEC_PER_USEC) / hz()) << NTP_SCALE_SHIFT;
    n.tick_length = n.tick_length.wrapping_add(step as u64);
    n.time_adjust = 0;
    leap
}

/// `process_adj_status()`.
fn process_adj_status(n: &mut NtpData, tkid: c_uint, txc: &Timex) {
    if n.time_status & STA_PLL != 0 && txc.status & STA_PLL == 0 {
        n.time_state = TIME_OK;
        n.time_status = STA_UNSYNC;
        n.ntp_next_leap_sec = TIME64_MAX;
    }
    // If we turn on PLL adjustments then reset the reference time to current time.
    if n.time_status & STA_PLL == 0 && txc.status & STA_PLL != 0 {
        n.time_reftime = unsafe { rust_nt_ntp_seconds(tkid) };
    }
    // only set allowed bits
    n.time_status &= STA_RONLY;
    n.time_status |= txc.status & !STA_RONLY;
}

/// `process_adjtimex_modes()`.
fn process_modes(n: &mut NtpData, tkid: c_uint, txc: &Timex, time_tai: &mut i32) {
    if txc.modes & ADJ_STATUS != 0 {
        process_adj_status(n, tkid, txc);
    }
    if txc.modes & ADJ_NANO != 0 {
        n.time_status |= STA_NANO;
    }
    if txc.modes & ADJ_MICRO != 0 {
        n.time_status &= !STA_NANO;
    }
    if txc.modes & ADJ_FREQUENCY != 0 {
        n.time_freq = txc.freq.wrapping_mul(PPM_SCALE);
        n.time_freq = n.time_freq.min(MAXFREQ_SCALED);
        n.time_freq = n.time_freq.max(-MAXFREQ_SCALED);
    }
    if txc.modes & ADJ_MAXERROR != 0 {
        n.time_maxerror = (txc.maxerror as c_long).clamp(0, NTP_PHASE_LIMIT);
    }
    if txc.modes & ADJ_ESTERROR != 0 {
        n.time_esterror = (txc.esterror as c_long).clamp(0, NTP_PHASE_LIMIT);
    }
    if txc.modes & ADJ_TIMECONST != 0 {
        n.time_constant = (txc.constant as c_long).clamp(0, MAXTC as c_long);
        if n.time_status & STA_NANO == 0 {
            n.time_constant += 4;
        }
        n.time_constant = n.time_constant.clamp(0, MAXTC as c_long);
    }
    if txc.modes & ADJ_TAI != 0 && txc.constant >= 0 && txc.constant <= MAX_TAI_OFFSET {
        *time_tai = txc.constant as i32;
    }
    if txc.modes & ADJ_OFFSET != 0 {
        update_offset(n, tkid, txc.offset as c_long);
    }
    if txc.modes & ADJ_TICK != 0 {
        n.tick_usec = txc.tick as c_ulong;
    }
    if txc.modes & (ADJ_TICK | ADJ_FREQUENCY | ADJ_OFFSET) != 0 {
        update_frequency(n);
    }
}

/// Body of `ntp_adjtimex()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ntp_adjtimex(n: *mut NtpData, tkid: c_uint, txc: *mut Timex, ts: *const Ts64, time_tai: *mut i32, ad: *mut core::ffi::c_void) -> c_int {
    let (n, txc, ts, time_tai) = unsafe { (&mut *n, &mut *txc, &*ts, &mut *time_tai) };
    if txc.modes & ADJ_ADJTIME != 0 {
        let save_adjust = n.time_adjust;
        if txc.modes & ADJ_OFFSET_READONLY == 0 {
            // adjtime() is independent from ntp_adjtime()
            n.time_adjust = txc.offset as c_long;
            update_frequency(n);
            unsafe {
                rust_nt_audit(ad, AU_ADJUST, false, save_adjust as i64);
                rust_nt_audit(ad, AU_ADJUST, true, n.time_adjust as i64);
            }
        }
        txc.offset = save_adjust as i64;
    } else {
        // If there are input parameters, then process them.
        if txc.modes != 0 {
            unsafe {
                rust_nt_audit(ad, AU_OFFSET, false, n.time_offset);
                rust_nt_audit(ad, AU_FREQ, false, n.time_freq);
                rust_nt_audit(ad, AU_STATUS, false, n.time_status as i64);
                rust_nt_audit(ad, AU_TAI, false, *time_tai as i64);
                rust_nt_audit(ad, AU_TICK, false, n.tick_usec as i64);
            }
            process_modes(n, tkid, txc, time_tai);
            unsafe {
                rust_nt_audit(ad, AU_OFFSET, true, n.time_offset);
                rust_nt_audit(ad, AU_FREQ, true, n.time_freq);
                rust_nt_audit(ad, AU_STATUS, true, n.time_status as i64);
                rust_nt_audit(ad, AU_TAI, true, *time_tai as i64);
                rust_nt_audit(ad, AU_TICK, true, n.tick_usec as i64);
            }
        }
        txc.offset = shift_right(n.time_offset.wrapping_mul(hz()), NTP_SCALE_SHIFT);
        if n.time_status & STA_NANO == 0 {
            txc.offset = txc.offset.wrapping_div(NSEC_PER_USEC);
        }
    }

    let mut result = n.time_state;
    if n.time_status & (STA_UNSYNC | STA_CLOCKERR) != 0 {
        result = TIME_ERROR;
    }

    txc.freq = shift_right((n.time_freq >> PPM_SCALE_INV_SHIFT).wrapping_mul(PPM_SCALE_INV), NTP_SCALE_SHIFT);
    txc.maxerror = n.time_maxerror as i64;
    txc.esterror = n.time_esterror as i64;
    txc.status = n.time_status;
    txc.constant = n.time_constant as i64;
    txc.precision = 1;
    txc.tolerance = MAXFREQ_SCALED / PPM_SCALE;
    txc.tick = n.tick_usec as i64;
    txc.tai = *time_tai;

    // Fill PPS status fields: PPS is not implemented, so these are zero.
    txc.ppsfreq = 0;
    txc.jitter = 0;
    txc.shift = 0;
    txc.stabil = 0;
    txc.jitcnt = 0;
    txc.calcnt = 0;
    txc.errcnt = 0;
    txc.stbcnt = 0;

    txc.time_sec = ts.tv_sec;
    txc.time_usec = ts.tv_nsec;
    if n.time_status & STA_NANO == 0 {
        txc.time_usec = ts.tv_nsec / NSEC_PER_USEC;
    }

    // Handle leapsec adjustments.
    if ts.tv_sec >= n.ntp_next_leap_sec {
        if n.time_state == TIME_INS && n.time_status & STA_INS != 0 {
            result = TIME_OOP;
            txc.tai = txc.tai.wrapping_add(1);
            txc.time_sec = txc.time_sec.wrapping_sub(1);
        }
        if n.time_state == TIME_DEL && n.time_status & STA_DEL != 0 {
            result = TIME_WAIT;
            txc.tai = txc.tai.wrapping_sub(1);
            txc.time_sec = txc.time_sec.wrapping_add(1);
        }
        if n.time_state == TIME_OOP && ts.tv_sec == n.ntp_next_leap_sec {
            result = TIME_WAIT;
        }
    }
    result
}
