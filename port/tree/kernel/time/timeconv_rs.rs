// SPDX-License-Identifier: LGPL-2.0+

//! Calendar conversion: `time64_to_tm()`.
//!
//! Ported from `kernel/time/timeconv.c` (6.18.49). Copyright (C) 2001, 2002,
//! 2003, 2004, 2005, 2006, 2007, 2008, 2009 Free Software Foundation, Inc.,
//! contributed by Paul Eggert (the date algorithm itself is Proposition 6.3 of
//! Neri and Schneider, "Euclidean Affine Functions and Applications to Calendar
//! Algorithms", https://arxiv.org/abs/2102.06959, as the C file says).
//!
//! The C file is one pure function, so it is the whole file: no C entry stays
//! (no guard, WARN or static key). `EXPORT_SYMBOL` is carried by
//! `kernel::kabi_export!`; the contract text is the C definition's
//! gendwarfksyms output (CRC 0xc06bd7c6), taken before the C was removed.
//!
//! Replaces: kernel/time/timeconv.c

use core::ffi::{c_int, c_long};

const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;

/// Mirrors `struct tm` (`include/linux/time.h`).
#[repr(C)]
pub struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_long,
    tm_wday: c_int,
    tm_yday: c_int,
}

// Types the contracts below refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#tm",
    "structure_type tm { member base_type int byte_size(4) encoding(5) tm_sec data_member_location(0) , member base_type int byte_size(4) encoding(5) tm_min data_member_location(4) , member base_type int byte_size(4) encoding(5) tm_hour data_member_location(8) , member base_type int byte_size(4) encoding(5) tm_mday data_member_location(12) , member base_type int byte_size(4) encoding(5) tm_mon data_member_location(16) , member base_type long byte_size(8) encoding(5) tm_year data_member_location(24) , member base_type int byte_size(4) encoding(5) tm_wday data_member_location(32) , member base_type int byte_size(4) encoding(5) tm_yday data_member_location(36) } byte_size(40)");
kernel::kabi_rule!("type_string", "t#__s64",
    "typedef_type __s64 { base_type long long byte_size(8) encoding(5) }");
kernel::kabi_rule!("type_string", "t#time64_t",
    "typedef_type time64_t { t#__s64 }");

kernel::kabi_export! {
    time64_to_tm,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter t#time64_t totalsecs , formal_parameter base_type int byte_size(4) encoding(5) offset , formal_parameter pointer_type { s#tm } result ) -> base_type void",
}

/// Break `totalsecs` (seconds since 1970-01-01 00:00:00 UTC), shifted by
/// `offset` seconds, into calendar fields.
///
/// # Safety
/// `result` must be writable for one `struct tm`.
#[no_mangle]
pub unsafe extern "C" fn time64_to_tm(totalsecs: i64, offset: c_int, result: *mut Tm) {
    let result = unsafe { &mut *result };

    /* div_s64_rem(): truncating division, remainder takes the dividend's sign */
    let mut days: i64 = totalsecs / SECS_PER_DAY;
    let mut rem: i64 = (totalsecs % SECS_PER_DAY) + offset as i64;
    while rem < 0 {
        rem += SECS_PER_DAY;
        days = days.wrapping_sub(1);
    }
    while rem >= SECS_PER_DAY {
        rem -= SECS_PER_DAY;
        days = days.wrapping_add(1);
    }

    result.tm_hour = (rem / SECS_PER_HOUR) as c_int;
    rem %= SECS_PER_HOUR;
    result.tm_min = (rem / 60) as c_int;
    result.tm_sec = (rem % 60) as c_int;

    /* January 1, 1970 was a Thursday. */
    result.tm_wday = ((4i64.wrapping_add(days)) % 7) as c_int;
    if result.tm_wday < 0 {
        result.tm_wday += 7;
    }

    /*
     * The following algorithm is, basically, Proposition 6.3 of Neri
     * and Schneider [1]. In a few words: it works on the computational
     * (fictitious) calendar where the year starts in March, month = 2
     * (*), and finishes in February, month = 13. This calendar is
     * mathematically convenient because the day of the year does not
     * depend on whether the year is leap or not. For instance:
     *
     * March 1st		0-th day of the year;
     * ...
     * April 1st		31-st day of the year;
     * ...
     * January 1st		306-th day of the year; (Important!)
     * ...
     * February 28th	364-th day of the year;
     * February 29th	365-th day of the year (if it exists).
     *
     * After having worked out the date in the computational calendar
     * (using just arithmetics) it's easy to convert it to the
     * corresponding date in the Gregorian calendar.
     */
    let udays: u64 = (days as u64).wrapping_add(2305843009213814918u64);

    let u64tmp: u64 = 4u64.wrapping_mul(udays).wrapping_add(3);
    let century: u64 = u64tmp / 146097;
    let u64tmp: u64 = u64tmp % 146097;
    let day_of_century: u32 = (u64tmp / 4) as u32;

    let u32tmp: u32 = 4u32.wrapping_mul(day_of_century).wrapping_add(3);
    let u64tmp: u64 = 2939745u64 * u32tmp as u64;
    let year_of_century: u32 = (u64tmp >> 32) as u32;
    let mut day_of_year: u32 = (u64tmp as u32) / 2939745 / 4;

    let year: u64 = century.wrapping_mul(100).wrapping_add(year_of_century as u64);
    let is_leap_year: bool = if year_of_century != 0 { year_of_century % 4 == 0 } else { century % 4 == 0 };

    let u32tmp: u32 = 2141u32 * day_of_year + 132377;
    let mut month: u32 = u32tmp >> 16;
    let mut day: u32 = (u32tmp as u16 as u32) / 2141;

    /*
     * Recall that January 1st is the 306-th day of the year in the
     * computational (not Gregorian) calendar.
     */
    let is_jan_or_feb: bool = day_of_year >= 306;

    /* Convert to the Gregorian calendar and adjust to Unix time. */
    let year: u64 = year.wrapping_add(is_jan_or_feb as u64).wrapping_sub(6313183731940000u64);
    month = if is_jan_or_feb { month.wrapping_sub(12) } else { month };
    day += 1;
    day_of_year = day_of_year.wrapping_add(if is_jan_or_feb { 306u32.wrapping_neg() } else { 31 + 28 + is_leap_year as u32 });

    /* Convert to tm's format. */
    result.tm_year = year.wrapping_sub(1900) as c_long;
    result.tm_mon = month as c_int;
    result.tm_mday = day as c_int;
    result.tm_yday = day_of_year as c_int;
}
