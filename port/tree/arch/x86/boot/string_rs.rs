// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/string.c in the 16-bit real-mode setup (code16, -Zregparm=3).
//! Exports exactly the 12 global symbols the C object of this build exports (nm of build-fast string.o):
//! memcmp, bcmp, strcmp, strncmp, strnlen, strlen, strstr, strchr, simple_strtoull, simple_strtol,
//! kstrtoull, boot_kstrtoul. memcpy/memset/memmove are NOT here: in real mode they are copy.S (asm, stays).
//! The same string.c is #included by compressed/string.c for the 64-bit stub, which has its own accepted
//! Rust version (compressed/string_rs.rs); that file and string.c itself are untouched. This is the
//! real-mode flavour: 32-bit `unsigned long`/`size_t`/pointers, no 64-bit divide library.
//!
//! Types of the target (i386): `unsigned long` = u32, `long` = i32, `size_t` = u32, `unsigned long long` = u64.
//! They are spelled out below (ULong/Long) so the host build (rig/realmode/run-string-diff.sh) uses the same widths.
//!
//! SELF-RECURSION HAZARD (same as the stub's file): LLVM turns plain byte loops into calls of strlen/memcmp/memcpy,
//! i.e. of the very function being compiled. Defences, checked on the object by disassembly: `#![no_builtins]` (idiom
//! recognition off for every function in the crate), memcmp is the C's own inline asm (`repe cmpsb`), and no slice
//! comparison / `ptr::copy` / `core::str` helper is used. The 64-bit division of _parse_integer's overflow check
//! must not become a call to __udivdi3 (the setup has no libgcc): like the C, it uses one 32-bit `div` (`div_u64`).
//!
//! Semantics reproduced from the C, statement by statement (all byte compares are on UNSIGNED bytes, as the C):
//! - memcmp/bcmp return 0 or 1 only (never an ordering): `test len,len; repe cmpsb; setnz`. In 16-bit mode `repe cmpsb`
//!   counts in %cx (the C's asm is the same instruction sequence), so len >= 0x10000 behaves as in the C.
//! - strcmp: difference of the first differing unsigned bytes (int, may be > 1), 0 if equal; strncmp: -1/+1 only, stops at NUL or count.
//! - strnlen reads `*es` BEFORE testing maxlen (a string of exactly maxlen bytes without NUL is read one byte past), as the C.
//! - simple_strtoull: base 0 -> 16 if "0x"+hexdigit, 8 if starts with '0', else 10 (no sign, no whitespace skipping);
//!   base 16 skips a "0x"/"0X" prefix even when no digit follows (so "0x" alone leaves endp past the 0x and the result is 0);
//!   digits >= base stop the scan; NO overflow detection (64-bit wrap); bases above 16 are not rejected (digits are still 0-9a-f only).
//!   simple_strtol: a leading '-' negates (64-bit negate, truncated to long); "+" is NOT accepted there.
//! - kstrtoull: one optional '+', then base fixup, then _parse_integer with the overflow rule: it only checks when
//!   `res` has any of its top 4 bits set (res & (~0 << 60)), then `res > (ULLONG_MAX - val) / base` -> KSTRTOX_OVERFLOW (bit 31 of the
//!   consumed-character count); -ERANGE (-34) on overflow, -EINVAL (-22) if no digit or trailing junk (one '\n' is allowed before the NUL);
//!   *res is written only on success. The rule is exact for base <= 16 (proof in logs/proofs/string-bounds.py and the Kani harness);
//!   for base > 16 (documented as unsupported) the C can wrap undetected when res < 2^60 (kept, recorded in logs/realmode-string.md).
//! - boot_kstrtoul: unsigned long is 32 bits here, so it is the C's `_kstrtoul` branch: kstrtoull then -ERANGE if the value does not fit 32 bits.
//! No message strings exist in the C or here.
//!
//! Deliberate divergences: none in behaviour. Callers in this setup: strncmp + simple_strtoull (early_serial_console.c, earlyprintk=/console=),
//! strnlen (printf.c %s); strcmp only from edd.c (CONFIG_EDD unset in this tree, so not built); the rest are linked (whole object) but not called.
//!
//! TEST-GAP: (1) the real 16-bit execution of memcmp/bcmp/strcmp/strstr/strchr/strlen/simple_strtol/kstrtoull/boot_kstrtoul: no code in the
//! setup calls them in this configuration, so a boot cannot reach them; they are run for real in rig/realmode/string-boot/ (a boot-sector test
//! that links the C and Rust code16 objects and compares them inside QEMU) and on the host in the differential (C vs Rust, both with 32-bit
//! unsigned long). (2) `size_t`/`unsigned long` = 32 bits cannot be forced on the host build for pointer-sized values: the host has 64-bit
//! pointers/size_t, counts above 2^32 are not tested. (3) The `div` asm and `repe cmpsb` asm are replaced by their definitions in the host
//! and Kani builds; they are covered by the disassembly compare and the in-guest test.
#![cfg_attr(not(kani), no_builtins)]
#![allow(dead_code, clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int, c_uint};
use core::ptr::null_mut;

/// C `unsigned long` / `long` of the i386 target (the host build keeps these widths).
pub type ULong = u32;
pub type Long = i32;

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const KSTRTOX_OVERFLOW: c_uint = 1 << 31;

// TEST-GAP: this asm (repe cmpsb with the 16-bit %cx/%si/%di counters, DF assumed clear) runs only in rig/realmode/string-boot (real 16-bit
// execution under QEMU/KVM + TCG, C vs Rust) and in the object compare; the host differential and Kani run its definition (the byte loop below).
// No code of the setup calls memcmp/bcmp/strstr here in this configuration, so a normal boot cannot reach it.
/// `repe cmpsb`: 1 if any of the first len bytes differ, else 0. `test` makes ZF right for len == 0, where `repe cmpsb`
/// does not execute at all. Same instructions as the C's `asm volatile("test %3,%3; repe cmpsb" : "=@ccnz")`.
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
unsafe fn bytes_differ(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    let diff: u8;
    // SAFETY: caller guarantees both regions are readable for len bytes (ds = es, flat offsets).
    unsafe {
        core::arch::asm!(
            "xchg esi, {s2:e}", // esi is reserved by LLVM here (cannot be an operand): swap it in and back
            "test ecx, ecx",
            "repe cmpsb",
            "setnz al",
            "xchg esi, {s2:e}",
            s2 = inout(reg) s2 => _,
            inout("ecx") len => _,
            inout("edi") s1 => _,
            out("al") diff,
            options(nostack, readonly)
        );
    }
    diff as c_int
}

/// Host / Kani model of the above: its definition as an ascending byte loop.
#[cfg(any(host_mock, kani))]
unsafe fn bytes_differ(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    let mut i = 0;
    while i < len {
        // SAFETY: caller guarantees both regions are readable for len bytes.
        if unsafe { *s1.add(i) != *s2.add(i) } {
            return 1;
        }
        i += 1;
    }
    0
}

/// `int memcmp(const void *s1, const void *s2, size_t len)`: 0 equal, 1 different, never an ordering.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    // SAFETY: caller guarantees both regions are readable for len bytes.
    unsafe { bytes_differ(s1, s2, len) }
}

/// Clang may lower `memcmp == 0` to `bcmp == 0`.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    // SAFETY: same contract.
    unsafe { memcmp(s1, s2, len) }
}

/// `int strcmp(const char *str1, const char *str2)`: delta of the first differing UNSIGNED bytes.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strcmp(str1: *const c_char, str2: *const c_char) -> c_int {
    let mut s1 = str1 as *const u8;
    let mut s2 = str2 as *const u8;
    // SAFETY: both NUL-terminated by contract; stops at the first difference or when both are at their NUL.
    unsafe {
        while *s1 != 0 || *s2 != 0 {
            let delta = *s1 as c_int - *s2 as c_int;
            if delta != 0 {
                return delta;
            }
            s1 = s1.add(1);
            s2 = s2.add(1);
        }
    }
    0
}

/// `int strncmp(const char *cs, const char *ct, size_t count)`: -1 / 0 / +1 on unsigned bytes.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int {
    let mut cs = cs as *const u8;
    let mut ct = ct as *const u8;
    let mut count = count;
    // SAFETY: reads at most `count` bytes of each, stopping at NUL / difference.
    unsafe {
        while count != 0 {
            let c1 = *cs;
            cs = cs.add(1);
            let c2 = *ct;
            ct = ct.add(1);
            if c1 != c2 {
                return if c1 < c2 { -1 } else { 1 };
            }
            if c1 == 0 {
                break;
            }
            count -= 1;
        }
    }
    0
}

/// `size_t strnlen(const char *s, size_t maxlen)`; `*es` is read before `maxlen` is tested, as the C.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const c_char, maxlen: usize) -> usize {
    let mut es = s;
    let mut maxlen = maxlen;
    // SAFETY: NUL-terminated or readable for maxlen (+1) bytes, exactly like the C.
    unsafe {
        while *es != 0 && maxlen != 0 {
            es = es.add(1);
            maxlen -= 1;
        }
    }
    (es as usize).wrapping_sub(s as usize)
}

/// Works only for digits and letters, but small and fast (TOLOWER of the C).
#[inline(always)]
fn tolower(x: u8) -> u8 {
    x | 0x20
}

#[inline(always)]
fn isdigit(ch: u8) -> bool {
    ch.wrapping_sub(b'0') < 10
}

/// ctype.h isxdigit(): 0-9, a-f, A-F (bytes >= 0x80 are never hex digits).
#[inline(always)]
fn isxdigit(ch: u8) -> bool {
    isdigit(ch) || (ch >= b'a' && ch <= b'f') || (ch >= b'A' && ch <= b'F')
}

unsafe fn simple_guess_base(cp: *const u8) -> c_uint {
    // SAFETY: NUL-terminated; cp[1] is read only if cp[0] == '0' (so not the NUL), cp[2] only if cp[1] is x/X.
    unsafe {
        if *cp == b'0' {
            if tolower(*cp.add(1)) == b'x' && isxdigit(*cp.add(2)) {
                16
            } else {
                8
            }
        } else {
            10
        }
    }
}

/// `unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)`
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> u64 {
    let mut cp = cp as *const u8;
    let mut base = base;
    let mut result: u64 = 0;
    // SAFETY: NUL-terminated string by contract; endp, if non-null, is writable.
    unsafe {
        if base == 0 {
            base = simple_guess_base(cp);
        }
        if base == 16 && *cp == b'0' && tolower(*cp.add(1)) == b'x' {
            cp = cp.add(2);
        }
        while isxdigit(*cp) {
            let value: c_uint = if isdigit(*cp) { (*cp - b'0') as c_uint } else { (tolower(*cp) - b'a' + 10) as c_uint };
            if value >= base {
                break;
            }
            result = result.wrapping_mul(base as u64).wrapping_add(value as u64);
            cp = cp.add(1);
        }
        if !endp.is_null() {
            *endp = cp as *mut c_char;
        }
    }
    result
}

/// `long simple_strtol(const char *cp, char **endp, unsigned int base)`
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn simple_strtol(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> Long {
    // SAFETY: same contract as simple_strtoull.
    unsafe {
        if *cp == b'-' as c_char {
            // C: `-simple_strtoull(...)` on unsigned long long, then converted to long.
            return (simple_strtoull(cp.add(1), endp, base) as Long).wrapping_neg();
        }
        simple_strtoull(cp, endp, base) as Long
    }
}

/// `size_t strlen(const char *s)`
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let mut sc = s;
    // SAFETY: NUL-terminated by contract.
    unsafe {
        while *sc != 0 {
            sc = sc.add(1);
        }
    }
    (sc as usize).wrapping_sub(s as usize)
}

/// `char *strstr(const char *s1, const char *s2)`: the C checks `l1--` before comparing, i.e. it tries the
/// l1 - l2 + 1 start positions in order; an empty needle returns s1.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strstr(s1: *const c_char, s2: *const c_char) -> *mut c_char {
    let mut s1 = s1;
    // SAFETY: NUL-terminated strings by contract; memcmp reads l2 bytes of each, both inside.
    unsafe {
        let l2 = strlen(s2);
        if l2 == 0 {
            return s1 as *mut c_char;
        }
        let mut l1 = strlen(s1);
        while l1 >= l2 {
            l1 -= 1;
            if memcmp(s1 as *const u8, s2 as *const u8, l2) == 0 {
                return s1 as *mut c_char;
            }
            s1 = s1.add(1);
        }
    }
    null_mut()
}

/// `char *strchr(const char *s, int c)`: compares as `char` (c truncated); also finds the NUL when (char)c == 0.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let mut s = s;
    // SAFETY: NUL-terminated by contract.
    unsafe {
        while *s != c as c_char {
            let ch = *s;
            s = s.add(1);
            if ch == 0 {
                return null_mut();
            }
        }
    }
    s as *mut c_char
}

// TEST-GAP: the `div` asm only executes for real in the in-guest test (kstrtoull on overflow-region numbers) and the boots never reach kstrtoull
// (no setup caller); the host/Kani builds use a plain 64-bit division, which logs/proofs/string-bounds.py S3 shows equal to this decomposition.
/// The C's `__div_u64()`: dividend / divisor with at most one 32-bit `divl` and no libgcc call.
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn div_u64(dividend: u64, divisor: u32) -> u64 {
    let mut hi = (dividend >> 32) as u32;
    let lo = dividend as u32;
    let mut qhi = 0u32;
    if hi >= divisor {
        qhi = hi / divisor;
        hi %= divisor;
    }
    let qlo: u32;
    // SAFETY: hi < divisor, so the quotient fits in 32 bits (no #DE); divisor != 0 (callers: base >= 1).
    unsafe {
        core::arch::asm!(
            "div {d:e}",
            d = in(reg) divisor,
            inout("eax") lo => qlo,
            inout("edx") hi => _,
            options(pure, nomem, nostack)
        );
    }
    ((qhi as u64) << 32) | qlo as u64
}

/// Host / Kani model: plain 64-bit division (same value; the target avoids __udivdi3, see above).
#[cfg(any(host_mock, kani))]
fn div_u64(dividend: u64, divisor: u32) -> u64 {
    dividend / divisor as u64
}

/// _parse_integer_fixup_radix(): base 0 -> detect; skip "0x" for base 16.
unsafe fn parse_integer_fixup_radix(s: *const u8, base: &mut c_uint) -> *const u8 {
    // SAFETY: NUL-terminated string; s[1] is read only when s[0] == '0'.
    unsafe {
        if *base == 0 {
            if *s == b'0' {
                if tolower(*s.add(1)) == b'x' && isxdigit(*s.add(2)) {
                    *base = 16;
                } else {
                    *base = 8;
                }
            } else {
                *base = 10;
            }
        }
        if *base == 16 && *s == b'0' && tolower(*s.add(1)) == b'x' {
            return s.add(2);
        }
    }
    s
}

/// One digit-accumulation step of _parse_integer: returns (new res, overflow flag). `base` != 0.
/// For base <= 16 and val < base the result is exact when !overflow and the true value does not fit when overflow (proved).
#[inline(always)]
fn parse_step(res: u64, base: c_uint, val: c_uint) -> (u64, bool) {
    // Check for overflow only if we are within range of it in the max base we support (16).
    let ovf = res & (!0u64 << 60) != 0 && res > div_u64(u64::MAX - val as u64, base);
    (res.wrapping_mul(base as u64).wrapping_add(val as u64), ovf)
}

/// _parse_integer(): number of characters consumed, or-ed with KSTRTOX_OVERFLOW; the (possibly wrapped) value in *p.
unsafe fn parse_integer(s: *const u8, base: c_uint, p: &mut u64) -> c_uint {
    let mut s = s;
    let mut res: u64 = 0;
    let mut rv: c_uint = 0;
    // SAFETY: NUL-terminated string (the NUL ends the loop: it is neither digit nor a-f).
    unsafe {
        loop {
            let c = *s as c_uint;
            let lc = c | 0x20; // don't tolower() this line
            let val: c_uint;

            if c >= b'0' as c_uint && c <= b'9' as c_uint {
                val = c - b'0' as c_uint;
            } else if lc >= b'a' as c_uint && lc <= b'f' as c_uint {
                val = lc - b'a' as c_uint + 10;
            } else {
                break;
            }
            if val >= base {
                break;
            }
            let (r, ovf) = parse_step(res, base, val);
            if ovf {
                rv |= KSTRTOX_OVERFLOW;
            }
            res = r;
            rv += 1;
            s = s.add(1);
        }
    }
    *p = res;
    rv
}

unsafe fn kstrtoull_inner(s: *const u8, base: c_uint, res: *mut u64) -> c_int {
    let mut base = base;
    let mut r: u64 = 0;
    // SAFETY: NUL-terminated string; res writable.
    unsafe {
        let mut s = parse_integer_fixup_radix(s, &mut base);
        let rv = parse_integer(s, base, &mut r);
        if rv & KSTRTOX_OVERFLOW != 0 {
            return -ERANGE;
        }
        if rv == 0 {
            return -EINVAL;
        }
        s = s.add(rv as usize);
        if *s == b'\n' {
            s = s.add(1);
        }
        if *s != 0 {
            return -EINVAL;
        }
        *res = r;
    }
    0
}

/// `int kstrtoull(const char *s, unsigned int base, unsigned long long *res)`
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn kstrtoull(s: *const c_char, base: c_uint, res: *mut u64) -> c_int {
    let mut s = s as *const u8;
    // SAFETY: NUL-terminated string; res writable.
    unsafe {
        if *s == b'+' {
            s = s.add(1);
        }
        kstrtoull_inner(s, base, res)
    }
}

/// `int boot_kstrtoul(const char *s, unsigned int base, unsigned long *res)`: unsigned long is 32 bits here, so this is the
/// C's `_kstrtoul()` branch (the C's sizeof test picks it at compile time).
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn boot_kstrtoul(s: *const c_char, base: c_uint, res: *mut ULong) -> c_int {
    let mut tmp: u64 = 0;
    // SAFETY: same contract as kstrtoull; res writable.
    unsafe {
        let rv = kstrtoull(s, base, &mut tmp);
        if rv < 0 {
            return rv;
        }
        if tmp != (tmp as ULong) as u64 {
            return -ERANGE;
        }
        *res = tmp as ULong;
    }
    0
}

// ---- Kani proofs (rig/realmode/run-string-kani.sh; logs/realmode-string.md) ------------------------
// Under cfg(kani) the two asm primitives are their definitions (a byte loop, a 64-bit division); everything else is the shipped code.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// The digit-accumulation step for EVERY u64 `res`, every base 1..=16 and every digit value < base: when no overflow is
    /// flagged the wrapped result equals the exact value res*base+val (computed in u128), when it is flagged the exact value
    /// does not fit in 64 bits. (== "no wrap goes undetected, no false alarm".)
    #[kani::proof]
    fn step_exact_for_base_le_16() {
        let res: u64 = kani::any();
        let base: c_uint = kani::any();
        let val: c_uint = kani::any();
        kani::assume(base >= 1 && base <= 16 && val < base);
        let (r, ovf) = parse_step(res, base, val);
        let exact = res as u128 * base as u128 + val as u128;
        if ovf {
            assert!(exact > u64::MAX as u128);
        } else {
            assert!(exact <= u64::MAX as u128 && r as u128 == exact);
        }
    }

    /// strlen/strnlen on every byte string of a 6-byte buffer (any contents): result is the index of the first NUL
    /// (or the buffer end bound), never reads outside, strnlen(s, n) == min(strlen(s), n) when n < 6 or a NUL exists.
    #[kani::proof]
    #[kani::unwind(8)]
    fn strlen_strnlen_first_nul() {
        let mut b: [u8; 6] = kani::any();
        b[5] = 0; // NUL-terminated buffer (the contract)
        let n: usize = kani::any();
        kani::assume(n <= 5);
        let l = unsafe { strlen(b.as_ptr() as *const c_char) };
        let mut first = 0;
        while b[first] != 0 {
            first += 1;
        }
        assert!(l == first && l <= 5 && b[l] == 0);
        let m = unsafe { strnlen(b.as_ptr() as *const c_char, n) };
        assert!(m == if l < n { l } else { n });
    }

    /// Reference check shared by the parse_integer harnesses: `b` is NUL-terminated at its last byte; consumed count == number of leading valid
    /// digits, overflow flag == the exact value (u128 reference, saturated once it exceeds U64MAX) > U64MAX, value == exact value when no overflow.
    fn check_parse<const N: usize>(b: &[u8; N], base: c_uint) {
        let mut p = 0u64;
        let rv = unsafe { parse_integer(b.as_ptr(), base, &mut p) };
        let mut exact: u128 = 0;
        let mut n = 0u32;
        let mut big = false;
        let mut i = 0;
        while i < N - 1 {
            let c = b[i];
            let v: u32 = if c >= b'0' && c <= b'9' {
                (c - b'0') as u32
            } else if (c | 0x20) >= b'a' && (c | 0x20) <= b'f' {
                ((c | 0x20) - b'a' + 10) as u32
            } else {
                break;
            };
            if v >= base {
                break;
            }
            exact = exact * base as u128 + v as u128;
            if exact > u64::MAX as u128 {
                big = true;
                exact = u64::MAX as u128 + 1; // saturate: still "too big" (further steps only grow it, base >= 2)
            }
            n += 1;
            i += 1;
        }
        kani::cover!(big, "overflow reached");
        kani::cover!(!big && n >= 15, "15+ digits parsed without overflow");
        assert!(rv & !KSTRTOX_OVERFLOW == n);
        assert!((rv & KSTRTOX_OVERFLOW != 0) == big);
        if !big {
            assert!(p as u128 == exact);
        }
    }

    /// parse_integer on EVERY string of up to 6 arbitrary characters (any bytes), every base 2..=16: count, flag and value as the reference.
    #[kani::proof]
    #[kani::unwind(9)]
    fn parse_integer_short_any() {
        let mut b: [u8; 7] = kani::any();
        b[6] = 0;
        let base: c_uint = kani::any();
        kani::assume(base >= 2 && base <= 16);
        check_parse(&b, base);
    }

    /// The overflow region in hex: 14 concrete 'f' (res = 2^56-1) followed by 6 arbitrary characters (the 17th hex digit overflows).
    #[kani::proof]
    #[kani::unwind(23)]
    fn parse_integer_hex_overflow_tail() {
        let mut b: [u8; 21] = [0; 21];
        let mut i = 0;
        while i < 14 {
            b[i] = b'f';
            i += 1;
        }
        let t: [u8; 6] = kani::any();
        i = 0;
        while i < 6 {
            b[14 + i] = t[i];
            i += 1;
        }
        check_parse(&b, 16);
    }

    /// The overflow region in decimal: 18 concrete '9' (res = 10^18-1) followed by 3 arbitrary characters (U64MAX has 20 digits).
    #[kani::proof]
    #[kani::unwind(23)]
    fn parse_integer_dec_overflow_tail() {
        let mut b: [u8; 22] = [0; 22];
        let mut i = 0;
        while i < 18 {
            b[i] = b'9';
            i += 1;
        }
        let t: [u8; 3] = kani::any();
        i = 0;
        while i < 3 {
            b[18 + i] = t[i];
            i += 1;
        }
        check_parse(&b, 10);
    }
}
