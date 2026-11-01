// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/string.c, which #includes ../string.c
//! (shared with the 16-bit setup; that file stays C, untouched).
//!
//! Exports exactly what the C object did: memcpy, memmove, memset, memcmp, bcmp, strcmp,
//! strncmp, strnlen, strlen, strstr, strchr, simple_strtoull, simple_strtol, kstrtoull,
//! boot_kstrtoul (and with --cfg=kasan the __memset/__memmove/__memcpy names).
//! 64-bit only (the Makefile gate is CONFIG_RUST, which x86 has only for 64-bit): the C's
//! CONFIG_X86_32 `rep movsl` variant of ____memcpy is not needed.
//!
//! SELF-RECURSION HAZARD. Every other Rust object, `core` and `compiler_builtins` call the
//! symbols memcpy/memmove/memset/memcmp/bcmp/strlen, and LLVM turns plain byte loops into
//! calls to those very functions ("loop idiom recognition"): a Rust `for i in 0..n { d[i] = s[i] }`
//! inside memcpy would compile to `call memcpy`. Three defences, all checked on the object by
//! disassembly (logs/stubd-string.md): `#![no_builtins]` (rustc then tags every function
//! `no-builtins`, which switches idiom recognition off), the hot paths are inline asm
//! (`rep movsq/movsb`, `rep stosb`, `repe cmpsb`, as the C already used for memcpy/memcmp), and
//! the one loop left in memmove is made of volatile accesses. No slice comparison or
//! `core::ptr::copy*` is used anywhere in this file for the same reason.
#![cfg_attr(not(kani), no_builtins)]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(kani))]
use core::arch::asm;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_ulonglong};
use core::ptr::{null_mut, read_volatile, write_volatile};

#[cfg(kani)]
static mut WARNS: u32 = 0;
/// Kani model of warn(): only counts the calls.
#[cfg(kani)]
unsafe fn warn(_m: *const c_char) {
    unsafe { WARNS += 1 };
}

#[cfg(not(kani))]
extern "C" {
    /// error_rs.rs (error.c): prints "\n\n", the message, "\n\n".
    fn warn(m: *const c_char);
}

/// Same text as the C. A by-value array (not a `&str`/`&CStr`): no pointer inside, so no load-time
/// relocation (the stub forbids them); and Kani cannot model C string literals.
static OVERLAP_MSG: [u8; 50] = *b"Avoiding potentially unsafe overlapping memcpy()!\0";

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const KSTRTOX_OVERFLOW: c_uint = 1 << 31;

/// The C ____memcpy(): `rep movsq` for n/8 quadwords, then `rep movsb` for n%8 bytes.
/// Direction flag is clear, as the ABI promises.
#[cfg(not(kani))]
#[inline(always)]
unsafe fn copy_forward(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller guarantees src..src+n and dest..dest+n are valid and, going forward,
    // that a destination byte is never read after being written (dest <= src or no overlap).
    unsafe {
        asm!(
            "rep movsq",
            "mov rcx, {rem}",
            "rep movsb",
            rem = in(reg) n & 7,
            inout("rcx") n >> 3 => _,
            inout("rdi") dest => _,
            inout("rsi") src => _,
            options(nostack)
        );
    }
    dest
}

/// `rep movs` copies ascending, one element at a time (DF = 0): modelled for Kani as that loop.
#[cfg(kani)]
unsafe fn copy_forward(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1;
    }
    dest
}

/// `rep stosb`: store the low byte of `c` n times, ascending.
#[cfg(not(kani))]
#[inline(always)]
unsafe fn fill_bytes(s: *mut u8, c: c_int, n: usize) {
    // SAFETY: caller guarantees s..s+n is writable.
    unsafe {
        asm!(
            "rep stosb",
            inout("rcx") n => _,
            inout("rdi") s => _,
            in("al") c as u8,
            options(nostack)
        );
    }
}

#[cfg(kani)]
unsafe fn fill_bytes(s: *mut u8, c: c_int, n: usize) {
    let mut i = 0;
    while i < n {
        unsafe { *s.add(i) = c as u8 };
        i += 1;
    }
}

/// `repe cmpsb`: 1 if any of the first len bytes differ, else 0. `test` makes ZF right for
/// len == 0, where `repe cmpsb` does not execute at all.
#[cfg(not(kani))]
#[inline(always)]
unsafe fn bytes_differ(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    let diff: u8;
    // SAFETY: caller guarantees both regions are readable for len bytes.
    unsafe {
        asm!(
            "test rcx, rcx",
            "repe cmpsb",
            "setnz al",
            inout("rcx") len => _,
            inout("rdi") s1 => _,
            inout("rsi") s2 => _,
            out("al") diff,
            options(nostack)
        );
    }
    diff as c_int
}

#[cfg(kani)]
unsafe fn bytes_differ(s1: *const u8, s2: *const u8, len: usize) -> c_int {
    let mut i = 0;
    while i < len {
        if unsafe { *s1.add(i) != *s2.add(i) } {
            return 1;
        }
        i += 1;
    }
    0
}

/// `void *memset(void *s, int c, size_t n)`. The C stored `(char)c` n times, byte by byte.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: c_int, n: usize) -> *mut u8 {
    // SAFETY: caller guarantees s..s+n is writable.
    unsafe { fill_bytes(s, c, n) };
    s
}

/// `void *memmove(void *dest, const void *src, size_t n)`:
/// forward copy when `dest <= src` or the regions do not overlap (`dest - src >= n`, unsigned),
/// else a backward byte copy.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let d = dest as usize;
    let s = src as usize;

    if d <= s || d - s >= n {
        // SAFETY: forward copy is correct in this case (see copy_forward).
        return unsafe { copy_forward(dest, src, n) };
    }

    let mut i = n;
    while i > 0 {
        i -= 1;
        // SAFETY: i < n, both regions valid for n bytes. Volatile: stops LLVM from
        // recognising the loop as a memmove and calling this very function.
        unsafe { write_volatile(dest.add(i), read_volatile(src.add(i))) };
    }
    dest
}

/// Detect and warn about potential overlaps, but handle them with memmove.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let d = dest as usize;
    let s = src as usize;

    if d > s && d - s < n {
        // SAFETY: NUL-terminated literal; warn() is error_rs.rs / error.c.
        unsafe { warn(OVERLAP_MSG.as_ptr() as *const c_char) };
        // SAFETY: same contract as memcpy.
        return unsafe { memmove(dest, src, n) };
    }
    // SAFETY: same contract as memcpy.
    unsafe { copy_forward(dest, src, n) }
}

#[cfg(kasan)]
mod kasan_names {
    #[cfg_attr(not(kani), no_mangle)]
    pub unsafe extern "C" fn __memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
        unsafe { super::memset(s, c, n) }
    }
    #[cfg_attr(not(kani), no_mangle)]
    pub unsafe extern "C" fn __memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
        unsafe { super::memmove(d, s, n) }
    }
    #[cfg_attr(not(kani), no_mangle)]
    pub unsafe extern "C" fn __memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
        unsafe { super::memcpy(d, s, n) }
    }
}

/// `int memcmp(const void *s1, const void *s2, size_t len)`.
/// NOTE: like the C it returns only 0 (equal) or 1 (different), never an ordering.
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

#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strcmp(str1: *const c_char, str2: *const c_char) -> c_int {
    let mut s1 = str1 as *const u8;
    let mut s2 = str2 as *const u8;

    // SAFETY: both are NUL-terminated by contract; we stop at the first difference or
    // when both are at their NUL.
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

#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const c_char, maxlen: usize) -> usize {
    let mut es = s;
    let mut maxlen = maxlen;

    // SAFETY: NUL-terminated or readable for maxlen bytes, exactly like the C (`*es` is read before
    // maxlen is tested, so a string of exactly maxlen bytes without NUL is read one past).
    unsafe {
        while *es != 0 && maxlen != 0 {
            es = es.add(1);
            maxlen -= 1;
        }
    }
    (es as usize) - (s as usize)
}

/// Works only for digits and letters, but small and fast.
#[inline(always)]
fn tolower(x: u8) -> u8 {
    x | 0x20
}

#[inline(always)]
fn isdigit(ch: u8) -> bool {
    ch.wrapping_sub(b'0') < 10
}

#[inline(always)]
fn isxdigit(ch: u8) -> bool {
    isdigit(ch) || (b'a'..=b'f').contains(&ch) || (b'A'..=b'F').contains(&ch)
}

unsafe fn simple_guess_base(cp: *const u8) -> c_uint {
    // SAFETY: NUL-terminated string; cp[1] is read only if cp[0] == '0' (so not the NUL),
    // cp[2] only if cp[1] is 'x'/'X'.
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
pub unsafe extern "C" fn simple_strtoull(
    cp: *const c_char,
    endp: *mut *mut c_char,
    base: c_uint,
) -> c_ulonglong {
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
            let value: c_uint =
                if isdigit(*cp) { (*cp - b'0') as c_uint } else { (tolower(*cp) - b'a' + 10) as c_uint };
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

#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn simple_strtol(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> c_long {
    // SAFETY: same contract as simple_strtoull.
    unsafe {
        if *cp == b'-' as c_char {
            // C: `-simple_strtoull(...)` on unsigned long long, then converted to long.
            return (simple_strtoull(cp.add(1), endp, base) as c_long).wrapping_neg();
        }
        simple_strtoull(cp, endp, base) as c_long
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
    (sc as usize) - (s as usize)
}

/// `char *strstr(const char *s1, const char *s2)`; the C checks `l1--` before comparing, which is
/// the same as trying the l1 - l2 + 1 start positions in order.
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

/// `char *strchr(const char *s, int c)`: also finds the terminating NUL when c == 0.
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

/// _parse_integer(): number of characters consumed, or-ed with KSTRTOX_OVERFLOW.
unsafe fn parse_integer(s: *const u8, base: c_uint, p: &mut u64) -> c_uint {
    let mut s = s;
    let mut res: u64 = 0;
    let mut rv: c_uint = 0;

    // SAFETY: NUL-terminated string (the NUL ends the loop: it is neither digit nor a-f).
    unsafe {
        loop {
            let c = *s as c_uint;
            let lc = c | 0x20;
            let val: c_uint;

            if (b'0' as c_uint..=b'9' as c_uint).contains(&c) {
                val = c - b'0' as c_uint;
            } else if (b'a' as c_uint..=b'f' as c_uint).contains(&lc) {
                val = lc - b'a' as c_uint + 10;
            } else {
                break;
            }

            if val >= base {
                break;
            }
            // Check for overflow only if we are within range of it in the max base we support (16).
            // base != 0 here: val >= 0 == base would have broken out above.
            if res & (!0u64 << 60) != 0 && res > (u64::MAX - val as u64) / (base as u64) {
                rv |= KSTRTOX_OVERFLOW;
            }
            res = res.wrapping_mul(base as u64).wrapping_add(val as u64);
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
pub unsafe extern "C" fn kstrtoull(s: *const c_char, base: c_uint, res: *mut c_ulonglong) -> c_int {
    let mut s = s as *const u8;
    // SAFETY: NUL-terminated string; res writable.
    unsafe {
        if *s == b'+' {
            s = s.add(1);
        }
        kstrtoull_inner(s, base, res)
    }
}

/// `int boot_kstrtoul(const char *s, unsigned int base, unsigned long *res)`;
/// unsigned long is unsigned long long here (64-bit), so this is the C's shortcut branch.
#[cfg_attr(not(kani), no_mangle)]
pub unsafe extern "C" fn boot_kstrtoul(s: *const c_char, base: c_uint, res: *mut c_ulong) -> c_int {
    // SAFETY: same contract; c_ulong and c_ulonglong are both u64 on this target.
    unsafe { kstrtoull(s, base, res as *mut c_ulonglong) }
}

// ---- Kani proofs (logs/proofs/kani-string.md; run: kani --harness <name> string_rs.rs) -----------
// Under `cfg(kani)` the three inline-asm primitives are replaced by the ascending byte loops that
// `rep movs/stos/cmps` are defined to be, and warn() by a counter; everything else (the overlap
// decisions, the backward volatile loop, every pointer offset) is the code that ships.
#[cfg(kani)]
mod proofs {
    use super::*;
    const N: usize = 12;

    /// memmove: for EVERY dest/src offset pair and length inside a 12-byte buffer of arbitrary
    /// contents: no out-of-bounds access (Kani checks each raw-pointer access), the result is the
    /// destination pointer, and the buffer equals "copy from a snapshot of the source" (the
    /// definition of memmove), whatever the overlap.
    #[kani::proof]
    #[kani::unwind(14)]
    fn memmove_is_memmove() {
        let mut buf: [u8; N] = kani::any();
        let orig = buf;
        let d: usize = kani::any();
        let s: usize = kani::any();
        let n: usize = kani::any();
        kani::assume(d <= N && s <= N && n <= N - d && n <= N - s);
        let p = buf.as_mut_ptr();
        let r = unsafe { memmove(p.add(d), p.add(s) as *const u8, n) };
        assert!(r == unsafe { p.add(d) });
        let mut expect = orig;
        let mut i = 0;
        while i < n {
            expect[d + i] = orig[s + i];
            i += 1;
        }
        assert!(buf == expect);
    }

    /// memcpy: same result as memmove, and it warns exactly when dest > src and the regions
    /// overlap (dest - src < n), never otherwise.
    #[kani::proof]
    #[kani::unwind(14)]
    fn memcpy_is_memmove_and_warns_on_overlap() {
        let mut buf: [u8; N] = kani::any();
        let orig = buf;
        let d: usize = kani::any();
        let s: usize = kani::any();
        let n: usize = kani::any();
        kani::assume(d <= N && s <= N && n <= N - d && n <= N - s);
        unsafe { WARNS = 0 };
        let p = buf.as_mut_ptr();
        let r = unsafe { memcpy(p.add(d), p.add(s) as *const u8, n) };
        assert!(r == unsafe { p.add(d) });
        let mut expect = orig;
        let mut i = 0;
        while i < n {
            expect[d + i] = orig[s + i];
            i += 1;
        }
        assert!(buf == expect);
        let overlap_backward = d > s && d - s < n;
        assert!(unsafe { WARNS } == if overlap_backward { 1 } else { 0 });
    }

    /// memset: bytes d..d+n become (c as u8), every other byte is untouched, for any int c.
    #[kani::proof]
    #[kani::unwind(14)]
    fn memset_sets_exactly_the_range() {
        let mut buf: [u8; N] = kani::any();
        let orig = buf;
        let d: usize = kani::any();
        let n: usize = kani::any();
        let c: c_int = kani::any();
        kani::assume(d <= N && n <= N - d);
        let p = buf.as_mut_ptr();
        let r = unsafe { memset(p.add(d), c, n) };
        assert!(r == unsafe { p.add(d) });
        let mut i = 0;
        while i < N {
            let inside = i >= d && i < d + n;
            assert!(buf[i] == if inside { c as u8 } else { orig[i] });
            i += 1;
        }
    }

    /// memcmp/bcmp: 0 iff the first n bytes are equal, else 1 (the stub's memcmp is not an ordering).
    #[kani::proof]
    #[kani::unwind(14)]
    fn memcmp_is_inequality_flag() {
        let a: [u8; N] = kani::any();
        let b: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let r = unsafe { memcmp(a.as_ptr(), b.as_ptr(), n) };
        let mut differ = false;
        let mut i = 0;
        while i < n {
            if a[i] != b[i] {
                differ = true;
            }
            i += 1;
        }
        assert!(r == if differ { 1 } else { 0 });
        assert!(unsafe { bcmp(a.as_ptr(), b.as_ptr(), n) } == r);
    }

    /// strlen/strnlen on an arbitrary buffer that contains a NUL: strlen is the index of the first
    /// NUL; strnlen is min(that, maxlen); no read past the NUL (strlen) / past the NUL or maxlen+1
    /// bytes (strnlen, which like the C reads *es before testing maxlen).
    #[kani::proof]
    #[kani::unwind(14)]
    fn strlen_strnlen_find_first_nul() {
        let s: [c_char; N] = kani::any();
        let maxlen: usize = kani::any();
        kani::assume(maxlen <= N);
        let mut first = N;
        let mut i = 0;
        while i < N {
            if s[i] == 0 && first == N {
                first = i;
            }
            i += 1;
        }
        kani::assume(first < N);
        assert!(unsafe { strlen(s.as_ptr()) } == first);
        let m = unsafe { strnlen(s.as_ptr(), maxlen) };
        assert!(m == if first < maxlen { first } else { maxlen });
    }
}
