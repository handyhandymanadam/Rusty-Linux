// SPDX-License-Identifier: GPL-2.0

//! C string and memory functions -- the Rust behind most of `lib/string.c`.
//!
//! Ported from `lib/string.c` (6.18.49), "stupid library routines", for x86-64, where the generic file builds exactly the
//! functions below (the architecture supplies `memcpy`, `memmove`, `memset`, `memset16/32/64` in assembly): `strncasecmp`,
//! `strcasecmp`, `strcpy`, `strncpy`, `stpcpy`, `strcat`, `strncat`, `strcmp`, `strncmp`, `strchr`, `strchrnul`, `strnchrnul`,
//! `strrchr`, `strnchr`, `strlen`, `strnlen`, `strspn`, `strcspn`, `strpbrk`, `strsep`, `memcmp`, `bcmp`, `memscan`, `strstr`,
//! `strnstr`, `memchr` and `memchr_inv`. In C (`string_glue.c`): `sized_strscpy()` (it carries `WARN_ON_ONCE`) and `strlcat()` (it
//! carries `BUG_ON`): those plant bug-table entries naming their own file and line, so their C entries stay
//! (`logs/c-entry-rule.md`). Any other architecture keeps the whole C file.
//!
//! SELF-RECURSION HAZARD, as in the boot stub's `string_rs.rs`: LLVM turns plain byte loops into calls to `strlen`, `memcpy`,
//! `memcmp`..., which here would be these very functions. `#![no_builtins]` switches that idiom recognition off for the crate
//! (the same defence the stub's Rust uses); no `core::ptr::copy*`, slice comparison or `CStr` helper is used. The functions call
//! each other and the arch `memcpy` only through plain calls. Every export is `#[inline(never)]` (an inlined callee gets its
//! caller's MODVERSIONS fingerprint from `gendwarfksyms`, see `time_rs.rs`).
//!
//! `tolower()` / `isupper()` read the kernel's `_ctype` table exactly as `include/linux/ctype.h` does. `char` is signed on x86,
//! so `(char)c` comparisons and the `strcasecmp` difference are computed with that in mind. `memcmp` returns the difference of the
//! first differing bytes (not just a sign), as the C does, and skips equal 8-byte words first (the
//! `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` path, always on for x86).
//!
//! None of the exports has a guard, WARN or static key, so no C entry stays for them: `kernel::kabi_export!` carries each
//! export and its contract (C fingerprints taken from the C object before it was removed, `rig/kabi-symtypes.sh`).
//!
//! Replaces: lib/string.c (x86-64, all but sized_strscpy and strlcat)
#![no_builtins]

use core::ffi::{c_char, c_int, c_void};

#[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
compile_error!("string_rs.rs: x86-64 only (the set of functions lib/string.c builds is the x86-64 one)");

extern "C" {
    static _ctype: [u8; 256];
}

/// `_U` in `include/linux/ctype.h`.
const CTYPE_U: u8 = 0x01;

/// `tolower()`.
#[inline(always)]
fn tolower(c: u8) -> u8 {
    if unsafe { _ctype[c as usize] } & CTYPE_U != 0 {
        c.wrapping_add(b'a'.wrapping_sub(b'A'))
    } else {
        c
    }
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");

kernel::kabi_export! {
    strncasecmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s1 , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s2 , formal_parameter t#size_t len ) -> base_type int byte_size(4) encoding(5)",
}
/// `strncasecmp()`.
///
/// # Safety
/// Both strings readable up to their NUL or `len` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strncasecmp(s1: *const c_char, s2: *const c_char, len: usize) -> c_int {
    let mut s1 = s1 as *const u8;
    let mut s2 = s2 as *const u8;
    let mut len = len;
    let mut c1: u8;
    let mut c2: u8;

    if len == 0 {
        return 0;
    }

    loop {
        c1 = unsafe { *s1 };
        s1 = unsafe { s1.add(1) };
        c2 = unsafe { *s2 };
        s2 = unsafe { s2.add(1) };
        if c1 == 0 || c2 == 0 {
            break;
        }
        if c1 != c2 {
            c1 = tolower(c1);
            c2 = tolower(c2);
            if c1 != c2 {
                break;
            }
        }
        len -= 1;
        if len == 0 {
            break;
        }
    }
    c1 as c_int - c2 as c_int
}

kernel::kabi_export! {
    strcasecmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s1 , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s2 ) -> base_type int byte_size(4) encoding(5)",
}
/// `strcasecmp()`.
///
/// # Safety
/// Both strings NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    let mut s1 = s1 as *const u8;
    let mut s2 = s2 as *const u8;
    let mut c1: c_int;
    let mut c2: c_int;

    loop {
        c1 = tolower(unsafe { *s1 }) as c_int;
        s1 = unsafe { s1.add(1) };
        c2 = tolower(unsafe { *s2 }) as c_int;
        s2 = unsafe { s2.add(1) };
        if !(c1 == c2 && c1 != 0) {
            break;
        }
    }
    c1 - c2
}

kernel::kabi_export! {
    strcpy,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strcpy()`.
///
/// # Safety
/// `src` NUL-terminated; `dest` large enough.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    let tmp = dest;
    let mut d = dest;
    let mut s = src;

    loop {
        let c = unsafe { *s };
        unsafe { *d = c };
        d = unsafe { d.add(1) };
        s = unsafe { s.add(1) };
        if c == 0 {
            break;
        }
    }
    tmp
}

kernel::kabi_export! {
    strncpy,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src , formal_parameter t#size_t count ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strncpy()`: copy up to `count` bytes, padding with NULs.
///
/// # Safety
/// `dest` writable for `count`; `src` readable up to its NUL or `count`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strncpy(dest: *mut c_char, src: *const c_char, count: usize) -> *mut c_char {
    let mut tmp = dest;
    let mut src = src;
    let mut count = count;

    while count != 0 {
        let c = unsafe { *src };
        unsafe { *tmp = c };
        if c != 0 {
            src = unsafe { src.add(1) };
        }
        tmp = unsafe { tmp.add(1) };
        count -= 1;
    }
    dest
}

kernel::kabi_export! {
    stpcpy,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter restrict_type { pointer_type { base_type char byte_size(1) encoding(8) } } dest , formal_parameter restrict_type { pointer_type { const_type { base_type char byte_size(1) encoding(8) } } } src ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `stpcpy()`: like `strcpy()`, returns the address of the copied NUL.
///
/// # Safety
/// As [`strcpy`].
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    let mut d = dest;
    let mut s = src;

    loop {
        let c = unsafe { *s };
        unsafe { *d = c };
        d = unsafe { d.add(1) };
        s = unsafe { s.add(1) };
        if c == 0 {
            break;
        }
    }
    unsafe { d.sub(1) }
}

kernel::kabi_export! {
    strcat,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strcat()`.
///
/// # Safety
/// Both NUL-terminated; `dest` large enough.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    let tmp = dest;
    let mut d = dest;
    let mut s = src;

    while unsafe { *d } != 0 {
        d = unsafe { d.add(1) };
    }
    loop {
        let c = unsafe { *s };
        unsafe { *d = c };
        d = unsafe { d.add(1) };
        s = unsafe { s.add(1) };
        if c == 0 {
            break;
        }
    }
    tmp
}

kernel::kabi_export! {
    strncat,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } dest , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } src , formal_parameter t#size_t count ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strncat()`.
///
/// # Safety
/// As [`strcat`], with room for `count + 1` more bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strncat(dest: *mut c_char, src: *const c_char, count: usize) -> *mut c_char {
    let tmp = dest;
    let mut d = dest;
    let mut s = src;
    let mut count = count;

    if count != 0 {
        while unsafe { *d } != 0 {
            d = unsafe { d.add(1) };
        }
        loop {
            let c = unsafe { *s };
            unsafe { *d = c };
            d = unsafe { d.add(1) };
            s = unsafe { s.add(1) };
            if c == 0 {
                break;
            }
            count -= 1;
            if count == 0 {
                unsafe { *d = 0 };
                break;
            }
        }
    }
    tmp
}

kernel::kabi_export! {
    strcmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } cs , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } ct ) -> base_type int byte_size(4) encoding(5)",
}
/// `strcmp()`: -1, 0 or 1.
///
/// # Safety
/// Both NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strcmp(cs: *const c_char, ct: *const c_char) -> c_int {
    let mut cs = cs as *const u8;
    let mut ct = ct as *const u8;

    loop {
        let c1 = unsafe { *cs };
        cs = unsafe { cs.add(1) };
        let c2 = unsafe { *ct };
        ct = unsafe { ct.add(1) };
        if c1 != c2 {
            return if c1 < c2 { -1 } else { 1 };
        }
        if c1 == 0 {
            break;
        }
    }
    0
}

kernel::kabi_export! {
    strncmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } cs , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } ct , formal_parameter t#size_t count ) -> base_type int byte_size(4) encoding(5)",
}
/// `strncmp()`: -1, 0 or 1.
///
/// # Safety
/// Both readable up to NUL or `count`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strncmp(cs: *const c_char, ct: *const c_char, count: usize) -> c_int {
    let mut cs = cs as *const u8;
    let mut ct = ct as *const u8;
    let mut count = count;

    while count != 0 {
        let c1 = unsafe { *cs };
        cs = unsafe { cs.add(1) };
        let c2 = unsafe { *ct };
        ct = unsafe { ct.add(1) };
        if c1 != c2 {
            return if c1 < c2 { -1 } else { 1 };
        }
        if c1 == 0 {
            break;
        }
        count -= 1;
    }
    0
}

kernel::kabi_export! {
    strchr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type int byte_size(4) encoding(5) c ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strchr()`.
///
/// # Safety
/// `s` NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let mut s = s;

    while unsafe { *s } != c as c_char {
        if unsafe { *s } == 0 {
            return core::ptr::null_mut();
        }
        s = unsafe { s.add(1) };
    }
    s as *mut c_char
}

kernel::kabi_export! {
    strchrnul,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type int byte_size(4) encoding(5) c ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strchrnul()`.
///
/// # Safety
/// `s` NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    let mut s = s;

    while unsafe { *s } != 0 && unsafe { *s } != c as c_char {
        s = unsafe { s.add(1) };
    }
    s as *mut c_char
}

/// `strnchrnul()` (not exported).
///
/// # Safety
/// `s` readable up to NUL or `count`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strnchrnul(s: *const c_char, count: usize, c: c_int) -> *mut c_char {
    let mut s = s;
    let mut count = count;

    loop {
        let had = count;
        count = count.wrapping_sub(1);
        if had == 0 || unsafe { *s } == 0 || unsafe { *s } == c as c_char {
            break;
        }
        s = unsafe { s.add(1) };
    }
    s as *mut c_char
}

kernel::kabi_export! {
    strrchr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter base_type int byte_size(4) encoding(5) c ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strrchr()`.
///
/// # Safety
/// `s` NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    let mut last: *const c_char = core::ptr::null();
    let mut s = s;

    loop {
        if unsafe { *s } == c as c_char {
            last = s;
        }
        let end = unsafe { *s } == 0;
        s = unsafe { s.add(1) };
        if end {
            break;
        }
    }
    last as *mut c_char
}

kernel::kabi_export! {
    strnchr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count , formal_parameter base_type int byte_size(4) encoding(5) c ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strnchr()`.
///
/// # Safety
/// `s` readable up to NUL or `count`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strnchr(s: *const c_char, count: usize, c: c_int) -> *mut c_char {
    let mut s = s;
    let mut count = count;

    loop {
        let had = count;
        count = count.wrapping_sub(1);
        if had == 0 {
            break;
        }
        if unsafe { *s } == c as c_char {
            return s as *mut c_char;
        }
        let end = unsafe { *s } == 0;
        s = unsafe { s.add(1) };
        if end {
            break;
        }
    }
    core::ptr::null_mut()
}

kernel::kabi_export! {
    strlen,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s ) -> t#size_t",
}
/// `strlen()`.
///
/// # Safety
/// `s` NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let mut sc = s;

    while unsafe { *sc } != 0 {
        sc = unsafe { sc.add(1) };
    }
    (sc as usize).wrapping_sub(s as usize)
}

kernel::kabi_export! {
    strnlen,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter t#size_t count ) -> t#__kernel_size_t",
}
/// `strnlen()`.
///
/// # Safety
/// `s` readable up to NUL or `count`.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strnlen(s: *const c_char, count: usize) -> usize {
    let mut sc = s;
    let mut count = count;

    loop {
        let had = count;
        count = count.wrapping_sub(1);
        if had == 0 || unsafe { *sc } == 0 {
            break;
        }
        sc = unsafe { sc.add(1) };
    }
    (sc as usize).wrapping_sub(s as usize)
}

kernel::kabi_export! {
    strspn,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } accept ) -> t#__kernel_size_t",
}
/// `strspn()`.
///
/// # Safety
/// Both NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    let mut p = s;

    while unsafe { *p } != 0 {
        if unsafe { strchr(accept, *p as c_int) }.is_null() {
            break;
        }
        p = unsafe { p.add(1) };
    }
    (p as usize).wrapping_sub(s as usize)
}

kernel::kabi_export! {
    strcspn,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } reject ) -> t#__kernel_size_t",
}
/// `strcspn()`.
///
/// # Safety
/// Both NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    let mut p = s;

    while unsafe { *p } != 0 {
        if !unsafe { strchr(reject, *p as c_int) }.is_null() {
            break;
        }
        p = unsafe { p.add(1) };
    }
    (p as usize).wrapping_sub(s as usize)
}

kernel::kabi_export! {
    strpbrk,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } cs , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } ct ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strpbrk()`.
///
/// # Safety
/// Both NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strpbrk(cs: *const c_char, ct: *const c_char) -> *mut c_char {
    let mut sc = cs;

    while unsafe { *sc } != 0 {
        if !unsafe { strchr(ct, *sc as c_int) }.is_null() {
            return sc as *mut c_char;
        }
        sc = unsafe { sc.add(1) };
    }
    core::ptr::null_mut()
}

kernel::kabi_export! {
    strsep,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { pointer_type { base_type char byte_size(1) encoding(8) } } s , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } ct ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strsep()`.
///
/// # Safety
/// `s` valid; `*s` NULL or a writable NUL-terminated string; `ct` NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strsep(s: *mut *mut c_char, ct: *const c_char) -> *mut c_char {
    let sbegin = unsafe { *s };

    if sbegin.is_null() {
        return core::ptr::null_mut();
    }

    let mut end = unsafe { strpbrk(sbegin, ct) };
    if !end.is_null() {
        unsafe { *end = 0 };
        end = unsafe { end.add(1) };
    }
    unsafe { *s = end };
    sbegin
}

kernel::kabi_export! {
    memcmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } cs , formal_parameter pointer_type { const_type { base_type void } } ct , formal_parameter t#size_t count ) -> base_type int byte_size(4) encoding(5)",
}
/// `memcmp()`: difference of the first differing bytes.
///
/// # Safety
/// Both readable for `count` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcmp(cs: *const c_void, ct: *const c_void, count: usize) -> c_int {
    let mut count = count;
    let mut p1 = cs as *const u8;
    let mut p2 = ct as *const u8;

    /* CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS: skip equal words */
    if count >= 8 {
        loop {
            let a = unsafe { core::ptr::read_unaligned(p1 as *const u64) };
            let b = unsafe { core::ptr::read_unaligned(p2 as *const u64) };
            if a != b {
                break;
            }
            p1 = unsafe { p1.add(8) };
            p2 = unsafe { p2.add(8) };
            count -= 8;
            if count < 8 {
                break;
            }
        }
    }
    let mut res: c_int = 0;
    while count > 0 {
        res = unsafe { *p1 } as c_int - unsafe { *p2 } as c_int;
        if res != 0 {
            break;
        }
        p1 = unsafe { p1.add(1) };
        p2 = unsafe { p2.add(1) };
        count -= 1;
    }
    res
}

kernel::kabi_export! {
    bcmp,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } a , formal_parameter pointer_type { const_type { base_type void } } b , formal_parameter t#size_t len ) -> base_type int byte_size(4) encoding(5)",
}
/// `bcmp()`.
///
/// # Safety
/// As [`memcmp`].
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int {
    unsafe { memcmp(a, b, len) }
}

kernel::kabi_export! {
    memscan,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } addr , formal_parameter base_type int byte_size(4) encoding(5) c , formal_parameter t#size_t size ) -> pointer_type { base_type void }",
}
/// `memscan()`: first occurrence of byte `c`, or the end of the area.
///
/// # Safety
/// `addr` readable for `size` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memscan(addr: *mut c_void, c: c_int, size: usize) -> *mut c_void {
    let mut p = addr as *mut u8;
    let mut size = size;

    while size != 0 {
        if unsafe { *p } == c as u8 {
            return p as *mut c_void;
        }
        p = unsafe { p.add(1) };
        size -= 1;
    }
    p as *mut c_void
}

kernel::kabi_export! {
    strstr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s1 , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s2 ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strstr()`.
///
/// # Safety
/// Both NUL-terminated.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strstr(s1: *const c_char, s2: *const c_char) -> *mut c_char {
    let mut s1 = s1;

    let l2 = unsafe { strlen(s2) };
    if l2 == 0 {
        return s1 as *mut c_char;
    }
    let mut l1 = unsafe { strlen(s1) };
    while l1 >= l2 {
        l1 -= 1;
        if unsafe { memcmp(s1 as *const c_void, s2 as *const c_void, l2) } == 0 {
            return s1 as *mut c_char;
        }
        s1 = unsafe { s1.add(1) };
    }
    core::ptr::null_mut()
}

kernel::kabi_export! {
    strnstr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s1 , formal_parameter pointer_type { const_type { base_type char byte_size(1) encoding(8) } } s2 , formal_parameter t#size_t len ) -> pointer_type { base_type char byte_size(1) encoding(8) }",
}
/// `strnstr()`.
///
/// # Safety
/// `s2` NUL-terminated; `s1` readable for `len` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strnstr(s1: *const c_char, s2: *const c_char, len: usize) -> *mut c_char {
    let mut s1 = s1;
    let mut len = len;

    let l2 = unsafe { strlen(s2) };
    if l2 == 0 {
        return s1 as *mut c_char;
    }
    while len >= l2 {
        len -= 1;
        if unsafe { memcmp(s1 as *const c_void, s2 as *const c_void, l2) } == 0 {
            return s1 as *mut c_char;
        }
        s1 = unsafe { s1.add(1) };
    }
    core::ptr::null_mut()
}

kernel::kabi_export! {
    memchr,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } s , formal_parameter base_type int byte_size(4) encoding(5) c , formal_parameter t#size_t n ) -> pointer_type { base_type void }",
}
/// `memchr()`.
///
/// # Safety
/// `s` readable for `n` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    let mut p = s as *const u8;
    let mut n = n;

    while n != 0 {
        n -= 1;
        let b = unsafe { *p };
        p = unsafe { p.add(1) };
        if c as u8 == b {
            return unsafe { p.sub(1) } as *mut c_void;
        }
    }
    core::ptr::null_mut()
}

/// `check_bytes8()`.
unsafe fn check_bytes8(start: *const u8, value: u8, bytes: u32) -> *mut c_void {
    let mut start = start;
    let mut bytes = bytes;

    while bytes != 0 {
        if unsafe { *start } != value {
            return start as *mut c_void;
        }
        start = unsafe { start.add(1) };
        bytes -= 1;
    }
    core::ptr::null_mut()
}

kernel::kabi_export! {
    memchr_inv,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } start , formal_parameter base_type int byte_size(4) encoding(5) c , formal_parameter t#size_t bytes ) -> pointer_type { base_type void }",
}
/// `memchr_inv()`: first byte that differs from `c`, or NULL.
///
/// # Safety
/// `start` readable for `bytes` bytes.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memchr_inv(start: *const c_void, c: c_int, bytes: usize) -> *mut c_void {
    let value = c as u8;
    let mut start = start as *const u8;
    let mut bytes = bytes;

    if bytes <= 16 {
        return unsafe { check_bytes8(start, value, bytes as u32) };
    }

    /* CONFIG_ARCH_HAS_FAST_MULTIPLIER on x86-64 */
    let value64: u64 = (value as u64).wrapping_mul(0x0101010101010101);

    let mut prefix = ((start as usize) % 8) as u32;
    if prefix != 0 {
        prefix = 8 - prefix;
        let r = unsafe { check_bytes8(start, value, prefix) };
        if !r.is_null() {
            return r;
        }
        start = unsafe { start.add(prefix as usize) };
        bytes -= prefix as usize;
    }

    let mut words = (bytes / 8) as u32;

    while words != 0 {
        if unsafe { *(start as *const u64) } != value64 {
            return unsafe { check_bytes8(start, value, 8) };
        }
        start = unsafe { start.add(8) };
        words -= 1;
    }

    unsafe { check_bytes8(start, value, (bytes % 8) as u32) }
}
