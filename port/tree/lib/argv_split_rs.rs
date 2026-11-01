// SPDX-License-Identifier: GPL-2.0-only

//! `argv_split()` and `argv_free()` -- the Rust behind `lib/argv_split.c`.
//!
//! Ported from `lib/argv_split.c` (6.18.49): split a string on whitespace into a freshly allocated `argv[]` whose first slot (index -1) holds the copy of the string the
//! words point into. Whitespace is the kernel's `isspace()` (its `_ctype` table): `\t \n \v \f \r`, space, and 0xa0. In C (`argv_split_glue.c`): the exports as thunks
//! (the MODVERSIONS fingerprint comes from the DWARF of the definition) and one-line wrappers for the allocator calls (`kstrndup()` with `KMALLOC_MAX_SIZE`,
//! `kmalloc_array()`, `kfree()`: allocation profiling and configuration-dependent limits).
//!
//! Replaces: lib/argv_split.c

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

extern "C" {
    fn rust_as_kstrndup(s: *const c_char, gfp: u32) -> *mut c_char;
    fn rust_as_kmalloc_array(n: usize, gfp: u32) -> *mut *mut c_char;
    fn rust_as_kfree(p: *const c_void);
}

/// The kernel's `isspace()` (checked against the macro by the userspace differential and, in the kernel, by libtest's 0xa0 case).
fn isspace(c: c_char) -> bool {
    matches!(c as u8, 0x09..=0x0d | 0x20 | 0xa0)
}

unsafe fn count_argc(mut s: *const c_char) -> c_int {
    let mut count = 0;
    let mut was_space = true;
    while unsafe { *s } != 0 {
        if isspace(unsafe { *s }) {
            was_space = true;
        } else if was_space {
            was_space = false;
            count += 1;
        }
        s = unsafe { s.add(1) };
    }
    count
}

/// The body of C `argv_free()`.
#[no_mangle]
pub unsafe extern "C" fn rust_argv_free(argv: *mut *mut c_char) {
    unsafe {
        let argv = argv.sub(1);
        rust_as_kfree(*argv as *const c_void);
        rust_as_kfree(argv as *const c_void);
    }
}

/// The body of C `argv_split()`.
#[no_mangle]
pub unsafe extern "C" fn rust_argv_split(gfp: u32, str: *const c_char, argcp: *mut c_int) -> *mut *mut c_char {
    unsafe {
        let mut argv_str = rust_as_kstrndup(str, gfp);
        if argv_str.is_null() {
            return null_mut();
        }

        let argc = count_argc(argv_str);
        let mut argv = rust_as_kmalloc_array(argc as usize + 2, gfp);
        if argv.is_null() {
            rust_as_kfree(argv_str as *const c_void);
            return null_mut();
        }

        *argv = argv_str;
        argv = argv.add(1);
        let argv_ret = argv;
        let mut was_space = true;
        while *argv_str != 0 {
            if isspace(*argv_str) {
                was_space = true;
                *argv_str = 0;
            } else if was_space {
                was_space = false;
                *argv = argv_str;
                argv = argv.add(1);
            }
            argv_str = argv_str.add(1);
        }
        *argv = null_mut();

        if !argcp.is_null() {
            *argcp = argc;
        }
        argv_ret
    }
}
