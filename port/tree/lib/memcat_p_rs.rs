// SPDX-License-Identifier: GPL-2.0-only

//! `__memcat_p()` -- the Rust behind `lib/memcat_p.c`.
//!
//! Ported from `lib/memcat_p.c` (6.18.49): merge two NULL-terminated pointer arrays into a newly allocated, NULL-terminated one. The walk is kept as upstream's: count both
//! arrays, then fill the new one from its NULL terminator backwards, `p` stepping back through `b[]` and then `a[]`. In C (`memcat_p_glue.c`): the export as a thunk (the
//! MODVERSIONS fingerprint comes from the DWARF of the definition) and the `kmalloc_array(..., GFP_KERNEL)` wrapper (allocation profiling).
//!
//! Replaces: lib/memcat_p.c

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

extern "C" {
    fn rust_mc_kmalloc_array(n: usize) -> *mut *mut c_void;
}

/// The body of C `__memcat_p()`.
#[no_mangle]
pub unsafe extern "C" fn rust___memcat_p(a: *mut *mut c_void, b: *mut *mut c_void) -> *mut *mut c_void {
    unsafe {
        let mut nr: c_int = 0;

        // count the elements in both arrays
        let mut p = a;
        while !(*p).is_null() {
            nr += 1;
            p = p.add(1);
        }
        p = b;
        while !(*p).is_null() {
            nr += 1;
            p = p.add(1);
        }
        // one for the NULL-terminator
        nr += 1;

        let new = rust_mc_kmalloc_array(nr as usize);
        if new.is_null() {
            return null_mut();
        }

        // nr -> last index; p points to NULL in b[]
        nr -= 1;
        while nr >= 0 {
            *new.add(nr as usize) = *p;
            nr -= 1;
            p = if p == b { a.offset(nr as isize) } else { p.sub(1) };
        }

        new
    }
}
