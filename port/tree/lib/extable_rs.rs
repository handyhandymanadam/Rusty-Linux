// SPDX-License-Identifier: GPL-2.0-or-later

//! Exception table sort/search -- the Rust behind `lib/extable.c`.
//!
//! Replaces: lib/extable.c (`sort_extable`, `search_extable`, and their
//! helpers). `trim_init_extable()` stays in C -- see below.
//!
//! None of these three functions carry `EXPORT_SYMBOL`; all are
//! kernel-internal, called from `kernel/extable.c` and module loading, so
//! no ABI contract macro applies here.
//!
//! # `trim_init_extable()` was left behind, and why
//!
//! It is `CONFIG_MODULES`-only and walks `struct module`'s per-memory-type
//! regions via the `static inline within_module_init()` (itself iterating
//! `mod->mem[type].{base,size}` over every "init" `enum mod_mem_type`).
//! That is real coupling to `struct module`'s internal layout for one
//! trimming helper -- exactly the kind of reach-into-a-large-evolving-struct
//! this project's own candidate rule (`rig/candidates.sh`) already excludes
//! everywhere else. `sort_extable()` and `search_extable()` have no such
//! coupling and are the actual hot path (`fixup_exception()` calls
//! `search_extable()` on every recoverable fault), so they move and the
//! module-lifecycle helper does not.
//!
//! # `ARCH_HAS_RELATIVE_EXTABLE`'s x86 arm only -- the other is unreachable here
//!
//! x86-64 always defines it (`arch/x86/include/asm/extable.h`), so this
//! file reproduces only that arm: `exception_table_entry` as three `i32`
//! offsets, `ex_to_insn()` resolving the instruction's relative offset, and
//! `swap_ex()` correcting both offsets for the entries' new addresses.
//!
//! # `swap_ex()`'s `data` field: found in the arch header, not the generic file
//!
//! `lib/extable.c`'s own `swap_ex()` only mentions `insn`/`fixup` under
//! `#ifdef swap_ex_entry_fixup`, with a generic `#else` arm that would leave
//! `data` unswapped. **x86 does define `swap_ex_entry_fixup`**
//! (`arch/x86/include/asm/extable.h`), and that macro's body additionally
//! does a plain `a->data = b->data; b->data = tmp.data` -- `data` is not a
//! relative offset, so it needs copying, not delta-adjusting. Reading only
//! the generic file would have missed this; the reproduced `swap_ex` below
//! includes it because the arch override is what actually compiles here.

use core::ffi::{c_int, c_void};

/// Mirrors `struct exception_table_entry` on x86-64
/// (`ARCH_HAS_RELATIVE_EXTABLE`): three offsets, relative to the entry's
/// own field address, not absolute pointers.
#[repr(C)]
pub struct ExceptionTableEntry {
    insn: i32,
    fixup: i32,
    data: i32,
}

extern "C" {
    fn sort(
        base: *mut c_void,
        num: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
        swap: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
    );
    fn bsearch(
        key: *const c_void,
        base: *const c_void,
        num: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
}

/// `ex_to_insn()`, `ARCH_HAS_RELATIVE_EXTABLE` arm: the field's own address
/// plus its (signed) relative offset.
#[inline]
unsafe fn ex_to_insn(x: *const ExceptionTableEntry) -> usize {
    // SAFETY: caller guarantees `x` is valid.
    let field_addr = unsafe { core::ptr::addr_of!((*x).insn) } as usize;
    // SAFETY: reading a plain i32 field.
    let off = unsafe { (*x).insn } as isize;
    field_addr.wrapping_add(off as usize)
}

/// `cmp_ex_sort()`.
unsafe extern "C" fn cmp_ex_sort(a: *const c_void, b: *const c_void) -> c_int {
    let x = a.cast::<ExceptionTableEntry>();
    let y = b.cast::<ExceptionTableEntry>();
    // SAFETY: `sort()` calls this with valid element pointers.
    let (xi, yi) = unsafe { (ex_to_insn(x), ex_to_insn(y)) };
    if xi > yi {
        1
    } else if xi < yi {
        -1
    } else {
        0
    }
}

/// `swap_ex()`, x86's `swap_ex_entry_fixup` arm inlined: both offsets
/// delta-adjusted for the entries' new positions, `data` copied verbatim.
unsafe extern "C" fn swap_ex(a: *mut c_void, b: *mut c_void, _size: c_int) {
    let x = a.cast::<ExceptionTableEntry>();
    let y = b.cast::<ExceptionTableEntry>();
    let delta = (b as isize).wrapping_sub(a as isize) as i32;
    // SAFETY: `sort()` calls this with valid, distinct element pointers.
    unsafe {
        let tmp_insn = (*x).insn;
        let tmp_fixup = (*x).fixup;
        let tmp_data = (*x).data;

        (*x).insn = (*y).insn + delta;
        (*y).insn = tmp_insn - delta;
        (*x).fixup = (*y).fixup + delta;
        (*y).fixup = tmp_fixup - delta;
        (*x).data = (*y).data;
        (*y).data = tmp_data;
    }
}

/// `sort_extable()`: sort the range `[start, finish)` by instruction
/// address, so [`search_extable`] can binary-search it.
///
/// # Safety
/// `[start, finish)` must be a valid range of `ExceptionTableEntry`.
#[no_mangle]
pub unsafe extern "C" fn sort_extable(
    start: *mut ExceptionTableEntry,
    finish: *mut ExceptionTableEntry,
) {
    // SAFETY: caller guarantees `[start, finish)` is a valid range of this
    // element type; `finish >= start` is the same assumption the C's
    // pointer subtraction makes.
    let num = unsafe { finish.offset_from(start) } as usize;
    // SAFETY: `sort()` (still linkable, whichever language defines it)
    // receives a valid base pointer, element count, and correctly-typed
    // callbacks for that element size.
    unsafe {
        sort(
            start.cast(),
            num,
            core::mem::size_of::<ExceptionTableEntry>(),
            cmp_ex_sort,
            Some(swap_ex),
        )
    };
}

/// `cmp_ex_search()`.
unsafe extern "C" fn cmp_ex_search(key: *const c_void, elt: *const c_void) -> c_int {
    // SAFETY: `bsearch()` calls this with the key pointer given to it and a
    // valid element pointer.
    let k = unsafe { *key.cast::<usize>() };
    let e = elt.cast::<ExceptionTableEntry>();
    // SAFETY: `e` is a valid element pointer from `bsearch()`.
    let ei = unsafe { ex_to_insn(e) };
    if k > ei {
        1
    } else if k < ei {
        -1
    } else {
        0
    }
}

/// `search_extable()`: binary-search a *sorted* exception table for the
/// entry matching `value`, or `NULL`.
///
/// # Safety
/// `base` must point at `num` valid, sorted `ExceptionTableEntry` values.
#[no_mangle]
pub unsafe extern "C" fn search_extable(
    base: *const ExceptionTableEntry,
    num: usize,
    value: usize,
) -> *const ExceptionTableEntry {
    // SAFETY: forwarding the caller's guarantee to `bsearch()`.
    unsafe {
        bsearch(
            core::ptr::addr_of!(value).cast(),
            base.cast(),
            num,
            core::mem::size_of::<ExceptionTableEntry>(),
            cmp_ex_search,
        )
    }
    .cast()
}
