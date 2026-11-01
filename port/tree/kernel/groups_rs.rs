// SPDX-License-Identifier: GPL-2.0

//! Supplementary group list sorting and search -- the Rust behind part of `kernel/groups.c`.
//!
//! Ported from `kernel/groups.c` (6.18.49): `gid_cmp()`, `groups_sort()` (EXPORT_SYMBOL) and
//! `groups_search()`, the binary search every permission check (`in_group_p()`) runs. What stays in C
//! (`groups_glue.c`): allocation, credentials, user-namespace mapping, user-memory copies and the
//! system calls.
//!
//! `groups_sort()` calls the kernel's own `sort()` with the same comparison and no swap function;
//! `groups_search()` is the C's unsigned-index bisection, comparing raw gid values (`gid_gt`/`gid_lt`
//! compare `kgid_t.val`). Neither has a guard, WARN or static key, so no C entry stays:
//! `kernel::kabi_export!` carries the export and its contract (C fingerprint 0x4c2a82bc, taken from
//! the C object before it was removed with `rig/kabi-symtypes.sh`).
//!
//! Replaces: kernel/groups.c (the sort/search half)

use core::ffi::{c_int, c_void};

/// Mirrors `kgid_t`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Kgid(u32);

/// Mirrors `struct group_info` (`include/linux/cred.h`); `gid` is a flexible array.
#[repr(C)]
pub struct GroupInfo {
    usage: i32,
    ngroups: c_int,
    gid: [Kgid; 0],
}

extern "C" {
    fn sort(
        base: *mut c_void,
        num: usize,
        size: usize,
        cmp_func: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
        swap_func: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
    );
}

/// `gid_cmp()`: `gid_gt(a, b) - gid_lt(a, b)`.
unsafe extern "C" fn gid_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = unsafe { (*(a as *const Kgid)).0 };
    let b = unsafe { (*(b as *const Kgid)).0 };

    (a > b) as c_int - (a < b) as c_int
}

// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
kernel::kabi_rule!("type_string", "s#group_info",
    "structure_type group_info { member t#refcount_t usage data_member_location(0) , member base_type int byte_size(4) encoding(5) ngroups data_member_location(4) , member array_type[] { t#kgid_t } gid data_member_location(8) } byte_size(8)");
kernel::kabi_rule!("type_string", "s#refcount_struct",
    "structure_type refcount_struct { member t#atomic_t refs data_member_location(0) } byte_size(4)");
kernel::kabi_rule!("type_string", "t#atomic_t",
    "typedef_type atomic_t { structure_type { member base_type int byte_size(4) encoding(5) counter data_member_location(0) } byte_size(4) }");
kernel::kabi_rule!("type_string", "t#gid_t",
    "typedef_type gid_t { t#__kernel_gid32_t }");
kernel::kabi_rule!("type_string", "t#__kernel_gid32_t",
    "typedef_type __kernel_gid32_t { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#kgid_t",
    "typedef_type kgid_t { structure_type { member t#gid_t val data_member_location(0) } byte_size(4) }");
kernel::kabi_rule!("type_string", "t#refcount_t",
    "typedef_type refcount_t { s#refcount_struct }");

kernel::kabi_export! {
    groups_sort,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { s#group_info } group_info ) -> base_type void",
}

/// `groups_sort()`: sort the group list by gid.
///
/// # Safety
/// `group_info` valid, with `ngroups` writable entries after the header.
#[no_mangle]
pub unsafe extern "C" fn groups_sort(group_info: *mut GroupInfo) {
    unsafe {
        sort(
            (*group_info).gid.as_mut_ptr() as *mut c_void,
            (*group_info).ngroups as usize,
            core::mem::size_of::<Kgid>(),
            Some(gid_cmp),
            None,
        )
    };
}

/* a simple bsearch */
/// `groups_search()`: is `grp` in the sorted list? 1 if so, 0 if not (or no list).
///
/// # Safety
/// `group_info` is NULL, or valid with `ngroups` readable, sorted entries.
#[no_mangle]
pub unsafe extern "C" fn groups_search(group_info: *const GroupInfo, grp: Kgid) -> c_int {
    if group_info.is_null() {
        return 0;
    }

    let gid = unsafe { (*group_info).gid.as_ptr() };
    let mut left: u32 = 0;
    let mut right: u32 = unsafe { (*group_info).ngroups } as u32;
    while left < right {
        let mid: u32 = left.wrapping_add(right) / 2;
        let g = unsafe { (*gid.add(mid as usize)).0 };
        if grp.0 > g {
            left = mid + 1;
        } else if grp.0 < g {
            right = mid;
        } else {
            return 1;
        }
    }
    0
}
