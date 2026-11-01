// SPDX-License-Identifier: GPL-2.0-only

//! The kobject machinery -- the Rust behind `lib/kobject.c`.
//!
//! Ported from `lib/kobject.c` (6.18.49): reference-counted objects that appear as sysfs directories, grouped in ksets, with namespace-type registration.
//! In Rust: path building, the kset join/leave, add/del/rename/move, the reference counting and cleanup, `kset_register`/`kset_unregister`/`kset_find_obj`
//! and the namespace-type table. In C (`kobject_glue.c`): everything that takes a `va_list` or `...` (`kobject_set_name*`, `kobject_add*`,
//! `kobject_init_and_add`, `kset_create*`, `kobject_create*`), `kset_init` (lockdep key per call site), the two `kobj_type`s and `kobj_sysfs_ops`
//! (static data with function pointers), the export thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition), and one-line wrappers
//! for everything whose behaviour depends on the configuration: `spinlock_t`, `kref`/`refcount_t`, list operations, the sysfs and uevent calls, the
//! allocator (allocation profiling), the bit-fields of `struct kobject`, and every WARN/BUG/pr_err site (messages now name the glue file -- recorded divergence).
//! `pr_debug` sites are not carried over: the Rust arm is only built when `CONFIG_DEBUG_KOBJECT` is off, where they compile to nothing.
//!
//! Replaces: lib/kobject.c (all but the variadic parts, `kset_init` and the static `kobj_type`s)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const ENOENT: c_int = 2;

const KOBJ_ADD: c_int = 0;
const KOBJ_REMOVE: c_int = 1;
const KOBJ_MOVE: c_int = 3;
const KOBJ_NS_TYPE_NONE: c_int = 0;
const KOBJ_NS_TYPES: c_int = 2;

/// `struct list_head`.
#[repr(C)]
pub struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

/// `struct kobject` up to the bit-fields (checked by `kobject_glue.c`; the bit-fields and the optional delayed work are only touched through wrappers).
#[repr(C)]
pub struct Kobject {
    name: *const c_char,
    entry: ListHead,
    parent: *mut Kobject,
    kset: *mut c_void,
    ktype: *const KobjType,
    sd: *mut c_void,
}

type ReleaseFn = Option<unsafe extern "C" fn(*mut Kobject)>;
type ChildNsFn = Option<unsafe extern "C" fn(*const Kobject) -> *const NsOps>;
type NamespaceFn = Option<unsafe extern "C" fn(*const Kobject) -> *const c_void>;
type OwnershipFn = Option<unsafe extern "C" fn(*const Kobject, *mut c_void, *mut c_void)>;

/// `struct kobj_type`.
#[repr(C)]
pub struct KobjType {
    release: ReleaseFn,
    sysfs_ops: *const c_void,
    default_groups: *const c_void,
    child_ns_type: ChildNsFn,
    namespace: NamespaceFn,
    get_ownership: OwnershipFn,
}

/// `struct kobj_ns_type_operations`.
#[repr(C)]
pub struct NsOps {
    type_: c_int,
    current_may_mount: Option<unsafe extern "C" fn() -> bool>,
    grab_current_ns: Option<unsafe extern "C" fn() -> *mut c_void>,
    netlink_ns: *const c_void,
    initial_ns: *const c_void,
    drop_ns: Option<unsafe extern "C" fn(*mut c_void)>,
}

extern "C" {
    // layout of `struct kset` (it is __randomize_layout, so the offsets come from C)
    static rust_ks_off_list: usize;
    static rust_ks_off_kobj: usize;

    fn kset_init(k: *mut c_void);

    fn rust_ko_ks_lock(kset: *mut c_void);
    fn rust_ko_ks_unlock(kset: *mut c_void);
    fn rust_ko_ns_lock();
    fn rust_ko_ns_unlock();

    fn rust_ko_list_add_tail(new: *mut ListHead, head: *mut ListHead);
    fn rust_ko_list_del_init(entry: *mut ListHead);
    fn rust_ko_init_list_head(l: *mut ListHead);

    fn rust_ko_kref_init(k: *mut Kobject);
    fn rust_ko_kref_get(k: *mut Kobject);
    fn rust_ko_kref_get_unless_zero(k: *mut Kobject) -> bool;
    fn rust_ko_kref_put(k: *mut Kobject);

    fn rust_ko_init_state(k: *mut Kobject);
    fn rust_ko_get_initialized(k: *const Kobject) -> bool;
    fn rust_ko_get_in_sysfs(k: *const Kobject) -> bool;
    fn rust_ko_set_in_sysfs(k: *mut Kobject, v: bool);
    fn rust_ko_get_add_sent(k: *const Kobject) -> bool;
    fn rust_ko_get_remove_sent(k: *const Kobject) -> bool;

    fn rust_ko_sysfs_create_dir_ns(k: *mut Kobject, ns: *const c_void) -> c_int;
    fn rust_ko_sysfs_create_groups(k: *mut Kobject, groups: *const c_void) -> c_int;
    fn rust_ko_sysfs_remove_groups(k: *mut Kobject, groups: *const c_void);
    fn rust_ko_sysfs_remove_dir(k: *mut Kobject);
    fn rust_ko_sysfs_get(k: *mut Kobject);
    fn rust_ko_sysfs_put(sd: *mut c_void);
    fn rust_ko_sysfs_enable_ns(k: *mut Kobject);
    fn rust_ko_sysfs_rename_dir_ns(k: *mut Kobject, new_name: *const c_char, ns: *const c_void) -> c_int;
    fn rust_ko_sysfs_move_dir_ns(k: *mut Kobject, new_parent: *mut Kobject, ns: *const c_void) -> c_int;

    fn rust_ko_uevent(k: *mut Kobject, action: c_int) -> c_int;
    fn rust_ko_uevent_env(k: *mut Kobject, action: c_int, envp: *mut *mut c_char) -> c_int;

    fn rust_ko_root_ownership(uid: *mut c_void, gid: *mut c_void);
    fn rust_ko_gfp_kernel() -> u32;
    fn rust_ko_kzalloc(size: usize, gfp: u32) -> *mut c_char;
    fn rust_ko_kfree(p: *const c_void);
    fn rust_ko_kfree_const(p: *const c_char);
    fn rust_ko_kstrdup_const(s: *const c_char) -> *const c_char;
    fn rust_ko_devpath_old(devpath: *const c_char) -> *mut c_char;

    fn rust_ko_bug_on(cond: bool);
    fn rust_ko_bug_null_fn();
    fn rust_ko_err_init_bad(k: *mut Kobject, which: c_int);
    fn rust_ko_err_reinit(k: *mut Kobject);
    fn rust_ko_warn_empty_name(k: *mut Kobject);
    fn rust_ko_err_eexist(k: *mut Kobject);
    fn rust_ko_err_add(k: *mut Kobject, error: c_int, parent: *mut Kobject);
    fn rust_ko_warn_uninit(k: *mut Kobject, get: bool);
    fn rust_ko_err_no_ktype();
}

unsafe fn strlen(s: *const c_char) -> usize {
    let mut n = 0;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

unsafe fn streq(a: *const c_char, b: *const c_char) -> bool {
    let mut i = 0;
    loop {
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
        i += 1;
    }
}

#[inline(always)]
unsafe fn ks_kobj(kset: *mut c_void) -> *mut Kobject {
    unsafe { (kset as *mut u8).add(rust_ks_off_kobj) as *mut Kobject }
}

#[inline(always)]
unsafe fn ks_list(kset: *mut c_void) -> *mut ListHead {
    unsafe { (kset as *mut u8).add(rust_ks_off_list) as *mut ListHead }
}

fn ns_type_is_valid(t: c_int) -> bool {
    !(t <= KOBJ_NS_TYPE_NONE || t >= KOBJ_NS_TYPES)
}

// ---- namespace types -------------------------------------------------------------------------------------------------------------------------------

static mut KOBJ_NS_OPS_TBL: [*const NsOps; KOBJ_NS_TYPES as usize] = [null(); KOBJ_NS_TYPES as usize];

/// The body of C `kobj_ns_type_register()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_type_register(ops: *const NsOps) -> c_int {
    let t = unsafe { (*ops).type_ };
    let mut error;
    unsafe { rust_ko_ns_lock() };
    'out: {
        error = -EINVAL;
        if !ns_type_is_valid(t) {
            break 'out;
        }
        error = -16; // -EBUSY
        if unsafe { !KOBJ_NS_OPS_TBL[t as usize].is_null() } {
            break 'out;
        }
        error = 0;
        unsafe { KOBJ_NS_OPS_TBL[t as usize] = ops };
    }
    unsafe { rust_ko_ns_unlock() };
    error
}

/// The body of C `kobj_ns_type_registered()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_type_registered(t: c_int) -> c_int {
    let mut registered = 0;
    unsafe { rust_ko_ns_lock() };
    if ns_type_is_valid(t) {
        registered = unsafe { !KOBJ_NS_OPS_TBL[t as usize].is_null() } as c_int;
    }
    unsafe { rust_ko_ns_unlock() };
    registered
}

/// The body of C `kobj_child_ns_ops()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_child_ns_ops(parent: *const Kobject) -> *const NsOps {
    if !parent.is_null() {
        let kt = unsafe { (*parent).ktype };
        if !kt.is_null() {
            if let Some(f) = unsafe { (*kt).child_ns_type } {
                return unsafe { f(parent) };
            }
        }
    }
    null()
}

/// The body of C `kobj_ns_ops()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_ops(kobj: *const Kobject) -> *const NsOps {
    unsafe { rust_kobj_child_ns_ops((*kobj).parent) }
}

/// The body of C `kobj_ns_current_may_mount()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_current_may_mount(t: c_int) -> bool {
    let mut may_mount = true;
    unsafe { rust_ko_ns_lock() };
    if ns_type_is_valid(t) {
        let ops = unsafe { KOBJ_NS_OPS_TBL[t as usize] };
        if !ops.is_null() {
            match unsafe { (*ops).current_may_mount } {
                Some(f) => may_mount = unsafe { f() },
                None => unsafe { rust_ko_bug_null_fn() },
            }
        }
    }
    unsafe { rust_ko_ns_unlock() };
    may_mount
}

/// The body of C `kobj_ns_grab_current()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_grab_current(t: c_int) -> *mut c_void {
    let mut ns = null_mut();
    unsafe { rust_ko_ns_lock() };
    if ns_type_is_valid(t) {
        let ops = unsafe { KOBJ_NS_OPS_TBL[t as usize] };
        if !ops.is_null() {
            match unsafe { (*ops).grab_current_ns } {
                Some(f) => ns = unsafe { f() },
                None => unsafe { rust_ko_bug_null_fn() },
            }
        }
    }
    unsafe { rust_ko_ns_unlock() };
    ns
}

/// The body of C `kobj_ns_drop()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobj_ns_drop(t: c_int, ns: *mut c_void) {
    unsafe { rust_ko_ns_lock() };
    if ns_type_is_valid(t) {
        let ops = unsafe { KOBJ_NS_OPS_TBL[t as usize] };
        if !ops.is_null() {
            if let Some(f) = unsafe { (*ops).drop_ns } {
                unsafe { f(ns) };
            }
        }
    }
    unsafe { rust_ko_ns_unlock() };
}

// ---- ownership, namespace, sysfs directory -----------------------------------------------------------------------------------------------------

/// The body of C `kobject_namespace()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_namespace(kobj: *const Kobject) -> *const c_void {
    let ns_ops = unsafe { rust_kobj_ns_ops(kobj) };
    if ns_ops.is_null() || unsafe { (*ns_ops).type_ } == KOBJ_NS_TYPE_NONE {
        return null();
    }
    match unsafe { (*(*kobj).ktype).namespace } {
        Some(f) => unsafe { f(kobj) },
        None => {
            unsafe { rust_ko_bug_null_fn() };
            null()
        }
    }
}

/// The body of C `kobject_get_ownership()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_get_ownership(kobj: *const Kobject, uid: *mut c_void, gid: *mut c_void) {
    unsafe { rust_ko_root_ownership(uid, gid) };
    if let Some(f) = unsafe { (*(*kobj).ktype).get_ownership } {
        unsafe { f(kobj, uid, gid) };
    }
}

unsafe fn create_dir(kobj: *mut Kobject) -> c_int {
    let ktype = unsafe { (*kobj).ktype };
    let mut error = unsafe { rust_ko_sysfs_create_dir_ns(kobj, rust_kobject_namespace(kobj)) };
    if error != 0 {
        return error;
    }
    if !ktype.is_null() {
        error = unsafe { rust_ko_sysfs_create_groups(kobj, (*ktype).default_groups) };
        if error != 0 {
            unsafe { rust_ko_sysfs_remove_dir(kobj) };
            return error;
        }
    }
    // @kobj->sd may be deleted by an ancestor going away; hold a reference so it stays valid for the lifetime of @kobj
    unsafe { rust_ko_sysfs_get(kobj) };
    // If @kobj has child kobjects on which it holds a namespace tag, enable namespace support on its children
    let ops = unsafe { rust_kobj_child_ns_ops(kobj) };
    if !ops.is_null() {
        let t = unsafe { (*ops).type_ };
        unsafe {
            rust_ko_bug_on(!ns_type_is_valid(t));
            rust_ko_bug_on(rust_kobj_ns_type_registered(t) == 0);
            rust_ko_sysfs_enable_ns(kobj);
        }
    }
    0
}

// ---- paths -----------------------------------------------------------------------------------------------------------------------------------------

unsafe fn get_kobj_path_length(kobj: *const Kobject) -> c_int {
    let mut length: c_int = 1;
    let mut parent = kobj;
    // walk up the ancestors until we hit the one pointing to the root; add 1 to strlen for the leading '/' of each level
    loop {
        let name = unsafe { (*parent).name };
        if name.is_null() {
            return 0;
        }
        length = length.wrapping_add(unsafe { strlen(name) } as c_int).wrapping_add(1);
        parent = unsafe { (*parent).parent };
        if parent.is_null() {
            break;
        }
    }
    length
}

unsafe fn fill_kobj_path(kobj: *const Kobject, path: *mut c_char, length: c_int) -> c_int {
    let mut length = length.wrapping_sub(1);
    let mut parent = kobj;
    while !parent.is_null() {
        let name = unsafe { (*parent).name };
        let cur = unsafe { strlen(name) } as c_int;
        // back up enough to print this name with '/'
        length = length.wrapping_sub(cur);
        if length <= 0 {
            return -EINVAL;
        }
        unsafe { core::ptr::copy_nonoverlapping(name, path.add(length as usize), cur as usize) };
        length -= 1;
        unsafe { *path.add(length as usize) = b'/' as c_char };
        parent = unsafe { (*parent).parent };
    }
    0
}

/// The body of C `kobject_get_path()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_get_path(kobj: *const Kobject, gfp: u32) -> *mut c_char {
    loop {
        let len = unsafe { get_kobj_path_length(kobj) };
        if len == 0 {
            return null_mut();
        }
        let path = unsafe { rust_ko_kzalloc(len as usize, gfp) };
        if path.is_null() {
            return null_mut();
        }
        if unsafe { fill_kobj_path(kobj, path, len) } != 0 {
            unsafe { rust_ko_kfree(path as *const c_void) };
            continue;
        }
        return path;
    }
}

// ---- ksets -----------------------------------------------------------------------------------------------------------------------------------------

/// `kset_get()` / `kset_put()` (header inlines).
unsafe fn kset_get(k: *mut c_void) {
    if !k.is_null() {
        unsafe { rust_kobject_get(ks_kobj(k)) };
    }
}

unsafe fn kset_put(k: *mut c_void) {
    unsafe { rust_kobject_put(ks_kobj(k)) };
}

/// add the kobject to its kset's list
unsafe fn kobj_kset_join(kobj: *mut Kobject) {
    let ks = unsafe { (*kobj).kset };
    if ks.is_null() {
        return;
    }
    unsafe {
        kset_get(ks);
        rust_ko_ks_lock(ks);
        rust_ko_list_add_tail(&raw mut (*kobj).entry, ks_list(ks));
        rust_ko_ks_unlock(ks);
    }
}

/// remove the kobject from its kset's list
unsafe fn kobj_kset_leave(kobj: *mut Kobject) {
    let ks = unsafe { (*kobj).kset };
    if ks.is_null() {
        return;
    }
    unsafe {
        rust_ko_ks_lock(ks);
        rust_ko_list_del_init(&raw mut (*kobj).entry);
        rust_ko_ks_unlock(ks);
        kset_put(ks);
    }
}

/// The body of C `kobject_init_internal()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_init_internal(kobj: *mut Kobject) {
    if kobj.is_null() {
        return;
    }
    unsafe {
        rust_ko_kref_init(kobj);
        rust_ko_init_list_head(&raw mut (*kobj).entry);
        rust_ko_init_state(kobj);
    }
}

/// The body of C `kobject_add_internal()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_add_internal(kobj: *mut Kobject) -> c_int {
    if kobj.is_null() {
        return -ENOENT;
    }
    unsafe {
        let name = (*kobj).name;
        if name.is_null() || *name == 0 {
            rust_ko_warn_empty_name(kobj);
            return -EINVAL;
        }

        let mut parent = rust_kobject_get((*kobj).parent);

        // join kset if set, use it as parent if we do not already have one
        if !(*kobj).kset.is_null() {
            if parent.is_null() {
                parent = rust_kobject_get(ks_kobj((*kobj).kset));
            }
            kobj_kset_join(kobj);
            (*kobj).parent = parent;
        }

        let error = create_dir(kobj);
        if error != 0 {
            kobj_kset_leave(kobj);
            rust_kobject_put(parent);
            (*kobj).parent = null_mut();

            // be noisy on error issues
            if error == -17 {
                rust_ko_err_eexist(kobj);
            } else {
                rust_ko_err_add(kobj, error, parent);
            }
            error
        } else {
            rust_ko_set_in_sysfs(kobj, true);
            error
        }
    }
}

/// The body of C `kobject_init()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_init(kobj: *mut Kobject, ktype: *const KobjType) {
    unsafe {
        if kobj.is_null() {
            rust_ko_err_init_bad(kobj, 0);
            return;
        }
        if ktype.is_null() {
            rust_ko_err_init_bad(kobj, 1);
            return;
        }
        if rust_ko_get_initialized(kobj) {
            // do not error out as sometimes we can recover
            rust_ko_err_reinit(kobj);
        }
        rust_kobject_init_internal(kobj);
        (*kobj).ktype = ktype;
    }
}

// ---- rename / move ---------------------------------------------------------------------------------------------------------------------------------

/// The body of C `kobject_rename()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_rename(kobj: *mut Kobject, new_name: *const c_char) -> c_int {
    unsafe {
        let error;
        let mut devpath_string: *mut c_char = null_mut();
        let mut dup_name: *const c_char = null();
        let mut envp: [*mut c_char; 2] = [null_mut(); 2];

        let kobj = rust_kobject_get(kobj);
        if kobj.is_null() {
            return -EINVAL;
        }
        if (*kobj).parent.is_null() {
            rust_kobject_put(kobj);
            return -EINVAL;
        }

        let devpath = rust_kobject_get_path(kobj, rust_ko_gfp_kernel());
        'out: {
            if devpath.is_null() {
                error = -ENOMEM;
                break 'out;
            }
            devpath_string = rust_ko_devpath_old(devpath);
            if devpath_string.is_null() {
                error = -ENOMEM;
                break 'out;
            }
            envp[0] = devpath_string;
            envp[1] = null_mut();

            let name = rust_ko_kstrdup_const(new_name);
            dup_name = name;
            if name.is_null() {
                error = -ENOMEM;
                break 'out;
            }

            error = rust_ko_sysfs_rename_dir_ns(kobj, new_name, rust_kobject_namespace(kobj));
            if error != 0 {
                break 'out;
            }

            // Install the new kobject name
            dup_name = (*kobj).name;
            (*kobj).name = name;

            // This function is mostly/only used for network interface. Some hotplug package track interfaces by their name and therefore want to know when the name is changed by the user.
            rust_ko_uevent_env(kobj, KOBJ_MOVE, envp.as_mut_ptr());
        }
        rust_ko_kfree_const(dup_name);
        rust_ko_kfree(devpath_string as *const c_void);
        rust_ko_kfree(devpath as *const c_void);
        rust_kobject_put(kobj);
        error
    }
}

/// The body of C `kobject_move()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_move(kobj: *mut Kobject, new_parent: *mut Kobject) -> c_int {
    unsafe {
        let error;
        let mut devpath_string: *mut c_char = null_mut();
        let mut envp: [*mut c_char; 2] = [null_mut(); 2];

        let kobj = rust_kobject_get(kobj);
        if kobj.is_null() {
            return -EINVAL;
        }
        let mut new_parent = rust_kobject_get(new_parent);
        if new_parent.is_null() && !(*kobj).kset.is_null() {
            new_parent = rust_kobject_get(ks_kobj((*kobj).kset));
        }

        // old object path
        let devpath = rust_kobject_get_path(kobj, rust_ko_gfp_kernel());
        'out: {
            if devpath.is_null() {
                error = -ENOMEM;
                break 'out;
            }
            devpath_string = rust_ko_devpath_old(devpath);
            if devpath_string.is_null() {
                error = -ENOMEM;
                break 'out;
            }
            envp[0] = devpath_string;
            envp[1] = null_mut();
            error = rust_ko_sysfs_move_dir_ns(kobj, new_parent, rust_kobject_namespace(kobj));
            if error != 0 {
                break 'out;
            }
            let old_parent = (*kobj).parent;
            (*kobj).parent = new_parent;
            new_parent = null_mut();
            rust_kobject_put(old_parent);
            rust_ko_uevent_env(kobj, KOBJ_MOVE, envp.as_mut_ptr());
        }
        rust_kobject_put(new_parent);
        rust_kobject_put(kobj);
        rust_ko_kfree(devpath_string as *const c_void);
        rust_ko_kfree(devpath as *const c_void);
        error
    }
}

// ---- del / get / put -------------------------------------------------------------------------------------------------------------------------------

unsafe fn kobject_del_inner(kobj: *mut Kobject) {
    unsafe {
        let sd = (*kobj).sd;
        let ktype = (*kobj).ktype;

        if !ktype.is_null() {
            rust_ko_sysfs_remove_groups(kobj, (*ktype).default_groups);
        }

        // send "remove" if the caller did not do it but sent "add"
        if rust_ko_get_add_sent(kobj) && !rust_ko_get_remove_sent(kobj) {
            rust_ko_uevent(kobj, KOBJ_REMOVE);
        }

        rust_ko_sysfs_remove_dir(kobj);
        rust_ko_sysfs_put(sd);

        rust_ko_set_in_sysfs(kobj, false);
        kobj_kset_leave(kobj);
        (*kobj).parent = null_mut();
    }
}

/// The body of C `kobject_del()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_del(kobj: *mut Kobject) {
    if kobj.is_null() {
        return;
    }
    unsafe {
        let parent = (*kobj).parent;
        kobject_del_inner(kobj);
        rust_kobject_put(parent);
    }
}

/// The body of C `kobject_get()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_get(kobj: *mut Kobject) -> *mut Kobject {
    if !kobj.is_null() {
        unsafe {
            if !rust_ko_get_initialized(kobj) {
                rust_ko_warn_uninit(kobj, true);
            }
            rust_ko_kref_get(kobj);
        }
    }
    kobj
}

/// The body of C `kobject_get_unless_zero()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_get_unless_zero(kobj: *mut Kobject) -> *mut Kobject {
    if kobj.is_null() {
        return null_mut();
    }
    if unsafe { !rust_ko_kref_get_unless_zero(kobj) } {
        return null_mut();
    }
    kobj
}

/// free kobject resources (called by the kref release in C)
/// The body of C `kobject_cleanup()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_cleanup(kobj: *mut Kobject) {
    unsafe {
        let mut parent = (*kobj).parent;
        let t = (*kobj).ktype;
        let name = (*kobj).name;

        // remove from sysfs if the caller did not do it
        if rust_ko_get_in_sysfs(kobj) {
            kobject_del_inner(kobj);
        } else {
            // avoid dropping the parent reference unnecessarily
            parent = null_mut();
        }

        if !t.is_null() {
            if let Some(release) = (*t).release {
                release(kobj);
            }
        }

        // free name if we allocated it
        if !name.is_null() {
            rust_ko_kfree_const(name);
        }

        rust_kobject_put(parent);
    }
}

/// The body of C `kobject_put()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_put(kobj: *mut Kobject) {
    if !kobj.is_null() {
        unsafe {
            if !rust_ko_get_initialized(kobj) {
                rust_ko_warn_uninit(kobj, false);
            }
            rust_ko_kref_put(kobj);
        }
    }
}

// ---- ksets -----------------------------------------------------------------------------------------------------------------------------------------

/// The body of C `kset_register()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kset_register(k: *mut c_void) -> c_int {
    if k.is_null() {
        return -EINVAL;
    }
    unsafe {
        let kobj = ks_kobj(k);
        if (*kobj).ktype.is_null() {
            rust_ko_err_no_ktype();
            return -EINVAL;
        }
        kset_init(k);
        let err = rust_kobject_add_internal(kobj);
        if err != 0 {
            rust_ko_kfree_const((*kobj).name);
            // Set it to NULL to avoid accessing bad pointer in callers.
            (*kobj).name = null();
            return err;
        }
        rust_ko_uevent(kobj, KOBJ_ADD);
    }
    0
}

/// The body of C `kset_unregister()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kset_unregister(k: *mut c_void) {
    if k.is_null() {
        return;
    }
    unsafe {
        rust_kobject_del(ks_kobj(k));
        rust_kobject_put(ks_kobj(k));
    }
}

/// The body of C `kset_find_obj()` (`kobject_glue.c` holds the export).
#[no_mangle]
pub unsafe extern "C" fn rust_kset_find_obj(kset: *mut c_void, name: *const c_char) -> *mut Kobject {
    let mut ret = null_mut();
    unsafe {
        rust_ko_ks_lock(kset);
        let head = ks_list(kset);
        let mut p = (*head).next;
        while p != head {
            // list_for_each_entry: `entry` is the list member of struct kobject
            let k = (p as *mut u8).sub(core::mem::offset_of!(Kobject, entry)) as *mut Kobject;
            let n = (*k).name;
            if !n.is_null() && streq(n, name) {
                ret = rust_kobject_get_unless_zero(k);
                break;
            }
            p = (*p).next;
        }
        rust_ko_ks_unlock(kset);
    }
    ret
}
