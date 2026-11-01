// SPDX-License-Identifier: GPL-2.0-only

//! The synthetic-uevent parser and the MODALIAS filter -- the Rust behind part of `lib/kobject_uevent.c`.
//!
//! Ported from `lib/kobject_uevent.c` (6.18.49): `kobject_action_type()` (the action word of "add [UUID KEY=VALUE ...]"), `action_arg_word_end()`,
//! `kobject_action_args()` (the UUID and the KEY=VALUE pairs, turned into SYNTH_UUID= / SYNTH_ARG_KEY= variables), `kobject_synth_uevent()` and
//! `zap_modalias_env()` (removing every MODALIAS= variable from the environment block, compacting the buffer). In C (`kobject_uevent_glue.c`): everything else
//! -- the netlink and usermode-helper delivery, `kobject_uevent_env()`, `add_uevent_var()` (it takes `...`), the sockets and the sysctl -- plus the exports
//! as thunks and the wrappers for what Rust cannot express: `add_uevent_var()` with its format strings, `uuid_is_valid()`, the allocator, `pr_warn()`.
//! `struct kobj_uevent_env` is plain data with fixed sizes (`UEVENT_NUM_ENVP` 64, `UEVENT_BUFFER_SIZE` 2048); its layout is checked by `kobject_uevent_glue.c`.
//!
//! Replaces: lib/kobject_uevent.c (kobject_action_type, action_arg_word_end, kobject_action_args, kobject_synth_uevent, zap_modalias_env)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const UUID_STRING_LEN: usize = 36;
const N_ACTIONS: usize = 8;

/// `offsetof(struct kobj_uevent_env, ...)` (checked by `kobject_uevent_glue.c`).
const ENV_ENVP: usize = 24;
const ENV_ENVP_IDX: usize = 536;
const ENV_BUFLEN: usize = 2588;

extern "C" {
    fn rust_ue_action_name(i: usize) -> *const c_char;
    fn rust_ue_isalnum(c: c_char) -> bool;
    fn rust_ue_uuid_is_valid(buf: *const c_char) -> bool;
    fn rust_ue_add_synth_uuid(env: *mut c_void, buf: *const c_char) -> c_int;
    fn rust_ue_add_synth_arg(env: *mut c_void, key: *const c_char, key_len: c_int, val: *const c_char, val_len: c_int) -> c_int;
    fn rust_ue_kzalloc_env() -> *mut c_void;
    fn rust_ue_kfree(p: *const c_void);
    fn rust_ue_uevent_env(kobj: *mut c_void, action: c_int, envp: *mut *mut c_char) -> c_int;
    fn rust_ue_uevent_env_no_uuid(kobj: *mut c_void, action: c_int) -> c_int;
    fn rust_ue_warn_synth(kobj: *mut c_void, msg: c_int);
}

unsafe fn strlen(s: *const c_char) -> usize {
    let mut n = 0;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// The kernel's `isalnum()` (its `_ctype` table: Latin-1 letters count too), through a wrapper.
unsafe fn isalnum(c: c_char) -> bool {
    unsafe { rust_ue_isalnum(c) }
}

/// `strncmp(a, b, n) != 0` for a NUL-terminated `a` and a buffer `b` of at least `n` readable bytes.
unsafe fn strncmp_differs(a: *const c_char, b: *const c_char, n: usize) -> bool {
    for i in 0..n {
        let (x, y) = unsafe { (*a.add(i) as u8, *b.add(i) as u8) };
        if x != y {
            return true;
        }
        if x == 0 {
            return false;
        }
    }
    false
}

unsafe fn kobject_action_type(buf: *const c_char, mut count: usize, ty: *mut c_int, args: *mut *const c_char) -> c_int {
    unsafe {
        if count != 0 && (*buf.add(count - 1) == b'\n' as c_char || *buf.add(count - 1) == 0) {
            count -= 1;
        }
        if count == 0 {
            return -EINVAL;
        }

        // strnchr(buf, count, ' '): stops at a NUL
        let mut args_start: *const c_char = null();
        for i in 0..count {
            if *buf.add(i) == b' ' as c_char {
                args_start = buf.add(i);
                break;
            }
            if *buf.add(i) == 0 {
                break;
            }
        }
        let count_first;
        if !args_start.is_null() {
            count_first = args_start.offset_from(buf) as usize;
            args_start = args_start.add(1);
        } else {
            count_first = count;
        }

        for action in 0..N_ACTIONS {
            let name = rust_ue_action_name(action);
            if strncmp_differs(name, buf, count_first) {
                continue;
            }
            // `kobject_actions[action][count_first]`: past the end of a shorter name the C reads the next byte of .rodata; here that is "not NUL"
            if count_first > strlen(name) || *name.add(count_first) != 0 {
                continue;
            }
            if !args.is_null() {
                *args = args_start;
            }
            *ty = action as c_int;
            return 0;
        }
        -EINVAL
    }
}

unsafe fn action_arg_word_end(buf: *const c_char, buf_end: *const c_char, delim: c_char) -> *const c_char {
    unsafe {
        let mut next = buf;
        while next <= buf_end && *next != delim {
            let c = *next;
            next = next.add(1);
            if !isalnum(c) {
                return null();
            }
        }
        if next == buf {
            return null();
        }
        next
    }
}

unsafe fn kobject_action_args(buf: *const c_char, mut count: usize, ret_env: *mut *mut c_void) -> c_int {
    unsafe {
        if count != 0 && (*buf.add(count - 1) == b'\n' as c_char || *buf.add(count - 1) == 0) {
            count -= 1;
        }
        if count == 0 {
            return -EINVAL;
        }

        let env = rust_ue_kzalloc_env();
        if env.is_null() {
            return -ENOMEM;
        }

        let mut r = -EINVAL;
        'out: {
            // first arg is UUID
            if count < UUID_STRING_LEN || !rust_ue_uuid_is_valid(buf) || rust_ue_add_synth_uuid(env, buf) != 0 {
                break 'out;
            }

            // the rest are custom environment variables in KEY=VALUE format with ' ' delimiter between each KEY=VALUE pair
            let mut next = buf.add(UUID_STRING_LEN);
            let buf_end = buf.add(count - 1);

            while next <= buf_end {
                if *next != b' ' as c_char {
                    break 'out;
                }

                // skip the ' ', key must follow
                next = next.add(1);
                let key = next;
                if key > buf_end {
                    break 'out;
                }

                let mut b = next;
                next = action_arg_word_end(b, buf_end, b'=' as c_char);
                if next.is_null() || next > buf_end || *next != b'=' as c_char {
                    break 'out;
                }
                let key_len = next.offset_from(b) as c_int;

                // skip the '=', value must follow
                next = next.add(1);
                if next > buf_end {
                    break 'out;
                }

                b = next;
                next = action_arg_word_end(b, buf_end, b' ' as c_char);
                if next.is_null() {
                    break 'out;
                }

                if rust_ue_add_synth_arg(env, key, key_len, b, next.offset_from(b) as c_int) != 0 {
                    break 'out;
                }
            }
            r = 0;
        }
        if r != 0 {
            rust_ue_kfree(env);
        } else {
            *ret_env = env;
        }
        r
    }
}

/// The body of C `kobject_synth_uevent()` (`kobject_uevent_glue.c` holds the definition the kernel exports to drivers/base).
#[no_mangle]
pub unsafe extern "C" fn rust_kobject_synth_uevent(kobj: *mut c_void, buf: *const c_char, count: usize) -> c_int {
    unsafe {
        let mut action: c_int = 0;
        let mut action_args: *const c_char = null();
        let mut env: *mut c_void = null_mut();
        let mut msg = 0; // 0: none, 1: "unknown uevent action string", 2: "incorrect uevent action arguments"

        let mut r = kobject_action_type(buf, count, &mut action, &mut action_args);
        'out: {
            if r != 0 {
                msg = 1;
                break 'out;
            }

            if action_args.is_null() {
                r = rust_ue_uevent_env_no_uuid(kobj, action);
                break 'out;
            }

            r = kobject_action_args(action_args, count.wrapping_sub(action_args.offset_from(buf) as usize), &mut env);
            if r == -EINVAL {
                msg = 2;
                break 'out;
            }

            if r != 0 {
                break 'out;
            }

            r = rust_ue_uevent_env(kobj, action, (env as *mut u8).add(ENV_ENVP) as *mut *mut c_char);
            rust_ue_kfree(env);
        }
        if r != 0 {
            rust_ue_warn_synth(kobj, msg);
        }
        r
    }
}

/// The body of C `zap_modalias_env()`: drop every `MODALIAS=` variable from the environment block and close the gap in the buffer.
#[no_mangle]
pub unsafe extern "C" fn rust_zap_modalias_env(env: *mut c_void) {
    const PREFIX: &[u8; 9] = b"MODALIAS=";
    unsafe {
        let envp = (env as *mut u8).add(ENV_ENVP) as *mut *mut c_char;
        let envp_idx = (env as *mut u8).add(ENV_ENVP_IDX) as *mut c_int;
        let buflen = (env as *mut u8).add(ENV_BUFLEN) as *mut c_int;

        let mut i: c_int = 0;
        while i < *envp_idx {
            let e = *envp.add(i as usize);
            let mut is_prefix = true;
            for (k, p) in PREFIX.iter().enumerate() {
                let c = *e.add(k) as u8;
                if c != *p {
                    is_prefix = false;
                    break;
                }
            }
            if !is_prefix {
                i += 1;
                continue;
            }

            let len = (strlen(e) + 1) as isize;

            if i != *envp_idx - 1 {
                // the target block (everything after this variable) is moved backward by `len`
                let next = *envp.add(i as usize + 1);
                let n = (*buflen as isize).wrapping_sub(next.offset_from(*envp));
                core::ptr::copy(next, e, n as usize);

                let mut j = i;
                while j < *envp_idx - 1 {
                    *envp.add(j as usize) = (*envp.add(j as usize + 1)).offset(-len);
                    j += 1;
                }
            }

            *envp_idx -= 1;
            *buflen -= len as c_int;
        }
    }
}
