// SPDX-License-Identifier: GPL-2.0-only

//! System-info dump on demand -- the Rust behind `lib/sys_info.c`.
//!
//! Replaces: lib/sys_info.c
//!
//! None of the three functions here carry `EXPORT_SYMBOL`; all are called
//! from within the kernel image itself (panic/oops paths and a sysctl
//! table), so no ABI contract macro applies.
//!
//! Every mask/bit value here is `c_ulong` (`unsigned long`), matching the
//! C's actual signatures (`sys_info_parse_param`'s return, `sys_info`'s
//! parameter, `sys_info_name.bit`) exactly -- not `c_uint`, even though
//! every individual `SYS_INFO_*` value happens to fit in 32 bits.
//!
//! # Four `static inline` callees, reproduced rather than called
//!
//! None of `show_state()`, `show_mem()`, `debug_show_all_locks()` or
//! `trigger_all_cpu_backtrace()` has a linkable symbol on this project's
//! configuration; each is reproduced from its header body instead:
//!
//! - `show_state()` = `show_state_filter(0)` (`sched/debug.h`).
//! - `show_mem()` = `__show_mem(0, NULL, MAX_NR_ZONES - 1)` (`mm.h`).
//!   `MAX_NR_ZONES` is `enum zone_type`'s variant count, and four of its six
//!   possible members are individually `#ifdef`-gated
//!   (`include/linux/mmzone.h`); [`max_zone_idx`] below counts present
//!   variants the same way, via the matching `#[cfg(...)]`s, rather than a
//!   literal that would silently go stale if the zone Kconfig set changes.
//! - `debug_show_all_locks()` is the `CONFIG_LOCKDEP` no-op arm on both of
//!   this project's configs (`CONFIG_LOCKDEP` is unset; the SMP-only debug
//!   symbol some configs also carry, `CONFIG_LOCKDEP_SUPPORT`, is a
//!   different thing entirely). Reproduced as a real `#[cfg(CONFIG_LOCKDEP)]`
//!   fork rather than collapsed, since -- unlike an architecture fact --
//!   this is a debug option a future config could plausibly turn on.
//! - `trigger_all_cpu_backtrace()` dispatches to
//!   `arch_trigger_cpumask_backtrace()`, which x86-64 always provides
//!   (`arch/x86/include/asm/irq.h`, not Kconfig-gated) -- the `#else` arm
//!   returning `false` is unreachable on this project's only target.
//!   `sys_info()` discards this function's `bool` return, so only the
//!   call's side effect matters here.
//!
//! # `CtlTable` mirrors only as much of `struct ctl_table` as this file touches
//!
//! `sysctl_sys_info_handler()` copies `*ro_table` by value and overwrites
//! two fields (`data`, `maxlen`) before forwarding to `proc_dostring()`. The
//! struct's other fields (a function pointer, two more pointers) are never
//! read or written here -- only copied through -- so they are declared with
//! their real types anyway (matching `pahole -C ctl_table`'s field order
//! and offsets exactly, checked by `rig/layout-check.sh`), which is no more
//! work than opaque bytes and keeps the mirror checkable.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

/// `SYS_INFO_*` bit flags -- `include/linux/sys_info.h`.
const SYS_INFO_TASKS: c_ulong = 0x0000_0001;
const SYS_INFO_MEM: c_ulong = 0x0000_0002;
const SYS_INFO_TIMERS: c_ulong = 0x0000_0004;
const SYS_INFO_LOCKS: c_ulong = 0x0000_0008;
const SYS_INFO_FTRACE: c_ulong = 0x0000_0010;
const SYS_INFO_ALL_CPU_BT: c_ulong = 0x0000_0040;
const SYS_INFO_BLOCKED_TASKS: c_ulong = 0x0000_0080;

/// `DUMP_ALL` -- `enum ftrace_dump_mode`, `include/linux/trace_printk.h`
/// (`DUMP_NONE` = 0, `DUMP_ALL` = 1, ...).
#[cfg(CONFIG_TRACING)]
const DUMP_ALL: c_int = 1;
/// `TASK_UNINTERRUPTIBLE` -- `include/linux/sched.h`.
const TASK_UNINTERRUPTIBLE: c_uint = 0x0000_0002;

/// `MAX_NR_ZONES - 1`: see the module doc comment.
const fn max_zone_idx() -> c_int {
    let mut n: c_int = 0;
    #[cfg(CONFIG_ZONE_DMA)]
    {
        n += 1;
    }
    #[cfg(CONFIG_ZONE_DMA32)]
    {
        n += 1;
    }
    n += 1; // ZONE_NORMAL, unconditional
    #[cfg(CONFIG_HIGHMEM)]
    {
        n += 1;
    }
    n += 1; // ZONE_MOVABLE, unconditional
    #[cfg(CONFIG_ZONE_DEVICE)]
    {
        n += 1;
    }
    n - 1
}

extern "C" {
    fn strsep(s: *mut *mut c_char, ct: *const c_char) -> *mut c_char;

    fn show_state_filter(state_filter: c_uint);
    fn __show_mem(filter: c_uint, nodemask: *mut c_void, max_zone_idx: c_int);
    #[cfg(CONFIG_TRACING)]
    fn ftrace_dump(mode: c_int);
    fn sysrq_timer_list_show();
    #[cfg(CONFIG_LOCKDEP)]
    fn debug_show_all_locks();

    /// x86's real, always-present backtrace-IPI primitive -- see the
    /// module doc comment on why `trigger_all_cpu_backtrace()` itself
    /// (header-only, `static inline`) is reproduced instead of called.
    fn arch_trigger_cpumask_backtrace(mask: *const c_void, exclude_cpu: c_int);
    /// `cpu_online_mask` is `(const struct cpumask *)&__cpu_online_mask`.
    static __cpu_online_mask: c_void;

    fn proc_dostring(
        table: *const CtlTable,
        write: c_int,
        buffer: *mut c_void,
        lenp: *mut usize,
        ppos: *mut c_long,
    ) -> c_int;
}

/// Mirrors `struct ctl_table` (`include/linux/sysctl.h`).
/// See the module doc comment for why every field is here.
#[repr(C)]
pub struct CtlTable {
    procname: *const c_char,
    data: *mut c_void,
    maxlen: c_int,
    mode: u16,
    proc_handler: *const c_void,
    poll: *const c_void,
    extra1: *mut c_void,
    extra2: *mut c_void,
}

struct SysInfoName {
    bit: c_ulong,
    name: &'static [u8], // NUL-terminated, no embedded NUL
}

const SI_NAMES: [SysInfoName; 7] = [
    SysInfoName { bit: SYS_INFO_TASKS, name: b"tasks\0" },
    SysInfoName { bit: SYS_INFO_MEM, name: b"mem\0" },
    SysInfoName { bit: SYS_INFO_TIMERS, name: b"timers\0" },
    SysInfoName { bit: SYS_INFO_LOCKS, name: b"locks\0" },
    SysInfoName { bit: SYS_INFO_FTRACE, name: b"ftrace\0" },
    SysInfoName { bit: SYS_INFO_ALL_CPU_BT, name: b"all_bt\0" },
    SysInfoName { bit: SYS_INFO_BLOCKED_TASKS, name: b"blocked_tasks\0" },
];

/// `sizeof(sys_info_avail)`: every name joined by commas, plus the
/// terminating NUL. "tasks,mem,timers,locks,ftrace,all_bt,blocked_tasks\0"
/// = 53 bytes.
const SYS_INFO_AVAIL_LEN: usize = 53;

/// `sys_info_parse_param()`: parse a comma-separated list of names from
/// `include/linux/sys_info.h`'s table into the matching bitmask.
///
/// # Safety
/// `str_` must be a valid, NUL-terminated, mutable C string (`strsep`
/// writes into it, exactly as the C does).
#[no_mangle]
pub unsafe extern "C" fn sys_info_parse_param(str_: *mut c_char) -> c_ulong {
    let mut si_bits: c_ulong = 0;
    let mut s: *mut c_char = str_;
    let sep = c",".as_ptr();

    loop {
        // SAFETY: `s` is valid per the caller's guarantee (first iteration)
        // or per `strsep`'s own contract (subsequent iterations): it
        // either advances `s` past a comma or sets it null at the end.
        let name = unsafe { strsep(&mut s, sep) };
        if name.is_null() {
            break;
        }
        // SAFETY: `strsep` returns a pointer into the caller's
        // NUL-terminated buffer.
        if unsafe { *name } == 0 {
            continue;
        }
        for si in &SI_NAMES {
            // SAFETY: `name` and `si.name` are both NUL-terminated.
            let matches = unsafe { c_strcmp_eq(name, si.name.as_ptr().cast()) };
            if matches {
                si_bits |= si.bit;
                break;
            }
        }
    }

    si_bits
}

/// Plain NUL-terminated byte comparison -- avoids pulling in `strcmp` for
/// one use, and both sides are guaranteed NUL-terminated (a static string
/// literal, and `strsep`'s output).
unsafe fn c_strcmp_eq(a: *const c_char, b: *const c_char) -> bool {
    let mut i = 0isize;
    loop {
        // SAFETY: both strings are NUL-terminated; the loop stops at the
        // first NUL in either, never reading past it.
        let (ca, cb) = unsafe { (*a.offset(i), *b.offset(i)) };
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i = i.wrapping_add(1);
    }
}

/// `sysctl_sys_info_handler()`.
///
/// # Safety
/// `ro_table` must be valid, and its `data` must point at a valid
/// `c_ulong` -- matching the C's `unsigned long *si_bits_global`.
#[allow(unused_assignments)]
#[no_mangle]
pub unsafe extern "C" fn sysctl_sys_info_handler(
    ro_table: *const CtlTable,
    write: c_int,
    buffer: *mut c_void,
    lenp: *mut usize,
    ppos: *mut c_long,
) -> c_int {
    let mut names = [0u8; SYS_INFO_AVAIL_LEN];
    // SAFETY: caller guarantees `ro_table` is valid.
    let si_bits_global = unsafe { (*ro_table).data } as *mut c_ulong;

    // SAFETY: caller guarantees `ro_table` is valid; this is a read of the
    // struct's value, matching the C's `table = *ro_table`.
    let mut table = unsafe { core::ptr::read(ro_table) };
    table.data = names.as_mut_ptr().cast();
    table.maxlen = SYS_INFO_AVAIL_LEN as c_int;

    if write != 0 {
        // SAFETY: `table` is a valid on-stack copy with `data`/`maxlen`
        // pointing at `names`, matching what `proc_dostring` expects to
        // write into.
        let ret = unsafe { proc_dostring(&table, write, buffer, lenp, ppos) };
        if ret != 0 {
            return ret;
        }
        // SAFETY: `names` is NUL-terminated by `proc_dostring` on success.
        let si_bits = unsafe { sys_info_parse_param(names.as_mut_ptr().cast()) };
        // WRITE_ONCE(): non-tearing, not otherwise synchronized -- same as
        // the C's own comment says.
        unsafe { core::ptr::write_volatile(si_bits_global, si_bits) };
        0
    } else {
        // SAFETY: reading the global mask; not otherwise synchronized,
        // same as the C (a plain read there, not even READ_ONCE).
        let bits = unsafe { *si_bits_global };
        let mut len = 0usize;
        let mut first = true;
        for si in &SI_NAMES {
            if bits & si.bit != 0 {
                if !first {
                    names[len] = b',';
                    len = len.wrapping_add(1);
                }
                first = false;
                // name includes its own NUL; copy all but that NUL.
                let n = si.name.len() - 1;
                names[len..len.wrapping_add(n)].copy_from_slice(&si.name[..n]);
                len = len.wrapping_add(n);
            }
        }
        names[len] = 0;
        // SAFETY: `table` is a valid on-stack copy with `data`/`maxlen`
        // pointing at the `names` buffer just filled in.
        unsafe { proc_dostring(&table, write, buffer, lenp, ppos) }
    }
}

/// `sys_info()`: dump whichever subsystems `si_mask` selects.
///
/// # Safety
/// None beyond ordinary control-flow -- every callee here takes no
/// arguments (or a plain value) and this function does not touch memory
/// directly.
#[no_mangle]
pub unsafe extern "C" fn sys_info(si_mask: c_ulong) {
    // SAFETY: each callee is a real, always-linked kernel function taking
    // no arguments (or a plain integer), called unconditionally on its own
    // bit -- exactly the C's sequence of independent `if` statements.
    unsafe {
        if si_mask & SYS_INFO_TASKS != 0 {
            show_state_filter(0); // show_state(), inlined
        }
        if si_mask & SYS_INFO_MEM != 0 {
            __show_mem(0, core::ptr::null_mut(), max_zone_idx()); // show_mem(), inlined
        }
        if si_mask & SYS_INFO_TIMERS != 0 {
            sysrq_timer_list_show();
        }
        if si_mask & SYS_INFO_LOCKS != 0 {
            #[cfg(CONFIG_LOCKDEP)]
            debug_show_all_locks();
            // #[cfg(not(CONFIG_LOCKDEP))]: the no-op arm -- nothing to call.
        }
        if si_mask & SYS_INFO_FTRACE != 0 {
            #[cfg(CONFIG_TRACING)]
            ftrace_dump(DUMP_ALL);
            // #[cfg(not(CONFIG_TRACING))]: ftrace_dump() inlines to a
            // no-op there too -- nothing to call.
        }
        if si_mask & SYS_INFO_ALL_CPU_BT != 0 {
            // trigger_all_cpu_backtrace(), inlined -- see the module doc
            // comment. Its own `bool` return is discarded by the C too.
            arch_trigger_cpumask_backtrace(core::ptr::addr_of!(__cpu_online_mask), -1);
        }
        if si_mask & SYS_INFO_BLOCKED_TASKS != 0 {
            show_state_filter(TASK_UNINTERRUPTIBLE);
        }
    }
}
