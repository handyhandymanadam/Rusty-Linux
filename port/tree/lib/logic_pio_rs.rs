// SPDX-License-Identifier: GPL-2.0-only

//! The logical PIO range registry -- the Rust behind `lib/logic_pio.c`.
//!
//! Ported from `lib/logic_pio.c` (6.18.49, HiSilicon): a list of I/O ranges, memory-mapped ones laid out back to back from logical address 0 and indirect ones above
//! `MMIO_UPPER_LIMIT`, with translation between hardware addresses and logical port numbers. Writers (`register`/`unregister`) take `io_range_mutex`; readers walk the list
//! under RCU. In C (`logic_pio_glue.c`): the exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition), the `BUILD_LOGIC_IO` accessors
//! (compiled only with `CONFIG_INDIRECT_PIO` and a `PCI_IOBASE`; they call the ops table), and one-line wrappers for what depends on the configuration: the mutex and the
//! list head, `list_add_tail_rcu`/`list_del_rcu`/`list_for_each_entry_rcu`, `rcu_read_lock`/`synchronize_rcu`, the limits (`MMIO_UPPER_LIMIT`, `IO_SPACE_LIMIT`) and the
//! `pr_err`/`pr_warn` sites (messages now name the glue file -- recorded divergence).
//!
//! Replaces: lib/logic_pio.c (all but the BUILD_LOGIC_IO accessors)

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr::null_mut;

const EINVAL: c_int = 22;
const EEXIST: c_int = 17;
const EFAULT: c_int = 14;
const E2BIG: c_int = 7;
const SZ_64K: u64 = 0x10000;
const LOGIC_PIO_INDIRECT: c_ulong = 0;
const LOGIC_PIO_CPU_MMIO: c_ulong = 1;

/// `struct list_head`.
#[repr(C)]
pub struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

/// `struct logic_pio_hwaddr` (checked by `logic_pio_glue.c`; `resource_size_t` is 64 bits there).
#[repr(C)]
pub struct HwAddr {
    list: ListHead,
    fwnode: *const c_void,
    hw_start: u64,
    io_start: u64,
    size: u64,
    flags: c_ulong,
    hostdata: *mut c_void,
    ops: *const c_void,
}

extern "C" {
    fn rust_lp_lock();
    fn rust_lp_unlock();
    fn rust_lp_head() -> *mut ListHead;
    fn rust_lp_next(p: *mut ListHead) -> *mut ListHead;
    fn rust_lp_add_tail_rcu(new: *mut ListHead);
    fn rust_lp_del_rcu(entry: *mut ListHead);
    fn rust_lp_synchronize_rcu();
    fn rust_lp_rcu_lock();
    fn rust_lp_rcu_unlock();
    fn rust_lp_mmio_upper_limit() -> u64;
    fn rust_lp_io_space_limit() -> u64;
    fn rust_lp_warn_too_big();
    fn rust_lp_err_token(pio: c_ulong);
    fn rust_lp_err_trans_hw();
    fn rust_lp_err_size(size: u64, range_size: u64);
    fn rust_lp_err_cpuaddr(addr: u64);
}

#[inline(always)]
unsafe fn entry(p: *mut ListHead) -> *mut HwAddr {
    // list_entry(): `list` is the first member
    p as *mut HwAddr
}

/// `in_range64(val, start, len)`
#[inline(always)]
fn in_range(val: u64, start: u64, len: u64) -> bool {
    val.wrapping_sub(start) < len
}

/// The body of C `logic_pio_register_range()`.
#[no_mangle]
pub unsafe extern "C" fn rust_logic_pio_register_range(new_range: *mut HwAddr) -> c_int {
    unsafe {
        if new_range.is_null() || (*new_range).fwnode.is_null() || (*new_range).size == 0 || ((*new_range).flags == LOGIC_PIO_INDIRECT && (*new_range).ops.is_null()) {
            return -EINVAL;
        }

        let start = (*new_range).hw_start;
        let end = (*new_range).hw_start.wrapping_add((*new_range).size);
        let mut mmio_end: u64 = 0;
        let mut iio_sz: u64 = rust_lp_mmio_upper_limit();
        let mmio_upper = iio_sz;
        let mut ret = 0;

        rust_lp_lock();
        'end_register: {
            let head = rust_lp_head();
            let mut p = rust_lp_next(head);
            while p != head {
                let range = entry(p);
                if (*range).fwnode == (*new_range).fwnode {
                    // range already there
                    ret = -EEXIST;
                    break 'end_register;
                }
                if (*range).flags == LOGIC_PIO_CPU_MMIO && (*new_range).flags == LOGIC_PIO_CPU_MMIO {
                    // for MMIO ranges we need to check for overlap
                    if start >= (*range).hw_start.wrapping_add((*range).size) || end < (*range).hw_start {
                        mmio_end = (*range).io_start.wrapping_add((*range).size);
                    } else {
                        ret = -EFAULT;
                        break 'end_register;
                    }
                } else if (*range).flags == LOGIC_PIO_INDIRECT && (*new_range).flags == LOGIC_PIO_INDIRECT {
                    iio_sz = iio_sz.wrapping_add((*range).size);
                }
                p = rust_lp_next(p);
            }

            // range not registered yet, check for available space
            if (*new_range).flags == LOGIC_PIO_CPU_MMIO {
                if mmio_end.wrapping_add((*new_range).size).wrapping_sub(1) > mmio_upper {
                    // if it's too big check if 64K space can be reserved
                    if mmio_end.wrapping_add(SZ_64K).wrapping_sub(1) > mmio_upper {
                        ret = -E2BIG;
                        break 'end_register;
                    }
                    (*new_range).size = SZ_64K;
                    rust_lp_warn_too_big();
                }
                (*new_range).io_start = mmio_end;
            } else if (*new_range).flags == LOGIC_PIO_INDIRECT {
                if iio_sz.wrapping_add((*new_range).size).wrapping_sub(1) > rust_lp_io_space_limit() {
                    ret = -E2BIG;
                    break 'end_register;
                }
                (*new_range).io_start = iio_sz;
            } else {
                // invalid flag
                ret = -EINVAL;
                break 'end_register;
            }

            rust_lp_add_tail_rcu(&raw mut (*new_range).list);
        }
        rust_lp_unlock();
        ret
    }
}

/// The body of C `logic_pio_unregister_range()`.
#[no_mangle]
pub unsafe extern "C" fn rust_logic_pio_unregister_range(range: *mut HwAddr) {
    unsafe {
        rust_lp_lock();
        rust_lp_del_rcu(&raw mut (*range).list);
        rust_lp_unlock();
        rust_lp_synchronize_rcu();
    }
}

/// The body of C `find_io_range_by_fwnode()`.
#[no_mangle]
pub unsafe extern "C" fn rust_find_io_range_by_fwnode(fwnode: *const c_void) -> *mut HwAddr {
    unsafe {
        let mut found: *mut HwAddr = null_mut();
        rust_lp_rcu_lock();
        let head = rust_lp_head();
        let mut p = rust_lp_next(head);
        while p != head {
            let range = entry(p);
            if (*range).fwnode == fwnode {
                found = range;
                break;
            }
            p = rust_lp_next(p);
        }
        rust_lp_rcu_unlock();
        found
    }
}

/// The body of C `find_io_range()` (static in C; the BUILD_LOGIC_IO accessors reach it through a thunk).
#[no_mangle]
pub unsafe extern "C" fn rust_find_io_range(pio: c_ulong) -> *mut HwAddr {
    unsafe {
        let mut found: *mut HwAddr = null_mut();
        rust_lp_rcu_lock();
        let head = rust_lp_head();
        let mut p = rust_lp_next(head);
        while p != head {
            let range = entry(p);
            if in_range(pio as u64, (*range).io_start, (*range).size) {
                found = range;
                break;
            }
            p = rust_lp_next(p);
        }
        rust_lp_rcu_unlock();

        if found.is_null() {
            rust_lp_err_token(pio);
        }
        found
    }
}

/// The body of C `logic_pio_to_hwaddr()`.
#[no_mangle]
pub unsafe extern "C" fn rust_logic_pio_to_hwaddr(pio: c_ulong) -> u64 {
    unsafe {
        let range = rust_find_io_range(pio);
        if !range.is_null() {
            return (*range).hw_start.wrapping_add(pio as u64).wrapping_sub((*range).io_start);
        }
        !0
    }
}

/// The body of C `logic_pio_trans_hwaddr()`.
#[no_mangle]
pub unsafe extern "C" fn rust_logic_pio_trans_hwaddr(fwnode: *const c_void, addr: u64, size: u64) -> c_ulong {
    unsafe {
        let range = rust_find_io_range_by_fwnode(fwnode);
        if range.is_null() || (*range).flags == LOGIC_PIO_CPU_MMIO {
            rust_lp_err_trans_hw();
            return !0;
        }
        if (*range).size < size {
            rust_lp_err_size(size, (*range).size);
            return !0;
        }
        addr.wrapping_sub((*range).hw_start).wrapping_add((*range).io_start) as c_ulong
    }
}

/// The body of C `logic_pio_trans_cpuaddr()`.
#[no_mangle]
pub unsafe extern "C" fn rust_logic_pio_trans_cpuaddr(addr: u64) -> c_ulong {
    unsafe {
        rust_lp_rcu_lock();
        let head = rust_lp_head();
        let mut p = rust_lp_next(head);
        while p != head {
            let range = entry(p);
            if (*range).flags == LOGIC_PIO_CPU_MMIO && in_range(addr, (*range).hw_start, (*range).size) {
                let cpuaddr = addr.wrapping_sub((*range).hw_start).wrapping_add((*range).io_start) as c_ulong;
                rust_lp_rcu_unlock();
                return cpuaddr;
            }
            p = rust_lp_next(p);
        }
        rust_lp_rcu_unlock();

        rust_lp_err_cpuaddr(addr);
        !0
    }
}
