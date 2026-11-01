// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/cpu.c (16-bit real-mode setup): abort the boot with a message
//! if the CPU lacks obligatory features. Exports `validate_cpu()` like the C (0 = ok, -1 = refuse).
//!
//! Messages are byte-identical to the C: "This kernel requires an %s CPU, " / "but only detected
//! an %s CPU.\n" (cpu name "x86-64", or "i%d86" with level 15 shown as 6), "This kernel requires
//! the following features not present on the CPU:\n", then one word per missing feature (its
//! name from `x86_cap_strs`, or "%d:%d " for a bit with no name) and a final '\n'.
//!
//! `x86_cap_strs` is the SAME table the C walks: the C compiler's image of cpustr.h (written by
//! the hostprog mkcpustr from cpufeatures.h and the REQUIRED_MASKs) is turned into cpustr.bin by
//! the Makefile (cpustr_blob.o -> objcopy) and include_bytes!'d here. Table format: entries
//! `word, bit, NUL-terminated name`, sorted, only for REQUIRED bits, the last entry (word 21,
//! bit 31) unconditional with its terminating NUL. `show_cap_strs` is the C's pointer walk,
//! unchanged (a single skip per (word, bit) position, which relies on that sorted order and on the
//! unconditional last entry for termination: checked exhaustively and with Z3, see
//! logs/realmode-cpu.md).
//!
//! Deliberate divergences from the C: none in behaviour. `check_cpu`, `check_knl_erratum`
//! (cpucheck_rs.rs) are called through extern "C". Under `--cfg host_mock` (host tests only)
//! printf/puts/putchar go to mock_* hooks and the table is read from the file RM_GEN_DIR names.
//!
//! TEST-GAP: a CPU that lacks a feature with no name in the table ("%d:%d " fallback) cannot be
//! made with QEMU's CPU models for the shipped masks (every required bit has a name); that arm is
//! covered only by the host walker tests (all 22x32 single bits, random multi-bit words).
#![allow(dead_code, non_upper_case_globals)]

use core::ffi::{c_char, c_int};

extern "C" {
    #[cfg_attr(host_mock, link_name = "mock_printf")]
    fn printf(fmt: *const c_char, ...) -> c_int;
    #[cfg_attr(host_mock, link_name = "mock_sprintf")]
    fn sprintf(buf: *mut c_char, fmt: *const c_char, ...) -> c_int;
    #[cfg_attr(host_mock, link_name = "mock_puts")]
    fn puts(s: *const c_char);
    #[cfg_attr(host_mock, link_name = "mock_putchar")]
    fn putchar(c: c_int);
    /// cpucheck(_rs).rs
    fn check_cpu(cpu_level_ptr: *mut c_int, req_level_ptr: *mut c_int, err_flags_ptr: *mut *mut u32) -> c_int;
    fn check_knl_erratum() -> c_int;
}

include!(concat!(env!("RM_GEN_DIR"), "/cpucheck_gen.rs")); // NCAPINTS (and the rest, unused here)

/// `static const char x86_cap_strs[]` of cpustr.h, byte for byte (include_bytes of cpustr.bin).
static x86_cap_strs: [u8; include_bytes!(concat!(env!("RM_GEN_DIR"), "/cpustr.bin")).len()] =
    *include_bytes!(concat!(env!("RM_GEN_DIR"), "/cpustr.bin"));

/// `static char buf[6];` (plain .bss)
#[link_section = ".bss"]
static mut buf: [u8; 6] = [0; 6];

unsafe fn cpu_name(level: c_int) -> *const c_char {
    unsafe {
        if level == 64 {
            b"x86-64\0".as_ptr() as *const c_char
        } else {
            let level = if level == 15 { 6 } else { level };
            let b = core::ptr::addr_of_mut!(buf) as *mut c_char;
            sprintf(b, b"i%d86\0".as_ptr() as *const c_char, level);
            b
        }
    }
}

/// The C's walk of `x86_cap_strs` for the RM_NCAPINTS words of `err_flags`.
unsafe fn show_cap_strs(err_flags: *const u32) {
    unsafe {
        let mut msg_strs: *const u8 = x86_cap_strs.as_ptr();
        let mut i: c_int = 0;
        while i < RM_NCAPINTS as c_int {
            let mut e: u32 = *err_flags.add(i as usize);
            let mut j: c_int = 0;
            while j < 32 {
                if (*msg_strs as c_int) < i || (*msg_strs as c_int == i && (*msg_strs.add(1) as c_int) < j) {
                    // Skip to the next string
                    msg_strs = msg_strs.add(2);
                    loop {
                        let c = *msg_strs;
                        msg_strs = msg_strs.add(1);
                        if c == 0 {
                            break;
                        }
                    }
                }
                if e & 1 != 0 {
                    if *msg_strs as c_int == i && *msg_strs.add(1) as c_int == j && *msg_strs.add(2) != 0 {
                        printf(b"%s \0".as_ptr() as *const c_char, msg_strs.add(2));
                    } else {
                        printf(b"%d:%d \0".as_ptr() as *const c_char, i, j);
                    }
                }
                e >>= 1;
                j += 1;
            }
            i += 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn validate_cpu() -> c_int {
    unsafe {
        // like the C's uninitialised locals: check_cpu() stores all three (none of its pointers is NULL)
        let mut err_flags = core::mem::MaybeUninit::<*mut u32>::uninit();
        let mut cpu_level = core::mem::MaybeUninit::<c_int>::uninit();
        let mut req_level = core::mem::MaybeUninit::<c_int>::uninit();

        check_cpu(cpu_level.as_mut_ptr(), req_level.as_mut_ptr(), err_flags.as_mut_ptr());
        let (err_flags, cpu_level, req_level) =
            (err_flags.assume_init(), cpu_level.assume_init(), req_level.assume_init());

        if cpu_level < req_level {
            printf(b"This kernel requires an %s CPU, \0".as_ptr() as *const c_char, cpu_name(req_level));
            printf(b"but only detected an %s CPU.\n\0".as_ptr() as *const c_char, cpu_name(cpu_level));
            return -1;
        }

        if !err_flags.is_null() {
            puts(b"This kernel requires the following features not present on the CPU:\n\0".as_ptr() as *const c_char);
            show_cap_strs(err_flags);
            putchar(b'\n' as c_int);
            -1
        } else if check_knl_erratum() != 0 {
            -1
        } else {
            0
        }
    }
}

/// Host-test hook (never in the target build): the walker alone, for an arbitrary `err_flags`.
#[cfg(host_mock)]
#[no_mangle]
pub unsafe extern "C" fn rs_show_cap_strs(err_flags: *const u32) {
    unsafe { show_cap_strs(err_flags) }
}
