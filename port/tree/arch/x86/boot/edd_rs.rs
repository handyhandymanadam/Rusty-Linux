// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/edd.c (16-bit real-mode setup, code16, -Zregparm=3): the BIOS Enhanced Disk Drive probe.
//! Exports `query_edd` (the C's only non-static function; main.c calls it when CONFIG_EDD[_MODULE] is set). The whole C file is inside
//! `#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)`, so in a configuration without EDD the C object is EMPTY (no section, no
//! symbol); the Makefile therefore swaps in this object only when CONFIG_EDD is set, and this file is empty-equivalent otherwise.
//!
//! Same sequence as the C: query_edd reads `edd=` (skipmbr/skip -> no MBR signatures, off -> nothing, on -> default) and `quiet`,
//! prints "Probing EDD (edd=off to disable)... " unless quiet, then for BIOS drives 0x80..0x90: get_edd_info (INT 13h AH=41h with BX=0x55AA,
//! AH=48h with SI -> ei->params, AH=08h with ES=0: legacy CHS) and, if EDD info was found and fewer than 6 are stored, copy the 82-byte
//! struct edd_info into boot_params.eddbuf; and (unless skipmbr) read_mbr_sig (INT 13h AX=0201h, CX=1, DL=drive, BX=buffer; the MBR is read
//! into a naturally aligned buffer on the heap starting at `_end`, which needs CAN_USE_HEAP and the buffer below heap_end_ptr) storing the
//! u32 at MBR+0x1b8 into edd_mbr_sig_buffer[] BEFORE the 0xAA55 magic check (a bad magic still leaves the signature stored but does not count
//! it), then prints "ok\n". Message strings are the C's, byte for byte. HAZARD (found by the QEMU EDD boot compare): LLVM rewrites `printf("ok\n")` into
//! `puts("ok")` (libc semantics: puts adds the newline), but the setup's puts() does NOT add one; the format pointers go through `black_box` so the call stays a printf.
//!
//! Structures (i386 layout, checked against the real header by the host rig): `struct edd_info` is 82 bytes: device 0, version 1, interface_support 2,
//! legacy_max_cylinder 4, legacy_max_head 6, legacy_sectors_per_track 7, params at 8 (length at 8, bytes_per_sector at 8+24); boot_params:
//! eddbuf_entries 0x1e9, edd_mbr_sig_buf_entries 0x1ea, edd_mbr_sig_buffer 0x290 (u32 x 16), eddbuf 0xd00 (6 x 82), hdr.loadflags 0x211,
//! hdr.heap_end_ptr 0x224, hdr.cmd_line_ptr 0x228.
//!
//! Faithful oddities (kept): the signature slot is written before the magic test; `mbrptr` advances only when do_mbr; the C's `ei` is not
//! re-initialised for read_mbr_sig when get_edd_info failed after its memset (bytes_per_sector = 0 -> sector size 512 guess); `be_quiet` is -1
//! (true) when cmd_line_ptr >= 1 MiB; buffer arithmetic is u32 (`(ds()<<4) + &_end`), alignment mask `~(sector_size-1)` (wrong for a non-power-of-two
//! sector size exactly as in the C); pointers/`size_t` are 32 bits on the target.
//!
//! TEST-GAP: see logs/realmode-edd.md (real BIOS drives: SeaBIOS only; EDD info of a CD/USB/RAID BIOS; the heap-too-small and no-CAN_USE_HEAP arms;
//! a BIOS that answers 0x48 differently; 0x80..0x8f drives beyond the first few are absent under QEMU).
#![allow(dead_code, static_mut_refs, unused_parens)]

#[path = "rm_common.rs"]
mod rm;

use core::ffi::{c_char, c_int};
use core::ptr::{addr_of, addr_of_mut};
use rm::*;

include!(concat!(env!("RM_GEN_DIR"), "/edd_gen.rs"));

const OFF_EDDBUF_ENTRIES: usize = 0x1e9; // C: offsetof(struct boot_params, eddbuf_entries)
const OFF_EDD_MBR_SIG_ENTRIES: usize = 0x1ea;
const OFF_EDD_MBR_SIG_BUFFER: usize = 0x290;
const OFF_EDDBUF: usize = 0xd00;
const OFF_LOADFLAGS: usize = 0x211;
const OFF_HEAP_END_PTR: usize = 0x224;
const OFF_CMD_LINE_PTR: usize = 0x228;
const SIZEOF_EDD_INFO: usize = 82;
const EI_DEVICE: usize = 0;
const EI_VERSION: usize = 1;
const EI_INTERFACE_SUPPORT: usize = 2;
const EI_LEGACY_MAX_CYLINDER: usize = 4;
const EI_LEGACY_MAX_HEAD: usize = 6;
const EI_LEGACY_SECTORS_PER_TRACK: usize = 7;
const EI_PARAMS: usize = 8;
const EI_PARAMS_LENGTH: usize = 8;
const EI_PARAMS_BYTES_PER_SECTOR: usize = 8 + 24;

static MSG_PROBING: &[u8] = b"Probing EDD (edd=off to disable)... \0";
static MSG_OK: &[u8] = b"ok\n\0";
static OPT_EDD: &[u8] = b"edd\0";
static OPT_QUIET: &[u8] = b"quiet\0";
static ARG_SKIPMBR: &[u8] = b"skipmbr\0";
static ARG_SKIP: &[u8] = b"skip\0";
static ARG_OFF: &[u8] = b"off\0";
static ARG_ON: &[u8] = b"on\0";

#[cfg(not(host_mock))]
extern "C" {
    fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn printf(fmt: *const c_char, ...) -> c_int;
}
#[cfg(host_mock)]
extern "C" {
    fn __cmdline_find_option(cmdline_ptr: u32, option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn printf(fmt: *const c_char, ...) -> c_int;
}
// memset()/memcpy() of the C are core::ptr::write_bytes / copy_nonoverlapping (LLVM lowers them to the same libcalls, defined by copy.S).
#[inline(always)]
unsafe fn memset(s: *mut u8, c: c_int, n: usize) {
    unsafe { core::ptr::write_bytes(s, c as u8, n) }
}
#[inline(always)]
unsafe fn memcpy(d: *mut u8, s: *const u8, n: usize) {
    unsafe { core::ptr::copy_nonoverlapping(s, d, n) }
}
extern "C" {
    static mut boot_params: [u8; 4096];
}
#[cfg(host_mock)]
extern "C" {
    fn mock_heap_limit(v: usize) -> usize;
}

#[inline(always)]
fn bp() -> *mut u8 {
    unsafe { addr_of_mut!(boot_params) as *mut u8 }
}
#[inline(always)]
unsafe fn rd8(off: usize) -> u8 {
    unsafe { bp().add(off).read() }
}
#[inline(always)]
unsafe fn rd16(off: usize) -> u16 {
    unsafe { (bp().add(off) as *const u16).read_unaligned() }
}
#[inline(always)]
unsafe fn rd32(off: usize) -> u32 {
    unsafe { (bp().add(off) as *const u32).read_unaligned() }
}
#[inline(always)]
unsafe fn wr8(off: usize, v: u8) {
    unsafe { bp().add(off).write(v) }
}
#[inline(always)]
unsafe fn wr32(off: usize, v: u32) {
    unsafe { (bp().add(off) as *mut u32).write_unaligned(v) }
}

/// boot.h `cmdline_find_option()`.
#[inline(always)]
unsafe fn cmdline_find_option(option: &[u8], buffer: *mut c_char, bufsize: c_int) -> c_int {
    unsafe {
        let cmd_line_ptr = rd32(OFF_CMD_LINE_PTR);
        if cmd_line_ptr >= 0x100000 {
            return -1; // inaccessible
        }
        __cmdline_find_option(cmd_line_ptr, option.as_ptr() as *const c_char, buffer, bufsize)
    }
}
/// boot.h `cmdline_find_option_bool()`.
#[inline(always)]
unsafe fn cmdline_find_option_bool(option: &[u8]) -> c_int {
    unsafe {
        let cmd_line_ptr = rd32(OFF_CMD_LINE_PTR);
        if cmd_line_ptr >= 0x100000 {
            return -1; // inaccessible
        }
        __cmdline_find_option_bool(cmd_line_ptr, option.as_ptr() as *const c_char)
    }
}

/// Read the MBR (first sector) from a specific device: `INT 13h AX=0201h CX=1 DL=devno BX=buf`; 0 or -1.
unsafe fn read_mbr(devno: u8, buf: *mut u8) -> c_int {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        ireg.set_ax(0x0201); // Legacy Read, one sector
        ireg.set_cx(0x0001); // Sector 0-0-1
        ireg.set_dl(devno);
        ireg.set_bx(buf as usize as u16);
        intcall(0x13, &ireg, oreg.as_mut_ptr());
        -((oreg.assume_init_ref().eflags & X86_EFLAGS_CF) as c_int) // 0 or -1
    }
}

unsafe fn read_mbr_sig(devno: u8, ei: *const u8, mbrsig: *mut u32) -> u32 {
    unsafe {
        let mut sector_size: c_int = (ei.add(EI_PARAMS_BYTES_PER_SECTOR) as *const u16).read_unaligned() as c_int;
        if sector_size == 0 {
            sector_size = 512; // Best available guess
        }
        // Produce a naturally aligned buffer on the heap
        let end = addr_of_mut!(_end);
        let buf_base: u32 = ((ds() as u32) << 4).wrapping_add(end as usize as u32);
        let ss = sector_size as u32;
        let mbr_base: u32 = buf_base.wrapping_add(ss).wrapping_sub(1) & !(ss.wrapping_sub(1));
        let mbrbuf_ptr: *mut u8 = (end as usize).wrapping_add(mbr_base.wrapping_sub(buf_base) as usize) as *mut u8;
        let mbrbuf_end: usize = (mbrbuf_ptr as usize).wrapping_add(sector_size as usize);

        // Make sure we actually have space on the heap...
        if rd8(OFF_LOADFLAGS) & RM_CAN_USE_HEAP == 0 {
            return u32::MAX; // -1
        }
        #[cfg(not(host_mock))]
        let heap_limit = rd16(OFF_HEAP_END_PTR) as usize;
        #[cfg(host_mock)]
        let heap_limit = mock_heap_limit(rd16(OFF_HEAP_END_PTR) as usize); // host only: see rig/realmode/run-edd-diff.sh
        if mbrbuf_end > heap_limit {
            return u32::MAX;
        }

        memset(mbrbuf_ptr, 0, sector_size as usize);
        if read_mbr(devno, mbrbuf_ptr) != 0 {
            return u32::MAX;
        }

        *mbrsig = (mbrbuf_ptr.add(RM_EDD_MBR_SIG_OFFSET) as *const u32).read_unaligned();
        let mbr_magic: u16 = (mbrbuf_ptr.add(510) as *const u16).read_unaligned();

        // check for valid MBR magic
        if mbr_magic == 0xAA55 { 0 } else { u32::MAX }
    }
}

unsafe fn get_edd_info(devno: u8, ei: *mut u8) -> c_int {
    unsafe {
        memset(ei, 0, SIZEOF_EDD_INFO);

        // Check Extensions Present
        let mut ireg = new_regs();
        let mut oreg = out_regs();
        ireg.set_ah(0x41);
        ireg.set_bx(RM_EDDMAGIC1);
        ireg.set_dl(devno);
        intcall(0x13, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        if o.eflags & X86_EFLAGS_CF != 0 {
            return -1; // No extended information
        }
        if o.bx() != RM_EDDMAGIC2 {
            return -1;
        }

        ei.add(EI_DEVICE).write(devno);
        ei.add(EI_VERSION).write(o.ah()); // EDD version number
        (ei.add(EI_INTERFACE_SUPPORT) as *mut u16).write_unaligned(o.cx()); // EDD functionality subsets

        // Extended Get Device Parameters
        (ei.add(EI_PARAMS_LENGTH) as *mut u16).write_unaligned(RM_EDDPARMSIZE);
        ireg.set_ah(0x48);
        ireg.set_si(ei.add(EI_PARAMS) as usize as u16);
        intcall(0x13, &ireg, oreg.as_mut_ptr());

        // Get legacy CHS parameters
        // Ralf Brown recommends setting ES:DI to 0:0
        ireg.set_ah(0x08);
        ireg.es = 0;
        intcall(0x13, &ireg, oreg.as_mut_ptr());
        let o = oreg.assume_init_ref();

        if o.eflags & X86_EFLAGS_CF == 0 {
            let cyl = (o.ch() as c_int + (((o.cl() & 0xc0) as c_int) << 2)) as u16;
            (ei.add(EI_LEGACY_MAX_CYLINDER) as *mut u16).write_unaligned(cyl);
            ei.add(EI_LEGACY_MAX_HEAD).write(o.dh());
            ei.add(EI_LEGACY_SECTORS_PER_TRACK).write(o.cl() & 0x3f);
        }
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn query_edd() {
    unsafe {
        // C: `char eddarg[8]; struct edd_info ei;` both uninitialised (eddarg is NUL-terminated by cmdline_find_option when it
        // returns > 0, which is the only case it is read; ei is memset by the first get_edd_info before any use).
        let mut eddarg = core::mem::MaybeUninit::<[u8; 8]>::uninit();
        let mut ei = core::mem::MaybeUninit::<[u8; SIZEOF_EDD_INFO]>::uninit();
        let mut do_mbr = true;
        let mut do_edd = !RM_EDD_OFF;

        if cmdline_find_option(OPT_EDD, eddarg.as_mut_ptr() as *mut c_char, 8) > 0 {
            let a = eddarg.as_ptr() as *const c_char;
            if strcmp(a, ARG_SKIPMBR.as_ptr() as *const c_char) == 0 || strcmp(a, ARG_SKIP.as_ptr() as *const c_char) == 0 {
                do_edd = true;
                do_mbr = false;
            } else if strcmp(a, ARG_OFF.as_ptr() as *const c_char) == 0 {
                do_edd = false;
            } else if strcmp(a, ARG_ON.as_ptr() as *const c_char) == 0 {
                do_edd = true;
            }
        }

        let be_quiet = cmdline_find_option_bool(OPT_QUIET);

        let mut edp = bp().add(OFF_EDDBUF);
        let mut mbrptr = bp().add(OFF_EDD_MBR_SIG_BUFFER) as *mut u32;

        if !do_edd {
            return;
        }

        // Bugs in OnBoard or AddOnCards Bios may hang the EDD probe, so give a hint if this happens.
        if be_quiet == 0 {
            printf(core::hint::black_box(MSG_PROBING.as_ptr()) as *const c_char);
        }

        let mut devno: c_int = 0x80;
        while devno < 0x80 + RM_EDD_MBR_SIG_MAX as c_int {
            // Scan the BIOS-supported hard disks and query EDD information...
            if get_edd_info(devno as u8, ei.as_mut_ptr() as *mut u8) == 0 && rd8(OFF_EDDBUF_ENTRIES) < RM_EDDMAXNR {
                memcpy(edp, ei.as_ptr() as *const u8, SIZEOF_EDD_INFO);
                edp = edp.add(SIZEOF_EDD_INFO);
                wr8(OFF_EDDBUF_ENTRIES, rd8(OFF_EDDBUF_ENTRIES).wrapping_add(1));
            }

            if do_mbr {
                let slot = mbrptr;
                mbrptr = mbrptr.add(1);
                if read_mbr_sig(devno as u8, ei.as_ptr() as *const u8, slot) == 0 {
                    wr8(OFF_EDD_MBR_SIG_ENTRIES, (devno - 0x80 + 1) as u8);
                }
            }
            devno += 1;
        }

        if be_quiet == 0 {
            printf(core::hint::black_box(MSG_OK.as_ptr()) as *const c_char);
        }
    }
}
