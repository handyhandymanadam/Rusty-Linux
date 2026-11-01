// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/efi.c (early access to the EFI configuration table).
//!
//! Built for the 64-bit stub only: `IS_ENABLED(CONFIG_X86_64)` is true and the `#ifndef CONFIG_X86_64`
//! arms of the C are not ported (one comment marks each). `debug_putstr()` is `__putstr()` only with
//! CONFIG_X86_VERBOSE_BOOTUP, which the Makefile passes as `--cfg=verbose_bootup`; otherwise it is a
//! no-op, as in misc.h. Text of every message is the C's. Same four exported symbols, same C ABI.
//!
//! `struct boot_params` is not mirrored whole (4096 bytes, mostly irrelevant here): only the two
//! places this file reads are addressed, by offsets asserted below against the uapi header.

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr;

/// efi_guid_t: 16 bytes, aligned 4 (passed by value to efi_find_vendor_table(), as in the C).
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EfiGuid([u8; 16]);

/// `struct efi_info` (arch/x86/include/uapi/asm/bootparam.h).
#[repr(C)]
#[allow(dead_code)]
struct EfiInfo {
    efi_loader_signature: u32,
    efi_systab: u32,
    efi_memdesc_size: u32,
    efi_memdesc_version: u32,
    efi_memmap: u32,
    efi_memmap_size: u32,
    efi_systab_hi: u32,
    efi_memmap_hi: u32,
}

/// `struct setup_data` (arch/x86/include/uapi/asm/setup_data.h), without the flexible `data[]`.
#[repr(C)]
#[allow(dead_code)]
struct SetupData {
    next: u64,
    type_: u32,
    len: u32,
}

/// `struct efi_setup_data` (arch/x86/include/asm/setup_data.h).
#[repr(C)]
#[allow(dead_code)]
struct EfiSetupData {
    fw_vendor: u64,
    unused: u64,
    tables: u64,
    smbios: u64,
    reserved: [u64; 8],
}

/// `efi_table_hdr_t` (include/linux/efi.h).
#[repr(C)]
#[allow(dead_code)]
struct EfiTableHdr {
    signature: u64,
    revision: u32,
    headersize: u32,
    crc32: u32,
    reserved: u32,
}

/// `efi_system_table_64_t` (include/linux/efi.h).
#[repr(C)]
#[allow(dead_code)]
struct EfiSystemTable64 {
    hdr: EfiTableHdr,
    fw_vendor: u64,
    fw_revision: u32,
    pad1: u32,
    con_in_handle: u64,
    con_in: u64,
    con_out_handle: u64,
    con_out: u64,
    stderr_handle: u64,
    stderr: u64,
    runtime: u64,
    boottime: u64,
    nr_tables: u32,
    pad2: u32,
    tables: u64,
}

/// `efi_system_table_32_t` (include/linux/efi.h).
#[repr(C)]
#[allow(dead_code)]
struct EfiSystemTable32 {
    hdr: EfiTableHdr,
    fw_vendor: u32,
    fw_revision: u32,
    con_in_handle: u32,
    con_in: u32,
    con_out_handle: u32,
    con_out: u32,
    stderr_handle: u32,
    stderr: u32,
    runtime: u32,
    boottime: u32,
    nr_tables: u32,
    tables: u32,
}

/// `efi_config_table_64_t` (include/linux/efi.h); 24 bytes, align 8, guid is align 4.
#[repr(C)]
struct EfiConfigTable64 {
    guid: EfiGuid,
    table: u64,
}

/// `efi_config_table_32_t` (include/linux/efi.h); 20 bytes, align 4.
#[repr(C)]
struct EfiConfigTable32 {
    guid: EfiGuid,
    table: u32,
}

// Sizes and offsets of the uapi/boot_params ones were checked with a userspace C program that
// includes the real uapi <asm/bootparam.h> (boot_params 4096, efi_info at 448 size 32, efi_systab_hi at
// 24, hdr at 497, setup_header.setup_data at 95, setup_data 16 with type at 8). efi_setup_data and
// the efi.h types are in non-uapi headers: the C program used transcriptions of the header text (same
// field lists), the compiler's numbers matched my hand derivation: efi_setup_data 96 / tables 16;
// config64 24 / table 16 / align 8; config32 20 / table 16; hdr 24; systab64 120 / nr_tables 104 /
// tables 112; systab32 72 / nr_tables 64 / tables 68.
const _: () = assert!(core::mem::size_of::<EfiGuid>() == 16 && core::mem::align_of::<EfiGuid>() == 4);
const _: () = assert!(core::mem::size_of::<EfiInfo>() == 32);
const _: () = assert!(core::mem::offset_of!(EfiInfo, efi_systab) == 4);
const _: () = assert!(core::mem::offset_of!(EfiInfo, efi_systab_hi) == 24);
const _: () = assert!(core::mem::size_of::<SetupData>() == 16);
const _: () = assert!(core::mem::offset_of!(SetupData, next) == 0);
const _: () = assert!(core::mem::offset_of!(SetupData, type_) == 8);
const _: () = assert!(core::mem::size_of::<EfiSetupData>() == 96);
const _: () = assert!(core::mem::offset_of!(EfiSetupData, tables) == 16);
const _: () = assert!(core::mem::size_of::<EfiTableHdr>() == 24);
const _: () = assert!(core::mem::size_of::<EfiSystemTable64>() == 120);
const _: () = assert!(core::mem::offset_of!(EfiSystemTable64, nr_tables) == 104);
const _: () = assert!(core::mem::offset_of!(EfiSystemTable64, tables) == 112);
const _: () = assert!(core::mem::size_of::<EfiSystemTable32>() == 72);
const _: () = assert!(core::mem::offset_of!(EfiSystemTable32, nr_tables) == 64);
const _: () = assert!(core::mem::offset_of!(EfiSystemTable32, tables) == 68);
const _: () = assert!(core::mem::size_of::<EfiConfigTable64>() == 24);
const _: () = assert!(core::mem::align_of::<EfiConfigTable64>() == 8);
const _: () = assert!(core::mem::offset_of!(EfiConfigTable64, table) == 16);
const _: () = assert!(core::mem::size_of::<EfiConfigTable32>() == 20);
const _: () = assert!(core::mem::offset_of!(EfiConfigTable32, table) == 16);

/// Offset of `efi_info` in `struct boot_params` (0x1c0, bootparam.h comment; C program: 448).
const BP_EFI_INFO: usize = 448;
/// Offset of `hdr.setup_data` in `struct boot_params` (hdr at 497 + 95 in setup_header = 592; C program).
const BP_HDR_SETUP_DATA: usize = 592;
const _: () = assert!(BP_HDR_SETUP_DATA == 497 + 95);

/// `enum efi_type` of compressed/misc.h: EFI_TYPE_64 = 0, EFI_TYPE_32 = 1, EFI_TYPE_NONE = 2.
const EFI_TYPE_64: c_int = 0;
const EFI_TYPE_32: c_int = 1;
const EFI_TYPE_NONE: c_int = 2;

/// SETUP_EFI of uapi/asm/setup_data.h.
const SETUP_EFI: u32 = 4;
const EINVAL: c_int = 22;

extern "C" {
    /// misc.c; the target of debug_putstr() when CONFIG_X86_VERBOSE_BOOTUP is set.
    #[cfg(verbose_bootup)]
    fn __putstr(s: *const core::ffi::c_char);
}

/// `debug_putstr()`: `__putstr()` with CONFIG_X86_VERBOSE_BOOTUP, nothing otherwise.
macro_rules! debug_putstr {
    ($s:expr) => {
        #[cfg(verbose_bootup)]
        {
            // SAFETY: __putstr() takes a NUL-terminated string; C"..." literals are.
            #[allow(unused_unsafe)]
            unsafe { __putstr($s.as_ptr()) };
        }
    };
}

/// `enum efi_type efi_get_type(struct boot_params *bp)`
#[no_mangle]
pub unsafe extern "C" fn efi_get_type(bp: *mut c_void) -> c_int {
    // SAFETY: bp is the boot_params pointer the caller holds; efi_info lies inside the 4096 bytes.
    let ei = unsafe { (bp as *mut u8).add(BP_EFI_INFO) } as *const EfiInfo;
    // SAFETY: as above; efi_loader_signature is the first field.
    let sig: [u8; 4] = unsafe { ptr::addr_of!((*ei).efi_loader_signature).cast::<[u8; 4]>().read_unaligned() };

    // strncmp(sig, "EL64", 4) == 0: "EL64"/"EL32" contain no NUL in their first 4 bytes, so strncmp's
    // stop-at-NUL never triggers before byte 4 matches and the test is a plain 4-byte equality.
    let sig = u32::from_ne_bytes(sig);
    if sig == u32::from_ne_bytes(*b"EL64") {
        EFI_TYPE_64
    } else if sig == u32::from_ne_bytes(*b"EL32") {
        EFI_TYPE_32
    } else {
        debug_putstr!(c"No EFI environment detected.\n");
        // Dead arm: `#ifndef CONFIG_X86_64` "EFI system table is located above 4GB" check, not ported.
        EFI_TYPE_NONE
    }
}

/// `unsigned long efi_get_system_table(struct boot_params *bp)`
#[no_mangle]
pub unsafe extern "C" fn efi_get_system_table(bp: *mut c_void) -> c_ulong {
    // SAFETY: as in efi_get_type().
    let ei = unsafe { (bp as *mut u8).add(BP_EFI_INFO) } as *const EfiInfo;
    // Dead arm: the `#else sys_tbl_pa = ei->efi_systab;` of !CONFIG_X86_64 is not ported.
    // SAFETY: ei points into boot_params.
    let sys_tbl_pa: u64 = unsafe { (*ei).efi_systab as u64 | (((*ei).efi_systab_hi as u64) << 32) };
    if sys_tbl_pa == 0 {
        debug_putstr!(c"EFI system table not found.");
        return 0;
    }

    sys_tbl_pa as c_ulong
}

/// kexec provides the initial physical address of the config table in a SETUP_EFI setup_data entry.
unsafe fn get_kexec_setup_data(bp: *mut c_void, _et: c_int) -> *const EfiSetupData {
    let mut esd: *const EfiSetupData = ptr::null();

    // SAFETY: the boot loader's setup_data list is physical addresses, identity mapped in the stub;
    // the field is inside boot_params.
    unsafe {
        let mut pa_data: u64 = (bp as *mut u8).add(BP_HDR_SETUP_DATA).cast::<u64>().read_unaligned();
        while pa_data != 0 {
            let data = pa_data as usize as *const SetupData;
            if ptr::addr_of!((*data).type_).read_unaligned() == SETUP_EFI {
                esd = (pa_data as usize + core::mem::size_of::<SetupData>()) as *const EfiSetupData;
                break;
            }

            pa_data = ptr::addr_of!((*data).next).read_unaligned();
        }

        if !esd.is_null() && ptr::addr_of!((*esd).tables).read_unaligned() == 0 {
            debug_putstr!(c"kexec EFI environment missing valid configuration table.\n");
            return ptr::null();
        }
    }

    esd
}

/// `int efi_get_conf_table(struct boot_params *bp, unsigned long *cfg_tbl_pa, unsigned int *cfg_tbl_len)`
#[no_mangle]
pub unsafe extern "C" fn efi_get_conf_table(bp: *mut c_void, cfg_tbl_pa: *mut c_ulong, cfg_tbl_len: *mut c_uint) -> c_int {
    if cfg_tbl_pa.is_null() || cfg_tbl_len.is_null() {
        return -EINVAL;
    }

    // SAFETY: bp is the caller's boot_params.
    let sys_tbl_pa = unsafe { efi_get_system_table(bp) };
    if sys_tbl_pa == 0 {
        return -EINVAL;
    }

    // Handle EFI bitness properly
    // SAFETY: as above.
    let et = unsafe { efi_get_type(bp) };
    if et == EFI_TYPE_64 {
        let stbl = sys_tbl_pa as *const EfiSystemTable64;

        // kexec provides an alternative EFI conf table, check for it.
        // SAFETY: bp as above.
        let esd = unsafe { get_kexec_setup_data(bp, et) };

        // SAFETY: stbl is the firmware's system table (physical address, identity mapped); the
        // out-pointers were checked non-null and belong to the caller.
        unsafe {
            *cfg_tbl_pa = if !esd.is_null() {
                ptr::addr_of!((*esd).tables).read_unaligned() as c_ulong
            } else {
                ptr::addr_of!((*stbl).tables).read_unaligned() as c_ulong
            };
            *cfg_tbl_len = ptr::addr_of!((*stbl).nr_tables).read_unaligned();
        }
    } else if et == EFI_TYPE_32 {
        let stbl = sys_tbl_pa as *const EfiSystemTable32;

        // SAFETY: as above.
        unsafe {
            *cfg_tbl_pa = ptr::addr_of!((*stbl).tables).read_unaligned() as c_ulong;
            *cfg_tbl_len = ptr::addr_of!((*stbl).nr_tables).read_unaligned();
        }
    } else {
        return -EINVAL;
    }

    0
}

/// Get vendor table address/guid from EFI config table at the given index.
unsafe fn get_vendor_table(
    cfg_tbl: *const c_void,
    idx: c_uint,
    vendor_tbl_pa: &mut c_ulong,
    vendor_tbl_guid: &mut EfiGuid,
    et: c_int,
) -> c_int {
    if et == EFI_TYPE_64 {
        let tbl_entry = (cfg_tbl as *const EfiConfigTable64).wrapping_add(idx as usize);

        // Dead arm: `!IS_ENABLED(CONFIG_X86_64) && table >> 32` ("located above 4GB") is never true here.
        // SAFETY: the firmware's config table has at least cfg_tbl_len entries (caller's contract).
        unsafe {
            *vendor_tbl_pa = ptr::addr_of!((*tbl_entry).table).read_unaligned() as c_ulong;
            *vendor_tbl_guid = ptr::addr_of!((*tbl_entry).guid).read_unaligned();
        }
    } else if et == EFI_TYPE_32 {
        let tbl_entry = (cfg_tbl as *const EfiConfigTable32).wrapping_add(idx as usize);

        // SAFETY: as above.
        unsafe {
            *vendor_tbl_pa = ptr::addr_of!((*tbl_entry).table).read_unaligned() as c_ulong;
            *vendor_tbl_guid = ptr::addr_of!((*tbl_entry).guid).read_unaligned();
        }
    } else {
        return -EINVAL;
    }

    0
}

/// `efi_guidcmp(a, b) == 0`: the C is memcmp() of 16 bytes; four u32 compares give the same equality
/// without risking a call to memcmp/bcmp from the optimiser.
fn guid_equal(a: &EfiGuid, b: &EfiGuid) -> bool {
    let pa = a as *const EfiGuid as *const u32;
    let pb = b as *const EfiGuid as *const u32;
    // SAFETY: EfiGuid is 16 bytes, align 4: four in-bounds aligned u32 reads each.
    unsafe {
        pa.read() == pb.read()
            && pa.add(1).read() == pb.add(1).read()
            && pa.add(2).read() == pb.add(2).read()
            && pa.add(3).read() == pb.add(3).read()
    }
}

/// `unsigned long efi_find_vendor_table(struct boot_params *bp, unsigned long cfg_tbl_pa,
///                                      unsigned int cfg_tbl_len, efi_guid_t guid)`
#[no_mangle]
pub unsafe extern "C" fn efi_find_vendor_table(bp: *mut c_void, cfg_tbl_pa: c_ulong, cfg_tbl_len: c_uint, guid: EfiGuid) -> c_ulong {
    // SAFETY: as in the other entry points.
    let et = unsafe { efi_get_type(bp) };
    if et == EFI_TYPE_NONE {
        return 0;
    }

    let mut i: c_uint = 0;
    while i < cfg_tbl_len {
        let mut vendor_tbl_pa: c_ulong = 0;
        let mut vendor_tbl_guid = EfiGuid([0; 16]);

        // SAFETY: cfg_tbl_pa is the firmware config table address obtained from efi_get_conf_table().
        let ret = unsafe { get_vendor_table(cfg_tbl_pa as usize as *const c_void, i, &mut vendor_tbl_pa, &mut vendor_tbl_guid, et) };
        if ret != 0 {
            return 0;
        }

        if guid_equal(&guid, &vendor_tbl_guid) {
            return vendor_tbl_pa;
        }
        i += 1;
    }

    0
}
