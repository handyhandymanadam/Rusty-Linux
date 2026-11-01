// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/acpi.c (find the RSDP; SRAT immovable regions for KASLR).
//!
//! Built for the 64-bit stub only (`acpi_physical_address` is u64). The Makefile passes, for the
//! switches the C file has: `--cfg=efi` (CONFIG_EFI), `--cfg=verbose_bootup` (CONFIG_X86_VERBOSE_BOOTUP,
//! which makes `debug_putstr()` a `__putstr()`; otherwise a no-op as in misc.h), `--cfg=hotremove_srat`
//! (CONFIG_RANDOMIZE_BASE && CONFIG_MEMORY_HOTREMOVE) and `--cfg=kexec_core` (CONFIG_KEXEC_CORE).
//! Text of every message is the C's. Same exported symbols, same C ABI.
//!
//! Everything here reads firmware / boot-loader memory at physical addresses that the stub has
//! identity mapped; all such reads are `read_unaligned` of mirrored `#[repr(C, packed)]` structs.

#[allow(unused_imports)]
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;

#[cfg(efi)]
use core::ffi::c_uint;

/// NODES_SHIFT of include/linux/numa.h: CONFIG_NODES_SHIFT if defined, else 0. The Makefile runs rustc
/// with the env var STUBF_NODES_SHIFT set to the number (empty when CONFIG_NODES_SHIFT is unset).
const NODES_SHIFT: u32 = parse_shift(option_env!("STUBF_NODES_SHIFT"));

/// Decimal parser for `NODES_SHIFT`; None or empty gives 0. A non-digit fails the build (const panic).
const fn parse_shift(s: Option<&str>) -> u32 {
    let b = match s {
        Some(s) => s.as_bytes(),
        None => return 0,
    };
    let mut v: u32 = 0;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i] >= b'0' && b[i] <= b'9');
        v = v * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    v
}

/// `MAX_NUMNODES` of include/linux/numa.h: `1 << NODES_SHIFT`.
const MAX_NUMNODES: usize = 1usize << NODES_SHIFT;

/// `struct mem_vector` (arch/x86/boot/compressed/misc.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemVector {
    start: u64,
    size: u64,
}

/// Immovable memory regions representation. Max amount of memory regions is MAX_NUMNODES*2.
/// Defined unconditionally, as in the C (only its users are under CONFIG_RANDOMIZE_BASE &&
/// CONFIG_MEMORY_HOTREMOVE). Zero initialised, so it lives in .bss without relocations.
#[no_mangle]
pub static mut immovable_mem: [MemVector; MAX_NUMNODES * 2] = [MemVector { start: 0, size: 0 }; MAX_NUMNODES * 2];

/// efi_guid_t: 16 bytes, aligned 4 (passed by value to efi_find_vendor_table(), as in the C).
#[cfg(efi)]
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EfiGuid([u8; 16]);

/// ACPI_20_TABLE_GUID = EFI_GUID(0x8868e871, 0xe4f1, 0x11d3, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81)
/// (include/linux/efi.h)
#[cfg(efi)]
const ACPI_20_TABLE_GUID: EfiGuid = EfiGuid([
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
]);

/// ACPI_TABLE_GUID = EFI_GUID(0xeb9d2d30, 0x2d88, 0x11d3, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)
/// (include/linux/efi.h)
#[cfg(efi)]
const ACPI_TABLE_GUID: EfiGuid = EfiGuid([
    0x30, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
]);

/// `struct acpi_table_rsdp` (include/acpi/actbl.h, inside `#pragma pack(1)`).
#[repr(C, packed)]
#[allow(dead_code)]
struct AcpiTableRsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_physical_address: u32,
    length: u32,
    xsdt_physical_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// `struct acpi_table_header` (include/acpi/actbl.h, packed).
#[repr(C, packed)]
#[allow(dead_code)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    asl_compiler_id: [u8; 4],
    asl_compiler_revision: u32,
}

/// `struct acpi_subtable_header` (include/acpi/actbl1.h, packed).
#[repr(C, packed)]
#[allow(dead_code)]
struct AcpiSubtableHeader {
    type_: u8,
    length: u8,
}

/// `struct acpi_table_srat` (include/acpi/actbl3.h, packed).
#[repr(C, packed)]
#[allow(dead_code)]
struct AcpiTableSrat {
    header: AcpiTableHeader,
    table_revision: u32,
    reserved: u64,
}

/// `struct acpi_srat_mem_affinity` (include/acpi/actbl3.h, packed).
#[repr(C, packed)]
#[allow(dead_code)]
struct AcpiSratMemAffinity {
    header: AcpiSubtableHeader,
    proximity_domain: u32,
    reserved: u16,
    base_address: u64,
    length: u64,
    reserved1: u32,
    flags: u32,
    reserved2: u64,
}

// Sizes from the layouts in the headers (ACPI_OEM_ID_SIZE 6, ACPI_OEM_TABLE_ID_SIZE 8, NAMESEG 4);
// RSDP 36 is also ACPI_RSDP_XCHECKSUM_LENGTH.
const _: () = assert!(core::mem::size_of::<AcpiTableRsdp>() == 36);
const _: () = assert!(core::mem::offset_of!(AcpiTableRsdp, revision) == 15);
const _: () = assert!(core::mem::offset_of!(AcpiTableRsdp, rsdt_physical_address) == 16);
const _: () = assert!(core::mem::offset_of!(AcpiTableRsdp, xsdt_physical_address) == 24);
const _: () = assert!(core::mem::size_of::<AcpiTableHeader>() == 36);
const _: () = assert!(core::mem::offset_of!(AcpiTableHeader, length) == 4);
const _: () = assert!(core::mem::size_of::<AcpiSubtableHeader>() == 2);
const _: () = assert!(core::mem::size_of::<AcpiTableSrat>() == 48);
const _: () = assert!(core::mem::size_of::<AcpiSratMemAffinity>() == 40);
const _: () = assert!(core::mem::offset_of!(AcpiSratMemAffinity, base_address) == 8);
const _: () = assert!(core::mem::offset_of!(AcpiSratMemAffinity, length) == 16);
const _: () = assert!(core::mem::offset_of!(AcpiSratMemAffinity, flags) == 28);
const _: () = assert!(core::mem::size_of::<MemVector>() == 16);

/// include/acpi/acconfig.h
#[cfg(not(stubf_test_ebda))]
const ACPI_EBDA_PTR_LOCATION: usize = 0x0000_040E;
/// TEST-ONLY (rig/stubf/run-acpi.sh passes --cfg=stubf_test_ebda; the shipped object never does): a userspace process cannot map
/// page 0 (vm.mmap_min_addr), so the differential test moves the EBDA pointer word to 0x1040E in the C copy and here alike.
/// The real value is checked against the C header by rig/stubf/layouts-acpi.txt.
#[cfg(stubf_test_ebda)]
const ACPI_EBDA_PTR_LOCATION: usize = 0x0001_040E;
const ACPI_EBDA_WINDOW_SIZE: u32 = 1024;
const ACPI_HI_RSDP_WINDOW_BASE: usize = 0x000E_0000;
const ACPI_HI_RSDP_WINDOW_SIZE: u32 = 0x0002_0000;
const ACPI_RSDP_SCAN_STEP: usize = 16;
const ACPI_RSDP_CHECKSUM_LENGTH: u32 = 20;
const ACPI_RSDP_XCHECKSUM_LENGTH: u32 = 36;

/// include/acpi/actbl.h: `sizeof(u32)` / `sizeof(u64)`.
#[cfg(hotremove_srat)]
const ACPI_RSDT_ENTRY_SIZE: u32 = 4;
#[cfg(hotremove_srat)]
const ACPI_XSDT_ENTRY_SIZE: u32 = 8;

/// include/acpi/actbl3.h: `ACPI_SRAT_TYPE_MEMORY_AFFINITY` (enum acpi_srat_type) and
/// `ACPI_SRAT_MEM_HOT_PLUGGABLE` (1<<1).
#[cfg(hotremove_srat)]
const ACPI_SRAT_TYPE_MEMORY_AFFINITY: u8 = 1;
#[cfg(hotremove_srat)]
const ACPI_SRAT_MEM_HOT_PLUGGABLE: u32 = 1 << 1;

/// Longest parameter of 'acpi=' is 'copy_dsdt', plus an extra '\0' for termination.
#[cfg(hotremove_srat)]
const MAX_ACPI_ARG_LENGTH: usize = 10;

/// Max length of 64-bit hex address string is 19, prefix "0x" + 16 hex digits, and '\0' for termination.
#[cfg(all(hotremove_srat, kexec_core))]
const MAX_ADDR_LEN: usize = 19;

/// Offset of `acpi_rsdp_addr` in `struct boot_params` (0x070 in the bootparam.h comment; a C program
/// including the real uapi <asm/bootparam.h> and printing offsetof() gave 112, sizeof 4096).
const BP_ACPI_RSDP_ADDR: usize = 112;

extern "C" {
    static mut boot_params_ptr: *mut c_void;

    /// misc.c; the target of debug_putstr() when CONFIG_X86_VERBOSE_BOOTUP is set.
    #[cfg(verbose_bootup)]
    fn __putstr(s: *const c_char);

    #[cfg(hotremove_srat)]
    fn cmdline_find_option(option: *const c_char, buffer: *mut c_char, bufsize: c_int) -> c_int;
    #[cfg(hotremove_srat)]
    fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    /// arch/x86/boot/string.h
    #[cfg(all(hotremove_srat, kexec_core))]
    fn boot_kstrtoul(s: *const c_char, base: core::ffi::c_uint, res: *mut c_ulong) -> c_int;

    #[cfg(efi)]
    fn efi_get_type(bp: *mut c_void) -> c_int;
    #[cfg(efi)]
    fn efi_get_system_table(bp: *mut c_void) -> c_ulong;
    #[cfg(efi)]
    fn efi_get_conf_table(bp: *mut c_void, cfg_tbl_pa: *mut c_ulong, cfg_tbl_len: *mut c_uint) -> c_int;
    #[cfg(efi)]
    fn efi_find_vendor_table(bp: *mut c_void, cfg_tbl_pa: c_ulong, cfg_tbl_len: c_uint, guid: EfiGuid) -> c_ulong;

    /// error_rs.rs / error.c
    #[cfg(efi)]
    fn error(m: *mut c_char) -> !;
    #[cfg(all(hotremove_srat, kexec_core))]
    fn warn(m: *const c_char);
}

/// `enum efi_type` of compressed/misc.h: EFI_TYPE_NONE = 2.
#[cfg(efi)]
const EFI_TYPE_NONE: c_int = 2;

/// `debug_putstr()`: `__putstr()` with CONFIG_X86_VERBOSE_BOOTUP, nothing otherwise.
#[allow(unused_macros)]
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

/// `boot_params_ptr->acpi_rsdp_addr`
unsafe fn bp_acpi_rsdp_addr() -> u64 {
    // SAFETY: boot_params_ptr is set before get_rsdp_addr() can run; the field is inside the 4096 bytes.
    unsafe { (ptr::addr_of!(boot_params_ptr).read() as *const u8).add(BP_ACPI_RSDP_ADDR).cast::<u64>().read_unaligned() }
}

/// `__efi_get_rsdp_addr()`; without CONFIG_EFI it returns 0.
#[allow(unused_variables)]
unsafe fn __efi_get_rsdp_addr(cfg_tbl_pa: c_ulong, cfg_tbl_len: u32) -> u64 {
    #[cfg(efi)]
    {
        // SAFETY: C helpers from efi.c (efi_rs.rs); boot_params_ptr is valid as above.
        unsafe {
            let bp = ptr::addr_of!(boot_params_ptr).read();

            // Search EFI system tables for RSDP. Preferred is ACPI_20_TABLE_GUID to
            // ACPI_TABLE_GUID because it has more features.
            let rsdp_addr = efi_find_vendor_table(bp, cfg_tbl_pa, cfg_tbl_len, ACPI_20_TABLE_GUID);
            if rsdp_addr != 0 {
                return rsdp_addr as u64;
            }

            // No ACPI_20_TABLE_GUID found, fallback to ACPI_TABLE_GUID.
            let rsdp_addr = efi_find_vendor_table(bp, cfg_tbl_pa, cfg_tbl_len, ACPI_TABLE_GUID);
            if rsdp_addr != 0 {
                return rsdp_addr as u64;
            }
        }

        debug_putstr!(c"Error getting RSDP address.\n");
    }
    0
}

/// `efi_get_rsdp_addr()`; without CONFIG_EFI it returns 0.
unsafe fn efi_get_rsdp_addr() -> u64 {
    #[cfg(efi)]
    {
        let mut cfg_tbl_pa: c_ulong = 0;
        let mut cfg_tbl_len: c_uint = 0;

        // SAFETY: C helpers from efi.c (efi_rs.rs); boot_params_ptr is valid as above.
        unsafe {
            let bp = ptr::addr_of!(boot_params_ptr).read();

            let et = efi_get_type(bp);
            if et == EFI_TYPE_NONE {
                return 0;
            }

            let systab_pa = efi_get_system_table(bp);
            if systab_pa == 0 {
                error(c"EFI support advertised, but unable to locate system table.".as_ptr() as *mut c_char);
            }

            let ret = efi_get_conf_table(bp, &mut cfg_tbl_pa, &mut cfg_tbl_len);
            if ret != 0 || cfg_tbl_pa == 0 {
                error(c"EFI config table not found.".as_ptr() as *mut c_char);
            }

            __efi_get_rsdp_addr(cfg_tbl_pa, cfg_tbl_len)
        }
    }
    #[cfg(not(efi))]
    {
        0
    }
}

/// `compute_checksum()`: u8 wrapping sum of `length` bytes.
unsafe fn compute_checksum(buffer: *const u8, length: u32) -> u8 {
    let end = (buffer as usize).wrapping_add(length as usize);
    let mut p = buffer as usize;
    let mut sum: u8 = 0;

    while p < end {
        // SAFETY: the caller passes a window of identity-mapped memory.
        sum = sum.wrapping_add(unsafe { (p as *const u8).read() });
        p = p.wrapping_add(1);
    }

    sum
}

/// Search a block of memory for the RSDP signature. Returns the address or 0 (NULL).
unsafe fn scan_mem_for_rsdp(start: usize, length: u32) -> usize {
    let end = start.wrapping_add(length as usize);
    let mut address = start;

    // Search from given start address for the requested length
    while address < end {
        // Both RSDP signature and checksum must be correct.
        // Note: Sometimes there exists more than one RSDP in memory;
        // the valid RSDP has a valid checksum, all others have an
        // invalid checksum.
        let rsdp = address as *const AcpiTableRsdp;

        // BAD Signature. ACPI_VALIDATE_RSDP_SIG(): strncmp(signature, "RSD PTR ", 8); neither string has
        // a NUL in its 8 bytes (the literal has none), so this is an 8-byte equality.
        // SAFETY: a window of identity-mapped low memory; all reads unaligned.
        let sig = unsafe { ptr::addr_of!((*rsdp).signature).read_unaligned() };
        if u64::from_ne_bytes(sig) != u64::from_ne_bytes(*b"RSD PTR ") {
            address = address.wrapping_add(ACPI_RSDP_SCAN_STEP);
            continue;
        }

        // Check the standard checksum
        // SAFETY: as above.
        if unsafe { compute_checksum(rsdp as *const u8, ACPI_RSDP_CHECKSUM_LENGTH) } != 0 {
            address = address.wrapping_add(ACPI_RSDP_SCAN_STEP);
            continue;
        }

        // Check extended checksum if table version >= 2
        // SAFETY: as above.
        let revision = unsafe { ptr::addr_of!((*rsdp).revision).read_unaligned() };
        if revision >= 2 && unsafe { compute_checksum(rsdp as *const u8, ACPI_RSDP_XCHECKSUM_LENGTH) } != 0 {
            address = address.wrapping_add(ACPI_RSDP_SCAN_STEP);
            continue;
        }

        // Signature and checksum valid, we have found a real RSDP
        return address;
    }
    0
}

/// Search RSDP address in EBDA.
unsafe fn bios_get_rsdp_addr() -> u64 {
    // Get the location of the Extended BIOS Data Area (EBDA)
    // SAFETY: the BIOS data area word at 0x40E; low memory is identity mapped.
    let mut address: c_ulong = unsafe { (ACPI_EBDA_PTR_LOCATION as *const u16).read_unaligned() } as c_ulong;
    address <<= 4;

    // Search EBDA paragraphs (EBDA is required to be a minimum of 1K length)
    if address > 0x400 {
        // SAFETY: scans the EBDA window.
        let rsdp = unsafe { scan_mem_for_rsdp(address as usize, ACPI_EBDA_WINDOW_SIZE) };
        if rsdp != 0 {
            return rsdp as u64;
        }
    }

    // Search upper memory: 16-byte boundaries in E0000h-FFFFFh
    // SAFETY: scans the BIOS ROM window.
    let rsdp = unsafe { scan_mem_for_rsdp(ACPI_HI_RSDP_WINDOW_BASE, ACPI_HI_RSDP_WINDOW_SIZE) };
    if rsdp != 0 {
        return rsdp as u64;
    }

    0
}

/// Return RSDP address on success, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn get_rsdp_addr() -> u64 {
    // SAFETY: helpers above; boot_params_ptr is set before this is called.
    unsafe {
        let mut pa = bp_acpi_rsdp_addr();

        if pa == 0 {
            pa = efi_get_rsdp_addr();
        }

        if pa == 0 {
            pa = bios_get_rsdp_addr();
        }

        pa
    }
}

/// `get_cmdline_acpi_rsdp()`: `acpi_rsdp=` from the command line; only with CONFIG_KEXEC_CORE, else 0.
#[cfg(hotremove_srat)]
unsafe fn get_cmdline_acpi_rsdp() -> c_ulong {
    #[cfg(kexec_core)]
    {
        let mut addr: c_ulong = 0;
        let mut val = [0 as c_char; MAX_ADDR_LEN];

        // SAFETY: C helpers; val is MAX_ADDR_LEN bytes, as passed.
        unsafe {
            let ret = cmdline_find_option(c"acpi_rsdp".as_ptr(), val.as_mut_ptr(), MAX_ADDR_LEN as c_int);
            if ret < 0 {
                return 0;
            }

            // C compares `int ret >= sizeof(val)` (size_t), ret is non-negative here.
            if ret as usize >= MAX_ADDR_LEN {
                warn(c"acpi_rsdp= value too long; ignoring".as_ptr());
                return 0;
            }

            if boot_kstrtoul(val.as_ptr(), 16, &mut addr) != 0 {
                return 0;
            }
        }
        addr
    }
    #[cfg(not(kexec_core))]
    {
        0
    }
}

/// Compute SRAT address from RSDP.
#[cfg(hotremove_srat)]
unsafe fn get_acpi_srat_table() -> c_ulong {
    let mut arg = [0 as c_char; 10];

    // SAFETY: firmware tables and the C helpers; physical addresses are identity mapped.
    unsafe {
        // Check whether we were given an RSDP on the command line. We don't
        // stash this in boot params because the kernel itself may have
        // different ideas about whether to trust a command-line parameter.
        let mut rsdp = get_cmdline_acpi_rsdp() as usize as *const AcpiTableRsdp;
        if rsdp.is_null() {
            rsdp = bp_acpi_rsdp_addr() as usize as *const AcpiTableRsdp;
        }

        if rsdp.is_null() {
            return 0;
        }

        // Get ACPI root table from RSDP.
        let xsdt = ptr::addr_of!((*rsdp).xsdt_physical_address).read_unaligned();
        let revision = ptr::addr_of!((*rsdp).revision).read_unaligned();
        let root_table: c_ulong;
        let size: u32;
        if !(cmdline_find_option(c"acpi".as_ptr(), arg.as_mut_ptr(), arg.len() as c_int) == 4
            && strncmp(arg.as_ptr(), c"rsdt".as_ptr(), 4) == 0)
            && xsdt != 0
            && revision > 1
        {
            root_table = xsdt as c_ulong;
            size = ACPI_XSDT_ENTRY_SIZE;
        } else {
            root_table = ptr::addr_of!((*rsdp).rsdt_physical_address).read_unaligned() as c_ulong;
            size = ACPI_RSDT_ENTRY_SIZE;
        }

        if root_table == 0 {
            return 0;
        }

        let header = root_table as *const AcpiTableHeader;
        let len: u32 = ptr::addr_of!((*header).length).read_unaligned();
        if (len as usize) < core::mem::size_of::<AcpiTableHeader>() + size as usize {
            return 0;
        }

        let mut num_entries: u32 = (len - core::mem::size_of::<AcpiTableHeader>() as u32) / size;
        let mut entry: usize = (root_table as usize).wrapping_add(core::mem::size_of::<AcpiTableHeader>());

        // C: while (num_entries--)
        while num_entries != 0 {
            num_entries -= 1;

            let acpi_table: c_ulong = if size == ACPI_RSDT_ENTRY_SIZE {
                (entry as *const u32).read_unaligned() as c_ulong
            } else {
                (entry as *const u64).read_unaligned() as c_ulong
            };

            if acpi_table != 0 {
                let header = acpi_table as *const AcpiTableHeader;

                // ACPI_COMPARE_NAMESEG(): 4-byte compare (no ACPI_MISALIGNMENT_NOT_SUPPORTED on x86).
                let sig = ptr::addr_of!((*header).signature).read_unaligned();
                if u32::from_ne_bytes(sig) == u32::from_ne_bytes(*b"SRAT") {
                    return acpi_table;
                }
            }
            entry = entry.wrapping_add(size as usize);
        }
    }
    0
}

/// count_immovable_mem_regions - Parse SRAT and cache the immovable memory regions into the
/// immovable_mem array.
///
/// Return the number of immovable memory regions on success, 0 on failure:
///
/// - Too many immovable memory regions
/// - ACPI off or no SRAT found
/// - No immovable memory region found.
#[cfg(hotremove_srat)]
#[no_mangle]
pub unsafe extern "C" fn count_immovable_mem_regions() -> c_int {
    let mut arg = [0 as c_char; MAX_ACPI_ARG_LENGTH];
    let mut num: c_int = 0;

    // SAFETY: C helpers, the SRAT in firmware memory (identity mapped), and the immovable_mem array,
    // whose index is below MAX_NUMNODES*2 at every write (checked after each increment, as in the C).
    unsafe {
        if cmdline_find_option(c"acpi".as_ptr(), arg.as_mut_ptr(), arg.len() as c_int) == 3
            && strncmp(arg.as_ptr(), c"off".as_ptr(), 3) == 0
        {
            return 0;
        }

        let table_addr = get_acpi_srat_table();
        if table_addr == 0 {
            return 0;
        }

        let table_header = table_addr as *const AcpiTableHeader;
        let table_end: usize = (table_addr as usize).wrapping_add(ptr::addr_of!((*table_header).length).read_unaligned() as usize);
        let mut table: usize = (table_addr as usize).wrapping_add(core::mem::size_of::<AcpiTableSrat>());

        while table.wrapping_add(core::mem::size_of::<AcpiSubtableHeader>()) < table_end {
            let sub_table = table as *const AcpiSubtableHeader;
            let sub_length = ptr::addr_of!((*sub_table).length).read_unaligned();
            if sub_length == 0 {
                debug_putstr!(c"Invalid zero length SRAT subtable.\n");
                return 0;
            }

            if ptr::addr_of!((*sub_table).type_).read_unaligned() == ACPI_SRAT_TYPE_MEMORY_AFFINITY {
                let ma = sub_table as *const AcpiSratMemAffinity;
                let flags = ptr::addr_of!((*ma).flags).read_unaligned();
                let ma_length = ptr::addr_of!((*ma).length).read_unaligned();
                if flags & ACPI_SRAT_MEM_HOT_PLUGGABLE == 0 && ma_length != 0 {
                    let slot = (ptr::addr_of_mut!(immovable_mem) as *mut MemVector).add(num as usize);
                    (*slot).start = ptr::addr_of!((*ma).base_address).read_unaligned();
                    (*slot).size = ma_length;
                    num += 1;
                }

                if num as usize >= MAX_NUMNODES * 2 {
                    debug_putstr!(c"Too many immovable memory regions, aborting.\n");
                    return 0;
                }
            }
            table = table.wrapping_add(sub_length as usize);
        }
    }
    num
}
