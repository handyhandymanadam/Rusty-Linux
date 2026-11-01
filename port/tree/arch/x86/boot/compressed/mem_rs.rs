// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/mem.c (unaccepted-memory helpers).
//!
//! Built only with CONFIG_UNACCEPTED_MEMORY (selected by INTEL_TDX_GUEST and AMD_MEM_ENCRYPT, needs
//! EFI_STUB) and the same gate as the other Phase B files. `--cfg=tdx_guest` / `--cfg=amd_mem_encrypt`
//! stand for the two IS_ENABLED()/#ifdef switches the C file and its headers have.
//! Text of every message is the C's.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

/// efi_guid_t: 16 bytes, aligned 4 (passed by value to efi_find_vendor_table(), as in the C).
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct EfiGuid([u8; 16]);

/// LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID = EFI_GUID(0xd5d1de3c, 0x105c, 0x44f9, 0x9e, 0xa9, 0xbc, 0xef, 0x98, 0x12, 0x00, 0x31)
const UNACCEPTED_MEM_TABLE_GUID: EfiGuid = EfiGuid([
    0x3c, 0xde, 0xd1, 0xd5, 0x5c, 0x10, 0xf9, 0x44, 0x9e, 0xa9, 0xbc, 0xef, 0x98, 0x12, 0x00, 0x31,
]);

/// `struct efi_unaccepted_memory` (include/linux/efi.h); only `version` is read here.
#[repr(C)]
pub struct EfiUnacceptedMemory {
    version: u32,
    unit_size: u32,
    phys_base: u64,
    size: u64,
}

/// `enum efi_type` of compressed/misc.h: EFI_TYPE_64 = 0, EFI_TYPE_32 = 1, EFI_TYPE_NONE = 2.
const EFI_TYPE_NONE: c_int = 2;

extern "C" {
    static mut boot_params_ptr: *mut c_void;
    /// drivers/firmware/efi/libstub/unaccepted_memory.c
    static mut unaccepted_table: *mut EfiUnacceptedMemory;

    fn efi_get_type(bp: *mut c_void) -> c_int;
    fn efi_get_conf_table(bp: *mut c_void, cfg_tbl_pa: *mut c_ulong, cfg_tbl_len: *mut c_uint) -> c_int;
    fn efi_find_vendor_table(bp: *mut c_void, cfg_tbl_pa: c_ulong, cfg_tbl_len: c_uint, guid: EfiGuid) -> c_ulong;

    /// cpuflags_rs.rs (cpuflags.c)
    fn cpuid_count(id: u32, count: u32, a: *mut u32, b: *mut u32, c: *mut u32, d: *mut u32);

    fn warn(m: *const c_char);
    fn error(m: *mut c_char) -> !;
    /// error_rs.rs / error.c (CONFIG_EFI_STUB, which UNACCEPTED_MEMORY depends on)
    fn panic(fmt: *const c_char, ...) -> !;

    #[cfg(tdx_guest)]
    fn tdx_accept_memory(start: u64, end: u64) -> bool;
    #[cfg(amd_mem_encrypt)]
    fn snp_accept_memory(start: u64, end: u64);
    #[cfg(amd_mem_encrypt)]
    fn early_is_sevsnp_guest() -> bool;
}

#[cfg(tdx_guest)]
const TDX_CPUID_LEAF_ID: u32 = 0x21;

/// accept_memory() and process_unaccepted_memory() are called from the EFI stub, which runs before
/// the decompressor and its early_tdx_detect(); enumerate TDX directly from the early users.
#[cfg(tdx_guest)]
unsafe fn early_is_tdx_guest() -> bool {
    static mut ONCE: bool = false;
    static mut IS_TDX: bool = false;

    // SAFETY: single CPU, no concurrency in the boot stub.
    unsafe {
        if !ONCE {
            let mut eax = 0u32;
            let mut sig = [0u32; 3];
            // C: cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]), so
            // sig = [ebx, edx, ecx]; TDX_IDENT is "IntelTDX    ".
            cpuid_count(TDX_CPUID_LEAF_ID, 0, &mut eax, &mut sig[0], &mut sig[2], &mut sig[1]);
            IS_TDX = sig[0] == u32::from_le_bytes(*b"Inte")
                && sig[1] == u32::from_le_bytes(*b"lTDX")
                && sig[2] == u32::from_le_bytes(*b"    ");
            ONCE = true;
        }
        IS_TDX
    }
}

/// `void arch_accept_memory(phys_addr_t start, phys_addr_t end)`
#[no_mangle]
pub unsafe extern "C" fn arch_accept_memory(start: u64, end: u64) {
    // SAFETY: calls into the C TDX / SEV-SNP helpers with the caller's range, as the C did.
    unsafe {
        #[cfg(tdx_guest)]
        {
            if early_is_tdx_guest() {
                if !tdx_accept_memory(start, end) {
                    panic(c"TDX: Failed to accept memory\n".as_ptr());
                }
                return;
            }
        }
        #[cfg(amd_mem_encrypt)]
        {
            if early_is_sevsnp_guest() {
                snp_accept_memory(start, end);
                return;
            }
        }
        let _ = (start, end);
        error(c"Cannot accept memory: unknown platform\n".as_ptr() as *mut c_char);
    }
}

/// `bool init_unaccepted_memory(void)`
#[no_mangle]
pub unsafe extern "C" fn init_unaccepted_memory() -> bool {
    let mut cfg_table_pa: c_ulong = 0;
    let mut cfg_table_len: c_uint = 0;

    // SAFETY: C helpers from efi.c; boot_params_ptr is set before extract_kernel() runs.
    unsafe {
        let et = efi_get_type(boot_params_ptr);
        if et == EFI_TYPE_NONE {
            return false;
        }

        let ret = efi_get_conf_table(boot_params_ptr, &mut cfg_table_pa, &mut cfg_table_len);
        if ret != 0 {
            warn(c"EFI config table not found.".as_ptr());
            return false;
        }

        let table = efi_find_vendor_table(boot_params_ptr, cfg_table_pa, cfg_table_len, UNACCEPTED_MEM_TABLE_GUID)
            as *mut EfiUnacceptedMemory;
        if table.is_null() {
            return false;
        }

        if (*table).version != 1 {
            error(c"Unknown version of unaccepted memory table\n".as_ptr() as *mut c_char);
        }

        // In many cases unaccepted_table is already set by the EFI stub, but it has to be
        // initialized again to cover cases when the table is not allocated by the EFI stub or the
        // EFI stub copied the kernel image with efi_relocate_kernel() before the variable is set.
        // It must be initialized before the first usage of accept_memory().
        unaccepted_table = table;
    }
    true
}
