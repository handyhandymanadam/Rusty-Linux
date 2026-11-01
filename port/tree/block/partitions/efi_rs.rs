// SPDX-License-Identifier: GPL-2.0-or-later

//! GUID partition table validation -- the Rust behind part of `block/partitions/efi.c`.
//!
//! Ported from `block/partitions/efi.c` (6.18.49, Matt Domsch): the protective / hybrid MBR test (`pmbr_part_valid`, `is_pmbr_valid`), the checks `is_gpt_valid()` makes on a GPT header
//! once it has been read (signature, header size bounds, header CRC with the CRC field zeroed while it is computed, own LBA, usable range, entry size), `is_pte_valid()`, the comparison
//! of the primary and alternate headers (`compare_gpts`, with its warnings) and the UTF-16 to 7-bit label conversion (`utf16_le_to_7bit`). In C (`efi_glue.c`): all reading of the disk
//! (`read_lba`, `alloc_read_gpt_*`), `is_gpt_valid`'s allocation and entry-array checks, `find_valid_gpt`, `efi_partition`, and the `rust_efi_*` wrappers for `crc32`, `pr_warn`. The
//! `pr_debug` lines of the original (silent unless dynamic debug enables them) are not carried over.
//!
//! Replaces: block/partitions/efi.c (the pure checks listed above)

use core::ffi::{c_int, c_void};

const MSDOS_MBR_SIGNATURE: u16 = 0xaa55;
const EFI_PMBR_OSTYPE_EFI_GPT: u8 = 0xEE;
const GPT_MBR_PROTECTIVE: c_int = 1;
const GPT_MBR_HYBRID: c_int = 2;
const GPT_HEADER_SIGNATURE: u64 = 0x5452415020494645;
const GPT_PRIMARY_PARTITION_TABLE_LBA: u32 = 1;
/// `sizeof(gpt_header)`.
const GPT_HEADER_SIZE: u32 = 92;
/// `sizeof(gpt_entry)`.
const GPT_ENTRY_SIZE: u32 = 128;

// Offsets of the packed on-disk structures (asserted by the glue).
const H_SIGNATURE: usize = 0;
const H_HEADER_SIZE: usize = 12;
const H_HEADER_CRC32: usize = 16;
const H_MY_LBA: usize = 24;
const H_ALTERNATE_LBA: usize = 32;
const H_FIRST_USABLE_LBA: usize = 40;
const H_LAST_USABLE_LBA: usize = 48;
const H_DISK_GUID: usize = 56;
const H_NUM_ENTRIES: usize = 80;
const H_ENTRY_SIZE: usize = 84;
const H_ENTRY_ARRAY_CRC32: usize = 88;
const E_TYPE_GUID: usize = 0;
const E_STARTING_LBA: usize = 32;
const E_ENDING_LBA: usize = 40;
const MBR_PARTITION_RECORD: usize = 446;
const MBR_RECORD_SIZE: usize = 16;
const MBR_SIGNATURE: usize = 510;
const R_OS_TYPE: usize = 4;
const R_STARTING_LBA: usize = 8;

extern "C" {
    /// `efi_crc32(buf, len)`: `crc32(~0, buf, len) ^ ~0`
    fn rust_efi_crc32(buf: *const c_void, len: u32) -> u32;
    /// The `pr_warn()` lines of `compare_gpts()`, by number (see the glue).
    fn rust_efi_warn(which: c_int, a: u64, b: u64);
}

unsafe fn rd16(p: *const u8, off: usize) -> u16 {
    unsafe { u16::from_le((p.add(off) as *const u16).read_unaligned()) }
}
unsafe fn rd32(p: *const u8, off: usize) -> u32 {
    unsafe { u32::from_le((p.add(off) as *const u32).read_unaligned()) }
}
unsafe fn rd64(p: *const u8, off: usize) -> u64 {
    unsafe { u64::from_le((p.add(off) as *const u64).read_unaligned()) }
}

/// `pmbr_part_valid()`: does this MBR record describe a protective GPT partition starting at LBA 1?
unsafe fn pmbr_part_valid(part: *const u8) -> c_int {
    unsafe {
        if *part.add(R_OS_TYPE) != EFI_PMBR_OSTYPE_EFI_GPT {
            return 0;
        }

        // set to 0x00000001 (i.e., the LBA of the GPT Partition Header)
        if rd32(part, R_STARTING_LBA) != GPT_PRIMARY_PARTITION_TABLE_LBA {
            return 0;
        }
        GPT_MBR_PROTECTIVE
    }
}

/// `is_pmbr_valid()`: 0 if the sector is no protective MBR, 1 for a protective one, 2 for a hybrid.
#[no_mangle]
pub unsafe extern "C" fn rust_efi_is_pmbr_valid(mbr: *const u8) -> c_int {
    unsafe {
        let mut ret = 0; // invalid by default

        if mbr.is_null() || rd16(mbr, MBR_SIGNATURE) != MSDOS_MBR_SIGNATURE {
            return ret;
        }

        let mut found = false;
        for i in 0..4 {
            ret = pmbr_part_valid(mbr.add(MBR_PARTITION_RECORD + i * MBR_RECORD_SIZE));
            if ret == GPT_MBR_PROTECTIVE {
                // Ok, we at least know that there's a protective MBR, now check if there are other partition types for hybrid MBR.
                found = true;
                break;
            }
        }
        if !found {
            return ret;
        }

        for i in 0..4 {
            let os_type = *mbr.add(MBR_PARTITION_RECORD + i * MBR_RECORD_SIZE + R_OS_TYPE);
            if os_type != EFI_PMBR_OSTYPE_EFI_GPT && os_type != 0x00 {
                ret = GPT_MBR_HYBRID;
            }
        }
        // (the C code then notes, at debug level only, a protective MBR whose size differs from the disk)
        ret
    }
}

/// The header checks of `is_gpt_valid()` between reading the header and reading the entry array: 0 if it passes, else the number of the failed check. `ssz` is the logical block size.
/// The header CRC is computed with the CRC field zeroed, which is restored afterwards.
#[no_mangle]
pub unsafe extern "C" fn rust_efi_gpt_header_check(gpt: *mut u8, lba: u64, lastlba: u64, ssz: u32) -> c_int {
    unsafe {
        if rd64(gpt, H_SIGNATURE) != GPT_HEADER_SIGNATURE {
            return 1;
        }

        if rd32(gpt, H_HEADER_SIZE) > ssz {
            return 2;
        }

        if rd32(gpt, H_HEADER_SIZE) < GPT_HEADER_SIZE {
            return 3;
        }

        let origcrc = rd32(gpt, H_HEADER_CRC32);
        (gpt.add(H_HEADER_CRC32) as *mut u32).write_unaligned(0);
        let crc = rust_efi_crc32(gpt as *const c_void, rd32(gpt, H_HEADER_SIZE));
        if crc != origcrc {
            return 4;
        }
        (gpt.add(H_HEADER_CRC32) as *mut u32).write_unaligned(origcrc.to_le());

        // Check that the my_lba entry points to the LBA that contains the GUID Partition Table
        if rd64(gpt, H_MY_LBA) != lba {
            return 5;
        }

        // Check the first_usable_lba and last_usable_lba are within the disk.
        if rd64(gpt, H_FIRST_USABLE_LBA) > lastlba {
            return 6;
        }
        if rd64(gpt, H_LAST_USABLE_LBA) > lastlba {
            return 7;
        }
        if rd64(gpt, H_LAST_USABLE_LBA) < rd64(gpt, H_FIRST_USABLE_LBA) {
            return 8;
        }
        if rd32(gpt, H_ENTRY_SIZE) != GPT_ENTRY_SIZE {
            return 9;
        }
        0
    }
}

/// `is_pte_valid()`: a partition entry is usable if its type GUID is not null and it lies on the disk.
#[no_mangle]
pub unsafe extern "C" fn rust_efi_is_pte_valid(pte: *const u8, lastlba: u64) -> c_int {
    unsafe {
        let mut null_guid = true;
        for i in 0..16 {
            if *pte.add(E_TYPE_GUID + i) != 0 {
                null_guid = false;
            }
        }
        if null_guid || rd64(pte, E_STARTING_LBA) > lastlba || rd64(pte, E_ENDING_LBA) > lastlba {
            return 0;
        }
        1
    }
}

/// `compare_gpts()`: warn about every difference between the primary and alternate headers; returns the number found.
#[no_mangle]
pub unsafe extern "C" fn rust_efi_compare_gpts(pgpt: *const u8, agpt: *const u8, lastlba: u64) -> c_int {
    unsafe {
        let mut error_found = 0;

        if pgpt.is_null() || agpt.is_null() {
            return 0;
        }
        if rd64(pgpt, H_MY_LBA) != rd64(agpt, H_ALTERNATE_LBA) {
            rust_efi_warn(0, rd64(pgpt, H_MY_LBA), rd64(agpt, H_ALTERNATE_LBA));
            error_found += 1;
        }
        if rd64(pgpt, H_ALTERNATE_LBA) != rd64(agpt, H_MY_LBA) {
            rust_efi_warn(1, rd64(pgpt, H_ALTERNATE_LBA), rd64(agpt, H_MY_LBA));
            error_found += 1;
        }
        if rd64(pgpt, H_FIRST_USABLE_LBA) != rd64(agpt, H_FIRST_USABLE_LBA) {
            rust_efi_warn(2, rd64(pgpt, H_FIRST_USABLE_LBA), rd64(agpt, H_FIRST_USABLE_LBA));
            error_found += 1;
        }
        if rd64(pgpt, H_LAST_USABLE_LBA) != rd64(agpt, H_LAST_USABLE_LBA) {
            rust_efi_warn(3, rd64(pgpt, H_LAST_USABLE_LBA), rd64(agpt, H_LAST_USABLE_LBA));
            error_found += 1;
        }
        if core::slice::from_raw_parts(pgpt.add(H_DISK_GUID), 16) != core::slice::from_raw_parts(agpt.add(H_DISK_GUID), 16) {
            rust_efi_warn(4, 0, 0);
            error_found += 1;
        }
        if rd32(pgpt, H_NUM_ENTRIES) != rd32(agpt, H_NUM_ENTRIES) {
            rust_efi_warn(5, rd32(pgpt, H_NUM_ENTRIES) as u64, rd32(agpt, H_NUM_ENTRIES) as u64);
            error_found += 1;
        }
        if rd32(pgpt, H_ENTRY_SIZE) != rd32(agpt, H_ENTRY_SIZE) {
            rust_efi_warn(6, rd32(pgpt, H_ENTRY_SIZE) as u64, rd32(agpt, H_ENTRY_SIZE) as u64);
            error_found += 1;
        }
        if rd32(pgpt, H_ENTRY_ARRAY_CRC32) != rd32(agpt, H_ENTRY_ARRAY_CRC32) {
            rust_efi_warn(7, rd32(pgpt, H_ENTRY_ARRAY_CRC32) as u64, rd32(agpt, H_ENTRY_ARRAY_CRC32) as u64);
            error_found += 1;
        }
        if rd64(pgpt, H_ALTERNATE_LBA) != lastlba {
            rust_efi_warn(8, rd64(pgpt, H_ALTERNATE_LBA), lastlba);
            error_found += 1;
        }

        if rd64(agpt, H_MY_LBA) != lastlba {
            rust_efi_warn(9, rd64(agpt, H_MY_LBA), lastlba);
            error_found += 1;
        }

        if error_found != 0 {
            rust_efi_warn(10, 0, 0);
        }
        error_found
    }
}

/// `utf16_le_to_7bit()`: keep the low 7 bits of each UTF-16 unit, replacing the non-printable ones by '!'; `out[size]` is the terminating NUL.
#[no_mangle]
pub unsafe extern "C" fn rust_efi_utf16_le_to_7bit(inp: *const u16, size: u32, out: *mut u8) {
    unsafe {
        *out.add(size as usize) = 0;

        let mut i = 0;
        while i < size as usize {
            let mut c = (u16::from_le(inp.add(i).read_unaligned()) & 0x7f) as u8;

            // isprint()
            if c != 0 && !(0x20..0x7f).contains(&c) {
                c = b'!';
            }
            *out.add(i) = c;
            i += 1;
        }
    }
}
