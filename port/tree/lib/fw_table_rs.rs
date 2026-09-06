// SPDX-License-Identifier: GPL-2.0-or-later

//! Firmware-table subtable walking -- the Rust behind `lib/fw_table.c`.
//!
//! Replaces: lib/fw_table.c
//!
//! ACPI and ACPI-like tables are a fixed header followed by a run of
//! variable-length subtables, each starting with its own little header
//! carrying a type and a length. This file walks that run, and for each
//! entry whose type matches one the caller asked for, calls the caller's
//! handler. Five table families put the type and length in five different
//! places and at five different widths, which is what all the `match`
//! statements below are for.
//!
//! # THIS FILE HAS NO EXPORTED SYMBOLS, AND THE MACRO THAT LOOKS LIKE ONE
//! # EXPANDS TO NOTHING
//!
//! `cdat_table_parse()` is followed by `EXPORT_SYMBOL_FWTBL_LIB(...)`, which
//! reads like an export and on this project's configuration is not one:
//!
//! ```text
//! IS_ENABLED(CONFIG_ACPI) && !IS_ENABLED(CONFIG_CXL_BUS)      <- true here
//!   -> EXPORT_SYMBOL_ACPI_LIB(x), which is
//!        CONFIG_ACPI_TABLE_LIB=y -> EXPORT_SYMBOL_NS_GPL(x, "ACPI")
//!        CONFIG_ACPI_TABLE_LIB=n -> nothing at all              <- this arm
//!      and __init_or_fwtbl_lib = __init_or_acpilib, which is
//!        CONFIG_ACPI_TABLE_LIB=y -> nothing
//!        CONFIG_ACPI_TABLE_LIB=n -> __init                      <- this arm
//! else
//!   -> EXPORT_SYMBOL_NS_GPL(x, "CXL"), __init_or_fwtbl_lib = nothing
//! ```
//!
//! `CONFIG_ACPI_TABLE_LIB` is a bare `bool` selected by exactly one thing in
//! the whole tree -- `CXL_ACPI` (`drivers/cxl/Kconfig:63`) -- and
//! `CONFIG_CXL_BUS` is unset in both of this project's configs. Read out of
//! the built object rather than from the headers: `build-full/lib/fw_table.o`
//! has a `.text` section of **zero** bytes, `0x3c9` bytes of `.init.text`,
//! no `__export_symbol_*` at all, and `Module.symvers` carries neither
//! symbol.
//!
//! So there are no `kernel::kabi_export!` blocks below and no type pins:
//! there is no CRC for either function, and GOALS.md §2 criterion 4 has
//! nothing to check in this file. Both functions are nonetheless **global**
//! (`nm` reports `T`) because `drivers/acpi/tables.c` and `drivers/cxl/`
//! call them across a translation unit, so they are plain `#[no_mangle]
//! extern "C"` with no export machinery -- the `lib/union_find` shape.
//!
//! # `__init`, and why that is no longer new territory
//!
//! Every function here is `__init` in this configuration: `.init.text`,
//! discarded once boot finishes. `#[link_section = ".init.text"]`
//! reproduces that, and `lib/decompress.c`'s port
//! (`port/tree/lib/decompress_rs.rs`) already ships exactly this
//! arrangement, table in `.init.rodata` and body in `.init.text`. Dropping
//! the attribute would not be a correctness bug; it would leave a page
//! permanently resident that upstream reclaims.
//!
//! It does change what criterion 5 can mean here, and the two halves differ:
//!
//! | symbol | reached? |
//! |---|---|
//! | `acpi_parse_entries_array` | **yes, on every x86 boot.** `drivers/acpi/tables.c`'s `acpi_table_parse_entries_array()` is how MADT and friends are parsed, so booting proves it -- SCOPE.md §4's class B, not class A |
//! | `cdat_table_parse` | **no.** Its only in-tree caller is `drivers/cxl/`, and `CONFIG_CXL_BUS` is unset in both configs. Compiled, linked, unreachable -- the same shape as `check_signature()`'s six BIOS-probe callers that qemu never presents |
//!
//! # The five header shapes, and where each keeps its type and length
//!
//! This is the whole of what the `match`es encode, so it is written once
//! here instead of five times below. All of these are `#pragma pack(1)`
//! (`include/acpi/actbl.h:47`, `actbl1.h:74`, `actbl2.h:67`), so every field
//! read is potentially unaligned and every mirror is `#[repr(C, packed)]`.
//!
//! | family | type field | length field | header size |
//! |---|---|---|---|
//! | `ACPI_SUBTABLE_COMMON` | `u8` @0 | `u8` @1 | 2 |
//! | `ACPI_SUBTABLE_HMAT` | `u16` @0 | `u32` @4 | 8 |
//! | `ACPI_SUBTABLE_PRMT` | *none -- always 0* | `u16` @2 | 4 |
//! | `ACPI_SUBTABLE_CEDT` | `u8` @0 | `u16` @2 | 4 |
//! | `CDAT_SUBTABLE` | `u8` @0 | `u16` @2, **little-endian** | 4 |
//!
//! CDAT is the odd one: the C reads its lengths through `le16_to_cpu()` /
//! `le32_to_cpu()` while every other family reads native, because a CDAT
//! table comes off a device rather than out of firmware. On x86-64 that is a
//! no-op and no test here can tell the difference; `u16::from_le` /
//! `u32::from_le` reproduce it so that a big-endian kernel gets the same
//! answer. Recorded rather than measured -- `logs/floor.md` RAISE 5 wants a
//! big-endian run and this harness has not had one.
//!
//! # Where the arithmetic wraps, and it is reachable rather than theoretical
//!
//! The C does its bounds work on `unsigned long` values converted from
//! pointers, and every one of them wraps by definition. That is not a
//! hypothetical here: `table_len` comes from **the table's own length
//! field**, and `entry_len` from **each subtable's own length field**, both
//! attacker- or firmware-controlled. Under
//! `CONFIG_RUST_OVERFLOW_CHECKS=y` a plain `+` would turn the C's silent
//! wrap into a kernel panic on a malformed table, which is a behaviour
//! change on exactly the input this code exists to survive. So all FOUR
//! address computations are `wrapping_add`, spelled at each site:
//!
//! * `table_header + table_len` -> `table_end`
//! * `table_header + table_size` -> the first entry
//! * `entry.hdr + subtable_len` -> the loop guard
//! * `entry.hdr + entry_len` -> the next entry
//!
//! (This list said "three" and omitted the loop guard until adversarial
//! review counted them, 2026-09-05. The code was already right; the list was
//! not. The reviewer also established the stronger fact the list is a proxy
//! for: built with `-C overflow-checks=on`, the object's ONLY undefined
//! symbol is `_printk` -- no `panic_const_add_overflow` anywhere -- and
//! swapping a single `wrapping_add` for `+` makes one appear. So every
//! overflow-capable operation in this file is wrapping, checked
//! mechanically rather than by reading.)
//!
//! The two counters are `wrapping_add` for a different reason: signed
//! overflow is undefined in C, gcc wraps, and reproducing the wrap is the
//! conservative choice where reproducing the panic would not be. Neither is
//! reachable with a table small enough to exist.
//!
//! # Two integer promotions the C does silently and this file spells out
//!
//! 1. `acpi_get_entry_type()` returns `unsigned long` and is compared
//!    against `proc[i].id`, an `int`. C converts the `int` to
//!    `unsigned long`, sign-extending first -- so a negative `id` becomes a
//!    very large value rather than never matching. `id as usize` in Rust
//!    sign-extends identically.
//! 2. `count` is `int` and `max_entries` is `unsigned int`, so
//!    `count < max_entries` and `count > max_entries` are **unsigned**
//!    comparisons in C. Both are written as unsigned here.
//!
//! # The C's three `return 0;` fall-throughs have no Rust counterpart
//!
//! Each of `acpi_get_entry_type()`, `acpi_get_entry_length()` and
//! `acpi_get_subtable_header_length()` ends with a `return 0;` after a
//! `switch` that already covers all five enumerators. Those three lines are
//! unreachable: `entry->type` is only ever set from
//! `acpi_get_subtable_type()`, which returns one of the five. Measured
//! rather than argued -- `gcov` on the oracle over this port's corpus puts
//! all three at **0 executions** against 208,979 / 104,501 / 16,617 entries
//! to their switches, and they are the only unexecuted lines in the file.
//!
//! A Rust `match` over an exhaustive enum has no fall-through arm to write,
//! so the port simply has nothing there. That is a structural difference
//! with nothing observable behind it -- GOALS.md §5's three questions all
//! answer no -- and it is recorded here so a reader comparing the two files
//! line by line does not read the absence as an omission.
//!
//! # `pr_err`'s argument is `proc->id`, not `proc[i].id`
//!
//! Both diagnostics report the FIRST handler's id regardless of which entry
//! actually failed. That is upstream's, it is very likely a slip, and it is
//! reproduced rather than fixed: nothing outside can observe a difference
//! except the text of a printk, and GOALS.md §5's first question is whether
//! anything outside can observe the difference. Recorded so it is not read
//! as a porting bug.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

/// `-EINVAL`.
const EINVAL: c_int = 22;

// ---------------------------------------------------------------------------
// The ACPICA header mirrors. All `#pragma pack(1)` in the C.
// ---------------------------------------------------------------------------

// Every mirror below carries the C struct's WHOLE geometry, including fields
// this file never reads. `#[allow(dead_code)]` says that deliberately: the
// unread fields are not leftovers, they are what makes
// `rig/layout-check.sh`'s comparison against the built kernel's DWARF mean
// anything, and dropping them would silently change every following field's
// offset. `Copy` is required to be a union member and costs nothing on
// plain-old-data.

/// Mirrors `struct acpi_table_header` (`include/acpi/actbl.h`).
///
/// Only `length` is read here; the rest is carried so the mirror has the C
/// struct's geometry for `rig/layout-check.sh`.
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiTableHeader {
    signature: [c_char; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [c_char; 6],
    oem_table_id: [c_char; 8],
    oem_revision: u32,
    asl_compiler_id: [c_char; 4],
    asl_compiler_revision: u32,
}

/// Mirrors `struct acpi_table_cdat` (`include/acpi/actbl1.h`).
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiTableCdat {
    length: u32,
    revision: u8,
    checksum: u8,
    reserved: [u8; 6],
    sequence: u32,
}

/// Mirrors `struct acpi_subtable_header` (`include/acpi/actbl1.h`).
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiSubtableHeader {
    r#type: u8,
    length: u8,
}

/// Mirrors `struct acpi_hmat_structure` (`include/acpi/actbl1.h`).
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiHmatStructure {
    r#type: u16,
    reserved: u16,
    length: u32,
}

/// Mirrors `struct acpi_prmt_module_header` (`include/acpi/actbl2.h`).
///
/// The only family with no type field at all -- `acpi_get_entry_type()`
/// returns a hard 0 for it.
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiPrmtModuleHeader {
    revision: u16,
    length: u16,
}

/// Mirrors `struct acpi_cedt_header` (`include/acpi/actbl1.h`).
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiCedtHeader {
    r#type: u8,
    reserved: u8,
    length: u16,
}

/// Mirrors `struct acpi_cdat_header` (`include/acpi/actbl1.h`).
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiCdatHeader {
    r#type: u8,
    reserved: u8,
    length: u16,
}

/// Mirrors `union fw_table_header` (`include/linux/fw_table.h`).
#[repr(C)]
pub union FwTableHeader {
    /// The ACPI form: a 36-byte header whose `length` is native-endian.
    pub acpi: AcpiTableHeader,
    /// The CDAT form: a 16-byte header whose `length` is little-endian.
    pub cdat: AcpiTableCdat,
}

/// Mirrors `union acpi_subtable_headers` (`include/linux/fw_table.h`).
#[repr(C)]
pub union AcpiSubtableHeaders {
    /// `struct acpi_subtable_header`.
    pub common: AcpiSubtableHeader,
    /// `struct acpi_hmat_structure`.
    pub hmat: AcpiHmatStructure,
    /// `struct acpi_prmt_module_header`.
    pub prmt: AcpiPrmtModuleHeader,
    /// `struct acpi_cedt_header`.
    pub cedt: AcpiCedtHeader,
    /// `struct acpi_cdat_header`.
    pub cdat: AcpiCdatHeader,
}

/// `acpi_tbl_entry_handler` (`include/linux/fw_table.h`). Nullable in the C;
/// `Option<fn>` has the identical representation.
pub type AcpiTblEntryHandler =
    unsafe extern "C" fn(header: *mut AcpiSubtableHeaders, end: usize) -> c_int;

/// `acpi_tbl_entry_handler_arg` (`include/linux/fw_table.h`).
pub type AcpiTblEntryHandlerArg = unsafe extern "C" fn(
    header: *mut AcpiSubtableHeaders,
    arg: *mut c_void,
    end: usize,
) -> c_int;

/// Mirrors `struct acpi_subtable_proc` (`include/linux/fw_table.h`).
///
/// Caller-owned, and `count` is written back through it, so the layout is
/// part of the contract rather than an implementation detail. Not packed --
/// unlike the ACPICA headers above, this one is an ordinary kernel struct.
#[repr(C)]
pub struct AcpiSubtableProc {
    id: c_int,
    handler: Option<AcpiTblEntryHandler>,
    handler_arg: Option<AcpiTblEntryHandlerArg>,
    arg: *mut c_void,
    count: c_int,
}

extern "C" {
    /// `printk()`'s out-of-line half. `pr_err`/`pr_warn` are macros over it;
    /// the level is the `KERN_SOH "3"` / `KERN_SOH "4"` prefix on the format
    /// string, and this file defines no `pr_fmt`, so the default
    /// `pr_fmt(fmt) fmt` applies and nothing else is prepended.
    fn _printk(fmt: *const c_char, ...) -> c_int;
}

// ---------------------------------------------------------------------------
// `enum acpi_subtable_type` and `struct acpi_subtable_entry`, both file-local
// in the C and therefore free in shape (GOALS.md §5: nothing outside can
// observe either -- no symbol, no caller, not in any signature).
// ---------------------------------------------------------------------------

/// `enum acpi_subtable_type`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubtableType {
    Common,
    Hmat,
    Prmt,
    Cedt,
    Cdat,
}

/// `struct acpi_subtable_entry`. The C passes `&entry` to four helpers; this
/// passes the two fields, which is the same information and avoids a
/// pointer to a stack slot.
#[derive(Clone, Copy)]
struct Entry {
    hdr: *mut AcpiSubtableHeaders,
    ty: SubtableType,
}

/// `strncmp(id, sig, 4) == 0`, reproduced rather than replaced by a 4-byte
/// compare.
///
/// The difference is not cosmetic: `strncmp` stops at the first NUL, so on a
/// two-character `id` it reads three bytes and a flat `memcmp` would read
/// four. Every in-tree caller passes a four-character signature, so the
/// distinction is unreachable -- but it is a read past a NUL, and this port
/// does not introduce one the C does not make.
///
/// # Safety
/// `id` must be valid to read up to 4 bytes from, stopping at a NUL.
#[link_section = ".init.text"]
unsafe fn sig_matches(id: *const c_char, sig: &[u8; 4]) -> bool {
    // SAFETY: caller guarantees `id` is readable to the first NUL or 4 bytes.
    unsafe {
        for (i, &want) in sig.iter().enumerate() {
            let got = *id.add(i) as u8;
            if got != want {
                return false;
            }
            if got == 0 {
                // Both ran out together; strncmp would return 0. Unreachable
                // for a real signature, which has no NUL in its first four
                // bytes, but this is what strncmp does.
                return true;
            }
        }
        true
    }
}

/// `acpi_get_subtable_type()`.
///
/// # Safety
/// `id` must be valid per [`sig_matches`].
#[link_section = ".init.text"]
unsafe fn get_subtable_type(id: *const c_char) -> SubtableType {
    // SAFETY: caller guarantees `id` is readable.
    unsafe {
        if sig_matches(id, b"HMAT") {
            return SubtableType::Hmat;
        }
        if sig_matches(id, b"PRMT") {
            return SubtableType::Prmt;
        }
        if sig_matches(id, b"CEDT") {
            return SubtableType::Cedt;
        }
        if sig_matches(id, b"CDAT") {
            return SubtableType::Cdat;
        }
        SubtableType::Common
    }
}

/// `acpi_get_entry_type()`.
///
/// # Safety
/// `entry.hdr` must be valid to read this family's header from.
#[link_section = ".init.text"]
unsafe fn get_entry_type(entry: Entry) -> usize {
    let h = entry.hdr;
    // SAFETY: caller guarantees `hdr` is readable for this family's header.
    // Each read is `read_unaligned` because the ACPICA structs are
    // `#pragma pack(1)` and a subtable can start at any offset.
    unsafe {
        match entry.ty {
            SubtableType::Common => {
                ptr::read_unaligned(ptr::addr_of!((*h).common.r#type)) as usize
            }
            SubtableType::Hmat => {
                ptr::read_unaligned(ptr::addr_of!((*h).hmat.r#type)) as usize
            }
            SubtableType::Prmt => 0,
            SubtableType::Cedt => {
                ptr::read_unaligned(ptr::addr_of!((*h).cedt.r#type)) as usize
            }
            SubtableType::Cdat => {
                ptr::read_unaligned(ptr::addr_of!((*h).cdat.r#type)) as usize
            }
        }
    }
}

/// `acpi_get_entry_length()`.
///
/// # Safety
/// `entry.hdr` must be valid to read this family's header from.
#[link_section = ".init.text"]
unsafe fn get_entry_length(entry: Entry) -> usize {
    let h = entry.hdr;
    // SAFETY: as [`get_entry_type`].
    unsafe {
        match entry.ty {
            SubtableType::Common => {
                ptr::read_unaligned(ptr::addr_of!((*h).common.length)) as usize
            }
            SubtableType::Hmat => {
                ptr::read_unaligned(ptr::addr_of!((*h).hmat.length)) as usize
            }
            SubtableType::Prmt => {
                ptr::read_unaligned(ptr::addr_of!((*h).prmt.length)) as usize
            }
            SubtableType::Cedt => {
                ptr::read_unaligned(ptr::addr_of!((*h).cedt.length)) as usize
            }
            // The C's `le16_to_cpu()` on a `__force __le16` cast. A no-op on
            // x86-64; reproduced so a big-endian kernel agrees.
            SubtableType::Cdat => {
                u16::from_le(ptr::read_unaligned(ptr::addr_of!((*h).cdat.length))) as usize
            }
        }
    }
}

/// `acpi_get_subtable_header_length()` -- `sizeof` the family's header.
#[link_section = ".init.text"]
fn get_subtable_header_length(ty: SubtableType) -> usize {
    match ty {
        SubtableType::Common => core::mem::size_of::<AcpiSubtableHeader>(),
        SubtableType::Hmat => core::mem::size_of::<AcpiHmatStructure>(),
        SubtableType::Prmt => core::mem::size_of::<AcpiPrmtModuleHeader>(),
        SubtableType::Cedt => core::mem::size_of::<AcpiCedtHeader>(),
        SubtableType::Cdat => core::mem::size_of::<AcpiCdatHeader>(),
    }
}

/// `acpi_table_get_length()`.
///
/// # Safety
/// `header` must be valid to read this family's table header from.
#[link_section = ".init.text"]
unsafe fn table_get_length(ty: SubtableType, header: *mut FwTableHeader) -> usize {
    // SAFETY: caller guarantees `header` is readable.
    unsafe {
        if ty == SubtableType::Cdat {
            // The C's `le32_to_cpu()`; see [`get_entry_length`].
            return u32::from_le(ptr::read_unaligned(ptr::addr_of!((*header).cdat.length)))
                as usize;
        }
        ptr::read_unaligned(ptr::addr_of!((*header).acpi.length)) as usize
    }
}

/// `call_handler()`.
///
/// # Safety
/// `proc_entry` must be valid, and its handler (if any) must be safe to call
/// with `hdr` and `end`.
#[link_section = ".init.text"]
unsafe fn call_handler(
    proc_entry: *mut AcpiSubtableProc,
    hdr: *mut AcpiSubtableHeaders,
    end: usize,
) -> c_int {
    // SAFETY: caller guarantees `proc_entry` is valid.
    unsafe {
        if let Some(h) = (*proc_entry).handler {
            return h(hdr, end);
        }
        if let Some(h) = (*proc_entry).handler_arg {
            return h(hdr, (*proc_entry).arg, end);
        }
        -EINVAL
    }
}

// ---------------------------------------------------------------------------
// The two cross-TU entry points. Neither is exported; see the module docs.
// ---------------------------------------------------------------------------

/// `acpi_parse_entries_array()`: for each `proc_num` find a suitable
/// subtable.
///
/// For each `proc_num` find a subtable with `proc->id` and run
/// `proc->handler` on it. Assumption is that there's only single handler for
/// particular entry id.
///
/// `table_size` is not the size of the complete ACPI table (the length field
/// in the header struct), but only the size of the root table; i.e., the
/// offset from the very first byte of the complete ACPI table, to the first
/// byte of the very first subtable.
///
/// On success returns sum of all matching entries for all proc handlers.
/// Otherwise, `-ENODEV` or `-EINVAL` is returned.
///
/// # Safety
/// `id` must be a readable signature; `table_header` must point at a table
/// of at least `table_size` bytes whose own length field describes it; and
/// `proc` must be valid for `proc_num` entries. Exactly the C's contract:
/// this function trusts the table's self-declared lengths the way the C
/// does, and a malformed table is bounded only by `max_length` and by the
/// loop guard.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn acpi_parse_entries_array(
    id: *mut c_char,
    table_size: usize,
    table_header: *mut FwTableHeader,
    max_length: usize,
    proc: *mut AcpiSubtableProc,
    proc_num: c_int,
    max_entries: c_uint,
) -> c_int {
    // SAFETY: the caller's contract above.
    unsafe {
        let mut count: c_int = 0;

        let ty = get_subtable_type(id);
        let mut table_len = table_get_length(ty, table_header);
        if max_length != 0 && max_length < table_len {
            table_len = max_length;
        }
        // WRAPS, and the C wraps here too: `table_len` is the table's own
        // self-declared length. See the module docs.
        let table_end = (table_header as usize).wrapping_add(table_len);

        /* Parse all entries looking for a match. */

        let mut entry = Entry {
            // Same wrap, same reason.
            hdr: (table_header as usize).wrapping_add(table_size) as *mut AcpiSubtableHeaders,
            ty,
        };
        // Computed once, before the loop, exactly as the C does -- it is a
        // property of the family, not of the entry.
        let subtable_len = get_subtable_header_length(ty);

        while (entry.hdr as usize).wrapping_add(subtable_len) < table_end {
            for i in 0..proc_num {
                let p = proc.add(i as usize);
                // The C compares `unsigned long` against `int`, which
                // sign-extends the `int` first. `as usize` does the same.
                if get_entry_type(entry) != (*p).id as usize {
                    continue;
                }

                // `count < max_entries` is an UNSIGNED comparison in the C.
                if max_entries == 0 || (count as c_uint) < max_entries {
                    if call_handler(p, entry.hdr, table_end) != 0 {
                        return -EINVAL;
                    }
                }

                (*p).count = (*p).count.wrapping_add(1);
                count = count.wrapping_add(1);
                break;
            }

            /*
             * If entry->length is 0, break from this loop to avoid
             * infinite loop.
             */
            let entry_len = get_entry_length(entry);
            if entry_len == 0 {
                // `proc->id`, not `proc[i].id` -- upstream's, reproduced.
                // See the module docs.
                _printk(
                    c"\u{1}3[%4.4s:0x%02x] Invalid zero length\n".as_ptr(),
                    id,
                    (*proc).id,
                );
                return -EINVAL;
            }

            // Same wrap: `entry_len` is the subtable's own declared length.
            entry.hdr =
                (entry.hdr as usize).wrapping_add(entry_len) as *mut AcpiSubtableHeaders;
        }

        // Also an unsigned comparison in the C.
        if max_entries != 0 && (count as c_uint) > max_entries {
            _printk(
                c"\u{1}4[%4.4s:0x%02x] ignored %i entries of %i found\n".as_ptr(),
                id,
                (*proc).id,
                count.wrapping_sub(max_entries as c_int),
                count,
            );
        }

        count
    }
}

/// `cdat_table_parse()`: walk a CDAT table's subtables of one type.
///
/// # Safety
/// `table_header`, if non-null, must point at a CDAT table whose length
/// field describes it, and `handler_arg` must be safe to call with `arg`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn cdat_table_parse(
    ty: c_uint,
    handler_arg: Option<AcpiTblEntryHandlerArg>,
    arg: *mut c_void,
    table_header: *mut AcpiTableCdat,
    length: usize,
) -> c_int {
    // SAFETY: the caller's contract above.
    unsafe {
        let mut proc = AcpiSubtableProc {
            // `enum acpi_cdat_type` has only non-negative enumerators, so gcc
            // gives it `unsigned int`; the C assigns it to an `int` field and
            // this reproduces that conversion rather than hiding it.
            id: ty as c_int,
            handler: None,
            handler_arg,
            arg,
            count: 0,
        };

        if table_header.is_null() {
            return -EINVAL;
        }

        acpi_parse_entries_array(
            c"CDAT".as_ptr().cast_mut(),
            core::mem::size_of::<AcpiTableCdat>(),
            table_header.cast::<FwTableHeader>(),
            length,
            &mut proc,
            1,
            0,
        )
    }
}
