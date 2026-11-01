// SPDX-License-Identifier: GPL-2.0-only

//! Rust replacement for the table logic of `arch/x86/kernel/e820.c` (composite: `e820_glue.c` keeps the rest).
//!
//! IN RUST (every function below keeps the C's name where the C's was a global symbol):
//!   * range-type queries: `e820__mapped_raw_any`, `e820__mapped_any`, `e820__mapped_all`, `e820__get_entry_type`
//!     (and the C's two static scanners);
//!   * `e820__range_add`, `e820__range_remove`, the body of `__e820__range_update` (`e820_range_update_rs`),
//!     the sanitiser `e820__update_table` (body = `e820_update_table_rs`: change-point sort, overlap list, merge),
//!     `e820__update_table_print`, `e820__print_table` (+ `e820_print_type`);
//!   * the firmware copy: `__append_e820_table` (`e820_append_table_raw`), `append_e820_table`,
//!     `e820__memory_setup_default`;
//!   * `e820_search_gap`, `e820__setup_pci_gap`, `e820__end_ram_pfn` (`e820_end_ram_pfn_rs`);
//!   * the `mem=` / `memmap=` early parameters: `parse_memopt`, `parse_memmap_one`, `parse_memmap_opt`.
//!
//! EXPORTS: `e820__mapped_raw_any` and `e820__mapped_any` are `EXPORT_SYMBOL_GPL` upstream; the export and its
//! MODVERSIONS contract (captured from the C definition's DWARF, `kernel::kabi_export!`) live here, so their CRCs
//! are unchanged (`rig/crc-check.sh`).
//!
//! STAYS C (`e820_glue.c`, upstream's file with exactly the functions above removed, `#line` directives keep
//! upstream's file name and line numbers for every remaining BUG_ON): the three tables and their pointers,
//! `pci_mem_start` (+ its `EXPORT_SYMBOL`); the BUG_ON entry wrappers `e820__update_table` / `__e820__range_update` (a BUG_ON plants a bug-table entry
//! naming file and line: `logs/c-entry-rule.md`); everything that touches memblock, `early_memremap`, the resource
//! tree, `firmware_map`, `register_nosave_region`, `acpi_nvs_register`, `kmemdup`, `panic`, `early_printk` or a
//! header-only constant (`MAX_ARCH_PFN`, `ARRAY_SIZE`): `e820__memory_setup_extended`,
//! `e820__register_nosave_regions`, `e820__register_nvs_regions`, `e820__memblock_alloc_reserved`,
//! `e820__reallocate_tables`, `e820__finish_early_params`, `e820__reserve_resources[_late]`, `e820__memory_setup`,
//! `e820__memblock_setup`, `e820__end_of_ram_pfn`, `e820__end_of_low_ram_pfn`, the `e820_type_to_*` helpers.
//!
//! WHEN IT RUNS: single CPU, interrupts off, before the allocator (setup_arch), except the three `.text`
//! (non-`__init`) query functions, which are called any time (`e820__mapped_any` from `init_64.c`,
//! `e820__get_entry_type` from `ioremap.c`) and read the table only.
//!
//! NO PANIC PATH. Every `+ - << >>` the C does on unsigned values is `wrapping_*`; tables are indexed by raw pointer
//! like the C; `rig/uaccess-panic-check.sh` and an `nm` of the object (logs/hooks.md) confirm no `panic*` symbol.
//!
//! MESSAGES: every printk format string and level is the C's, character for character, and is passed to the kernel's
//! own `_printk` (checked by `rig/phase-e/e820_msgs_check.sh`, which compares the strings of the C object with these).
//!
//! Replaces: arch/x86/kernel/e820.c (partly: see above)

use core::ffi::{c_char, c_int, c_void};

// --- constants (checked against the kernel's headers by rig/phase-e/consts_check.py) ----------------------
// C-HEADERS: linux/types.h linux/errno.h asm/e820/types.h asm/e820/api.h asm/setup.h asm/page_types.h uapi/asm/bootparam.h linux/screen_info.h
const E820_TYPE_RAM: u32 = 1; // C: E820_TYPE_RAM
const E820_TYPE_RESERVED: u32 = 2; // C: E820_TYPE_RESERVED
const E820_TYPE_ACPI: u32 = 3; // C: E820_TYPE_ACPI
const E820_TYPE_NVS: u32 = 4; // C: E820_TYPE_NVS
const E820_TYPE_UNUSABLE: u32 = 5; // C: E820_TYPE_UNUSABLE
const E820_TYPE_PMEM: u32 = 7; // C: E820_TYPE_PMEM
const E820_TYPE_PRAM: u32 = 12; // C: E820_TYPE_PRAM
const E820_TYPE_SOFT_RESERVED: u32 = 0xefff_ffff; // C: E820_TYPE_SOFT_RESERVED
const EINVAL: i32 = 22; // C: EINVAL
const PAGE_SHIFT: u32 = 12; // C: PAGE_SHIFT
const LOWMEMSIZE: u64 = 0x9f000; // C: LOWMEMSIZE()
const HIGH_MEMORY: u64 = 0x100000; // C: HIGH_MEMORY
const MAX_GAP_END: u64 = 0x1_0000_0000; // C: 0x100000000ull
/// `sizeof(struct e820_entry)` and of `struct boot_e820_entry` (packed).
const ENTRY_SIZE: usize = 20; // C: sizeof(struct e820_entry)
/// `offsetof(struct e820_table, entries)`.
const TABLE_ENTRIES_OFF: usize = 4; // C: offsetof(struct e820_table, entries)
/// `offsetof(struct boot_params, e820_entries)`.
const BP_E820_ENTRIES: usize = 0x1e8; // C: offsetof(struct boot_params, e820_entries)
/// `offsetof(struct boot_params, e820_table)`.
const BP_E820_TABLE: usize = 0x2d0; // C: offsetof(struct boot_params, e820_table)
/// `offsetof(struct boot_params, alt_mem_k)`.
const BP_ALT_MEM_K: usize = 0x1e0; // C: offsetof(struct boot_params, alt_mem_k)
/// `offsetof(struct boot_params, screen_info.ext_mem_k)`.
const BP_EXT_MEM_K: usize = 0x2; // C: offsetof(struct boot_params, screen_info.ext_mem_k)

// --- the C structs this file reads and writes ------------------------------------------------------------

/// Mirrors `struct e820_entry` (and `struct boot_e820_entry`: same layout; both `__attribute__((packed))`, 20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct KernelE820Entry {
    /// `addr`.
    pub addr: u64,
    /// `size`.
    pub size: u64,
    /// `type` (`enum e820_type`, unsigned: one value is 0xefffffff).
    pub typ: u32,
}

/// `struct e820_table`: `nr_entries` then `E820_MAX_ENTRIES` entries (the count is config-dependent and comes
/// from `e820_table_max_entries`, which the C glue defines from `ARRAY_SIZE`).
#[repr(C)]
pub struct E820Table {
    /// `nr_entries`.
    pub nr_entries: u32,
    /// `entries[]`.
    pub entries: [KernelE820Entry; 0],
}

/// Mirrors `struct change_member` (the glue's scratch array element).
#[repr(C)]
pub struct E820ChangeMember {
    /// `entry`: the original entry.
    pub entry: *mut KernelE820Entry,
    /// `addr`: the address of this change point.
    pub addr: u64,
}

#[cfg(not(kani))]
extern "C" {
    /// `struct e820_table *e820_table`.
    static mut e820_table: *mut E820Table;
    /// `ARRAY_SIZE(e820_table->entries)`, defined by the glue (a build-time constant of the kernel's headers).
    static e820_table_max_entries: u32;
    /// `pci_mem_start`.
    static mut pci_mem_start: u64;
    /// `max_pfn`.
    static max_pfn: u64;
    /// `userdef` of the C (static there, global here: the glue's `e820__finish_early_params` reads it).
    static mut e820_userdef: i32;
    #[cfg(CONFIG_MEMORY_HOTPLUG)]
    static mut max_mem_size: u64;
    /// `boot_params`, addressed by offset.
    static boot_params: u8;

    fn _printk(fmt: *const c_char, ...) -> c_int;
    fn sort(
        base: *mut c_void,
        num: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
        swap: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
    );
    fn memparse(ptr: *const c_char, retptr: *mut *mut c_char) -> u64;
    fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> u64;
    /// The glue's entry wrapper (`nr_entries < 2`, `BUG_ON`, then `e820_update_table_rs`).
    fn e820__update_table(table: *mut E820Table) -> c_int;
}

/// `printk()`: the kernel's own `_printk` with the C's literal format (level byte included).
#[cfg(not(kani))]
macro_rules! printk {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        _printk($fmt.as_ptr() $(, $arg)*)
    };
}

// Under Kani (`rig/e820-kani`) the kernel's variables and callees are stand-ins: printk is dropped (its arguments are
// still evaluated), `sort` is an insertion sort over the same comparator, memparse / simple_strtoull are unconstrained.
#[cfg(kani)]
macro_rules! printk {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        $( let _ = $arg; )*
        0 as c_int
    }};
}
#[cfg(kani)]
static mut e820_table: *mut E820Table = core::ptr::null_mut();
#[cfg(kani)]
static e820_table_max_entries: u32 = 4;
#[cfg(kani)]
static mut pci_mem_start: u64 = 0;
#[cfg(kani)]
static max_pfn: u64 = 0;
#[cfg(kani)]
static mut e820_userdef: i32 = 0;
#[cfg(kani)]
static boot_params: u8 = 0;
#[cfg(kani)]
unsafe fn sort(
    base: *mut c_void,
    num: usize,
    size: usize,
    cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    _swap: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
) {
    // SAFETY: Kani stand-in, elements are `size` bytes (pointers).
    unsafe {
        let b = base.cast::<u8>();
        let mut i = 1usize;
        while i < num {
            let mut j = i;
            while j > 0 && cmp(b.add((j - 1) * size).cast(), b.add(j * size).cast()) > 0 {
                core::ptr::swap_nonoverlapping(b.add((j - 1) * size), b.add(j * size), size);
                j -= 1;
            }
            i += 1;
        }
    }
}
#[cfg(kani)]
unsafe fn memparse(_ptr: *const c_char, _retptr: *mut *mut c_char) -> u64 {
    kani::any()
}
#[cfg(kani)]
unsafe fn simple_strtoull(_cp: *const c_char, _endp: *mut *mut c_char, _base: u32) -> u64 {
    kani::any()
}
#[cfg(kani)]
unsafe fn e820__update_table(table: *mut E820Table) -> c_int {
    // SAFETY: Kani stand-in for the glue's wrapper: scratch arrays sized for max 4.
    unsafe {
        static mut CPL: [E820ChangeMember; 8] = [const { E820ChangeMember { entry: core::ptr::null_mut(), addr: 0 } }; 8];
        static mut CP: [*mut E820ChangeMember; 8] = [core::ptr::null_mut(); 8];
        static mut OL: [*mut KernelE820Entry; 4] = [core::ptr::null_mut(); 4];
        static mut NE: [KernelE820Entry; 4] = [KernelE820Entry { addr: 0, size: 0, typ: 0 }; 4];
        if (*table).nr_entries < 2 {
            return -1;
        }
        e820_update_table_rs(table, 4, (&raw mut CPL).cast(), (&raw mut CP).cast(), (&raw mut OL).cast(), (&raw mut NE).cast())
    }
}
#[cfg(kani)]
unsafe fn e820_range_update_entry(start: u64, size: u64, old_type: u32, new_type: u32) -> u64 {
    // SAFETY: Kani stand-in for the glue's e820__range_update() on the main table.
    unsafe { e820_range_update_rs(e820_table, start, size, old_type, new_type) }
}

// --- small helpers ---------------------------------------------------------------------------------------

/// `&table->entries[i]`.
#[inline(always)]
unsafe fn ent(t: *mut E820Table, i: usize) -> *mut KernelE820Entry {
    // SAFETY: caller keeps `i` inside the table, as the C does.
    unsafe { t.cast::<u8>().add(TABLE_ENTRIES_OFF).cast::<KernelE820Entry>().add(i) }
}

/// The C's `enum e820_type` for `e820_print_type()`: prints with `pr_cont`.
#[inline(always)]
unsafe fn print_type(typ: u32) {
    // SAFETY: `_printk` with the C's own literal formats; the one `%u` gets a `u32`.
    unsafe {
        match typ {
            E820_TYPE_RAM => printk!(c"\x01cusable"),
            E820_TYPE_RESERVED => printk!(c"\x01creserved"),
            E820_TYPE_SOFT_RESERVED => printk!(c"\x01csoft reserved"),
            E820_TYPE_ACPI => printk!(c"\x01cACPI data"),
            E820_TYPE_NVS => printk!(c"\x01cACPI NVS"),
            E820_TYPE_UNUSABLE => printk!(c"\x01cunusable"),
            E820_TYPE_PMEM | E820_TYPE_PRAM => printk!(c"\x01cpersistent (type %u)", typ),
            _ => printk!(c"\x01ctype %u", typ),
        };
    }
}

// --- range-type queries ------------------------------------------------------------------------------------

/// `_e820__mapped_any()`.
#[inline(always)]
unsafe fn mapped_any(table: *mut E820Table, start: u64, end: u64, typ: u32) -> bool {
    // SAFETY: the table is the kernel's; `i` stays below `nr_entries`.
    unsafe {
        let mut i: u32 = 0;
        while i < (*table).nr_entries {
            let e = ent(table, i as usize);
            i = i.wrapping_add(1);
            if typ != 0 && (*e).typ != typ {
                continue;
            }
            if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) <= start {
                continue;
            }
            return true;
        }
        false
    }
}

/// `e820__mapped_raw_any()` (`EXPORT_SYMBOL_GPL` in the glue): any part of `[start,end)` mapped with `type` in the firmware table.
///
/// # Safety
/// After `e820_table_firmware` is set (static initialiser).
#[no_mangle]
pub unsafe extern "C" fn e820__mapped_raw_any(start: u64, end: u64, typ: u32) -> bool {
    #[cfg(not(kani))]
    extern "C" {
        static mut e820_table_firmware: *mut E820Table;
    }
    #[cfg(kani)]
    static mut e820_table_firmware: *mut E820Table = core::ptr::null_mut();
    // SAFETY: plain read of the pointer variable.
    unsafe { mapped_any(e820_table_firmware, start, end, typ) }
}

/// `e820__mapped_any()` (`EXPORT_SYMBOL_GPL` in the glue).
///
/// # Safety
/// As above.
#[no_mangle]
pub unsafe extern "C" fn e820__mapped_any(start: u64, end: u64, typ: u32) -> bool {
    // SAFETY: plain read of the pointer variable.
    unsafe { mapped_any(e820_table, start, end, typ) }
}

// The exports' MODVERSIONS contract: the C definition's type strings (--symtypes form), captured from the
// pristine C compiled with this kernel's configuration (logs/hooks.md, e820 record). Not hand-written.
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_rule!("type_string", "t#__u64",
    "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_rule!("type_string", "t#u64", "typedef_type u64 { t#__u64 }");
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_rule!("type_string", "t#bool", "typedef_type bool { base_type _Bool byte_size(1) encoding(2) }");
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_rule!("type_string", "e#e820_type",
    "enumeration_type e820_type { enumerator E820_TYPE_RAM = 1 , enumerator E820_TYPE_RESERVED = 2 , enumerator E820_TYPE_ACPI = 3 , enumerator E820_TYPE_NVS = 4 , enumerator E820_TYPE_UNUSABLE = 5 , enumerator E820_TYPE_PMEM = 7 , enumerator E820_TYPE_PRAM = 12 , enumerator E820_TYPE_SOFT_RESERVED = 4026531839 } byte_size(4)");
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_export! {
    e820__mapped_raw_any,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#u64 start , formal_parameter t#u64 end , formal_parameter e#e820_type type ) -> t#bool",
}
#[cfg(not(any(userspace_test, kani)))]
kernel::kabi_export! {
    e820__mapped_any,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#u64 start , formal_parameter t#u64 end , formal_parameter e#e820_type type ) -> t#bool",
}

/// `__e820__mapped_all()`: the entry that completes coverage of `[start,end)`, or null.
#[inline(always)]
unsafe fn mapped_all(start: u64, end: u64, typ: u32) -> *mut KernelE820Entry {
    // SAFETY: as `mapped_any`.
    unsafe {
        let mut start = start;
        let mut i: u32 = 0;
        while i < (*e820_table).nr_entries {
            let e = ent(e820_table, i as usize);
            i = i.wrapping_add(1);
            if typ != 0 && (*e).typ != typ {
                continue;
            }
            // Is the region (part) in overlap with the current region?
            if (*e).addr >= end || (*e).addr.wrapping_add((*e).size) <= start {
                continue;
            }
            // If the region is at the beginning of <start,end> we move 'start' to the end of the region.
            if (*e).addr <= start {
                start = (*e).addr.wrapping_add((*e).size);
            }
            // If 'start' is now at or beyond 'end', we're done, full coverage exists.
            if start >= end {
                return e;
            }
        }
        core::ptr::null_mut()
    }
}

/// `e820__mapped_all()`: is the entire range `<start,end>` mapped with `type`?
///
/// # Safety
/// Early boot, as the C (`__init`).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__mapped_all(start: u64, end: u64, typ: u32) -> bool {
    // SAFETY: as the callee.
    unsafe { !mapped_all(start, end, typ).is_null() }
}

/// `e820__get_entry_type()`: the type of the entry covering `<start,end>`, or `-EINVAL`.
///
/// # Safety
/// Reads the table.
#[no_mangle]
pub unsafe extern "C" fn e820__get_entry_type(start: u64, end: u64) -> c_int {
    // SAFETY: as the callee.
    unsafe {
        let e = mapped_all(start, end, 0);
        if e.is_null() {
            -EINVAL
        } else {
            (*e).typ as c_int
        }
    }
}

// --- adding ----------------------------------------------------------------------------------------------

/// `__e820__range_add()`.
#[inline(always)]
unsafe fn range_add(table: *mut E820Table, start: u64, size: u64, typ: u32) {
    // SAFETY: the index is checked against the table size first, like the C.
    unsafe {
        let x = (*table).nr_entries as i32;
        // C: `x >= ARRAY_SIZE(table->entries)` compares an int with a size_t.
        if (x as i64 as u64) >= e820_table_max_entries as u64 {
            printk!(c"\x013too many entries; ignoring [mem %#010llx-%#010llx]\n",
                start,
                start.wrapping_add(size).wrapping_sub(1),
            );
            return;
        }
        let e = ent(table, x as usize);
        (*e).addr = start;
        (*e).size = size;
        (*e).typ = typ;
        (*table).nr_entries = (*table).nr_entries.wrapping_add(1);
    }
}

/// `e820__range_add()`: add a memory region to the kernel E820 map.
///
/// # Safety
/// Early boot, single CPU.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__range_add(start: u64, size: u64, typ: u32) {
    // SAFETY: as the callee.
    unsafe { range_add(e820_table, start, size, typ) }
}

/// `e820__print_table()`.
///
/// # Safety
/// Early boot; `who` is a NUL-terminated string.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__print_table(who: *mut c_char) {
    // SAFETY: as the C.
    unsafe {
        let mut i: i32 = 0;
        while (i as u32) < (*e820_table).nr_entries {
            let e = ent(e820_table, i as usize);
            printk!(c"\x016%s: [mem %#018Lx-%#018Lx] ",
                who,
                (*e).addr,
                (*e).addr.wrapping_add((*e).size).wrapping_sub(1),
            );
            print_type((*e).typ);
            printk!(c"\x01c\n");
            i = i.wrapping_add(1);
        }
    }
}

// --- sanitising ------------------------------------------------------------------------------------------

/// `e820_nomerge()`: types that mark distinct platform ranges and are never merged.
#[inline(always)]
fn nomerge(typ: u32) -> bool {
    typ == E820_TYPE_PRAM || typ == E820_TYPE_SOFT_RESERVED
}

/// `cpcompare()`: change points by address, and at equal address a region END after a region START.
///
/// # Safety
/// `a` and `b` point at two elements of the change-point pointer array.
unsafe extern "C" fn cpcompare(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the `sort()` contract: pointers to elements of `change_point[]`.
    unsafe {
        let ap = *a.cast::<*const E820ChangeMember>();
        let bp = *b.cast::<*const E820ChangeMember>();
        let (aa, ba) = ((*ap).addr, (*bp).addr);
        if aa != ba {
            return if aa > ba { 1 } else { -1 };
        }
        ((aa != (*(*ap).entry).addr) as c_int).wrapping_sub((ba != (*(*bp).entry).addr) as c_int)
    }
}

/// The body of `e820__update_table()` after the glue's `nr_entries < 2` return and `BUG_ON(nr_entries > max)`:
/// sanitise `table` (remove overlaps, resolve conflicting types in favour of the highest number, merge adjacent
/// equal ranges). Returns 0, or -1 if an entry wraps around zero.
///
/// `cpl`, `cp`, `ol` and `ne` are the glue's `change_point_list[2*max]`, `change_point[2*max]`,
/// `overlap_list[max]` and `new_entries[max]` scratch arrays (`__initdata`).
///
/// # Safety
/// Early boot, single CPU; `2 <= nr_entries <= max`; the scratch arrays have the sizes above.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820_update_table_rs(
    table: *mut E820Table,
    max_nr_entries: u32,
    cpl: *mut E820ChangeMember,
    cp: *mut *mut E820ChangeMember,
    ol: *mut *mut KernelE820Entry,
    ne: *mut KernelE820Entry,
) -> c_int {
    // SAFETY: indices are bounded exactly as in the C (`2*nr` change points, `nr` overlaps, `< max` new entries).
    unsafe {
        let nr = (*table).nr_entries;

        // Bail out if we find any unreasonable addresses in the map:
        let mut i: u32 = 0;
        while i < nr {
            let e = ent(table, i as usize);
            if (*e).addr.wrapping_add((*e).size) < (*e).addr {
                return -1;
            }
            i = i.wrapping_add(1);
        }

        // Create pointers for initial change-point information (for sorting):
        i = 0;
        while i < nr.wrapping_mul(2) {
            *cp.add(i as usize) = cpl.add(i as usize);
            i = i.wrapping_add(1);
        }

        // Record all known change-points (starting and ending addresses), omitting empty memory regions:
        let mut chg_idx: u32 = 0;
        i = 0;
        while i < nr {
            let e = ent(table, i as usize);
            if (*e).size != 0 {
                (**cp.add(chg_idx as usize)).addr = (*e).addr;
                (**cp.add(chg_idx as usize)).entry = e;
                chg_idx = chg_idx.wrapping_add(1);
                (**cp.add(chg_idx as usize)).addr = (*e).addr.wrapping_add((*e).size);
                (**cp.add(chg_idx as usize)).entry = e;
                chg_idx = chg_idx.wrapping_add(1);
            }
            i = i.wrapping_add(1);
        }
        let chg_nr = chg_idx;

        // Sort change-point list by memory addresses (low -> high):
        sort(
            cp.cast(),
            chg_nr as usize,
            core::mem::size_of::<*mut E820ChangeMember>(),
            cpcompare,
            None,
        );

        // Create a new memory map, removing overlaps:
        let mut overlap_entries: u32 = 0; // Number of entries in the overlap table
        let mut new_nr_entries: u32 = 0; // Index for creating new map entries
        let mut last_type: u32 = 0; // Start with undefined memory type
        let mut last_addr: u64 = 0; // Start with 0 as last starting address

        // Loop through change-points, determining effect on the new map:
        chg_idx = 0;
        while chg_idx < chg_nr {
            let c = *cp.add(chg_idx as usize);
            // Keep track of all overlapping entries
            if (*c).addr == (*(*c).entry).addr {
                // Add map entry to overlap list (> 1 entry implies an overlap)
                *ol.add(overlap_entries as usize) = (*c).entry;
                overlap_entries = overlap_entries.wrapping_add(1);
            } else {
                // Remove entry from list (order independent, so swap with last):
                i = 0;
                while i < overlap_entries {
                    if *ol.add(i as usize) == (*c).entry {
                        *ol.add(i as usize) = *ol.add(overlap_entries.wrapping_sub(1) as usize);
                    }
                    i = i.wrapping_add(1);
                }
                overlap_entries = overlap_entries.wrapping_sub(1);
            }
            // If there are overlapping entries, decide which "type" to use (larger value takes precedence).
            let mut current_type: u32 = 0;
            i = 0;
            while i < overlap_entries {
                if (**ol.add(i as usize)).typ > current_type {
                    current_type = (**ol.add(i as usize)).typ;
                }
                i = i.wrapping_add(1);
            }

            // Continue building up new map based on this information:
            if current_type != last_type || nomerge(current_type) {
                if last_type != 0 {
                    (*ne.add(new_nr_entries as usize)).size = (*c).addr.wrapping_sub(last_addr);
                    // Move forward only if the new size was non-zero:
                    if (*ne.add(new_nr_entries as usize)).size != 0 {
                        // No more space left for new entries?
                        new_nr_entries = new_nr_entries.wrapping_add(1);
                        if new_nr_entries >= max_nr_entries {
                            break;
                        }
                    }
                }
                if current_type != 0 {
                    (*ne.add(new_nr_entries as usize)).addr = (*c).addr;
                    (*ne.add(new_nr_entries as usize)).typ = current_type;
                    last_addr = (*c).addr;
                }
                last_type = current_type;
            }
            chg_idx = chg_idx.wrapping_add(1);
        }

        // Copy the new entries into the original location:
        #[cfg(not(kani))]
        core::ptr::copy_nonoverlapping(
            ne.cast::<u8>(),
            ent(table, 0).cast::<u8>(),
            (new_nr_entries as usize).wrapping_mul(ENTRY_SIZE),
        );
        // Kani models the byte copy of a whole `KernelE820Entry` array poorly; the same copy entry by entry.
        #[cfg(kani)]
        {
            let mut k = 0usize;
            while k < new_nr_entries as usize {
                *ent(table, k) = *ne.add(k);
                k += 1;
            }
        }
        (*table).nr_entries = new_nr_entries;

        0
    }
}

/// `__append_e820_table()`: add the boot-protocol entries to the table; -1 on a 64-bit overflow.
///
/// # Safety
/// `entries` points at `nr_entries` `struct boot_e820_entry` (packed, 20 bytes).
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820_append_table_raw(entries: *const KernelE820Entry, nr_entries: u32) -> c_int {
    // SAFETY: as the C.
    unsafe {
        let mut e = entries;
        let mut n = nr_entries;
        while n != 0 {
            let start = (*e).addr;
            let size = (*e).size;
            let end = start.wrapping_add(size).wrapping_sub(1);
            let typ = (*e).typ;

            // Ignore the entry on 64-bit overflow:
            if start > end && size != 0 {
                return -1;
            }

            range_add(e820_table, start, size, typ);

            e = e.add(1);
            n = n.wrapping_sub(1);
        }
        0
    }
}

/// `append_e820_table()`: only one memory region (or none)? Ignore it.
#[inline(always)]
unsafe fn append_e820_table(entries: *const KernelE820Entry, nr_entries: u32) -> c_int {
    if nr_entries < 2 {
        return -1;
    }
    // SAFETY: as the callee.
    unsafe { e820_append_table_raw(entries, nr_entries) }
}

// --- update / remove ---------------------------------------------------------------------------------------

/// The body of `__e820__range_update()` after the glue's `BUG_ON(old_type == new_type)`.
///
/// # Safety
/// Early boot, single CPU; `old_type != new_type`.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820_range_update_rs(
    table: *mut E820Table,
    start: u64,
    size: u64,
    old_type: u32,
    new_type: u32,
) -> u64 {
    // SAFETY: as the C: entries are indexed below `nr_entries`, re-read each pass because `range_add` grows it.
    unsafe {
        let mut size = size;
        let mut real_updated_size: u64 = 0;

        if size > (u64::MAX - start) {
            size = u64::MAX - start;
        }

        let end = start.wrapping_add(size);
        printk!(c"\x017e820: update [mem %#010Lx-%#010Lx] ", start, end.wrapping_sub(1));
        print_type(old_type);
        printk!(c"\x01c ==> ");
        print_type(new_type);
        printk!(c"\x01c\n");

        let mut i: u32 = 0;
        while i < (*table).nr_entries {
            let e = ent(table, i as usize);
            i = i.wrapping_add(1);

            if (*e).typ != old_type {
                continue;
            }

            let entry_end = (*e).addr.wrapping_add((*e).size);

            // Completely covered by new range?
            if (*e).addr >= start && entry_end <= end {
                (*e).typ = new_type;
                real_updated_size = real_updated_size.wrapping_add((*e).size);
                continue;
            }

            // New range is completely covered?
            if (*e).addr < start && entry_end > end {
                range_add(table, start, size, new_type);
                range_add(table, end, entry_end.wrapping_sub(end), (*e).typ);
                (*e).size = start.wrapping_sub((*e).addr);
                real_updated_size = real_updated_size.wrapping_add(size);
                continue;
            }

            // Partially covered:
            let final_start = if start > (*e).addr { start } else { (*e).addr };
            let final_end = if end < entry_end { end } else { entry_end };
            if final_start >= final_end {
                continue;
            }

            range_add(table, final_start, final_end.wrapping_sub(final_start), new_type);

            real_updated_size = real_updated_size.wrapping_add(final_end.wrapping_sub(final_start));

            // Left range could be head or tail, so need to update its size first:
            (*e).size = (*e).size.wrapping_sub(final_end.wrapping_sub(final_start));
            if (*e).addr < final_start {
                continue;
            }

            (*e).addr = final_end;
        }
        real_updated_size
    }
}

/// `e820__range_remove()`: remove a range of memory from the E820 table.
///
/// # Safety
/// Early boot, single CPU.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__range_remove(start: u64, size: u64, old_type: u32, check_type: bool) -> u64 {
    // SAFETY: as `e820_range_update_rs`.
    unsafe {
        let mut size = size;
        let mut real_removed_size: u64 = 0;

        if size > (u64::MAX - start) {
            size = u64::MAX - start;
        }

        let end = start.wrapping_add(size);
        printk!(c"\x017e820: remove [mem %#010Lx-%#010Lx] ", start, end.wrapping_sub(1));
        if check_type {
            print_type(old_type);
        }
        printk!(c"\x01c\n");

        let mut i: i32 = 0;
        while (i as u32) < (*e820_table).nr_entries {
            let e = ent(e820_table, i as usize);
            i = i.wrapping_add(1);

            if check_type && (*e).typ != old_type {
                continue;
            }

            let entry_end = (*e).addr.wrapping_add((*e).size);

            // Completely covered?
            if (*e).addr >= start && entry_end <= end {
                real_removed_size = real_removed_size.wrapping_add((*e).size);
                core::ptr::write_bytes(e.cast::<u8>(), 0, ENTRY_SIZE);
                continue;
            }

            // Is the new range completely covered?
            if (*e).addr < start && entry_end > end {
                range_add(e820_table, end, entry_end.wrapping_sub(end), (*e).typ);
                (*e).size = start.wrapping_sub((*e).addr);
                real_removed_size = real_removed_size.wrapping_add(size);
                continue;
            }

            // Partially covered:
            let final_start = if start > (*e).addr { start } else { (*e).addr };
            let final_end = if end < entry_end { end } else { entry_end };
            if final_start >= final_end {
                continue;
            }

            real_removed_size = real_removed_size.wrapping_add(final_end.wrapping_sub(final_start));

            // Left range could be head or tail, so need to update the size first:
            (*e).size = (*e).size.wrapping_sub(final_end.wrapping_sub(final_start));
            if (*e).addr < final_start {
                continue;
            }

            (*e).addr = final_end;
        }
        real_removed_size
    }
}

/// `e820__update_table_print()`.
///
/// # Safety
/// Early boot, single CPU.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__update_table_print() {
    // SAFETY: the glue's wrapper, then `e820__print_table`.
    unsafe {
        if e820__update_table(e820_table) != 0 {
            return;
        }
        printk!(c"\x016modified physical RAM map:\n");
        e820__print_table(c"modified".as_ptr().cast_mut());
    }
}

// --- the PCI gap -----------------------------------------------------------------------------------------

/// `e820_search_gap()`: search for a gap in the E820 memory space from 0 to MAX_GAP_END (4GB).
#[inline(always)]
unsafe fn search_gap(gapstart: &mut u64, gapsize: &mut u64) -> c_int {
    // SAFETY: indices stay in `0..nr_entries`.
    unsafe {
        let mut last: u64 = MAX_GAP_END;
        let mut i: i32 = (*e820_table).nr_entries as i32;
        let mut found: c_int = 0;

        loop {
            i = i.wrapping_sub(1);
            if i < 0 {
                break;
            }
            let e = ent(e820_table, i as usize);
            let start = (*e).addr;
            let end = start.wrapping_add((*e).size);

            // Since "last" is at most 4GB, we know we'll fit in 32 bits if this condition is true:
            if last > end {
                let gap = last.wrapping_sub(end);

                if gap >= *gapsize {
                    *gapsize = gap;
                    *gapstart = end;
                    found = 1;
                }
            }
            if start < last {
                last = start;
            }
        }
        found
    }
}

/// `e820__setup_pci_gap()`: the biggest gap in the low 32 bits of the E820 memory space, for the PCI subsystem.
///
/// # Safety
/// Single CPU, after `max_pfn` is set.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__setup_pci_gap() {
    // SAFETY: as the C.
    unsafe {
        let mut gapstart: u64 = 0;
        let mut gapsize: u64 = 0x400000;
        let found = search_gap(&mut gapstart, &mut gapsize);

        if found == 0 {
            // CONFIG_X86_64 (the only arm this file is built for)
            gapstart = (max_pfn << PAGE_SHIFT).wrapping_add(1024 * 1024);
            printk!(c"\x013Cannot find an available gap in the 32-bit address range\n");
            printk!(c"\x013PCI devices with unassigned 32-bit BARs may not work!\n");
        }

        // e820__reserve_resources_late() protects stolen RAM already:
        pci_mem_start = gapstart;

        printk!(c"\x016[mem %#010lx-%#010lx] available for PCI devices\n",
            gapstart,
            gapstart.wrapping_add(gapsize).wrapping_sub(1),
        );
    }
}

// --- highest RAM pfn -------------------------------------------------------------------------------------

/// `e820__end_ram_pfn()`: the highest page frame number we have available. The glue passes `MAX_ARCH_PFN`
/// (a header expression that reads the 5-level paging feature bit) as `max_arch_pfn`.
///
/// # Safety
/// Early boot, single CPU.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820_end_ram_pfn_rs(limit_pfn: u64, max_arch_pfn: u64) -> u64 {
    // SAFETY: as the C.
    unsafe {
        let mut last_pfn: u64 = 0;
        let mut i: i32 = 0;
        while (i as u32) < (*e820_table).nr_entries {
            let e = ent(e820_table, i as usize);
            i = i.wrapping_add(1);

            if (*e).typ != E820_TYPE_RAM && (*e).typ != E820_TYPE_ACPI {
                continue;
            }

            let start_pfn = (*e).addr >> PAGE_SHIFT;
            let end_pfn = (*e).addr.wrapping_add((*e).size) >> PAGE_SHIFT;

            if start_pfn >= limit_pfn {
                continue;
            }
            if end_pfn > limit_pfn {
                last_pfn = limit_pfn;
                break;
            }
            if end_pfn > last_pfn {
                last_pfn = end_pfn;
            }
        }

        if last_pfn > max_arch_pfn {
            last_pfn = max_arch_pfn;
        }

        printk!(c"\x016last_pfn = %#lx max_arch_pfn = %#lx\n", last_pfn, max_arch_pfn);
        last_pfn
    }
}

// --- the boot-protocol map -------------------------------------------------------------------------------

/// `e820__memory_setup_default()`: pass the firmware (bootloader) E820 map to the kernel and process it.
///
/// # Safety
/// Early boot, single CPU, `boot_params` copied.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn e820__memory_setup_default() -> *mut c_char {
    // SAFETY: `boot_params` is the kernel's; offsets are the C struct's (consts_check.py).
    unsafe {
        let bp = &raw const boot_params;
        let mut who: *const c_char = c"BIOS-e820".as_ptr();

        // Try to copy the BIOS-supplied E820-map.
        // Otherwise fake a memory map; one section from 0k->640k, the next section from 1mb->appropriate_mem_k
        let n = bp.add(BP_E820_ENTRIES).read() as u32;
        if append_e820_table(bp.add(BP_E820_TABLE).cast::<KernelE820Entry>(), n) < 0 {
            let alt_mem_k = bp.add(BP_ALT_MEM_K).cast::<u32>().read();
            let ext_mem_k = bp.add(BP_EXT_MEM_K).cast::<u16>().read();
            let mem_size: u64;

            // Compare results from other methods and take the one that gives more RAM:
            if alt_mem_k < ext_mem_k as u32 {
                mem_size = ext_mem_k as u64;
                who = c"BIOS-88".as_ptr();
            } else {
                mem_size = alt_mem_k as u64;
                who = c"BIOS-e801".as_ptr();
            }

            (*e820_table).nr_entries = 0;
            range_add(e820_table, 0, LOWMEMSIZE, E820_TYPE_RAM);
            range_add(e820_table, HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);
        }

        // We just appended a lot of ranges, sanitize the table:
        e820__update_table(e820_table);

        who.cast_mut()
    }
}

// --- the mem= and memmap= early parameters -----------------------------------------------------------------

/// `strcmp(p, lit) == 0` for a NUL-free ASCII `lit`.
#[inline(always)]
unsafe fn streq(p: *const c_char, lit: &[u8]) -> bool {
    // SAFETY: `p` is a NUL-terminated string; the loop stops at the first difference or the NUL.
    unsafe {
        let mut i = 0usize;
        while i < lit.len() {
            if *p.add(i) as u8 != lit[i] {
                return false;
            }
            i += 1;
        }
        *p.add(i) == 0
    }
}

/// `parse_memopt()`: the `mem=` early parameter. (`mem=nopentium` is the 32-bit-only branch: warns and fails here.)
///
/// # Safety
/// Early boot (`parse_early_param`), `p` NULL or a NUL-terminated string.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn parse_memopt(p: *mut c_char) -> c_int {
    // SAFETY: as the C.
    unsafe {
        if p.is_null() {
            return -EINVAL;
        }

        if streq(p, b"nopentium") {
            printk!(c"\x014mem=nopentium ignored! (only supported on x86_32)\n");
            return -EINVAL;
        }

        e820_userdef = 1;
        let mut pp: *mut c_char = p;
        let mem_size = memparse(pp, &mut pp);

        // Don't remove all memory when getting "mem={invalid}" parameter:
        if mem_size == 0 {
            return -EINVAL;
        }

        e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, true);

        #[cfg(CONFIG_MEMORY_HOTPLUG)]
        {
            max_mem_size = mem_size;
        }

        0
    }
}

/// `parse_memmap_one()`: one `memmap=` item.
#[inline(always)]
unsafe fn parse_memmap_one(p: *mut c_char) -> c_int {
    // SAFETY: as the C; `p` and every pointer `memparse` returns lie inside the NUL-terminated string.
    unsafe {
        if p.is_null() {
            return -EINVAL;
        }

        // strncmp(p, "exactmap", 8) == 0
        {
            let lit = b"exactmap";
            let mut i = 0usize;
            let mut same = true;
            while i < 8 {
                if *p.add(i) as u8 != lit[i] {
                    same = false;
                    break;
                }
                i += 1;
            }
            if same {
                (*e820_table).nr_entries = 0;
                e820_userdef = 1;
                return 0;
            }
        }

        let oldp = p;
        let mut p = p;
        let mem_size = memparse(p, &mut p);
        if p == oldp {
            return -EINVAL;
        }

        e820_userdef = 1;
        let c = *p as u8;
        if c == b'@' {
            let start_at = memparse(p.add(1), &mut p);
            e820__range_add(start_at, mem_size, E820_TYPE_RAM);
        } else if c == b'#' {
            let start_at = memparse(p.add(1), &mut p);
            e820__range_add(start_at, mem_size, E820_TYPE_ACPI);
        } else if c == b'$' {
            let start_at = memparse(p.add(1), &mut p);
            e820__range_add(start_at, mem_size, E820_TYPE_RESERVED);
        } else if c == b'!' {
            let start_at = memparse(p.add(1), &mut p);
            e820__range_add(start_at, mem_size, E820_TYPE_PRAM);
        } else if c == b'%' {
            let mut from: u32 = 0;
            let mut to: u32 = 0;

            let start_at = memparse(p.add(1), &mut p);
            if *p as u8 == b'-' {
                from = simple_strtoull(p.add(1), &mut p, 0) as u32;
            }
            if *p as u8 == b'+' {
                to = simple_strtoull(p.add(1), &mut p, 0) as u32;
            }
            if *p != 0 {
                return -EINVAL;
            }
            if from != 0 && to != 0 {
                e820_range_update_entry(start_at, mem_size, from, to);
            } else if to != 0 {
                e820__range_add(start_at, mem_size, to);
            } else if from != 0 {
                e820__range_remove(start_at, mem_size, from, true);
            } else {
                e820__range_remove(start_at, mem_size, 0, false);
            }
        } else {
            e820__range_remove(mem_size, u64::MAX - mem_size, E820_TYPE_RAM, true);
        }

        if *p == 0 {
            0
        } else {
            -EINVAL
        }
    }
}

#[cfg(not(kani))]
extern "C" {
    /// The glue's `e820__range_update()` (`BUG_ON(old == new)` then `e820_range_update_rs` on the main table).
    #[link_name = "e820__range_update"]
    fn e820_range_update_entry(start: u64, size: u64, old_type: u32, new_type: u32) -> u64;
}

/// `parse_memmap_opt()`: the `memmap=` early parameter, a comma-separated list; each item is cut out in place.
///
/// # Safety
/// Early boot (`parse_early_param`), `str` NULL or a writable NUL-terminated string.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn parse_memmap_opt(str: *mut c_char) -> c_int {
    // SAFETY: as the C: `strchr(str, ',')`, `*k++ = 0`.
    unsafe {
        let mut s = str;
        while !s.is_null() {
            let mut k = s;
            while *k != 0 && *k as u8 != b',' {
                k = k.add(1);
            }
            let next = if *k as u8 == b',' {
                *k = 0;
                k.add(1)
            } else {
                core::ptr::null_mut()
            };

            parse_memmap_one(s);
            s = next;
        }
        0
    }
}

/// Kani proofs (`cd rig/e820-kani && cargo kani`; inert in the kernel build). The table functions are run on
/// SYMBOLIC tables (every address, size and type) of a small fixed capacity; "for all" holds within that bound.
/// What they prove: no out-of-bounds access, no arithmetic panic (the build has overflow checks on and the code
/// uses wrapping ops, so a panic would be a real defect), `range_add` leaves the table exactly as specified, and the
/// sanitiser's result is, for every point of the address space, the highest-type covering entry, sorted, disjoint.
/// They do not cover the printk calls (dropped), `memparse` / `sort` (stand-ins) or tables larger than the bound.
#[cfg(kani)]
mod proofs {
    use super::*;

    const CAP: usize = 4;
    #[repr(C)]
    struct Tbl {
        nr: u32,
        e: [KernelE820Entry; CAP],
    }
    fn any_entry() -> KernelE820Entry {
        KernelE820Entry { addr: kani::any(), size: kani::any(), typ: kani::any() }
    }
    fn any_table(max_nr: u32) -> Tbl {
        let t = Tbl { nr: kani::any(), e: [any_entry(), any_entry(), any_entry(), any_entry()] };
        kani::assume(t.nr <= max_nr);
        t
    }

    /// `__e820__range_add`: in bounds, appends exactly one entry, or (table full) changes nothing.
    #[kani::proof]
    fn range_add_exact() {
        let mut t = any_table(CAP as u32);
        let before = (t.nr, t.e);
        let (s, z, ty): (u64, u64, u32) = (kani::any(), kani::any(), kani::any());
        // SAFETY: `t` is a valid table of capacity CAP == e820_table_max_entries.
        unsafe { range_add((&raw mut t).cast(), s, z, ty) };
        if (before.0 as usize) < CAP {
            assert!(t.nr == before.0 + 1);
            let i = before.0 as usize;
            let (a, b, c) = (t.e[i].addr, t.e[i].size, t.e[i].typ);
            assert!(a == s && b == z && c == ty);
            let mut k = 0;
            while k < CAP {
                if k != i {
                    let (x, y, w) = (t.e[k].addr, t.e[k].size, t.e[k].typ);
                    let (x0, y0, w0) = (before.1[k].addr, before.1[k].size, before.1[k].typ);
                    assert!(x == x0 && y == y0 && w == w0);
                }
                k += 1;
            }
        } else {
            assert!(t.nr == before.0);
        }
    }

    /// `e820_update_table_rs`, 2 symbolic entries: returns -1 exactly when an entry wraps; otherwise the result has
    /// <= CAP entries, none empty or of type 0, sorted and disjoint, and for EVERY address `p` the covering output
    /// entry's type is the highest type among the input entries covering `p` (and there is none if no input covers it).
    #[kani::proof]
    #[kani::unwind(9)]
    fn update_table_semantics_2() {
        let mut t = any_table(0);
        t.nr = 2;
        check_update(&mut t);
    }

    /// The same with 3 symbolic entries. NOT a proof harness: CBMC did not finish it in 2 hours (minisat) nor in 20
    /// minutes (kissat), so nothing is claimed for it; the 3-entry case is covered by the exhaustive comparison against the
    /// independent specification (`rig/phase-e/e820_cmp.sh`, EXH=1) and the randomised runs, not by a proof.
    #[allow(dead_code)]
    fn update_table_semantics_3() {
        let mut t = any_table(0);
        t.nr = 3;
        check_update(&mut t);
    }

    fn check_update(t: &mut Tbl) {
        let inp: [(u64, u64, u32); CAP] = {
            let mut a = [(0u64, 0u64, 0u32); CAP];
            let mut k = 0;
            while k < CAP {
                a[k] = (t.e[k].addr, t.e[k].size, t.e[k].typ);
                k += 1;
            }
            a
        };
        let n = t.nr as usize;
        let mut wraps = false;
        let mut k = 0;
        while k < n {
            if inp[k].0.wrapping_add(inp[k].1) < inp[k].0 {
                wraps = true;
            }
            k += 1;
        }
        // SAFETY: valid table; `e820__update_table` is the Kani stand-in of the glue wrapper (scratch for max 4).
        unsafe { e820_table = (&raw mut *t).cast() };
        let rc = unsafe { e820__update_table((&raw mut *t).cast()) };
        assert!((rc == -1) == wraps);
        if wraps {
            return;
        }
        let m = t.nr as usize;
        assert!(m <= CAP);
        let mut i = 0;
        while i < m {
            let (a, z, ty) = (t.e[i].addr, t.e[i].size, t.e[i].typ);
            assert!(z != 0 && ty != 0);
            assert!(a.checked_add(z).is_some());
            if i + 1 < m {
                assert!(a + z <= t.e[i + 1].addr);
            }
            i += 1;
        }
        if m < CAP {
            // not cut at the capacity: the output is the exact highest-type map
            let p: u64 = kani::any();
            let mut want: u32 = 0;
            let mut k = 0;
            while k < n {
                let (a, z, ty) = inp[k];
                if z != 0 && a <= p && p - a < z && ty > want {
                    want = ty;
                }
                k += 1;
            }
            let mut got: u32 = 0;
            let mut i = 0;
            while i < m {
                let (a, z, ty) = (t.e[i].addr, t.e[i].size, t.e[i].typ);
                if a <= p && p - a < z {
                    got = ty;
                }
                i += 1;
            }
            assert!(got == want);
        }
    }

    /// `e820_range_update_rs` / `e820__range_remove` on a symbolic 3-entry table: no panic, no out-of-bounds, and the
    /// number of entries stays <= CAP.
    #[kani::proof]
    #[kani::unwind(6)]
    fn range_update_bounds() {
        let mut t = any_table(3);
        let (s, z, o, n): (u64, u64, u32, u32) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(o != n);
        // SAFETY: valid table of capacity CAP.
        unsafe { e820_range_update_rs((&raw mut t).cast(), s, z, o, n) };
        assert!(t.nr as usize <= CAP);
    }

    /// `e820__range_remove` likewise.
    #[kani::proof]
    #[kani::unwind(6)]
    fn range_remove_bounds() {
        let mut t = any_table(3);
        let (s, z, o): (u64, u64, u32) = (kani::any(), kani::any(), kani::any());
        let chk: bool = kani::any();
        // SAFETY: valid table of capacity CAP.
        unsafe {
            e820_table = (&raw mut t).cast();
            e820__range_remove(s, z, o, chk);
        }
        assert!(t.nr as usize <= CAP);
    }

    /// The query functions never leave the table.
    #[kani::proof]
    #[kani::unwind(6)]
    fn mapped_queries_bounds() {
        let mut t = any_table(CAP as u32);
        let (s, e, ty): (u64, u64, u32) = (kani::any(), kani::any(), kani::any());
        // SAFETY: valid table of capacity CAP.
        unsafe {
            e820_table = (&raw mut t).cast();
            let _ = e820__mapped_any(s, e, ty);
            let _ = e820__mapped_all(s, e, ty);
            let _ = e820__get_entry_type(s, e);
        }
    }

    /// `e820_search_gap` / `e820__setup_pci_gap`: no panic, and a found gap lies below 4 GiB.
    #[kani::proof]
    #[kani::unwind(6)]
    fn pci_gap_bounds() {
        let mut t = any_table(CAP as u32);
        // SAFETY: valid table of capacity CAP.
        unsafe {
            e820_table = (&raw mut t).cast();
            let (mut gs, mut gz): (u64, u64) = (0, 0x400000);
            let found = search_gap(&mut gs, &mut gz);
            if found != 0 {
                assert!(gs.checked_add(gz).is_some() && gs + gz <= MAX_GAP_END);
            }
        }
    }
}
