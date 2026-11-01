// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/kaslr.c (the 64-bit boot stub's KASLR), including the
//! three C files that kaslr.c `#include`s into itself: arch/x86/lib/kaslr.c (kaslr_get_random_long:
//! RDRAND / RDTSC / i8254 entropy), lib/ctype.c (`_ctype`) and lib/cmdline.c (get_option, get_options,
//! memparse, parse_option_str, next_arg), plus the file's own skip_spaces().
//!
//! Exported symbols = the defined global symbols of the C object (`nm kaslr.o`): choose_random_location,
//! kaslr_get_random_long, skip_spaces, memparse, next_arg, get_option, get_options, parse_option_str and
//! `_ctype`. Only choose_random_location is used by another stub object (misc.o); the libstub (lib.a:
//! x86-stub.o -> kaslr_get_random_long; efi-stub-helper.o -> _ctype, next_arg, parse_option_str,
//! skip_spaces) uses the rest. The libstub archive carries its own copies of the cmdline/ctype/skip_spaces
//! code; kaslr.o's definitions came first on the link line so those archive members were never pulled
//! in. The same must hold here, so ALL the C object's globals are exported (a partial set would pull
//! lib-cmdline.stub.o in and clash with the ones defined here).
//!
//! 64-bit only: `IS_ENABLED(CONFIG_X86_64)` is true and the `CONFIG_X86_32` arms are not ported (one
//! comment marks each). Build/config facts come from kaslr_cfg.c as extern statics; the Makefile passes
//! these cfgs: `verbose_bootup` (CONFIG_X86_VERBOSE_BOOTUP: `debug_putstr()` is `__putstr()`, else a
//! no-op as in misc.h), `efi` (CONFIG_EFI), `unaccepted_memory` (CONFIG_UNACCEPTED_MEMORY),
//! `hotremove_acpi` (CONFIG_MEMORY_HOTREMOVE && CONFIG_ACPI), `kexec_handover` (CONFIG_KEXEC_HANDOVER).
//! `stubf_fake_hw` is TEST ONLY (see `mod hw`): the shipped object never sets it.
//! Text of every message is the C's, byte for byte; no message is added.
//!
//! `struct boot_params` and friends are not mirrored whole: only the fields this file reads are
//! addressed, by byte offsets that came from a userspace C program compiled against the real uapi
//! <asm/bootparam.h> (offsetof/sizeof printed), each const noted `// C: offsetof(...)`.

#![allow(non_upper_case_globals)]

#[allow(unused_imports)]
use core::arch::asm;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

// ------------------------------------------------------------------------------------------------
// Constants (each value taken from the header named; checked against the C compiler by a script)
// ------------------------------------------------------------------------------------------------

/// Only supporting at most 4 unusable memmap regions with kaslr (kaslr.c).
const MAX_MEMMAP_REGIONS: usize = 4;
/// `enum mem_avoid_index` (kaslr.c).
const MEM_AVOID_ZO_RANGE: usize = 0;
const MEM_AVOID_INITRD: usize = 1;
const MEM_AVOID_CMDLINE: usize = 2;
const MEM_AVOID_BOOTPARAMS: usize = 3;
const MEM_AVOID_MEMMAP_BEGIN: usize = 4;
#[allow(dead_code)]
const MEM_AVOID_MEMMAP_END: usize = MEM_AVOID_MEMMAP_BEGIN + MAX_MEMMAP_REGIONS - 1;
const MEM_AVOID_MAX: usize = MEM_AVOID_MEMMAP_END + 1;
/// `#define MAX_SLOT_AREA 100` (kaslr.c).
const MAX_SLOT_AREA: usize = 100;

/// PUD_SHIFT (arch/x86/include/asm/pgtable_64_types.h, 4-level and 5-level alike).
const PUD_SHIFT: u32 = 30;
/// PUD_SIZE = 1UL << PUD_SHIFT (same header).
const PUD_SIZE: u64 = 1 << PUD_SHIFT;

/// KASLR_FLAG (arch/x86/include/uapi/asm/bootparam.h): `(1<<1)`.
const KASLR_FLAG: u8 = 1 << 1;
/// SETUP_INDIRECT (arch/x86/include/uapi/asm/setup_data.h): `(1<<31)`, compared against the u32 `type`.
const SETUP_INDIRECT: u32 = 1 << 31;
/// SETUP_KEXEC_KHO (arch/x86/include/uapi/asm/setup_data.h).
#[allow(dead_code)]
const SETUP_KEXEC_KHO: u32 = 10;
/// E820_TYPE_RAM, `enum e820_type` (arch/x86/include/asm/e820/types.h).
const E820_TYPE_RAM: u32 = 1;

/// EFI_CONVENTIONAL_MEMORY (arch/x86/boot/compressed/efi.h).
#[allow(dead_code)]
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
/// EFI_UNACCEPTED_MEMORY (arch/x86/boot/compressed/efi.h).
#[allow(dead_code)]
const EFI_UNACCEPTED_MEMORY: u32 = 15;
/// EFI_MEMORY_MORE_RELIABLE (arch/x86/boot/compressed/efi.h).
#[allow(dead_code)]
const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000_0000_0001_0000;
/// EFI_MEMORY_SP (arch/x86/boot/compressed/efi.h).
#[allow(dead_code)]
const EFI_MEMORY_SP: u64 = 0x0000_0000_0004_0000;
/// EFI_PAGE_SHIFT (arch/x86/boot/compressed/efi.h).
#[allow(dead_code)]
const EFI_PAGE_SHIFT: u32 = 12;

/// X86_FEATURE_TSC = 0*32+4 (arch/x86/include/asm/cpufeatures.h).
const X86_FEATURE_TSC: c_int = 4;
/// X86_FEATURE_RDRAND = 4*32+30 (arch/x86/include/asm/cpufeatures.h).
const X86_FEATURE_RDRAND: c_int = 4 * 32 + 30;
/// RDRAND_RETRY_LOOPS (arch/x86/include/asm/archrandom.h).
#[allow(dead_code)]
const RDRAND_RETRY_LOOPS: c_uint = 10;

/// i8254 constants (arch/x86/lib/kaslr.c).
const I8254_PORT_CONTROL: u16 = 0x43;
const I8254_PORT_COUNTER0: u16 = 0x40;
const I8254_CMD_READBACK: u8 = 0xC0;
const I8254_SELECT_COUNTER0: u8 = 0x02;
const I8254_STATUS_NOTREADY: u8 = 0x40;

/// `mix_const` of kaslr_get_random_long() for CONFIG_X86_64 (arch/x86/lib/kaslr.c); the 32-bit value
/// 0x3f39e593 is not ported.
const MIX_CONST: u64 = 0x5d6008cbf3848dd3;

/// EINVAL (include/uapi/asm-generic/errno-base.h).
const EINVAL: c_int = 22;

// ---- offsets into struct boot_params (4096 bytes). All from a C program on the real uapi header. ----
/// C: sizeof(struct boot_params)
const BOOT_PARAMS_SIZE: usize = 4096;
/// C: offsetof(struct boot_params, hdr.loadflags)
const BP_HDR_LOADFLAGS: usize = 529;
/// C: offsetof(struct boot_params, hdr.ramdisk_image)
const BP_HDR_RAMDISK_IMAGE: usize = 536;
/// C: offsetof(struct boot_params, hdr.ramdisk_size)
const BP_HDR_RAMDISK_SIZE: usize = 540;
/// C: offsetof(struct boot_params, hdr.setup_data)
const BP_HDR_SETUP_DATA: usize = 592;
/// C: offsetof(struct boot_params, hdr.init_size)
const BP_HDR_INIT_SIZE: usize = 608;
/// C: offsetof(struct boot_params, ext_ramdisk_image)
const BP_EXT_RAMDISK_IMAGE: usize = 192;
/// C: offsetof(struct boot_params, ext_ramdisk_size)
const BP_EXT_RAMDISK_SIZE: usize = 196;
/// C: offsetof(struct boot_params, efi_info)
#[allow(dead_code)]
const BP_EFI_INFO: usize = 448;
/// C: offsetof(struct boot_params, e820_entries)
const BP_E820_ENTRIES: usize = 488;
/// C: offsetof(struct boot_params, e820_table)
const BP_E820_TABLE: usize = 720;

// ---- struct efi_info (inside boot_params at BP_EFI_INFO) ----
/// C: offsetof(struct efi_info, efi_loader_signature)
#[allow(dead_code)]
const EI_LOADER_SIGNATURE: usize = 0;
/// C: offsetof(struct efi_info, efi_memdesc_size)
#[allow(dead_code)]
const EI_MEMDESC_SIZE: usize = 8;
/// C: offsetof(struct efi_info, efi_memmap)
#[allow(dead_code)]
const EI_MEMMAP: usize = 16;
/// C: offsetof(struct efi_info, efi_memmap_size)
#[allow(dead_code)]
const EI_MEMMAP_SIZE: usize = 20;
/// C: offsetof(struct efi_info, efi_memmap_hi)
#[allow(dead_code)]
const EI_MEMMAP_HI: usize = 28;

// ---- struct boot_e820_entry (packed, 20 bytes) ----
/// C: sizeof(struct boot_e820_entry)
const E820_ENTRY_SIZE: usize = 20;
/// C: offsetof(struct boot_e820_entry, addr)
const E820_ADDR: usize = 0;
/// C: offsetof(struct boot_e820_entry, size)
const E820_SIZE: usize = 8;
/// C: offsetof(struct boot_e820_entry, type)
const E820_TYPE: usize = 16;

// ---- struct setup_data / struct setup_indirect (arch/x86/include/uapi/asm/bootparam.h, setup_data.h) ----
/// C: sizeof(struct setup_data)
const SETUP_DATA_SIZE: u64 = 16;
/// C: offsetof(struct setup_data, next)
const SD_NEXT: usize = 0;
/// C: offsetof(struct setup_data, type)
const SD_TYPE: usize = 8;
/// C: offsetof(struct setup_data, len)
const SD_LEN: usize = 12;
/// C: offsetof(struct setup_data, data)
const SD_DATA: usize = 16;
/// C: offsetof(struct setup_indirect, type)
const SI_TYPE: usize = 0;
/// C: offsetof(struct setup_indirect, len)
const SI_LEN: usize = 8;
/// C: offsetof(struct setup_indirect, addr)
const SI_ADDR: usize = 16;

// ---- struct kho_data (packed) / struct kho_scratch (include/linux/kexec_handover.h) ----
/// C: offsetof(struct kho_data, scratch_addr)
#[allow(dead_code)]
const KHO_SCRATCH_ADDR: usize = 16;
/// C: offsetof(struct kho_data, scratch_size)
#[allow(dead_code)]
const KHO_SCRATCH_SIZE: usize = 24;
/// C: sizeof(struct kho_scratch)
#[allow(dead_code)]
const KHO_SCRATCH_STRUCT_SIZE: usize = 16;
/// C: offsetof(struct kho_scratch, size)
#[allow(dead_code)]
const KS_SIZE: usize = 8;

// ---- efi_memory_desc_t (arch/x86/boot/compressed/efi.h). The stride is the RUNTIME efi_memdesc_size. ----
/// C: sizeof(efi_memory_desc_t)
#[allow(dead_code)]
const EFI_MD_SIZE: usize = 40;
/// C: offsetof(efi_memory_desc_t, type)
#[allow(dead_code)]
const EFI_MD_TYPE: usize = 0;
/// C: offsetof(efi_memory_desc_t, phys_addr)
#[allow(dead_code)]
const EFI_MD_PHYS_ADDR: usize = 8;
/// C: offsetof(efi_memory_desc_t, num_pages)
#[allow(dead_code)]
const EFI_MD_NUM_PAGES: usize = 24;
/// C: offsetof(efi_memory_desc_t, attribute)
#[allow(dead_code)]
const EFI_MD_ATTRIBUTE: usize = 32;

/// `struct mem_vector` (arch/x86/boot/compressed/misc.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct MemVector {
    start: u64,
    size: u64,
}

/// `struct slot_area` (kaslr.c).
#[repr(C)]
#[derive(Clone, Copy)]
struct SlotArea {
    addr: u64,
    num: c_ulong,
}

const _: () = assert!(core::mem::size_of::<MemVector>() == 16);
const _: () = assert!(core::mem::size_of::<SlotArea>() == 16);
const _: () = assert!(MEM_AVOID_MAX == 8);
const _: () = assert!(BP_HDR_SETUP_DATA == 497 + 95);

// ------------------------------------------------------------------------------------------------
// C world
// ------------------------------------------------------------------------------------------------

extern "C" {
    static mut boot_params_ptr: *mut c_void;

    // kaslr_cfg.c: the preprocessor facts.
    static kaslr_build_str: [c_char; 0];
    static kaslr_build_str_size: c_ulong;
    static kaslr_physical_align: c_ulong;
    static kaslr_load_physical_addr: c_ulong;
    static kaslr_kernel_image_size: c_ulong;
    static kaslr_command_line_size: c_ulong;
    /// MAXMEM: a runtime value with 5-level paging.
    fn kaslr_maxmem() -> c_ulong;
    #[cfg(efi)]
    fn kaslr_soft_reserve_enabled() -> bool;

    /// cmdline_rs.rs / cmdline.c
    fn get_cmd_line_ptr() -> c_ulong;
    fn cmdline_find_option_bool(option: *const c_char) -> c_int;
    /// cpuflags_rs.rs
    fn has_cpuflag(flag: c_int) -> bool;
    /// misc.c
    fn malloc(size: c_int) -> *mut c_void;
    fn free(where_: *mut c_void);
    /// verbose only: the target of debug_putstr().
    #[cfg(verbose_bootup)]
    fn __putstr(s: *const c_char);
    /// error_rs.rs / error.c
    fn warn(m: *const c_char);
    fn error(m: *mut c_char) -> !;
    /// string_rs.rs / arch/x86/boot/string.h
    fn memcpy(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    fn strnlen(s: *const c_char, maxlen: usize) -> usize;
    fn strlen(s: *const c_char) -> usize;
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    fn strstr(a: *const c_char, b: *const c_char) -> *mut c_char;
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    fn simple_strtoull(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> u64;
    fn simple_strtol(cp: *const c_char, endp: *mut *mut c_char, base: c_uint) -> c_long;

    /// misc.h: only with CONFIG_RANDOMIZE_BASE && CONFIG_MEMORY_HOTREMOVE && CONFIG_ACPI (acpi_rs.rs).
    #[cfg(hotremove_acpi)]
    fn count_immovable_mem_regions() -> c_int;
    /// `struct mem_vector immovable_mem[MAX_NUMNODES*2]` (acpi_rs.rs); indexed through a pointer.
    #[cfg(hotremove_acpi)]
    static immovable_mem: [MemVector; 0];
}

/// `struct port_io_ops` of arch/x86/boot/io.h. `inb`/`outb` in the stub are `pio_ops.f_inb`/`f_outb`
/// (TDX guests replace the callbacks), exactly as early_serial_console_rs.rs does.
#[cfg(not(stubf_fake_hw))]
#[repr(C)]
struct PortIoOps {
    f_inb: Option<unsafe extern "C" fn(u16) -> u8>,
    f_outb: Option<unsafe extern "C" fn(u8, u16)>,
    f_outw: Option<unsafe extern "C" fn(u16, u16)>,
}

#[cfg(not(stubf_fake_hw))]
extern "C" {
    static pio_ops: PortIoOps;
}

/// `debug_putstr()` with a C string literal: `__putstr()` with CONFIG_X86_VERBOSE_BOOTUP, nothing otherwise.
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

/// `debug_putstr(purpose)` for a caller-supplied pointer (kaslr_get_random_long's `purpose`).
#[inline(always)]
#[allow(unused_variables)]
unsafe fn debug_putstr_ptr(s: *const c_char) {
    #[cfg(verbose_bootup)]
    {
        // SAFETY: the caller passes a NUL-terminated string, as the C callers do.
        unsafe { __putstr(s) };
    }
}

// ------------------------------------------------------------------------------------------------
// Hardware leaf operations. ONE small private module with two arms.
// ------------------------------------------------------------------------------------------------

/// The real arm (`not(stubf_fake_hw)`) is what ships: RDRAND via `asm!` with the retry loop of
/// asm/archrandom.h rdrand_long(), RDTSC via `asm!`, and the i8254 readback sequence of
/// arch/x86/lib/kaslr.c through `pio_ops` (the C `inb()`/`outb()` of boot/io.h).
///
/// The `stubf_fake_hw` arm is TEST ONLY: thin wrappers over extern "C" functions that a userspace
/// harness provides so it can feed deterministic values. The shipped object never sets that cfg.
/// (In that arm the whole rdrand_long() -- retry loop included -- is the harness's
/// `kaslr_hw_rdrand_long`, so the 10-try loop is not exercised there; and i8254()'s sequence is
/// kept, over `kaslr_hw_inb`/`kaslr_hw_outb`.)
mod hw {
    use super::*;

    #[cfg(not(stubf_fake_hw))]
    mod arm {
        use super::*;

        /// `rdrand_long()` of arch/x86/include/asm/archrandom.h: `*v` is written on every try (RDRAND
        /// zeroes the destination on failure), up to RDRAND_RETRY_LOOPS tries.
        pub unsafe fn rdrand_long(v: &mut u64) -> bool {
            let mut retry: c_uint = RDRAND_RETRY_LOOPS;
            loop {
                let ok: u8;
                let out: u64;
                // SAFETY: RDRAND is only executed after has_cpuflag(X86_FEATURE_RDRAND) said it exists.
                unsafe {
                    asm!("rdrand {out}", "setc {ok}", out = out(reg) out, ok = out(reg_byte) ok,
                         options(nomem, nostack));
                }
                *v = out;
                if ok != 0 {
                    return true;
                }
                retry = retry.wrapping_sub(1);
                if retry == 0 {
                    break;
                }
            }
            false
        }

        /// `rdtsc()` of asm/tsc.h (native, unordered), as one u64.
        pub fn rdtsc() -> u64 {
            let lo: u32;
            let hi: u32;
            // SAFETY: RDTSC is only executed after has_cpuflag(X86_FEATURE_TSC) said it exists.
            unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
            ((hi as u64) << 32) | lo as u64
        }

        /// C `inb(port)` of the stub: `pio_ops.f_inb(port)`.
        pub unsafe fn inb(port: u16) -> u8 {
            // SAFETY: init_default_io_ops() (misc.c) has set f_inb before choose_random_location() can run.
            unsafe { (pio_ops.f_inb.unwrap_unchecked())(port) }
        }

        /// C `outb(v, port)` of the stub: `pio_ops.f_outb(v, port)`.
        pub unsafe fn outb(v: u8, port: u16) {
            // SAFETY: as inb(), for f_outb.
            unsafe { (pio_ops.f_outb.unwrap_unchecked())(v, port) }
        }
    }

    #[cfg(stubf_fake_hw)]
    mod arm {
        extern "C" {
            fn kaslr_hw_rdrand_long(out: *mut u64) -> bool;
            fn kaslr_hw_rdtsc() -> u64;
            fn kaslr_hw_inb(port: u16) -> u8;
            fn kaslr_hw_outb(v: u8, port: u16);
        }

        pub unsafe fn rdrand_long(v: &mut u64) -> bool {
            // SAFETY: the harness's function writes one u64 through the pointer.
            unsafe { kaslr_hw_rdrand_long(v as *mut u64) }
        }
        pub fn rdtsc() -> u64 {
            // SAFETY: harness function, no preconditions.
            unsafe { kaslr_hw_rdtsc() }
        }
        pub unsafe fn inb(port: u16) -> u8 {
            // SAFETY: harness function.
            unsafe { kaslr_hw_inb(port) }
        }
        pub unsafe fn outb(v: u8, port: u16) {
            // SAFETY: harness function.
            unsafe { kaslr_hw_outb(v, port) }
        }
    }

    pub use arm::{rdrand_long, rdtsc};

    /// `i8254()` of arch/x86/lib/kaslr.c.
    pub unsafe fn i8254() -> u16 {
        let mut status: u16;
        let mut timer: u16;

        // SAFETY (whole body): port I/O on the legacy PIT, exactly the C sequence.
        unsafe {
            loop {
                arm::outb(I8254_CMD_READBACK | I8254_SELECT_COUNTER0, I8254_PORT_CONTROL);
                status = arm::inb(I8254_PORT_COUNTER0) as u16;
                timer = arm::inb(I8254_PORT_COUNTER0) as u16;
                timer |= (arm::inb(I8254_PORT_COUNTER0) as u16) << 8;
                // `while (status & I8254_STATUS_NOTREADY)`; status is u16 in the C, the byte is zero-extended.
                if status & (I8254_STATUS_NOTREADY as u16) == 0 {
                    break;
                }
            }
        }

        timer
    }
}

// ------------------------------------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------------------------------------

/// Unsigned division by a runtime value that the C also divides without a check (CONFIG_PHYSICAL_ALIGN
/// is a Kconfig range that is never 0; the callers' other divisors are shown non-zero at each use).
/// `assert_unchecked` keeps rustc from emitting its divide-by-zero panic path: no panics in the stub.
#[inline(always)]
unsafe fn udiv(a: u64, b: u64) -> u64 {
    // SAFETY: b != 0 is the C's UB-free precondition too.
    unsafe { core::hint::assert_unchecked(b != 0) };
    a / b
}

/// `a % b`, same contract as udiv().
#[inline(always)]
unsafe fn urem(a: u64, b: u64) -> u64 {
    // SAFETY: as udiv().
    unsafe { core::hint::assert_unchecked(b != 0) };
    a % b
}

/// 32-bit unsigned division by a firmware-supplied value (efi_memmap_size / efi_memdesc_size). The C
/// compiles to a `div`, which raises #DE on zero; rustc would call its panic handler instead, so the
/// instruction is issued directly to keep the C's behaviour.
#[cfg(efi)]
#[inline(always)]
fn div_u32(a: u32, b: u32) -> u32 {
    let q: u32;
    // SAFETY: DIV with edx = 0; raises #DE only for b == 0, as the C does.
    unsafe {
        asm!("div {d:e}", d = in(reg) b, inout("eax") a => q, inout("edx") 0u32 => _,
             options(nomem, nostack));
    }
    q
}

/// `ALIGN(x, a)` for u64 `x`: `(x + (a - 1)) & ~(a - 1)` with the C's unsigned wrap-around.
#[inline(always)]
fn align_up(x: u64, a: u64) -> u64 {
    let mask = a.wrapping_sub(1);
    x.wrapping_add(mask) & !mask
}

/// `ALIGN_DOWN(x, a)` = `ALIGN(x - (a - 1), a)` = `x & ~(a - 1)` modulo 2^64.
#[inline(always)]
fn align_down(x: u64, a: u64) -> u64 {
    let mask = a.wrapping_sub(1);
    x.wrapping_sub(mask).wrapping_add(mask) & !mask
}

/// `clamp(val, lo, hi)` of include/linux/minmax.h: `val >= hi ? hi : (val <= lo ? lo : val)`.
#[cfg(hotremove_acpi)]
#[inline(always)]
fn clamp(val: u64, lo: u64, hi: u64) -> u64 {
    if val >= hi {
        hi
    } else if val <= lo {
        lo
    } else {
        val
    }
}

/// `CONFIG_PHYSICAL_ALIGN` (a power of two; kaslr_cfg.c). One accessor so the Kani proofs below can make it symbolic.
#[cfg(not(kani))]
#[inline(always)]
fn phys_align() -> u64 {
    // SAFETY: an immutable .rodata value defined by kaslr_cfg.c.
    unsafe { kaslr_physical_align }
}

/// Kani: the harness sets this to a symbolic power of two before calling into the code under proof.
#[cfg(kani)]
static mut KANI_ALIGN: u64 = 0x200000;
#[cfg(kani)]
fn phys_align() -> u64 {
    // SAFETY: single-threaded proof harness.
    unsafe { KANI_ALIGN }
}

/// The current `boot_params_ptr`, as a byte pointer.
#[inline(always)]
unsafe fn bp() -> *mut u8 {
    // SAFETY: boot_params_ptr is set by the stub's entry code before choose_random_location().
    unsafe { ptr::addr_of!(boot_params_ptr).read() as *mut u8 }
}

/// Read a `u32` of boot_params at byte offset `off`.
#[inline(always)]
unsafe fn bp_u32(off: usize) -> u32 {
    // SAFETY: every offset used is a field inside the 4096 bytes.
    unsafe { bp().add(off).cast::<u32>().read_unaligned() }
}

/// Read a `u64` of boot_params at byte offset `off`.
#[inline(always)]
unsafe fn bp_u64(off: usize) -> u64 {
    // SAFETY: as bp_u32().
    unsafe { bp().add(off).cast::<u64>().read_unaligned() }
}

// ------------------------------------------------------------------------------------------------
// State (zero-initialised statics: .bss, no relocations)
// ------------------------------------------------------------------------------------------------

static mut memmap_too_large: bool = false;

/// Store memory limit: MAXMEM on 64-bit (KERNEL_IMAGE_SIZE on 32-bit, not ported). It may be reduced by
/// "mem=nn[KMG]" or "memmap=nn[KMG]" command line options.
static mut mem_limit: u64 = 0;

/// Number of immovable memory regions.
static mut num_immovable_mem: c_int = 0;

static mut mem_avoid: [MemVector; MEM_AVOID_MAX] = [MemVector { start: 0, size: 0 }; MEM_AVOID_MAX];

/// Store the number of 1GB huge pages which users specified.
static mut max_gb_huge_pages: c_ulong = 0;

static mut slot_areas: [SlotArea; MAX_SLOT_AREA] = [SlotArea { addr: 0, num: 0 }; MAX_SLOT_AREA];
static mut slot_area_index: c_uint = 0;
static mut slot_max: c_ulong = 0;

/// `static int i` of mem_avoid_memmap(): persists between calls.
static mut mem_avoid_memmap_i: c_int = 0;
/// `static bool gbpage_sz` of parse_gb_huge_pages(): persists between calls.
static mut parse_gb_huge_pages_gbpage_sz: bool = false;

/// `&mem_avoid[i]`
#[inline(always)]
unsafe fn avoid(i: usize) -> *mut MemVector {
    // SAFETY: callers keep i < MEM_AVOID_MAX (MEM_AVOID_MEMMAP_BEGIN + i with i < MAX_MEMMAP_REGIONS).
    unsafe { (ptr::addr_of_mut!(mem_avoid) as *mut MemVector).add(i) }
}

/// `&slot_areas[i]`
#[inline(always)]
unsafe fn slot_area(i: usize) -> *mut SlotArea {
    // SAFETY: callers keep i < MAX_SLOT_AREA.
    unsafe { (ptr::addr_of_mut!(slot_areas) as *mut SlotArea).add(i) }
}

// ------------------------------------------------------------------------------------------------
// lib/ctype.c
// ------------------------------------------------------------------------------------------------

// include/linux/ctype.h
const _U: u8 = 0x01; // upper
const _L: u8 = 0x02; // lower
const _D: u8 = 0x04; // digit
const _C: u8 = 0x08; // cntrl
const _P: u8 = 0x10; // punct
const _S: u8 = 0x20; // white space (space/lf/tab)
const _X: u8 = 0x40; // hex digit
const _SP: u8 = 0x80; // hard space (0x20)

/// `const unsigned char _ctype[]` (lib/ctype.c), row for row. Plain data in .rodata, no relocations.
#[no_mangle]
pub static _ctype: [u8; 256] = [
    _C, _C, _C, _C, _C, _C, _C, _C, // 0-7
    _C, _C | _S, _C | _S, _C | _S, _C | _S, _C | _S, _C, _C, // 8-15
    _C, _C, _C, _C, _C, _C, _C, _C, // 16-23
    _C, _C, _C, _C, _C, _C, _C, _C, // 24-31
    _S | _SP, _P, _P, _P, _P, _P, _P, _P, // 32-39
    _P, _P, _P, _P, _P, _P, _P, _P, // 40-47
    _D, _D, _D, _D, _D, _D, _D, _D, // 48-55
    _D, _D, _P, _P, _P, _P, _P, _P, // 56-63
    _P, _U | _X, _U | _X, _U | _X, _U | _X, _U | _X, _U | _X, _U, // 64-71
    _U, _U, _U, _U, _U, _U, _U, _U, // 72-79
    _U, _U, _U, _U, _U, _U, _U, _U, // 80-87
    _U, _U, _U, _P, _P, _P, _P, _P, // 88-95
    _P, _L | _X, _L | _X, _L | _X, _L | _X, _L | _X, _L | _X, _L, // 96-103
    _L, _L, _L, _L, _L, _L, _L, _L, // 104-111
    _L, _L, _L, _L, _L, _L, _L, _L, // 112-119
    _L, _L, _L, _P, _P, _P, _P, _C, // 120-127
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 128-143
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 144-159
    _S | _SP, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, // 160-175
    _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, // 176-191
    _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, // 192-207
    _U, _U, _U, _U, _U, _U, _U, _P, _U, _U, _U, _U, _U, _U, _U, _L, // 208-223
    _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, // 224-239
    _L, _L, _L, _L, _L, _L, _L, _P, _L, _L, _L, _L, _L, _L, _L, _L, // 240-255
];

/// `isspace(c)` of include/linux/ctype.h: `(_ctype[(int)(unsigned char)(c)] & _S) != 0` (false for NUL).
#[inline(always)]
unsafe fn isspace(c: c_char) -> bool {
    // SAFETY: the index is a u8 (< 256), inside the 256-entry table.
    unsafe { (ptr::addr_of!(_ctype) as *const u8).add(c as u8 as usize).read() & _S != 0 }
}

// ------------------------------------------------------------------------------------------------
// skip_spaces (kaslr.c's own copy of lib/string.c's) and lib/cmdline.c
// ------------------------------------------------------------------------------------------------

/// `char *skip_spaces(const char *str)`
#[no_mangle]
pub unsafe extern "C" fn skip_spaces(str_: *const c_char) -> *mut c_char {
    let mut s = str_;
    // SAFETY: str_ is NUL-terminated (caller's contract); isspace(NUL) is false.
    unsafe {
        while isspace(*s) {
            s = s.add(1);
        }
    }
    s as *mut c_char
}

/// `static int get_range(char **str, int *pint, int n)` (lib/cmdline.c)
unsafe fn get_range(str_: *mut *mut c_char, pint: *mut c_int, n: c_int) -> c_int {
    let mut pint = pint;
    let mut n = n;
    // SAFETY: caller's pointers (get_options()).
    unsafe {
        *str_ = (*str_).add(1);
        let upper_range: c_int = simple_strtol(*str_, ptr::null_mut(), 0) as c_int;
        let inc_counter: c_int = upper_range.wrapping_sub(*pint);
        let mut x: c_int = *pint;
        while n != 0 && x < upper_range {
            *pint = x;
            pint = pint.add(1);
            x = x.wrapping_add(1);
            n = n.wrapping_sub(1);
        }
        inc_counter
    }
}

/// `int get_option(char **str, int *pint)` (lib/cmdline.c)
#[no_mangle]
pub unsafe extern "C" fn get_option(str_: *mut *mut c_char, pint: *mut c_int) -> c_int {
    // SAFETY: caller's pointers; *str_ is NUL-terminated.
    unsafe {
        let mut cur = *str_;
        let value: c_int;

        if cur.is_null() || *cur == 0 {
            return 0;
        }
        if *cur == b'-' as c_char {
            cur = cur.add(1);
            value = simple_strtoull(cur, str_, 0).wrapping_neg() as c_int;
        } else {
            value = simple_strtoull(cur, str_, 0) as c_int;
        }
        if !pint.is_null() {
            *pint = value;
        }
        if cur == *str_ {
            return 0;
        }
        if **str_ == b',' as c_char {
            *str_ = (*str_).add(1);
            return 2;
        }
        if **str_ == b'-' as c_char {
            return 3;
        }

        1
    }
}

/// `char *get_options(const char *str, int nints, int *ints)` (lib/cmdline.c)
#[no_mangle]
pub unsafe extern "C" fn get_options(str_: *const c_char, nints: c_int, ints: *mut c_int) -> *mut c_char {
    let mut s: *mut c_char = str_ as *mut c_char;
    let validate = nints == 0;
    let mut i: c_int = 1;

    // SAFETY: caller's contract (ints has room for nints elements, or one when validating).
    unsafe {
        while i < nints || validate {
            let pint: *mut c_int = if validate { ints } else { ints.offset(i as isize) };

            let res = get_option(&mut s, pint);
            if res == 0 {
                break;
            }
            if res == 3 {
                let n: c_int = if validate { 0 } else { nints.wrapping_sub(i) };

                let range_nums = get_range(&mut s, pint, n);
                if range_nums < 0 {
                    break;
                }
                // Decrement the result by one to leave out the last number in the range. The next
                // iteration will handle the upper number in the range
                i = i.wrapping_add(range_nums.wrapping_sub(1));
            }
            i = i.wrapping_add(1);
            if res == 1 {
                break;
            }
        }
        *ints = i.wrapping_sub(1);
    }
    s
}

/// `unsigned long long memparse(const char *ptr, char **retptr)` (lib/cmdline.c)
#[no_mangle]
pub unsafe extern "C" fn memparse(ptr_: *const c_char, retptr: *mut *mut c_char) -> u64 {
    let mut endptr: *mut c_char = ptr::null_mut(); // local pointer to end of parsed string

    // SAFETY: ptr_ is NUL-terminated; simple_strtoull() writes endptr; retptr is optional.
    unsafe {
        let mut ret: u64 = simple_strtoull(ptr_, &mut endptr, 0);

        // The C switch falls through from 'E' down to 'K': 'E' shifts six times, 'P' five, ... 'K' one,
        // and only 'K'/'k' (the bottom of the chain, which every suffix reaches) does endptr++.
        // (Folded compares; rustc may still lower them to a switch -- the only .rodata relocations in the object
        // are R_X86_64_PC32 jump-table entries, i.e. position-independent, no absolute/dynamic relocation.)
        let c = (*endptr as u8) | 0x20; // 'E'/'e' -> 'e', etc.; no other byte folds onto these six letters
        let shifts: u32 = if c == b'e' {
            6
        } else if c == b'p' {
            5
        } else if c == b't' {
            4
        } else if c == b'g' {
            3
        } else if c == b'm' {
            2
        } else if c == b'k' {
            1
        } else {
            0
        };
        let mut k = shifts;
        while k > 0 {
            ret <<= 10;
            k -= 1;
        }
        if shifts > 0 {
            endptr = endptr.add(1);
        }

        if !retptr.is_null() {
            *retptr = endptr;
        }

        ret
    }
}

/// `bool parse_option_str(const char *str, const char *option)` (lib/cmdline.c)
#[no_mangle]
pub unsafe extern "C" fn parse_option_str(str_: *const c_char, option: *const c_char) -> bool {
    let mut s = str_;
    // SAFETY: both strings are NUL-terminated (caller's contract).
    unsafe {
        while *s != 0 {
            if strncmp(s, option, strlen(option)) == 0 {
                s = s.add(strlen(option));
                if *s == 0 || *s == b',' as c_char {
                    return true;
                }
            }

            while *s != 0 && *s != b',' as c_char {
                s = s.add(1);
            }

            if *s == b',' as c_char {
                s = s.add(1);
            }
        }
    }

    false
}

/// `char *next_arg(char *args, char **param, char **val)` (lib/cmdline.c)
///
/// Parse a string to get a param value pair. You can use " around spaces, but can't escape ".
/// Hyphens and underscores equivalent in parameter names.
#[no_mangle]
pub unsafe extern "C" fn next_arg(args: *mut c_char, param: *mut *mut c_char, val: *mut *mut c_char) -> *mut c_char {
    let mut args = args;
    let mut i: c_uint = 0;
    let mut equals: c_uint = 0;
    let mut in_quote: c_int = 0;
    let mut quoted: c_int = 0;
    let quote = b'"' as c_char;

    // SAFETY: args is a writable NUL-terminated string (caller's contract); every index is <= its length,
    // except args[i-1] with i == 0 which the C guards (`i > 0`) or cannot reach (`equals` implies i > 0).
    unsafe {
        if *args == quote {
            args = args.add(1);
            in_quote = 1;
            quoted = 1;
        }

        while *args.add(i as usize) != 0 {
            if isspace(*args.add(i as usize)) && in_quote == 0 {
                break;
            }
            if equals == 0 {
                if *args.add(i as usize) == b'=' as c_char {
                    equals = i;
                }
            }
            if *args.add(i as usize) == quote {
                in_quote = (in_quote == 0) as c_int;
            }
            i = i.wrapping_add(1);
        }

        *param = args;
        if equals == 0 {
            *val = ptr::null_mut();
        } else {
            *args.add(equals as usize) = 0;
            *val = args.add(equals as usize + 1);

            // Don't include quotes in value.
            if **val == quote {
                *val = (*val).add(1);
                if *args.add(i.wrapping_sub(1) as usize) == quote {
                    *args.add(i.wrapping_sub(1) as usize) = 0;
                }
            }
        }
        if quoted != 0 && i > 0 && *args.add(i.wrapping_sub(1) as usize) == quote {
            *args.add(i.wrapping_sub(1) as usize) = 0;
        }

        if *args.add(i as usize) != 0 {
            *args.add(i as usize) = 0;
            args = args.add(i as usize + 1);
        } else {
            args = args.add(i as usize);
        }

        // Chew up trailing spaces.
        skip_spaces(args)
    }
}

// ------------------------------------------------------------------------------------------------
// arch/x86/lib/kaslr.c, with the two helpers kaslr.c defines before including it
// ------------------------------------------------------------------------------------------------

/// `rotate_xor()`: rotate by an odd number of bits (57 left == 7 right on 64 bits) and XOR, one
/// unsigned long at a time, `size / sizeof(hash)` times.
unsafe fn rotate_xor(hash: c_ulong, area: *const u8, size: usize) -> c_ulong {
    let mut hash = hash;
    let words = size / core::mem::size_of::<c_ulong>();
    let ptr = area as *const c_ulong;
    let mut i: usize = 0;

    // SAFETY: area has at least `size` readable bytes (build_str / boot_params).
    unsafe {
        while i < words {
            // Rotate by odd number of bits and XOR.
            hash = hash.rotate_right(7);
            hash ^= ptr.add(i).read_unaligned();
            i += 1;
        }
    }

    hash
}

/// Attempt to create a simple but unpredictable starting entropy.
unsafe fn get_boot_seed() -> c_ulong {
    let mut hash: c_ulong = 0;

    // SAFETY: kaslr_build_str is kaslr_build_str_size bytes of .rodata; boot_params is 4096 bytes.
    unsafe {
        hash = rotate_xor(hash, ptr::addr_of!(kaslr_build_str) as *const u8, kaslr_build_str_size as usize);
        hash = rotate_xor(hash, bp(), BOOT_PARAMS_SIZE);
    }

    hash
}

/// `unsigned long kaslr_get_random_long(const char *purpose)`
#[no_mangle]
pub unsafe extern "C" fn kaslr_get_random_long(purpose: *const c_char) -> c_ulong {
    let mut raw: c_ulong = 0;
    // SAFETY: boot_params_ptr is valid (get_boot_seed()).
    let mut random: c_ulong = unsafe { get_boot_seed() };
    let mut use_i8254 = true;

    if !purpose.is_null() {
        // SAFETY: purpose is a NUL-terminated string.
        unsafe { debug_putstr_ptr(purpose) };
        debug_putstr!(c" KASLR using");
    }

    // SAFETY: has_cpuflag() is the stub's own (cpuflags_rs.rs).
    if unsafe { has_cpuflag(X86_FEATURE_RDRAND) } {
        if !purpose.is_null() {
            debug_putstr!(c" RDRAND");
        }
        // SAFETY: the CPU reported RDRAND.
        if unsafe { hw::rdrand_long(&mut raw) } {
            random ^= raw;
            use_i8254 = false;
        }
    }

    // SAFETY: as above, for TSC.
    if unsafe { has_cpuflag(X86_FEATURE_TSC) } {
        if !purpose.is_null() {
            debug_putstr!(c" RDTSC");
        }
        raw = hw::rdtsc();

        random ^= raw;
        use_i8254 = false;
    }

    if use_i8254 {
        if !purpose.is_null() {
            debug_putstr!(c" i8254");
        }
        // SAFETY: legacy PIT port I/O, as the C.
        random ^= unsafe { hw::i8254() } as c_ulong;
    }

    // Circular multiply for better bit diffusion: `mul` leaves the 128-bit product in rdx:rax.
    let prod: u128 = (random as u128) * (MIX_CONST as u128);
    random = prod as u64;
    raw = (prod >> 64) as u64;
    random = random.wrapping_add(raw);

    if !purpose.is_null() {
        debug_putstr!(c"...\n");
    }

    random
}

// ------------------------------------------------------------------------------------------------
// kaslr.c proper
// ------------------------------------------------------------------------------------------------

fn mem_overlaps(one: &MemVector, two: &MemVector) -> bool {
    // Item one is entirely before item two.
    if one.start.wrapping_add(one.size) <= two.start {
        return false;
    }
    // Item one is entirely after item two.
    if one.start >= two.start.wrapping_add(two.size) {
        return false;
    }
    true
}

/// `static int parse_memmap(char *p, u64 *start, u64 *size)`
unsafe fn parse_memmap(p: *mut c_char, start: *mut u64, size: *mut u64) -> c_int {
    let mut p = p;

    if p.is_null() {
        return -EINVAL;
    }

    // SAFETY: p is a NUL-terminated writable string from handle_mem_options(); start/size are the caller's.
    unsafe {
        // We don't care about this option here
        if strncmp(p, c"exactmap".as_ptr(), 8) == 0 {
            return -EINVAL;
        }

        let oldp = p;
        *size = memparse(p, &mut p);
        if p == oldp {
            return -EINVAL;
        }

        match *p as u8 {
            b'#' | b'$' | b'!' => {
                *start = memparse(p.add(1), &mut p);
                0
            }
            // memmap=nn@ss specifies usable region, should be skipped; then falls through to the default.
            b'@' => {
                *size = 0;
                *start = 0;
                0
            }
            // If w/o offset, only size specified, memmap=nn[KMG] has the same behaviour as mem=nn[KMG].
            // It limits the max address system can use. Region above the limit should be avoided.
            _ => {
                *start = 0;
                0
            }
        }
        // (the C's trailing `return -EINVAL` after the switch is unreachable)
    }
}

unsafe fn mem_avoid_memmap(str_: *mut c_char) {
    let mut str_ = str_;

    // SAFETY: single-threaded boot stub: the statics are only touched from here; str_ is the
    // writable tmp_cmdline copy.
    unsafe {
        if mem_avoid_memmap_i >= MAX_MEMMAP_REGIONS as c_int {
            return;
        }

        while !str_.is_null() && mem_avoid_memmap_i < MAX_MEMMAP_REGIONS as c_int {
            let mut start: u64 = 0;
            let mut size: u64 = 0;
            let mut k = strchr(str_, b',' as c_int);

            if !k.is_null() {
                *k = 0;
                k = k.add(1);
            }

            let rc = parse_memmap(str_, &mut start, &mut size);
            if rc < 0 {
                break;
            }
            str_ = k;

            if start == 0 {
                // Store the specified memory limit if size > 0
                if size > 0 && size < mem_limit {
                    mem_limit = size;
                }

                continue;
            }

            let slot = avoid(MEM_AVOID_MEMMAP_BEGIN + mem_avoid_memmap_i as usize);
            (*slot).start = start;
            (*slot).size = size;
            mem_avoid_memmap_i += 1;
        }

        // More than 4 memmaps, fail kaslr
        if mem_avoid_memmap_i >= MAX_MEMMAP_REGIONS as c_int && !str_.is_null() {
            memmap_too_large = true;
        }
    }
}

unsafe fn parse_gb_huge_pages(param: *mut c_char, val: *mut c_char) {
    // SAFETY: single-threaded boot stub; param/val come from next_arg() on tmp_cmdline (val may be
    // NULL exactly where the C would pass NULL on to memparse()/simple_strtoull()).
    unsafe {
        let mut p: *mut c_char;

        if strcmp(param, c"hugepagesz".as_ptr()) == 0 {
            p = val;
            if memparse(p, &mut p) != PUD_SIZE {
                parse_gb_huge_pages_gbpage_sz = false;
                return;
            }

            if parse_gb_huge_pages_gbpage_sz {
                warn(c"Repeatedly set hugeTLB page size of 1G!\n".as_ptr());
            }
            parse_gb_huge_pages_gbpage_sz = true;
            return;
        }

        if strcmp(param, c"hugepages".as_ptr()) == 0 && parse_gb_huge_pages_gbpage_sz {
            p = val;
            max_gb_huge_pages = simple_strtoull(p, &mut p, 0) as c_ulong;
            return;
        }
    }
}

unsafe fn handle_mem_options() {
    // SAFETY: single-threaded boot stub; the command line is NUL-terminated or at least
    // COMMAND_LINE_SIZE-1 long (strnlen bound), and tmp_cmdline is our private copy.
    unsafe {
        let mut args = get_cmd_line_ptr() as usize as *mut c_char;
        let mut param: *mut c_char = ptr::null_mut();
        let mut val: *mut c_char = ptr::null_mut();

        if args.is_null() {
            return;
        }

        let len = strnlen(args, (kaslr_command_line_size as usize).wrapping_sub(1));
        let tmp_cmdline = malloc(len.wrapping_add(1) as c_int) as *mut c_char;
        if tmp_cmdline.is_null() {
            error(c"Failed to allocate space for tmp_cmdline".as_ptr() as *mut c_char);
        }

        memcpy(tmp_cmdline as *mut c_void, args as *const c_void, len);
        *tmp_cmdline.add(len) = 0;
        args = tmp_cmdline;

        // Chew leading spaces
        args = skip_spaces(args);

        while *args != 0 {
            args = next_arg(args, &mut param, &mut val);
            // Stop at --
            if val.is_null() && strcmp(param, c"--".as_ptr()) == 0 {
                break;
            }

            if strcmp(param, c"memmap".as_ptr()) == 0 {
                mem_avoid_memmap(val);
            } else if !strstr(param, c"hugepages".as_ptr()).is_null() {
                // `IS_ENABLED(CONFIG_X86_64) &&` is true here.
                parse_gb_huge_pages(param, val);
            } else if strcmp(param, c"mem".as_ptr()) == 0 {
                let mut p = val;

                if strcmp(p, c"nopentium".as_ptr()) == 0 {
                    continue;
                }
                let mem_size = memparse(p, &mut p);
                if mem_size == 0 {
                    break;
                }

                if mem_size < mem_limit {
                    mem_limit = mem_size;
                }
            }
        }

        free(tmp_cmdline as *mut c_void);
    }
}

/// See the long comment above mem_avoid_init() in kaslr.c for the memory-layout reasoning.
unsafe fn mem_avoid_init(input: c_ulong, input_size: c_ulong, output: c_ulong) {
    let _ = input_size; // unused in the C as well

    // SAFETY: single-threaded boot stub; boot_params_ptr valid; the command line is read with strnlen's bound.
    unsafe {
        let init_size: c_ulong = bp_u32(BP_HDR_INIT_SIZE) as c_ulong;

        // Avoid the region that is unsafe to overlap during decompression.
        (*avoid(MEM_AVOID_ZO_RANGE)).start = input;
        (*avoid(MEM_AVOID_ZO_RANGE)).size = output.wrapping_add(init_size).wrapping_sub(input);

        // Avoid initrd.
        let mut initrd_start: u64 = (bp_u32(BP_EXT_RAMDISK_IMAGE) as u64) << 32;
        initrd_start |= bp_u32(BP_HDR_RAMDISK_IMAGE) as u64;
        let mut initrd_size: u64 = (bp_u32(BP_EXT_RAMDISK_SIZE) as u64) << 32;
        initrd_size |= bp_u32(BP_HDR_RAMDISK_SIZE) as u64;
        (*avoid(MEM_AVOID_INITRD)).start = initrd_start;
        (*avoid(MEM_AVOID_INITRD)).size = initrd_size;
        // No need to set mapping for initrd, it will be handled in VO.

        // Avoid kernel command line.
        let cmd_line: c_ulong = get_cmd_line_ptr();
        // Calculate size of cmd_line.
        if cmd_line != 0 {
            let cmd_line_size: c_ulong =
                strnlen(cmd_line as usize as *const c_char, (kaslr_command_line_size as usize).wrapping_sub(1)).wrapping_add(1) as c_ulong;
            (*avoid(MEM_AVOID_CMDLINE)).start = cmd_line;
            (*avoid(MEM_AVOID_CMDLINE)).size = cmd_line_size;
        }

        // Avoid boot parameters.
        (*avoid(MEM_AVOID_BOOTPARAMS)).start = bp() as usize as c_ulong;
        (*avoid(MEM_AVOID_BOOTPARAMS)).size = BOOT_PARAMS_SIZE as u64;

        // We don't need to set a mapping for setup_data.

        // Mark the memmap regions we need to avoid
        handle_mem_options();

        // Enumerate the immovable memory regions
        #[cfg(hotremove_acpi)]
        {
            num_immovable_mem = count_immovable_mem_regions();
        }
        // misc.h: without CONFIG_MEMORY_HOTREMOVE && CONFIG_ACPI, count_immovable_mem_regions() is an inline `return 0`.
        #[cfg(not(hotremove_acpi))]
        {
            num_immovable_mem = 0;
        }
    }
}

/// Does this memory vector overlap a known avoided area? If so, record the overlap region with the
/// lowest address.
unsafe fn mem_avoid_overlap(img: &MemVector, overlap: &mut MemVector) -> bool {
    let mut earliest: u64 = img.start.wrapping_add(img.size);
    let mut is_overlapping = false;

    // SAFETY: single-threaded boot stub; the setup_data list is physical addresses, identity mapped in
    // the stub (boot-loader memory, hence read_unaligned).
    unsafe {
        let mut i: usize = 0;
        while i < MEM_AVOID_MAX {
            let a = *avoid(i);
            if mem_overlaps(img, &a) && a.start < earliest {
                *overlap = a;
                earliest = overlap.start;
                is_overlapping = true;
            }
            i += 1;
        }

        // Avoid all entries in the setup_data linked list.
        let mut ptr_: *const u8 = bp_u64(BP_HDR_SETUP_DATA) as usize as *const u8;
        while !ptr_.is_null() {
            let mut avoid_: MemVector = MemVector { start: 0, size: 0 };

            avoid_.start = ptr_ as usize as u64;
            avoid_.size = SETUP_DATA_SIZE.wrapping_add(ptr_.add(SD_LEN).cast::<u32>().read_unaligned() as u64);

            if mem_overlaps(img, &avoid_) && avoid_.start < earliest {
                *overlap = avoid_;
                earliest = overlap.start;
                is_overlapping = true;
            }

            let data = ptr_.add(SD_DATA);
            if ptr_.add(SD_TYPE).cast::<u32>().read_unaligned() == SETUP_INDIRECT
                && data.add(SI_TYPE).cast::<u32>().read_unaligned() != SETUP_INDIRECT
            {
                avoid_.start = data.add(SI_ADDR).cast::<u64>().read_unaligned();
                avoid_.size = data.add(SI_LEN).cast::<u64>().read_unaligned();

                if mem_overlaps(img, &avoid_) && avoid_.start < earliest {
                    *overlap = avoid_;
                    earliest = overlap.start;
                    is_overlapping = true;
                }
            }

            ptr_ = ptr_.add(SD_NEXT).cast::<u64>().read_unaligned() as usize as *const u8;
        }
    }

    is_overlapping
}

unsafe fn store_slot_info(region: &MemVector, image_size: c_ulong) {
    // SAFETY: single-threaded boot stub; index checked against MAX_SLOT_AREA just below.
    unsafe {
        if slot_area_index as usize == MAX_SLOT_AREA {
            return;
        }

        let mut sa = SlotArea { addr: 0, num: 0 };
        sa.addr = region.start;
        sa.num = 1u64.wrapping_add(udiv(region.size.wrapping_sub(image_size), phys_align()));

        *slot_area(slot_area_index as usize) = sa;
        slot_area_index += 1;
        slot_max = slot_max.wrapping_add(sa.num);
    }
}

/// Skip as many 1GB huge pages as possible in the passed region according to the number which users
/// specified.
unsafe fn process_gb_huge_pages(region: &MemVector, image_size: c_ulong) {
    // SAFETY: single-threaded boot stub.
    unsafe {
        // `!IS_ENABLED(CONFIG_X86_64 ) ||` is false here.
        if max_gb_huge_pages == 0 {
            store_slot_info(region, image_size);
            return;
        }

        // Are there any 1GB pages in the region?
        let pud_start: u64 = align_up(region.start, PUD_SIZE);
        let mut pud_end: u64 = align_down(region.start.wrapping_add(region.size), PUD_SIZE);

        // No good 1GB huge pages found:
        if pud_start >= pud_end {
            store_slot_info(region, image_size);
            return;
        }

        // Check if the head part of the region is usable.
        if pud_start >= region.start.wrapping_add(image_size) {
            let tmp = MemVector { start: region.start, size: pud_start.wrapping_sub(region.start) };
            store_slot_info(&tmp, image_size);
        }

        // Skip the good 1GB pages.
        let gb_huge_pages: c_ulong = pud_end.wrapping_sub(pud_start) >> PUD_SHIFT;
        if gb_huge_pages > max_gb_huge_pages {
            pud_end = pud_start.wrapping_add(max_gb_huge_pages << PUD_SHIFT);
            max_gb_huge_pages = 0;
        } else {
            max_gb_huge_pages = max_gb_huge_pages.wrapping_sub(gb_huge_pages);
        }

        // Check if the tail part of the region is usable.
        if region.start.wrapping_add(region.size) >= pud_end.wrapping_add(image_size) {
            let tmp = MemVector { start: pud_end, size: region.start.wrapping_add(region.size).wrapping_sub(pud_end) };
            store_slot_info(&tmp, image_size);
        }
    }
}

unsafe fn slots_fetch_random() -> u64 {
    // SAFETY: single-threaded boot stub.
    unsafe {
        // Handle case of no slots stored.
        if slot_max == 0 {
            return 0;
        }

        let slot: c_ulong = urem(kaslr_get_random_long(c"Physical".as_ptr()), slot_max);

        slot_lookup(slot)
    }
}

/// The part of slots_fetch_random() after the random number: walk slot_areas[] to the slot'th slot (split out so the
/// Kani proofs can run it without the hardware entropy).
unsafe fn slot_lookup(slot: c_ulong) -> u64 {
    let mut slot = slot;
    // SAFETY: single-threaded boot stub.
    unsafe {
        let mut i: c_uint = 0;
        while i < slot_area_index {
            let sa = *slot_area(i as usize);
            if slot >= sa.num {
                slot = slot.wrapping_sub(sa.num);
                i += 1;
                continue;
            }
            return sa.addr.wrapping_add((slot as u64).wrapping_mul(phys_align()));
        }

        if i == slot_area_index {
            debug_putstr!(c"slots_fetch_random() failed!?\n");
        }
        0
    }
}

unsafe fn __process_mem_region(entry: &MemVector, minimum: c_ulong, image_size: c_ulong) {
    let mut region = MemVector { start: 0, size: 0 };
    let mut overlap = MemVector { start: 0, size: 0 };

    // SAFETY: single-threaded boot stub.
    unsafe {
        // Enforce minimum and memory limit.
        region.start = if entry.start >= minimum { entry.start } else { minimum }; // max_t(u64, ...)
        let sum = entry.start.wrapping_add(entry.size);
        let region_end: u64 = if sum <= mem_limit { sum } else { mem_limit }; // min(...)

        // Give up if slot area array is full.
        while (slot_area_index as usize) < MAX_SLOT_AREA {
            // Potentially raise address to meet alignment needs.
            region.start = align_up(region.start, phys_align());

            // Did we raise the address above the passed in memory entry?
            if region.start > region_end {
                return;
            }

            // Reduce size by any delta from the original address.
            region.size = region_end.wrapping_sub(region.start);

            // Return if region can't contain decompressed kernel
            if region.size < image_size {
                return;
            }

            // If nothing overlaps, store the region and return.
            if !mem_avoid_overlap(&region, &mut overlap) {
                process_gb_huge_pages(&region, image_size);
                return;
            }

            // Store beginning of region if holds at least image_size.
            if overlap.start >= region.start.wrapping_add(image_size) {
                region.size = overlap.start.wrapping_sub(region.start);
                process_gb_huge_pages(&region, image_size);
            }

            // Clip off the overlapping region and start over.
            region.start = overlap.start.wrapping_add(overlap.size);
        }
    }
}

unsafe fn process_mem_region(region: &MemVector, minimum: c_ulong, image_size: c_ulong) -> bool {
    // SAFETY: single-threaded boot stub.
    unsafe {
        // If no immovable memory found, or MEMORY_HOTREMOVE disabled, use @region directly.
        if num_immovable_mem == 0 {
            __process_mem_region(region, minimum, image_size);

            if slot_area_index as usize == MAX_SLOT_AREA {
                debug_putstr!(c"Aborted e820/efi memmap scan (slot_areas full)!\n");
                return true;
            }
            return false;
        }

        // #if defined(CONFIG_MEMORY_HOTREMOVE) && defined(CONFIG_ACPI)
        #[cfg(hotremove_acpi)]
        {
            // If immovable memory found, filter the intersection between immovable memory and @region.
            let mut i: c_int = 0;
            while i < num_immovable_mem {
                let im = *(ptr::addr_of!(immovable_mem) as *const MemVector).add(i as usize);

                if !mem_overlaps(region, &im) {
                    i += 1;
                    continue;
                }

                let start: u64 = im.start;
                let end: u64 = start.wrapping_add(im.size);
                let region_end: u64 = region.start.wrapping_add(region.size);

                let mut entry = MemVector { start: 0, size: 0 };
                entry.start = clamp(region.start, start, end);
                let entry_end: u64 = clamp(region_end, start, end);
                entry.size = entry_end.wrapping_sub(entry.start);

                __process_mem_region(&entry, minimum, image_size);

                if slot_area_index as usize == MAX_SLOT_AREA {
                    debug_putstr!(c"Aborted e820/efi memmap scan when walking immovable regions(slot_areas full)!\n");
                    return true;
                }
                i += 1;
            }
        }
        false
    }
}

/// Only EFI_CONVENTIONAL_MEMORY and EFI_UNACCEPTED_MEMORY (if supported) are guaranteed to be free.
///
/// Pick free memory more conservatively than the EFI spec allows: according to the spec,
/// EFI_BOOT_SERVICES_{CODE|DATA} are also free memory and thus available to place the kernel image
/// into, but in practice there's firmware where using that memory leads to crashes. Preserve
/// EFI_BOOT_SERVICES_* regions until after SetVirtualAddressMap().
#[cfg(efi)]
unsafe fn memory_type_is_free(md: *const u8) -> bool {
    // SAFETY: md points at a firmware efi_memory_desc_t.
    let ty = unsafe { md.add(EFI_MD_TYPE).cast::<u32>().read_unaligned() };

    if ty == EFI_CONVENTIONAL_MEMORY {
        return true;
    }

    #[cfg(unaccepted_memory)]
    if ty == EFI_UNACCEPTED_MEMORY {
        return true;
    }

    false
}

/// Returns true if we processed the EFI memmap, which we prefer over the E820 table if it is available.
#[cfg(efi)]
unsafe fn process_efi_entries(minimum: c_ulong, image_size: c_ulong) -> bool {
    let mut efi_mirror_found = false;
    let mut region = MemVector { start: 0, size: 0 };

    // SAFETY: boot_params efi_info fields are inside the 4096 bytes; the memmap is the firmware's
    // (identity mapped physical memory), addressed per efi_early_memdesc_ptr() with the u32 stride arithmetic.
    unsafe {
        let e: *const u8 = bp().add(BP_EFI_INFO);
        let signature = e.add(EI_LOADER_SIGNATURE) as *const c_char;
        if strncmp(signature, c"EL32".as_ptr(), 4) != 0 && strncmp(signature, c"EL64".as_ptr(), 4) != 0 {
            return false;
        }

        // Dead arm: `#ifdef CONFIG_X86_32` "EFI memmap is above 4GB, can't be handled now on x86_32" (+ `pmap = e->efi_memmap`).
        let memmap = e.add(EI_MEMMAP).cast::<u32>().read_unaligned();
        let memmap_hi = e.add(EI_MEMMAP_HI).cast::<u32>().read_unaligned();
        let pmap: c_ulong = (memmap as u64 | ((memmap_hi as u64) << 32)) as c_ulong;

        let memdesc_size: u32 = e.add(EI_MEMDESC_SIZE).cast::<u32>().read_unaligned();
        let nr_desc: u32 = div_u32(e.add(EI_MEMMAP_SIZE).cast::<u32>().read_unaligned(), memdesc_size);

        // efi_early_memdesc_ptr(map, desc_size, n): (void *)map + (n * desc_size), `int * u32` in u32.
        let md_at = |n: c_int| -> *const u8 { (pmap as usize).wrapping_add((n as u32).wrapping_mul(memdesc_size) as usize) as *const u8 };

        let mut i: c_int = 0;
        while (i as u32) < nr_desc {
            let md = md_at(i);
            if md.add(EFI_MD_ATTRIBUTE).cast::<u64>().read_unaligned() & EFI_MEMORY_MORE_RELIABLE != 0 {
                efi_mirror_found = true;
                break;
            }
            i = i.wrapping_add(1);
        }

        i = 0;
        while (i as u32) < nr_desc {
            let md = md_at(i);

            if !memory_type_is_free(md) {
                i = i.wrapping_add(1);
                continue;
            }

            let attribute = md.add(EFI_MD_ATTRIBUTE).cast::<u64>().read_unaligned();
            if kaslr_soft_reserve_enabled() && (attribute & EFI_MEMORY_SP != 0) {
                i = i.wrapping_add(1);
                continue;
            }

            if efi_mirror_found && (attribute & EFI_MEMORY_MORE_RELIABLE == 0) {
                i = i.wrapping_add(1);
                continue;
            }

            region.start = md.add(EFI_MD_PHYS_ADDR).cast::<u64>().read_unaligned();
            region.size = md.add(EFI_MD_NUM_PAGES).cast::<u64>().read_unaligned() << EFI_PAGE_SHIFT;
            if process_mem_region(&region, minimum, image_size) {
                break;
            }
            i = i.wrapping_add(1);
        }
        true
    }
}

/// Without CONFIG_EFI: `static inline bool process_efi_entries() { return false; }`.
#[cfg(not(efi))]
unsafe fn process_efi_entries(_minimum: c_ulong, _image_size: c_ulong) -> bool {
    false
}

unsafe fn process_e820_entries(minimum: c_ulong, image_size: c_ulong) {
    let mut region = MemVector { start: 0, size: 0 };

    // SAFETY: boot_params is valid; the table index is the u8 e820_entries (<= 255; the loader bounds it
    // by E820_MAX_ENTRIES_ZEROPAGE, as for the C).
    unsafe {
        // Verify potential e820 positions, appending to slots list.
        let mut i: c_int = 0;
        while i < bp().add(BP_E820_ENTRIES).read() as c_int {
            let entry: *const u8 = bp().add(BP_E820_TABLE + (i as usize) * E820_ENTRY_SIZE);
            // Skip non-RAM entries.
            if entry.add(E820_TYPE).cast::<u32>().read_unaligned() != E820_TYPE_RAM {
                i += 1;
                continue;
            }
            region.start = entry.add(E820_ADDR).cast::<u64>().read_unaligned();
            region.size = entry.add(E820_SIZE).cast::<u64>().read_unaligned();
            if process_mem_region(&region, minimum, image_size) {
                break;
            }
            i += 1;
        }
    }
}

/// If KHO is active, only process its scratch areas to ensure we are not stepping onto preserved memory.
#[cfg(kexec_handover)]
unsafe fn process_kho_entries(minimum: c_ulong, image_size: c_ulong) -> bool {
    let mut kho_scratch: *const u8 = ptr::null();
    let mut nr_areas: c_int = 0;

    // SAFETY: the setup_data list and the KHO scratch table are boot-loader memory (physical addresses,
    // identity mapped in the stub), read with read_unaligned.
    unsafe {
        let mut ptr_: *const u8 = bp_u64(BP_HDR_SETUP_DATA) as usize as *const u8;
        while !ptr_.is_null() {
            if ptr_.add(SD_TYPE).cast::<u32>().read_unaligned() == SETUP_KEXEC_KHO {
                let kho = ptr_.add(SD_DATA);
                kho_scratch = kho.add(KHO_SCRATCH_ADDR).cast::<u64>().read_unaligned() as usize as *const u8;
                // `int nr_areas = kho->scratch_size / sizeof(*kho_scratch)`: u64 quotient truncated to int.
                nr_areas = (kho.add(KHO_SCRATCH_SIZE).cast::<u64>().read_unaligned() / KHO_SCRATCH_STRUCT_SIZE as u64) as c_int;
                break;
            }

            ptr_ = ptr_.add(SD_NEXT).cast::<u64>().read_unaligned() as usize as *const u8;
        }

        if nr_areas == 0 {
            return false;
        }

        let mut i: c_int = 0;
        while i < nr_areas {
            let area = kho_scratch.wrapping_add(i as isize as usize * KHO_SCRATCH_STRUCT_SIZE);
            let region = MemVector {
                start: area.cast::<u64>().read_unaligned(),
                size: area.add(KS_SIZE).cast::<u64>().read_unaligned(),
            };

            if process_mem_region(&region, minimum, image_size) {
                break;
            }
            i += 1;
        }

        true
    }
}

/// Without CONFIG_KEXEC_HANDOVER: `if (!IS_ENABLED(CONFIG_KEXEC_HANDOVER)) return false;`.
#[cfg(not(kexec_handover))]
unsafe fn process_kho_entries(_minimum: c_ulong, _image_size: c_ulong) -> bool {
    false
}

unsafe fn find_random_phys_addr(minimum: c_ulong, image_size: c_ulong) -> c_ulong {
    // SAFETY: single-threaded boot stub.
    unsafe {
        // Bail out early if it's impossible to succeed.
        if minimum.wrapping_add(image_size) > mem_limit {
            return 0;
        }

        // Check if we had too many memmaps.
        if memmap_too_large {
            debug_putstr!(c"Aborted memory entries scan (more than 4 memmap= args)!\n");
            return 0;
        }

        // During kexec handover only process KHO scratch areas that are known not to contain any data
        // that must be preserved.
        if !process_kho_entries(minimum, image_size) && !process_efi_entries(minimum, image_size) {
            process_e820_entries(minimum, image_size);
        }

        let phys_addr: u64 = slots_fetch_random();

        // Perform a final check to make sure the address is in range.
        if phys_addr < minimum || phys_addr.wrapping_add(image_size) > mem_limit {
            warn(c"Invalid physical address chosen!\n".as_ptr());
            return 0;
        }

        phys_addr as c_ulong
    }
}

unsafe fn find_random_virt_addr(minimum: c_ulong, image_size: c_ulong) -> c_ulong {
    // SAFETY: kaslr_physical_align is never 0; slots >= 1 + 0 and cannot wrap to 0 (the quotient is at
    // most (2^64-1)/2 as CONFIG_PHYSICAL_ALIGN >= 2).
    unsafe {
        // There are how many CONFIG_PHYSICAL_ALIGN-sized slots that can hold image_size within the range
        // of minimum to KERNEL_IMAGE_SIZE?
        let slots: c_ulong = 1u64.wrapping_add(udiv(
            kaslr_kernel_image_size.wrapping_sub(minimum).wrapping_sub(image_size),
            phys_align(),
        ));

        let random_addr: c_ulong = urem(kaslr_get_random_long(c"Virtual".as_ptr()), slots);

        random_addr.wrapping_mul(phys_align()).wrapping_add(minimum)
    }
}

/// Since this function examines addresses much more numerically, it takes the input and output
/// pointers as 'unsigned long'.
#[no_mangle]
pub unsafe extern "C" fn choose_random_location(
    input: c_ulong,
    input_size: c_ulong,
    output: *mut c_ulong,
    output_size: c_ulong,
    virt_addr: *mut c_ulong,
) {
    // SAFETY: the caller (misc.c extract_kernel()) passes valid pointers; boot_params_ptr is set.
    unsafe {
        if cmdline_find_option_bool(c"nokaslr".as_ptr()) != 0 {
            warn(c"KASLR disabled: 'nokaslr' on cmdline.".as_ptr());
            return;
        }

        let lf = bp().add(BP_HDR_LOADFLAGS);
        lf.write(lf.read() | KASLR_FLAG);

        // Dead arm: `if (IS_ENABLED(CONFIG_X86_32)) mem_limit = KERNEL_IMAGE_SIZE;`
        mem_limit = kaslr_maxmem();

        // Record the various known unsafe memory ranges.
        mem_avoid_init(input, input_size, *output);

        // Low end of the randomization range should be the smaller of 512M or the initial kernel image
        // location:
        let cap: c_ulong = 512 << 20;
        let mut min_addr: c_ulong = if *output <= cap { *output } else { cap };
        // Make sure minimum is aligned.
        min_addr = align_up(min_addr, phys_align());

        // Walk available memory entries to find a random address.
        let mut random_addr: c_ulong = find_random_phys_addr(min_addr, output_size);
        if random_addr == 0 {
            warn(c"Physical KASLR disabled: no suitable memory region!".as_ptr());
        } else {
            // Update the new physical address location.
            if *output != random_addr {
                *output = random_addr;
            }
        }

        // Pick random virtual address starting from LOAD_PHYSICAL_ADDR. (`IS_ENABLED(CONFIG_X86_64)` is true.)
        random_addr = find_random_virt_addr(kaslr_load_physical_addr, output_size);
        *virt_addr = random_addr;
    }
}

// ------------------------------------------------------------------------------------------------
// Kani proofs (cd rig/stubf/kani && cargo kani).  They run on THIS code (not a model); see logs/stubf-boot-protocol.md for
// exactly what is covered and what is not.
// ------------------------------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// A symbolic power-of-two alignment 2^0 .. 2^40, installed as CONFIG_PHYSICAL_ALIGN.
    fn pow2_align() -> u64 {
        let e: u32 = kani::any();
        kani::assume(e <= 40);
        let a = 1u64 << e;
        // SAFETY: single-threaded harness.
        unsafe { KANI_ALIGN = a };
        a
    }

    #[kani::proof]
    fn mem_overlaps_is_interval_intersection() {
        let a = MemVector { start: kani::any(), size: kani::any() };
        let b = MemVector { start: kani::any(), size: kani::any() };
        kani::assume(a.size > 0 && b.size > 0);
        kani::assume(a.start.checked_add(a.size).is_some() && b.start.checked_add(b.size).is_some());
        let r = mem_overlaps(&a, &b);
        assert_eq!(r, a.start < b.start + b.size && b.start < a.start + a.size);
        assert_eq!(r, mem_overlaps(&b, &a));
    }

    #[kani::proof]
    fn align_up_and_down_are_exact() {
        let a = pow2_align();
        let x: u64 = kani::any();
        let mask = a - 1;
        if x <= u64::MAX - mask {
            let u = align_up(x, a);
            assert!(u & mask == 0 && u >= x && u - x < a);
        }
        let d = align_down(x, a);
        assert!(d & mask == 0 && d <= x && x - d < a);
    }

    /// store_slot_info(): for any aligned region that can hold the image, the recorded (addr, num) describes only slots that are
    /// aligned, inside the region and large enough for the image, with no u64 wrap in any address computation.
    #[kani::proof]
    fn store_slot_info_slots_fit() {
        let a = pow2_align();
        let start: u64 = kani::any();
        let size: u64 = kani::any();
        let image: u64 = kani::any();
        kani::assume(image >= 1 && size >= image);
        kani::assume(start & (a - 1) == 0);
        kani::assume(start.checked_add(size).is_some());
        // SAFETY: single-threaded harness resets the statics the function updates.
        unsafe {
            slot_area_index = 0;
            slot_max = 0;
            store_slot_info(&MemVector { start, size }, image);
            let sa = *slot_area(0);
            assert!(sa.addr == start && sa.num >= 1 && slot_max == sa.num && slot_area_index == 1);
            let k: u64 = kani::any();
            kani::assume(k < sa.num);
            let off = k.checked_mul(a).unwrap();
            let addr = sa.addr.checked_add(off).unwrap();
            assert!(addr & (a - 1) == 0 && addr >= start);
            assert!(addr.checked_add(image).unwrap() <= start + size);
        }
    }

    /// slots_fetch_random()'s lookup: every slot number below the total maps to slot (slot - earlier areas) of the right area.
    #[kani::proof]
    fn slot_lookup_finds_the_right_area() {
        let a = pow2_align();
        let n: [u64; 3] = [kani::any(), kani::any(), kani::any()];
        let addr: [u64; 3] = [kani::any(), kani::any(), kani::any()];
        let mut i = 0;
        while i < 3 {
            kani::assume(n[i].checked_mul(a).is_some() && addr[i].checked_add(n[i] * a).is_some());
            i += 1;
        }
        let total = n[0].checked_add(n[1]).and_then(|t| t.checked_add(n[2]));
        kani::assume(total.is_some());
        // SAFETY: single-threaded harness fills the statics the function reads.
        unsafe {
            *slot_area(0) = SlotArea { addr: addr[0], num: n[0] };
            *slot_area(1) = SlotArea { addr: addr[1], num: n[1] };
            *slot_area(2) = SlotArea { addr: addr[2], num: n[2] };
            slot_area_index = 3;
            let slot: u64 = kani::any();
            kani::assume(slot < total.unwrap());
            let r = slot_lookup(slot);
            let want = if slot < n[0] {
                addr[0] + slot * a
            } else if slot - n[0] < n[1] {
                addr[1] + (slot - n[0]) * a
            } else {
                addr[2] + (slot - n[0] - n[1]) * a
            };
            assert_eq!(r, want);
        }
    }

    /// process_gb_huge_pages(): every piece it records lies inside the region and never intersects the 1 GiB pages it skips;
    /// the number of skipped pages is min(pages in region, max_gb_huge_pages).  (Region limited to 2^44 and 21-bit alignment.)
    #[kani::proof]
    #[kani::unwind(4)]
    fn gb_huge_pages_pieces_avoid_the_skipped_pages() {
        let a: u64 = 0x200000;
        // SAFETY: single-threaded harness.
        unsafe { KANI_ALIGN = a };
        let start: u64 = kani::any();
        let size: u64 = kani::any();
        let image: u64 = kani::any();
        let maxp: u64 = kani::any();
        kani::assume(start < (1 << 44) && size < (1 << 44) && image >= 1 && image <= size && start & (a - 1) == 0);
        kani::assume(maxp >= 1 && maxp < 8);
        // SAFETY: single-threaded harness.
        unsafe {
            slot_area_index = 0;
            slot_max = 0;
            max_gb_huge_pages = maxp;
            process_gb_huge_pages(&MemVector { start, size }, image);
            let end = start + size;
            let pud_s = align_up(start, PUD_SIZE);
            let pud_e = align_down(end, PUD_SIZE);
            let n = slot_area_index as usize;
            assert!(n <= 2);
            if pud_s >= pud_e {
                // no whole 1 GiB page: the region is recorded unchanged, nothing skipped
                assert!(n == 1 && (*slot_area(0)).addr == start && max_gb_huge_pages == maxp);
            } else {
                let pages = (pud_e - pud_s) >> PUD_SHIFT;
                let cap_e = if pages > maxp { pud_s + (maxp << PUD_SHIFT) } else { pud_e };
                assert!(max_gb_huge_pages == if pages > maxp { 0 } else { maxp - pages });
                let mut i = 0;
                while i < n {
                    let sa = *slot_area(i);
                    // the recorded piece is [sa.addr, sa.addr + (sa.num-1)*a + image) at most; its full extent is inside the region
                    let last_end = sa.addr + (sa.num - 1) * a + image;
                    assert!(sa.addr >= start && last_end <= end);
                    // ... and entirely below the skipped pages, or entirely above them
                    assert!(last_end <= pud_s || sa.addr >= cap_e);
                    i += 1;
                }
            }
        }
    }
}
