// SPDX-License-Identifier: GPL-2.0

//! Rust replacement for `arch/x86/boot/startup/gdt_idt.c`: the first C-callable code the
//! kernel proper runs after the decompressor (`head_64.S:74` and `head64.c:322`).
//!
//! THIS IS A `.pi.o` OBJECT (position independent, `__pi_` symbol prefix; see
//! `logs/phase-e-pi.md`). It runs on the IDENTITY MAPPING, before the kernel's virtual
//! addresses are usable, so it must contain
//!   * no absolute relocation (objtool `--noabs`), no GOT, no PLT to a non-`__pi_` symbol;
//!   * no panic path (any `panic_const_*` / `core::panicking` call is an undefined symbol
//!     that does not exist with the `__pi_` prefix, and would run on the wrong mapping).
//! Addresses of kernel symbols are taken with `lea reg, [rip + sym]` in inline asm
//! (the C's `rip_rel_ptr()`), so the code model of the compiler cannot change them.
//!
//! Symbols, after `llvm-objcopy --prefix-symbols=__pi_`: `__pi_startup_64_load_idt` (also
//! called from `early_setup_idt()`, head64.c) and `__pi_startup_64_setup_gdt_idt`.
//!
//! TEST-GAP: an error here is a triple fault (silent reset; no message): a wrong GDT limit,
//! a wrong `lgdt`/`lidt` operand, a wrong segment value. The boot reaching userspace on both
//! x86 configs is the proof that this code ran correctly; the `vc_handler` arm
//! (CONFIG_AMD_MEM_ENCRYPT) is compile-checked only (logs/test-gaps.md).
//!
//! Replaces: arch/x86/boot/startup/gdt_idt.c

use core::arch::{asm, global_asm};

/// `NUM_EXCEPTION_VECTORS` (asm/segment.h).
const NUM_EXCEPTION_VECTORS: usize = 32;
/// `X86_TRAP_VC` (asm/trapnr.h): VMM Communication Exception.
const X86_TRAP_VC: usize = 29;
/// `__KERNEL_CS` = `GDT_ENTRY_KERNEL_CS (2) * 8` (x86-64).
const KERNEL_CS: u64 = 0x10;
/// `__KERNEL_DS` = `GDT_ENTRY_KERNEL_DS (3) * 8` (x86-64).
const KERNEL_DS: u32 = 0x18;
/// `GDT_SIZE` = `GDT_ENTRIES (16) * 8` (x86-64).
const GDT_SIZE: u16 = 16 * 8;
/// `enum desc_type`: `GATE_INTERRUPT`.
const GATE_INTERRUPT: u64 = 0xE;

/// `gate_desc` (`struct gate_struct`, 16 bytes, packed) as two little-endian u64 words.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GateDesc {
    /// Bytes 0..8: offset_low, segment, bits, offset_middle.
    pub lo: u64,
    /// Bytes 8..16: offset_high, reserved.
    pub hi: u64,
}

/// `struct desc_ptr` (packed): `u16 size; unsigned long address`.
#[repr(C, packed)]
struct DescPtr {
    size: u16,
    address: u64,
}

const _: () = assert!(core::mem::size_of::<GateDesc>() == 16);
const _: () = assert!(core::mem::size_of::<DescPtr>() == 10);
const _: () = assert!(core::mem::offset_of!(DescPtr, address) == 2);

/// `bringup_idt_table`: `.data..page_aligned`, zero. The C object is 512 bytes in a 4096-aligned
/// section; a Rust type cannot be aligned to 4096 without being padded to 4096, so the symbol is
/// 4096 bytes. Every other `.data..page_aligned` member is itself page aligned, so no address moves
/// (logs/phase-e-pi.md, checked against the C vmlinux).
#[repr(C, align(4096))]
struct BringupIdt([GateDesc; NUM_EXCEPTION_VECTORS]);

#[no_mangle]
#[link_section = ".data..page_aligned"]
#[allow(non_upper_case_globals)]
static mut bringup_idt_table: BringupIdt = BringupIdt([GateDesc { lo: 0, hi: 0 }; NUM_EXCEPTION_VECTORS]);

// The C is built with `-include hidden.h` (every symbol `visibility("hidden")`), so after the final
// link none of these is a global symbol: `/proc/kallsyms` shows `t`/`d`, not `T`/`D`. Rust has no
// per-file default visibility on the pinned rustc, so the same is said to the assembler: hidden on
// the three definitions and on the kernel symbols this file references.
global_asm!(
    ".hidden startup_64_load_idt",
    ".hidden startup_64_setup_gdt_idt",
    ".hidden bringup_idt_table",
    ".hidden gdt_page",
);
#[cfg(CONFIG_AMD_MEM_ENCRYPT)]
global_asm!(".hidden vc_no_ghcb");

/// What `init_idt_data()` + `idt_init_desc()` build for `X86_TRAP_VC`: offset_low, segment =
/// `__KERNEL_CS`, bits = { type = GATE_INTERRUPT, p = 1 } (ist = dpl = 0), offset_middle,
/// offset_high, reserved = 0. Pure, so it is compared with the C bitfield code in userspace
/// (`rig/phase-e/`) and proved with Z3 (`logs/proofs/gdt-idt-gate.py`).
pub const fn interrupt_gate(address: u64) -> GateDesc {
    // idt_bits: ist:3 zero:5 type:5 dpl:2 p:1 -> type at bit 8, p at bit 15.
    let bits: u64 = (GATE_INTERRUPT << 8) | (1 << 15);
    GateDesc {
        lo: (address & 0xffff) | (KERNEL_CS << 16) | (bits << 32) | (((address >> 16) & 0xffff) << 48),
        hi: address >> 32,
    }
}

extern "C" {
    /// The boot CPU's `struct gdt_page` (`DEFINE_PER_CPU_PAGE_ALIGNED`); only its address is used.
    static gdt_page: [u64; GDT_SIZE as usize / 8];
    /// head_64.S: the #VC handler used before a GHCB exists.
    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    fn vc_no_ghcb();
}

/// `native_load_idt()`.
///
/// # Safety
/// `desc` must describe a valid IDT (ring 0).
#[inline(always)]
unsafe fn load_idt(desc: *const DescPtr) {
    // SAFETY: the C was `asm volatile("lidt %0" :: "m" (*dtr))`.
    unsafe { asm!("lidt [{}]", in(reg) desc, options(readonly, nostack, preserves_flags)) };
}

/// This may run while still in the direct mapping.
///
/// `vc_handler` is set only for a VMM Communication Exception.
///
/// # Safety
/// Ring 0, early boot, single CPU; `vc_handler` null or a handler entry point.
#[no_mangle]
pub unsafe extern "C" fn startup_64_load_idt(vc_handler: *mut core::ffi::c_void) {
    let table: *mut GateDesc;
    // rip_rel_ptr(bringup_idt_table): a lea, valid on the identity mapping.
    // SAFETY: only takes the address of the static.
    unsafe {
        asm!("lea {}, [rip + {}]", out(reg) table, sym bringup_idt_table,
             options(pure, nomem, nostack, preserves_flags));
    }
    let desc = DescPtr {
        size: (NUM_EXCEPTION_VECTORS * 16 - 1) as u16,
        address: table as usize as u64,
    };

    if !vc_handler.is_null() {
        // SAFETY: X86_TRAP_VC < NUM_EXCEPTION_VECTORS; the table is the static above.
        unsafe {
            table.add(X86_TRAP_VC).write(interrupt_gate(vc_handler as usize as u64));
        }
    }

    // SAFETY: `desc` describes the bringup table.
    unsafe { load_idt(&desc) };
}

/// Setup boot CPU state needed before kernel switches to virtual addresses.
///
/// # Safety
/// Called once from `head_64.S` on the boot CPU, on the identity mapping.
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn startup_64_setup_gdt_idt() {
    let gdt: usize;
    // rip_rel_ptr(&gdt_page): `gdt_page` is `__pi_gdt_page` after the prefixing (a linker-provided
    // alias of the per-CPU init copy); `gdt` is its first member.
    // SAFETY: only takes the address of the symbol.
    unsafe {
        asm!("lea {}, [rip + {}]", out(reg) gdt, sym gdt_page, options(pure, nomem, nostack, preserves_flags));
    }
    let startup_gdt_descr = DescPtr { size: GDT_SIZE - 1, address: gdt as u64 };

    // Load GDT, then reload the data segment registers: the new GDT is live.
    // SAFETY: the C was `native_load_gdt()` (lgdt) and `movl %eax, %ds/%ss/%es` with `__KERNEL_DS`.
    unsafe {
        asm!("lgdt [{}]", in(reg) &startup_gdt_descr, options(readonly, nostack, preserves_flags));
        asm!("mov ds, {0:e}", "mov ss, {0:e}", "mov es, {0:e}",
             in(reg) KERNEL_DS, options(nostack, preserves_flags));
    }

    #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
    let handler: *mut core::ffi::c_void = {
        let h: usize;
        // SAFETY: only takes the address of the symbol (`__pi_vc_no_ghcb`).
        unsafe {
            asm!("lea {}, [rip + {}]", out(reg) h, sym vc_no_ghcb, options(pure, nomem, nostack, preserves_flags));
        }
        h as *mut core::ffi::c_void
    };
    #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
    let handler: *mut core::ffi::c_void = core::ptr::null_mut();

    // SAFETY: as above.
    unsafe { startup_64_load_idt(handler) };
}
