// SPDX-License-Identifier: GPL-2.0

//! Rust part of `arch/x86/kernel/idt.c`: the gate writer and the early-IDT group
//! (`idt_setup_from_table`, the bodies of `idt_setup_early_traps`, `idt_setup_early_pf`
//! and `idt_setup_early_handler`, and the two early gate tables). The rest of the file stays C in
//! `idt_glue.c` (see `logs/hooks.md`, the idt record).
//!
//! All of it runs on the boot CPU, interrupts off, in `setup_arch()` / `trap_init()` /
//! `init_IRQ()`, before the allocator and before any other CPU exists. Not a `.pi.o`: ordinary
//! kernel-address code. A panic path here would run on the early IDT, so there is none (raw
//! pointer arithmetic and masked shifts only; see the `nm` check in logs/hooks.md).
//!
//! The C's `idt_table` and `idt_descr` are `static` in `idt_glue.c` (the rest of the file uses
//! them), so the three C entry functions there pass them in: the Rust never names them.
//!
//! Deliberately not carried over: the `BUG_ON(n > 0xFF)` inside the header inline
//! `init_idt_data()` that `set_intr_gate()` runs. `idt_setup_early_handler()` calls it with
//! `n < NUM_EXCEPTION_VECTORS` (32), so it cannot fire here; the C `set_intr_gate()` (still used by
//! the APIC / IRQ gates and `idt_install_sysvec()`) keeps its own. Recorded in logs/deviations.md.
//!
//! Replaces (x86-64 only): the functions above in arch/x86/kernel/idt.c

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

// C-HEADERS: linux/types.h asm/desc_defs.h asm/segment.h asm/trapnr.h asm/ibt.h asm/idtentry.h
/// `NUM_EXCEPTION_VECTORS` (asm/segment.h).
const NUM_EXCEPTION_VECTORS: usize = 32; // C: NUM_EXCEPTION_VECTORS
/// `EARLY_IDT_HANDLER_SIZE` (asm/segment.h): `9 + ENDBR_INSN_SIZE`; `ENDBR_INSN_SIZE` is 4 with `CONFIG_X86_KERNEL_IBT`, else 0.
#[cfg(CONFIG_X86_KERNEL_IBT)]
const EARLY_IDT_HANDLER_SIZE: usize = 13; // C: EARLY_IDT_HANDLER_SIZE
/// `EARLY_IDT_HANDLER_SIZE` (asm/segment.h): without IBT.
#[cfg(not(CONFIG_X86_KERNEL_IBT))]
const EARLY_IDT_HANDLER_SIZE: usize = 9; // (no `C:` tag: consts_check cannot follow a cfg arm; neither config here lacks IBT, the arm is covered by the userspace differential's IBT=0 runs)
/// `__KERNEL_CS` = `GDT_ENTRY_KERNEL_CS (2) * 8`.
const KERNEL_CS: u32 = 0x10; // C: __KERNEL_CS
/// `enum desc_type`: `GATE_INTERRUPT`.
const GATE_INTERRUPT: u16 = 0xE; // C: GATE_INTERRUPT
/// `X86_TRAP_DB`.
const X86_TRAP_DB: u32 = 1; // C: X86_TRAP_DB
/// `X86_TRAP_BP`.
const X86_TRAP_BP: u32 = 3; // C: X86_TRAP_BP
/// `X86_TRAP_PF`.
const X86_TRAP_PF: u32 = 14; // C: X86_TRAP_PF
/// `X86_TRAP_VE` (only the TDX arm uses it).
#[cfg(CONFIG_INTEL_TDX_GUEST)]
const X86_TRAP_VE: u32 = 20; // C: X86_TRAP_VE
/// `DPL0`.
const DPL0: u16 = 0; // C: 0x0
/// `DPL3`.
const DPL3: u16 = 3; // C: 0x3
/// `sizeof(gate_desc)`.
const GATE_SIZE: usize = 16; // C: sizeof(gate_desc)
/// `IDT_ENTRIES`.
const IDT_ENTRIES: usize = 256; // C: IDT_ENTRIES
/// `sizeof(struct idt_data)`.
const IDT_DATA_SIZE: usize = 24; // C: sizeof(struct idt_data)
/// `offsetof(struct idt_data, bits)`.
const IDT_DATA_BITS: usize = 8; // C: offsetof(struct idt_data, bits)
/// `offsetof(struct idt_data, addr)`.
const IDT_DATA_ADDR: usize = 16; // C: offsetof(struct idt_data, addr)
/// `BITS_PER_LONG`.
const BITS_PER_LONG: u32 = 64; // C: BITS_PER_LONG

/// `struct idt_data` (asm/desc_defs.h): one gate to install. `bits` is `struct idt_bits`, a
/// packed 16-bit field `ist:3 zero:5 type:5 dpl:2 p:1`, kept as its raw value.
/// Mirrors `struct idt_data`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdtData {
    /// vector number.
    pub vector: u32,
    /// code segment selector.
    pub segment: u32,
    /// `struct idt_bits` as a `u16`.
    pub bits: u16,
    /// handler entry point.
    pub addr: *const c_void,
}

// SAFETY: plain data; the pointer is the address of a kernel entry point, never dereferenced.
unsafe impl Sync for IdtData {}

const _: () = assert!(core::mem::size_of::<IdtData>() == IDT_DATA_SIZE);
const _: () = assert!(core::mem::offset_of!(IdtData, bits) == IDT_DATA_BITS);
const _: () = assert!(core::mem::offset_of!(IdtData, addr) == IDT_DATA_ADDR);

/// `struct desc_ptr` (packed): `u16 size; unsigned long address`.
#[repr(C, packed)]
pub struct DescPtr {
    /// limit.
    pub size: u16,
    /// base.
    pub address: u64,
}

/// `struct idt_bits` as a number: `G()` sets `.ist`, `.type`, `.dpl`, `.p = 1` (`zero` stays 0).
pub const fn idt_bits(ist: u16, ty: u16, dpl: u16) -> u16 {
    (ist & 7) | ((ty & 0x1f) << 8) | ((dpl & 3) << 13) | (1 << 15)
}

/// `idt_init_desc()` (asm/desc.h) for x86-64: the 16 bytes of the gate for `d`, as the two
/// little-endian words the packed `gate_desc` is (`offset_low`, `segment`, `bits`, `offset_middle`
/// | `offset_high`, `reserved` = 0). Pure.
pub fn gate_words(d: &IdtData) -> (u64, u64) {
    let addr = d.addr as usize as u64;
    let lo = (addr & 0xffff)
        | (((d.segment & 0xffff) as u64) << 16)
        | ((d.bits as u64) << 32)
        | (((addr >> 16) & 0xffff) << 48);
    (lo, addr >> 32)
}

/// The system-vector bitmap word and mask for `set_bit(vector, system_vectors)`.
pub fn bitmap_pos(vector: u32) -> (usize, usize) {
    ((vector / BITS_PER_LONG) as usize, 1usize.wrapping_shl(vector % BITS_PER_LONG))
}

/// `idt_setup_from_table()` over explicit state: for each entry build the gate, store it at
/// `idt[vector]`, and, if `sys`, set the vector's bit in `system_vectors` (atomic, as `set_bit()`).
///
/// # Safety
/// `idt` points at an `IDT_ENTRIES`-gate table, `t` at `size` entries whose vectors are below
/// `IDT_ENTRIES`, `sv` at the kernel's `system_vectors` bitmap of `IDT_ENTRIES` bits.
pub unsafe fn from_table(idt: *mut u8, t: *const IdtData, size: i32, sys: bool, sv: *const AtomicUsize) {
    let mut i: i32 = 0;
    while i < size {
        // SAFETY: caller contract; the gate is 16 bytes at a 16-byte-aligned slot of the table.
        unsafe {
            let d = &*t.add(i as usize);
            let (lo, hi) = gate_words(d);
            let slot = idt.add((d.vector as usize).wrapping_mul(GATE_SIZE)).cast::<u64>();
            slot.write_unaligned(lo);
            slot.add(1).write_unaligned(hi);
            if sys {
                let (w, m) = bitmap_pos(d.vector);
                (*sv.add(w)).fetch_or(m, Ordering::SeqCst);
            }
        }
        i = i.wrapping_add(1);
    }
}

/// `early_idts[]` (`__initconst`).
#[cfg_attr(not(userspace_test), link_section = ".init.rodata")]
static EARLY_IDTS: [IdtData; EARLY_IDTS_LEN] = early_idts();

/// `early_pf_idts[]` (`__initconst`).
#[cfg_attr(not(userspace_test), link_section = ".init.rodata")]
static EARLY_PF_IDTS: [IdtData; 1] = early_pf_idts();

/// Number of entries of `early_idts[]`: `#DB`, `#BP`, plus `#VE` with `CONFIG_INTEL_TDX_GUEST`
/// (the `X86_TRAP_PF` entry is `CONFIG_X86_32` only).
#[cfg(CONFIG_INTEL_TDX_GUEST)]
const EARLY_IDTS_LEN: usize = 3;
/// Number of entries of `early_idts[]` without TDX.
#[cfg(not(CONFIG_INTEL_TDX_GUEST))]
const EARLY_IDTS_LEN: usize = 2;

extern "C" {
    // The entry points of arch/x86/entry/entry_64.S / idtentry.h; only their addresses are used.
    fn asm_exc_debug();
    fn asm_exc_int3();
    fn asm_exc_page_fault();
    #[cfg(CONFIG_INTEL_TDX_GUEST)]
    fn asm_exc_virtualization_exception();
    /// `early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE]` (head_64.S).
    static early_idt_handler_array: [u8; NUM_EXCEPTION_VECTORS * EARLY_IDT_HANDLER_SIZE];
    /// `system_vectors` (irq.c): `DECLARE_BITMAP(system_vectors, NR_VECTORS)`.
    static system_vectors: [AtomicUsize; IDT_ENTRIES / 64];
}

/// `INTG()` / `SYSG()`: `G(vector, addr, DEFAULT_STACK, GATE_INTERRUPT, dpl, __KERNEL_CS)`.
const fn gate(vector: u32, addr: unsafe extern "C" fn(), dpl: u16) -> IdtData {
    IdtData { vector, segment: KERNEL_CS, bits: idt_bits(0, GATE_INTERRUPT, dpl), addr: addr as *const c_void }
}

/// The initializer of `early_idts[]`.
const fn early_idts() -> [IdtData; EARLY_IDTS_LEN] {
    let mut t = [gate(X86_TRAP_DB, asm_exc_debug, DPL0); EARLY_IDTS_LEN];
    t[1] = gate(X86_TRAP_BP, asm_exc_int3, DPL3);
    #[cfg(CONFIG_INTEL_TDX_GUEST)]
    {
        t[2] = gate(X86_TRAP_VE, asm_exc_virtualization_exception, DPL0);
    }
    t
}

/// The initializer of `early_pf_idts[]`.
const fn early_pf_idts() -> [IdtData; 1] {
    [gate(X86_TRAP_PF, asm_exc_page_fault, DPL0)]
}

/// `native_load_idt()`.
///
/// # Safety
/// `desc` describes a valid IDT; ring 0.
#[cfg(not(userspace_test))]
#[inline(always)]
unsafe fn load_idt(desc: *const DescPtr) {
    // SAFETY: the C was `asm volatile("lidt %0" :: "m" (*dtr))`.
    unsafe { core::arch::asm!("lidt [{}]", in(reg) desc, options(readonly, nostack, preserves_flags)) };
}
/// Userspace test: the harness records the descriptor.
#[cfg(userspace_test)]
unsafe fn load_idt(desc: *const DescPtr) {
    extern "C" {
        fn test_load_idt(d: *const DescPtr);
    }
    // SAFETY: the harness records the descriptor.
    unsafe { test_load_idt(desc) };
}

// The C `static` helper became a global symbol so `idt_glue.c` can call it; hidden, so that after
// the final link it is local again like the C (`/proc/kallsyms` letter `t`).
#[cfg(not(userspace_test))]
core::arch::global_asm!(
    ".hidden idt_setup_from_table",
    ".hidden idt_setup_early_traps_rs",
    ".hidden idt_setup_early_pf_rs",
    ".hidden idt_setup_early_handler_rs",
);

/// `idt_setup_from_table()` against the kernel's `system_vectors`.
///
/// # Safety
/// As [`from_table`].
pub unsafe fn setup_from_table(idt: *mut u8, t: *const IdtData, size: i32, sys: bool) {
    // SAFETY: caller contract.
    unsafe { from_table(idt, t, size, sys, &raw const system_vectors as *const AtomicUsize) };
}

/// Body of `idt_setup_early_traps()`: the early traps, then `load_idt(&idt_descr)`.
///
/// # Safety
/// `idt` = `idt_table`, `descr` = `&idt_descr`; boot CPU, early.
pub unsafe fn early_traps(idt: *mut u8, descr: *const DescPtr) {
    // SAFETY: caller contract.
    unsafe {
        setup_from_table(idt, EARLY_IDTS.as_ptr(), EARLY_IDTS_LEN as i32, true);
        load_idt(descr);
    }
}

/// Body of `idt_setup_early_pf()` (x86-64): install the early #PF gate.
///
/// # Safety
/// `idt` = `idt_table`; boot CPU, early.
pub unsafe fn early_pf(idt: *mut u8) {
    // SAFETY: caller contract.
    unsafe { setup_from_table(idt, EARLY_PF_IDTS.as_ptr(), 1, true) };
}

/// The early-handler gate for exception `i`: what `set_intr_gate(i, early_idt_handler_array[i])`
/// builds (`init_idt_data()`: `__KERNEL_CS`, `GATE_INTERRUPT`, present, `ist = dpl = 0`).
pub fn early_handler_gate(i: usize, base: usize) -> (u64, u64) {
    let d = IdtData {
        vector: i as u32,
        segment: KERNEL_CS,
        bits: idt_bits(0, GATE_INTERRUPT, DPL0),
        addr: base.wrapping_add(i.wrapping_mul(EARLY_IDT_HANDLER_SIZE)) as *const c_void,
    };
    gate_words(&d)
}

/// Body of `idt_setup_early_handler()` (x86-64): point vectors 0..31 at the early handlers, then
/// `load_idt(&idt_descr)`. (Not `system_vectors`: `set_intr_gate()` passes `sys = false`.)
///
/// # Safety
/// `idt` = `idt_table`, `descr` = `&idt_descr`; boot CPU, early.
pub unsafe fn early_handler(idt: *mut u8, descr: *const DescPtr) {
    let base = (&raw const early_idt_handler_array) as usize;
    let mut i = 0usize;
    while i < NUM_EXCEPTION_VECTORS {
        let (lo, hi) = early_handler_gate(i, base);
        // SAFETY: i < 32 < IDT_ENTRIES; the table is IDT_ENTRIES gates.
        unsafe {
            let slot = idt.add(i.wrapping_mul(GATE_SIZE)).cast::<u64>();
            slot.write_unaligned(lo);
            slot.add(1).write_unaligned(hi);
        }
        i = i.wrapping_add(1);
    }
    // SAFETY: caller contract.
    unsafe { load_idt(descr) };
}

/// `idt_setup_from_table(idt, t, size, sys)` (was `static __init`; called by `set_intr_gate()`,
/// `idt_setup_traps()` and `idt_setup_apic_and_irq_gates()` in `idt_glue.c`).
///
/// # Safety
/// As [`from_table`].
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn idt_setup_from_table(idt: *mut u8, t: *const IdtData, size: i32, sys: bool) {
    // SAFETY: caller contract.
    unsafe { setup_from_table(idt, t, size, sys) };
}

/// Entry for `idt_setup_early_traps()`.
///
/// # Safety
/// As [`early_traps`].
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn idt_setup_early_traps_rs(idt: *mut u8, descr: *const DescPtr) {
    // SAFETY: caller contract.
    unsafe { early_traps(idt, descr) };
}

/// Entry for `idt_setup_early_pf()`.
///
/// # Safety
/// As [`early_pf`].
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn idt_setup_early_pf_rs(idt: *mut u8) {
    // SAFETY: caller contract.
    unsafe { early_pf(idt) };
}

/// Entry for `idt_setup_early_handler()`.
///
/// # Safety
/// As [`early_handler`].
#[cfg(not(userspace_test))]
#[no_mangle]
#[link_section = ".init.text"]
pub unsafe extern "C" fn idt_setup_early_handler_rs(idt: *mut u8, descr: *const DescPtr) {
    // SAFETY: caller contract.
    unsafe { early_handler(idt, descr) };
}

/// Userspace test only: the two early tables, to compare with the C's.
#[cfg(userspace_test)]
pub fn early_tables() -> (&'static [IdtData], &'static [IdtData]) {
    (&EARLY_IDTS, &EARLY_PF_IDTS)
}
