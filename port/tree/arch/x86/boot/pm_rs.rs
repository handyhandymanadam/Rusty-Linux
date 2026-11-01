// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/pm.c in the 16-bit real-mode setup (code16, -Zregparm=3): the
//! preparation for the switch to protected mode. Exports exactly the one global of the C object (nm of
//! build-fast pm.o): `go_to_protected_mode()`; everything else (realmode_switch_hook, mask_all_interrupts,
//! reset_coprocessor, setup_gdt, setup_idt, the tables) is private (`t`/`r`/`b` locals), as the C's statics.
//!
//! Sequence (the same as the C, one call each, same order):
//!  1. realmode_switch_hook(): if boot_params.hdr.realmode_swtch (u32 at boot_params+0x208, a far pointer
//!     seg:off) != 0, `lcallw *boot_params+0x208` with eax/ebx/ecx/edx declared clobbered; else `cli`,
//!     outb(0x80, 0x70) (disable NMI) and io_delay() (outb(0, 0x80)).
//!  2. enable_a20() (a20_rs.rs); nonzero -> puts("A20 gate not responding, unable to boot...\n"); die().
//!  3. reset_coprocessor(): outb(0, 0xf0), delay, outb(0, 0xf1), delay.   4. mask_all_interrupts(): outb(0xff, 0xa1),
//!     delay, outb(0xfb, 0x21), delay.   5. setup_idt(): `lidtl` of a static const null idt {0, 0}.
//!  6. setup_gdt(): static const boot_gdt (16-byte aligned, `.rodata`) with GDT_ENTRY(DESC_CODE32, 0, 0xfffff) at
//!     GDT_ENTRY_BOOT_CS (2), GDT_ENTRY(DESC_DATA32, 0, 0xfffff) at BOOT_DS (3), GDT_ENTRY(DESC_TSS32, 4096, 103) at
//!     BOOT_TSS (4); entries 0 and 1 are zero, so the table is 5 * 8 = 40 bytes and len = sizeof-1 = 39 (0x27). The
//!     descriptor values are NOT hand-copied: pm_gen.rs is made by the C preprocessor from the very macros pm.c uses
//!     (pm_gen.rs.in); the array length is BOOT_TSS + 1 (what the C's designated initialisers give). The static `gdt_ptr`
//!     {len: u16, ptr: u32} (packed, 6 bytes) stays a static in plain `.bss` (setup.ld collects `*(.bss)` only): Xen HVM
//!     keeps a pointer to it, so it must outlive the function. ptr = (u32)&boot_gdt + (ds() << 4) (u32 wrapping add), then
//!     `lgdtl`.
//!  7. protected_mode_jump(boot_params.hdr.code32_start (u32 at +0x214), (u32)&boot_params + (ds() << 4)) (pmjump.S,
//!     regparm 3: eax, edx; noreturn).
//! `puts`/`die`/`enable_a20`/`protected_mode_jump` are the ported/asm objects; port I/O is `pio_ops` (io.h, TDX).
//! The message bytes are the C's (".rodata.str1.1", 43 characters + NUL).
//!
//! Deliberate divergences from the C: none in behaviour. Differences of form only: boot_gdt's `.rodata` object is 48 bytes (the 40-byte table
//! is byte-identical; the 16-byte-aligned wrapper adds 8 zero bytes after it, outside the gdt limit), the tables are separate sections (the C
//! shares one `.rodata`; the lea offset 0x10 into it is a plain symbol here), the functions are `.text.<name>` sections; ds() is `mov r16, ds` into a register
//! (C: a stack slot via the "rm" constraint); the asm blocks have the default (memory-clobbering) options, the C's have no
//! "memory" clobber (the Rust ones are stricter, never looser); the three asm operands use `sym` (absolute 16-bit address,
//! the C's R_386_16 relocations). Under `--cfg host_mock` (host tests only, rig/realmode/pm-diff.c) the asm blocks, the
//! 32-bit address of boot_gdt / boot_params, ds() and the callee symbols are extern hooks; never set for the target build.
//!
//! Evidence (logs/realmode-pm.md): object compare with the C, boot compare (cmp2), live-guest GDT bytes (rig/realmode/pm-gdtmem.sh), port
//! trace of 0x70/0x80/0xa1/0x21/0xf0/0xf1 (pm-trace.sh), patched-header hook boot (pm-hook.sh), host lockstep with mocks (run-pm-diff.sh),
//! Kani over all inputs (run-pm-kani.sh: `mod kmodel`/`proofs` at the end of this file, cfg(kani) only), Z3 (logs/proofs/pm-gdt.py).
//!
//! TEST-GAP: (a) the realmode_swtch hook is a real far call into the loader's code: QEMU/SeaBIOS never sets it, so the boots
//! run it only through a patched header (a stub that does `out 0xe9`), not a real loader's hook (what a real hook does with the machine state is untested);
//! (b) enable_a20() failure (message + die) cannot happen under QEMU (A20 is on): host lockstep with mocks, plus a boot
//! sabotage that forces the failure; (c) lgdt/lidt/the mode switch are architectural effects QEMU executes, not hardware;
//! (d) Xen HVM's retained pointer to `gdt_ptr` is not modelled; (e) the real (u32) value of &boot_gdt + (ds() << 4)
//! only sees the loader's ds (0x1000 in QEMU); other ds values are covered by the host differential only (logs/test-gaps.md).
#![allow(dead_code, unused_parens)] // unused_parens: pm_gen.rs holds the C preprocessor's macro expansions verbatim

#[cfg(not(kani))]
#[path = "rm_common.rs"]
mod rm;

use core::ffi::c_char;
#[cfg(not(kani))]
use rm::*;
#[cfg(kani)]
use kmodel::*;

include!(concat!(env!("RM_GEN_DIR"), "/pm_gen.rs"));

/// `struct gdt_ptr`: {u16 len; u32 ptr} __attribute__((packed)), also the descriptor-table pointer `lgdtl`/`lidtl` read.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtPtr {
    pub len: u16,
    pub ptr: u32,
}

const BOOT_GDT_N: usize = RM_GDT_ENTRY_BOOT_TSS + 1;

#[repr(C, align(16))]
struct Gdt16([u64; BOOT_GDT_N]);

const fn boot_gdt_init() -> Gdt16 {
    let mut a = [0u64; BOOT_GDT_N];
    a[RM_GDT_ENTRY_BOOT_CS] = RM_GDT_CS; // CS: code, read/execute, 4 GB, base 0
    a[RM_GDT_ENTRY_BOOT_DS] = RM_GDT_DS; // DS: data, read/write, 4 GB, base 0
    a[RM_GDT_ENTRY_BOOT_TSS] = RM_GDT_TSS; // TSS: 32-bit tss, 104 bytes, base 4096 (only to keep Intel VT happy)
    Gdt16(a)
}

/// There are machines which are known to not boot with the GDT being 8-byte unaligned; Intel recommends 16.
static BOOT_GDT: Gdt16 = boot_gdt_init();

/// Xen HVM incorrectly stores a pointer to the gdt_ptr, instead of its contents: static, so it stays in memory.
#[link_section = ".bss"]
static mut GDT: GdtPtr = GdtPtr { len: 0, ptr: 0 };

static NULL_IDT: GdtPtr = GdtPtr { len: 0, ptr: 0 };

/// pm.c's message, byte for byte.
static A20_MSG: &[u8; 44] = b"A20 gate not responding, unable to boot...\n\0";

/// `sizeof(boot_gdt) - 1` as the gdt_ptr limit (the array's size: 40, the aligned(16) attribute does not pad a C array); stored into a u16.
const GDT_LEN: u16 = (core::mem::size_of::<[u64; BOOT_GDT_N]>() - 1) as u16;
const _: () = assert!(core::mem::size_of::<[u64; BOOT_GDT_N]>() == 8 * BOOT_GDT_N && core::mem::align_of::<Gdt16>() == 16);
const _: () = assert!(RM_GDT_ENTRY_BOOT_CS < BOOT_GDT_N && RM_GDT_ENTRY_BOOT_DS < BOOT_GDT_N);

/// boot_params.hdr.realmode_swtch / code32_start (offsetof(struct boot_params, ...) = 0x208 / 0x214, setup header layout).
const OFF_REALMODE_SWTCH: usize = 0x208;
const OFF_CODE32_START: usize = 0x214;

#[cfg(not(any(host_mock, kani)))]
extern "C" {
    static boot_params: [u8; 4096];
    fn enable_a20() -> i32;
    fn puts(s: *const c_char);
    fn die() -> !;
    fn protected_mode_jump(entrypoint: u32, bootparams: u32) -> !;
}
#[cfg(all(host_mock, not(kani)))]
extern "C" {
    static boot_params: [u8; 4096];
    #[link_name = "mock_enable_a20"]
    fn enable_a20() -> i32;
    #[link_name = "mock_puts"]
    fn puts(s: *const c_char);
    #[link_name = "mock_die"]
    fn die() -> !;
    #[link_name = "mock_protected_mode_jump"]
    fn protected_mode_jump(entrypoint: u32, bootparams: u32) -> !;
    fn mock_cli();
    fn mock_lcallw(far: u32);
    fn mock_lgdt(p: *const GdtPtr);
    fn mock_lidt(p: *const GdtPtr);
    fn mock_ds() -> u16;
    fn mock_addr_boot_gdt(p: *const u8) -> u32;
    fn mock_addr_boot_params(p: *const u8) -> u32;
}

#[inline(always)]
unsafe fn io_delay() {
    // SAFETY: port 0x80 is the conventional delay port; pio_ops set up in main().
    unsafe { outb(0, 0x80) }
}

#[inline(always)]
unsafe fn rd32(off: usize) -> u32 {
    // SAFETY: boot_params is the 4 KiB zero page; off + 4 <= 4096; x86 allows the unaligned read.
    unsafe { ((core::ptr::addr_of!(boot_params) as *const u8).add(off) as *const u32).read_volatile() }
}

/// boot.h `ds()`.
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn ds() -> u16 {
    let s: u16;
    // SAFETY: reads a segment register.
    unsafe { core::arch::asm!("mov {0:x}, ds", out(reg_abcd) s, options(nomem, nostack, preserves_flags)) };
    s
}
#[cfg(any(host_mock, kani))]
fn ds() -> u16 {
    unsafe { mock_ds() }
}

#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn addr_boot_gdt() -> u32 {
    core::ptr::addr_of!(BOOT_GDT) as u32
}
#[cfg(any(host_mock, kani))]
fn addr_boot_gdt() -> u32 {
    unsafe { mock_addr_boot_gdt(core::ptr::addr_of!(BOOT_GDT) as *const u8) }
}
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn addr_boot_params() -> u32 {
    unsafe { core::ptr::addr_of!(boot_params) as u32 }
}
#[cfg(any(host_mock, kani))]
fn addr_boot_params() -> u32 {
    unsafe { mock_addr_boot_params(core::ptr::addr_of!(boot_params) as *const u8) }
}

/// `(u32)&x + (ds() << 4)`: ds() is promoted to int (<= 0xffff0), the sum wraps in u32.
#[inline(always)]
fn linear(addr: u32, ds: u16) -> u32 {
    addr.wrapping_add((ds as u32) << 4)
}

/// Invoke the realmode switch hook if present; otherwise disable all interrupts.
#[inline(always)]
unsafe fn realmode_switch_hook() {
    unsafe {
        if rd32(OFF_REALMODE_SWTCH) != 0 {
            #[cfg(not(any(host_mock, kani)))]
            core::arch::asm!(
                "lcallw *{bp}+{off}",
                bp = sym boot_params, off = const OFF_REALMODE_SWTCH,
                out("eax") _, out("ebx") _, out("ecx") _, out("edx") _,
                options(att_syntax)
            );
            #[cfg(any(host_mock, kani))]
            mock_lcallw(rd32(OFF_REALMODE_SWTCH));
        } else {
            #[cfg(not(any(host_mock, kani)))]
            core::arch::asm!("cli", options(nomem, nostack));
            #[cfg(any(host_mock, kani))]
            mock_cli();
            outb(0x80, 0x70); // Disable NMI
            io_delay();
        }
    }
}

/// Disable all interrupts at the legacy PIC.
#[inline(never)]
unsafe fn mask_all_interrupts() {
    unsafe {
        outb(0xff, 0xa1); // Mask all interrupts on the secondary PIC
        io_delay();
        outb(0xfb, 0x21); // Mask all but cascade on the primary PIC
        io_delay();
    }
}

/// Reset IGNNE# if asserted in the FPU.
#[inline(never)]
unsafe fn reset_coprocessor() {
    unsafe {
        outb(0, 0xf0);
        io_delay();
        outb(0, 0xf1);
        io_delay();
    }
}

#[inline(never)]
unsafe fn setup_gdt() {
    unsafe {
        let g = core::ptr::addr_of_mut!(GDT);
        (*g).len = GDT_LEN;
        (*g).ptr = linear(addr_boot_gdt(), ds());
        #[cfg(not(any(host_mock, kani)))]
        core::arch::asm!("lgdtl {g}", g = sym GDT, options(att_syntax));
        #[cfg(any(host_mock, kani))]
        mock_lgdt(g);
    }
}

#[inline(always)]
unsafe fn setup_idt() {
    unsafe {
        #[cfg(not(any(host_mock, kani)))]
        core::arch::asm!("lidtl {i}", i = sym NULL_IDT, options(att_syntax));
        #[cfg(any(host_mock, kani))]
        mock_lidt(core::ptr::addr_of!(NULL_IDT));
    }
}

/// Actual invocation sequence.
#[no_mangle]
pub unsafe extern "C" fn go_to_protected_mode() -> ! {
    unsafe {
        // Hook before leaving real mode, also disables interrupts
        realmode_switch_hook();

        // Enable the A20 gate
        if enable_a20() != 0 {
            puts(A20_MSG.as_ptr() as *const c_char);
            die();
        }

        // Reset coprocessor (IGNNE#)
        reset_coprocessor();

        // Mask all interrupts in the PIC
        mask_all_interrupts();

        // Actual transition to protected mode...
        setup_idt();
        setup_gdt();
        protected_mode_jump(rd32(OFF_CODE32_START), linear(addr_boot_params(), ds()));
    }
}

// ---- Kani (rig/realmode/run-pm-kani.sh): the SAME go_to_protected_mode() against symbolic inputs ----------------------------------------
// Every outside effect is a model that appends to an event log; die()/protected_mode_jump() (the only ways out) compare the whole log with
// an independent model of pm.c written from the C text and then cut the path (assume(false)). So each harness proves, for ALL values of
// ds, the two 32-bit addresses, realmode_swtch, code32_start and enable_a20()'s result: the exact sequence of effects and their values.
// Not modelled: the effects themselves (what lgdt/lcallw do), pio_ops (an outb log), the real addresses of the statics (u32 hooks).
#[cfg(kani)]
mod kmodel {
    use super::*;
    pub static mut boot_params: [u8; 4096] = [0; 4096];
    pub const MAXEV: usize = 24;
    pub static mut LOG: [(u8, u64, u64); MAXEV] = [(0, 0, 0); MAXEV];
    pub static mut N: usize = 0;
    pub static mut S_DS: u16 = 0;
    pub static mut S_AGDT: u32 = 0;
    pub static mut S_ABP: u32 = 0;
    pub static mut S_A20: i32 = 0;
    fn ev(k: u8, a: u64, b: u64) {
        unsafe {
            if N < MAXEV {
                LOG[N] = (k, a, b);
            }
            N += 1;
        }
    }
    pub unsafe fn outb(v: u8, port: u16) { ev(1, v as u64, port as u64) }
    pub unsafe fn mock_cli() { ev(2, 0, 0) }
    pub unsafe fn mock_lcallw(far: u32) { ev(3, far as u64, 0) }
    pub unsafe fn mock_lgdt(p: *const GdtPtr) { let (l, q) = unsafe { ((*p).len, (*p).ptr) }; ev(4, l as u64, q as u64) }
    pub unsafe fn mock_lidt(p: *const GdtPtr) { let (l, q) = unsafe { ((*p).len, (*p).ptr) }; ev(5, l as u64, q as u64) }
    pub unsafe fn mock_ds() -> u16 { unsafe { S_DS } }
    pub unsafe fn mock_addr_boot_gdt(p: *const u8) -> u32 {
        // the table as the CPU will read it: 5 little-endian u64, architectural values written out independently of pm_gen.rs
        let t = unsafe { core::slice::from_raw_parts(p as *const u64, 5) };
        assert!(t[0] == 0 && t[1] == 0);
        assert!(t[2] == 0x00cf_9b00_0000_ffff); // CS: P DPL0 S, type 0xb (exec/read/accessed), G=1 D=1, limit 0xfffff, base 0
        assert!(t[3] == 0x00cf_9300_0000_ffff); // DS: type 0x3 (read/write/accessed), same flags/limit/base
        assert!(t[4] == 0x0000_8900_1000_0067); // TSS: P, type 9 (32-bit TSS available), byte granularity, limit 103, base 0x1000
        assert!((p as usize) % 16 == 0);
        ev(6, 0, 0);
        unsafe { S_AGDT }
    }
    pub unsafe fn mock_addr_boot_params(_p: *const u8) -> u32 { ev(7, 0, 0); unsafe { S_ABP } }
    pub unsafe fn enable_a20() -> i32 { ev(8, unsafe { S_A20 } as u32 as u64, 0); unsafe { S_A20 } }
    pub unsafe fn puts(s: *const c_char) {
        let m = b"A20 gate not responding, unable to boot...\n\0";
        let mut i = 0;
        while i < 44 { assert!(unsafe { *(s as *const u8).add(i) } == m[i]); i += 1; }
        ev(9, 0, 0);
    }
    fn check_log() {
        unsafe {
            let sw = u32::from_le_bytes([boot_params[0x208], boot_params[0x209], boot_params[0x20a], boot_params[0x20b]]);
            let c32 = u32::from_le_bytes([boot_params[0x214], boot_params[0x215], boot_params[0x216], boot_params[0x217]]);
            let mut e = [(0u8, 0u64, 0u64); MAXEV]; let mut n = 0;
            macro_rules! push { ($k:expr, $a:expr, $b:expr) => {{ e[n] = ($k, $a as u64, $b as u64); n += 1; }}; }
            if sw != 0 { push!(3, sw, 0); } else { push!(2, 0, 0); push!(1, 0x80, 0x70); push!(1, 0, 0x80); }
            push!(8, S_A20 as u32, 0);
            if S_A20 != 0 { push!(9, 0, 0); push!(10, 0, 0); }
            else {
                push!(1, 0, 0xf0); push!(1, 0, 0x80); push!(1, 0, 0xf1); push!(1, 0, 0x80);
                push!(1, 0xff, 0xa1); push!(1, 0, 0x80); push!(1, 0xfb, 0x21); push!(1, 0, 0x80);
                push!(5, 0, 0); push!(6, 0, 0);
                push!(4, 0x27, S_AGDT.wrapping_add((S_DS as u32) << 4));
                push!(7, 0, 0);
                push!(11, c32, S_ABP.wrapping_add((S_DS as u32) << 4));
            }
            assert!(N == n);
            let mut i = 0;
            while i < n { assert!(LOG[i] == e[i]); i += 1; }
        }
    }
    pub unsafe fn die() -> ! { ev(10, 0, 0); check_log(); kani::cover!(true, "die path"); kani::assume(false); loop {} }
    pub unsafe fn protected_mode_jump(e: u32, b: u32) -> ! { ev(11, e as u64, b as u64); check_log(); kani::cover!(true, "jump path"); kani::assume(false); loop {} }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use super::kmodel as k;
    fn setup(a20_zero: Option<bool>, swtch_zero: Option<bool>) {
        unsafe {
            k::N = 0;
            k::S_DS = kani::any(); k::S_AGDT = kani::any(); k::S_ABP = kani::any();
            k::S_A20 = kani::any();
            if let Some(z) = a20_zero { if z { k::S_A20 = 0 } else { kani::assume(k::S_A20 != 0) } }
            let sw: u32 = kani::any(); let c32: u32 = kani::any();
            if let Some(z) = swtch_zero { if z { kani::assume(sw == 0) } else { kani::assume(sw != 0) } }
            k::boot_params[0x208..0x20c].copy_from_slice(&sw.to_le_bytes());
            k::boot_params[0x214..0x218].copy_from_slice(&c32.to_le_bytes());
        }
    }
    /// All inputs, both hook branches, both enable_a20() outcomes: the exact effect sequence (and the table bytes, gdt_ptr, jump arguments).
    #[kani::proof]
    #[kani::unwind(50)]
    fn go_to_protected_mode_all() { setup(None, None); unsafe { go_to_protected_mode() } }
    #[kani::proof]
    #[kani::unwind(50)]
    fn go_to_protected_mode_a20_ok_nohook() { setup(Some(true), Some(true)); unsafe { go_to_protected_mode() } }
    #[kani::proof]
    #[kani::unwind(50)]
    fn go_to_protected_mode_a20_fail_hook() { setup(Some(false), Some(false)); unsafe { go_to_protected_mode() } }
    /// linear(): the u32 wrapping value equals the true sum mod 2^32, and for a 16-bit offset (< 64 KiB) never wraps.
    #[kani::proof]
    fn linear_arith() {
        let a: u32 = kani::any(); let d: u16 = kani::any();
        assert!(linear(a, d) as u64 == (a as u64 + ((d as u64) << 4)) & 0xffff_ffff);
        if a < 0x10000 { assert!(linear(a, d) as u64 == a as u64 + (d as u64) * 16 && linear(a, d) <= 0x10ffef); }
        assert!(((d as i32) << 4) >= 0); // the C's `ds() << 4` is a positive int: no signed overflow
    }
}
