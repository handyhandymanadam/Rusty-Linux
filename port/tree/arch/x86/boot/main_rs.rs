// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/main.c in the 16-bit real-mode setup (code16, -Zregparm=3): the setup entry `main()` that
//! header.S calls. Exports exactly the globals of the C object (nm of build-fast main.o): `main` (T), `boot_params` (B, 4096 bytes,
//! 16-byte aligned, plain `.bss`), `pio_ops` (B, 12 bytes, `.bss`), `HEAP` and `heap_end` (D, 4 bytes each, `.data`, initialised to
//! `_end`: R_386_32 relocations as in the C). copy_boot_params / init_heap are inlined into main (as the C compiler did);
//! keyboard_init, query_ist, set_bios_mode stay out of line (as in the C); the three port functions `__inb/__outb/__outw` of
//! asm/shared/io.h are local `in`/`out` functions (`x86_inb/x86_outb/x86_outw` here) whose addresses go into `pio_ops` by
//! `init_default_io_ops()` (io.h) exactly as in the C; rm_common.rs's inb()/outb() call them through the pointers (regparm 3: al/ax =
//! first argument, dx = port).
//!
//! Sequence (same order as the C): init_default_io_ops; copy_boot_params (memcpy of `hdr` (header.S, 0x7b bytes) to boot_params+0x1f1;
//! if the new cmd_line_ptr (0x228) is 0 and the u16 at ds:0x20 is OLD_CL_MAGIC 0xA33F, the old-style command line protocol: u16 offset at ds:0x22;
//! cmdline_seg = ds() if offset < hdr.setup_move_size (0x212) else 0x9000; cmd_line_ptr = (cmdline_seg << 4) + offset, the u16 promoted to int);
//! console_init(); cmdline_find_option_bool("debug") (inline of boot.h: cmd_line_ptr >= 0x100000 -> -1, which is TRUE: the C then prints the
//! message too) -> puts("early console in setup code\n"); init_heap (loadflags (0x211) & CAN_USE_HEAP: heap_end = u16 heap_end_ptr (0x224) + 0x200,
//! clamped to `esp - STACK_SIZE` (1024) as unsigned 32-bit, esp live at that point; else puts("WARNING: Ancient bootloader, some functionality may
//! be limited!\n")); validate_cpu() != 0 -> puts("Unable to boot - please use a kernel appropriate for your CPU.\n"); die(); set_bios_mode() (only with
//! CONFIG_X86_64: INT 15h AX=EC00 BX=2); detect_memory(); keyboard_init() (INT 16h AH=02 -> boot_params.kbd_status (0x1eb) = al; INT 16h AX=0305);
//! query_ist() (cpu.level < 6: return; INT 15h AX=E980 EDX='GSIC' -> boot_params.ist_info (0x60) = eax ebx ecx edx); query_apm_bios() only with
//! CONFIG_APM[_MODULE], query_edd() only with CONFIG_EDD[_MODULE] (both C, video-less files, called via extern "C" when the build configuration
//! says so); set_video() (C); go_to_protected_mode() (pm_rs.rs).
//! Strings are the C's, byte for byte (".rodata.str1.1" there). The configuration switches and CAN_USE_HEAP / OLD_CL_* come from the real kernel headers through
//! main_gen.rs (main_gen.rs.in, same C-preprocessor rule as cpucheck_gen/pm_gen); the struct offsets (setup header at 0x1f1, size 0x7b, kbd_status,
//! ist_info, hdr fields) and STACK_SIZE are written out here and checked against the real headers by the host rig (rig/realmode/run-main-diff.sh) and by the object compare.
//!
//! Deliberate divergences (form only; behaviour identical, logs/realmode-main.md): (1) `main`'s frame: the C pushes one register to hold the `ds()` temporary
//! (esp - 4 at the point where init_heap reads esp), the Rust frame differs, so with the heap clamp active `heap_end` can differ by that frame difference
//! (the C is not the specification of a compiler's stack layout; the clamp keeps >= STACK_SIZE bytes of stack either way); (2) HEAP/heap_end/boot_params/pio_ops are Rust statics
//! with `#[link_section]` names; (3) the two stores of heap_end in the C (assign, then clamp) are one store of the final value; (4) oreg/ireg are `MaybeUninit`/BiosRegs
//! locals filled by initregs()/intcall() as in the C. Under `--cfg host_mock` / `--cfg kani` (host tests only) the asm blocks, ds(), esp, the old-cmdline pointer and every callee are
//! extern hooks / models; never set for the target build.
//!
//! TEST-GAP: (a) the old-style command line protocol with cmdline_seg == ds() (offset < setup_move_size) cannot be told from the 0x9000 branch at boot (QEMU loads
//! the protocol-2.00 setup at 0x9000 = ds): host differential/Kani only; (b) `cpu.level < 6` in query_ist is dead for this X86_64 config at boot (validate_cpu
//! fails any CPU below level 64 first): host differential/Kani only; (c) CONFIG_APM / CONFIG_EDD / !X86_64 variants are not built (this config has neither APM nor EDD
//! and is X86_64): host differential builds all 8 combinations; (d) the heap clamp: QEMU's loader sets heap_end_ptr far above the stack so the clamp's esp
//! side is exercised only by the host differential/Kani/Z3 (and by the 2.01 boot where heap_end_ptr is lower); (e) real BIOS INT 15h E980 / EC00 / INT 16h behaviour (SeaBIOS only);
//! (f) a TDX guest swapping pio_ops is not modelled (compressed/tdx.c, not real mode).
#![allow(dead_code, unused_parens, static_mut_refs)]

use core::ffi::{c_char, c_int};
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut};

include!(concat!(env!("RM_GEN_DIR"), "/main_gen.rs"));

/// `struct biosregs` (boot.h): eleven u32 words, segment halves split out; 44 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BiosRegs {
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub _esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub gs: u16,
    pub fs: u16,
    pub es: u16,
    pub ds: u16,
    pub eflags: u32,
}

/// `struct port_io_ops` (io.h).
#[repr(C)]
pub struct PortIoOps {
    pub f_inb: Option<unsafe extern "C" fn(u16) -> u8>,
    pub f_outb: Option<unsafe extern "C" fn(u8, u16)>,
    pub f_outw: Option<unsafe extern "C" fn(u16, u16)>,
}

/// Only the first member of `struct cpu_features` (cpuflags.h) is read here.
#[repr(C)]
pub struct CpuLevel {
    pub level: c_int,
}

/// `struct boot_params boot_params __attribute__((aligned(16)));` 4096 bytes, `.bss`.
#[repr(C, align(16))]
pub struct BootParams(pub [u8; 4096]);

const _: () = assert!(core::mem::size_of::<BootParams>() == 4096 && core::mem::align_of::<BootParams>() == 16); // BUILD_BUG_ON(sizeof(boot_params) != 4096)
const _: () = assert!(core::mem::size_of::<PortIoOps>() == if cfg!(any(host_mock, kani)) { 24 } else { 12 });
const _: () = assert!(core::mem::size_of::<BiosRegs>() == 44);
const _: () = assert!(MSG_DEBUG_OPT.len() == 6 && MSG_EARLY.len() == 29 && MSG_CPU.len() == 64 && MSG_ANCIENT.len() == 65); // the C's .rodata.str1.1 sizes (incl. NUL)

// Offsets into boot_params (struct boot_params / struct setup_header of uapi/asm/bootparam.h; verified by rig/realmode/run-main-diff.sh against the real header).
const OFF_IST_INFO: usize = 0x60;
const OFF_KBD_STATUS: usize = 0x1eb;
const OFF_HDR: usize = 0x1f1;
const SIZEOF_HDR: usize = 0x7b;
const OFF_LOADFLAGS: usize = 0x211;
const OFF_SETUP_MOVE_SIZE: usize = 0x212;
const OFF_HEAP_END_PTR: usize = 0x224;
const OFF_CMD_LINE_PTR: usize = 0x228;
/// boot.h: `#define STACK_SIZE 1024`.
const STACK_SIZE: u32 = 1024;

#[cfg_attr(not(any(host_mock, kani)), link_section = ".bss")]
#[no_mangle]
pub static mut boot_params: BootParams = BootParams([0; 4096]);

#[cfg_attr(not(any(host_mock, kani)), link_section = ".bss")]
#[no_mangle]
pub static mut pio_ops: PortIoOps = PortIoOps { f_inb: None, f_outb: None, f_outw: None };

/// `char *HEAP = _end;` / `char *heap_end = _end; /* Default end of heap = no heap */`
#[cfg_attr(not(any(host_mock, kani)), link_section = ".data")]
#[no_mangle]
pub static mut HEAP: *mut u8 = unsafe { addr_of_mut!(_end) };
#[cfg_attr(not(any(host_mock, kani)), link_section = ".data")]
#[no_mangle]
pub static mut heap_end: *mut u8 = unsafe { addr_of_mut!(_end) };

static MSG_DEBUG_OPT: &[u8] = b"debug\0";
static MSG_EARLY: &[u8] = b"early console in setup code\n\0";
static MSG_ANCIENT: &[u8] = b"WARNING: Ancient bootloader, some functionality may be limited!\n\0";
static MSG_CPU: &[u8] = b"Unable to boot - please use a kernel appropriate for your CPU.\n\0";

// ---- callees: the C/asm objects (target), mock hooks (host_mock), a model (kani) -------------------------------------------------------------
#[cfg(not(any(host_mock, kani)))]
extern "C" {
    fn intcall(int_no: u8, ireg: *const BiosRegs, oreg: *mut BiosRegs);
    fn initregs(reg: *mut BiosRegs);
    fn puts(s: *const c_char);
    fn console_init();
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    fn validate_cpu() -> c_int;
    fn detect_memory();
    fn set_video();
    fn go_to_protected_mode() -> !;
    fn die() -> !;
    fn query_apm_bios();
    fn query_edd();
    fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
}
#[cfg(all(host_mock, not(kani)))]
extern "C" {
    #[link_name = "mock_intcall"]
    fn intcall(int_no: u8, ireg: *const BiosRegs, oreg: *mut BiosRegs);
    #[link_name = "mock_initregs"]
    fn initregs(reg: *mut BiosRegs);
    #[link_name = "mock_puts"]
    fn puts(s: *const c_char);
    #[link_name = "mock_console_init"]
    fn console_init();
    #[link_name = "mock_cmdline_find_option_bool"]
    fn __cmdline_find_option_bool(cmdline_ptr: u32, option: *const c_char) -> c_int;
    #[link_name = "mock_validate_cpu"]
    fn validate_cpu() -> c_int;
    #[link_name = "mock_detect_memory"]
    fn detect_memory();
    #[link_name = "mock_set_video"]
    fn set_video();
    #[link_name = "mock_go_to_protected_mode"]
    fn go_to_protected_mode() -> !;
    #[link_name = "mock_die"]
    fn die() -> !;
    #[link_name = "mock_query_apm_bios"]
    fn query_apm_bios();
    #[link_name = "mock_query_edd"]
    fn query_edd();
    fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
    fn mock_inb(port: u16) -> u8;
    fn mock_outb(v: u8, port: u16);
    fn mock_outw(v: u16, port: u16);
    fn mock_ds() -> u16;
    fn mock_esp() -> u32;
    fn mock_oldcmd() -> *const u8;
}
#[cfg(not(kani))]
extern "C" {
    /// header.S: the setup header (at 0x1f1)
    static hdr: u8;
    /// cpuflags.c
    static mut cpu: CpuLevel;
    /// setup.ld: end of .bss
    static mut _end: u8;
}
#[cfg(kani)]
use kmodel::*;

// ---- port functions of asm/shared/io.h: BUILDIO(b, b, u8), BUILDIO(w, w, u16) -----------------------------------------------------------------
#[cfg(not(any(host_mock, kani)))]
unsafe extern "C" fn x86_inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: `inb %w1, %b0`; no memory, no stack.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}
#[cfg(not(any(host_mock, kani)))]
unsafe extern "C" fn x86_outb(v: u8, port: u16) {
    // SAFETY: `outb %b0, %w1`.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}
#[cfg(not(any(host_mock, kani)))]
unsafe extern "C" fn x86_outw(v: u16, port: u16) {
    // SAFETY: `outw %w0, %w1`.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) };
}
#[cfg(all(host_mock, not(kani)))]
unsafe extern "C" fn x86_inb(port: u16) -> u8 {
    unsafe { mock_inb(port) }
}
#[cfg(all(host_mock, not(kani)))]
unsafe extern "C" fn x86_outb(v: u8, port: u16) {
    unsafe { mock_outb(v, port) }
}
#[cfg(all(host_mock, not(kani)))]
unsafe extern "C" fn x86_outw(v: u16, port: u16) {
    unsafe { mock_outw(v, port) }
}
#[cfg(kani)]
unsafe extern "C" fn x86_inb(_port: u16) -> u8 {
    0
}
#[cfg(kani)]
unsafe extern "C" fn x86_outb(_v: u8, _port: u16) {}
#[cfg(kani)]
unsafe extern "C" fn x86_outw(_v: u16, _port: u16) {}

/// io.h `init_default_io_ops()`: use the normal I/O instructions by default. TEST-GAP (f): a TDX guest swaps these pointers (compressed/tdx.c); not real-mode, not modelled.
#[inline(always)]
unsafe fn init_default_io_ops() {
    unsafe {
        let p = addr_of_mut!(pio_ops);
        (*p).f_inb = Some(x86_inb);
        (*p).f_outb = Some(x86_outb);
        (*p).f_outw = Some(x86_outw);
    }
}

// ---- machine state readers --------------------------------------------------------------------------------------------------------------------
/// boot.h `ds()`.
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn ds() -> u16 {
    let s: u16;
    // SAFETY: reads a segment register.
    unsafe { core::arch::asm!("mov {0:x}, ds", out(reg_abcd) s, options(nomem, nostack, preserves_flags)) };
    s
}
#[cfg(all(host_mock, not(kani)))]
fn ds() -> u16 {
    unsafe { mock_ds() }
}
#[cfg(kani)]
fn ds() -> u16 {
    unsafe { kmodel::S_DS }
}

/// asm/asm.h `current_stack_pointer` (the esp register, 32 bits).
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn current_stack_pointer() -> u32 {
    let sp: u32;
    // SAFETY: reads esp.
    unsafe { core::arch::asm!("mov {0:e}, esp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
    sp
}
#[cfg(all(host_mock, not(kani)))]
fn current_stack_pointer() -> u32 {
    unsafe { mock_esp() }
}
#[cfg(kani)]
fn current_stack_pointer() -> u32 {
    unsafe { kmodel::S_ESP }
}

/// `absolute_pointer(OLD_CL_ADDRESS)`: ds-relative offset 0x20 (`struct old_cmdline { u16 cl_magic; u16 cl_offset; }`).
#[cfg(not(any(host_mock, kani)))]
#[inline(always)]
fn oldcmd() -> *const u8 {
    RM_OLD_CL_ADDRESS as *const u8
}
#[cfg(all(host_mock, not(kani)))]
fn oldcmd() -> *const u8 {
    unsafe { mock_oldcmd() }
}
#[cfg(kani)]
fn oldcmd() -> *const u8 {
    unsafe { addr_of!(kmodel::OLDCMD) as *const u8 }
}

// ---- boot_params accessors ----------------------------------------------------------------------------------------------------------------------
#[inline(always)]
fn bp() -> *mut u8 {
    addr_of_mut!(boot_params) as *mut u8
}
#[inline(always)]
unsafe fn rd8(off: usize) -> u8 {
    unsafe { bp().add(off).read() }
}
#[inline(always)]
unsafe fn rd16(off: usize) -> u16 {
    unsafe { (bp().add(off) as *const u16).read_unaligned() }
}
#[inline(always)]
unsafe fn rd32(off: usize) -> u32 {
    unsafe { (bp().add(off) as *const u32).read_unaligned() }
}
#[inline(always)]
unsafe fn wr8(off: usize, v: u8) {
    unsafe { bp().add(off).write(v) }
}
#[inline(always)]
unsafe fn wr32(off: usize, v: u32) {
    unsafe { (bp().add(off) as *mut u32).write_unaligned(v) }
}

/// boot.h `cmdline_find_option_bool()`: `cmd_line_ptr >= 0x100000` is "inaccessible" = -1 (non-zero, so the caller's `if` is TRUE).
#[inline(always)]
unsafe fn cmdline_find_option_bool(option: *const c_char) -> c_int {
    unsafe {
        let cmd_line_ptr = rd32(OFF_CMD_LINE_PTR);
        if cmd_line_ptr >= 0x100000 {
            return -1; // inaccessible
        }
        __cmdline_find_option_bool(cmd_line_ptr, option)
    }
}

/// Copy the header into the boot parameter block. Since this screws up the old-style command line protocol, adjust by filling in the new-style
/// command line pointer instead.
#[inline(always)]
unsafe fn copy_boot_params() {
    unsafe {
        memcpy(bp().add(OFF_HDR), addr_of!(hdr) as *const u8, SIZEOF_HDR);

        if rd32(OFF_CMD_LINE_PTR) == 0 && (oldcmd() as *const u16).read_volatile() == RM_OLD_CL_MAGIC {
            // Old-style command line protocol: figure out if the command line falls in the region of memory that an old kernel would have copied up to 0x90000...
            let cl_offset = (oldcmd().add(2) as *const u16).read_volatile();
            // TEST-GAP (a): the `ds()` arm cannot be told from the 0x9000 arm at boot (QEMU's protocol-2.00 setup runs at 0x9000 = ds); host differential/Kani only
            let cmdline_seg: u16 = if cl_offset < rd16(OFF_SETUP_MOVE_SIZE) { ds() } else { 0x9000 };
            // `(cmdline_seg << 4) + oldcmd->cl_offset`: both u16 are promoted to int (<= 0xffff0 + 0xffff, positive), stored into the u32.
            wr32(OFF_CMD_LINE_PTR, ((cmdline_seg as u32) << 4) + cl_offset as u32);
        }
    }
}

/// Query the keyboard lock status as given by the BIOS, and set the keyboard repeat rate to maximum.
#[inline(never)]
unsafe fn keyboard_init() {
    unsafe {
        let mut ireg = new_regs();
        let mut oreg = MaybeUninit::<BiosRegs>::uninit();

        ireg.eax = (ireg.eax & !0xff00) | (0x02 << 8); // ireg.ah = 0x02: Get keyboard status
        intcall(0x16, &ireg, oreg.as_mut_ptr());
        wr8(OFF_KBD_STATUS, oreg.assume_init_ref().eax as u8); // boot_params.kbd_status = oreg.al

        ireg.eax = (ireg.eax & 0xffff_0000) | 0x0305; // ireg.ax = 0x0305: Set keyboard repeat rate
        intcall(0x16, &ireg, core::ptr::null_mut());
    }
}

/// Get Intel SpeedStep (IST) information.
#[inline(never)]
unsafe fn query_ist() {
    unsafe {
        // TEST-GAP (b): dead for this X86_64 config at boot (validate_cpu() fails every CPU below level 64 first): host differential/Kani only
        // Some older BIOSes apparently crash on this call, so filter it from machines too old to have SpeedStep at all.
        if addr_of!(cpu.level).read_volatile() < 6 {
            return;
        }

        let mut ireg = new_regs();
        let mut oreg = MaybeUninit::<BiosRegs>::uninit();
        ireg.eax = (ireg.eax & 0xffff_0000) | 0xe980; // ireg.ax = 0xe980: IST Support
        ireg.edx = 0x47534943; // Request value
        intcall(0x15, &ireg, oreg.as_mut_ptr());

        let o = oreg.assume_init_ref();
        wr32(OFF_IST_INFO, o.eax); // ist_info.signature
        wr32(OFF_IST_INFO + 4, o.ebx); // .command
        wr32(OFF_IST_INFO + 8, o.ecx); // .event
        wr32(OFF_IST_INFO + 12, o.edx); // .perf_level
    }
}

/// Tell the BIOS what CPU mode we intend to run in.
#[inline(never)]
unsafe fn set_bios_mode() {
    if RM_MAIN_X86_64 {
        unsafe {
            let mut ireg = new_regs();
            ireg.eax = (ireg.eax & 0xffff_0000) | 0xec00;
            ireg.ebx = (ireg.ebx & 0xffff_0000) | 2;
            intcall(0x15, &ireg, core::ptr::null_mut());
        }
    }
}

/// `struct biosregs ireg; initregs(&ireg);`
#[inline(always)]
unsafe fn new_regs() -> BiosRegs {
    let mut r = MaybeUninit::<BiosRegs>::uninit();
    // SAFETY: initregs() writes every byte of the 44-byte struct.
    unsafe {
        initregs(r.as_mut_ptr());
        r.assume_init()
    }
}

#[inline(always)]
unsafe fn init_heap() {
    unsafe {
        if rd8(OFF_LOADFLAGS) & RM_CAN_USE_HEAP != 0 {
            // TEST-GAP (d): QEMU's heap_end_ptr (0xfe00) puts the clamp's esp side in play (observed live, heap_end = esp - 1024); the wrap below esp < 1024 and
            // other esp/heap_end_ptr pairs are host differential/Kani/Z3 only (logs/proofs/main-heap.py)
            // stack_end = (char *)(current_stack_pointer - STACK_SIZE): unsigned 32-bit, wraps below STACK_SIZE
            let stack_end: u32 = current_stack_pointer().wrapping_sub(STACK_SIZE);
            // heap_end = (char *)((size_t)boot_params.hdr.heap_end_ptr + 0x200), then `if (heap_end > stack_end) heap_end = stack_end` (pointer compare, unsigned)
            let mut he: u32 = rd16(OFF_HEAP_END_PTR) as u32 + 0x200;
            if he > stack_end {
                he = stack_end;
            }
            heap_end = he as usize as *mut u8;
        } else {
            // Boot protocol 2.00 only, no heap available
            puts(MSG_ANCIENT.as_ptr() as *const c_char);
        }
    }
}

#[cfg_attr(not(host_mock), no_mangle)]
#[cfg_attr(host_mock, export_name = "rs_main")] // the host harness has its own main()
pub unsafe extern "C" fn main() {
    unsafe {
        init_default_io_ops();

        // First, copy the boot header into the "zeropage"
        copy_boot_params();

        // Initialize the early-boot console
        console_init();
        if cmdline_find_option_bool(MSG_DEBUG_OPT.as_ptr() as *const c_char) != 0 {
            puts(MSG_EARLY.as_ptr() as *const c_char);
        }

        // End of heap check
        init_heap();

        // Make sure we have all the proper CPU support
        if validate_cpu() != 0 {
            puts(MSG_CPU.as_ptr() as *const c_char);
            die();
        }

        // Tell the BIOS what CPU mode we intend to run in
        set_bios_mode();

        // Detect memory layout
        detect_memory();

        // Set keyboard repeat rate (why?) and query the lock flags
        keyboard_init();

        // Query Intel SpeedStep (IST) information
        query_ist();

        // TEST-GAP (c): neither query_apm_bios() nor query_edd() is built in this config (CONFIG_APM/CONFIG_EDD off): all 8 CONFIG combinations are host differential/Kani only
        // Query APM information
        if RM_MAIN_APM {
            query_apm_bios();
        }

        // Query EDD information
        if RM_MAIN_EDD {
            query_edd();
        }

        // Set the video mode
        set_video();

        // Do the last things and invoke protected mode
        go_to_protected_mode();
    }
}

// ---- Kani (rig/realmode/run-main-kani.sh): the SAME main() against symbolic inputs ---------------------------------------------------------------
// Every outside effect is a model that appends to an event log; die()/go_to_protected_mode() (the only ways out) compare the whole log, boot_params and heap_end with an
// independent model of main.c written from the C text (u64 arithmetic, no shared helper), then cut the path. So each harness proves, for ALL values of the 123 header bytes,
// the old-style command line words, ds, esp (32 bits), cpu.level, find_option's and validate_cpu's results and every BIOS output register: the exact effect sequence and arguments
// (all ireg words), the final zero page byte by byte (header copy except cmd_line_ptr, cmd_line_ptr, kbd_status, ist_info, nothing else written) and heap_end.
// Not modelled: what the callees do, the real in/out instructions, a 32-bit pointer width (the host has 64-bit pointers: heap_end is compared as a u64 value that always fits u32).
#[cfg(kani)]
mod kmodel {
    use super::*;
    pub static mut hdr: [u8; 0x7b] = [0; 0x7b];
    pub static mut cpu: CpuLevel = CpuLevel { level: 0 };
    pub static mut _end: u8 = 0;
    pub static mut S_DS: u16 = 0;
    pub static mut S_ESP: u32 = 0;
    pub static mut OLDCMD: [u16; 2] = [0; 2];
    pub static mut S_FIND: i32 = 0;
    pub static mut S_VALID: i32 = 0;
    pub static mut S_FS: u16 = 0;
    pub static mut S_GS: u16 = 0;
    pub static mut ORET: [[u32; 11]; 3] = [[0; 11]; 3];
    pub static mut NOR: usize = 0;
    pub const MAXEV: usize = 24;
    pub static mut LOG: [(u8, u64, u64); MAXEV] = [(0, 0, 0); MAXEV];
    pub static mut N: usize = 0;
    fn ev(k: u8, a: u64, b: u64) {
        unsafe {
            if N < MAXEV {
                LOG[N] = (k, a, b);
            }
            N += 1;
        }
    }
    pub unsafe fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
        unsafe { core::ptr::copy_nonoverlapping(s, d, n) };
        d
    }
    pub unsafe fn initregs(r: *mut BiosRegs) {
        unsafe {
            *r = BiosRegs { edi: 0, esi: 0, ebp: 0, _esp: 0, ebx: 0, edx: 0, ecx: 0, eax: 0, gs: S_GS, fs: S_FS, es: S_DS, ds: S_DS, eflags: 1 };
        }
        ev(6, 0, 0);
    }
    pub unsafe fn intcall(n: u8, ireg: *const BiosRegs, oreg: *mut BiosRegs) {
        unsafe {
            let i = *ireg;
            // everything initregs() set and the call did not touch must still be there
            assert!(i.edi == 0 && i.esi == 0 && i.ebp == 0 && i._esp == 0 && i.ecx == 0 && i.eflags == 1 && i.gs == S_GS && i.fs == S_FS && i.es == S_DS && i.ds == S_DS);
            ev(7, n as u64 | ((i.eax as u64) << 8) | ((i.ebx as u64) << 40), i.edx as u64 | ((!oreg.is_null()) as u64) << 32);
            if !oreg.is_null() {
                let o = ORET[NOR];
                NOR += 1;
                *oreg = BiosRegs { edi: o[0], esi: o[1], ebp: o[2], _esp: o[3], ebx: o[4], edx: o[5], ecx: o[6], eax: o[7], gs: o[8] as u16, fs: (o[8] >> 16) as u16, es: o[9] as u16, ds: (o[9] >> 16) as u16, eflags: o[10] };
            }
        }
    }
    pub unsafe fn puts(s: *const c_char) {
        // identify the message by its bytes (compared in full), log which one
        let m: [&[u8]; 3] = [b"early console in setup code\n\0", b"WARNING: Ancient bootloader, some functionality may be limited!\n\0", b"Unable to boot - please use a kernel appropriate for your CPU.\n\0"];
        let mut id = 0u64;
        let mut k = 0;
        while k < 3 {
            let mut same = true;
            let mut i = 0;
            while i < m[k].len() {
                if unsafe { *(s as *const u8).add(i) } != m[k][i] {
                    same = false;
                    break; // never read past the NUL of a shorter message
                }
                i += 1;
            }
            if same {
                id = k as u64 + 1;
            }
            k += 1;
        }
        assert!(id != 0);
        ev(3, id, 0);
    }
    pub unsafe fn console_init() { ev(1, 0, 0) }
    pub unsafe fn __cmdline_find_option_bool(p: u32, o: *const c_char) -> c_int {
        let d = b"debug\0";
        let mut i = 0;
        while i < 6 { assert!(unsafe { *(o as *const u8).add(i) } == d[i]); i += 1; }
        ev(2, p as u64, 0);
        unsafe { S_FIND }
    }
    pub unsafe fn validate_cpu() -> c_int { ev(4, 0, 0); unsafe { S_VALID } }
    pub unsafe fn detect_memory() { ev(8, 0, 0) }
    pub unsafe fn set_video() { ev(9, 0, 0) }
    pub unsafe fn query_apm_bios() { ev(10, 0, 0) }
    pub unsafe fn query_edd() { ev(11, 0, 0) }
    fn rd16h(o: usize) -> u64 { unsafe { hdr[o] as u64 | (hdr[o + 1] as u64) << 8 } }
    fn check_log() {
        unsafe {
            let base = 0x1f1usize;
            let (lf, hp, smv) = (hdr[0x211 - base], rd16h(0x224 - base), rd16h(0x212 - base));
            let cl0 = rd16h(0x228 - base) | rd16h(0x228 - base + 2) << 16;
            let old = cl0 == 0 && OLDCMD[0] == 0xA33F;
            let cl = if old { let seg: u64 = if (OLDCMD[1] as u64) < smv { S_DS as u64 } else { 0x9000 }; seg * 16 + OLDCMD[1] as u64 } else { cl0 };
            assert!(cl < (1 << 32));
            let mut e = [(0u8, 0u64, 0u64); MAXEV];
            let mut n = 0;
            macro_rules! push { ($k:expr, $a:expr, $b:expr) => {{ e[n] = ($k, $a as u64, $b as u64); n += 1; }}; }
            push!(1, 0, 0);
            if cl < 0x100000 { push!(2, cl, 0); }
            if cl >= 0x100000 || S_FIND != 0 { push!(3, 1, 0); }
            let heap = lf & 0x80 != 0;
            if !heap { push!(3, 2, 0); }
            push!(4, 0, 0);
            if S_VALID != 0 { push!(3, 3, 0); push!(5, 0, 0); }
            else {
                // intcall event: (int | eax << 8 | ebx << 40, edx | oreg_nonnull << 32); ireg words other than eax/ebx/edx are checked in the mock
                if RM_MAIN_X86_64 { push!(6, 0, 0); push!(7, 0x15u64 | (0xec00u64 << 8) | (2u64 << 40), 0); }
                push!(8, 0, 0);
                push!(6, 0, 0); push!(7, 0x16u64 | (0x0200u64 << 8), 1u64 << 32);
               
                push!(7, 0x16u64 | (0x0305u64 << 8), 0);
                if CPU_LEVEL_GE6() { push!(6, 0, 0); push!(7, 0x15u64 | (0xe980u64 << 8), 0x47534943u64 | 1u64 << 32); }
                if RM_MAIN_APM { push!(10, 0, 0); }
                if RM_MAIN_EDD { push!(11, 0, 0); }
                push!(9, 0, 0);
                push!(12, 0, 0);
            }
            let mut i = 0;
            assert!(N == n);
            while i < n { assert!(LOG[i] == e[i]); i += 1; }
            // zero page, byte by byte for a symbolic index
            let k: usize = kani::any();
            kani::assume(k < 4096);
            let b = boot_params.0[k];
            let in_hdr = k >= 0x1f1 && k < 0x1f1 + 0x7b;
            if in_hdr {
                if k >= 0x228 && k < 0x22c { assert!(b == (cl >> (8 * (k - 0x228))) as u8); } else { assert!(b == hdr[k - 0x1f1]); }
            } else if S_VALID == 0 && k == 0x1eb { assert!(b == ORET[0][7] as u8); }
            else if S_VALID == 0 && CPU_LEVEL_GE6() && k >= 0x60 && k < 0x70 {
                let o = ORET[1]; // the IST call is the second BIOS call with an output register set
                let w = [o[7], o[4], o[6], o[5]];
                assert!(b == (w[(k - 0x60) / 4] >> (8 * ((k - 0x60) % 4))) as u8);
            } else { assert!(b == 0); }
            // heap_end / HEAP
            let endp = addr_of!(_end) as usize;
            assert!(HEAP as usize == endp);
            if heap {
                let he = hp + 0x200;
                let se = (S_ESP as u64 + (1u64 << 32) - 1024) & 0xffff_ffff;
                let f = if he < se { he } else { se };
                assert!(heap_end as usize as u64 == f);
            } else { assert!(heap_end as usize == endp); }
            // the three port functions are installed
            assert!(pio_ops.f_inb.is_some() && pio_ops.f_outb.is_some() && pio_ops.f_outw.is_some());
        }
    }
    fn CPU_LEVEL_GE6() -> bool { unsafe { cpu.level >= 6 } }
    pub unsafe fn die() -> ! { ev(5, 0, 0); kani::cover!(true, "die path"); check_log(); kani::assume(false); loop {} }
    pub unsafe fn go_to_protected_mode() -> ! { ev(12, 0, 0); kani::cover!(true, "go_to_protected_mode path"); check_log(); kani::assume(false); loop {} }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use super::kmodel as k;
    fn setup() {
        unsafe {
            k::N = 0;
            k::NOR = 0;
            k::hdr = kani::any();
            k::OLDCMD = kani::any();
            k::S_DS = kani::any();
            k::S_ESP = kani::any();
            k::S_FS = kani::any();
            k::S_GS = kani::any();
            k::S_FIND = kani::any();
            k::S_VALID = kani::any();
            k::cpu.level = kani::any();
            k::ORET = kani::any();
            boot_params.0 = [0; 4096];
        }
    }
    /// All inputs: the whole of main() (both outcomes of validate_cpu, both heap arms, old-style command line or not).
    #[kani::proof]
    #[kani::unwind(70)]
    fn main_all() {
        setup();
        unsafe { main() }
    }
    /// Only the heap clamp: loadflags with CAN_USE_HEAP, any heap_end_ptr and esp (u32): heap_end == min(heap_end_ptr + 0x200, esp - 1024 mod 2^32).
    #[kani::proof]
    #[kani::unwind(70)]
    fn heap_clamp_all() {
        setup();
        unsafe { k::hdr[0x211 - 0x1f1] |= 0x80; k::S_VALID = kani::any(); }
        unsafe { main() }
    }
    /// The old-style command line protocol arithmetic: (seg << 4) + offset for every seg/offset (int arithmetic, never wraps), cmd_line_ptr starts at 0.
    #[kani::proof]
    #[kani::unwind(70)]
    fn old_cmdline_all() {
        setup();
        unsafe { k::hdr[0x228 - 0x1f1..0x22c - 0x1f1].copy_from_slice(&[0; 4]); k::OLDCMD[0] = 0xA33F; }
        unsafe { main() }
    }
}
