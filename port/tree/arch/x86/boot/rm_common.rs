// SPDX-License-Identifier: GPL-2.0-only
//! Declarations shared by the real-mode setup ports (`#[path = "rm_common.rs"] mod rm;`).
//! Mirrors boot.h / io.h of the 16-bit setup code; every `extern "C"` here is called with the
//! C's `-mregparm=3` convention because the whole crate is built with `-Zregparm=3`.
#![allow(dead_code)]

use core::arch::asm;
use core::mem::MaybeUninit;

pub const X86_EFLAGS_CF: u32 = 0x0001;
pub const X86_EFLAGS_ZF: u32 = 0x0040;

/// `struct biosregs`: eleven u32 (edi esi ebp _esp ebx edx ecx eax _fsgs _dses eflags).
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

/// `struct port_io_ops pio_ops` (io.h; main.c).
#[repr(C)]
pub struct PortIoOps {
    pub f_inb: Option<unsafe extern "C" fn(u16) -> u8>,
    pub f_outb: Option<unsafe extern "C" fn(u8, u16)>,
    pub f_outw: Option<unsafe extern "C" fn(u16, u16)>,
}

extern "C" {
    pub fn intcall(int_no: u8, ireg: *const BiosRegs, oreg: *mut BiosRegs);
    pub fn initregs(reg: *mut BiosRegs);
    pub static pio_ops: PortIoOps;
}

/// `struct biosregs ireg; initregs(&ireg);`
#[inline(always)]
pub unsafe fn new_regs() -> BiosRegs {
    let mut r = MaybeUninit::<BiosRegs>::uninit();
    // SAFETY: initregs() writes every byte of the 44-byte struct.
    unsafe {
        initregs(r.as_mut_ptr());
        r.assume_init()
    }
}

/// An output register set whose contents the BIOS call fills (intcall() writes all of it).
#[inline(always)]
pub unsafe fn out_regs() -> MaybeUninit<BiosRegs> {
    MaybeUninit::uninit()
}

/// `inb(port)` of io.h: through `pio_ops.f_inb` (TDX guests swap it).
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: init_default_io_ops() ran in main() before any caller.
    unsafe { (pio_ops.f_inb.unwrap_unchecked())(port) }
}

#[inline(always)]
pub unsafe fn outb(v: u8, port: u16) {
    // SAFETY: as inb().
    unsafe { (pio_ops.f_outb.unwrap_unchecked())(v, port) }
}

#[inline(always)]
pub fn cpu_relax() {
    // SAFETY: `pause` is a hint with no side effects.
    unsafe { asm!("pause", options(nomem, nostack, preserves_flags)) };
}

// ---- helpers added for the edd/apm/video ports (nothing above changed; every item is #[inline(always)] or a type, so the
// objects of the earlier ports are unaffected) -----------------------------------------------------------------------------------

/// The partial-register views of `struct biosregs` (boot.h's anonymous unions): `ireg.ah = x` keeps the other bits, exactly as the C.
impl BiosRegs {
    #[inline(always)]
    pub fn set_ax(&mut self, v: u16) {
        self.eax = (self.eax & !0xffff) | v as u32;
    }
    #[inline(always)]
    pub fn set_al(&mut self, v: u8) {
        self.eax = (self.eax & !0xff) | v as u32;
    }
    #[inline(always)]
    pub fn set_ah(&mut self, v: u8) {
        self.eax = (self.eax & !0xff00) | ((v as u32) << 8);
    }
    #[inline(always)]
    pub fn set_bx(&mut self, v: u16) {
        self.ebx = (self.ebx & !0xffff) | v as u32;
    }
    #[inline(always)]
    pub fn set_bl(&mut self, v: u8) {
        self.ebx = (self.ebx & !0xff) | v as u32;
    }
    #[inline(always)]
    pub fn set_bh(&mut self, v: u8) {
        self.ebx = (self.ebx & !0xff00) | ((v as u32) << 8);
    }
    #[inline(always)]
    pub fn set_cx(&mut self, v: u16) {
        self.ecx = (self.ecx & !0xffff) | v as u32;
    }
    #[inline(always)]
    pub fn set_dl(&mut self, v: u8) {
        self.edx = (self.edx & !0xff) | v as u32;
    }
    #[inline(always)]
    pub fn set_dh(&mut self, v: u8) {
        self.edx = (self.edx & !0xff00) | ((v as u32) << 8);
    }
    #[inline(always)]
    pub fn set_si(&mut self, v: u16) {
        self.esi = (self.esi & !0xffff) | v as u32;
    }
    #[inline(always)]
    pub fn set_di(&mut self, v: u16) {
        self.edi = (self.edi & !0xffff) | v as u32;
    }
    #[inline(always)]
    pub fn ax(&self) -> u16 {
        self.eax as u16
    }
    #[inline(always)]
    pub fn al(&self) -> u8 {
        self.eax as u8
    }
    #[inline(always)]
    pub fn ah(&self) -> u8 {
        (self.eax >> 8) as u8
    }
    #[inline(always)]
    pub fn bx(&self) -> u16 {
        self.ebx as u16
    }
    #[inline(always)]
    pub fn bl(&self) -> u8 {
        self.ebx as u8
    }
    #[inline(always)]
    pub fn bh(&self) -> u8 {
        (self.ebx >> 8) as u8
    }
    #[inline(always)]
    pub fn cx(&self) -> u16 {
        self.ecx as u16
    }
    #[inline(always)]
    pub fn cl(&self) -> u8 {
        self.ecx as u8
    }
    #[inline(always)]
    pub fn ch(&self) -> u8 {
        (self.ecx >> 8) as u8
    }
    #[inline(always)]
    pub fn dx(&self) -> u16 {
        self.edx as u16
    }
    #[inline(always)]
    pub fn dl(&self) -> u8 {
        self.edx as u8
    }
    #[inline(always)]
    pub fn dh(&self) -> u8 {
        (self.edx >> 8) as u8
    }
    #[inline(always)]
    pub fn si(&self) -> u16 {
        self.esi as u16
    }
    #[inline(always)]
    pub fn di(&self) -> u16 {
        self.edi as u16
    }
    /// `hsi` (the high half of esi)
    #[inline(always)]
    pub fn hsi(&self) -> u16 {
        (self.esi >> 16) as u16
    }
}

/// boot.h `ds()`.
#[cfg(not(host_mock))]
#[inline(always)]
pub fn ds() -> u16 {
    let s: u16;
    // SAFETY: reads a segment register.
    unsafe { asm!("mov {0:x}, ds", out(reg_abcd) s, options(nomem, nostack, preserves_flags)) };
    s
}
/// boot.h `set_fs()`: `movw %0,%%fs` (a memory clobber is NOT declared by the C either: it is `asm volatile`).
#[cfg(not(host_mock))]
#[inline(always)]
pub unsafe fn set_fs(seg: u16) {
    unsafe { asm!("mov fs, {0:x}", in(reg_abcd) seg, options(nostack, preserves_flags)) };
}
/// boot.h `rdfs8(addr)`: `movb %fs:(addr)`.
#[cfg(not(host_mock))]
#[inline(always)]
pub unsafe fn rdfs8(addr: u32) -> u8 {
    let v: u8;
    unsafe { asm!("mov {0}, byte ptr fs:[{1:e}]", out(reg_byte) v, in(reg) addr, options(nostack, preserves_flags, readonly)) };
    v
}
/// boot.h `rdfs16(addr)`.
#[cfg(not(host_mock))]
#[inline(always)]
pub unsafe fn rdfs16(addr: u32) -> u16 {
    let v: u16;
    unsafe { asm!("mov {0:x}, word ptr fs:[{1:e}]", out(reg) v, in(reg) addr, options(nostack, preserves_flags, readonly)) };
    v
}
#[cfg(host_mock)]
extern "C" {
    fn mock_ds() -> u16;
    fn mock_set_fs(seg: u16);
    fn mock_rdfs8(addr: u32) -> u8;
    fn mock_rdfs16(addr: u32) -> u16;
}
#[cfg(host_mock)]
pub fn ds() -> u16 {
    unsafe { mock_ds() }
}
#[cfg(host_mock)]
pub unsafe fn set_fs(seg: u16) {
    unsafe { mock_set_fs(seg) }
}
#[cfg(host_mock)]
pub unsafe fn rdfs8(addr: u32) -> u8 {
    unsafe { mock_rdfs8(addr) }
}
#[cfg(host_mock)]
pub unsafe fn rdfs16(addr: u32) -> u16 {
    unsafe { mock_rdfs16(addr) }
}

// The setup heap of boot.h (`HEAP`, `heap_end`, `_end`): main.c defines the two pointers.
extern "C" {
    pub static mut HEAP: *mut u8;
    pub static mut heap_end: *mut u8;
    #[cfg_attr(host_mock, link_name = "host_end")] // host rigs: the GNU linker owns the name `_end`
    pub static mut _end: u8;
}

/// `RESET_HEAP()`
#[inline(always)]
pub unsafe fn reset_heap() {
    unsafe { HEAP = core::ptr::addr_of_mut!(_end) };
}
/// `__get_heap(size, align, n)`: align HEAP up, hand out the old value, advance by size*n.
#[inline(always)]
pub unsafe fn get_heap(size: usize, align: usize, n: usize) -> *mut u8 {
    unsafe {
        HEAP = ((HEAP as usize).wrapping_add(align - 1) & !(align - 1)) as *mut u8;
        let tmp = HEAP;
        HEAP = (HEAP as usize).wrapping_add(size.wrapping_mul(n)) as *mut u8;
        tmp
    }
}
/// `heap_free(n)`: `(int)(heap_end-HEAP) >= (int)n`.
#[inline(always)]
pub unsafe fn heap_free(n: usize) -> bool {
    unsafe { ((heap_end as usize).wrapping_sub(HEAP as usize) as i32) >= (n as i32) }
}
