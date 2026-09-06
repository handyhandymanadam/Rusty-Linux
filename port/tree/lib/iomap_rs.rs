// SPDX-License-Identifier: GPL-2.0
//! `lib/iomap.c` -> `lib/iomap_rs.rs`. The IO_COND dispatch (PIO vs
//! MMIO), the byte-swap and 64-bit hi/lo halving arithmetic, the
//! repeat-loop bookkeeping, and `bad_io_access()`'s rate-limited WARN all
//! moved here. `pci_iounmap()` did NOT move, and neither did any of the
//! real hardware-access primitives underneath every function in this
//! file -- see `lib/iomap.c`'s own header comment for both: the C entry
//! stays wherever moving it would mean either reproducing a real,
//! non-bare-instruction primitive (`insb`/`outsb`'s
//! `cc_platform_has()` check) or paying a ~512-type kabi pin closure for
//! one `IO_COND` branch (`pci_iounmap()`, `struct pci_dev *`).
//!
//! # `bad_io_access()`'s WARN() stays behind a single retained-C thunk
//!
//! `WARN()` builds a `__bug_table` entry attributing itself to the file
//! and line it is written at -- same reason `lib/dynamic_queue_limits.c`'s
//! `__dql_completed_bug_on()` and this project's other `WARN`/`BUG`-using
//! retained thunks exist (`logs/c-entry-rule.md`). `rust_iomap_bad_io_access()`
//! is that one thunk, called from every dispatch site in this file with a
//! short static string identifying the call site -- not the exact
//! stringified C expression the original `#is_pio` macro argument produced
//! (that string was never part of any ABI or tested contract, just
//! diagnostic text for a "this should never happen" path). **One
//! divergence worth recording**: the original file shared ONE
//! `static int count = 10` between EVERY caller, `pci_iounmap()` included,
//! rate-limiting the combined total of all bad accesses across the whole
//! file. Splitting `pci_iounmap()` back into `lib/iomap.c` means it now
//! keeps its own independent copy of `bad_io_access()` (`static`, C-only)
//! with its own independent count of 10 -- so a pathological caller could
//! now see up to 20 total warnings (10 from each side) instead of 10.
//! Unobservable in practice: this path is "a driver handed a garbage
//! cookie", never exercised by this port's differential or reachability
//! testing, and the count only ever affects how many times a diagnostic
//! prints before going silent, not correctness.
//!
//! # `CONFIG_KMSAN` is off on both configs
//!
//! `kmsan_check_memory()`/`kmsan_unpoison_memory()` are real functions
//! under `CONFIG_KMSAN` and `static inline` no-ops otherwise
//! (`include/linux/kmsan-checks.h`); `__no_kmsan_checks` is a real
//! sanitizer attribute under it and nothing otherwise. Neither this
//! project's config-full nor config-fast sets it, so all of the above are
//! omitted here rather than reproduced as no-ops that would need
//! revisiting the moment a config that DOES set it is added (GOALS.md's
//! floor is these two configs).

use core::ffi::c_void;

const PIO_OFFSET: usize = 0x10000;
const PIO_MASK: usize = 0x0ffff;
const PIO_RESERVED: usize = 0x40000;

unsafe extern "C" {
    fn rust_iomap_bad_io_access(port: u64, what: *const core::ffi::c_char);

    fn rust_iomap_inb(port: u16) -> u8;
    fn rust_iomap_inw(port: u16) -> u16;
    fn rust_iomap_inl(port: u16) -> u32;
    fn rust_iomap_outb(val: u8, port: u16);
    fn rust_iomap_outw(val: u16, port: u16);
    fn rust_iomap_outl(val: u32, port: u16);

    fn rust_iomap_readb(addr: *const c_void) -> u8;
    fn rust_iomap_readw(addr: *const c_void) -> u16;
    fn rust_iomap_readl(addr: *const c_void) -> u32;
    fn rust_iomap_readq(addr: *const c_void) -> u64;
    fn rust_iomap_writeb(val: u8, addr: *mut c_void);
    fn rust_iomap_writew(val: u16, addr: *mut c_void);
    fn rust_iomap_writel(val: u32, addr: *mut c_void);
    fn rust_iomap_writeq(val: u64, addr: *mut c_void);

    fn rust_iomap_raw_readb(addr: *const c_void) -> u8;
    fn rust_iomap_raw_readw(addr: *const c_void) -> u16;
    fn rust_iomap_raw_readl(addr: *const c_void) -> u32;
    fn rust_iomap_raw_writeb(val: u8, addr: *mut c_void);
    fn rust_iomap_raw_writew(val: u16, addr: *mut c_void);
    fn rust_iomap_raw_writel(val: u32, addr: *mut c_void);

    fn rust_iomap_insb(port: u16, addr: *mut c_void, count: u64);
    fn rust_iomap_insw(port: u16, addr: *mut c_void, count: u64);
    fn rust_iomap_insl(port: u16, addr: *mut c_void, count: u64);
    fn rust_iomap_outsb(port: u16, addr: *const c_void, count: u64);
    fn rust_iomap_outsw(port: u16, addr: *const c_void, count: u64);
    fn rust_iomap_outsl(port: u16, addr: *const c_void, count: u64);
}

enum IoAddr {
    Pio(u16),
    Mmio(*mut c_void),
}

/// Reproduces `IO_COND`'s three-way split exactly: a MMIO cookie (the
/// high range), a PIO cookie (masked down to its real port number), or
/// -- an address in the low, "clearly bad" range -- a rate-limited WARN
/// and `None`, meaning "do nothing, return the caller's own bad-value
/// sentinel".
#[inline]
unsafe fn io_cond(addr: *const c_void, what: &core::ffi::CStr) -> Option<IoAddr> {
    let port = addr as usize;
    if port >= PIO_RESERVED {
        Some(IoAddr::Mmio(addr as *mut c_void))
    } else if port > PIO_OFFSET {
        Some(IoAddr::Pio((port & PIO_MASK) as u16))
    } else {
        unsafe { rust_iomap_bad_io_access(port as u64, what.as_ptr()) };
        None
    }
}

/// Reads a byte from a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread8(addr: *const c_void) -> u32 {
    unsafe {
        match io_cond(addr, c"ioread8") {
            Some(IoAddr::Pio(port)) => rust_iomap_inb(port) as u32,
            Some(IoAddr::Mmio(a)) => rust_iomap_readb(a) as u32,
            None => 0xff,
        }
    }
}

/// Reads a 16-bit little-endian value from a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread16(addr: *const c_void) -> u32 {
    unsafe {
        match io_cond(addr, c"ioread16") {
            Some(IoAddr::Pio(port)) => rust_iomap_inw(port) as u32,
            Some(IoAddr::Mmio(a)) => rust_iomap_readw(a) as u32,
            None => 0xffff,
        }
    }
}

/// Reads a 16-bit big-endian value from a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread16be(addr: *const c_void) -> u32 {
    unsafe {
        match io_cond(addr, c"ioread16be") {
            Some(IoAddr::Pio(port)) => rust_iomap_inw(port).swap_bytes() as u32,
            Some(IoAddr::Mmio(a)) => rust_iomap_readw(a).swap_bytes() as u32,
            None => 0xffff,
        }
    }
}

/// Reads a 32-bit little-endian value from a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread32(addr: *const c_void) -> u32 {
    unsafe {
        match io_cond(addr, c"ioread32") {
            Some(IoAddr::Pio(port)) => rust_iomap_inl(port),
            Some(IoAddr::Mmio(a)) => rust_iomap_readl(a),
            None => 0xffffffff,
        }
    }
}

/// Reads a 32-bit big-endian value from a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread32be(addr: *const c_void) -> u32 {
    unsafe {
        match io_cond(addr, c"ioread32be") {
            Some(IoAddr::Pio(port)) => rust_iomap_inl(port).swap_bytes(),
            Some(IoAddr::Mmio(a)) => rust_iomap_readl(a).swap_bytes(),
            None => 0xffffffff,
        }
    }
}

kernel::kabi_export! {
    ioread8, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> base_type unsigned int byte_size(4) encoding(7)",
}
kernel::kabi_export! {
    ioread16, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> base_type unsigned int byte_size(4) encoding(7)",
}
kernel::kabi_export! {
    ioread16be, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> base_type unsigned int byte_size(4) encoding(7)",
}
kernel::kabi_export! {
    ioread32, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> base_type unsigned int byte_size(4) encoding(7)",
}
kernel::kabi_export! {
    ioread32be, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// `port.wrapping_add(4)`, not `port + 4`: the pristine C computes
/// `port + sizeof(u32)` as `unsigned long` (never overflows, since
/// `IO_COND` already masked `port` to 16 bits) and only truncates back to
/// 16 bits implicitly, at the `inl()`/`outl()` call site's `u16`
/// parameter -- so a `port` near `0xffff` silently wraps there in the
/// real C too. `wrapping_add` reproduces that truncation explicitly,
/// rather than relying on this build happening not to check for
/// overflow (caught by this file's own differential harness, which
/// deliberately turns overflow checks on: `port + 4` panicked at
/// `0xfffe`).
#[cfg(CONFIG_64BIT)]
fn pio_read64_lo_hi(port: u16) -> u64 {
    unsafe {
        let lo = rust_iomap_inl(port) as u64;
        let hi = rust_iomap_inl(port.wrapping_add(4)) as u64;
        lo | (hi << 32)
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_read64_hi_lo(port: u16) -> u64 {
    unsafe {
        let hi = rust_iomap_inl(port.wrapping_add(4)) as u64;
        let lo = rust_iomap_inl(port) as u64;
        lo | (hi << 32)
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_read64be_lo_hi(port: u16) -> u64 {
    unsafe {
        let lo = rust_iomap_inl(port.wrapping_add(4)).swap_bytes() as u64;
        let hi = rust_iomap_inl(port).swap_bytes() as u64;
        lo | (hi << 32)
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_read64be_hi_lo(port: u16) -> u64 {
    unsafe {
        let hi = rust_iomap_inl(port).swap_bytes() as u64;
        let lo = rust_iomap_inl(port.wrapping_add(4)).swap_bytes() as u64;
        lo | (hi << 32)
    }
}

/// 64-bit little-endian read, low word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __ioread64_lo_hi(addr: *const c_void) -> u64 {
    unsafe {
        match io_cond(addr, c"__ioread64_lo_hi") {
            Some(IoAddr::Pio(port)) => pio_read64_lo_hi(port),
            Some(IoAddr::Mmio(a)) => rust_iomap_readq(a),
            None => 0xffffffffffffffff,
        }
    }
}
/// 64-bit little-endian read, high word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __ioread64_hi_lo(addr: *const c_void) -> u64 {
    unsafe {
        match io_cond(addr, c"__ioread64_hi_lo") {
            Some(IoAddr::Pio(port)) => pio_read64_hi_lo(port),
            Some(IoAddr::Mmio(a)) => rust_iomap_readq(a),
            None => 0xffffffffffffffff,
        }
    }
}
/// 64-bit big-endian read, low word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __ioread64be_lo_hi(addr: *const c_void) -> u64 {
    unsafe {
        match io_cond(addr, c"__ioread64be_lo_hi") {
            Some(IoAddr::Pio(port)) => pio_read64be_lo_hi(port),
            Some(IoAddr::Mmio(a)) => rust_iomap_readq(a).swap_bytes(),
            None => 0xffffffffffffffff,
        }
    }
}
/// 64-bit big-endian read, high word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __ioread64be_hi_lo(addr: *const c_void) -> u64 {
    unsafe {
        match io_cond(addr, c"__ioread64be_hi_lo") {
            Some(IoAddr::Pio(port)) => pio_read64be_hi_lo(port),
            Some(IoAddr::Mmio(a)) => rust_iomap_readq(a).swap_bytes(),
            None => 0xffffffffffffffff,
        }
    }
}

#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __ioread64_lo_hi, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> t#u64",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __ioread64_hi_lo, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> t#u64",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __ioread64be_lo_hi, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> t#u64",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __ioread64be_hi_lo, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr ) -> t#u64",
}

/// Writes a byte to a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite8(val: u8, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"iowrite8") {
            Some(IoAddr::Pio(port)) => rust_iomap_outb(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writeb(val, a),
            None => {}
        }
    }
}
/// Writes a 16-bit little-endian value to a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite16(val: u16, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"iowrite16") {
            Some(IoAddr::Pio(port)) => rust_iomap_outw(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writew(val, a),
            None => {}
        }
    }
}
/// Writes a 16-bit big-endian value to a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite16be(val: u16, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"iowrite16be") {
            Some(IoAddr::Pio(port)) => rust_iomap_outw(val.swap_bytes(), port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writew(val.swap_bytes(), a),
            None => {}
        }
    }
}
/// Writes a 32-bit little-endian value to a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite32(val: u32, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"iowrite32") {
            Some(IoAddr::Pio(port)) => rust_iomap_outl(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writel(val, a),
            None => {}
        }
    }
}
/// Writes a 32-bit big-endian value to a PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite32be(val: u32, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"iowrite32be") {
            Some(IoAddr::Pio(port)) => rust_iomap_outl(val.swap_bytes(), port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writel(val.swap_bytes(), a),
            None => {}
        }
    }
}

kernel::kabi_export! {
    iowrite8, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u8 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
kernel::kabi_export! {
    iowrite16, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u16 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
kernel::kabi_export! {
    iowrite16be, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u16 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
kernel::kabi_export! {
    iowrite32, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u32 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
kernel::kabi_export! {
    iowrite32be, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u32 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}

#[cfg(CONFIG_64BIT)]
fn pio_write64_lo_hi(val: u64, port: u16) {
    unsafe {
        rust_iomap_outl(val as u32, port);
        rust_iomap_outl((val >> 32) as u32, port.wrapping_add(4));
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_write64_hi_lo(val: u64, port: u16) {
    unsafe {
        rust_iomap_outl((val >> 32) as u32, port.wrapping_add(4));
        rust_iomap_outl(val as u32, port);
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_write64be_lo_hi(val: u64, port: u16) {
    unsafe {
        rust_iomap_outl((val as u32).swap_bytes(), port.wrapping_add(4));
        rust_iomap_outl(((val >> 32) as u32).swap_bytes(), port);
    }
}
#[cfg(CONFIG_64BIT)]
fn pio_write64be_hi_lo(val: u64, port: u16) {
    unsafe {
        rust_iomap_outl(((val >> 32) as u32).swap_bytes(), port);
        rust_iomap_outl((val as u32).swap_bytes(), port.wrapping_add(4));
    }
}

/// 64-bit little-endian write, low word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __iowrite64_lo_hi(val: u64, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"__iowrite64_lo_hi") {
            Some(IoAddr::Pio(port)) => pio_write64_lo_hi(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writeq(val, a),
            None => {}
        }
    }
}
/// 64-bit little-endian write, high word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __iowrite64_hi_lo(val: u64, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"__iowrite64_hi_lo") {
            Some(IoAddr::Pio(port)) => pio_write64_hi_lo(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writeq(val, a),
            None => {}
        }
    }
}
/// 64-bit big-endian write, low word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __iowrite64be_lo_hi(val: u64, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"__iowrite64be_lo_hi") {
            Some(IoAddr::Pio(port)) => pio_write64be_lo_hi(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writeq(val.swap_bytes(), a),
            None => {}
        }
    }
}
/// 64-bit big-endian write, high word first on the PIO path.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn __iowrite64be_hi_lo(val: u64, addr: *mut c_void) {
    unsafe {
        match io_cond(addr, c"__iowrite64be_hi_lo") {
            Some(IoAddr::Pio(port)) => pio_write64be_hi_lo(val, port),
            Some(IoAddr::Mmio(a)) => rust_iomap_writeq(val.swap_bytes(), a),
            None => {}
        }
    }
}

#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __iowrite64_lo_hi, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u64 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __iowrite64_hi_lo, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u64 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __iowrite64be_lo_hi, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u64 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}
#[cfg(CONFIG_64BIT)]
kernel::kabi_export! {
    __iowrite64be_hi_lo, license = "", namespace = "",
    contract = "subprogram ( formal_parameter t#u64 val , formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}

/// `mmio_ins*()`/`mmio_outs*()` -- the "note the __raw accesses" comment
/// in the pristine C is real and preserved: no byte-swap, no barrier
/// beyond what `__raw_read*()`/`__raw_write*()` themselves give.
///
/// `count.wrapping_sub(1)`, not `count -= 1`: the pristine C's own
/// `while (--count >= 0)` decrements a plain, unchecked `int` that
/// arrived truncated from `ioread8_rep()`'s `unsigned long count`
/// (`count as i32` at the call site, matching the same implicit
/// narrowing) -- a `count` this large is not a realistic driver request,
/// but a signed-int decrement underflow is undefined behaviour in C too,
/// not a crash, so `wrapping_sub` avoids adding a Rust-only panic where
/// the C had none (found via `rig/uaccess-panic-check.sh`).
unsafe fn mmio_insb(addr: *const c_void, dst: *mut u8, count: i32) {
    unsafe {
        let mut count = count;
        let mut dst = dst;
        while { count = count.wrapping_sub(1); count >= 0 } {
            *dst = rust_iomap_raw_readb(addr);
            dst = dst.add(1);
        }
    }
}
unsafe fn mmio_insw(addr: *const c_void, dst: *mut u16, count: i32) {
    unsafe {
        let mut count = count;
        let mut dst = dst;
        while { count = count.wrapping_sub(1); count >= 0 } {
            *dst = rust_iomap_raw_readw(addr);
            dst = dst.add(1);
        }
    }
}
unsafe fn mmio_insl(addr: *const c_void, dst: *mut u32, count: i32) {
    unsafe {
        let mut count = count;
        let mut dst = dst;
        while { count = count.wrapping_sub(1); count >= 0 } {
            *dst = rust_iomap_raw_readl(addr);
            dst = dst.add(1);
        }
    }
}
unsafe fn mmio_outsb(addr: *mut c_void, src: *const u8, count: i32) {
    unsafe {
        let mut count = count;
        let mut src = src;
        while { count = count.wrapping_sub(1); count >= 0 } {
            rust_iomap_raw_writeb(*src, addr);
            src = src.add(1);
        }
    }
}
unsafe fn mmio_outsw(addr: *mut c_void, src: *const u16, count: i32) {
    unsafe {
        let mut count = count;
        let mut src = src;
        while { count = count.wrapping_sub(1); count >= 0 } {
            rust_iomap_raw_writew(*src, addr);
            src = src.add(1);
        }
    }
}
unsafe fn mmio_outsl(addr: *mut c_void, src: *const u32, count: i32) {
    unsafe {
        let mut count = count;
        let mut src = src;
        while { count = count.wrapping_sub(1); count >= 0 } {
            rust_iomap_raw_writel(*src, addr);
            src = src.add(1);
        }
    }
}

/// Faithful to the C: `count` arrives as `unsigned long` but the loops
/// above use a signed, decrement-then-test `int` (`while (--count >= 0)`)
/// -- so a `count` beyond `INT_MAX` truncates the same way it would in
/// the original, not a divergence.
/// Reads `count` bytes into `dst` from a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread8_rep(addr: *const c_void, dst: *mut c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"ioread8_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_insb(port, dst, count),
            Some(IoAddr::Mmio(a)) => mmio_insb(a, dst as *mut u8, count as i32),
            None => {}
        }
    }
}
/// Reads `count` 16-bit words into `dst` from a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread16_rep(addr: *const c_void, dst: *mut c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"ioread16_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_insw(port, dst, count),
            Some(IoAddr::Mmio(a)) => mmio_insw(a, dst as *mut u16, count as i32),
            None => {}
        }
    }
}
/// Reads `count` 32-bit words into `dst` from a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn ioread32_rep(addr: *const c_void, dst: *mut c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"ioread32_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_insl(port, dst, count),
            Some(IoAddr::Mmio(a)) => mmio_insl(a, dst as *mut u32, count as i32),
            None => {}
        }
    }
}
/// Writes `count` bytes from `src` to a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite8_rep(addr: *mut c_void, src: *const c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"iowrite8_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_outsb(port, src, count),
            Some(IoAddr::Mmio(a)) => mmio_outsb(a, src as *const u8, count as i32),
            None => {}
        }
    }
}
/// Writes `count` 16-bit words from `src` to a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite16_rep(addr: *mut c_void, src: *const c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"iowrite16_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_outsw(port, src, count),
            Some(IoAddr::Mmio(a)) => mmio_outsw(a, src as *const u16, count as i32),
            None => {}
        }
    }
}
/// Writes `count` 32-bit words from `src` to a fixed PIO or MMIO cookie.
#[no_mangle]
pub unsafe extern "C" fn iowrite32_rep(addr: *mut c_void, src: *const c_void, count: u64) {
    unsafe {
        match io_cond(addr, c"iowrite32_rep") {
            Some(IoAddr::Pio(port)) => rust_iomap_outsl(port, src, count),
            Some(IoAddr::Mmio(a)) => mmio_outsl(a, src as *const u32, count as i32),
            None => {}
        }
    }
}

kernel::kabi_export! {
    ioread8_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr , formal_parameter pointer_type { base_type void } dst , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}
kernel::kabi_export! {
    ioread16_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr , formal_parameter pointer_type { base_type void } dst , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}
kernel::kabi_export! {
    ioread32_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } addr , formal_parameter pointer_type { base_type void } dst , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}
kernel::kabi_export! {
    iowrite8_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } addr , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}
kernel::kabi_export! {
    iowrite16_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } addr , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}
kernel::kabi_export! {
    iowrite32_rep, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } addr , formal_parameter pointer_type { const_type { base_type void } } src , formal_parameter base_type unsigned long byte_size(8) encoding(7) count ) -> base_type void",
}

/// Creates a virtual mapping cookie for an IO port range -- pure
/// arithmetic, no hardware access at all (the actual mapping is encoded
/// entirely in the returned cookie's numeric value, per this file's own
/// module doc in the pristine C).
#[cfg(CONFIG_HAS_IOPORT_MAP)]
/// Creates a virtual mapping cookie for an IO port range.
#[no_mangle]
pub unsafe extern "C" fn ioport_map(port: u64, nr: u32) -> *mut c_void {
    let _ = nr;
    if port > PIO_MASK as u64 {
        core::ptr::null_mut()
    } else {
        (port + PIO_OFFSET as u64) as *mut c_void
    }
}

#[cfg(CONFIG_HAS_IOPORT_MAP)]
/// Releases a cookie from `ioport_map()` -- nothing to do.
#[no_mangle]
pub unsafe extern "C" fn ioport_unmap(addr: *mut c_void) {
    let _ = addr;
}

#[cfg(CONFIG_HAS_IOPORT_MAP)]
kernel::kabi_export! {
    ioport_map, license = "", namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) port , formal_parameter base_type unsigned int byte_size(4) encoding(7) nr ) -> pointer_type { base_type void }",
}
#[cfg(CONFIG_HAS_IOPORT_MAP)]
kernel::kabi_export! {
    ioport_unmap, license = "", namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { base_type void } addr ) -> base_type void",
}

kernel::kabi_rule!("type_string", "t#__u8", "typedef_type __u8 { base_type unsigned char byte_size(1) encoding(8) }");
kernel::kabi_rule!("type_string", "t#u8", "typedef_type u8 { t#__u8 }");
kernel::kabi_rule!("type_string", "t#__u16", "typedef_type __u16 { base_type unsigned short byte_size(2) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u16", "typedef_type u16 { t#__u16 }");
kernel::kabi_rule!("type_string", "t#__u32", "typedef_type __u32 { base_type unsigned int byte_size(4) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u32", "typedef_type u32 { t#__u32 }");
kernel::kabi_rule!("type_string", "t#__u64", "typedef_type __u64 { base_type unsigned long long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#u64", "typedef_type u64 { t#__u64 }");
