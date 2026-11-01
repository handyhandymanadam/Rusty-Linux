// SPDX-License-Identifier: GPL-2.0
//! Pre-boot Rust probe: does no_std Rust run in arch/x86/boot/compressed/?
//!
//! There is no kernel here yet -- no allocator, no rust/ runtime, no panic
//! infrastructure. Everything this file needs, it brings.

#![no_std]

/// The boot stub has no console by the time a panic could happen and nowhere
/// to unwind to. `sev.c` does the same thing for the same reason.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        // SAFETY: `hlt` touches no memory and never returns to us in a way
        // that matters; the loop is here because an NMI can wake it.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// A value only this Rust could produce.
///
/// Deliberately not constant-foldable to nothing: it walks a slice and does
/// wrapping arithmetic, so if it is elided the answer changes. The caller in
/// misc.c prints it, which is criterion 5 -- "the Rust actually ran" -- rather
/// than merely "it linked".
#[no_mangle]
pub extern "C" fn rust_preboot_probe(seed: u32) -> u32 {
    let mut h: u32 = seed ^ 0x9e37_79b9;
    let mut i: u32 = 0;
    while i < 32 {
        h = h.rotate_left(5).wrapping_mul(0x0100_0193) ^ i;
        i += 1;
    }
    h
}

/// `core` is linked into the stub as one object now (the XZ decoder uses it),
/// and that object references 128-bit division from `fmt`'s integer printing.
/// Nothing in the stub formats a u128, so this is dead code that exists only
/// so the link resolves; if it ever runs, stopping is the safe answer. The
/// running kernel's `rust/compiler_builtins.rs` makes the same choice.
#[no_mangle]
pub extern "C" fn __udivti3(_n: u128, _d: u128) -> u128 {
    loop {
        // SAFETY: as `panic` above.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
