// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/version.c: the one global `const char kernel_version[]` =
//! `UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") " UTS_VERSION`, NUL-terminated, in `.rodata`.
//! header.S points the setup header's `kernel_version` field at it (`kernel_version-512`), so the boot loader prints it.
//! The text comes from version_gen.rs (the Makefile runs the C preprocessor over version_gen.rs.in with the same generated
//! headers the C includes), so it cannot drift from the C. No code, no relocations, no other symbol.
//!
//! TEST-GAP: nothing here can be wrong in a way a runtime test could see that the object comparison does not: the object
//! is data only. What a boot loader does with the string (GRUB/syslinux `uname -r` style display, `file bzImage`) is not tested
//! here beyond reading the bytes at the header's offset in the booted image (rig/realmode/version-check.sh).
#![allow(dead_code)]

include!(concat!(env!("RM_GEN_DIR"), "/version_gen.rs"));

const LEN: usize = RM_KERNEL_VERSION.len() + 1;

const fn with_nul() -> [u8; LEN] {
    let s = RM_KERNEL_VERSION.as_bytes();
    let mut out = [0u8; LEN];
    let mut i = 0;
    while i < s.len() {
        out[i] = s[i];
        i += 1;
    }
    out
}

/// `const char kernel_version[]` (plain `.rodata`, as the C's).
#[no_mangle]
#[link_section = ".rodata"]
pub static kernel_version: [u8; LEN] = with_nul();
