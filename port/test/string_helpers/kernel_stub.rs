// SPDX-License-Identifier: GPL-2.0
//! Stand-in for the real `kernel` crate, compiled as an actual separate
//! crate (not a same-file submodule) so `kernel::kabi_export!`/
//! `kernel::kabi_rule!`/`kernel::kabi_warn!`/`kernel::bindings::*` resolve
//! from `string_helpers_rs.rs` exactly as they would if it were pulled in
//! as a submodule -- same reasoning as `port/test/lzo_compress/
//! kernel_stub.rs`. kabi pinning is a kernel-build-only concern, so both
//! macros are no-ops here; `kabi_warn!` still evaluates and returns its
//! condition (matching the real macro's shape) so the differential
//! exercises the same control flow.
#![allow(unused_macros)]

#[macro_export]
macro_rules! kabi_rule {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! kabi_export {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! kabi_warn {
    ($cond:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        let cond = $cond;
        if cond {
            eprintln!(concat!("kabi_warn: ", $fmt) $(, $arg)*);
        }
        cond
    }};
}

pub mod bindings {
    /// Matches `build-full/rust/bindings/bindings_generated.rs`'s value for
    /// this kernel/config -- read directly, not guessed.
    pub const GFP_KERNEL: u32 = 3264;
    pub const PAGE_SIZE: usize = 4096;
}

pub mod page {
    pub const PAGE_SIZE: usize = crate::bindings::PAGE_SIZE;
}
