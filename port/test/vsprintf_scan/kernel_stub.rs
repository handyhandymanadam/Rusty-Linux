// SPDX-License-Identifier: GPL-2.0
//! Stand-in for the real `kernel` crate, same reasoning as
//! `port/test/string_helpers/kernel_stub.rs`: compiled as an actual
//! separate crate so `kernel::kabi_export!`/`kernel::kabi_rule!`/
//! `kernel::kabi_warn!`/`kernel::kabi_warn_on_once!`/`kernel::bindings::*`
//! resolve from `vsprintf_rs.rs` exactly as they would pulled in as a
//! submodule of the real kernel crate. kabi pinning is a kernel-build-only
//! concern, so `kabi_rule!`/`kabi_export!` are no-ops; `kabi_warn!`/
//! `kabi_warn_on_once!` still evaluate and return their condition
//! (matching the real macros' shape) so the differential exercises the
//! same control flow.
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
            $(let _ = &$arg;)*
            eprintln!("kabi_warn: {}", $fmt);
        }
        cond
    }};
}
#[macro_export]
macro_rules! kabi_warn_on_once {
    ($cond:expr) => {{
        let cond = $cond;
        cond
    }};
}

pub mod bindings {
    pub const GFP_KERNEL: u32 = 3264;
    pub const PAGE_SIZE: usize = 4096;
}
