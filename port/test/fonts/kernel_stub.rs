// SPDX-License-Identifier: GPL-2.0-or-later
//! Stand-in for the real `kernel` crate, compiled as an actual separate
//! crate so `kernel::kabi_export!`/`kernel::kabi_rule!` resolve from
//! font_8x16_rs.rs exactly as they would pulled in as a submodule
//! (`#[path] mod ..;`, as layout_probe.rs does) -- a local `mod kernel
//! {}` sibling only resolves for code concatenated into the SAME
//! top-level scope, which a `#[path]`-included submodule is not. kabi
//! pinning is a kernel-build-only concern, so both macros are no-ops
//! here. Same shape as port/test/xarray/kernel_stub.rs.
#![allow(unused_macros)]

#[macro_export]
macro_rules! kabi_rule {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! kabi_export {
    ($($t:tt)*) => {};
}
