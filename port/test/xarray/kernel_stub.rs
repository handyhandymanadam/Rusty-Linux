// SPDX-License-Identifier: GPL-2.0-or-later
//! Stand-in for the real `kernel` crate, compiled as an actual separate
//! crate (not a same-file submodule) so `kernel::kabi_export!`/
//! `kernel::kabi_rule!` resolve from `xarray_rs.rs` exactly as they would
//! if it were pulled in as a submodule (`#[path] mod ..;`, as probe.rs
//! does) -- a local `mod kernel {}` sibling only resolves for code
//! concatenated into the SAME top-level scope, which a `#[path]`-included
//! submodule is not. kabi pinning is a kernel-build-only concern, so
//! `kabi_rule!`/`kabi_export!` are no-ops here.
//!
//! `kabi_warn_on_once!`/`warn_on!` are NOT no-ops: they evaluate and return
//! their condition, matching the real macros' shape, so the differential
//! exercises the same control flow the kernel does. A no-op that dropped the
//! condition would silently change every `if kernel::warn_on!(c)` into a
//! never-taken branch and the harness would stop testing the guarded paths
//! entirely -- same reasoning as port/test/vsprintf/kernel_stub.rs.
#![allow(unused_macros)]

#[macro_export]
macro_rules! kabi_rule {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! kabi_export {
    ($($t:tt)*) => {};
}

// The real macros report to dmesg and return the condition. Here only the
// return value matters: the harness has no bug table, and the C reference arm
// prints nothing a differential could compare against either.
#[macro_export]
macro_rules! kabi_warn_on_once {
    ($cond:expr) => {{
        let cond = $cond;
        cond
    }};
}
#[macro_export]
macro_rules! warn_on {
    ($cond:expr) => {{
        let cond = $cond;
        cond
    }};
}
