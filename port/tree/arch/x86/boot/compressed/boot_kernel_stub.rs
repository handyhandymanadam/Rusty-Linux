// SPDX-License-Identifier: GPL-2.0
//! A crate named `kernel` for the x86 boot stub, holding only the
//! symbol-versioning annotation macros (kabi_rule, kabi_export, kabi_modinfo) that lib/*_rs.rs files invoke as
//! `kernel::kabi_rule!` / `kernel::kabi_export!`. In the running kernel they
//! emit contract data for gendwarfksyms (rust/kernel/kabi.rs); the stub exports
//! no symbols, so here they expand to nothing. Used by lib/lz4/lz4_decompress_rs.rs and lib/xxhash_rs.rs.
#![no_std]

#[macro_export]
macro_rules! kabi_rule {
    ($($t:tt)*) => {};
}

#[macro_export]
macro_rules! kabi_export {
    ($($t:tt)*) => {};
}

#[macro_export]
macro_rules! kabi_modinfo {
    ($($t:tt)*) => {};
}
