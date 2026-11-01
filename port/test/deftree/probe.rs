// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `deftree_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, by path, rather than
//! copying it -- a stale copy tested here while the kernel builds something
//! else is the failure notes/PRIOR-ART.md §2 records four times.
//!
//! `deftree_rs.rs` itself carries `deftree_rs_abi`, so nothing needs to be
//! added here; this file exists only to compile it as a `mod` (so it lands
//! in the staticlib the harness links) rather than as its own crate root.

#[path = "../../tree/lib/zlib_deflate/deftree_rs.rs"]
mod deftree_rs;
