// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `deflate_rs.rs` and `deftree_rs.rs`.
//!
//! Pulls in the files the kernel build compiles, by path, rather than copying them -- a stale copy tested here
//! while the kernel builds something else is the failure notes/PRIOR-ART.md section 2 records four times.

#[path = "../../tree/lib/zlib_deflate/deftree_rs.rs"]
mod deftree_rs;
#[path = "../../tree/lib/zlib_deflate/deflate_rs.rs"]
mod deflate_rs;
