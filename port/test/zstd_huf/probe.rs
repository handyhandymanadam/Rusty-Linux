// SPDX-License-Identifier: GPL-2.0

//! Differential-harness wrapper around the real `huf_decompress_rs.rs`.
//!
//! Pulls in the file the kernel build compiles, BY PATH, rather than copying
//! it -- a stale copy tested here while the kernel builds something else is
//! the failure PRIOR-ART.md §2 records four times.
//!
//! It presents the port's nine entry points under `rs_*` so both arms can live
//! in one binary. All nine keep their own names in the kernel: none is
//! `EXPORT_SYMBOL`'d, so none carries a MODVERSIONS CRC and there are no
//! thunks -- the `lib/union_find` shape.

#![allow(non_snake_case)]

use std::os::raw::{c_int, c_uint, c_void};

/// The port itself, compiled from the file the kernel build compiles.
#[path = "../../tree/lib/zstd/decompress/huf_decompress_rs.rs"]
mod huf_decompress_rs;

use huf_decompress_rs as p;

macro_rules! fwd_dctx {
    ($rs:ident, $inner:ident) => {
        /// Entry point as the kernel links it: a direct Rust definition.
        /// # Safety
        /// Same contract as the C.
        #[no_mangle]
        pub unsafe extern "C" fn $rs(
            dctx: *mut u32, dst: *mut c_void, dstSize: usize,
            cSrc: *const c_void, cSrcSize: usize,
            wksp: *mut c_void, wkspSize: usize, flags: c_int,
        ) -> usize {
            // SAFETY: the harness owns every buffer and passes the same ones
            // to the C arm; preconditions are identical for both.
            unsafe {
                p::$inner(dctx, dst, dstSize, cSrc, cSrcSize, wksp, wkspSize, flags)
            }
        }
    };
}

fwd_dctx!(rs_HUF_decompress1X1_DCtx_wksp,   HUF_decompress1X1_DCtx_wksp);
fwd_dctx!(rs_HUF_decompress1X2_DCtx_wksp,   HUF_decompress1X2_DCtx_wksp);
fwd_dctx!(rs_HUF_decompress1X_DCtx_wksp,    HUF_decompress1X_DCtx_wksp);
fwd_dctx!(rs_HUF_decompress4X_hufOnly_wksp, HUF_decompress4X_hufOnly_wksp);

macro_rules! fwd_using {
    ($rs:ident, $inner:ident) => {
        /// Entry point as the kernel links it: a direct Rust definition.
        /// # Safety
        /// Same contract as the C: `DTable` must be one this file built.
        #[no_mangle]
        pub unsafe extern "C" fn $rs(
            dst: *mut c_void, maxDstSize: usize,
            cSrc: *const c_void, cSrcSize: usize,
            DTable: *const u32, flags: c_int,
        ) -> usize {
            // SAFETY: as above.
            unsafe { p::$inner(dst, maxDstSize, cSrc, cSrcSize, DTable, flags) }
        }
    };
}

fwd_using!(rs_HUF_decompress1X_usingDTable, HUF_decompress1X_usingDTable);
fwd_using!(rs_HUF_decompress4X_usingDTable, HUF_decompress4X_usingDTable);

macro_rules! fwd_read {
    ($rs:ident, $inner:ident) => {
        /// Entry point as the kernel links it: a direct Rust definition.
        /// # Safety
        /// Same contract as the C. Note `DTable[0]` is an INPUT carrying the
        /// DTableDesc, not just output space -- see port/test/zstd_huf/main.c.
        #[no_mangle]
        pub unsafe extern "C" fn $rs(
            DTable: *mut u32, src: *const c_void, srcSize: usize,
            wksp: *mut c_void, wkspSize: usize, flags: c_int,
        ) -> usize {
            // SAFETY: as above.
            unsafe { p::$inner(DTable, src, srcSize, wksp, wkspSize, flags) }
        }
    };
}

fwd_read!(rs_HUF_readDTableX1_wksp, HUF_readDTableX1_wksp);
fwd_read!(rs_HUF_readDTableX2_wksp, HUF_readDTableX2_wksp);

/// `HUF_selectDecoder`: pure over two sizes, and the branch that picks X1 or
/// X2 for every literals block in the kernel.
#[no_mangle]
pub extern "C" fn rs_HUF_selectDecoder(dstSize: usize, cSrcSize: usize) -> c_uint {
    p::HUF_selectDecoder(dstSize, cSrcSize)
}
