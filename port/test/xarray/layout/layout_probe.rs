// SPDX-License-Identifier: GPL-2.0-or-later
//! Drives xarray_rs.rs's `print_layout()` (see that file's own doc
//! comment). Compile with `--cfg xa_layout_probe`, and with
//! `--cfg xa_harness_small_chunk` for the CONFIG_BASE_SMALL=1 arm or
//! without it for the real-config (=6) arm -- matching
//! layout_probe.c's `-DCONFIG_BASE_SMALL=1`/`=0`.

#[path = "../../../tree/lib/xarray_rs.rs"]
mod xarray_rs;

fn main() {
    xarray_rs::print_layout();
}
