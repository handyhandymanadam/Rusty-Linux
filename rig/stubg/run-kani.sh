#!/usr/bin/env bash
# run-kani.sh -- Kani 0.68 on misc_rs.rs (reloc_target / phdr size harnesses). Prints one verdict per harness.
cd "$(dirname "$0")/kani" && RUSTFLAGS="--cfg need_relocs --cfg relocatable" cargo kani 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error"
