#!/usr/bin/env bash
# run-cmdline-kani.sh -- Kani on port/tree/arch/x86/boot/cmdline_rs.rs (#[cfg(kani)] mod proofs): memory safety, no overflow,
# window bound, NUL placement, any-bufsize index bound. One verdict per harness. Needs cargo-kani (Kani 0.68).
cd "$(dirname "$0")/kani-cmdline" && cargo kani 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error|Failed Checks|SUCCESSFUL|FAILED"
