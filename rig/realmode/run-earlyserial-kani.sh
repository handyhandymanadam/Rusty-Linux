#!/usr/bin/env bash
# run-earlyserial-kani.sh -- Kani on port/tree/arch/x86/boot/early_serial_console_rs.rs (#[cfg(kani)] mod proofs): memory safety of the
# command-line parse over every value, no idiv by zero, exact UART access sequence/values of early_serial_init for every port and
# nonzero baud, probe_baud's order and #DE-iff-zero, result range. One verdict per harness. Needs cargo-kani (Kani 0.68).
cd "$(dirname "$0")/kani-earlyserial" && cargo kani 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error|Failed Checks|SUCCESSFUL|FAILED"
