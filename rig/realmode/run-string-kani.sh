#!/usr/bin/env bash
# run-string-kani.sh -- Kani on port/tree/arch/x86/boot/string_rs.rs (#[cfg(kani)] mod proofs): the digit-accumulation step exact for every u64 res and base 1..16,
# strlen/strnlen on every 6-byte string, parse_integer on every <= 21-char digit string vs a u128 reference. One verdict per harness. Needs cargo-kani (Kani 0.68).
cd "$(dirname "$0")/kani-string" && cargo kani 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error|Failed Checks|SUCCESSFUL|FAILED"
