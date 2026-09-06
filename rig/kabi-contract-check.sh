#!/usr/bin/env bash
# kabi-contract-check.sh [build-dir]
#
# RE-DERIVE EVERY ABI CONTRACT FROM THE C, AND SHOW THE DIFFERENCE.
#
# Adam's design, 2026-09-04 (logs/abi-contract-design.md), point 3: "rebasing
# produces a diff, and the diff is the product" -- and point 4, which is the
# one that makes it worth having: "GENERATE MECHANICALLY, ACCEPT
# DELIBERATELY." So this prints and exits non-zero. It never edits a contract.
# A tool that silently updates the record to match reality is a tool whose
# alarm can never fire.
#
# WHY IT IS NEEDED NOW. kernel::kabi_export!() moved the ABI contract into the
# Rust object. That is the point -- the contract travels with the thing making
# the promise -- but it has a consequence: the C header stops participating in
# the fingerprint entirely. The contract becomes a LITERAL, a written assertion
# about a C declaration that nothing re-reads. If a rebase changes that
# declaration, every C caller quietly adopts the new one and our Rust does not,
# and no fingerprint moves, because nothing in the hash comes from that header
# any more.
#
# So something has to go back and read the C. This does.
#
# WHERE THE C COMES FROM. port/pristine/, compiled by rig/abi-ref.sh with the
# exact command line kbuild used -- not the header, and not our copy. A header
# declaration carries no parameter names and the contract depends on them; our
# copy would be the check agreeing with itself.
#
# RUN rig/abi-ref.sh FIRST. It is not run from here on purpose: it compiles 45
# files, and a check that silently rebuilds its own oracle is a check whose
# oracle you never look at.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:-build-fast}
[ -d "$root/$build" ] || { echo "no build dir $root/$build" >&2; exit 2; }
[ -d "$root/$build/abi-ref" ] || {
    echo "no C reference objects in $build/abi-ref -- run ./rig/abi-ref.sh $build" >&2
    exit 2
}
[ -x "$root/$build/scripts/gendwarfksyms/gendwarfksyms" ] || {
    echo "no gendwarfksyms in $build" >&2; exit 2; }

exec python3 "$root/rig/kabi-contract-check.py" "$root" "$build"
