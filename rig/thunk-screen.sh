#!/usr/bin/env bash
# thunk-screen.sh
#
# BEFORE CLOSING A THUNK, READ WHAT THE C ENTRY ACTUALLY DOES.
#
# rig/guard-check.sh catches a closure that threw a guard away, AFTER the fact.
# This is the same question asked before: for every C function in port/tree/
# that calls into Rust, what is in it besides the call?
#
# It exists because on 2026-09-04 seven closures answered that question by
# assuming. Two stopped the kernel booting. No ABI check could see any of them,
# because the signature was byte-identical every time.
#
# VERDICTS
#   PASS-THROUGH   one statement, nothing but the call. Closeable as far as
#                  THIS check can see -- it does not know about __weak, __pure,
#                  an exported data symbol the entry passes down, or anything
#                  else outside the body. Read the file.
#   REVIEW         more than one statement, no guard keyword matched. Read it.
#   DO NOT CLOSE   a guard, a dispatch, an allocation, or preprocessor
#                  conditionals in the body.
#
# The keyword list is deliberately broad. A false DO NOT CLOSE costs a minute
# of reading; a false PASS-THROUGH cost a kernel that would not boot.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
exec python3 "$root/rig/thunk-screen.py" "$root/port/tree"
