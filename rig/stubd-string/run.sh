#!/usr/bin/env bash
# run.sh [builddir]   (default build-fast, must hold a CONFIG_RUST build with string_rs.o)
# Differential test of the stub's string functions: the ORIGINAL C (arch/x86/boot/compressed/string.c
# compiled here with the exact command line kbuild used for misc.o, i.e. the stub's flags) against the
# Rust string_rs.o that is linked into the stub. Both objects' symbols are prefixed (c_ / rs_) and linked
# with rig/stubd-string/difftest.c and libc (libc's memmove is the reference for memcpy/memmove).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
b="$root/${1:-build-fast}"
w=$(mktemp -d "${TMPDIR:-/tmp}/stubd.XXXXXX")
cmd="$b/arch/x86/boot/compressed/.misc.o.cmd"
line=$(head -1 "$cmd" | sed 's/^savedcmd_[^ ]* := //')
line=${line//-DINFLATE_BOOT_RUST/}; line=${line//-DINFLATE_DRIVER_BOOT_RUST/}
line=${line//-c -o arch\/x86\/boot\/compressed\/misc.o *\/misc.c/-c -o $w/string_c.o $root/src/linux/arch/x86/boot/compressed/string.c}
line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.misc.o.d/}
# Self-recursion check (LLVM turns byte loops into calls to memcpy/memset/strlen = itself): the ONLY
# symbols the Rust object may reference are warn() and its own kstrtoull/.rodata; any call or jump
# to a mem*/str* name is a failure. Reads the relocations of the object that is linked into the stub.
rs="$b/arch/x86/boot/compressed/string_rs.o"
refs=$(objdump -dr "$rs" | grep -E 'R_X86_64_' | awk '{print $NF}' | sed 's/-0x[0-9a-f]*$//' | sort -u | tr '\n' ' ')
echo "string_rs.o references: $refs"
bad=$(objdump -dr "$rs" | grep -E 'R_X86_64_' | awk '{print $NF}' | sed 's/-0x[0-9a-f]*$//' | grep -vE '^(warn|kstrtoull|\.rodata.*)$' || true)
[ -z "$bad" ] || { echo "FAIL: unexpected references from string_rs.o: $bad"; exit 1; }
ncall=$(objdump -d "$rs" | grep -cE '\bcall\b' || true)
echo "call instructions in string_rs.o: $ncall (expected 1: warn)"
[ "$ncall" = 1 ] || { echo "FAIL: expected exactly one call (warn)"; exit 1; }
(cd "$b" && eval "$line")
nm "$w/string_c.o" | grep -E ' [TtU] ' | sed 's/^/  C   /' | head -40
objcopy --prefix-symbols=c_ "$w/string_c.o" "$w/c.o"
objcopy --prefix-symbols=rs_ "$b/arch/x86/boot/compressed/string_rs.o" "$w/rs.o"
cc -O1 -g -o "$w/difftest" "$root/rig/stubd-string/difftest.c" "$w/c.o" "$w/rs.o"
"$w/difftest"
rc=$?
echo "difftest rc=$rc (objects in $w)"
exit $rc
