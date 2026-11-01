#!/usr/bin/env bash
# run-cmdline-diff.sh [scenarios] [seed] -- differential of port/tree/arch/x86/boot/cmdline_rs.rs against the original
# arch/x86/boot/cmdline.c, both built for the HOST against ONE memory model (cmdline-diff.c: 1.06 MiB flat buffer indexed by
# seg*16+offset, so segment and window behaviour are modelled). Compared per scenario for __cmdline_find_option AND
# __cmdline_find_option_bool: return value, the whole output buffer (incl. bytes after the NUL, 0x5a pre-filled + guards), and the
# SEQUENCE of events (set_fs(seg), each fs read offset, in order). Also against an independent word-based reference.
# Changes to the C copy (asserted): `unsigned long cmdline_ptr` -> u32 (the setup is i386: unsigned long is 32 bits; the host's is 64);
# names prefixed c_ by -D. Compiled -fwrapv (kernel: -fno-strict-overflow).
# Env: SABOTAGE=<sed expr> on a copy of the Rust (tree untouched); COVER=1 builds the C with clang source coverage and prints it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT
N=${1:-1000000}; SEED=${2:-1}
python3 - "$root/src/linux/arch/x86/boot/cmdline.c" "$T/cmdline_c.c" <<'PY'
import sys
s=open(sys.argv[1]).read()
assert s.count('unsigned long cmdline_ptr')==2
open(sys.argv[2],'w').write(s.replace('unsigned long cmdline_ptr','u32 cmdline_ptr'))
PY
CCOV=""; [ -n "${COVER:-}" ] && CCOV="-fprofile-instr-generate -fcoverage-mapping"
clang -O2 -w -fwrapv -ffreestanding $CCOV -I"$here/inc-cmdline" -D__cmdline_find_option=c_cmdline_find_option \
   -D__cmdline_find_option_bool=c_cmdline_find_option_bool -c "$T/cmdline_c.c" -o "$T/c.o"
cp "$root/port/tree/arch/x86/boot/cmdline_rs.rs" "$T/cmdline_rs.rs"
if [ -n "${SABOTAGE:-}" ]; then
  sed -i ${SABOTAGE_Z:+-z} "$SABOTAGE" "$T/cmdline_rs.rs"
  cmp -s "$T/cmdline_rs.rs" "$root/port/tree/arch/x86/boot/cmdline_rs.rs" && { echo "SABOTAGE changed nothing"; exit 3; }
  echo "SABOTAGE applied: $SABOTAGE"
fi
RCOV="-C opt-level=2"; [ -n "${COVER:-}" ] && RCOV="-C opt-level=0 -C instrument-coverage"
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib $RCOV -C panic=abort -C debug-assertions=off -C overflow-checks=off \
   --cfg host_mock --crate-name=cmdline_rs -o "$T/libcmdline_rs.a" "$T/cmdline_rs.rs" 2>&1 | grep -E "^error" -A8 || true
clang -O2 -w $CCOV "$here/cmdline-diff.c" "$T/c.o" "$T/libcmdline_rs.a" -o "$T/h" -lpthread -ldl -lm
export LLVM_PROFILE_FILE="$T/p.profraw"
rc=0; "$T/h" "$N" "$SEED" || rc=$?
if [ -n "${COVER:-}" ]; then   # C: lines+branches of cmdline.c; Rust: lines+regions of cmdline_rs.rs (opt-level 0 build; the kani module is not compiled)
  llvm-profdata merge -o "$T/p.profdata" "$T/p.profraw"
  llvm-cov report "$T/h" -instr-profile="$T/p.profdata" "$T/cmdline_c.c" "$T/cmdline_rs.rs" 2>/dev/null || true
  echo "--- uncovered C branches (if any):"
  llvm-cov show "$T/h" -instr-profile="$T/p.profdata" "$T/cmdline_c.c" -show-branches=count 2>/dev/null | grep -B2 -E "Branch \([0-9:]+\): \[True: 0|False: 0\]|Branch.*: \[True: 0," | head -30 || true
fi
[ $rc = 0 ] && echo "CMDLINE-DIFF OK" || echo "CMDLINE-DIFF MISMATCHES"
exit $rc
