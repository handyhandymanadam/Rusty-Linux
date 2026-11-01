#!/usr/bin/env bash
# run-earlyserial-diff.sh [scenarios] [seed] -- lockstep differential of port/tree/arch/x86/boot/early_serial_console_rs.rs against the ORIGINAL
# arch/x86/boot/early_serial_console.c, both built for the HOST against one environment model (earlyserial-diff.c: model UART with DLAB / any
# divisor incl. 0, mocked cmdline_find_option, the REAL string.c for strncmp/simple_strtoull). Compared: every port access in order with the
# values read, the cmdline/strtoull call sequence, final early_serial_base, final UART state, and the #DE trap. Plus a directed table with
# hand-derived expected results. Changes to the C copy: names prefixed (c_console_init, c_early_serial_base); string.c has `unsigned long` -> u32
# as in run-string-diff.sh. Env: SABOTAGE=<sed expr> on a copy of the Rust (tree untouched); COVER=1 prints coverage of the C and Rust.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT
python3 - "$root/src/linux/arch/x86/boot/string.c" "$T/string_c.c" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
n0=len(re.findall(r'unsigned long(?! long)',s)); n1=len(re.findall(r'(?<![a-z ])long simple_strtol',s))
assert n0==7 and n1==1, (n0,n1)
s=re.sub(r'unsigned long(?! long)','u32',s); s=re.sub(r'(?<![a-z ])long simple_strtol','s32 simple_strtol',s)
open(sys.argv[2],'w').write(s)
PY
cp "$root/src/linux/arch/x86/boot/ctype.h" "$T/"
python3 - "$root/src/linux/arch/x86/boot/string.h" "$T/string.h" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
s=re.sub(r'unsigned long(?! long)','u32',s); s=re.sub(r'(?<![a-z ])long simple_strtol','s32 simple_strtol',s)
open(sys.argv[2],'w').write(s)
PY
clang -O2 -w -fwrapv -ffreestanding -fno-builtin -I"$here/inc-string" -c "$T/string_c.c" -o "$T/s0.o"
objcopy --prefix-symbols=sc_ "$T/s0.o" "$T/s.o"
CCOV=""; [ -n "${COVER:-}" ] && CCOV="-fprofile-instr-generate -fcoverage-mapping"
cp "$root/src/linux/arch/x86/boot/early_serial_console.c" "$T/esc_c.c"
clang -O2 -w -fwrapv -ffreestanding -fno-builtin $CCOV -I"$here/inc-earlyserial" -Dconsole_init=c_console_init -Dearly_serial_base=c_early_serial_base \
   -c "$T/esc_c.c" -o "$T/c.o"
RS=${RS_SRC:-$root/port/tree/arch/x86/boot/early_serial_console_rs.rs}
cp "$RS" "$T/early_serial_console_rs.rs"; cp "$root/port/tree/arch/x86/boot/rm_common.rs" "$T/"
if [ -n "${SABOTAGE:-}" ]; then
  sed -i ${SABOTAGE_Z:+-z} "$SABOTAGE" "$T/early_serial_console_rs.rs"
  cmp -s "$T/early_serial_console_rs.rs" "$RS" && { echo "SABOTAGE changed nothing"; exit 3; }
  echo "SABOTAGE applied: $SABOTAGE"
fi
RCOV="-C opt-level=2"; [ -n "${COVER:-}" ] && RCOV="-C opt-level=0 -C instrument-coverage"
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib $RCOV -C panic=abort -C debug-assertions=off -C overflow-checks=off \
   --cfg host_mock --crate-name=early_serial_console_rs -o "$T/libesc_rs.a" "$T/early_serial_console_rs.rs" 2>&1 | grep -E "^error" -A8 || true
[ -s "$T/libesc_rs.a" ] || { echo "Rust build failed"; exit 4; }
clang -O2 -w $CCOV "$here/earlyserial-diff.c" "$T/c.o" "$T/s.o" "$T/libesc_rs.a" -o "$T/h" -lpthread -ldl -lm
export LLVM_PROFILE_FILE="$T/p.profraw"
rc=0; "$T/h" "${1:-1000000}" "${2:-1}" || rc=$?
if [ -n "${COVER:-}" ]; then
  llvm-profdata merge -o "$T/p.profdata" "$T/p.profraw"
  llvm-cov report "$T/h" -instr-profile="$T/p.profdata" "$T/esc_c.c" "$T/early_serial_console_rs.rs" 2>/dev/null || true
  echo "--- uncovered C branches (if any):"
  llvm-cov show "$T/h" -instr-profile="$T/p.profdata" "$T/esc_c.c" -show-branches=count 2>/dev/null | grep -B2 -E "Branch \([0-9:]+\): \[True: 0|False: 0\]" | head -30 || true
fi
[ $rc = 0 ] && echo "EARLYSERIAL-DIFF OK" || echo "EARLYSERIAL-DIFF MISMATCHES"
exit $rc
