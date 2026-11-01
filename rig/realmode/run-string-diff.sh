#!/usr/bin/env bash
# run-string-diff.sh [extra] -- differential of port/tree/arch/x86/boot/string_rs.rs against the ORIGINAL arch/x86/boot/string.c, both built for the HOST
# (x86_64). The target's 32-bit types are kept: the C copy has `unsigned long` -> u32 and `long` -> s32 (asserted rewrites: _kstrtoul, boot_kstrtoul (incl. its sizeof test: false for 4 vs 8 bytes, as on the target), the
# cast in _kstrtoul, simple_strtol), the Rust file has them by construction (ULong/Long); size_t / pointers are 64-bit on the host (so lengths above 2^32 are
# not tested). Symbols are prefixed (c_ / rs_) with objcopy and linked with string-diff.c + libc. The asm primitives (repe cmpsb, divl) run on the host
# as written in the C (x86-64 regs) / as their definitions in the Rust (host_mock). Env: SABOTAGE=<sed expr> on a copy of the Rust (tree untouched), RS_SRC=<file>.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT
python3 - "$root/src/linux/arch/x86/boot/string.c" "$T/string_c.c" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
n0=len(re.findall(r'unsigned long(?! long)',s)); n1=len(re.findall(r'(?<![a-z ])long simple_strtol',s))
assert n0==7 and n1==1, (n0,n1)      # boot_kstrtoul/_kstrtoul decl + (unsigned long)tmp ; simple_strtol
s=re.sub(r'unsigned long(?! long)','u32',s); s=re.sub(r'(?<![a-z ])long simple_strtol','s32 simple_strtol',s)
open(sys.argv[2],'w').write(s)
PY
cp "$root/src/linux/arch/x86/boot/ctype.h" "$T/"
python3 - "$root/src/linux/arch/x86/boot/string.h" "$T/string.h" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
n0=len(re.findall(r'unsigned long(?! long)',s)); n1=len(re.findall(r'(?<![a-z ])long simple_strtol',s))
assert n0==1 and n1==1, (n0,n1)      # boot_kstrtoul prototype ; simple_strtol prototype
s=re.sub(r'unsigned long(?! long)','u32',s); s=re.sub(r'(?<![a-z ])long simple_strtol','s32 simple_strtol',s)
open(sys.argv[2],'w').write(s)
PY
CCOV=""; [ -n "${COVER:-}" ] && CCOV="-fprofile-instr-generate -fcoverage-mapping"   # COVER=1: line/branch coverage of the C original under the harness
clang -O2 -w -fwrapv -ffreestanding -fno-builtin $CCOV -I"$here/inc-string" -c "$T/string_c.c" -o "$T/c0.o"
objcopy --prefix-symbols=c_ "$T/c0.o" "$T/c.o"
RS_SRC=${RS_SRC:-$root/port/tree/arch/x86/boot/string_rs.rs}   # RS_SRC: a snapshot of the Rust file (the sabotage batch runs from one while the tree is edited)
cp "$RS_SRC" "$T/string_rs.rs"
if [ -n "${SABOTAGE:-}" ]; then
  sed -i "$SABOTAGE" "$T/string_rs.rs"
  cmp -s "$T/string_rs.rs" "$RS_SRC" && { echo "SABOTAGE changed nothing"; exit 3; }
  echo "SABOTAGE applied: $SABOTAGE"
fi
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=lib -Zcrate-attr=no_std -C opt-level=2 -C panic=abort -C debug-assertions=off -C overflow-checks=off \
   --cfg host_mock --crate-name=string_rs --emit=obj -o "$T/rs0.o" "$T/string_rs.rs" 2>&1 | grep -E "^error" -A8 || true
[ -s "$T/rs0.o" ] || { echo "Rust build failed"; exit 4; }
und=$(nm "$T/rs0.o" | grep ' U ' || true); [ -z "$und" ] || { echo "Rust object has undefined symbols: $und"; exit 5; }
objcopy --prefix-symbols=rs_ "$T/rs0.o" "$T/rs.o"
clang -O1 -w $CCOV "$here/string-diff.c" "$T/c.o" "$T/rs.o" -o "$T/h"
export LLVM_PROFILE_FILE="$T/p.profraw"
rc=0; "$T/h" || rc=$?
if [ -n "${COVER:-}" ]; then
  llvm-profdata merge -o "$T/p.profdata" "$T/p.profraw" && llvm-cov report "$T/h" -instr-profile="$T/p.profdata" "$T/string_c.c" 2>/dev/null
  echo "--- uncovered C lines/branches (if any):"
  llvm-cov show "$T/h" -instr-profile="$T/p.profdata" "$T/string_c.c" -show-branches=count 2>/dev/null | grep -E "^ +[0-9]+\| +0\||Branch \([0-9:]+\): \[True: 0|False: 0\]" | head -30 || true
fi
[ $rc = 0 ] && echo "STRING-DIFF OK" || echo "STRING-DIFF MISMATCHES"
exit $rc
