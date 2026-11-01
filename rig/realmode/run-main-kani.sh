#!/usr/bin/env bash
# run-main-kani.sh [variant...] -- Kani on port/tree/arch/x86/boot/main_rs.rs (#[cfg(kani)] mod kmodel/proofs): main() for ALL header bytes, old-style command line words, ds, esp,
# cpu.level, callee results and BIOS output registers: exact effect sequence (every ireg word), the final zero page byte by byte, heap_end = min(heap_end_ptr + 0x200, esp - 1024 mod 2^32).
# SABOTAGE=sed-expr runs the harness on a mutated copy of $MAIN_RS (default: the tree's main_rs.rs); HARNESS=name runs one harness.
# Variants (bit0 = CONFIG_X86_64, bit1 = APM, bit2 = EDD) select main_gen.rs; default: the build's real one (variant 1: X86_64 only).
root=$(cd "$(dirname "$0")/../.." && pwd); . "$root/kbuild-env.sh" >/dev/null 2>&1
SRC=$root/src/linux; B=$root/build-fast
KINC="-I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$B/arch/x86/include/generated/uapi -I$B/include/generated/uapi"
GINC="-I$SRC/arch/x86/include -I$SRC/include $KINC -I$B/arch/x86/include/generated -I$B/include/generated"
for v in "${@:-real}"; do
  D=$(mktemp -d)
  if [ "$v" = real ]; then cp "$B/arch/x86/boot/main_gen.rs" "$D/"; else
    CFG=""; [ $((v&1)) = 1 ] && CFG="$CFG -DCONFIG_X86_64=1"; [ $(((v>>1)&1)) = 1 ] && CFG="$CFG -DCONFIG_APM=1"; [ $(((v>>2)&1)) = 1 ] && CFG="$CFG -DCONFIG_EDD=1"
    clang $GINC $CFG -D__KERNEL__ -E -P -x c "$root/port/tree/arch/x86/boot/main_gen.rs.in" | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(ULL\|UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > "$D/main_gen.rs"
  fi
  echo "== variant $v"; grep -o "RM_MAIN_[A-Z0-9_]*: bool = [a-z]*" "$D/main_gen.rs" | tr '\n' ' '; echo
  KD="$root/rig/realmode/kani-main"
  if [ -n "${SABOTAGE:-}" ]; then   # SABOTAGE=sed-expr: run on a mutated COPY of the Rust (the tree is untouched); HARNESS=name restricts to one harness
    KD=$(mktemp -d); sed 's|^path = .*|path = "main_rs.rs"|' "$root/rig/realmode/kani-main/Cargo.toml" > "$KD/Cargo.toml"
    SRCRS=${MAIN_RS:-$root/port/tree/arch/x86/boot/main_rs.rs}; sed "$SABOTAGE" "$SRCRS" > "$KD/main_rs.rs"; cmp -s "$KD/main_rs.rs" "$SRCRS" && { echo "SABOTAGE did not change the file"; exit 2; }
  fi
  (cd "$KD" && RM_GEN_DIR="$D" cargo kani ${HARNESS:+--harness $HARNESS} 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error|Failed Checks|SUCCESSFUL|FAILED|cover|SATISFIED|UNSATISFIABLE|unwinding")
  rm -rf "$D"; [ -n "${SABOTAGE:-}" ] && rm -rf "$KD"
done
