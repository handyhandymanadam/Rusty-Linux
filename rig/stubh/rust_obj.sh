#!/usr/bin/env bash
# rust_obj.sh BUILD_DIR FILE_rs.rs OUT.o [extra rustc args, e.g. --cfg=amd_mem_encrypt]
# Builds ONE stub Rust object with the Makefile's preboot_rustflags and the STUB* per-file flags
# (needs BUILD_DIR/arch/x86/boot/compressed/lib{core,compiler_builtins}.rlib from a kernel build).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/kbuild-env.sh"
b=$(cd "$1" && pwd); rs=$2; out=$3; shift 3
envs=(); args=(); for a in "$@"; do if [[ $a =~ ^[A-Z_0-9]+= ]]; then envs+=("$a"); else args+=("$a"); fi; done
c=$b/arch/x86/boot/compressed
export RUSTC_BOOTSTRAP=1
exec env "${envs[@]}" "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
  -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
  --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" \
  -Zdirect-access-external-data=yes "${args[@]}" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
  --crate-name="$(basename "$rs" .rs)" --emit=obj \
  --extern core="$c/libcore.rlib" --extern compiler_builtins="$c/libcompiler_builtins.rlib" -o "$out" "$rs"
