#!/usr/bin/env bash
# rust_obj.sh BUILD_DIR FILE_rs.rs OUT.o [extra rustc args / NAME=value env] -- builds ONE real-mode Rust asm object with
# EXACTLY the flags of arch/x86/boot/Makefile's rm_rustflags (needs BUILD_DIR/arch/x86/boot/librm_{core,compiler_builtins}.rlib).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/kbuild-env.sh"
b=$(cd "$1" && pwd); rs=$2; out=$3; shift 3
envs=(); args=(); for a in "$@"; do if [[ $a =~ ^[A-Z_0-9]+= ]]; then envs+=("$a"); else args+=("$a"); fi; done
c=$b/arch/x86/boot
export RUSTC_BOOTSTRAP=1
exec env "${envs[@]}" "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -C opt-level=s -C panic=immediate-abort \
  -C debug-assertions=off -C overflow-checks=off -Zfunction-sections=y -Zregparm=3 \
  --target="$root/port/tree/arch/x86/boot/realmode_target.json" "${args[@]}" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib \
  --crate-name="$(basename "$rs" .rs)" --emit=obj \
  --extern core="$c/librm_core.rlib" --extern compiler_builtins="$c/librm_compiler_builtins.rlib" -o "$out" "$rs"
