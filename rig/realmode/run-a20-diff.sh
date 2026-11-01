#!/usr/bin/env bash
# run-a20-diff.sh [scenarios] [never-cases] -- lockstep differential of port/tree/arch/x86/boot/a20_rs.rs against the
# original arch/x86/boot/a20.c, both built for the HOST against a simulated PC (A20 gate, 8042, port 0x92, BIOS 15h).
# The Rust is built with --cfg host_mock (segment accesses via extern hooks); nothing else differs from the target build.
# Sabotage: SABOTAGE=sed-expression applies to a copy of the Rust (the tree is untouched).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT
cp "$root/src/linux/arch/x86/boot/a20.c" "$T/a20_c.c"
clang -O1 -w -I"$here/inc-a20" -Denable_a20=c_enable_a20 -c "$T/a20_c.c" -o "$T/c_a20.o"
cp "$root/port/tree/arch/x86/boot/"{a20_rs.rs,rm_common.rs} "$T/"
[ -n "${SABOTAGE:-}" ] && sed -i "$SABOTAGE" "$T/a20_rs.rs" && ! diff -q "$T/a20_rs.rs" "$root/port/tree/arch/x86/boot/a20_rs.rs" >/dev/null
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib -C opt-level=2 -C panic=abort --cfg host_mock \
    --crate-name=a20_rs -o "$T/liba20_rs.a" "$T/a20_rs.rs"
clang -O2 -w -I"$here/inc-a20" "$here/a20-diff.c" -o "$T/h" "$T/c_a20.o" "$T/liba20_rs.a" -lpthread -ldl -lm
"$T/h" "${1:-2000}" "${2:-2}"
