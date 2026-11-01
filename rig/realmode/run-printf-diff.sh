#!/usr/bin/env bash
# run-printf-diff.sh [cases]  -- differential test of port/tree/arch/x86/boot/printf_rs.rs against the
# original arch/x86/boot/printf.c: both are built for the HOST (x86_64) and fed the same random
# format strings/arguments; buffers (0x5a-filled, whole 8 KiB compared), return values and %n results must
# match. Host differences that are NOT the port's (documented, excluded by the generator): `long` is
# 64-bit here (so %l with negative/large values are given sign/zero-extended slots) and "%p" with no
# width (default width 2*sizeof(void*) = 16 here, 8 on the target).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT
cp "$root/src/linux/arch/x86/boot/printf.c" "$T/printf_c.c"
clang -O1 -w -I"$here/inc" -Dsprintf=c_sprintf -Dvsprintf=c_vsprintf -Dprintf=c_printf -c "$T/printf_c.c" -o "$T/c_printf.o"
cp "$root/port/tree/arch/x86/boot/"{printf_rs.rs,rm_common.rs} "$T/"
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib -C opt-level=2 -C panic=abort \
    --crate-name=printf_rs -o "$T/libprintf_rs.a" "$T/printf_rs.rs"
clang -O1 -w "$here/printf-diff.c" -o "$T/h" "$T/c_printf.o" "$T/libprintf_rs.a" -lpthread -ldl -lm
"$T/h" "${1:-300000}"
