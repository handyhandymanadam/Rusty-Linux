#!/usr/bin/env bash
# port/test/oid_registry/run.sh -- the userspace differential for
# lib/oid_registry.c.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree. oid_table.h (the real per-OID byte
# encodings) is generated from build-full/lib/oid_registry_data.c, the
# same build artifact both the pristine C and the Rust tables are sourced
# from -- see oid_registry_rs.rs's module doc.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/oid_registry"
out="${TMPDIR:-/tmp}/oid_registry-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/oid_registry.c"
RS="$root/port/tree/lib/oid_registry_rs.rs"
GENDATA="$root/build-full/lib/oid_registry_data.c"
for f in "$C" "$RS" "$GENDATA"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

{
    echo '#![allow(non_snake_case)]'
    echo '#[allow(unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
    echo '}'
    sed 's|^//!|//|' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name oid_registry_rs -o "$out/librs.a" "$out/probe.rs"

# oid_registry.c does `#include "oid_registry_data.c"` (quoted, so it
# resolves relative to the SOURCE FILE'S OWN directory first) -- neither
# port/pristine/ nor this test dir ships that generated file, so -I
# build-full/lib supplies it via the fallback path search.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim" -I "$root/build-full/lib")
REN=(-Dlook_up_OID=c_look_up_OID -Dparse_OID=c_parse_OID -Dsprint_oid=c_sprint_oid)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if OID_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
