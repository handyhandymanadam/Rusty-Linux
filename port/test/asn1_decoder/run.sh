#!/usr/bin/env bash
# port/test/asn1_decoder/run.sh -- the userspace differential for
# lib/asn1_decoder.c.
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. The C is
# port/pristine/, not the tree. See drv.c's header comment for the harness
# shape (two real, production ASN.1 grammars, action-call-log comparison,
# seed + mutation + random fuzzing).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/asn1_decoder"
out="${TMPDIR:-/tmp}/asn1-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/asn1_decoder.c"
RS="$root/port/tree/lib/asn1_decoder_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

{
    echo '#![allow(non_snake_case, non_upper_case_globals)]'
    echo '#[allow(unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
    echo '}'
    # The source's own `#![allow(non_upper_case_globals)]` is a crate-root
    # inner attribute; it has to be first in the FILE, but the `mod kernel`
    # block above is already ahead of it once concatenated. The wrapper's
    # own `#![allow(...)]` line already covers the same lint, so drop the
    # source's copy here rather than fight over first-item position.
    sed 's|^//!|//|; /^#!\[allow(non_upper_case_globals)\]$/d' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name asn1_decoder_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=( -Dasn1_ber_decoder=cref_asn1_ber_decoder )

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
cc "${CF[@]}" "${RENAME[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if ASN1_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
