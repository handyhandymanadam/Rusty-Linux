#!/usr/bin/env bash
# port/test/kstrtox/run.sh -- the userspace differential for lib/kstrtox.
#
# WHY IT EXISTS. lib/kstrtox.c is 22 exported symbols (test-kstrtox.c, the
# in-kernel module test, only exercises the type-specific ones and prints no
# pass count on success -- WARN() only fires on failure, which is a weak
# proof caller next to a real oracle). This is also the project's first
# __user boundary; see kstrtox_rs.rs's module doc comment for why calling
# _copy_from_user() directly is faithful and not a shortcut.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/kstrtox"
out="${TMPDIR:-/tmp}/kstrtox-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/kstrtox.c"
H="$root/port/pristine/lib/kstrtox.h"
RS="$root/port/tree/lib/kstrtox_rs.rs"
for f in "$C" "$H" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

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
    --crate-name kstrtox_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim" -I "$root/port/pristine/lib")
# Every symbol lib/kstrtox.c DEFINES is renamed c_<name>, so both arms can be
# linked into one binary. Internal-linkage helpers included.
REN=(
    -Dkstrtoull=c_kstrtoull -Dkstrtoll=c_kstrtoll
    -D_kstrtoul=c__kstrtoul -D_kstrtol=c__kstrtol
    -Dkstrtouint=c_kstrtouint -Dkstrtoint=c_kstrtoint
    -Dkstrtou16=c_kstrtou16 -Dkstrtos16=c_kstrtos16
    -Dkstrtou8=c_kstrtou8 -Dkstrtos8=c_kstrtos8
    -Dkstrtobool=c_kstrtobool -Dkstrtobool_from_user=c_kstrtobool_from_user
    -Dkstrtoull_from_user=c_kstrtoull_from_user
    -Dkstrtoll_from_user=c_kstrtoll_from_user
    -Dkstrtoul_from_user=c_kstrtoul_from_user
    -Dkstrtol_from_user=c_kstrtol_from_user
    -Dkstrtouint_from_user=c_kstrtouint_from_user
    -Dkstrtoint_from_user=c_kstrtoint_from_user
    -Dkstrtou16_from_user=c_kstrtou16_from_user
    -Dkstrtos16_from_user=c_kstrtos16_from_user
    -Dkstrtou8_from_user=c_kstrtou8_from_user
    -Dkstrtos8_from_user=c_kstrtos8_from_user
    -D_parse_integer_fixup_radix=c__parse_integer_fixup_radix
    -D_parse_integer_limit=c__parse_integer_limit
    -D_parse_integer=c__parse_integer
)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if KSTRTOX_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
