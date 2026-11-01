#!/usr/bin/env bash
# port/test/sha1/run.sh -- the userspace differential for lib/crypto/sha1.c.
#
# SCOPE: the portable algorithm only -- see drv.c's own header comment.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/sha1"
out="${TMPDIR:-/tmp}/sha1-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/sha1.c"
RS="$root/port/tree/lib/crypto/sha1_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

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
    --crate-name sha1_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(
    -Dsha1_init_raw=c_sha1_init_raw -Dsha1_transform=c_sha1_transform
    -Dsha1_init=c_sha1_init -Dsha1_update=c_sha1_update -Dsha1_final=c_sha1_final
    -Dsha1=c_sha1
    -Dhmac_sha1_preparekey=c_hmac_sha1_preparekey -Dhmac_sha1_init=c_hmac_sha1_init
    -Dhmac_sha1_init_usingrawkey=c_hmac_sha1_init_usingrawkey
    -Dhmac_sha1_final=c_hmac_sha1_final -Dhmac_sha1=c_hmac_sha1
    -Dhmac_sha1_usingrawkey=c_hmac_sha1_usingrawkey
)
# No -DCONFIG_CRYPTO_LIB_SHA1_ARCH: the C arm takes sha1_blocks_generic
# directly, the same generic path the Rust implements. See drv.c.
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if SHA1_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
