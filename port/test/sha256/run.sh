#!/usr/bin/env bash
# port/test/sha256/run.sh -- the userspace differential for
# lib/crypto/sha256.c.
#
# SCOPE: the portable algorithm only -- see drv.c's own header comment. The
# real x86 static_call/static_branch dispatch is verified separately by
# booting build-fast with CONFIG_CRYPTO_LIB_SHA256_KUNIT_TEST (upstream's
# own suite, including sha256_finup_2x specifically) -- see this port's
# commit message for the boot results.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/sha256"
out="${TMPDIR:-/tmp}/sha256-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/sha256.c"
RS="$root/port/tree/lib/crypto/sha256_rs.rs"
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
    --crate-name sha256_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(
    -Dsha224_init=c_sha224_init -Dsha256_init=c_sha256_init
    -D__sha256_update=c___sha256_update
    -Dsha224_final=c_sha224_final -Dsha256_final=c_sha256_final
    -Dsha224=c_sha224 -Dsha256=c_sha256
    -Dsha256_finup_2x=c_sha256_finup_2x
    -Dsha256_finup_2x_is_optimized=c_sha256_finup_2x_is_optimized
    -Dhmac_sha224_preparekey=c_hmac_sha224_preparekey
    -Dhmac_sha256_preparekey=c_hmac_sha256_preparekey
    -D__hmac_sha256_init=c___hmac_sha256_init
    -Dhmac_sha224_init_usingrawkey=c_hmac_sha224_init_usingrawkey
    -Dhmac_sha256_init_usingrawkey=c_hmac_sha256_init_usingrawkey
    -Dhmac_sha224_final=c_hmac_sha224_final -Dhmac_sha256_final=c_hmac_sha256_final
    -Dhmac_sha224=c_hmac_sha224 -Dhmac_sha256=c_hmac_sha256
    -Dhmac_sha224_usingrawkey=c_hmac_sha224_usingrawkey
    -Dhmac_sha256_usingrawkey=c_hmac_sha256_usingrawkey
)
# No -DCONFIG_CRYPTO_LIB_SHA256_ARCH: the C arm takes sha256_blocks_generic
# and sha256_finup_2x_arch's #ifndef fallback directly. See drv.c.
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if SHA256_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
