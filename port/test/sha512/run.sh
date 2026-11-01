#!/usr/bin/env bash
# port/test/sha512/run.sh -- the userspace differential for
# lib/crypto/sha512.c.
#
# SCOPE: the portable algorithm only -- see drv.c's own header comment for
# exactly what this does and does not prove. The real x86 SIMD dispatch is
# not exercised here; CONFIG_CRYPTO_LIB_SHA512_KUNIT_TEST cannot be used to
# check it either -- it needs CONFIG_KUNIT, which findings.md #11 keeps off
# config-full (the only config CONFIG_CRYPTO_LIB_SHA512 builds under) because
# it moves 2,146 unrelated exported-symbol CRCs. lib/libtest.c's test_sha512()
# is this module's boot-time proof caller instead, same reasoning as its
# test_md5().
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/sha512"
out="${TMPDIR:-/tmp}/sha512-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/sha512.c"
RS="$root/port/tree/lib/crypto/sha512_rs.rs"
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
    --crate-name sha512_rs -o "$out/librs.a" "$out/probe.rs"

# NOTE: -I "$here/shim" ONLY -- adding shim/linux too would let angle-bracket
# <string.h> resolve to OUR OWN shim/linux/string.h (same basename as the
# real system header) instead of glibc's, and since it's #pragma once, that
# self-match silently supplies no memcpy/memset declarations at all.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(
    -Dsha384_init=c_sha384_init -Dsha512_init=c_sha512_init
    -D__sha512_update=c___sha512_update
    -Dsha384_final=c_sha384_final -Dsha512_final=c_sha512_final
    -Dsha384=c_sha384 -Dsha512=c_sha512
    -Dhmac_sha384_preparekey=c_hmac_sha384_preparekey
    -Dhmac_sha512_preparekey=c_hmac_sha512_preparekey
    -D__hmac_sha512_init=c___hmac_sha512_init
    -Dhmac_sha384_init_usingrawkey=c_hmac_sha384_init_usingrawkey
    -Dhmac_sha512_init_usingrawkey=c_hmac_sha512_init_usingrawkey
    -Dhmac_sha384_final=c_hmac_sha384_final -Dhmac_sha512_final=c_hmac_sha512_final
    -Dhmac_sha384=c_hmac_sha384 -Dhmac_sha512=c_hmac_sha512
    -Dhmac_sha384_usingrawkey=c_hmac_sha384_usingrawkey
    -Dhmac_sha512_usingrawkey=c_hmac_sha512_usingrawkey
)
# No -DCONFIG_CRYPTO_LIB_SHA512_ARCH: the C arm takes sha512_blocks_generic
# directly, the same generic path the Rust implements. See drv.c.
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if SHA512_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
