#!/usr/bin/env bash
# port/test/md5/run.sh -- the userspace differential for lib/crypto/md5.c.
#
# SCOPE: all ten exported symbols (md5_init/update/final/md5,
# hmac_md5_preparekey/init/init_usingrawkey/final/hmac_md5/usingrawkey).
# md5_block_generic() has no arch dispatch on x86-64 to reproduce -- see
# md5_rs.rs's module doc -- so this is a plain two-arm differential, the
# bcd/int_pow shape, not the multi-arm blake2s/memneq one.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree, for the usual reason: reading the oracle out
# of a tree we have edited is a test agreeing with itself.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/md5"
out="${TMPDIR:-/tmp}/md5-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/md5.c"
RS="$root/port/tree/lib/crypto/md5_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

# ---------------------------------------------------------------------------
# THE SHIM MUST MATCH THE KERNEL HEADER, NOT MERELY COMPILE. HMAC_IPAD/OPAD
# are the constants the whole HMAC half of this file depends on.
want=$(sed -n '/^#define HMAC_IPAD_VALUE/,/^#define HMAC_OPAD_VALUE/p' \
       "$root/src/linux/include/crypto/hmac.h" | tr -d ' \t')
have=$(sed -n '/^#define HMAC_IPAD_VALUE/,/^#define HMAC_OPAD_VALUE/p' \
       "$here/shim/crypto/hmac.h" | tr -d ' \t')
if [ "$want" != "$have" ]; then
    echo "SHIM MISMATCH (crypto/hmac.h) -- the oracle would be a different program"
    echo "  kernel: $want"
    echo "  shim:   $have"
    exit 1
fi
echo "shim crypto/hmac.h matches include/crypto/hmac.h"

# ---------------------------------------------------------------------------
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
    --crate-name md5_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmd5_init=c_md5_init -Dmd5_update=c_md5_update -Dmd5_final=c_md5_final -Dmd5=c_md5
     -Dhmac_md5_preparekey=c_hmac_md5_preparekey -Dhmac_md5_init=c_hmac_md5_init
     -Dhmac_md5_init_usingrawkey=c_hmac_md5_init_usingrawkey
     -Dhmac_md5_final=c_hmac_md5_final -Dhmac_md5=c_hmac_md5
     -Dhmac_md5_usingrawkey=c_hmac_md5_usingrawkey)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MD5_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
