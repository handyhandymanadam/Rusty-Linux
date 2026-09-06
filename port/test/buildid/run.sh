#!/usr/bin/env bash
# port/test/buildid/run.sh -- differential test for lib/buildid.c ->
# lib/buildid_rs.rs. See drv.c's and pristine_wrap.c's header comments for
# the harness shape (memory-backed freader only; get_build_id_32/64 and
# parse_build_id given real names on both sides since the public API only
# reaches them through the file-backed entry points).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/buildid-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/buildid.c"
RC="$root/port/tree/lib/buildid.c"
RS="$root/port/tree/lib/buildid_rs.rs"

for f in "$PC" "$RC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# buildid_rs.rs uses kernel::bindings::{vm_area_struct,file} -- not
# available outside the real kernel build, and not needed here: none of
# the functions this harness exercises (get_build_id_32/64, parse_build_id,
# build_id_parse_buf) take a vma or file. Stub the two build_id_parse/
# build_id_parse_nofault/build_id_parse_file entries out of the compiled
# probe entirely (they are simply never called by this harness) by
# stubbing `kernel::bindings` itself, same shape as dynamic_queue_limits/
# run.sh's kabi_rule!/kabi_export! stub -- and stub those three macros too,
# since this file's kabi_export! calls also reference type pins that need
# no real resolution here.
{
    echo '#![allow(non_snake_case, dead_code, unused_variables)]'
    echo '#[allow(unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    pub mod bindings {'
    echo '        #[repr(C)] pub struct vm_area_struct { pub vm_file: *mut file }'
    echo '        #[repr(C)] pub struct file { _opaque: [u8; 0] }'
    echo '    }'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export};'
    echo '}'
    # crate::kernel::, not kernel::: the config-split kabi_rule! pins
    # (buildid_rs.rs's #[cfg(CONFIG_VMCORE_INFO)]/#[cfg(not(...))] pin
    # modules) invoke it from a NESTED module, where a bare leading
    # `kernel::` only resolves through the extern prelude -- fine in the
    # real kernel build where `kernel` is a real extern crate, not fine
    # here where it is just a sibling `mod kernel` this stub declares at
    # the crate root. `crate::kernel::` resolves from any nesting depth.
    sed 's|^//!|//|; s|\bkernel::kabi_|crate::kernel::kabi_|g' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name buildid_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=(
    -Dbuild_id_parse_nofault=build_id_parse_nofault_c_ref
    -Dbuild_id_parse=build_id_parse_c_ref
    -Dbuild_id_parse_file=build_id_parse_file_c_ref
    -Dbuild_id_parse_buf=build_id_parse_buf_c_ref
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

# pristine_wrap.c does `#include "buildid.c"` -- give it the pristine
# directory to resolve that against, ahead of the shim.
cc "${CF[@]}" -I "$root/port/pristine/lib" "${RENAME[@]}" -c -o "$out/pc.o" "$here/pristine_wrap.c"
cc "${CF[@]}" -c -o "$out/rc.o" "$RC"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/rc.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if BUILDID_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-30000}" "${2:-20260906}"
