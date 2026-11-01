#!/usr/bin/env bash
# port/test/iomap/run.sh -- differential test for lib/iomap.c ->
# lib/iomap_rs.rs. See drv.c's header comment for scope: the 26 functions
# that moved to Rust, with every real hardware primitive underneath them
# simulated (shim/linux/io.h) rather than reimplemented or exercised for
# real -- pci_iounmap() stayed in C and is not covered here (see
# lib/iomap.c's own header comment for why).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/iomap-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/iomap.c"
RC="$root/port/tree/lib/iomap.c"
RS="$root/port/tree/lib/iomap_rs.rs"

for f in "$PC" "$RC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# Same stub-module trick as port/test/seq_buf/run.sh -- no config split in
# this file, so a plain `kernel::` stub suffices.
{
    echo '#![allow(non_snake_case, dead_code, unused_variables)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export};'
    echo '}'
    sed 's|^//!|//|' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    --cfg CONFIG_HAS_IOPORT_MAP --cfg CONFIG_64BIT \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name iomap_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=(
    -Dioread8=ioread8_c_ref -Dioread16=ioread16_c_ref -Dioread16be=ioread16be_c_ref
    -Dioread32=ioread32_c_ref -Dioread32be=ioread32be_c_ref
    -D__ioread64_lo_hi=__ioread64_lo_hi_c_ref -D__ioread64_hi_lo=__ioread64_hi_lo_c_ref
    -D__ioread64be_lo_hi=__ioread64be_lo_hi_c_ref -D__ioread64be_hi_lo=__ioread64be_hi_lo_c_ref
    -Diowrite8=iowrite8_c_ref -Diowrite16=iowrite16_c_ref -Diowrite16be=iowrite16be_c_ref
    -Diowrite32=iowrite32_c_ref -Diowrite32be=iowrite32be_c_ref
    -D__iowrite64_lo_hi=__iowrite64_lo_hi_c_ref -D__iowrite64_hi_lo=__iowrite64_hi_lo_c_ref
    -D__iowrite64be_lo_hi=__iowrite64be_lo_hi_c_ref -D__iowrite64be_hi_lo=__iowrite64be_hi_lo_c_ref
    -Dioread8_rep=ioread8_rep_c_ref -Dioread16_rep=ioread16_rep_c_ref -Dioread32_rep=ioread32_rep_c_ref
    -Diowrite8_rep=iowrite8_rep_c_ref -Diowrite16_rep=iowrite16_rep_c_ref -Diowrite32_rep=iowrite32_rep_c_ref
    -Dioport_map=ioport_map_c_ref -Dioport_unmap=ioport_unmap_c_ref
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

# No CONFIG_PCI: pci_iounmap() (the one function that stayed in C) never
# compiles for this harness, and is not differentially tested -- see this
# file's and drv.c's own header comments for why.
cc "${CF[@]}" -DCONFIG_64BIT -DCONFIG_HAS_IOPORT_MAP "${RENAME[@]}" -c -o "$out/pc.o" "$PC"
cc "${CF[@]}" -c -o "$out/rc.o" "$RC"
cc -O2 -g -Wall -I "$here/shim" -c -o "$out/stubs.o" "$here/stubs.c"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/rc.o" "$out/stubs.o" "$out/librs.a"

if IOMAP_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-50000}" "${2:-0xC0FFEE}"
