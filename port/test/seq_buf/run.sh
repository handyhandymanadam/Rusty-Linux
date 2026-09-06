#!/usr/bin/env bash
# port/test/seq_buf/run.sh -- differential test for lib/seq_buf.c ->
# lib/seq_buf_rs.rs. See drv.c's header comment for scope (six functions
# with real arithmetic; the three thin pass-throughs plus bprintf are
# proven for real in the kernel instead, by lib/libtest.c's test_seq_buf()).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/seq_buf-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/seq_buf.c"
RC="$root/port/tree/lib/seq_buf.c"
RS="$root/port/tree/lib/seq_buf_rs.rs"

for f in "$PC" "$RC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# Same stub-module trick as port/test/buildid/run.sh -- and the same
# nested-module fix: this file's kabi_rule!/kabi_export! calls are all at
# the crate root here (no config split needed, see the file's own header
# comment), so a plain `kernel::` stub suffices without the crate::
# rewrite buildid's harness needed.
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
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name seq_buf_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=(
    -Dseq_buf_vprintf=seq_buf_vprintf_c_ref
    -Dseq_buf_printf=seq_buf_printf_c_ref
    -Dseq_buf_print_seq=seq_buf_print_seq_c_ref
    -Dseq_buf_do_printk=seq_buf_do_printk_c_ref
    -Dseq_buf_puts=seq_buf_puts_c_ref
    -Dseq_buf_putc=seq_buf_putc_c_ref
    -Dseq_buf_putmem=seq_buf_putmem_c_ref
    -Dseq_buf_putmem_hex=seq_buf_putmem_hex_c_ref
    -Dseq_buf_path=seq_buf_path_c_ref
    -Dseq_buf_to_user=seq_buf_to_user_c_ref
    -Dseq_buf_hex_dump=seq_buf_hex_dump_c_ref
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

# See shim/linux/uaccess.h's own header comment: it #undefs __BIG_ENDIAN,
# which glibc leaks into scope regardless of this host's real endianness.
cc "${CF[@]}" "${RENAME[@]}" -c -o "$out/pc.o" "$PC"
cc "${CF[@]}" -c -o "$out/rc.o" "$RC"
cc -O2 -g -Wall -c -o "$out/stubs.o" "$here/stubs.c"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/rc.o" "$out/stubs.o" "$out/librs.a"

if SEQ_BUF_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-20000}" "${2:-0xC0FFEE}"
