#!/usr/bin/env bash
# %pK's restricted_pointer_decision() -- pure-function matrix test, no
# kernel/IRQ/credential state needed. See main_pk_decision.c's own comment
# for why the oracle here is a hand-transcribed table, not a second C
# implementation to diff against.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/vsprintf-pk-decision-difftest.$$"

RUSTC=/home/adam/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib"
INC=(-I "$here/shim" -I "$here" -I "$P")
CFLAGS=(-std=gnu11 -g -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wno-unused-variable -DCONFIG_KALLSYMS -DCONFIG_64BIT -DCONFIG_BINARY_PRINTF -DCONFIG_BLOCK)

echo "sources:"
for f in "$root/port/tree/lib/vsprintf_rs.rs"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done

# vsprintf_rs.rs is one crate/one object -- calling ANY exported symbol from
# it pulls the whole object in, so the linker still needs every other
# extern it references resolved too (no_hash_pointers, kptr_restrict,
# vsprintf_c_in_irq_context, the deferred %p handlers, ...), even though
# this test only calls vsprintf_rs_restricted_pointer_decision. Same
# stubs.c/stubs_deferred.c Island A links, for exactly that reason.
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ctype.o" "$P/ctype.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/stubs.o" "$here/stubs.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/stubs_deferred.o" "$here/stubs_deferred.c"

"$RUSTC" --edition 2021 --crate-type rlib -O -Cpanic=abort \
    --crate-name kernel -o "$out/libkernel.rlib" "$here/kernel_stub.rs"

"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --extern kernel="$out/libkernel.rlib" \
    --cfg CONFIG_BINARY_PRINTF \
    --crate-name vsprintf_rs -o "$out/libvsprintf_rs.a" "$root/port/tree/lib/vsprintf_rs.rs"

echo "RS arm compiled clean."

cc "${CFLAGS[@]}" -I "$here/shim" -c -o "$out/main_pk_decision.o" "$here/main_pk_decision.c"

cc -o "$out/difftest" "$out/main_pk_decision.o" "$out/ctype.o" "$out/stubs.o" "$out/stubs_deferred.o" \
   "$out/libvsprintf_rs.a" -lpthread -ldl

cd "$root"
"$out/difftest"
