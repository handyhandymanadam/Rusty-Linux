#!/usr/bin/env bash
# Differential test for lib/vsprintf.c's pointer()/format_decode()/number()
# family -> lib/vsprintf_rs.rs. Userspace, no kernel.
#
#   run.sh [runs] [seed]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/vsprintf-difftest.$$"

RUSTC=/home/adam/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib"
INC=(-I "$here/shim" -I "$here" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/vsprintf_rs.rs" "$P/vsprintf.c" "$P/ctype.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# REF arm: pristine vsprintf.c, -Dstatic= exposes every internal (format_decode,
# number, string, pointer, ...) as a real external symbol; the handful that
# would otherwise collide with libc or with Rust's own exported symbols are
# individually renamed ref_*. kptr_restrict/no_hash_pointers/
# filled_random_ptr_key/ptr_key/debug_boot_weak_hash (real pristine globals)
# get their own ref_* copies too, so REF and RS never share mutable state by
# accident -- main.c syncs the two copies explicitly before each case.
REF_RENAMES=(-Dstatic=
             -Dvsnprintf=ref_vsnprintf
             -Dvscnprintf=ref_vscnprintf
             -Dsnprintf=ref_snprintf
             -Dscnprintf=ref_scnprintf
             -Dvsprintf=ref_vsprintf
             -Dsprintf=ref_sprintf
             -Dvbin_printf=ref_vbin_printf
             -Dbstr_printf=ref_bstr_printf
             -Dvsscanf=ref_vsscanf
             -Dsscanf=ref_sscanf
             -Dptr_to_hashval=ref_ptr_to_hashval
             -Dnum_to_str=ref_num_to_str
             -Dno_hash_pointers=ref_no_hash_pointers
             -Dkptr_restrict=ref_kptr_restrict
             -Dfilled_random_ptr_key=ref_filled_random_ptr_key
             -Dptr_key=ref_ptr_key
             -Ddebug_boot_weak_hash=ref_debug_boot_weak_hash)

# CONFIG_64BIT/CONFIG_KALLSYMS: real values on this project's only target
# (x86_64) and both its .config's -- checked directly. Without
# CONFIG_64BIT, __ptr_to_hashval()'s own #ifdef takes the 32-bit
# siphash_1u32()-no-masking arm instead, a real fork this harness must NOT
# take (vsprintf_rs.rs's own ptr_to_hashval_impl only ever implements the
# CONFIG_64BIT arm, matching this project's real target -- see its own
# "put_dec's 64-bit-only fork" precedent).
CFLAGS=(-std=gnu11 -g -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wno-unused-variable -DCONFIG_KALLSYMS -DCONFIG_64BIT)

cc "${CFLAGS[@]}" "${INC[@]}" "${REF_RENAMES[@]}" -c -o "$out/ref_vsprintf.o" "$P/vsprintf.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ctype.o" "$P/ctype.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/stubs.o" "$here/stubs.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/stubs_deferred.o" "$here/stubs_deferred.c"

echo "REF arm compiled clean."

# RS arm: vsprintf_rs.rs against a kernel_stub, exporting vsprintf_rs_pointer
# (and, once CONFIG_BINARY_PRINTF is on, bstr_printf) as real C-ABI symbols.
"$RUSTC" --edition 2021 --crate-type rlib -O -Cpanic=abort \
    --crate-name kernel -o "$out/libkernel.rlib" "$here/kernel_stub.rs"

"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --extern kernel="$out/libkernel.rlib" \
    --cfg CONFIG_BINARY_PRINTF \
    --crate-name vsprintf_rs -o "$out/libvsprintf_rs.a" "$root/port/tree/lib/vsprintf_rs.rs"

echo "RS arm compiled clean."

cc "${CFLAGS[@]}" -I "$here/shim" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" "$out/ref_vsprintf.o" "$out/ctype.o" "$out/stubs.o" "$out/stubs_deferred.o" \
   "$out/libvsprintf_rs.a" -lpthread -ldl

cd "$root"
"$out/difftest" "${1:-2000}" "${2:-20260906}"
