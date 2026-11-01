#!/usr/bin/env bash
# Island C: real-va_list oracle. pristine vsnprintf() (REF, real varargs)
# vs. THIS PROJECT'S OWN retained-C vsnprintf() (port/tree/lib/vsprintf.c,
# calling into vsprintf_rs.rs's bridge functions), also with real varargs.
# Userspace, no kernel.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/vsprintf-vsnprintf-difftest.$$"

RUSTC=/home/adam/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib"
MINE="$root/port/tree/lib"
INC=(-I "$here/shim" -I "$here" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/vsprintf_rs.rs" "$root/port/tree/lib/vsprintf.c" "$P/vsprintf.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done

# REF arm: pristine vsprintf.c, -Dstatic=, renamed to avoid colliding with
# THIS RUN's second C source (port/tree/lib/vsprintf.c, "mine") which keeps
# vsnprintf/vsscanf/simple_strtoXX unrenamed (real production symbol names,
# exactly what vsprintf_rs.o's own no_hash_pointers/filled_random_ptr_key/
# ptr_key/debug_boot_weak_hash externs must resolve against too).
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
             -Ddebug_boot_weak_hash=ref_debug_boot_weak_hash
             -Dsimple_strntoull=ref_simple_strntoull
             -Dsimple_strtoull=ref_simple_strtoull
             -Dsimple_strtoul=ref_simple_strtoul
             -Dsimple_strntoul=ref_simple_strntoul
             -Dsimple_strtol=ref_simple_strtol
             -Dsimple_strntoll=ref_simple_strntoll
             -Dsimple_strtoll=ref_simple_strtoll
             -Dhash_pointers_finalize=ref_hash_pointers_finalize
             -Dhash_pointers_mode_parse=ref_hash_pointers_mode_parse
             -Dno_hash_pointers_enable=ref_no_hash_pointers_enable
             -Ddebug_boot_weak_hash_enable=ref_debug_boot_weak_hash_enable
             -Dfill_ptr_key=ref_fill_ptr_key
             -Dvsprintf_init_hashval=ref_vsprintf_init_hashval)

CFLAGS=(-std=gnu11 -g -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wno-unused-variable -DCONFIG_KALLSYMS -DCONFIG_64BIT -DCONFIG_BINARY_PRINTF -DCONFIG_BLOCK)

cc "${CFLAGS[@]}" "${INC[@]}" "${REF_RENAMES[@]}" -c -o "$out/ref_vsprintf.o" "$P/vsprintf.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ctype.o" "$P/ctype.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/stubs.o" "$here/stubs.c"

echo "REF arm compiled clean."

# "mine" arm: THIS project's own retained-C vsprintf.c, unrenamed (its own
# real production symbol names -- vsnprintf/vbin_printf/no_hash_pointers/
# filled_random_ptr_key/ptr_key/debug_boot_weak_hash/etc), calling into the
# real vsprintf_rs.o.
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/mine_vsprintf.o" "$MINE/vsprintf.c"

echo "mine arm compiled clean."

"$RUSTC" --edition 2021 --crate-type rlib -O -Cpanic=abort \
    --crate-name kernel -o "$out/libkernel.rlib" "$here/kernel_stub.rs"

"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --extern kernel="$out/libkernel.rlib" \
    --cfg CONFIG_BINARY_PRINTF \
    --crate-name vsprintf_rs -o "$out/libvsprintf_rs.a" "$root/port/tree/lib/vsprintf_rs.rs"

echo "RS arm compiled clean."

cc "${CFLAGS[@]}" -I "$here/shim" -c -o "$out/main_vsnprintf.o" "$here/main_vsnprintf.c"

cc -o "$out/difftest" "$out/main_vsnprintf.o" "$out/ref_vsprintf.o" "$out/mine_vsprintf.o" \
   "$out/ctype.o" "$out/stubs.o" "$out/libvsprintf_rs.a" -lpthread -ldl

cd "$root"
"$out/difftest"
