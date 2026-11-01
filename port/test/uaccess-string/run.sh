#!/usr/bin/env bash
# port/test/uaccess-string/run.sh -- differential test for
# lib/strnlen_user.c / lib/strncpy_from_user.c's word-at-a-time bodies,
# moved to Rust behind a retained C entry. See drv.c's header comment for
# the harness shape (one fault-simulation knob driving both arms' own
# unsafe_get_user(), independent oracle scoped to the unambiguous shape).
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. So is
# the retained C entry (port/tree/lib/{strnlen_user,strncpy_from_user}.c);
# only the ORACLE side is the pristine C, renamed via -D to avoid a link
# clash with the real, unrenamed symbol of the same name.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/uaccess-string-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC_STRNLEN="$root/port/pristine/lib/strnlen_user.c"
PC_STRNCPY="$root/port/pristine/lib/strncpy_from_user.c"
RC_STRNLEN="$root/port/tree/lib/strnlen_user.c"
RC_STRNCPY="$root/port/tree/lib/strncpy_from_user.c"
RS_STRNLEN="$root/port/tree/lib/strnlen_user_rs.rs"
RS_STRNCPY="$root/port/tree/lib/strncpy_from_user_rs.rs"

for f in "$PC_STRNLEN" "$PC_STRNCPY" "$RC_STRNLEN" "$RC_STRNCPY" "$RS_STRNLEN" "$RS_STRNCPY"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

echo "sources:"
for f in "$PC_STRNLEN" "$PC_STRNCPY" "$RC_STRNLEN" "$RC_STRNCPY" "$RS_STRNLEN" "$RS_STRNCPY"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name strnlen_user_rs -o "$out/libstrnlen_rs.a" "$RS_STRNLEN"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name strncpy_from_user_rs -o "$out/libstrncpy_rs.a" "$RS_STRNCPY"

# CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y in both real project configs
# (confirmed by grep, md5-porter 2026-09-05) -- x86-64 always selects it.
# Without this, do_strncpy_from_user's IS_UNALIGNED(src,dst) macro takes the
# OTHER arm (real alignment check instead of compile-time 0), making the
# pristine oracle a DIFFERENT PROGRAM from the one the kernel actually
# builds whenever the harness's randomized src pointer is misaligned -- the
# same class of bug lz4/run.sh's ARCH comment warns about.
CF=(-O2 -g -Wall -Wno-unused-parameter -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=1 -I "$here/shim")

cc "${CF[@]}" -Dstrnlen_user=strnlen_user_c_ref \
   -c -o "$out/pc_strnlen.o" "$PC_STRNLEN"
cc "${CF[@]}" -Dstrncpy_from_user=strncpy_from_user_c_ref \
   -c -o "$out/pc_strncpy.o" "$PC_STRNCPY"
cc "${CF[@]}" -c -o "$out/rc_strnlen.o" "$RC_STRNLEN"
cc "${CF[@]}" -c -o "$out/rc_strncpy.o" "$RC_STRNCPY"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" \
   "$out/pc_strnlen.o" "$out/pc_strncpy.o" \
   "$out/rc_strnlen.o" "$out/rc_strncpy.o" \
   "$out/libstrnlen_rs.a" "$out/libstrncpy_rs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if UACCESS_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-30000}" "${2:-20260905}"
