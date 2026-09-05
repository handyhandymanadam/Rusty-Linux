#!/usr/bin/env bash
# Differential test for lib/zstd/decompress/huf_decompress.c
# -> port/tree/lib/zstd/decompress/huf_decompress_rs.rs.
#
#   run.sh [runs] [seed]
#   run.sh --selfcheck [runs] [seed]   # ref vs ref: proves the harness only
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zstdhuf-difftest.$$"

self=0
if [ "${1:-}" = "--selfcheck" ]; then self=1; shift; fi

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/zstd"
# The shim is zstd_entropy's -- lib/zstd/decompress pulls in exactly the same
# headers as lib/zstd/common plus zstd_internal.h, which needs no shimming.
INC=(-I "$root/port/test/zstd_entropy/shim" -I "$root/port/test/common/shim"
     -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/include")

echo "sources:"
for f in "$root/port/tree/lib/zstd/decompress/huf_decompress_rs.rs" \
         "$P/decompress/huf_decompress.c"; do
    [ -f "$f" ] && printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)
LINTS=(-D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs
       -W rust_2018_idioms -W unreachable_pub -A stable_features
       -A unused_features -D warnings)

if [ "$self" = 0 ]; then
    # floor.md RAISE 1. These files carry no CONFIG_ fork; the fork that
    # exists is DYNAMIC_BMI2, which portability_macros.h derives from the
    # TARGET, so the sweep is over targets. A target whose core is not
    # installed is reported UNSWEPT and fails, never skipped.
    echo "config sweep: huf_decompress_rs.rs builds for x86_64 (DYNAMIC_BMI2=1)"
    echo "              and aarch64 (DYNAMIC_BMI2=0, the non-dispatch arm)"
    swept_nonx86=0
        # THE THIRD ARM, added 2026-09-04 after adversarial review. DYNAMIC_BMI2 is
    # x86 AND NOT compile-time BMI2 (portability_macros.h:61-71), and with
    # CONFIG_X86_NATIVE_CPU=y the kernel passes -march=native /
    # -Ctarget-cpu=native, which sets __BMI2__. Two targets were not enough:
    # baseline x86 and aarch64 both leave the dispatch shape ON or OFF for the
    # wrong reason, and the arm where the C turns it off ON x86 was never built.
    for t in x86_64-unknown-linux-gnu x86_64-unknown-linux-gnu+bmi2 aarch64-unknown-none; do
        tf=""
        case "$t" in *+bmi2) t=${t%%+bmi2}; tf="-C target-feature=+bmi2";; esac
        if RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -C panic=abort -Z crate-attr=no_std "${LINTS[@]}" \
            $tf --target "$t" --crate-name sweep --emit=metadata \
            -o "$out/sweep-$t$tf.rmeta" \
            "$root/port/tree/lib/zstd/decompress/huf_decompress_rs.rs" \
            2>"$out/sweep.err"
        then
            echo "  ok  $t ${tf:+(bmi2)}"
            case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
        else
            sed -n '1,14p' "$out/sweep.err"; echo "  FAIL $t"; exit 1
        fi
    done
    [ "$swept_nonx86" = 1 ] || { echo "  UNSWEPT: no non-x86 target"; exit 1; }
    echo

    # NOTE ON -A unreachable_pub: probe.rs pulls the port in as a PRIVATE
    # `#[path] mod`, so every pub item in it is unreachable-pub in THIS crate.
    # That is an artefact of how the harness nests the file, not a property of
    # the file; the sweep above compiles it as a crate root, as the kernel
    # does, and is where the lint does real work.
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        "${LINTS[@]}" -A unreachable_pub \
        --crate-name huf_decompress_rs \
        -o "$out/libhuf_decompress_rs.a" "$here/probe.rs"
fi

for f in ref_huf_decompress main; do
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/$f.o" "$here/$f.c"
done
# the entropy arm, which huf_decompress calls into
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_entropy_common.o" \
   "$root/port/test/zstd_entropy/ref_entropy_common.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_fse_decompress.o" \
   "$root/port/test/zstd_entropy/ref_fse_decompress.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_error_private.o" \
   "$root/port/test/zstd_entropy/ref_error_private.c"
cc "${CFLAGS[@]}"             -c -o "$out/corpus.o" "$here/corpus.c"

if [ "$self" = 1 ]; then
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/selfcheck.o" "$here/selfcheck.c"
    cc -o "$out/difftest" "$out"/*.o -lzstd
else
    cc -o "$out/difftest" "$out"/*.o "$out/libhuf_decompress_rs.a" -lzstd
fi

cd "$root"
"$out/difftest" "${1:-20000}" "${2:-20260904}"
