#!/usr/bin/env bash
# Differential test for lib/zstd/common/{entropy_common,fse_decompress}.c
# -> port/tree/lib/zstd/common/entropy_common_rs.rs.
#
#   run.sh [runs] [seed]
#   run.sh --selfcheck [runs] [seed]   # ref vs ref: proves the harness only
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zstdentropy-difftest.$$"

self=0
if [ "${1:-}" = "--selfcheck" ]; then self=1; shift; fi

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/zstd/common"
# Shim order matters: the module's own shim wins, the shared base backs it,
# and src/linux/include supplies <linux/zstd_errors.h>, which is a bare enum
# and needs no shimming. Anything NOT shimmed falls through to a real kernel
# header and fails loudly, which is the intended behaviour.
INC=(-I "$here/shim" -I "$root/port/test/common/shim"
     -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/include")

echo "sources:"
for f in "$root/port/tree/lib/zstd/common/entropy_common_rs.rs" \
         "$root/port/tree/lib/zstd/common/error_private_rs.rs" \
         "$root/port/tree/lib/zstd/common/zstd_common_rs.rs" \
         "$P/entropy_common.c" "$P/fse_decompress.c" "$P/error_private.c" \
         "$P/zstd_common.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

if [ "$self" = 0 ]; then
    # floor.md RAISE 1: every combination of the Kconfig symbols this file
    # reads. It reads none -- lib/zstd/common has no CONFIG_ fork in these two
    # files -- so the sweep is over the two states of the ONE thing that does
    # fork the code: DYNAMIC_BMI2, which portability_macros.h derives from the
    # target rather than from Kconfig. Building for a non-x86 target is how
    # the DYNAMIC_BMI2=0 arm gets compiled at all.
    echo "config sweep: entropy_common_rs.rs builds for x86_64 (DYNAMIC_BMI2=1)"
    echo "              and aarch64 (DYNAMIC_BMI2=0, the non-dispatch arm)"
    # RUSTC_BOOTSTRAP=1 is how -Zcrate-attr reaches a STABLE rustc. That is
    # not a trick this harness invented: Makefile:632 exports it
    # unconditionally for the whole kernel build, so the port is compiled this
    # way in the kernel too and the sweep matches rather than diverges.
    #
    # A target whose `core` is not installed is reported as UNSWEPT and fails
    # the run. Quietly skipping it would leave the sweep passing while one of
    # the two arms had never been compiled -- the shape of failure notes/STATUS.md
    # lesson 9 records twice.
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
            -C panic=abort -Z crate-attr=no_std \
            -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
            $tf --target "$t" --crate-name sweep --emit=metadata \
            -o "$out/sweep-$t$tf.rmeta" \
            "$root/port/tree/lib/zstd/common/entropy_common_rs.rs" 2>"$out/sweep.err" \
        && RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -C panic=abort -Z crate-attr=no_std \
            -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
            --target "$t" --crate-name sweep2 --emit=metadata \
            -o "$out/sweep2-$t.rmeta" \
            "$root/port/tree/lib/zstd/common/error_private_rs.rs" 2>>"$out/sweep.err" \
        && RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -C panic=abort -Z crate-attr=no_std \
            -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
            --target "$t" --crate-name sweep3 --emit=metadata \
            -o "$out/sweep3-$t.rmeta" \
            "$root/port/tree/lib/zstd/common/zstd_common_rs.rs" 2>>"$out/sweep.err"
        then
            echo "  ok  $t ${tf:+(bmi2)}"
            case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
        else
            sed -n '1,12p' "$out/sweep.err"
            echo "  FAIL $t"
            exit 1
        fi
    done
    if [ "$swept_nonx86" = 0 ]; then
        echo "  UNSWEPT: no non-x86 target compiled, so the DYNAMIC_BMI2=0 arm"
        echo "           was never built. rustup target add aarch64-unknown-none"
        exit 1
    fi
    echo

# NOTE ON -A unreachable_pub, and why the staticlib build differs from the
# sweep above. probe.rs pulls the port in as `#[path] mod ..._rs;` -- a PRIVATE
# module -- so every `pub` item in the ported file becomes unreachable-pub in
# THIS crate. That is an artefact of how the harness nests the file, not a
# property of the file: the kernel compiles each .rs as its own crate root,
# where the same items are reachable. The sweep above, which does compile it as
# a crate root, keeps the lint on and is where it does real work.
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings -A unreachable_pub \
        --crate-name entropy_common_rs \
        -o "$out/libentropy_common_rs.a" "$here/probe.rs"
fi

for f in ref_entropy_common ref_fse_decompress ref_error_private \
         ref_zstd_common main; do
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/$f.o" "$here/$f.c"
done
# ZSTD_isError cannot be renamed with -D: zstd_internal.h:38 defines it as a
# macro and zstd_common.c #undef's that before defining the function, so any
# rename in front of the include is gone by the time the definition is
# reached. The rename happens on the object instead. See ref_zstd_common.c.
objcopy --redefine-sym ZSTD_isError=ref_ZSTD_isError "$out/ref_zstd_common.o"
cc "${CFLAGS[@]}"             -c -o "$out/corpus.o"        "$here/corpus.c"

if [ "$self" = 1 ]; then
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/selfcheck.o" "$here/selfcheck.c"
    cc -o "$out/difftest" "$out"/*.o
else
    cc -o "$out/difftest" "$out"/*.o "$out/libentropy_common_rs.a"
fi

cd "$root"
"$out/difftest" "${1:-20000}" "${2:-20260904}"
