#!/usr/bin/env bash
# port/test/ecb/run.sh -- differential for the logic of crypto/ecb.c (the block loop and remainder rule of crypto_ecb_crypt).
#   run.sh             4 shards: bsize 1/2/4/8/16/24/32 x n 0..13*bs-1 x in-place/separate x final/not x 8 alignments x two
#                      placements (flush at the end / at the start of a PROT_NONE-guarded page), plus 300k random scenarios
#   run.sh --sabotage  mutants of the Rust must each be caught (equivalent / out-of-contract ones are listed)
# C arm = crypto_ecb_crypt() sliced out of port/pristine/crypto/ecb.c (extract.py fails if it changes); Rust arm =
# port/tree/crypto/ecb_rs.rs; oracle = ECB from its definition (main.c).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/ecb"
out="${TMPDIR:-/tmp}/ecb-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/ecb.c"
RS="${ECB_RS:-$root/port/tree/crypto/ecb_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$out/extract.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name ecb_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
# run.sh --object <ecb_rs.o>: link the REAL object the kernel build produced (kernel flags, retpoline thunks) instead of
# re-compiling the Rust: the sweep then checks the code that is in vmlinux against the pristine C.
if [ "${1:-}" = "--object" ]; then
    obj=${2:?usage: run.sh --object <build-dir>/crypto/ecb_rs.o}
    mkdir -p "$out/obj"
    cc -O1 -w -I "$here" -c -o "$out/obj/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$out/obj/main.o" "$here/main.c"
    cc -c -o "$out/obj/thunks.o" "$here/thunks.S"
    cc -o "$out/obj/t" "$out/obj/main.o" "$out/obj/c.o" "$obj" "$out/obj/thunks.o"
    echo "object: $obj ($(sha256sum "$obj" | cut -c1-16))"
    if ECB_PROVE_CAN_FAIL=1 "$out/obj/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "prove-can-fail: poisoned result detected"
    runall "$out/obj/t" | sort
    exit 0
fi
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if ECB_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0; eq=0; eqok=0
    mut() {   # mut <name> <from> <to> [equiv]
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
assert a in s, "pattern missing: " + a
open(sys.argv[2], "w").write(s.replace(a, b, 1))
PY
        n=$((n+1)); build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 0 16 >/dev/null 2>&1 && "$out/m$n/t" 1 16 >/dev/null 2>&1 && "$out/m$n/t" 7 16 >/dev/null 2>&1; then
            if [ "${4:-}" = equiv ]; then echo "equivalent mutant $1: not seen (as expected)"; eqok=$((eqok+1)); eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: *** NOT CAUGHT"; fi
        else
            if [ "${4:-}" = equiv ]; then echo "equivalent mutant $1: SEEN -- not equivalent"; eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: caught"; caught=$((caught+1)); fi
        fi
    }
    mut loop-stop-early     'while bsize != 0 && nbytes >= bsize {' 'while bsize != 0 && nbytes > bsize {'
    mut loop-one-more       'while bsize != 0 && nbytes >= bsize {' 'while bsize != 0 && nbytes + 1 >= bsize {'
    mut src-stuck           'src = src.add(bsize as usize);' 'src = src.add(0);'
    mut dst-stuck           'dst = dst.add(bsize as usize);' 'dst = dst.add(0);'
    mut src-step-short      'src = src.add(bsize as usize);' 'src = src.add(bsize as usize - 1);'
    mut dst-step-long       'dst = dst.add(bsize as usize);' 'dst = dst.add(bsize as usize + 1);'
    mut swap-src-dst        'enc(tfm, dst, src);' 'enc(tfm, src as *mut u8, dst as *const u8);'
    mut cipher-skipped      'enc(tfm, dst, src);' 'if false { enc(tfm, dst, src); }'
    mut nbytes-step         'nbytes -= bsize;' 'nbytes -= 1;'
    mut final-ignored       'if nbytes != 0 && final_ {' 'if false && final_ {'
    mut final-always        'if nbytes != 0 && final_ {' 'if nbytes != 0 && (final_ || true) {'
    mut final-no-remainder-test 'if nbytes != 0 && final_ {' 'if final_ {'
    mut einval-value        '-EINVAL
    } else {' '-(EINVAL + 1)
    } else {'
    mut return-zero         'nbytes as c_int
    }' '0
    }'
    echo "$caught of $n mutants caught; $eqok of $eq equivalent mutants unseen"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
