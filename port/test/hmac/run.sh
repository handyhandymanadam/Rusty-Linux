#!/usr/bin/env bash
# port/test/hmac/run.sh -- differential for the pad derivation of crypto/hmac.c.
#   run.sh             every bs 1..256 x every keylen 0..bs x 6 key patterns, 4 shards
#   run.sh --sabotage  mutants of the Rust must each be caught (equivalent ones are listed and must NOT be)
# C arm = the pad statements sliced out of port/pristine/crypto/hmac.c (extract.py fails if they change);
# Rust arm = port/tree/crypto/hmac_rs.rs; oracle = RFC 2104 written in main.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/hmac"
out="${TMPDIR:-/tmp}/hmac-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/hmac.c"
RS="${HMAC_RS:-$root/port/tree/crypto/hmac_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the shim constants must be the kernel's
grep -q '#define HMAC_IPAD_VALUE 0x36' "$root/src/linux/include/crypto/hmac.h" && grep -q '#define HMAC_OPAD_VALUE 0x5c' "$root/src/linux/include/crypto/hmac.h" \
    || { echo "SHIM MISMATCH: HMAC_*_VALUE"; exit 1; }
python3 "$here/extract.py" "$C" "$out/extract.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name hmac_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if HMAC_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
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
        if "$out/m$n/t" 0 4 >/dev/null 2>&1 && "$out/m$n/t" 1 4 >/dev/null 2>&1 && "$out/m$n/t" 2 4 >/dev/null 2>&1 && "$out/m$n/t" 3 4 >/dev/null 2>&1; then
            if [ "${4:-}" = equiv ]; then echo "equivalent mutant $1: not seen (as expected)"; eqok=$((eqok+1)); eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: *** NOT CAUGHT"; fi
        else
            if [ "${4:-}" = equiv ]; then echo "equivalent mutant $1: SEEN -- not equivalent"; eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: caught"; caught=$((caught+1)); fi
        fi
    }
    mut ipad-const        'const HMAC_IPAD_VALUE: u8 = 0x36;' 'const HMAC_IPAD_VALUE: u8 = 0x37;'
    mut opad-const        'const HMAC_OPAD_VALUE: u8 = 0x5c;' 'const HMAC_OPAD_VALUE: u8 = 0x5d;'
    mut swap-consts       '*ipad.add(i) ^= HMAC_IPAD_VALUE;
            *opad.add(i) ^= HMAC_OPAD_VALUE;' '*ipad.add(i) ^= HMAC_OPAD_VALUE;
            *opad.add(i) ^= HMAC_IPAD_VALUE;'
    mut ipad-xor-skipped  '*ipad.add(i) ^= HMAC_IPAD_VALUE;' '*ipad.add(i) ^= HMAC_IPAD_VALUE & 0;'
    mut loop-bound-short  'while i < bs {' 'while i + 1 < bs {'
    mut memset-short      'write_bytes(ipad.add(keylen), 0, bs - keylen)' 'write_bytes(ipad.add(keylen), 0, (bs - keylen).saturating_sub(1))'
    mut memset-start      'write_bytes(ipad.add(keylen), 0, bs - keylen)' 'write_bytes(ipad.add(keylen + 1), 0, bs - keylen - 1)'
    mut opad-copy-short   'copy_nonoverlapping(ipad, opad, bs)' 'copy_nonoverlapping(ipad, opad, bs - 1)'
    mut opad-copy-zero    'copy_nonoverlapping(ipad, opad, bs);' 'write_bytes(opad, 0, bs);'
    mut keylen-short      'core::cmp::min(keylen as usize, bs)' 'core::cmp::min(keylen as usize, bs.saturating_sub(1))'
    mut memset-overrun    'write_bytes(ipad.add(keylen), 0, bs - keylen)' 'write_bytes(ipad.add(keylen), 0, bs - keylen + 1)'
    mut opad-copy-overrun 'copy_nonoverlapping(ipad, opad, bs)' 'copy_nonoverlapping(ipad, opad, bs + 1)'
    # EQUIVALENT: the clamp and the negative-bs guard are for out-of-contract inputs only, which the harness never sends
    mut bs-neg-guard      'let bs = if bs < 0 { 0 } else { bs as usize };' 'let bs = bs as usize;' equiv
    mut clamp-modulo      'let keylen = core::cmp::min(keylen as usize, bs);' 'let keylen = keylen as usize % (bs + 1);' equiv
    mut clamp-removed     'let keylen = core::cmp::min(keylen as usize, bs);' 'let keylen = keylen as usize;' equiv
    echo "$caught of $n real mutants caught; $eqok of $eq out-of-contract-guard mutants invisible, as they must be (keylen > bs and bs < 0 are never passed)"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
