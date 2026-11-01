#!/usr/bin/env bash
# port/test/cmac/run.sh -- differential for the logic of crypto/cmac.c (subkey derivation, final-block xor).
#   run.sh             4 shards: subkeys (bs 8,16 and 4,12,32) and finup (every len 0..bs)
#   run.sh --sabotage  mutants of the Rust must each be caught (equivalent / out-of-contract ones are listed and must NOT be)
# C arm = statements sliced out of port/pristine/crypto/cmac.c (extract.py fails if they change); Rust arm =
# port/tree/crypto/cmac_rs.rs; oracle = NIST SP 800-38B written in main.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/cmac"
out="${TMPDIR:-/tmp}/cmac-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/cmac.c"
RS="${CMAC_RS:-$root/port/tree/crypto/cmac_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$out/extract.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name cmac_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if CMAC_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
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
    mut poly-128          '& 0x87;' '& 0x86;'
    mut poly-64           'dbl64(v, 0x1B)' 'dbl64(v, 0x1A)'
    mut hi-lo-carry       'hi = (hi << 1) | (lo >> 63);' 'hi = hi << 1;'
    mut msb-from-lo       'let msb_mask = (((hi as i64) >> 63) as u8) & 0x87;' 'let msb_mask = (((lo as i64) >> 63) as u8) & 0x87;'
    mut k2-not-doubled    'while i < 2 {
                    let msb_mask' 'while i < 1 {
                    let msb_mask'
    mut k2-offset-128     'consts.add(16 * i)' 'consts.add(8 * i)'
    mut k2-offset-64      'consts.add(8 * i) as *mut u64' 'consts.add(4 * i) as *mut u64'
    mut endian-128-read   'let mut hi = u64::from_be(' 'let mut hi = u64::from_le('
    mut endian-64-write   'write_unaligned(v.to_be())' 'write_unaligned(v.to_le())'
    mut bs8-poly-in-128   'let msb_mask = (((hi as i64) >> 63) as u8) & 0x87;' 'let msb_mask = (((hi as i64) >> 63) as u8) & 0x1B;'
    mut dbl64-no-mask     'let msb_mask = (((v as i64) >> 63) as u8) & poly;' 'let msb_mask = 0u8 & poly;'
    mut other-bs-writes   '_ => {}' '_ => { (consts as *mut u64).write_unaligned(0) }'
    mut pad-const         '*prev.add(len) ^= 0x80;' '*prev.add(len) ^= 0x81;'
    mut pad-at-wrong-idx  '*prev.add(len) ^= 0x80;' '*prev.add(len.saturating_sub(1)) ^= 0x80;'
    mut k1-for-short      'offset += bs;' 'offset += 0;'
    mut k2-for-full       'if len != bs {' 'if len == bs && false {'
    mut src-xor-short     'while i < len {
            *prev.add(i) ^= *src.add(i);' 'while i + 1 < len {
            *prev.add(i) ^= *src.add(i);'
    mut key-xor-short     'while i < bs {
            *prev.add(i) ^= *consts.add(offset + i);' 'while i + 1 < bs {
            *prev.add(i) ^= *consts.add(offset + i);'
    mut key-xor-skipped   '*prev.add(i) ^= *consts.add(offset + i);' '*prev.add(i) ^= *consts.add(offset + i) & 0;'
    mut src-overread      'while i < len {
            *prev.add(i) ^= *src.add(i);' 'while i < len + 1 {
            *prev.add(i) ^= *src.add(i);'
    mut prev-overwrite    'while i < bs {
            *prev.add(i) ^= *consts.add(offset + i);' 'while i < bs + 1 {
            *prev.add(i) ^= *consts.add(offset + i);'
    # the clamp of len: invisible to in-contract comparisons, but the harness also calls len > bs against exact-size buffers
    mut clamp-removed     'let len = core::cmp::min(len as usize, bs);' 'let len = len as usize;'
    echo "$caught of $n mutants caught (the clamp one by SIGSEGV on the guard page); $eqok of $eq equivalent mutants unseen"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
