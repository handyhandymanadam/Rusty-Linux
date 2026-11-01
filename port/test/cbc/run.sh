#!/usr/bin/env bash
# port/test/cbc/run.sh -- differential for the logic of crypto/cbc.c (the four chaining loops).
#   run.sh             4 shards: bsize 1/2/4/8/16 x n 0..13*bs-1 (cap 300) x encrypt/decrypt x in-place/separate x 8 alignments x
#                      two placements (flush at the end / at the start of a PROT_NONE-guarded page), plus 300k random scenarios
#   run.sh --sabotage  mutants of the Rust must each be caught (equivalent / out-of-contract ones are listed)
# C arm = the four functions sliced out of port/pristine/crypto/cbc.c (extract.py fails if they change); Rust arm =
# port/tree/crypto/cbc_rs.rs; oracle = CBC from its definition over an invertible toy cipher (main.c).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/cbc"
out="${TMPDIR:-/tmp}/cbc-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/cbc.c"
RS="${CBC_RS:-$root/port/tree/crypto/cbc_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$out/extract.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name cbc_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
# run.sh --object <cbc_rs.o>: link the REAL object the kernel build produced (kernel flags, retpoline thunks) instead of
# re-compiling the Rust: the sweep then checks the code that is in vmlinux against the pristine C.
if [ "${1:-}" = "--object" ]; then
    obj=${2:?usage: run.sh --object <build-dir>/crypto/cbc_rs.o}
    mkdir -p "$out/obj"
    cc -O1 -w -I "$here" -c -o "$out/obj/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$out/obj/main.o" "$here/main.c"
    cc -c -o "$out/obj/thunks.o" "$here/thunks.S"
    cc -o "$out/obj/t" "$out/obj/main.o" "$out/obj/c.o" "$obj" "$out/obj/thunks.o"
    echo "object: $obj ($(sha256sum "$obj" | cut -c1-16))"
    if CBC_PROVE_CAN_FAIL=1 "$out/obj/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "prove-can-fail: poisoned result detected"
    runall "$out/obj/t" | sort
    exit 0
fi
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if CBC_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0; eq=0; eqok=0
    mut() {   # mut <name> <from> <to> [equiv]
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys, re
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
nth = 1
m = re.match(r"@(\d)@", a)
if m: nth = int(m.group(1)); a = a[m.end():]
assert s.count(a) >= nth, "pattern missing: " + a
i = -1
for _ in range(nth): i = s.index(a, i + 1)
open(sys.argv[2], "w").write(s[:i] + b + s[i + len(a):])
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
    # encrypt, segment
    mut es-no-xor           'xor_in_place(iv, src, bsize as usize);' 'if bsize == 99 { xor_in_place(iv, src, bsize as usize); }'
    mut es-xor-short        'xor_in_place(iv, src, bsize as usize);' 'xor_in_place(iv, src, bsize as usize - 1);'
    mut es-iv-not-chained   'core::ptr::copy_nonoverlapping(dst, iv, bsize as usize);' 'if bsize == 99 { core::ptr::copy_nonoverlapping(dst, iv, bsize as usize); }'
    mut es-iv-from-src      'core::ptr::copy_nonoverlapping(dst, iv, bsize as usize);' 'core::ptr::copy_nonoverlapping(src, iv, bsize as usize);'
    mut es-src-stuck        '@1@src = src.add(bsize as usize);' 'src = src.add(0);'
    mut es-dst-stuck        '@1@dst = dst.add(bsize as usize);' 'dst = dst.add(0);'
    mut es-stop-early       'while nbytes >= bsize {' 'while nbytes > bsize {'
    mut es-cipher-on-dst    'cipher(tfm, iv, dst, bsize);' 'cipher(tfm, dst, dst, bsize);'
    # encrypt, in place
    mut ei-no-xor           '@1@xor_in_place(src, iv, bsize as usize);' 'if bsize == 99 { xor_in_place(src, iv, bsize as usize); }'
    mut ei-iv-stuck         'cipher(tfm, src, src, bsize);
            iv = src;' 'cipher(tfm, src, src, bsize);
            iv = oiv;'
    mut ei-oiv-not-updated  '@1@core::ptr::copy(iv, oiv, bsize as usize);' 'if bsize == 99 { core::ptr::copy(iv, oiv, bsize as usize); }'
    mut ei-oiv-wrong-block  '@1@core::ptr::copy(iv, oiv, bsize as usize);' 'core::ptr::copy(src, oiv, bsize as usize);'
    mut ei-stop-early       'if nbytes < bsize {
                break;
            }
        }
        core::ptr::copy(iv, oiv, bsize as usize);' 'if nbytes <= bsize {
                break;
            }
        }
        core::ptr::copy(iv, oiv, bsize as usize);'
    mut ei-src-stuck        '@2@src = src.add(bsize as usize);' 'src = src.add(0);'
    # decrypt, segment
    mut ds-no-xor           'xor_in_place(dst, iv, bsize as usize);' 'if bsize == 99 { xor_in_place(dst, iv, bsize as usize); }'
    mut ds-iv-stuck         'xor_in_place(dst, iv, bsize as usize);
            iv = src;' 'xor_in_place(dst, iv, bsize as usize);
            iv = oiv;'
    mut ds-iv-is-dst        'xor_in_place(dst, iv, bsize as usize);
            iv = src;' 'xor_in_place(dst, iv, bsize as usize);
            iv = dst;'
    mut ds-dst-stuck        '@2@dst = dst.add(bsize as usize);' 'dst = dst.add(0);'
    mut ds-src-stuck        '@3@src = src.add(bsize as usize);' 'src = src.add(0);'
    mut ds-oiv-not-updated  '@2@core::ptr::copy(iv, oiv, bsize as usize);' 'if bsize == 99 { core::ptr::copy(iv, oiv, bsize as usize); }'
    mut ds-cipher-skipped   'cipher(tfm, src, dst, bsize);' 'if bsize == 99 { cipher(tfm, src, dst, bsize); }'
    # decrypt, in place
    mut di-start-first      'src = src.add(nbytes.wrapping_sub(nbytes % bsize).wrapping_sub(bsize) as usize);' 'src = src.add(0);'
    mut di-start-one-block-late 'src = src.add(nbytes.wrapping_sub(nbytes % bsize).wrapping_sub(bsize) as usize);' 'src = src.add((nbytes - nbytes % bsize) as usize - bsize as usize / 2);'
    mut di-last-iv-from-iv  'core::ptr::copy_nonoverlapping(src, last_iv.as_mut_ptr(), bsize as usize);' 'core::ptr::copy_nonoverlapping(iv, last_iv.as_mut_ptr(), bsize as usize);'
    mut di-no-chain-xor     'xor_in_place(src, src.sub(bsize as usize), bsize as usize);' 'if bsize == 99 { xor_in_place(src, src.sub(bsize as usize), bsize as usize); }'
    mut di-chain-xor-iv     'xor_in_place(src, src.sub(bsize as usize), bsize as usize);' 'xor_in_place(src, iv, bsize as usize);'
    mut di-final-xor-missing '@2@xor_in_place(src, iv, bsize as usize);' 'if bsize == 99 { xor_in_place(src, iv, bsize as usize); }'
    mut di-iv-not-updated   'core::ptr::copy_nonoverlapping(last_iv.as_ptr(), iv, bsize as usize);' 'if bsize == 99 { core::ptr::copy_nonoverlapping(last_iv.as_ptr(), iv, bsize as usize); }'
    mut di-src-not-stepped  'src = src.sub(bsize as usize);' 'src = src.sub(0);'
    mut di-stop-early       '@3@nbytes -= bsize;
            if nbytes < bsize {' 'nbytes -= bsize;
            if nbytes <= bsize {'
    # guards and returns
    mut guard-bsize-zero    '@1@bsize == 0 || bsize > MAX_CIPHER_BLOCKSIZE' 'bsize > MAX_CIPHER_BLOCKSIZE'
    mut guard-bsize-max     '@1@bsize == 0 || bsize > MAX_CIPHER_BLOCKSIZE' 'bsize == 0'
    mut nbytes-step         '@1@nbytes -= bsize;' 'nbytes -= 1;'
    echo "$caught of $n mutants caught; $eqok of $eq equivalent mutants unseen"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
