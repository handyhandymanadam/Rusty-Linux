#!/usr/bin/env bash
# port/test/ctr/run.sh -- differential for the logic of crypto/ctr.c (CTR block loops, RFC 3686 counter block).
#   run.sh             4 shards: bsize 4/8/16 x n 1..13*bs-1 x in-place/separate x 8 alignments x counter kinds (zero, all-0xff,
#                      carry out of every byte position, random) x two placements, plus 400k random scenarios
#   run.sh --sabotage  mutants of the Rust must each be caught (equivalent / out-of-contract ones are listed)
# C arm = statements sliced out of port/pristine/crypto/ctr.c and crypto_inc out of src/linux/crypto/algapi.c
# (extract.py fails if they change); Rust arm = port/tree/crypto/ctr_rs.rs; oracle = CTR mode from its definition (main.c).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/ctr"
out="${TMPDIR:-/tmp}/ctr-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/ctr.c"
RS="${CTR_RS:-$root/port/tree/crypto/ctr_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$root/src/linux/crypto/algapi.c" "$out/extract.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name ctr_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if CTR_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
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
    mut final-no-inc        'crypto_inc(ctrblk, bsize);
    }
}' 'let _ = bsize;
    }
}'
    mut final-keystream-off 'enc(tfm, keystream, ctrblk);
        let mut i = 0;' 'enc(tfm, keystream, ctrblk);
        let mut i = 1;'
    mut final-xor-src-only  '*dst.add(i) = *keystream.add(i) ^ *src.add(i);' '*dst.add(i) = *src.add(i);'
    mut final-n-plus-one    'let n = core::cmp::min(nbytes, bsize) as usize;' 'let n = core::cmp::min(nbytes + 1, bsize) as usize;'
    mut final-clamp-removed 'let n = core::cmp::min(nbytes, bsize) as usize;' 'let n = nbytes as usize;'
    mut seg-no-inc          'xor_in_place(dst, src, bsize as usize);
            // increment counter in counterblock
            crypto_inc(ctrblk, bsize);' 'xor_in_place(dst, src, bsize as usize);'
    mut seg-src-stuck       'src = src.add(bsize as usize);' 'src = src.add(0);'
    mut seg-stop-early      'nbytes -= bsize;
            if nbytes < bsize {
                break;
            }
        }
    }
    nbytes
}

/// Whole blocks, `dst == src`' 'nbytes -= bsize;
            if nbytes <= bsize {
                break;
            }
        }
    }
    nbytes
}

/// Whole blocks, `dst == src`'
    mut seg-xor-one-short   'xor_in_place(dst, src, bsize as usize);' 'xor_in_place(dst, src, bsize as usize - 1);'
    mut seg-return-zero     '    }
    nbytes
}

/// Whole blocks, `dst == src`' '    }
    0
}

/// Whole blocks, `dst == src`'
    mut inpl-no-inc         'xor_in_place(dst, keystream, bsize as usize);
            crypto_inc(ctrblk, bsize);' 'xor_in_place(dst, keystream, bsize as usize);'
    mut inpl-xor-ctr        'xor_in_place(dst, keystream, bsize as usize);' 'xor_in_place(dst, ctrblk, bsize as usize);'
    mut inpl-dst-stuck      'crypto_inc(ctrblk, bsize);
            dst = dst.add(bsize as usize);' 'crypto_inc(ctrblk, bsize);
            dst = dst.add(0);'
    mut inpl-return-nbytes-full 'crypto_inc(ctrblk, bsize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize;' 'crypto_inc(ctrblk, bsize);
            dst = dst.add(bsize as usize);
            nbytes -= bsize - 1;'
    mut rfc-nonce-len       'copy_nonoverlapping(nonce, iv, CTR_RFC3686_NONCE_SIZE)' 'copy_nonoverlapping(nonce, iv, CTR_RFC3686_NONCE_SIZE - 1)'
    mut rfc-iv-offset       'iv.add(CTR_RFC3686_NONCE_SIZE), CTR_RFC3686_IV_SIZE)' 'iv.add(CTR_RFC3686_NONCE_SIZE + 1), CTR_RFC3686_IV_SIZE)'
    mut rfc-counter-value   'ctr.add(3).write(1);' 'ctr.add(3).write(0);'
    mut rfc-counter-byte    'ctr.add(3).write(1);' 'ctr.add(2).write(1);'
    mut rfc-counter-overrun 'ctr.add(3).write(1);' 'ctr.add(4).write(1);'
    mut guard-bsize-zero    'if bsize == 0 || nbytes < bsize {
        return nbytes;
    }
    // SAFETY: nbytes >= bsize on entry and the loop continues only while the remainder is >= bsize, so each' 'if bsize == 0 {
        return nbytes;
    }
    // SAFETY: nbytes >= bsize on entry and the loop continues only while the remainder is >= bsize, so each'
    echo "$caught of $n mutants caught; $eqok of $eq equivalent mutants unseen"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
