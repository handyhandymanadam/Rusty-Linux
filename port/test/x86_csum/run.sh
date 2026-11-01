#!/usr/bin/env bash
# port/test/x86_csum/run.sh -- differential for arch/x86/lib/csum-partial_64.c.
#   run.sh             full sweep (4 shards): every length 0..4096 x every alignment 0..63 x 32 seeds/patterns,
#                      flush-against-guard-page placement, 24,000 random long buffers; C == Rust bit-identical, Rust == RFC 1071
#   run.sh --bench     C vs Rust timing in userspace (recorded, never a veto)
#   run.sh --sabotage  prove the harness fails on mutants of the Rust
# C arm = port/pristine/arch/x86/lib/csum-partial_64.c (unmodified) with shim headers; Rust arm = port/tree/arch/x86/lib/csum_partial_rs.rs.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/x86_csum"
out="${TMPDIR:-/tmp}/x86csum.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="${CSUM_PRISTINE:-$root/port/pristine/arch/x86/lib/csum-partial_64.c}"
RS="${CSUM_RS:-$root/port/tree/arch/x86/lib/csum_partial_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the shim's csum_fold must be the kernel's, byte for byte
python3 - "$root/src/linux/arch/x86/include/asm/checksum_64.h" "$here/shim/asm/checksum.h" <<'PY'
import re,sys
def body(p):
    s=open(p).read(); m=re.search(r'static inline __sum16 csum_fold\(__wsum sum\)\n\{.*?\n\}\n',s,re.S); return m.group(0)
a,b=body(sys.argv[1]),body(sys.argv[2])
sys.exit(0) if a==b else (print("SHIM csum_fold DIFFERS FROM THE KERNEL'S"),sys.exit(1))
PY
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name x86_csum_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -I "$here/shim" -Dcsum_partial=c_csum_partial -Dip_compute_csum=c_ip_compute_csum -c -o "$2/c.o" "$C"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" sweep "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if [ "${1:-}" = "--bench" ]; then "$out/real/t" bench; exit; fi
echo "prove-can-fail:"
if CSUM_PROVE_CAN_FAIL=1 "$out/real/t" sweep 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    mutate() {
        n=$((n+1))
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
assert a in s, "pattern missing: " + a
open(sys.argv[2], "w").write(s.replace(a, b, 1))
PY
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" sweep 0 4 >/dev/null 2>&1; then echo "mutant $1: *** NOT CAUGHT"; else echo "mutant $1: caught"; caught=$((caught+1)); fi
    }
    mutate adc-carry-or        '(s, c1 | c2)' '(s, c1 && c2)'
    mutate adc-drop-cin        'let (s, c2) = s.overflowing_add(cf as u64);' 'let (s, c2) = s.overflowing_add((cf as u64) >> 1);'
    mutate chain40-final-adc   'adc(s, 0, c).0
    }
}' 'adc(s, 0, c & false).0
    }
}'
    mutate chain40-word4       'let (s, c) = adc(s, word(m, 4), c);' 'let (s, c) = adc(s, word(m, 3), c);'
    mutate loop-len-step       'len -= 80;' 'len -= 79;'
    mutate loop-stride         'buff = buff.add(80);' 'buff = buff.add(72);'
    mutate second-chain-offset 'buff.add(40));' 'buff.add(32));'
    mutate combine-carry       'temp64 = adc(s, 0, c).0;
        }

        // len == 40' 'temp64 = adc(s, 0, c & false).0;
        }

        // len == 40'
    mutate step-40-len         'len -= 40;
            if len == 0 {' 'len -= 39;
            if len == 0 {'
    mutate step-40-advance     'buff = buff.add(40);
        }

        if len & 32' 'buff = buff.add(32);
        }

        if len & 32'
    mutate bit-32              'if len & 32 != 0 {' 'if len & 64 != 0 {'
    mutate bit-16-chain        'let (s, c) = adc(s, word(buff, 1), c);
            temp64 = adc(s, 0, c).0;
            buff = buff.add(16);' 'let (s, c) = adc(s, word(buff, 0), c);
            temp64 = adc(s, 0, c).0;
            buff = buff.add(16);'
    mutate bit-8-advance       'buff = buff.add(8);' 'buff = buff.add(7);'
    mutate tail-count          'let n = (len & 7) as usize;' 'let n = (len & 3) as usize;'
    mutate tail-shift          '<< (8 * i)' '<< (4 * i)'
    mutate tail-carry          'let (s, c) = temp64.overflowing_add(trail);
            temp64 = adc(s, 0, c).0;' 'temp64 = temp64.wrapping_add(trail);'
    mutate initial-sum         'let mut temp64 = sum as u64;' 'let mut temp64 = (sum as u64) >> 32;'
    mutate finalize-rotate     'temp64.rotate_right(32)' 'temp64.rotate_right(16)'
    mutate finalize-shift      '>> 32) as u32' '>> 31) as u32'
    mutate finalize-wrapping   'temp64.wrapping_add(temp64.rotate_right(32))' 'temp64 ^ temp64.rotate_right(32)'
    mutate fold-shift          '.overflowing_add(sum << 16)' '.overflowing_add(sum << 15)'
    mutate fold-const          'wrapping_add(0xffff)' 'wrapping_add(0xfffe)'
    mutate fold-carry          '.wrapping_add(c as u32)' '.wrapping_add((c as u32) >> 1)'
    mutate fold-invert         '(!s >> 16) as u16' '(s >> 16) as u16'
    mutate word-endian         '.read_unaligned() }' '.read_unaligned().swap_bytes() }'
    mutate ip-init-sum         'csum_partial_impl(buff as *const u8, len, 0)' 'csum_partial_impl(buff as *const u8, len, 1)'
    # EQUIVALENT mutants: they only move work between the 80/40/32/16/8-byte steps. The raw result is
    # order-independent (it is 0 when init and all data are zero, else the unique value in [1, 2^64-1]
    # congruent to the total mod 2^64-1: logs/proofs/x86_csum.py P2/P3), so the sweep must NOT see them;
    # that it does not is the empirical half of the equivalence argument.
    eq=0; eqok=0
    mutate_equiv() {
        eq=$((eq+1))
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
assert a in s, "pattern missing: " + a
open(sys.argv[2], "w").write(s.replace(a, b, 1))
PY
        build "$out/mut.rs" "$out/e$eq" >/dev/null 2>&1 || { echo "equivalent mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/e$eq/t" sweep 0 4 >/dev/null 2>&1; then echo "equivalent mutant $1: not seen by the sweep (as expected)"; eqok=$((eqok+1)); else echo "equivalent mutant $1: SEEN -- not equivalent, the argument is wrong"; fi
    }
    mutate_equiv loop-threshold 'if len < 80 {' 'if len < 81 {'
    mutate_equiv enter-80       'if len >= 80 {' 'if len > 80 {'
    mutate_equiv enter-40       'if len >= 40 {' 'if len > 40 {'
    echo "$caught of $n real mutants caught; $eqok of $eq equivalent mutants (work-splitting thresholds) invisible, as the proof says"; [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "sweep: 4 shards, $(( $(date +%s) - start )) s"
