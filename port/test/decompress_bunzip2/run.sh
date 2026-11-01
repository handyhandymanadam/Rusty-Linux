#!/usr/bin/env bash
# port/test/decompress_bunzip2/run.sh -- the userspace differential for
# lib/decompress_bunzip2.c.
#
# Ground truth is plaintext this script generates, never derived from either
# decompressor -- compressed by the SYSTEM bzip2, then decompressed by both
# the pristine C (port/pristine/) and the Rust port (port/tree/), each
# checked against that plaintext directly. See drv.c's header for why.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_bunzip2"
out="${TMPDIR:-/tmp}/decompress_bunzip2-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_bunzip2.c"
RS="$root/port/tree/lib/decompress_bunzip2_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

command -v bzip2 >/dev/null || { echo "bzip2(1) not found"; exit 2; }

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_bunzip2_rs -o "$out/librs.a" "$RS"

# STATIC empty (not "static"): #ifdef STATIC only checks definedness, so the
# PREBOOT arm and mm.h's bump allocator still activate, but `STATIC int INIT
# bunzip2(...)` expands to a plain external `int bunzip2(...)` instead of a
# TU-local static -- matching the symbol the Rust side and the kernel's
# lib/decompress.c dispatch table both call by that name.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$root/src/linux/include" -DSTATIC= \
    -include "$here/shim/decompress_globals.h")
cc "${CF[@]}" -Dbunzip2=cref_bunzip2 -c -o "$out/c.o" "$C"
cc -O2 -g -Wall -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# --- corpus: plaintext this script owns, never touched by either decompressor ---
gen="$out/gen"; mkdir -p "$gen"
python3 - "$gen" <<'PYEOF'
import os, random, sys
d = sys.argv[1]
random.seed(20260905)

def write(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

write("empty.txt", b"")
write("one_byte.txt", b"x")
write("ascii_repeat.txt", (b"the quick brown fox jumps over the lazy dog\n") * 5000)
write("all_same.txt", b"A" * 200000)
write("random.bin", bytes(random.randrange(256) for _ in range(150000)))
# Text with the full byte range represented sparsely, to exercise the
# symbol-map (symToByte) path with genuine gaps.
sparse = bytes((i * 37) % 256 for i in range(300000))
write("sparse_bytes.bin", sparse)
# A source file already in the tree, for something with real structure.
try:
    with open("/home/adam/Rusty-Linux-wt-decompress/port/pristine/lib/decompress_bunzip2.c", "rb") as f:
        write("c_source.c", f.read() * 3)
except OSError:
    pass
PYEOF

pairs=()
poison_pairs=()
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for level in 1 5 9; do
        comp="$out/${base}.bz2.${level}"
        bzip2 -"$level" -k -c "$plain" > "$comp"
        pairs+=("$comp" "$plain")
        # empty.txt decompresses to zero bytes -- there is nothing for the
        # poison byte-flip to corrupt, so it can never show a mismatch and
        # doesn't belong in the "poison must always be detected" set.
        [ -s "$plain" ] && poison_pairs+=("$comp" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# drv.c's poison mode reports every case with the SAME "FAIL"/"ok" logic as
# a real run -- a poisoned case should print FAIL, so exit 0 here (nothing
# failed) means the poison had no effect anywhere, which is the harness
# being unable to disagree, not a pass. A nonzero exit alone only proves AT
# LEAST ONE case disagreed, not that every poisonable case did -- checked by
# reading the "N/M cases passed" line back rather than claiming "all M" on
# exit code alone (found by adversarial review of decompress_unlz4's copy of
# this same check).
n_poison=$((${#poison_pairs[@]} / 2))
poison_out=$(DBZ2_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
if [ "$poison_rc" -eq 0 ]; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
if ! grep -qxF "0/$n_poison cases passed" <<<"$poison_out"; then
    echo "*** THE HARNESS CANNOT DISAGREE ON EVERY CASE -- expected \"0/$n_poison cases passed\":"
    echo "$poison_out"
    exit 1
fi
echo "prove-can-fail: poisoned output is detected on all $n_poison poisonable cases"

"$out/t" "${pairs[@]}"

# Regression coverage for the class of defect D1/D2 in the adversarial
# review of this port's first version: bit flips in a valid stream drove an
# accumulator out of range, a clean error in C and a checked-arithmetic
# panic in Rust. See drv.c's run_fuzz() for what this actually does.
"$out/t" --fuzz 300 "$out/ascii_repeat.txt.bz2.1" "$(stat -c%s "$gen/ascii_repeat.txt")"
