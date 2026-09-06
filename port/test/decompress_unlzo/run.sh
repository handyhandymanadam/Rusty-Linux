#!/usr/bin/env bash
# port/test/decompress_unlzo/run.sh -- the userspace differential for
# lib/decompress_unlzo.c. See drv.c's header for the shape (both arms link
# the SYSTEM liblzo2's lzo1x_decompress_safe, isolating the wrapper logic).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_unlzo"
out="${TMPDIR:-/tmp}/decompress_unlzo-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_unlzo.c"
RS="$root/port/tree/lib/decompress_unlzo_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
command -v lzop >/dev/null || { echo "lzop(1) not found"; exit 2; }

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_unlzo_rs -o "$out/librs.a" "$RS"

# shim/ takes priority over the real kernel include path, same reasoning as
# port/test/decompress_unlz4/run.sh. mm.h's shim DOES define STATIC/INIT
# (matching the real header's non-STATIC arm), but only after
# decompress_unlzo.c's own top-of-file #ifdef STATIC has already resolved.
CF=(-O2 -g -Wall -Wno-unused-parameter \
    -I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux/include")
cc "${CF[@]}" -Dunlzo=cref_unlzo -c -o "$out/c.o" "$C"
cc -O2 -g -Wall -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a" -l:liblzo2.so.2
cc -O2 -g -Wall -o "$out/gen_overlap" "$here/gen_overlap_archive.c" -l:liblzo2.so.2

# --- corpus: plaintext this script owns, archived by the REAL lzop CLI ---
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
write("sparse_bytes.bin", bytes((i * 37) % 256 for i in range(300000)))
# Something bigger than LZO_BLOCK_SIZE (256KB), to force multiple blocks
# through the main loop, not just the single-block case every smaller file
# gets.
write("multi_block.bin", bytes((i * 131 + i // 97) % 256 for i in range(900000)))
# NOT compressed by lzop below -- see gen_overlap_archive's own header
# comment for why lzop's fixed 256KB block size can never make
# decompress_unlzo_rs.rs's leftover-data ptr::copy actually overlap (even
# a fully-zero 256KB block's compressed size is well over the ~259-byte
# leftover ceiling that copy could ever be asked to move).
write("overlap_trigger.bin", bytes((i * 17 + i // 13) % 256 for i in range(20000)))
try:
    with open("/home/adam/Rusty-Linux-wt-decompress/port/pristine/lib/decompress_unlzo.c", "rb") as f:
        write("c_source.c", f.read() * 3)
except OSError:
    pass
PYEOF

pairs=()
poison_pairs=()
# Piped through stdin, not passed as a path: lzop embeds the source
# filename in the header otherwise, making the header size (and so
# drv.c's fixed payload offset for the corrupt-case test) depend on each
# file's name length instead of being the same 38 bytes for every archive.
for plain in "$gen"/*; do
    base=$(basename "$plain")
    if [ "$base" = "overlap_trigger.bin" ]; then
        # Real LZO1X compression, real LZOP framing -- just small blocks
        # (200 bytes decompressed each) lzop itself would never choose.
        # See gen_overlap_archive.c.
        arc="$out/${base}.lzo.small-blocks"
        "$out/gen_overlap" "$plain" "$arc" 200
        pairs+=("$arc" "$plain")
        poison_pairs+=("$arc" "$plain")
        continue
    fi
    for level in 1 5 9; do
        arc="$out/${base}.lzo.${level}"
        lzop -"$level" -c < "$plain" > "$arc"
        pairs+=("$arc" "$plain")
        [ -s "$plain" ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# See port/test/decompress_bunzip2/run.sh's copy of this same check for why
# it reads back the "N/M cases passed" line rather than trusting exit code
# alone -- a nonzero exit only proves at least one case disagreed.
n_poison=$((${#poison_pairs[@]} / 2))
poison_out=$(DBZO_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
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
