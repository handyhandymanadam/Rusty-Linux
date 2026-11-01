#!/usr/bin/env bash
# port/test/decompress_unzstd/run.sh -- the userspace differential for
# lib/decompress_unzstd.c. See drv.c's header for the shape: both arms link
# the SAME real zstd_* kernel API, backed by lib/zstd/'s plain-C arm
# (same precedent as decompress_unxz's shared-pristine-backend choice).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_unzstd"
out="${TMPDIR:-/tmp}/decompress_unzstd-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_unzstd.c"
RS="$root/port/tree/lib/decompress_unzstd_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_unzstd_rs -o "$out/librs.a" "$RS"

# shim/ takes priority over the real kernel include path. mm.h's shim
# defines STATIC/INIT as empty and large_malloc/large_free as libc
# malloc/free -- after decompress_unzstd.c's own top-of-file `#ifdef
# STATIC` has already resolved (undefined there, since this test never
# defines STATIC -- selecting the non-UNZSTD_PREBOOT arm this port
# replaces, matching decompress_unxz's identical shim of the same header).
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux/include")
Z="$root/src/linux/lib/zstd"
ZINC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$Z/common" -I "$root/src/linux/include")
CF=(-O2 -g -Wall -Wno-unused-parameter -Wno-sign-compare)

cc "${CF[@]}" "${INC[@]}" -Dunzstd=cref_unzstd -c -o "$out/c_oracle.o" "$C"
cc "${CF[@]}" "${INC[@]}" -c -o "$out/drv.o" "$here/drv.c"

# The backend behind the real zstd_* EXPORT_SYMBOLs both arms call: the
# CONFIG_RUST=n branch of lib/zstd/Makefile, unmodified upstream C (see
# drv.c's header for why using this arm rather than the Rust one currently
# shipping is the right choice for testing THIS wrapper).
for f in common/entropy_common.c common/error_private.c common/fse_decompress.c \
         common/zstd_common.c common/debug.c decompress/huf_decompress.c \
         decompress/zstd_ddict.c decompress/zstd_decompress.c \
         decompress/zstd_decompress_block.c zstd_decompress_module.c \
         zstd_common_module.c; do
    n=$(basename "$f" .c)
    cc "${CF[@]}" "${ZINC[@]}" -c -o "$out/$n.o" "$Z/$f"
done
cc "${CF[@]}" "${INC[@]}" -c -o "$out/xxhash.o" "$root/src/linux/lib/xxhash.c"

cc -o "$out/t" "$out/drv.o" "$out/c_oracle.o" "$out"/entropy_common.o \
   "$out"/error_private.o "$out"/fse_decompress.o "$out"/zstd_common.o \
   "$out"/debug.o "$out"/huf_decompress.o "$out"/zstd_ddict.o \
   "$out"/zstd_decompress.o "$out"/zstd_decompress_block.o \
   "$out"/zstd_decompress_module.o "$out"/zstd_common_module.o \
   "$out"/xxhash.o "$out/librs.a"

# --- corpus: plaintext this script owns, archived by the real zstd CLI ---
#
# The C source file is passed in as an argv path, not hardcoded inside the
# heredoc, and a missing/unreadable file is FATAL -- found by adversarial
# review (finding B): an earlier version had an absolute path into this
# worktree specifically, guarded by a bare `except OSError: pass`, so on any
# other machine the corpus silently shrank from 7 plaintexts to 6 and the
# harness reported success anyway (notes/PRIOR-ART.md §3's stale-input-set class,
# self-inflicted). A corpus that quietly gets smaller must fail loudly
# instead, the way rig/init distinguishes ABSENT from PASS.
gen="$out/gen"; mkdir -p "$gen"
python3 - "$gen" "$C" <<'PYEOF'
import os, random, sys
d, c_source_path = sys.argv[1], sys.argv[2]
random.seed(20260906)

def write(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

write("empty.txt", b"")
write("one_byte.txt", b"x")
write("ascii_repeat.txt", (b"the quick brown fox jumps over the lazy dog\n") * 5000)
write("all_same.txt", b"A" * 200000)
write("random.bin", bytes(random.randrange(256) for _ in range(150000)))
write("sparse_bytes.bin", bytes((i * 37) % 256 for i in range(300000)))
with open(c_source_path, "rb") as f:
    write("c_source.c", f.read() * 3)
PYEOF

pairs=()
poison_pairs=()
# Multiple compression levels, since level affects window size and block
# layout (small levels can pick a smaller window, exercising the
# zstd_dstream_workspace_bound()/window-size-check path with more than one
# value, not just the default's).
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for level in 1 3 19; do
        arc="$out/${base}.zst.${level}"
        zstd -q -f "-$level" -o "$arc" "$plain"
        pairs+=("$arc" "$plain")
        # >= 64 bytes, not just nonempty: drv.c now poisons all three
        # stages (buffer, callback, corrupt-case), and the corrupt-case
        # stage skips archives too small to contain a real payload byte
        # past the frame+block header. Excluding one_byte.txt (and
        # empty.txt) here keeps every poisoned pair contributing exactly
        # 3 cases, so n_poison below stays an exact, independently-
        # computed prediction rather than a guess -- the same property
        # finding D's fix depends on.
        [ "$(wc -c <"$plain")" -ge 64 ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# A nonzero exit alone only proves AT LEAST ONE case disagreed, not that
# every poisonable case did -- the same class of gap adversarial review
# found in bunzip2's and unlz4's harnesses. Checked by reading the "N/M
# cases passed" line back instead. 3 cases per pair (buffer, callback,
# corrupt) -- fixed by adversarial review (finding D): an earlier version
# ran only the buffer-mode stage under DBZ_PROVE_CAN_FAIL=1, so "0/N cases
# passed" was a true statement about one third of the harness, not all of
# it. All three stages are poisoned now (see drv.c), and poison_pairs is
# filtered so none of them skip, so 3x is exact, not approximate.
n_poison=$(( (${#poison_pairs[@]} / 2) * 3 ))
poison_out=$(DBZ_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
if [ "$poison_rc" -eq 0 ]; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
if grep -q "cases skipped" <<<"$poison_out"; then
    echo "*** POISON RUN SKIPPED A CASE -- n_poison's 3x-per-pair prediction no longer holds:"
    echo "$poison_out"
    exit 1
fi
if ! grep -qxF "0/$n_poison cases passed" <<<"$poison_out"; then
    echo "*** THE HARNESS CANNOT DISAGREE ON EVERY CASE -- expected \"0/$n_poison cases passed\":"
    echo "$poison_out"
    exit 1
fi
echo "prove-can-fail: poisoned output is detected on all $n_poison poisonable cases"

"$out/t" "${pairs[@]}"
