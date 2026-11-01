#!/usr/bin/env bash
# port/test/decompress_inflate/run.sh -- the userspace differential for
# lib/decompress_inflate.c's gunzip(). See drv.c's header for the shape:
# both arms link the SAME real zlib_inflate backend (inflate_thunk.c's
# real C entries, Rust bodies), compiled as separate objects the way the
# kernel Makefile actually does it (not combined into one crate the way
# port/test/zlib_inflate/'s own probe.rs does, for a different purpose).
#
# WHY THE PORTED (Rust) BACKEND, NOT A PRISTINE-C ONE LIKE decompress_unxz's
# harness: adversarial review noted this is the opposite of that documented
# precedent and asked for the reasoning written down. Both arms link the
# SAME backend either way, so it cancels for the differential regardless of
# which one is chosen -- what's under test is gunzip()'s own buffer/
# streaming logic, not zlib_inflate's. The ported backend is the better
# floor.md criterion-8 answer here specifically: it is what CONFIG_RUST=y
# actually ships, and this file's own port doesn't touch zlib_inflate/ at
# all, so there's no separate pristine-C fallback this harness would
# otherwise be proving anything about.
#
# PREREQUISITE: `bash rig/apply.sh` must have run first. inflate_thunk.c is
# a port-added file, not an upstream one -- it does not exist under
# src/linux/lib/zlib_inflate/ until apply.sh installs port/tree/ into the
# extracted kernel tree. A fresh tarball extraction without that step fails
# here with "missing .../inflate_thunk.c", which is the correct, loud
# failure (not a defect in this script) but worth knowing in advance.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_inflate"
out="${TMPDIR:-/tmp}/decompress_inflate-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_inflate.c"
RS="$root/port/tree/lib/decompress_inflate_rs.rs"
Z="$root/port/tree/lib/zlib_inflate"
for f in "$C" "$RS" "$Z/inflate_rs.rs" "$Z/inftrees_rs.rs" "$Z/inffast_rs.rs" \
         "$root/src/linux/lib/zlib_inflate/inflate_thunk.c"; do
    [ -f "$f" ] || { echo "missing $f (did you run 'bash rig/apply.sh' first?)"; exit 2; }
done

# floor.md RAISE 1: every #[cfg] a ported file reads gets swept. This file
# reads exactly one, CONFIG_ZLIB_DFLTCC (added by adversarial review, which
# found the C's DFLTCC fork silently dropped) -- same symbol
# port/test/zlib_inflate/run.sh already sweeps for inflate_rs.rs, and the
# same reason: `depends on S390`, so nothing here can actually RUN it, but
# leaving it unswept is how a supported architecture breaks silently.
for cfg in "" "--cfg CONFIG_ZLIB_DFLTCC"; do
    if ! "$KB_RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
            -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
            $cfg --crate-name sweep --out-dir "$out" "$RS" 2>"$out/sweep.err"; then
        echo "CONFIG SWEEP FAILED with [${cfg:-none}]"
        head -20 "$out/sweep.err"
        exit 1
    fi
done
echo "config sweep: decompress_inflate_rs.rs builds with and without CONFIG_ZLIB_DFLTCC"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_inflate_rs -o "$out/librs.a" "$RS"

# The real zlib_inflate backend gunzip() calls into, compiled as SEPARATE
# objects exactly like the kernel Makefile's CONFIG_RUST=y arm does
# (inffast_rs.o inflate_thunk.o inflate_rs.o inftrees_rs.o) -- cross-crate
# calls go through real extern "C" symbols the same way they do in the
# actual kernel link, not through a single combined crate.
for name in inflate_rs inftrees_rs inffast_rs; do
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name "$name" -o "$out/lib$name.a" "$Z/$name.rs"
done

# shim/ takes priority over the real kernel include path. mm.h's shim
# defines STATIC/INIT as empty and malloc/free as libc's -- after
# decompress_inflate.c's own top-of-file `#ifdef STATIC` has already
# resolved (undefined there -- this test never defines STATIC, selecting
# the non-PREBOOT arm this port's Rust replaces; decompress_inflate.c
# ITSELF is never modified by this port, see decompress_inflate_rs.rs's
# module doc for why).
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux/lib" -I "$root/src/linux/include")
CF=(-O2 -g -Wall -Wno-unused-parameter -Wno-sign-compare)

cc "${CF[@]}" "${INC[@]}" -Dgunzip=cref_gunzip -c -o "$out/c_oracle.o" "$C"
cc "${CF[@]}" "${INC[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" "${INC[@]}" -c -o "$out/inflate_thunk.o" \
   "$root/src/linux/lib/zlib_inflate/inflate_thunk.c"

cc -o "$out/t" "$out/drv.o" "$out/c_oracle.o" "$out/inflate_thunk.o" \
   "$out/librs.a" "$out"/libinflate_rs.a "$out"/libinftrees_rs.a "$out"/libinffast_rs.a

# --- corpus: plaintext this script owns, archived by the real gzip CLI ---
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
# -n: no filename/mtime stored -- keeps the header a fixed, known 10 bytes
# (no FNAME flag), matching what run_corrupt_case's payload_off assumes.
# Multiple levels for the same reason the rest of this file family varies
# compression level: different block/Huffman-table layouts.
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for level in 1 6 9; do
        arc="$out/${base}.gz.${level}"
        gzip -q -n -c "-$level" "$plain" > "$arc"
        pairs+=("$arc" "$plain")
        [ "$(wc -c <"$plain")" -ge 64 ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# 3 cases per pair (buffer, callback, corrupt) -- same reasoning as
# decompress_unzstd's run.sh: poison_pairs is filtered so the corrupt-case
# stage never skips for any included pair, so 3x is exact.
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
