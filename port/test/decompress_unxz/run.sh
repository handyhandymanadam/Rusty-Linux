#!/usr/bin/env bash
# port/test/decompress_unxz/run.sh -- the userspace differential for
# lib/decompress_unxz.c. See drv.c's header for the shape (both arms call
# the SAME pristine lib/xz/*.c backend, isolating the wrapper logic --
# same reasoning port/test/xz_stream/run.sh already uses one layer down).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_unxz"
out="${TMPDIR:-/tmp}/decompress_unxz-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_unxz.c"
RS="$root/port/tree/lib/decompress_unxz_rs.rs"
P="$root/port/pristine/lib/xz"
for f in "$C" "$RS" "$P/xz_dec_stream.c" "$P/xz_dec_lzma2.c" "$P/xz_dec_bcj.c" "$P/xz_crc32.c"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done
command -v xz >/dev/null || { echo "xz(1) not found"; exit 2; }

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_unxz_rs -o "$out/librs.a" "$RS"

# The seven BCJ filters both kernel configs enable, matching
# port/test/xz_stream/run.sh's own FILT array exactly -- an oracle built
# without them is a different program than the kernel compiles.
FILT=(-DXZ_DEC_X86 -DXZ_DEC_POWERPC -DXZ_DEC_ARM -DXZ_DEC_ARMTHUMB
      -DXZ_DEC_ARM64 -DXZ_DEC_SPARC -DXZ_DEC_RISCV)
BACKEND_INC=(-I "$root/port/test/xz_stream/shim" -I "$P" -I "$root/src/linux/include" \
             -I "$root/port/pristine/include")
CFLAGS=(-O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

for f in xz_dec_stream xz_dec_lzma2 xz_dec_bcj xz_crc32; do
    cc "${CFLAGS[@]}" "${BACKEND_INC[@]}" "${FILT[@]}" -c -o "$out/$f.o" "$P/$f.c"
done

# shim/ takes priority over the real kernel include path for the wrapper
# layer -- -D__KERNEL__ makes decompress_unxz.c include
# <linux/decompress/mm.h>, which resolves to this test's own shim (STATIC/
# INIT only; malloc/free stay real libc) rather than the real header (which
# would need full kernel headers for its kmalloc/vmalloc-backed versions).
WRAPPER_INC=(-I "$here/shim" -I "$root/src/linux/include")
cc "${CFLAGS[@]}" "${WRAPPER_INC[@]}" -D__KERNEL__ -Dunxz=cref_unxz -c -o "$out/c.o" "$C"
cc -O2 -g -Wall -c -o "$out/drv.o" "$here/drv.c"
cc -O2 -g -Wall -c -o "$out/crc_init.o" "$here/crc_init.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a" "$out/crc_init.o" \
   "$out/xz_dec_stream.o" "$out/xz_dec_lzma2.o" "$out/xz_dec_bcj.o" "$out/xz_crc32.o"

# --- corpus: plaintext this script owns, archived by the REAL xz CLI ---
gen="$out/gen"; mkdir -p "$gen"
python3 - "$gen" <<'PYEOF'
import os, random, sys
d = sys.argv[1]
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
write("multi_mb.bin", bytes((i * 131 + i // 97) % 256 for i in range(3 * 1024 * 1024)))
try:
    with open("/home/adam/Rusty-Linux-wt-decompress/port/pristine/lib/decompress_unxz.c", "rb") as f:
        write("c_source.c", f.read() * 3)
except OSError:
    pass
PYEOF

pairs=()
poison_pairs=()
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for level in 0 6 9; do
        arc="$out/${base}.xz.${level}"
        # --check=crc32: our kernels build XZ_DEC_ANY_CHECK=n, which rejects
        # any check type above CRC32 (XZ_OPTIONS_ERROR) -- `xz`'s own default
        # is CRC64. Compiling the oracle in a configuration the kernel does
        # not build is exactly floor.md criterion 8's failure mode.
        xz -"$level" -T1 --check=crc32 -c < "$plain" > "$arc"
        pairs+=("$arc" "$plain")
        [ -s "$plain" ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# See port/test/decompress_bunzip2/run.sh's copy of this same check for why
# it reads back the "N/M cases passed" line rather than trusting exit code
# alone -- a nonzero exit only proves at least one case disagreed.
n_poison=$((${#poison_pairs[@]} / 2))
poison_out=$(DBXZ_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
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
