#!/usr/bin/env bash
# codec-check.sh [codec ...]   (default: GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD)
#
# Build and BOOT the kernel once per CONFIG_KERNEL_<codec> choice, in one
# scratch build dir (build-codec, reconfigured and rebuilt incrementally).
#
# CODEC_BASE=build-efi BOOT_EFI=1 CODEC_DIR=build-codec-efi rig/codec-check.sh  -> the same, as an EFI-stub kernel under OVMF.
# WHY (logs/floor.md RAISE 7, 2026-10-02). Porting replaced
# lib/decompress_{unxz,bunzip2,unlz4,unlzo,unzstd}.c with Rust-thunk stubs and
# deleted the pre-boot (#ifdef STATIC) code arch/x86/boot/compressed/misc.c
# #includes. Every CONFIG_KERNEL_<codec> except GZIP/LZMA then failed to
# BUILD, and nothing noticed, because both gate configs use GZIP. This is the
# check that would have caught it. It reports what it READ: whether the codec's
# vmlinux.bin.<ext> exists, whether the build exited 0, and boot.sh's verdict.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/kbuild-env.sh"
codecs=("$@"); [ ${#codecs[@]} -gt 0 ] || codecs=(GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD)
b="$root/${CODEC_DIR:-build-codec}"
mkdir -p "$b"
fail=0
for c in "${codecs[@]}"; do
    cp "$root/${CODEC_BASE:-build-fast}/.config" "$b/.config"
    for o in GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD; do
        sed -i "/^CONFIG_KERNEL_$o=/d;/^# CONFIG_KERNEL_$o is not set/d" "$b/.config"
    done
    echo "CONFIG_KERNEL_$c=y" >> "$b/.config"
    echo "CONFIG_RD_$c=y" >> "$b/.config"
    kmake O="$b" olddefconfig >/dev/null 2>&1
    got=$(grep -c "^CONFIG_KERNEL_$c=y" "$b/.config")
    if [ "$got" != 1 ]; then printf '%-6s CONFIG DROPPED\n' "$c"; fail=1; continue; fi
    if ! kmake O="$b" -j"$(nproc)" >"$b/codec-$c.log" 2>&1; then
        printf '%-6s BUILD FAILED (%s)\n' "$c" "$(grep -m1 -E 'rror [0-9]+|error:' "$b/codec-$c.log" | cut -c1-100)"; fail=1; continue
    fi
    ext=$(echo "$c" | tr A-Z a-z)
    img=$(ls -t "$b"/arch/x86/boot/compressed/vmlinux.bin.* 2>/dev/null | head -1)
    verdict=$("$root/rig/boot.sh" "$b" 200 2>&1 | grep -E 'init |userspace |rust-ran' | tr -s ' ' | tr '\n' ';')
    case "$verdict" in *"init reached"*"userspace completed"*"rust-ran YES"*) st=OK;; *) st="BOOT FAILED"; fail=1;; esac
    # What the boot stub actually contains: Rust engine symbols (_rs crates, rust_*) linked
    # into arch/x86/boot/compressed/vmlinux. 0 means that codec still decompresses with the
    # original C (LZMA today; every codec on an EFI-stub config) -- reported, not hidden.
    rs=$(nm "$b/arch/x86/boot/compressed/vmlinux" 2>/dev/null | grep -cE '_rs|rust_')
    printf '%-6s %s  image=%s  stub-rust-syms=%s  %s\n' "$c" "$st" "$(basename "${img:-none}")" "$rs" "$verdict"
done
exit $fail
