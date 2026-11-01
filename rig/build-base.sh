#!/usr/bin/env bash
# build-base.sh -- build the two PRISTINE-C baseline kernels: build-fast-base
# and build-full-base. Adam's call 2026-09-03; implemented 2026-10-02.
#
# They are built from a SEPARATE extraction of the tarball
# (src/base/linux-6.18.49), never from src/linux, so no port file can leak in
# and the port's tree is not touched. Only the six port Kconfig files are
# overlaid (they add prompts, no code; same reasoning as baseline-symvers.sh)
# so the symbols the configs name survive olddefconfig. CONFIG_RUST is OFF:
# this is the unported C kernel. Everything else is the .config of the
# matching port build -- same config, different code.
#
# Idempotent: a finished build (vmlinux present) is never rebuilt; delete the
# build dir by hand to force it.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/kbuild-env.sh"
tar="$root/src/linux-6.18.49.tar.xz"
base="$root/src/base"
src="$base/linux-6.18.49"

if [ ! -d "$src" ]; then
    mkdir -p "$base"
    tar -C "$base" -xJf "$tar"
    while IFS= read -r f; do
        rel=${f#"$root"/port/tree/}
        cp -- "$f" "$src/$rel"
    done < <(find "$root/port/tree" -name Kconfig)
fi

for name in ${@:-fast full}; do
    b="$root/build-$name-base"
    [ -f "$b/vmlinux" ] && { echo "build-$name-base: already built"; continue; }
    mkdir -p "$b"
    cp "$root/build-$name/.config" "$b/.config"
    "$src/scripts/config" --file "$b/.config" --disable RUST
    make -C "$src" ${KB_ARCH:+ARCH=$KB_ARCH} O="$b" LLVM="$KB_LLVM" olddefconfig >/dev/null
    grep -q '^CONFIG_RUST=y' "$b/.config" && { echo "RUST still on in $b"; exit 1; }
    make -C "$src" ${KB_ARCH:+ARCH=$KB_ARCH} O="$b" LLVM="$KB_LLVM" -j"${KB_JOBS:-$(nproc)}" 2>&1 | tail -3
    [ -f "$b/vmlinux" ] || { echo "build-$name-base FAILED"; exit 1; }
    echo "build-$name-base: built"
done
echo BASE-DONE
