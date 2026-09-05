#!/usr/bin/env bash
# be-cross.sh -- provide a BIG-ENDIAN userspace toolchain for the differentials.
#
# WHY THIS EXISTS
#   Every harness under port/test/ had only ever run on x86-64 little-endian,
#   and a great deal of lib/ forks on byte order (MEM_readLE*, get_unaligned_le*,
#   MEM_isLittleEndian(), swab*, and the shims' own __BYTE_ORDER__ derivation).
#   The kernel builds lib/ for s390, big-endian PowerPC and big-endian MIPS, so
#   a byte-order mistake in a port is a live defect the rig could not see.
#
#   MEASURED, 2026-09-04, not asserted: with `u32::from_le`/`usize::from_le`
#   removed from a scratch copy of entropy_common_rs.rs, the zstd_entropy
#   differential reported 0 mismatches in 207924 comparisons on x86-64 and
#   failed on run 2 of 2000 on s390x. That is the size of the blind spot.
#
# WHAT IT PROVIDES, on success
#   BE_CC        cross compiler + --sysroot, as a single word-split string
#   BE_OBJCOPY   matching objcopy (zstd_entropy renames a symbol on the object)
#   BE_RUN       the qemu-user launcher, as a word-split string
#   BE_RUSTTARGET  s390x-unknown-linux-gnu
#   BE_ARCH      s390x
#
# WHY s390x AND NOT ppc64/mips
#   s390x is the arch the kernel actually still ships big-endian and cares
#   about, rustc carries it as a tier-2 target with std, and Fedora builds a
#   complete s390x glibc, so the sysroot is a download rather than a build.
#
# THE TOOLCHAIN IS NOT INSTALLED SYSTEM-WIDE.
#   `--bootstrap` unpacks RPMs into a cache directory and touches nothing else.
#   Fedora has no single package that yields a complete big-endian USERSPACE
#   cross toolchain: gcc-s390x-linux-gnu is built for kernel cross-builds and
#   ships no libc, so the glibc half must come from the s390x secondary-arch
#   repo either way. The nearest system-wide equivalent, for the record, is:
#
#     sudo dnf install gcc-s390x-linux-gnu binutils-s390x-linux-gnu \
#                      qemu-user-static-s390x
#
#   ...and it still leaves you needing the s390x glibc sysroot this script
#   fetches. ASSUMED, not established: that a system install would behave
#   identically; only the cache-dir form below has been run.
#
# USE
#     source port/test/common/be-cross.sh          # sets BE_* or exits 1
#     port/test/common/be-cross.sh --bootstrap     # fetch the toolchain
#     port/test/common/be-cross.sh                 # report what is present
#
# Override any piece with BE_CACHE / BE_CC / BE_RUN in the environment.

BE_ARCH=s390x
BE_RUSTTARGET=s390x-unknown-linux-gnu
BE_CACHE="${BE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rusty-linux-be}"

# Pinned to the versions this was measured with. Fedora 44 / glibc 2.43 /
# gcc 15.2.1 / binutils 2.45 / qemu 10.2.2. Bumping these is fine; recording
# them is what makes a later run comparable to this one.
_BE_FEDORA=44
_BE_S390=https://dl.fedoraproject.org/pub/fedora-secondary/releases/$_BE_FEDORA/Everything/s390x/os/Packages
_BE_X86=https://dl.fedoraproject.org/pub/fedora/linux/releases/$_BE_FEDORA/Everything/x86_64/os/Packages
_BE_SYSROOT_RPMS=(
    "$_BE_S390/g/glibc-2.43-2.fc44.s390x.rpm"
    "$_BE_S390/g/glibc-devel-2.43-2.fc44.s390x.rpm"
    "$_BE_S390/l/libgcc-16.0.1-0.10.fc44.s390x.rpm"
    "$_BE_S390/k/kernel-headers-6.19.6-300.fc44.s390x.rpm"
)
_BE_CROSS_RPMS=(
    "$_BE_X86/g/gcc-s390x-linux-gnu-15.2.1-1.fc44.x86_64.rpm"
    "$_BE_X86/b/binutils-s390x-linux-gnu-2.45-3.fc44.x86_64.rpm"
)
_BE_QEMU_RPMS=( "$_BE_X86/q/qemu-user-static-s390x-10.2.2-1.fc44.x86_64.rpm" )

be_bootstrap() {
    set -e
    mkdir -p "$BE_CACHE/rpms" "$BE_CACHE/sysroot" "$BE_CACHE/cross" "$BE_CACHE/qemu"
    local u f
    for u in "${_BE_SYSROOT_RPMS[@]}" "${_BE_CROSS_RPMS[@]}" "${_BE_QEMU_RPMS[@]}"; do
        f="$BE_CACHE/rpms/$(basename "$u")"
        [ -f "$f" ] || { echo "  fetch $(basename "$u")"; curl -sfL -o "$f" "$u"; }
    done
    for u in "${_BE_SYSROOT_RPMS[@]}"; do
        (cd "$BE_CACHE/sysroot" && rpm2cpio "$BE_CACHE/rpms/$(basename "$u")" | cpio -idmu --quiet)
    done
    for u in "${_BE_CROSS_RPMS[@]}"; do
        (cd "$BE_CACHE/cross" && rpm2cpio "$BE_CACHE/rpms/$(basename "$u")" | cpio -idmu --quiet)
    done
    for u in "${_BE_QEMU_RPMS[@]}"; do
        (cd "$BE_CACHE/qemu" && rpm2cpio "$BE_CACHE/rpms/$(basename "$u")" | cpio -idmu --quiet)
    done

    # The glibc RPM ships /lib64 as a real directory beside /usr/lib64 rather
    # than the symlink a live Fedora root has. ld(1) resolves the SONAME
    # /lib64/libc.so.6 through the sysroot literally, so without these two
    # links every link fails with "cannot find /lib64/libc.so.6 inside ...".
    # MEASURED: that was the failure, and this was the fix.
    if [ -d "$BE_CACHE/sysroot/lib64" ] && [ ! -L "$BE_CACHE/sysroot/lib64" ]; then
        cp -a "$BE_CACHE/sysroot/lib64/." "$BE_CACHE/sysroot/usr/lib64/"
        rm -rf "$BE_CACHE/sysroot/lib64"
    fi
    ln -sfn usr/lib64 "$BE_CACHE/sysroot/lib64"
    ln -sfn usr/lib   "$BE_CACHE/sysroot/lib"

    # gcc's collect2 searches its OWN exec prefix for a program literally named
    # `ld`; the cross binutils only ship `s390x-linux-gnu-ld`, and neither -B
    # nor COMPILER_PATH persuaded collect2 otherwise (tried, 2026-09-04).
    # Dropping the copies into the libexec dir it already searches is what
    # worked. Copies rather than symlinks: symlinks were also tried and also
    # failed, cause not established.
    local lx="$BE_CACHE/cross/usr/libexec/gcc/s390x-linux-gnu/15"
    cp -f "$BE_CACHE/cross/usr/bin/s390x-linux-gnu-ld" "$lx/ld"
    cp -f "$BE_CACHE/cross/usr/bin/s390x-linux-gnu-ld" "$lx/real-ld"

    echo "bootstrapped into $BE_CACHE"
    set +e
}

be_probe() {
    BE_CC="${BE_CC:-$BE_CACHE/cross/usr/bin/s390x-linux-gnu-gcc --sysroot=$BE_CACHE/sysroot}"
    BE_OBJCOPY="${BE_OBJCOPY:-$BE_CACHE/cross/usr/bin/s390x-linux-gnu-objcopy}"
    BE_RUN="${BE_RUN:-$BE_CACHE/qemu/usr/bin/qemu-s390x-static -L $BE_CACHE/sysroot}"
    local missing=0 w
    # shellcheck disable=SC2086
    set -- $BE_CC;    [ -x "$1" ] || { echo "missing cross gcc: $1"; missing=1; }
    [ -x "$BE_OBJCOPY" ] || { echo "missing objcopy: $BE_OBJCOPY"; missing=1; }
    # shellcheck disable=SC2086
    set -- $BE_RUN;   [ -x "$1" ] || { echo "missing qemu-user: $1"; missing=1; }
    for w in "$BE_CACHE/sysroot/usr/lib64/libc.so.6" "$BE_CACHE/sysroot/usr/include/stdio.h"; do
        [ -e "$w" ] || { echo "missing sysroot piece: $w"; missing=1; }
    done
    return $missing
}

# The Rust half is a plain `rustup target add`; it is small and reversible and
# is the only thing here that touches the toolchain the kernel build uses.
be_check_rust() {
    local rustc="${KB_RUSTC:?source kbuild-env.sh first}"
    if ! "$rustc" --print target-libdir --target "$BE_RUSTTARGET" >/dev/null 2>&1 ||
       [ ! -d "$("$rustc" --print target-libdir --target "$BE_RUSTTARGET" 2>/dev/null)" ]; then
        echo "missing rust std for $BE_RUSTTARGET"
        echo "  rustup target add $BE_RUSTTARGET --toolchain 1.98.0-x86_64-unknown-linux-gnu"
        return 1
    fi
    return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ "${1:-}" = "--bootstrap" ]; then be_bootstrap; fi
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/kbuild-env.sh"
    be_probe && echo "cross toolchain: ok  ($BE_CACHE)"
    be_check_rust && echo "rust std for $BE_RUSTTARGET: ok"
fi
