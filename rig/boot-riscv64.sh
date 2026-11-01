#!/usr/bin/env bash
# boot-riscv64.sh <build-dir> [seconds]
#
# SIBLING of rig/boot.sh for ARCH=riscv builds (logs/riscv64.md): qemu-system-riscv64
# -M virt, little-endian, TCG (no KVM on an x86 host). rig/boot.sh itself is
# untouched, so the x86 path is byte-for-byte what it was. The initramfs is NOT
# busybox (there is no riscv64 busybox in rig/): it is rig/riscv64/init.c, a static
# freestanding riscv64 init that prints the same RIG: markers as rig/init.
#
# Boot a built kernel under qemu on an initramfs, and REPORT WHAT THE
# SERIAL LOG SAID -- never what qemu's exit status implied. A kernel that
# panics, hangs, or boots without running any Rust all look like a successful
# qemu invocation from the outside.
set -u
RIG=$(cd "$(dirname "$0")" && pwd)
BUILD=${1:?usage: boot.sh <build-dir> [timeout-seconds]}
LIMIT=${2:-120}
NAME=$(basename "$BUILD")
LOG="$RIG/../logs/boot-$NAME.log"   # logs/boot-*.log is never committed

# GUARD: refuse to trust a build/boot result if port/tree/ has drifted from
# the src/linux/ tree kbuild actually reads. rig/apply.sh installs port/tree/
# into src/linux/ (gitignored, not versioned); kmake never looks at
# port/tree/ directly. A stale src/linux/ builds and boots "clean" while
# silently testing whatever state src/linux/ was last APPLIED to, not
# port/tree/'s current one. Caught 2026-09-06: a merge's verification build
# succeeded and booted clean against pre-merge C objects because apply.sh
# was never re-run in that worktree after the merge -- only the new .o
# file's literal absence gave it away, not the build or boot exit status.
# Only kept on disk (under logs/, for post-mortem) if the check actually
# fails -- on the (overwhelmingly common) clean pass there is nothing here
# worth the churn of a tracked file changing on every single boot.sh run.
APPLY_CHECK_TMP=$(mktemp)
if ! "$RIG/apply.sh" --check > "$APPLY_CHECK_TMP" 2>&1; then
    APPLY_CHECK_LOG="$RIG/../logs/apply-check-$NAME.log"
    mv "$APPLY_CHECK_TMP" "$APPLY_CHECK_LOG"
    echo "REFUSING to trust $BUILD: 'rig/apply.sh --check' reports port/tree/"
    echo "has drifted from src/linux/. This build may not reflect port/tree/'s"
    echo "current state at all -- run rig/apply.sh, rebuild $BUILD, then retry."
    echo "(diff: $APPLY_CHECK_LOG)"
    exit 1
fi
rm -f "$APPLY_CHECK_TMP"

IMG="$BUILD/arch/riscv/boot/Image"
[ -f "$IMG" ] || { echo "no Image at $IMG"; exit 1; }

# initramfs: the one static riscv64 init. Rebuilt every run so it can never be
# stale relative to the rig.
TMP=$(mktemp -d)
mkdir -p "$TMP/root"
clang --target=riscv64-linux-gnu -march=rv64imac -mabi=lp64 -mno-relax -nostdlib -static -fuse-ld=lld -O2 -ffreestanding \
      -fno-builtin -fno-stack-protector -o "$TMP/root/init" "$RIG/riscv64/init.c" \
    || { echo "init.c did not compile"; exit 1; }
( cd "$TMP/root" && find . | cpio -o -H newc --quiet | gzip -9 ) > "$TMP.cpio.gz"

START=$(date +%s.%N)
timeout "$LIMIT" qemu-system-riscv64 -M virt -cpu rv64 -bios default \
        -m 1024 -smp 2 -no-reboot -display none \
        -kernel "$IMG" -initrd "$TMP.cpio.gz" \
        -append "console=ttyS0 earlycon panic=-1 loglevel=7" \
        -serial mon:stdio < /dev/null > "$LOG" 2>&1
QEXIT=$?
END=$(date +%s.%N)
rm -rf "${TMP:?}" "${TMP:?}.cpio.gz"

# --- Report the state that was READ from the log.
say() { printf '  %-12s %s\n' "$1" "$2"; }
echo "boot report for $NAME  (log: $LOG)"
say "qemu-exit" "$QEXIT"
say "wall" "$(printf '%.1fs' "$(echo "$END - $START" | bc)")"
grep -q "RIG: init running" "$LOG" && say "init" "reached"      || say "init" "NOT REACHED"
grep -q "RIG: done"         "$LOG" && say "userspace" "completed" || say "userspace" "DID NOT COMPLETE"
grep -q "RIG: rust-ran YES" "$LOG" && say "rust-ran" "YES"      || say "rust-ran" "NO"
grep -qE "Kernel panic|BUG:|Oops" "$LOG" && say "faults" "PRESENT -- read the log" || say "faults" "none in log"
sed -n 's/^RIG: userspace /  userspace   /p;s/^RIG: kallsyms /  kallsyms    /p;s/^RIG: version /  version     /p' "$LOG"

grep -q "RIG: done" "$LOG" && grep -q "RIG: rust-ran YES" "$LOG"
