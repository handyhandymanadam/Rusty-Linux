#!/usr/bin/env bash
# boot.sh <build-dir> [seconds]
#
# Boot a built kernel under qemu on a busybox initramfs, and REPORT WHAT THE
# SERIAL LOG SAID -- never what qemu's exit status implied. A kernel that
# panics, hangs, or boots without running any Rust all look like a successful
# qemu invocation from the outside.
set -u
RIG=$(cd "$(dirname "$0")" && pwd)
BUILD=${1:?usage: boot.sh <build-dir> [timeout-seconds]}
LIMIT=${2:-120}
NAME=$(basename "$BUILD")
LOG="$RIG/../logs/boot-$NAME.log"

BZ="$BUILD/arch/x86/boot/bzImage"
[ -f "$BZ" ] || { echo "no bzImage at $BZ"; exit 1; }

# initramfs: static busybox + the init above. Rebuilt every run so it can
# never be stale relative to the rig.
TMP=$(mktemp -d)
mkdir -p "$TMP"/{bin,proc,sys,dev}
cp "$RIG/busybox" "$TMP/bin/busybox"
cp "$RIG/init"    "$TMP/init"
ln -sf busybox "$TMP/bin/sh"
chmod +x "$TMP/init" "$TMP/bin/busybox"
( cd "$TMP" && find . | cpio -o -H newc --quiet | gzip -9 ) > "$TMP.cpio.gz"

KVM=""
[ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"

START=$(date +%s.%N)
timeout "$LIMIT" qemu-system-x86_64 $KVM \
        -m 1024 -smp 2 -no-reboot -display none \
        -kernel "$BZ" -initrd "$TMP.cpio.gz" \
        -append "console=ttyS0 panic=-1 loglevel=7" \
        -serial mon:stdio < /dev/null > "$LOG" 2>&1
QEXIT=$?
END=$(date +%s.%N)
rm -rf "$TMP" "$TMP.cpio.gz"

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
