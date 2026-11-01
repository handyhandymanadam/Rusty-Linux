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
LOG="${BZ_LOG:-/tmp/claude-1000/bz2boot-$NAME.log}"

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

# RIG CHANGE 2026-10-06 (wt-conc1): BOOT_SMP (default 2) and BOOT_MEM (default 1024 MB) were hardcoded; defaults
# keep the old command line byte for byte. Used by the concurrency checker boots (logs/concurrency-tooling.md).
KVM=""
[ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"
# BOOT_TCG=1: no KVM, QEMU's software CPU (TCG) -- stricter about some instruction semantics (STUBH).
[ -n "${BOOT_TCG:-}" ] && KVM="-accel tcg"
# BOOT_CPU=max: QEMU CPU model (TCG "max" has LA57, so the stub runs its 4->5-level paging trampoline, la57toggle)
[ -n "${BOOT_CPU:-}" ] && KVM="$KVM -cpu $BOOT_CPU"

# BOOT_EFI=1: boot through OVMF (EFI firmware) instead of QEMU's built-in BIOS path, so a kernel
# built with CONFIG_EFI_STUB runs its EFI entry (logs/test-gaps.md). Needs the edk2-ovmf package.
EFI=""
if [ -n "${BOOT_EFI:-}" ]; then
    OVMF=/usr/share/edk2/ovmf
    [ -f "$OVMF/OVMF_CODE.fd" ] && [ -f "$OVMF/OVMF_VARS.fd" ] || { echo "BOOT_EFI set but no OVMF in $OVMF"; exit 1; }
    EFIVARS=$(mktemp); cp "$OVMF/OVMF_VARS.fd" "$EFIVARS"
    EFI="-machine q35 -drive if=pflash,format=raw,unit=0,readonly=on,file=$OVMF/OVMF_CODE.fd -drive if=pflash,format=raw,unit=1,file=$EFIVARS"
fi

START=$(date +%s.%N)
timeout "$LIMIT" qemu-system-x86_64 $KVM $EFI \
        -m "${BOOT_MEM:-1024}" -smp "${BOOT_SMP:-2}" -no-reboot -display none \
        -kernel "$BZ" -initrd "$TMP.cpio.gz" \
        -append "console=ttyS0 panic=-1 loglevel=7 ${BZ_APPEND:-}" \
        -serial mon:stdio < /dev/null > "$LOG" 2>&1
QEXIT=$?
END=$(date +%s.%N)
rm -rf "${TMP:?}" "${TMP:?}.cpio.gz" "${EFIVARS:-}"

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
