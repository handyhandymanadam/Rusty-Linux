#!/usr/bin/env bash
# modload.sh <build-dir> <log-path> <module.ko> [more.ko ...]
#
# Boot a kernel and actually INSMOD a module into it.
#
# WHY THIS EXISTS. logs/build-limits.md has recorded, since the beginning, that
# neither of this project's builds loads a module -- so GOALS.md §2 criterion 4
# ("the MODVERSIONS CRCs do not change") has always been a claim about numbers
# in a file, never a claim that a module built against those numbers loads.
# rig/crc-check.sh compares fingerprints; nothing checked that the fingerprints
# DO anything.
#
# Written 2026-09-04, during the GENKSYMS investigation, by the adversarial
# reviewer who needed to know whether "modpost raised no complaint" meant
# anything. It did not: modpost's "has no CRC!" warning only fires on the
# module side, and this project had never produced a .ko. Building one and
# loading it is what turned that from an assumption into a measurement.
#
# It has been proved to FAIL as well as pass: flipping a single byte in a
# module's __version_ext_crcs made the load fail with "disagrees about version
# of symbol", rc=22. The check has teeth.
#
# USE
#   Configure a build with some module set to =m, e.g.
#       CONFIG_SAMPLE_RUST_MINIMAL=m   (needs CONFIG_SAMPLES_RUST=y)
#   then
#       ./rig/modload.sh build-modload logs/modload.log \
#           build-modload/samples/rust/rust_minimal.ko
#
#   Greps for MODTEST lines plus the three failure phrases that matter:
#   "disagrees" (CRC mismatch), "no symbol version", "Unknown symbol".
set -u
RIG=$(cd "$(dirname "$0")" && pwd)
BUILD=$1; shift
LOG=$1; shift
BZ="$BUILD/arch/x86/boot/bzImage"
TMP=$(mktemp -d)
mkdir -p "$TMP"/{bin,proc,sys,dev,mod}
cp "$RIG/busybox" "$TMP/bin/busybox"; ln -sf busybox "$TMP/bin/sh"
for k in "$@"; do cp "$k" "$TMP/mod/"; done
cat > "$TMP/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
echo "MODTEST: init running"
for k in /mod/*.ko; do
  echo "MODTEST: insmod $k"
  insmod $k 2>&1 && echo "MODTEST: INSMOD-OK $k" || echo "MODTEST: INSMOD-FAIL $k rc=$?"
done
echo "MODTEST: lsmod:"; lsmod
echo "MODTEST: dmesg tail:"; dmesg | tail -25
echo "MODTEST: done"
poweroff -f
EOF
chmod +x "$TMP/init"
( cd "$TMP" && find . | cpio -o -H newc --quiet | gzip -9 ) > "$TMP.cpio.gz"
KVM=""; [ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"
timeout 120 qemu-system-x86_64 $KVM -m 1024 -smp 2 -no-reboot -display none \
  -kernel "$BZ" -initrd "$TMP.cpio.gz" -append "console=ttyS0 panic=-1 loglevel=7" \
  -serial mon:stdio < /dev/null > "$LOG" 2>&1
echo "qemu-exit=$?"
rm -rf "$TMP" "$TMP.cpio.gz"
grep -E "MODTEST|disagrees|no symbol version|Unknown symbol" "$LOG"
