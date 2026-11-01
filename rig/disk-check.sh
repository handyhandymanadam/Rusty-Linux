#!/usr/bin/env bash
# disk-check.sh [build-dir ...]  (default: build-full build-full-norust)
#
# Partition-table detection for real: block/partitions/efi.c (GPT) and msdos.c (MBR, extended partitions) run when the kernel finds a disk, and the rig has no disk. This script builds a set of
# small disk images -- a GPT disk, an MBR disk with an extended partition and logical partitions, a GPT disk whose primary header is destroyed (the kernel must fall back to the alternate GPT and say
# so), one whose primary entry array fails its CRC, one with a second disk GUID in the alternate header (compare_gpts warnings), a protective MBR over garbage, and random bytes -- and boots each
# build with the image attached as a virtio-blk disk (rig/boot.sh BOOT_DISK=...). For every image it compares, between the builds, the partition table (/proc/partitions) and the kernel's own
# lines about the disk ("vda:", "GPT").   Identical output from a Rust build and its CONFIG_RUST=n twin is the pass; the list of partitions per image is printed so a human can see that GPT
# and MBR were really recognised.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
builds=("$@"); [ ${#builds[@]} -gt 0 ] || builds=(build-full build-full-norust)
dir=/tmp/rigdisk; mkdir -p "$dir"
python3 - "$dir" <<'PY'
import subprocess, sys, struct, os, random
d = sys.argv[1]
def mk(name, script, size_mib=16):
    p = os.path.join(d, name + ".img")
    with open(p, "wb") as f: f.truncate(size_mib << 20)
    if script is not None:
        subprocess.run(["sfdisk", "--quiet", p], input=script.encode(), check=True, capture_output=True)
    return p
def patch(p, off, data):
    with open(p, "r+b") as f: f.seek(off); f.write(data)
def flip(p, off):
    with open(p, "r+b") as f: f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 0x55]))
mk("gpt", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n")
mk("mbr", "label: dos\n,2MiB,L\n,3MiB,S\n,,E\n,2MiB\n,2MiB\n")
p = mk("gpt-badprimary", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); patch(p, 512, b"\0" * 8)
p = mk("gpt-badentrycrc", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); flip(p, 1024 + 5)
p = mk("gpt-badalt", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); flip(p, (16 << 20) - 512 + 30)
import zlib
def fixcrc(p, off):
    """recompute the CRC of the GPT header at byte offset off"""
    with open(p, "r+b") as f:
        f.seek(off); h = bytearray(f.read(92)); h[16:20] = b"\0\0\0\0"
        h[16:20] = struct.pack("<I", zlib.crc32(bytes(h)) & 0xffffffff); f.seek(off); f.write(bytes(h))
alt = (16 << 20) - 512
p = mk("gpt-guidmismatch", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); flip(p, alt + 58); fixcrc(p, alt)
p = mk("gpt-usablemismatch", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); flip(p, alt + 40); fixcrc(p, alt)
p = mk("gpt-sizemismatch", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); patch(p, alt + 80, struct.pack("<I", 64)); fixcrc(p, alt)
p = mk("gpt-altnotatend", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); patch(p, 512 + 32, struct.pack("<Q", 30000)); fixcrc(p, 512)
p = mk("gpt-bothbad", "label: gpt\n,2MiB,L\n,4MiB,S\n,,U\n"); patch(p, 512, b"\0" * 8); patch(p, (16 << 20) - 512, b"\0" * 8)
p = mk("pmbr-garbage", None); patch(p, 446 + 4, bytes([0xEE])); patch(p, 446 + 8, struct.pack("<I", 1)); patch(p, 510, b"\x55\xaa")
p = mk("random", None); random.seed(7); patch(p, 0, bytes(random.getrandbits(8) for _ in range(65536)))
PY
rc=0
# Lines the kernel prints without any disk (the Rust build's libtest exercises the GPT warnings on purpose): boot each build once with no disk and subtract those lines, one for one, from every disk run.
for b in "${builds[@]}"; do
    rig/boot.sh "$root/$b" > "$dir/nodisk.$b.out" 2>&1
    grep -a -E "^\[ *[0-9.]+\] +(vda:|GPT|Alternate GPT|Primary GPT)" "logs/boot-$b.log" | sed -E 's/^\[ *[0-9.]+\] +//' | tr -d '\r' > "$dir/nodisk.$b.base"
done
subtract() {  # subtract <base> <file>: print <file> minus the lines of <base>, each removed once
    python3 - "$1" "$2" <<'PY'
import sys, collections
base = collections.Counter(open(sys.argv[1], errors="replace").read().split("\n"))
for l in open(sys.argv[2], errors="replace").read().split("\n"):
    if l and base[l] > 0: base[l] -= 1; continue
    print(l)
PY
}
for img in gpt mbr gpt-badprimary gpt-badentrycrc gpt-badalt gpt-guidmismatch gpt-usablemismatch gpt-sizemismatch gpt-altnotatend gpt-bothbad pmbr-garbage random; do
    for b in "${builds[@]}"; do
        BOOT_DISK="$dir/$img.img" rig/boot.sh "$root/$b" > "$dir/$img.$b.out" 2>&1
        LOG="logs/boot-$b.log"
        { grep -a "RIG: part " "$LOG" | sed 's/^.*RIG: part //'; grep -a -E "^\[ *[0-9.]+\] +(vda:|GPT|Alternate GPT|Primary GPT)" "$LOG" | sed -E 's/^\[ *[0-9.]+\] +//' | tr -d '\r' > "$dir/$img.$b.raw"; subtract "$dir/nodisk.$b.base" "$dir/$img.$b.raw"; } | tr -d '\r' > "$dir/$img.$b.res"
    done
    first=${builds[0]}; same=1
    for b in "${builds[@]:1}"; do cmp -s "$dir/$img.$first.res" "$dir/$img.$b.res" || same=0; done
    n=$(grep -c -E "^ +[0-9]+ +[0-9]+ +[0-9]+ +vda[0-9]+" "$dir/$img.$first.res")
    if [ $same = 1 ]; then printf '%-18s same  (%d partitions)  %s\n' "$img" "$n" "$(grep -a -E '^(vda:|GPT|Alternate|Primary)' "$dir/$img.$first.res" | head -2 | tr '\n' '|')"
    else printf '%-18s DIFFER -- diff %s %s\n' "$img" "$dir/$img.$first.res" "$dir/$img.${builds[1]}.res"; rc=1; fi
done
exit $rc
