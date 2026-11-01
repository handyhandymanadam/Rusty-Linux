#!/usr/bin/env bash
# trial.sh [-o] [-B BUILD] [-t SECONDS] -f FILE_rs.rs -s SEDEXPR [-v VARIANT-REGEX] -- SABOTAGE trial, always restored afterwards.
#   -f/-s   edit port/tree/arch/x86/boot/FILE with sed (a no-op edit is an error)
#   -v      the variants.txt name regex to object-compare (default: ^<file base>$)
#   -o      object comparison only (no build/boot)
#   Prints: the object comparison verdict for the sabotaged copy (it must say FAIL), then apply + build + boot verdict on BUILD
#   (default build-fast; a boot under QEMU legacy BIOS: rig/boot.sh), then restores the tree (apply + rebuild) and says so.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
R=port/tree/arch/x86/boot; B=build-fast; secs=90; obj=; f=; sedx=; v=
while getopts oB:t:f:s:v: o; do case $o in o) obj=1;; B) B=$OPTARG;; t) secs=$OPTARG;; f) f=$OPTARG;; s) sedx=$OPTARG;; v) v=$OPTARG;; esac; done
[ -n "$f" ] && [ -n "$sedx" ] || { echo "need -f and -s"; exit 2; }
v=${v:-^${f%_rs.rs}\$}
bk=$(mktemp -d); W=$(mktemp -d); cp $R/$f $bk/$f
restore() { cp $bk/$f $R/$f; if [ -z "$obj" ]; then rig/apply.sh >/dev/null 2>&1; kmake O="$root/$B" -j4 >$root/logs/rmasm-trial-restore.log 2>&1; echo "RESTORED tree (apply + rebuild rc=$?)"; rig/apply.sh --check >/dev/null 2>&1 && echo "apply --check clean"; else echo "RESTORED $f (object-only trial)"; fi; cmp -s $bk/$f $R/$f && echo "$f identical to the saved original"; rm -rf $bk $W; }
trap restore EXIT
sed -i "$sedx" $R/$f
if cmp -s $R/$f $bk/$f; then echo "SABOTAGE DID NOT CHANGE $f"; exit 2; fi
cp $R/$f $W/$f; echo "--- sabotaged $f: $(diff $bk/$f $R/$f | grep '^[<>]' | tr '\n' ' ' | cut -c1-240)"
echo "--- object comparison with the sabotaged file:"
rig/rmasm/check.sh -w $W "$v" 2>&1 | head -6
f1=$(ls tmp-rmasm/check/*.txt 2>/dev/null | head -0)
[ -n "$obj" ] && exit 0
rig/apply.sh >/dev/null 2>&1
kmake O="$root/$B" -j4 >logs/rmasm-trial.log 2>&1; echo "trial build rc=$?"
rig/boot.sh $B $secs 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit|no bzImage|REFUSING'
