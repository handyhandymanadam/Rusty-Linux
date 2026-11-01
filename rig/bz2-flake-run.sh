#!/usr/bin/env bash
# bz2-flake-run.sh <build-dir> <N> <tag> [cmdline]  -- N boots, classify each from the serial log.
cd "$(dirname "$0")/.."; B=$1; N=$2; TAG=$3; CL=${4:-slub_debug=FZPU}
D=/tmp/claude-1000/flake-$TAG; mkdir -p $D; : > $D/summary
for i in $(seq 1 $N); do
  BZ_APPEND="$CL" BZ_LOG=$D/$i.log rig/boot-cmdline.sh $B 120 >/dev/null 2>&1
  L=$D/$i.log
  di=$(grep -c 'bunzip2: Data integrity error' $L)
  bad=$(grep -cE 'BUG kmalloc|Redzone overwritten|Padding overwritten|Object corrupt|Freepointer corrupt|slab error' $L)
  oops=$(grep -cE 'Oops|Kernel panic|general protection|BUG:' $L)
  done_=$(grep -c 'RIG: done' $L)
  lt=$(grep -o 'libtest: [0-9]* self-tests passed, [0-9]* failed' $L | tail -1)
  echo "$i load=$(cut -d' ' -f1 /proc/loadavg) integrity_msg=$di slub_errs=$bad oops=$oops done=$done_ [$lt]" >> $D/summary
done
echo FINISHED >> $D/summary
