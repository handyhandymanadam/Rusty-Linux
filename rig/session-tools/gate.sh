cd ~/Claude/rusty-linux-private
source ./kbuild-env.sh
rig/apply.sh 2>&1 | tail -2
for b in build-fast build-full; do
  kmake O="$PWD/$b" -j12 2>&1 | grep -E 'error|warning: unused|BUILD-|Kernel:' | tail -5
  echo "$b build rc=${PIPESTATUS[0]}"
  rig/boot.sh $b 180 2>&1 | grep -E 'init|userspace|rust-ran|faults'
  rig/crc-check.sh $b 2>&1 | tail -5
done
echo GATE-DONE
