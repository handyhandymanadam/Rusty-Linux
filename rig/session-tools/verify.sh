cd ~/Claude/rusty-linux-private
S=/tmp/claude-1000/-home-adam-Claude-rusty-linux-private/8899d7a1-0a09-44c7-84ec-a89db821638d/scratchpad
source ./kbuild-env.sh
rm -f logs/apply-check-*.log
rig/apply.sh 2>&1 | tail -1
echo "== codec-check (all 7, Rust path)"; rig/codec-check.sh 2>&1 | grep -v objtool
echo "== CONFIG_RUST=n for each codec the helpers touched"
for c in XZ ZSTD LZO BZIP2 GZIP LZMA LZ4; do
  b=build-codec
  cp build-fast/.config $b/.config
  for o in GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD; do sed -i "/^CONFIG_KERNEL_$o=/d;/^# CONFIG_KERNEL_$o is not set/d" $b/.config; done
  echo "CONFIG_KERNEL_$c=y" >> $b/.config; echo "CONFIG_RD_$c=y" >> $b/.config
  src/linux/scripts/config --file $b/.config --disable RUST
  kmake O="$PWD/$b" olddefconfig >/dev/null 2>&1
  r=$(grep -c '^CONFIG_RUST=y' $b/.config)
  kmake O="$PWD/$b" -j8 > $b/norust-$c.log 2>&1; rc=$?
  if [ $rc != 0 ]; then v="BUILD FAILED (not booting a stale image)"; else v=$(rig/boot.sh $b 200 2>&1 | grep -E 'init |userspace ' | tr -s ' ' | tr '\n' ';'); fi
  echo "norust $c: RUST=y lines=$r build rc=$rc $v"
done
echo "== gate"; bash $S/gate.sh 2>&1 | grep -E 'rc=|init|userspace |CHANGED|ADDED|REMOVED|matched'
echo VERIFY-DONE
