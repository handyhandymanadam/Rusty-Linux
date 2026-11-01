#!/usr/bin/env bash
# rmcmp.sh BZ_A BZ_B -- real-mode behaviour comparison of two bzImages under QEMU legacy BIOS + KVM (rig/realmode/ style):
# (1) vga=ask: the video-mode MENU is drawn by the real-mode setup through BIOS calls (intcall), VGA text memory dumped and diffed;
# (2) the same after pressing Return (boots on with the default mode); (3) a normal boot: the serial log's BIOS-e820 lines
# (memory.c's INT 15h calls through bioscall.S), the early console line and the init marker are diffed.
set -u
here=$(cd "$(dirname "$0")" && pwd); A=$(readlink -f $1); B=$(readlink -f $2); D=$here/../../tmp-rmasm/rmcmp; rm -rf $D; mkdir -p $D
for t in a b; do bz=$A; [ $t = b ] && bz=$B
  $here/vga.sh $bz $D/$t-ask 6 - "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200" > $D/$t-ask.txt
  $here/vga.sh $bz $D/$t-ret 6 ret "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200" > $D/$t-ret.txt
  $here/vga.sh $bz $D/$t-boot 20 - "console=ttyS0 panic=-1 loglevel=7 debug earlyprintk=serial,ttyS0,115200" > /dev/null
done
for k in ask ret; do cmp $D/a-$k.txt $D/b-$k.txt && echo "VGA $k: identical ($(wc -l < $D/b-$k.txt) text lines)"; done
head -3 $D/b-ask.txt
diff <(grep -a "BIOS-e820\|early console in setup\|RIG: init" $D/a-boot.serial) <(grep -a "BIOS-e820\|early console in setup\|RIG: init" $D/b-boot.serial) && echo "serial e820 / early-console / init lines identical ($(grep -ac 'BIOS-e820' $D/b-boot.serial) e820 lines, $(grep -ac 'early console in setup' $D/b-boot.serial) early-console, $(grep -ac 'RIG: init' $D/b-boot.serial) init)"
