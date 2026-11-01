#!/usr/bin/env bash
# cmp.sh <bzImage> <tag>: runs the 3 boots, compares with C baseline
cd /tmp/rmart; BZ=$1; T=$2
./vga.sh $BZ $T-ask 6 - "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200" > $T-ask.txt
./vga.sh $BZ $T-ret 6 ret "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200" > $T-ret.txt
./vga.sh $BZ $T-boot 20 - "console=ttyS0 panic=-1 loglevel=7 debug earlyprintk=serial,ttyS0,115200" > /dev/null
for k in ask ret; do cmp C-$([ $k = ask ] && echo ask || echo ask-ret).txt $T-$k.txt && echo "VGA $k identical to C ($(wc -l < $T-$k.txt) lines)"; done
diff <(grep -a "BIOS-e820\|early console in setup\|RIG: init" C.serial) <(grep -a "BIOS-e820\|early console in setup\|RIG: init" $T-boot.serial) && echo "serial e820/early-console/init lines identical ($(grep -ac 'BIOS-e820' $T-boot.serial) e820 lines)"
