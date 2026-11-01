#!/usr/bin/env bash
# check.sh [-w WIPDIR] [NAME-regex] -- the RMASM object-level contract for every line of variants.txt: assemble the ORIGINAL .S with
# the kernel's own flags (from its .cmd), build the Rust object with the Makefile's real-mode rustc flags, run consts_check.py (once
# per Rust file and build) and objcmp.py twice (llvm-objdump -M i8086, and the default 32-bit view; byte contents/symbols/relocations
# are compared either way). Rust files are looked up in WIPDIR first, then port/tree/. Per-variant output in tmp-rmasm/check/NAME.txt;
# one summary line each here. Exit 1 on any failure.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"
W=tmp-rmasm/wip
while getopts w: o; do case $o in w) W=$OPTARG;; esac; done; shift $((OPTIND-1))
pat=${1:-.}
O=tmp-rmasm/check; mkdir -p $O $W
rc=0; declare -A seen
while IFS='|' read -r name B cmd src rs oargs rargs zox; do
  name=$(echo $name); case $name in ''|\#*) continue;; esac
  [[ $name =~ $pat ]] || continue
  B=$(echo $B); cmd=$(echo $cmd); src=$(echo $src); rs=$(echo $rs); oargs=${oargs//@ROOT@/$root}; rargs=${rargs//@ROOT@/$root}; zox=$(echo $zox)
  f=port/tree/$rs; [ -f "$W/$(basename $rs)" ] && f=$W/$(basename $rs)
  eval "$(rig/rmasm/envs.sh $B)"
  auto=$(rig/rmasm/envs.sh $B --cfgs)
  # per-variant header inputs: a copy of the build's zoffset.h (+ extras) is found by the .S through -iquote, and the same file feeds rmasm_consts.sh
  T=$O/$name.in; rm -rf $T; mkdir -p $T; cp $B/arch/x86/boot/zoffset.h $T/zoffset.h
  for kv in ${zox//,/ }; do printf '#define %s %s\n' "${kv%%=*}" "${kv#*=}" >> $T/zoffset.h; done
  sh port/tree/arch/x86/boot/rmasm_consts.sh $T/zoffset.h $B/arch/x86/boot/voffset.h > $T/zo.rs
  export RMASM_ZO_RS=$root/$T/zo.rs
  oargs="-iquote $root/$T $oargs"
  # variant overrides win over the build's cfg flags: a `--cfg=!name` in rargs drops it from $auto
  for d in $(printf '%s\n' $rargs | sed -n 's/^--nocfg=//p'); do auto=${auto//--cfg=$d/}; done
  noconsts=; [[ " $rargs " == *" --noconsts "* ]] && noconsts=1   # a variant whose headers cannot be evaluated as constants (x86_32: PMD_SHIFT is not a number there)
  rargs="$auto $(printf '%s\n' $rargs | grep -v '^--nocfg=\|^--noconsts$' | tr '\n' ' ')"
  {
    echo "### $name: build=$B orig=$src rust=$f orig-args=[$oargs] rust-args=[$rargs]"
    if [ -n "$noconsts" ]; then echo "consts_check: SKIPPED for this variant (--noconsts; the 64-bit variants check every const; the object comparison covers the bytes)"
    elif [ -z "${seen[$rs@$B]:-}" ]; then seen[$rs@$B]=1
      env $(printf '%s\n' $rargs | grep '^[A-Z_0-9]*=') python3 rig/stubh/consts_check.py $B $cmd $f $oargs || echo "CONSTS-FAILED"
    fi
    python3 rig/stubh/orig_asm.py $B $cmd src/linux/$src $O/$name.orig.o $oargs -g0 || echo "ORIG-ASM-FAILED"
    rig/rmasm/rust_obj.sh $B $f $O/$name.rust.o $rargs || echo "RUSTC-FAILED"
    echo "--- objcmp, GNU objdump -M i8086 (independent 16-bit decoder; .text32 of pmjump is 32-bit code, covered by the next two passes)"
    OBJCMP_OBJDUMP=objdump OBJCMP_OBJDUMP_ARGS="-M i8086" python3 rig/stubh/objcmp.py $O/$name.orig.o $O/$name.rust.o
    echo "--- objcmp, llvm-objdump --mattr=+16bit-mode"
    OBJCMP_OBJDUMP_ARGS="--mattr=+16bit-mode" python3 rig/stubh/objcmp.py $O/$name.orig.o $O/$name.rust.o
    echo "--- objcmp, llvm-objdump default (32-bit) view"
    python3 rig/stubh/objcmp.py $O/$name.orig.o $O/$name.rust.o
  } > $O/$name.txt 2>&1
  if [ "$(grep -c '^RESULT: IDENTICAL' $O/$name.txt)" != 3 ] || grep -q 'FAILED' $O/$name.txt || grep -Eq 'consts_check: [0-9]+ constants, [1-9]' $O/$name.txt; then rc=1; echo "FAIL  $name   (see $O/$name.txt)"; else echo "OK    $name   $(grep -c '^IDENTICAL' $O/$name.txt) identical groups, consts: $(grep -h 'consts_check' $O/$name.txt | tr '\n' ' ')"; fi
done < rig/rmasm/variants.txt
exit $rc
