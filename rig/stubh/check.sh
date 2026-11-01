#!/usr/bin/env bash
# check.sh [-b BUILD] [-w WIPDIR] [NAME-regex] -- the STUBH object-level contract for every line of variants.txt:
# assemble the ORIGINAL .S with the kernel's own flags (from its .cmd), build the Rust object with the stub's
# rustc flags, run consts_check.py (once per Rust file) and objcmp.py. Rust files are looked up in WIPDIR first,
# then port/tree/. Output per variant in tmp-stubh/check/NAME.txt; one summary line each here. Exit 1 on any failure.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"
B=build-fast; W=tmp-stubh/wip
while getopts b:w: o; do case $o in b) B=$OPTARG;; w) W=$OPTARG;; esac; done; shift $((OPTIND-1))
pat=${1:-.}
O=tmp-stubh/check; mkdir -p $O
# SBAT variant inputs: the .S gets CONFIG_EFI_SBAT_FILE from a header, the Rust gets it as an env var (see sbat_rs.rs)
printf '#define CONFIG_EFI_SBAT_FILE "%s/rig/stubh/sbat-test.csv"\n' "$root" > tmp-stubh/sbat_cfg.h
export STUBH_SBAT_FILE=$root/rig/stubh/sbat-test.csv
eval "$(rig/stubh/envs.sh $B)"   # STUBH_PHYSICAL_*/REQUIRED_MASK* for head_64_rs.rs
rc=0; declare -A seen
while IFS='|' read -r name cmd src rs oargs rargs; do
  name=$(echo $name); case $name in ''|\#*) continue;; esac
  [[ $name =~ $pat ]] || continue
  cmd=$(echo $cmd); src=$(echo $src); rs=$(echo $rs); oargs=${oargs//@ROOT@/$root}; rargs=${rargs//@ROOT@/$root}
  # the --cfg flags the Makefile derives from the build's .config (the .S side sees the same through autoconf.h); a variant that
  # #undefs a config symbol on the .S side drops the matching one here
  auto=$(rig/stubh/envs.sh $B --cfgs); [[ $oargs == *undef_fp.h* ]] && auto=${auto//--cfg=frame_pointer/}
  rargs="$auto $rargs"
  f=port/tree/$rs; [ -f "$W/$(basename $rs)" ] && f=$W/$(basename $rs)
  {
    echo "### $name: orig=$src rust=$f orig-args=[$oargs] rust-args=[$rargs]"
    if [ -z "${seen[$rs]:-}" ]; then seen[$rs]=1
      env $(printf '%s\n' $rargs | grep '^[A-Z_0-9]*=') python3 rig/stubh/consts_check.py $B $cmd $f $oargs || echo "CONSTS-FAILED"
    fi
    python3 rig/stubh/orig_asm.py $B $cmd src/linux/$src $O/$name.orig.o $oargs || echo "ORIG-ASM-FAILED"
    rig/stubh/rust_obj.sh $B $f $O/$name.rust.o $rargs || echo "RUSTC-FAILED"
    python3 rig/stubh/objcmp.py $O/$name.orig.o $O/$name.rust.o
  } > $O/$name.txt 2>&1
  if ! grep -q '^RESULT: IDENTICAL' $O/$name.txt || grep -q 'FAILED' $O/$name.txt || grep -Eq 'consts_check: [0-9]+ constants, [1-9]' $O/$name.txt; then rc=1; echo "FAIL  $name   (see $O/$name.txt)"; else echo "OK    $name   $(grep -c '^IDENTICAL' $O/$name.txt) identical groups, consts: $(grep -h 'consts_check' $O/$name.txt | tr '\n' ' ')"; fi
done < rig/stubh/variants.txt
exit $rc
