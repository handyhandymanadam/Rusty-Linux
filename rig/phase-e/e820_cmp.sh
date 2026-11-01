#!/usr/bin/env bash
# Userspace differential for e820_rs.rs (+ the real e820_glue.c wrappers) vs the REAL C of the pristine e820.c.
#   e820_cmp.sh [--sabotage] [--tie]      env: N cases per config (default 30000), EMAXES="5 12 131 320", HPS="0 1"
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${E820_RS:-$root/port/tree/arch/x86/kernel/e820_rs.rs}
GLUE=${E820_GLUE:-$root/port/tree/arch/x86/kernel/e820_glue.c}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
mkdir -p "$out/fake/linux"; for h in types export sort sched; do : > "$out/fake/linux/$h.h"; done
python3 "$here/e820_gen.py" "$root/port/pristine/arch/x86/kernel/e820.c" "$GLUE" "$root/port/pristine/lib/cmdline.c" "$out"
RENAMES=""
for n in e820_table e820_table_kexec e820_table_firmware pci_mem_start e820__mapped_raw_any e820__mapped_any e820__mapped_all e820__get_entry_type \
         e820__range_add e820__print_table e820__update_table e820__range_update e820__range_update_table e820__range_remove \
         e820__update_table_print e820__setup_pci_gap e820__end_of_ram_pfn e820__end_of_low_ram_pfn e820__memory_setup_default; do
    RENAMES="$RENAMES -D$n=c_$n"
done
CF="-O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -Wno-unused-variable -I$here"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1)"
build() {   # build <emax> <hp> <rs> <exe> [glue]
    local e=$1 h=$2 rs=$3 exe=$4 glue=${5:-$out/glue.inc} cfg=()
    [ "$h" = 1 ] && cfg=(--cfg CONFIG_MEMORY_HOTPLUG)
    cc $CF -DEMAX=$e -DHP=$h -DREFINC="\"$out/ref.inc\"" $RENAMES -c -o "$exe.ref.o" "$here/e820_ref.c"
    cc $CF -DEMAX=$e -DHP=$h -DGLUEINC="\"$glue\"" -c -o "$exe.gl.o" "$here/e820_gl.c"
    cc $CF -DEMAX=$e -DHP=$h -DMEMPARSE_INC="\"$out/memparse.inc\"" -c -o "$exe.env.o" "$here/e820_env.c"
    cc $CF -DEMAX=$e -DHP=$h -I"$out/fake" -DSORTC="\"$root/port/pristine/lib/sort.c\"" -c -o "$exe.sort.o" "$here/e820_sort.c"
    sed "s|E820RS|$rs|" "$here/e820_cmp.rs" > "$exe.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test "${cfg[@]}" \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$exe.ref.o" -C link-arg="$exe.gl.o" -C link-arg="$exe.env.o" -C link-arg="$exe.sort.o" \
        --crate-name e820cmp -o "$exe" "$exe.cmp.rs" 2>&1 | grep -E "^error" -A8 || true
}
if [ "${1:-}" != "--sabotage" ]; then
  for e in ${EMAXES:-5 12 131 320}; do for h in ${HPS:-0 1}; do
    echo "== EMAX=$e HOTPLUG=$h"
    build $e $h "$RS" "$out/t"
    if [ "${1:-}" = "--tie" ]; then TIE=1 N=${N:-30000} "$out/t" || echo "TIE-ORDER DEPENDENCE FOUND (informational)"; else N=${N:-30000} "$out/t"; fi
  done; done
else
python3 "$here/e820_mutants.py" "$RS" "$GLUE" "$out" "$KB_RUSTC" "$here" "$root"
fi
