#!/usr/bin/env bash
# trial.sh [-p pf] [-s FILE SEDEXPR]... [-t SECONDS] -- SABOTAGE / REACH trial on build-fast, always restored afterwards.
#   -s FILE SEDEXPR  edit port/tree/arch/x86/boot/compressed/FILE with sed (a no-op edit is an error): the "sabotage"
#   -p pf            probe: misc_rs.rs extract_kernel() first reads an UNMAPPED address (0x1_8000_0000), which raises a #PF
#                    that only the stub's stage-2 IDT -> boot_page_fault (idt_handlers_64) -> do_boot_page_fault can survive
#   -B DIR           build dir to trial in (default build-fast; build-amd for mem_encrypt)
#   -e               boot under OVMF (BOOT_EFI=1): the stub is entered through efi_pe_entry -> startup_64 (the 64-bit entry)
#   -l               also run rig/stubh/la57boot.sh (TCG -cpu max): the running kernel reports whether the stub's 4->5-level trampoline ran
#   Prints: object comparison verdict for each sabotaged file (check.sh with the edited copy), then apply+build+boot verdict.
#   The tree is restored (files, apply.sh, rebuild) on exit -- the last lines say so.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
C=port/tree/arch/x86/boot/compressed; B=build-fast; secs=60; probe=; la57=; declare -a files seds
while [ $# -gt 0 ]; do case $1 in -p) probe=$2; shift 2;; -s) files+=("$2"); seds+=("$3"); shift 3;; -t) secs=$2; shift 2;; -B) B=$2; shift 2;; -l) la57=1; shift;; -e) export BOOT_EFI=1; shift;; *) echo bad arg $1; exit 2;; esac; done
bk=$(mktemp -d); W=$(mktemp -d)
restore() { for f in "${files[@]}" misc_rs.rs; do [ -f $bk/$f ] && cp $bk/$f $C/$f; done; rig/apply.sh >/dev/null 2>&1; kmake O="$root/$B" -j4 >$root/logs/stubh-trial-restore.log 2>&1; echo "RESTORED tree (apply + rebuild rc=$?)"; rig/apply.sh --check >/dev/null 2>&1 && echo "apply --check clean"; rm -rf $bk $W; }
trap restore EXIT
cp $C/misc_rs.rs $bk/misc_rs.rs
for i in "${!files[@]}"; do f=${files[$i]}; cp $C/$f $bk/$f; sed -i "${seds[$i]}" $C/$f
  if cmp -s $C/$f $bk/$f; then echo "SABOTAGE DID NOT CHANGE $f"; exit 2; fi
  cp $C/$f $W/$f; echo "--- sabotaged $f: $(diff $bk/$f $C/$f | grep '^[<>]' | tr '\n' ' ' | cut -c1-200)"
done
if [ -n "${files:-}" ]; then echo "--- object comparison with the sabotaged file(s):"; for f in "${files[@]}"; do n=${f%_rs.rs}; n=${n//_/_}; rig/stubh/check.sh -b build-fast -w $W "^${n//-/.}(\$|\+)" 2>&1 | head -6; done; fi
if [ "$probe" = pf ]; then
  python3 - <<'PY'
p='port/tree/arch/x86/boot/compressed/misc_rs.rs'
t=open(p).read()
k='        virt_addr = misc_load_physical_addr;\n'
assert k in t
t=t.replace(k,k+'        // STUBH reach probe (rig/stubh/trial.sh -p pf): fault on an unmapped address; only boot_page_fault can map it\n        core::ptr::read_volatile(0x1_8000_0000usize as *const u32);\n',1)
open(p,'w').write(t)
PY
fi
rig/apply.sh >/dev/null 2>&1
kmake O="$root/$B" -j4 >logs/stubh-trial.log 2>&1; echo "trial build rc=$?"
rig/boot.sh $B $secs 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit'
[ -n "$la57" ] && { echo '--- la57 probe (TCG -cpu max):'; LIMIT=$secs rig/stubh/la57boot.sh $B; }
