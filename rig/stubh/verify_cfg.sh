#!/usr/bin/env bash
# verify_cfg.sh BUILD_DIR... -- STUBH in a config the default gate configs do not cover (build-amd = EFI config +
# CONFIG_AMD_MEM_ENCRYPT, build-tdx = EFI config + CONFIG_INTEL_TDX_GUEST). Per dir (one build at a time, -j4):
#   build with the Rust asm objects + boot (BIOS direct kernel load, KVM)  + boot under OVMF (BOOT_EFI=1) + boot under TCG
#   build the same with `boot_asm_rust=` (original .S objects, everything else Rust) + boot BIOS: the baseline, to tell a
#   STUBH problem from a pre-existing one;   then compare the two stub ELFs and bzImages (imgcmp.sh does the on/off builds)
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
for b in "$@"; do
  echo "=== $b ($(date +%T), load $(cut -d' ' -f1 /proc/loadavg)): $(grep -E '^CONFIG_(AMD_MEM_ENCRYPT|INTEL_TDX_GUEST|RELOCATABLE|RANDOMIZE_BASE)=' $b/.config | tr '\n' ' ')"
  rig/apply.sh --check >/dev/null 2>&1 || rig/apply.sh | tail -1
  kmake O="$root/$b" -j4 >logs/stubh-cfg-$b.log 2>&1; echo "$b build (Rust asm) rc=$?"
  echo "stub objects: $(ls $b/arch/x86/boot/compressed/*_rs.o | xargs -n1 basename | tr '\n' ' ' | cut -c1-300)"
  echo "--- boot BIOS/KVM";  rig/boot.sh $b 200 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit'
  echo "--- boot OVMF/KVM";  BOOT_EFI=1 rig/boot.sh $b 200 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit'
  echo "--- boot BIOS/TCG";  BOOT_TCG=1 rig/boot.sh $b 600 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit|wall'
  echo "--- on/off image comparison"; rig/stubh/imgcmp.sh $b | grep -E 'rc=|bzImage|vmlinux|nm|dis'
  echo "--- baseline: original .S objects (boot_asm_rust=), BIOS/KVM"
  C=$b/arch/x86/boot/compressed; rm -f $C/vmlinux; kmake O="$root/$b" -j4 boot_asm_rust= >logs/stubh-cfg-$b-off.log 2>&1; echo "$b build (.S asm) rc=$?"
  rig/boot.sh $b 200 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit'
  rm -f $C/vmlinux; kmake O="$root/$b" -j4 >/dev/null 2>&1; echo "restored STUBH-on build rc=$?"
done
echo "VERIFY-CFG-DONE $*"
