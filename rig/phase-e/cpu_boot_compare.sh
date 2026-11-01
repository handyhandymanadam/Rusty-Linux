#!/usr/bin/env bash
# cpu_boot_compare.sh [fast|full|both]     (NOT RUN by wt-pe5: rig/boot-cmdline.sh holds `rm -rf "$TMP"` for Adam's approval; the lead runs it)
#
# The CPU oracle for the common.c early group (CPUID decode, get_cpu_vendor, get_cpu_cap, early_identify_cpu, cpu_set_bug_bits). Boots the unmodified-C
# kernel (build-<cfg>-base of the main checkout) and the ported kernel (build-<cfg> of the tree this is run in) under several QEMU CPU models
# (TCG, so that the model is the CPUID the kernel sees; `host` under KVM too when /dev/kvm is writable) with `rig_cpuinfo` on the command line, and
# diffs, with the timestamps stripped:
#   * the CPU lines of the boot log: `x86/fpu`, `Hypervisor detected`, `CPU:`, `x86/CPU`, `x86/cpu`, the Spectre / Speculative / Retbleed / MDS / TAA / L1TF /
#     SRBDS / GDS / ITS / RFDS / BHI / SRSO / TSA / VMSCAPE / mitigation / Vulnerable lines, `Last level iTLB/dTLB`, `microcode`, `PTI`, `Memory Encryption`,
#     `clearcpuid` / `setcpuid` / `unknown CPU flag`, `Booting paravirtualized kernel`, `KERNEL supported cpus`
#   * `RIG: cpuinfo ...` (the first CPU block of /proc/cpuinfo: vendor_id, cpu family, model, stepping, flags, bugs, address sizes, clflush size,
#     cache_alignment) and `RIG: vuln ...` (every file of /sys/devices/system/cpu/vulnerabilities/): printed by rig/init when `rig_cpuinfo` is on the command
#     line (a marked rig change, logs/custom-messages.md)
# Each (config, model, command line) is one pair of boots. Prints one line per pair and N; exits 1 on the first difference found in ANY pair (all pairs are
# still run and printed). A model on which neither kernel prints a Linux banner is reported as `skip` (QEMU TCG could not start it), not as a pass.
# Env: MODELS="qemu64 max ..." to choose the models, CMDLINES_ALL=1 to run every extra command line on every model (default: on qemu64, max, EPYC only),
#      TIMEOUT (default 120 s per boot), SCRATCH (logs), MAIN_CHECKOUT (default /home/adam/Claude/rusty-linux-private).
# Needs: rig/boot-cmdline.sh (BZ_APPEND, BZ_LOG, BOOT_TCG, BOOT_CPU), qemu-system-x86_64, the build dirs. Run it from the worktree root.
# Usage:  rig/phase-e/cpu_boot_compare.sh both        # ~ 2 configs x 16 models x (1 + extra lines) x 2 boots
set -u
root=$(cd "$(dirname "$0")/../.." && pwd)
main=${MAIN_CHECKOUT:-/home/adam/Claude/rusty-linux-private}
which=${1:-both}
scratch=${SCRATCH:-/home/adam/Claude/tmp-pe5/cpu-boot}; mkdir -p "$scratch"
tmo=${TIMEOUT:-120}
avail=$(qemu-system-x86_64 -cpu help | awk '/^  [A-Za-z]/ {print $1}')
# 64-bit capable models only (the kernel stops at "This kernel requires an x86-64 CPU" on 486, pentium*, athlon, coreduo, n270, ...): Intel / AMD / Hygon / generic
wanted=${MODELS:-"qemu64 kvm64 max Nehalem Westmere SandyBridge IvyBridge Haswell Broadwell Skylake-Client Skylake-Server Cascadelake-Server Icelake-Server SapphireRapids Opteron_G1 Opteron_G2 Opteron_G3 Opteron_G4 Opteron_G5 phenom EPYC EPYC-Milan EPYC-Genoa Dhyana Conroe Penryn Denverton Snowridge"}
models=(); for m in $wanted; do if echo "$avail" | grep -qx "$m"; then models+=("$m"); else echo "note: model $m not in this QEMU ($(qemu-system-x86_64 --version | head -1)), left out"; fi; done
[ -w /dev/kvm ] && models+=(host)
# extra command lines: the parsers of the early group (clearcpuid= / setcpuid= / noxsave...), the FRED gate, and a made-up unknown flag
extra=("clearcpuid=avx,xsave,mwait" "noxsave noxsaveopt noxsaves nousershstk fred=on" "setcpuid=hypervisor,5 clearcpuid=703,bogus,spectre_v1,32" "clearcpuid=la57 nopti")
pat='x86/fpu|Hypervisor detected|CPU:|x86/CPU|x86/cpu|Spectre|Speculative|Retbleed|MDS|TAA|L1TF|SRBDS|GDS|ITS|RFDS|BHI|SRSO|TSA|VMSCAPE|mitigation|Mitigation|Vulnerable|Last level|microcode|PTI|Memory Encryption|clearcpuid|setcpuid|unknown CPU flag|Booting paravirtualized|KERNEL supported cpus|RIG: cpuinfo|RIG: vuln|FRED|Tainting|TAINT'
filt() { sed -E 's/^\[ *[0-9]+\.[0-9]+\] //' "$1" | grep -E "$pat" | grep -vE '^(WARNING: CPU:|CPU: [0-9]+ UID:)'; }  # the port kernel carries libtest, whose deliberate WARN self-tests print these lines (the C base has none)
n=0; bad=0; skipped=0; samelines=0
for cfg in $( [ "$which" = both ] && echo "fast full" || echo "$which" ); do
  for m in "${models[@]}"; do
    lines=("")
    if [ -n "${CMDLINES_ALL:-}" ] || [ "$m" = qemu64 ] || [ "$m" = max ] || [ "$m" = EPYC ]; then lines+=("${extra[@]}"); fi
    for i in "${!lines[@]}"; do
      a="rig_cpuinfo ${lines[$i]}"
      for side in base port; do
        d=$([ $side = base ] && echo "$main/build-$cfg-base" || echo "$root/build-$cfg")
        if [ "$m" = host ]; then BZ_APPEND="$a" BZ_LOG="$scratch/$cfg-$m-$side-$i.log" "$root/rig/boot-cmdline.sh" "$d" "$tmo" > "$scratch/$cfg-$m-$side-$i.report" 2>&1
        else BOOT_TCG=1 BOOT_CPU="$m" BZ_APPEND="$a" BZ_LOG="$scratch/$cfg-$m-$side-$i.log" "$root/rig/boot-cmdline.sh" "$d" "$tmo" > "$scratch/$cfg-$m-$side-$i.report" 2>&1; fi
        filt "$scratch/$cfg-$m-$side-$i.log" > "$scratch/$cfg-$m-$side-$i.cpu"
      done
      n=$((n+1)); tag="$cfg $m #$i ${lines[$i]:0:40}"
      if ! grep -q "Linux version" "$scratch/$cfg-$m-base-$i.log" && ! grep -q "Linux version" "$scratch/$cfg-$m-port-$i.log"; then echo "skip  $tag (neither kernel started on this model)"; skipped=$((skipped+1)); continue; fi
      if [ ! -s "$scratch/$cfg-$m-base-$i.cpu" ] || [ ! -s "$scratch/$cfg-$m-port-$i.cpu" ]; then echo "DIFF  $tag  one kernel printed no CPU lines: base $(wc -l < "$scratch/$cfg-$m-base-$i.cpu"), port $(wc -l < "$scratch/$cfg-$m-port-$i.cpu")"; bad=$((bad+1)); continue; fi
      if diff -u "$scratch/$cfg-$m-base-$i.cpu" "$scratch/$cfg-$m-port-$i.cpu" > "$scratch/$cfg-$m-$i.diff"; then
        k=$(wc -l < "$scratch/$cfg-$m-port-$i.cpu"); samelines=$((samelines+k))
        echo "same  $tag ($k CPU lines, bugs: $(grep -m1 'RIG: cpuinfo bugs' "$scratch/$cfg-$m-port-$i.cpu" | cut -c1-70), init: $(grep -c 'RIG: done' "$scratch/$cfg-$m-port-$i.log") reached userspace)"
      else echo "DIFF  $tag"; head -30 "$scratch/$cfg-$m-$i.diff"; bad=$((bad+1)); fi
    done
  done
done
echo "cpu_boot_compare: N=$n pairs (config x model x command line), $bad differ, $skipped skipped, $samelines CPU lines compared"
[ $bad = 0 ]
