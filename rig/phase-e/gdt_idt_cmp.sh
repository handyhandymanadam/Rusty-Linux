#!/usr/bin/env bash
# Userspace differential for gdt_idt_rs.rs (interrupt_gate vs the kernel's C). --sabotage: mutate the
# Rust and require the comparison to fail for every mutant.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
cc -O2 -c -o "$out/ref.o" "$here/gdt_idt_ref.c"
build() { "$KB_RUSTC" --edition 2021 -O -C panic=abort --cfg CONFIG_AMD_MEM_ENCRYPT -C link-arg="$out/ref.o" -o "$2" "$1"; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$here/gdt_idt_cmp.rs" "$out/t"
"$out/t"
if [ "${1:-}" = "--sabotage" ]; then
  python3 - "$root" "$out" "$KB_RUSTC" <<'PY'
import subprocess, sys, os
root, out, rustc = sys.argv[1:4]
src = open(f"{root}/port/tree/arch/x86/boot/startup/gdt_idt_rs.rs").read()
cmp_ = open(f"{root}/rig/phase-e/gdt_idt_cmp.rs").read().replace("../../port/tree/arch/x86/boot/startup/gdt_idt_rs.rs", f"{out}/m.rs")
M = [("type-trap", "const GATE_INTERRUPT: u64 = 0xE;", "const GATE_INTERRUPT: u64 = 0xF;"),
     ("segment", "const KERNEL_CS: u64 = 0x10;", "const KERNEL_CS: u64 = 0x08;"),
     ("p-bit", "(GATE_INTERRUPT << 8) | (1 << 15)", "(GATE_INTERRUPT << 8)"),
     ("mid-shift", "((address >> 16) & 0xffff) << 48", "((address >> 17) & 0xffff) << 48"),
     ("high-shift", "hi: address >> 32,", "hi: address >> 31,"),
     ("low-mask", "(address & 0xffff) | (KERNEL_CS", "(address & 0x7fff) | (KERNEL_CS"),
     ("ist", "(GATE_INTERRUPT << 8) | (1 << 15)", "(GATE_INTERRUPT << 8) | (1 << 15) | 1")]
caught = 0
for name, a, b in M:
    assert a in src, a
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1)); open(f"{out}/cmp_m.rs", "w").write(cmp_)
    r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "--cfg", "CONFIG_AMD_MEM_ENCRYPT",
                        "-C", f"link-arg={out}/ref.o", "-o", f"{out}/m", f"{out}/cmp_m.rs"], capture_output=True)
    if r.returncode: print(f"mutant {name}: DID NOT COMPILE\n{r.stderr.decode()[:400]}"); sys.exit(1)
    r = subprocess.run([f"{out}/m"], env={**os.environ, "N": "2000000"}, capture_output=True)
    if r.returncode: caught += 1; print(f"mutant {name}: caught")
    else: print(f"mutant {name}: *** NOT CAUGHT")
print(f"sabotage: {caught} of {len(M)} mutants caught"); sys.exit(0 if caught == len(M) else 1)
PY
fi
