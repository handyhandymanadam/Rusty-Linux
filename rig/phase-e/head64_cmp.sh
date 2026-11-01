#!/usr/bin/env bash
# Userspace differential for head64_rs.rs (early page-fault group) vs the real C of head64.c, both arms.
#   head64_cmp.sh [--sabotage]      N env: cases per arm
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${H64_RS:-$root/port/tree/arch/x86/kernel/head64_rs.rs}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/head64_gen.py" "$root/port/pristine/arch/x86/kernel/head64.c" "$out/h.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1)"
build() {   # build <amd 0|1> <rs file> <exe>
    local a=$1 rs=$2 exe=$3 cfg=()
    [ "$a" = 1 ] && cfg=(--cfg CONFIG_AMD_MEM_ENCRYPT)
    cc -O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -DAMD=$a -I"$here" -DHEADINC="\"$out/h.inc\"" -c -o "$exe.ref.o" "$here/head64_ref.c"
    sed "s|H64RS|$rs|" "$here/head64_cmp.rs" > "$exe.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test "${cfg[@]}" \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$exe.ref.o" --crate-name h64cmp -o "$exe" "$exe.cmp.rs" 2>&1 | grep -E "^error" -A6 || true
}
for a in 0 1; do
    echo "== arm AMD=$a"
    build $a "$RS" "$out/t$a"
    "$out/t$a"
done
if [ "${1:-}" = "--sabotage" ]; then
  python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys, os
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("max-bits-l4", "const MAX_PHYSMEM_BITS_L4: u32 = 46;", "const MAX_PHYSMEM_BITS_L4: u32 = 47;"),
 ("max-bits-l5", "const MAX_PHYSMEM_BITS_L5: u32 = 52;", "const MAX_PHYSMEM_BITS_L5: u32 = 51;"),
 ("maxmem-cmp", "if physaddr >= maxmem ||", "if physaddr > maxmem ||"),
 ("cr3-check", "env.read_cr3_pa() != env.pa_nodebug", "env.read_cr3_pa() == env.pa_nodebug"),
 ("start-map", "const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_0000;", "const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_1000;"),
 ("kernpg-flags", "const KERNPG_TABLE_NOENC: u64 = 0x63;", "const KERNPG_TABLE_NOENC: u64 = 0x67;"),
 ("early-tables", "const EARLY_DYNAMIC_PAGE_TABLES: u32 = 64;", "const EARLY_DYNAMIC_PAGE_TABLES: u32 = 63;"),
 ("pmd-mask", "const PMD_MASK: u64 = !((1u64 << PMD_SHIFT) - 1);", "const PMD_MASK: u64 = !((1u64 << 20) - 1);"),
 ("pfn-mask", "const PAGE_MASK: i64 = -4096;", "const PAGE_MASK: i64 = -8192;"),
 ("pgd-shift", "address.wrapping_shr(env.pgdir_shift)", "address.wrapping_shr(env.pgdir_shift.wrapping_add(1))"),
 ("p4d-index", "let p4d_idx = (address.wrapping_shr(P4D_SHIFT) as usize) & (env.ptrs_per_p4d as usize).wrapping_sub(1);", "let p4d_idx = 0usize;"),
 ("pud-shift", "address.wrapping_shr(PUD_SHIFT)", "address.wrapping_shr(PUD_SHIFT + 1)"),
 ("pmd-shift", "address.wrapping_shr(PMD_SHIFT) as usize) & (PTRS_PER_PMD - 1)).write(pmd)", "address.wrapping_shr(PMD_SHIFT + 1) as usize) & (PTRS_PER_PMD - 1)).write(pmd)"),
 ("l5-test", "if !env.l5 {\n            p4d_p = pgd_p;", "if env.l5 {\n            p4d_p = pgd_p;"),
 ("memset-p4d", "8usize.wrapping_mul(env.ptrs_per_p4d as usize)", "8usize.wrapping_mul(env.ptrs_per_p4d as usize / 2)"),
 ("memset-pud", "memset(pud_p.cast(), 0, 8 * PTRS_PER_PUD);", "memset(pud_p.cast(), 0, 8 * PTRS_PER_PUD - 8);"),
 ("memset-pmd", "memset(t.cast(), 0, 8 * PTRS_PER_PMD);", "memset(t.cast(), 0, 8 * PTRS_PER_PMD - 8);"),
 ("reset-count", "env.next_early_pgt.write(0);", "env.next_early_pgt.write(1);"),
 ("reset-len", "8 * (PTRS_PER_PGD - 1)", "8 * PTRS_PER_PGD"),
 ("reset-cr3", "c.write_cr3(env.pa_nodebug(env.early_top_pgt as usize as u64) | env.me_mask);", "c.write_cr3(env.pa_nodebug(env.early_top_pgt as usize as u64));"),
 ("pa-branch", "let add = if x > y { self.phys_base } else { START_KERNEL_MAP.wrapping_sub(self.page_offset) };", "let add = if x > y { START_KERNEL_MAP.wrapping_sub(self.page_offset) } else { self.phys_base };"),
 ("pgd-entry", "pgd_p.write((p4d_p as usize as u64).wrapping_sub(START_KERNEL_MAP).wrapping_add(env.phys_base)", "pgd_p.write((p4d_p as usize as u64).wrapping_sub(START_KERNEL_MAP)"),
 ("p4d-decode", "p4d_p = ((pgd & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base))", "p4d_p = ((pgd & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base).wrapping_add(8))"),
 ("pud-decode", "pud_p = ((p4d & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base))", "pud_p = ((p4d & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base).wrapping_add(8))"),
 ("pmd-decode", "pmd_p = ((pud & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base))", "pmd_p = ((pud & pfn_mask).wrapping_add(START_KERNEL_MAP).wrapping_sub(env.phys_base).wrapping_add(8))"),
 ("early-pmd", "(physaddr & PMD_MASK).wrapping_add(env.early_pmd_flags)", "(physaddr & PMD_MASK) | env.early_pmd_flags"),
 ("trap-pf", "const X86_TRAP_PF: i32 = 14;", "const X86_TRAP_PF: i32 = 13;"),
 ("pf-return", "if unsafe { early_make(env, c, cr2) } {\n            return;", "if unsafe { early_make(env, c, cr2) } {\n            c.fixup(regs, trapnr);\n            return;"),
 ("vc-order", "if amd && trapnr == X86_TRAP_VC && c.vc(regs) {", "if amd && trapnr == X86_TRAP_VC && !c.vc(regs) {"),
 ("ve-trap", "const X86_TRAP_VE: i32 = 20;", "const X86_TRAP_VE: i32 = 21;"),
 ("fixup-skip", "    c.fixup(regs, trapnr);\n}\n\n/// `x86_64_start_reservations()`", "    let _ = trapnr;\n}\n\n/// `x86_64_start_reservations()`"),
]
caught = 0; amd_only = ("vc-order",)
for name, a, b in M:
    assert src.count(a) >= 1, "pattern missing: " + name
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1))
    res = []
    for amd in (0, 1):
        cfg = ["--cfg", "CONFIG_AMD_MEM_ENCRYPT"] if amd else []
        exe = f"{out}/m{amd}"
        subprocess.run(["bash", "-c", f"cc -O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -DAMD={amd} -I{here} -DHEADINC='\"{out}/h.inc\"' -c -o {exe}.ref.o {here}/head64_ref.c && sed 's|H64RS|{out}/m.rs|' {here}/head64_cmp.rs > {exe}.cmp.rs"], check=True)
        r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test", *cfg,
                            "-C", "relocation-model=static", "-C", "link-arg=-no-pie", "-C", f"link-arg={exe}.ref.o",
                            "--crate-name", "h64cmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
        if r.returncode: res.append("COMPILE-FAIL"); continue
        r = subprocess.run([exe], env={**os.environ, "N": "30000"}, capture_output=True)
        res.append("caught" if r.returncode else "ok")
    status = "CAUGHT" if "caught" in res and "COMPILE-FAIL" not in res else ("COMPILE-FAIL" if "COMPILE-FAIL" in res else "*** NOT CAUGHT")
    if status == "CAUGHT": caught += 1
    print(f"mutant {name:14s} arm0={res[0]:6s} arm1={res[1]:6s} {status}")
print(f"sabotage: {caught} of {len(M)} mutants caught"); sys.exit(0 if caught == len(M) else 1)
PY
fi
