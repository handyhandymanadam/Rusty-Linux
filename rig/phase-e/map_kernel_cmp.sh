#!/usr/bin/env bash
# Userspace differential for map_kernel_rs.rs vs the real C of map_kernel.c, both arms (no AMD / AMD).
#   map_kernel_cmp.sh [--sabotage]      N / NW env: phase 1 / phase 2 case counts
#   MK_RS=<file> overrides the Rust file under test.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${MK_RS:-$root/port/tree/arch/x86/boot/startup/map_kernel_rs.rs}

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/map_kernel_gen.py" "$root/port/pristine/arch/x86/boot/startup/map_kernel.c" "$out/mk.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1)"
build() {   # build <amd 0|1> <rs file> <exe>
    local a=$1 rs=$2 exe=$3 cfg=() syms=()
    [ "$a" = 1 ] && { cfg=(--cfg CONFIG_AMD_MEM_ENCRYPT); syms=(-DAMD_SYMS); }
    cc -O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -DAMD=$a -I"$here" -DMKINC="\"$out/mk.inc\"" -c -o "$exe.ref.o" "$here/map_kernel_ref.c"
    cc -O0 "${syms[@]}" -c -o "$exe.syms.o" "$here/map_kernel_syms.c"
    sed "s|MKRS|$rs|" "$here/map_kernel_cmp.rs" > "$exe.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test "${cfg[@]}" \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$exe.ref.o" -C link-arg="$exe.syms.o" --crate-name mkcmp -o "$exe" "$exe.cmp.rs" 2>&1 | grep -v "^warning\|^ *|\|^ *-->\|^$\|^ *= " || true
}
for a in 0 1; do
    echo "== arm AMD=$a"
    build $a "$RS" "$out/t$a"
    "$out/t$a"
done
if [ "${1:-}" = "--sabotage" ]; then
  python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys, os, re
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("cr4-la57-bit", "const CR4_LA57: u64 = 1 << 12;", "const CR4_LA57: u64 = 1 << 13;"),
 ("la57-pgdir-shift", "t.pgdir_shift.write(48);", "t.pgdir_shift.write(47);"),
 ("la57-ptrs-p4d", "t.ptrs_per_p4d.write(512);", "t.ptrs_per_p4d.write(511);"),
 ("max-bits-l4", "const MAX_PHYSMEM_BITS_L4: u32 = 46;", "const MAX_PHYSMEM_BITS_L4: u32 = 47;"),
 ("max-bits-l5", "const MAX_PHYSMEM_BITS_L5: u32 = 52;", "const MAX_PHYSMEM_BITS_L5: u32 = 51;"),
 ("align-test", "if load_delta & (PMD_SIZE - 1) != 0 {", "if load_delta & (PMD_SIZE - 2) != 0 {"),
 ("phys-base", "t.phys_base.write(load_delta);", "t.phys_base.write(load_delta.wrapping_add(1));"),
 ("pgd-fixup-sign", "pgd_kernel.write(pgd_kernel.read().wrapping_add(load_delta));", "pgd_kernel.write(pgd_kernel.read().wrapping_sub(load_delta));"),
 ("p4d-fixup-index", "p4d.add(MAX_PTRS_PER_P4D - 1)", "p4d.add(MAX_PTRS_PER_P4D - 2)"),
 ("l3-index", "l3.add(PTRS_PER_PUD - 2)", "l3.add(PTRS_PER_PUD - 3)"),
 ("l3-second", "l3.add(PTRS_PER_PUD - 1)", "l3.add(PTRS_PER_PUD - 2)"),
 ("fixmap-num", "const FIXMAP_PMD_NUM: usize = 2;", "const FIXMAP_PMD_NUM: usize = 3;"),
 ("fixmap-top", "const FIXMAP_PMD_TOP: usize = 507;", "const FIXMAP_PMD_TOP: usize = 506;"),
 ("next-early", "t.next_early_pgt.write(2);", "t.next_early_pgt.write(1);"),
 ("kernpg-flags", "const KERNPG_TABLE_NOENC: u64 = 0x63;", "const KERNPG_TABLE_NOENC: u64 = 0x67;"),
 ("page-table-flags", "const PAGE_TABLE_NOENC: u64 = 0x67;", "const PAGE_TABLE_NOENC: u64 = 0x63;"),
 ("large-exec", "const PAGE_KERNEL_LARGE_EXEC: u64 = 0x1e3;", "const PAGE_KERNEL_LARGE_EXEC: u64 = 0x1e1;"),
 ("global-bit", "PAGE_KERNEL_LARGE_EXEC & !PAGE_GLOBAL", "PAGE_KERNEL_LARGE_EXEC"),
 ("pmd-entry-phys", "pmd_entry = pmd_entry.wrapping_add(physaddr);", "pmd_entry = pmd_entry.wrapping_add(physaddr >> 1);"),
 ("div-round-up", "wrapping_add(PMD_SIZE - 1) / PMD_SIZE", "wrapping_add(PMD_SIZE - 2) / PMD_SIZE"),
 ("pmd-stride", "i.wrapping_mul(PMD_SIZE)", "i.wrapping_mul(PMD_SIZE >> 1)"),
 ("p4d-second", "p4d.add((i.wrapping_add(1) as usize) % 512)", "p4d.add((i.wrapping_add(2) as usize) % 512)"),
 ("pud-second", "pud.add((i.wrapping_add(1) as usize) % PTRS_PER_PUD)", "pud.add((i.wrapping_add(2) as usize) % PTRS_PER_PUD)"),
 ("pgd-second", "pgd.add(i.wrapping_add(1)).write((pud as u64)", "pgd.add(i.wrapping_add(2)).write((pud as u64)"),
 ("last-inclusive", "while i <= last {", "while i < last {"),
 ("first-exclusive", "while i < first {", "while i <= first {"),
 ("present-test", "if v & PAGE_PRESENT != 0 {", "if v & PAGE_PRESENT == 0 {"),
 ("after-clear", "while i < PTRS_PER_PMD {\n            let e = pmd.add(i);\n            e.write(e.read() & !PAGE_PRESENT);", "while i < PTRS_PER_PMD {\n            let e = pmd.add(i);\n            e.write(e.read());"),
 ("la57-pgd-entry", "pgd_kernel.write((p4d as u64) | (PAGE_TABLE_NOENC | me_mask));", "pgd_kernel.write((p4d as u64) | PAGE_TABLE_NOENC);"),
 ("la57-next-early", "t.next_early_pgt.write(n.wrapping_add(1));", "t.next_early_pgt.write(n);"),
 ("me-mask-delta", "load_delta = load_delta.wrapping_add(me_mask);", "load_delta = load_delta.wrapping_add(0);"),
 ("me-mask-flags", "KERNPG_TABLE_NOENC.wrapping_add(me_mask)", "KERNPG_TABLE_NOENC"),
 ("me-mask-pmd", "pmd_entry = pmd_entry.wrapping_add(me_mask);", "pmd_entry = pmd_entry.wrapping_add(0);"),
 ("snp-sub", "e.write(e.read().wrapping_sub(me_mask));", "e.write(e.read().wrapping_add(me_mask));"),
 ("snp-step", "paddr = paddr.wrapping_add(PMD_SIZE);", "paddr = paddr.wrapping_add(PMD_SIZE >> 1);"),
 ("snp-npages", "early_snp_set_memory_shared(paddr, paddr, PTRS_PER_PMD as u64);", "early_snp_set_memory_shared(paddr, paddr, 1);"),
 ("snp-skip-test", "if me_mask != 0 {", "if me_mask > 1 << 60 {"),
 ("enc-call", "sme_encrypt_kernel(bp);", ""),
]
caught = 0
for name, a, b in M:
    assert src.count(a) >= 1, "pattern missing: " + a
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1))
    res = []
    for amd in (0, 1):
        cfg = ["--cfg", "CONFIG_AMD_MEM_ENCRYPT"] if amd else []
        exe = f"{out}/m{amd}"
        subprocess.run(["bash", "-c", f"cc -O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -DAMD={amd} -I{here} -DMKINC='\"{out}/mk.inc\"' -c -o {exe}.ref.o {here}/map_kernel_ref.c && cc -O0 {'-DAMD_SYMS' if amd else ''} -c -o {exe}.syms.o {here}/map_kernel_syms.c && sed 's|MKRS|{out}/m.rs|' {here}/map_kernel_cmp.rs > {exe}.cmp.rs"], check=True)
        r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test", *cfg,
                            "-C", "relocation-model=static", "-C", "link-arg=-no-pie", "-C", f"link-arg={exe}.ref.o", "-C", f"link-arg={exe}.syms.o",
                            "--crate-name", "mkcmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
        if r.returncode: res.append("COMPILE-FAIL"); continue
        r = subprocess.run([exe], env={**os.environ, "N": "40000", "NW": "4000"}, capture_output=True)
        res.append("caught" if r.returncode else "ok")
    # a mutant in code that exists only in one arm is judged on the arm that has it
    arms = [x for x in res if x != "COMPILE-FAIL"]
    status = "CAUGHT" if "caught" in arms and "COMPILE-FAIL" not in res else ("COMPILE-FAIL" if "COMPILE-FAIL" in res else "*** NOT CAUGHT")
    if status == "CAUGHT": caught += 1
    print(f"mutant {name:18s} arm0={res[0]:6s} arm1={res[1]:6s} {status}")
print(f"sabotage: {caught} of {len(M)} mutants caught"); sys.exit(0 if caught == len(M) else 1)
PY
fi
