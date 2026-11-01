#!/usr/bin/env bash
# Userspace differential for platform_quirks_rs.rs vs the real C of platform-quirks.c.  pq_cmp.sh [--sabotage]   N env: cases
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${PQ_RS:-$root/port/tree/arch/x86/kernel/platform_quirks_rs.rs}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
grep -v '^#include' "$root/port/pristine/arch/x86/kernel/platform-quirks.c" > "$out/pq.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1); C kept unedited except #include lines: $(wc -l < "$out/pq.inc") lines"
build() {  # build <rs> <exe> [extra cc -D]
    cc -O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -I"$here" -DPQINC="\"$out/pq.inc\"" ${3:-} -c -o "$2.ref.o" "$here/pq_ref.c"
    sed "s|PQRS|$1|" "$here/pq_cmp.rs" > "$2.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$2.ref.o" --crate-name pqcmp -o "$2" "$2.cmp.rs" 2>&1 | grep -E "^error" -A6 || true
}
build "$RS" "$out/t"
"$out/t"
if [ "${1:-}" = "--sabotage" ]; then
python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("i8042-default", "i8042: I8042_EXPECTED_PRESENT, rtc: 1", "i8042: 1, rtc: 1"),
 ("rtc-default", "rtc: 1, warm_reset: 1, reserve", "rtc: 0, warm_reset: 1, reserve"),
 ("warm-reset", "warm_reset: 1, reserve_bios_regions: 0, pnpbios: 1", "warm_reset: 0, reserve_bios_regions: 0, pnpbios: 1"),
 ("pnp-default", "reserve_bios_regions: 0, pnpbios: 1 }", "reserve_bios_regions: 0, pnpbios: 0 }"),
 ("pc-arm", "X86_SUBARCH_PC => l.reserve_bios_regions = 1,", "X86_SUBARCH_PC => l.reserve_bios_regions = 0,"),
 ("xen-rtc", "            l.pnpbios = 0;\n            l.rtc = 0;\n        }\n        X86_SUBARCH_INTEL_MID", "            l.pnpbios = 0;\n        }\n        X86_SUBARCH_INTEL_MID"),
 ("xen-pnp", "        X86_SUBARCH_XEN => {\n            l.pnpbios = 0;", "        X86_SUBARCH_XEN => {\n            l.pnpbios = 1;"),
 ("mid-i8042", "l.i8042 = I8042_PLATFORM_ABSENT;", "l.i8042 = 1;"),
 ("ce4100-arm", "X86_SUBARCH_INTEL_MID | X86_SUBARCH_CE4100 =>", "X86_SUBARCH_INTEL_MID =>"),
 ("const-xen", "const X86_SUBARCH_XEN: u32 = 2;", "const X86_SUBARCH_XEN: u32 = 1;"),
 ("const-mid", "const X86_SUBARCH_INTEL_MID: u32 = 3;", "const X86_SUBARCH_INTEL_MID: u32 = 5;"),
 ("off-rtc", "const LF_RTC: usize = 4;", "const LF_RTC: usize = 12;"),
 ("off-novga-touched", "const LF_WARM_RESET: usize = 8;", "const LF_WARM_RESET: usize = 12;"),
 ("off-legacy", "const XP_LEGACY: usize = 88;", "const XP_LEGACY: usize = 80;"),
 ("cb-skipped", "if let Some(f) = cb {", "if let Some(f) = cb.filter(|_| false) {"),
 ("cb-before", "        let legacy = xp.add(XP_LEGACY);\n", "        if let Some(f) = xp.add(XP_SET_LEGACY_FEATURES).cast::<Option<unsafe extern \"C\" fn()>>().read() { f(); }\n        let legacy = xp.add(XP_LEGACY);\n"),
 ("off-cb", "const XP_SET_LEGACY_FEATURES: usize = 112;", "const XP_SET_LEGACY_FEATURES: usize = 104;"),
 ("pnp-inverted", "    pnpbios == 0\n", "    pnpbios != 0\n"),
]
caught = 0
for name, a, b in M:
    assert src.count(a) >= 1, "pattern missing: " + name
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1))
    exe = f"{out}/m"
    subprocess.run(["bash", "-c", f"cc -O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -I{here} -DPQINC='\"{out}/pq.inc\"' -c -o {exe}.ref.o {here}/pq_ref.c && sed 's|PQRS|{out}/m.rs|' {here}/pq_cmp.rs > {exe}.cmp.rs"], check=True)
    r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test",
                        "-C", "relocation-model=static", "-C", "link-arg=-no-pie", "-C", f"link-arg={exe}.ref.o", "--crate-name", "pqcmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
    if r.returncode: print(f"mutant {name:18s} COMPILE-FAIL"); print(r.stderr.decode()[-400:]); continue
    r = subprocess.run([exe], env={"N": "30000"}, capture_output=True)
    st = "CAUGHT" if r.returncode else "*** NOT CAUGHT"
    if r.returncode: caught += 1
    print(f"mutant {name:18s} {st}")
print(f"sabotage: {caught} of {len(M)} mutants caught"); sys.exit(0 if caught == len(M) else 1)
PY
fi
