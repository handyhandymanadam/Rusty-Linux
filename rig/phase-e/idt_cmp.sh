#!/usr/bin/env bash
# Userspace differential for idt_rs.rs vs the real C cut out of the pristine idt.c.  idt_cmp.sh [--sabotage]   env: N cases
# Runs the 4 combinations of CONFIG_X86_KERNEL_IBT (EARLY_IDT_HANDLER_SIZE 13/9) x CONFIG_INTEL_TDX_GUEST (early_idts 3/2 entries).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${IDT_RS:-$root/port/tree/arch/x86/kernel/idt_rs.rs}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/idt_gen.py" "$root/port/pristine/arch/x86/kernel/idt.c" "$out/idt.inc"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1); C cut unedited from the pristine file: $(wc -l < "$out/idt.inc") lines"
build() {  # build <rs> <exe> <ibt 0|1> <tdx 0|1>
    local d="" c=""
    [ "$3" = 1 ] && { d="$d -DCONFIG_X86_KERNEL_IBT"; c="$c --cfg CONFIG_X86_KERNEL_IBT"; }
    [ "$4" = 1 ] && { d="$d -DCONFIG_INTEL_TDX_GUEST"; c="$c --cfg CONFIG_INTEL_TDX_GUEST"; }
    cc -O2 -fwrapv -fno-strict-aliasing -Wall -Wno-unused-function -Wno-unused-variable -I"$here" -DIDTINC="\"$out/idt.inc\"" $d -c -o "$2.ref.o" "$here/idt_ref.c"
    sed "s|IDTRS|$1|" "$here/idt_cmp.rs" > "$2.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test $c \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$2.ref.o" --crate-name idtcmp -o "$2" "$2.cmp.rs" 2>&1 | grep -E "^error" -A8 || true
}
if [ "${1:-}" != "--sabotage-only" ]; then
for ibt in 0 1; do for tdx in 0 1; do
    echo "== IBT=$ibt TDX=$tdx"; build "$RS" "$out/t$ibt$tdx" $ibt $tdx; "$out/t$ibt$tdx"
done; done
fi
if [ "${1:-}" = "--sabotage" ] || [ "${1:-}" = "--sabotage-only" ]; then
python3 - "$RS" "$out" "$KB_RUSTC" "$here" <<'PY'
import subprocess, sys
rs, out, rustc, here = sys.argv[1:5]
src = open(rs).read()
M = [
 ("seg-mask", "(((d.segment & 0xffff) as u64) << 16)", "(((d.segment & 0xff) as u64) << 16)"),
 ("bits-pos", "| ((d.bits as u64) << 32)", "| ((d.bits as u64) << 31)"),
 ("mid-shift", "(((addr >> 16) & 0xffff) << 48)", "(((addr >> 17) & 0xffff) << 48)"),
 ("hi-word", "(lo, addr >> 32)", "(lo, addr >> 33)"),
 ("hi-reserved", "(lo, addr >> 32)", "(lo, (addr >> 32) | (1 << 63))"),
 ("low-mask", "let lo = (addr & 0xffff)", "let lo = (addr & 0xfff)"),
 ("idt_bits-p", "| (1 << 15)\\n", "| (0 << 15)\\n"),
 ("idt_bits-type", "((ty & 0x1f) << 8)", "((ty & 0x1f) << 7)"),
 ("idt_bits-dpl", "((dpl & 3) << 13)", "((dpl & 3) << 12)"),
 ("const-cs", "const KERNEL_CS: u32 = 0x10;", "const KERNEL_CS: u32 = 0x08;"),
 ("const-gate", "const GATE_INTERRUPT: u16 = 0xE;", "const GATE_INTERRUPT: u16 = 0xF;"),
 ("const-db", "const X86_TRAP_DB: u32 = 1;", "const X86_TRAP_DB: u32 = 2;"),
 ("const-bp", "const X86_TRAP_BP: u32 = 3;", "const X86_TRAP_BP: u32 = 4;"),
 ("const-pf", "const X86_TRAP_PF: u32 = 14;", "const X86_TRAP_PF: u32 = 13;"),
 ("bp-dpl", "gate(X86_TRAP_BP, asm_exc_int3, DPL3)", "gate(X86_TRAP_BP, asm_exc_int3, DPL0)"),
 ("db-dpl", "[gate(X86_TRAP_DB, asm_exc_debug, DPL0); EARLY_IDTS_LEN]", "[gate(X86_TRAP_DB, asm_exc_debug, DPL3); EARLY_IDTS_LEN]"),
 ("pf-handler", "[gate(X86_TRAP_PF, asm_exc_page_fault, DPL0)]", "[gate(X86_TRAP_PF, asm_exc_int3, DPL0)]"),
 ("bp-handler", "gate(X86_TRAP_BP, asm_exc_int3, DPL3)", "gate(X86_TRAP_BP, asm_exc_debug, DPL3)"),
 ("slot-size", "idt.add((d.vector as usize).wrapping_mul(GATE_SIZE))", "idt.add((d.vector as usize).wrapping_mul(GATE_SIZE - 1))"),
 ("sys-skipped", "            if sys {\\n", "            if sys && false {\\n"),
 ("sys-always", "            if sys {\\n", "            if sys || true {\\n"),
 ("bitmap-word", "((vector / BITS_PER_LONG) as usize,", "((vector / (BITS_PER_LONG / 2)) as usize,"),
 ("bitmap-bit", "1usize.wrapping_shl(vector % BITS_PER_LONG)", "1usize.wrapping_shl(vector % 63)"),
 ("loop-bound", "while i < size {", "while i < size - 1 {"),
 ("hi-vs-lo-store", "slot.write_unaligned(lo);\\n            slot.add(1).write_unaligned(hi);\\n            if sys {", "slot.write_unaligned(hi);\\n            slot.add(1).write_unaligned(lo);\\n            if sys {"),
 ("early-handler-stride", "i.wrapping_mul(EARLY_IDT_HANDLER_SIZE)", "i.wrapping_mul(EARLY_IDT_HANDLER_SIZE + 1)"),
 ("early-handler-count", "while i < NUM_EXCEPTION_VECTORS {\\n        let (lo, hi) = early_handler_gate", "while i < NUM_EXCEPTION_VECTORS - 1 {\\n        let (lo, hi) = early_handler_gate"),
 ("early-handler-noload", "        i = i.wrapping_add(1);\\n    }\\n    // SAFETY: caller contract.\\n    unsafe { load_idt(descr) };", "        i = i.wrapping_add(1);\\n    }\\n"),
 ("early-traps-noload", "        setup_from_table(idt, EARLY_IDTS.as_ptr(), EARLY_IDTS_LEN as i32, true);\\n        load_idt(descr);", "        setup_from_table(idt, EARLY_IDTS.as_ptr(), EARLY_IDTS_LEN as i32, true);"),
 ("early-traps-nosys", "setup_from_table(idt, EARLY_IDTS.as_ptr(), EARLY_IDTS_LEN as i32, true);", "setup_from_table(idt, EARLY_IDTS.as_ptr(), EARLY_IDTS_LEN as i32, false);"),
 ("early-pf-nosys", "setup_from_table(idt, EARLY_PF_IDTS.as_ptr(), 1, true)", "setup_from_table(idt, EARLY_PF_IDTS.as_ptr(), 1, false)"),
 ("early-handler-sys", "            slot.add(1).write_unaligned(hi);\\n        }\\n        i = i.wrapping_add(1);", "            slot.add(1).write_unaligned(hi);\\n            system_vectors[0].fetch_or(1, Ordering::SeqCst);\\n        }\\n        i = i.wrapping_add(1);"),
 ("early-handler-vec-EQUIV", "        vector: i as u32,\\n        segment: KERNEL_CS,", "        vector: i as u32 + 1,\\n        segment: KERNEL_CS,"),
]
caught = 0; notapp = 0
for name, a, b in M:
    a = a.replace("\\n", "\n"); b = b.replace("\\n", "\n")
    if src.count(a) < 1: print(f"mutant {name:22s} PATTERN MISSING"); sys.exit(2)
    open(f"{out}/m.rs", "w").write(src.replace(a, b, 1))
    exe = f"{out}/m"
    subprocess.run(["bash", "-c", f"cc -O2 -fwrapv -fno-strict-aliasing -Wno-unused-function -Wno-unused-variable -I{here} -DIDTINC='\"{out}/idt.inc\"' -DCONFIG_X86_KERNEL_IBT -DCONFIG_INTEL_TDX_GUEST -c -o {exe}.ref.o {here}/idt_ref.c && sed 's|IDTRS|{out}/m.rs|' {here}/idt_cmp.rs > {exe}.cmp.rs"], check=True)
    r = subprocess.run([rustc, "--edition", "2021", "-O", "-C", "panic=abort", "-C", "overflow-checks=on", "--cfg", "userspace_test", "--cfg", "CONFIG_X86_KERNEL_IBT", "--cfg", "CONFIG_INTEL_TDX_GUEST",
                        "-C", "relocation-model=static", "-C", "link-arg=-no-pie", "-C", f"link-arg={exe}.ref.o", "--crate-name", "idtcmp", "-o", exe, f"{exe}.cmp.rs"], capture_output=True)
    if r.returncode: print(f"mutant {name:22s} COMPILE-FAIL"); print(r.stderr.decode()[-500:]); continue
    r = subprocess.run([exe], env={"N": "20000"}, capture_output=True)
    st = "CAUGHT" if r.returncode else "*** NOT CAUGHT"
    if "EQUIV" in name:  # provably equivalent: the vector field of early_handler_gate()'s IdtData is never read by gate_words()
        notapp += 1; st = "equivalent (expected not caught)" if not r.returncode else "*** EQUIVALENT MUTANT WAS CAUGHT"
    elif r.returncode: caught += 1
    print(f"mutant {name:22s} {st}")
print(f"sabotage: {caught} of {len(M) - notapp} non-equivalent mutants caught, {notapp} equivalent"); sys.exit(0 if caught == len(M) - notapp else 1)
PY
fi
