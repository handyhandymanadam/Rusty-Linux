#!/usr/bin/env bash
# port/test/x86_insn/run.sh -- differential for arch/x86/lib/insn.c + inat.c.
#   run.sh             full run (8 shards)
#   run.sh --sabotage  prove the harness fails on mutants of the Rust
# C arm = the kernel's own sync copy under tools/arch/x86/lib/ (identical to arch/x86/lib/ except include paths
# and INSN_MODE_KERN; checked by diff below) built with every function renamed c_*;
# Rust arm = port/tree/arch/x86/lib/insn_rs.rs, sharing the C arm's generated opcode tables.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/x86_insn"
out="${TMPDIR:-/tmp}/x86insn.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${X86INSN_RS:-$root/port/tree/arch/x86/lib/insn_rs.rs}"
T="$root/src/linux/tools/arch/x86"
TABLES="$root/build-full/arch/x86/lib"
for f in "$RS" "$T/lib/insn.c" "$T/lib/inat.c" "$TABLES/inat-tables.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the oracle must be the pristine kernel code: the tools copy may differ only in include paths / INSN_MODE_KERN
for f in insn inat; do
    n=$(diff "$root/port/pristine/arch/x86/lib/$f.c" "$T/lib/$f.c" | grep -c '^[<>]' || true)
    echo "tools/$f.c differs from pristine kernel $f.c in $n lines (include paths, INSN_MODE_KERN)"
    [ "$n" -le 12 ] || { echo "tools copy has drifted from the kernel file"; exit 1; }
done
REN=""
for fn in insn_init insn_get_prefixes insn_get_opcode insn_get_modrm insn_get_sib insn_get_displacement insn_get_immediate insn_get_length insn_rip_relative insn_decode \
          inat_get_opcode_attribute inat_get_last_prefix_id inat_get_escape_attribute inat_get_group_attribute inat_get_avx_attribute inat_get_xop_attribute; do
    REN="$REN -D$fn=c_$fn"
done
INC=(-I "$T/lib" -I "$T/include" -I "$root/src/linux/tools/include" -I "$TABLES")
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name insn_rs -o "$2/librs.a" "$2/probe.rs"
    # C arm: insn.c + inat.c (+ tables) in one object, functions renamed; tables keep their names and are shared
    cat "$T/lib/inat.c" > "$2/ref_inat.c"
    cc -O2 -w $REN "${INC[@]}" -c -o "$2/ref_insn.o" "$T/lib/insn.c"
    cc -O2 -w $REN "${INC[@]}" -c -o "$2/ref_inat.o" "$2/ref_inat.c"
    cc -O2 -w "${INC[@]}" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref_insn.o" "$2/ref_inat.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" 8 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if X86INSN_PROVE_CAN_FAIL=1 X86INSN_NRAND=1000 "$out/real/t" 0 8 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if X86INSN_FAILFAST=1 X86INSN_NRAND=3000000 timeout 300 "$out/m$n/t" 1 64 >/dev/null 2>&1 && X86INSN_FAILFAST=1 X86INSN_NRAND=3000000 timeout 300 "$out/m$n/t" 0 64 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
max-insn-size~const MAX_INSN_SIZE: c_int = 15;~const MAX_INSN_SIZE: c_int = 16;
addr-toggle64~insn.addr_bytes ^= 12;~insn.addr_bytes ^= 4;
addr-toggle32~insn.addr_bytes ^= 6;~insn.addr_bytes ^= 4;
opnd-toggle~insn.opnd_bytes ^= 6;~insn.opnd_bytes ^= 2;
dup-prefix~if insn.prefixes.byte(i) == b {~if insn.prefixes.byte(i) == b && i > 0 {
nb-limit~if nb == 4 {~if nb == 5 {
last-prefix~insn.prefixes.set_byte(3, lb);~insn.prefixes.set_byte(2, lb);
rex-w~if b & 8 != 0 {<NL>                    /* REX.W overrides opnd_size */<NL>                    insn.opnd_bytes = 8;<NL>                }<NL>            } else if inat_is_rex2_prefix~if b & 4 != 0 {<NL>                    /* REX.W overrides opnd_size */<NL>                    insn.opnd_bytes = 8;<NL>                }<NL>            } else if inat_is_rex2_prefix
rex2-len~insn.rex_prefix.nbytes = 2;~insn.rex_prefix.nbytes = 3;
rex2-skip~insn.next_byte = insn.next_byte.wrapping_add(2);<NL>                if b & 8~insn.next_byte = insn.next_byte.wrapping_add(1);<NL>                if b & 8
xop-pop~x86_modrm_reg(b2) == 0~x86_modrm_reg(b2) == 1
vex-32bit~if x86_modrm_mod(b2) != 3 {~if x86_modrm_mod(b2) != 2 {
evex-len~insn.vex_prefix.nbytes = 4;~insn.vex_prefix.nbytes = 3;
vex2-mask~insn.vex_prefix.set_byte(2, b2 & 0x7f);~insn.vex_prefix.set_byte(2, b2 & 0xff);
vex3-w~insn.x86_64 != 0 && b2 & 0x80 != 0 {<NL>                    /* VEX.W/XOP.W~insn.x86_64 != 0 && b2 & 0x40 != 0 {<NL>                    /* VEX.W/XOP.W
emul-xen~[0x0f, 0x0b, 0x78, 0x65, 0x6e]~[0x0f, 0x0b, 0x78, 0x65, 0x6f]
emul-kvm~[0x0f, 0x0b, 0x6b, 0x76, 0x6d]~[0x0f, 0x0b, 0x6b, 0x76, 0x6e]
inv64~insn.attr &= INAT_INV64;~insn.attr &= !INAT_INV64;
xop-ok~if !inat_accept_xop(insn.attr) {<NL>                    insn.attr = 0;~if inat_accept_xop(insn.attr) {<NL>                    insn.attr = 0;
evex-scalable~p as u32 == INAT_PFX_OPNDSZ~p as u32 == INAT_PFX_VEX2
vex-must-evex~(inat_must_evex(insn.attr) && !insn.is_evex())~(inat_must_evex(insn.attr) && insn.is_evex())
rex2-m~if insn.rex2_m_bit() != 0 {~if insn.rex2_m_bit() == 0 {
must-vex~if inat_must_vex(insn.attr) {~if inat_must_vex(insn.attr) && insn.x86_64 == 0 {
force64~if insn.x86_64 != 0 && inat_is_force64(insn.attr) {~if inat_is_force64(insn.attr) {
sib-addr~if insn.addr_bytes != 2 && x86_modrm_mod(modrm) != 3~if insn.addr_bytes != 4 && x86_modrm_mod(modrm) != 3
sib-rm~x86_modrm_rm(modrm) == 4~x86_modrm_rm(modrm) == 5
disp-rm5~|| (m == 0 && base == 5)~|| (m == 0 && base == 4)
disp16~if (m == 0 && rm == 6) || m == 2 {~if (m == 0 && rm == 5) || m == 2 {
imm-ptr8~            /* ptr16:64 is not exist (no segment) */<NL>            return false;~            /* ptr16:64 is not exist (no segment) */<NL>            return true;
imm-v-nbytes~insn.immediate1.nbytes = 4;~insn.immediate1.nbytes = 2;
imm-second~let v = need!(unsafe { insn.get_i8() });<NL>            insn.immediate2.set(v, 1);~let v = need!(unsafe { insn.get_i16() });<NL>            insn.immediate2.set(v, 2);
moffset8~            insn.immediate1.set(v, 4);<NL>            let Some(v) = (unsafe { insn.get_i32() }) else { return false };<NL>            insn.immediate2.set(v, 4);<NL>        }<NL>        _ => return false, /* opnd_bytes must be modified manually */<NL>    }<NL>    insn.immediate1.got = 1;~            insn.immediate1.set(v, 4);<NL>            let Some(v) = (unsafe { insn.get_i32() }) else { return false };<NL>            insn.immediate2.set(v, 2);<NL>        }<NL>        _ => return false, /* opnd_bytes must be modified manually */<NL>    }<NL>    insn.immediate1.got = 1;
length~insn.length = (insn.next_byte as usize).wrapping_sub(insn.kaddr as usize) as u8;~insn.length = (insn.next_byte as usize).wrapping_sub(insn.kaddr as usize) as u8 + 1;
rip~(modrm.byte(0) & 0xc7) == 0x5~(modrm.byte(0) & 0xc7) == 0x6
validate~<= self.end_kaddr as usize~< self.end_kaddr as usize
esc-lpfx~&& lpfx_id != 0 {<NL>            table = tab4(&inat_escape_tables~&& lpfx_id != 1 {<NL>            table = tab4(&inat_escape_tables
grp-common~*table.add(reg) | inat_group_common_attribute(grp_attr)~*table.add(reg)
avx-pfx~if !inat_is_group(*table.add(opcode as usize)) && vex_p != 0 {~if inat_is_group(*table.add(opcode as usize)) && vex_p != 0 {
xop-range~map_select < X86_XOP_M_MIN || map_select > X86_XOP_M_MAX~map_select <= X86_XOP_M_MIN || map_select > X86_XOP_M_MAX
decode-complete~i.immediate1.got != 0 {~i.immediate1.got == 0 {
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
