#!/usr/bin/env bash
# ident-ref.sh <build-dir> <outdir> : build the ORIGINAL ident_map_64.c (with the shared ident_map.c it
# #includes) as a userspace object, from the exact compile command kbuild used for that build dir
# (flags and config), preprocessed (-E) and then compiled by clang for the host. The defined symbols
# are renamed c_<name> so the Rust port can be linked beside it; the file-local state is exposed.
set -euo pipefail
B=$(cd "$1" && pwd); O=$2; mkdir -p "$O"
cmdf="$B/arch/x86/boot/compressed/.ident_map_64.o.cmd"
[ -f "$cmdf" ] || { echo "no $cmdf (build the stub first)"; exit 1; }
cd "$B"
python3 - "$cmdf" "$O" <<'PY'
import re, shlex, subprocess, sys
cmdf, O = sys.argv[1:3]
cmd = re.search(r'^savedcmd_\S+ := (.*)$', open(cmdf).read(), re.M).group(1)
out, toks, i = [], shlex.split(cmd), 0
while i < len(toks):
    t = toks[i]
    if t.startswith('-Wp,-MMD') or t.startswith('-Wa,') or t == '-c': i += 1; continue
    if t == '-o': out += ['-E', '-o', O + '/ident_map_64.i']; i += 2; continue
    out.append(t); i += 1
subprocess.run(out, check=True)
PY
# userspace cannot write CR3: elide that one instruction (the Rust twin does the same under --cfg=userspace_test)
sed -i 's/asm volatile("mov %0,%%cr3": : "r" (val) : "memory");/asm volatile("# cr3 write elided in the userspace test" : : "r" (val) : "memory");/' "$O/ident_map_64.i"
sed -i 's/asm volatile("mov %%cr3,%0" : "=r" (val));/asm volatile("mov test_cr3(%%rip),%0" : "=r" (val));/' "$O/ident_map_64.i"
grep -q "test_cr3" "$O/ident_map_64.i" || { echo "could not redirect the CR3 read"; exit 1; }
grep -q "cr3 write elided" "$O/ident_map_64.i" || { echo "could not elide the CR3 write"; exit 1; }
clang -x cpp-output -O1 -fPIC -w -c "$O/ident_map_64.i" -o "$O/ident_c.o"
syms="kernel_ident_mapping_init kernel_ident_mapping_free kernel_add_identity_map initialize_identity_maps
  set_page_decrypted set_page_encrypted set_page_non_present do_boot_page_fault do_boot_nmi_trap physical_mask
  __default_kernel_pte_mask mapping_info top_level_pgt pgt_data"
objcopy $(for s in $syms; do echo --redefine-sym $s=c_$s; done) "$O/ident_c.o" "$O/ident_c2.o"
objcopy $(for s in $syms; do echo --globalize-symbol=c_$s; done) "$O/ident_c2.o" "$O/ident_ref.o"
nm "$O/ident_ref.o" | grep -c ' [TDBb] c_' | sed 's/^/renamed+exposed symbols: /'
nm "$O/ident_ref.o" | grep -E ' b c_' && echo "WARNING: a state symbol is still local" || true
