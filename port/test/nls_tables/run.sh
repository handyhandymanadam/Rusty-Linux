#!/usr/bin/env bash
# port/test/nls_tables/run.sh -- exhaustive differential for the table-driven NLS charsets.
#   run.sh <ascii|iso8859-1|cp437>              full run
#   run.sh <ascii|iso8859-1|cp437> --sabotage   prove the harness fails on mutants of the Rust
#   run.sh <cs> --regen                         also check nls_<cs>_rs.rs == gen.py output
# C arm = port/pristine/fs/nls/nls_<cs>.c (compiled unmodified); Rust arm =
# port/tree/fs/nls/nls_<cs>_rs.rs (the file the kernel builds).
set -euo pipefail
cs=${1:?usage: run.sh <ascii|iso8859-1|cp437> [--sabotage|--regen]}; mode=${2:-}
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/nls_tables"
out="${TMPDIR:-/tmp}/nls-tables.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
u=${cs//-/_}
C="$root/port/pristine/fs/nls/nls_$cs.c"
RS="$root/port/tree/fs/nls/nls_${u}_rs.rs"
SYM="nls_${u}_rs_table"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
INC=(-I "$here/shim" -idirafter "$root/src/linux/include" -idirafter "$root/src/linux/include/uapi")
build() {   # build <rs> <dir>
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name "nls_${u}_rs" -o "$2/librs.a" "$1"
    cc -O2 -Wall -Wno-unused-function "${INC[@]}" -DNLS_PRISTINE_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall "${INC[@]}" -DRS_SYM="$SYM" -c -o "$2/main.o" "$here/main.c"
    cc -O2 -Wall "${INC[@]}" -c -o "$2/shim_register.o" "$here/shim_register.c"
    cc -o "$2/t" "$2"/ref.o "$2"/main.o "$2"/shim_register.o "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
if [ "$mode" = "--regen" ]; then
    python3 "$here/gen.py" "$C" "$out/regen.rs" "$(grep -o 'pub struct [A-Za-z0-9]*' "$RS" | head -1 | cut -d' ' -f3)" "$SYM" "$(grep -o 'charset: b"[^\\]*' "$RS" | cut -d'"' -f2)" "$cs"
    cmp "$out/regen.rs" "$RS" && echo "regen: byte-identical to gen.py output"; exit
fi
build "$RS" "$out/real"
echo "prove-can-fail:"
if NLS_PROVE_CAN_FAIL=1 "$out/real/t" >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"

if [ "$mode" = "--sabotage" ]; then
    n=0; caught=0
    mutate() {  # mutate <name> <python expr transforming s>
        n=$((n+1))
        MUT="$2" python3 - "$RS" "$out/mut.rs" <<'PY'
import os, re, sys
s = open(sys.argv[1]).read()
exec(os.environ["MUT"])
open(sys.argv[2], "w").write(s)
PY
        cmp -s "$RS" "$out/mut.rs" && { echo "mutant $1: NO-OP (mutation did not change the file)"; exit 1; }
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" >/dev/null 2>&1; then echo "mutant $1: *** NOT CAUGHT"; else echo "mutant $1: caught"; caught=$((caught+1)); fi
    }
    sub() { python3 -c 'import sys; a, b = sys.argv[1:3]; print("assert %r in s; s = s.replace(%r, %r, 1)" % (a, a, b))' "$1" "$2"; }
    mutate bl-zero-ok "$(sub 'if boundlen <= 0 {' 'if boundlen < 0 {')"
    mutate bl-neg-only "$(sub 'if boundlen <= 0 {' 'if boundlen < -1 {')"
    mutate errno-nametoolong "$(sub 'const ENAMETOOLONG: c_int = 36;' 'const ENAMETOOLONG: c_int = 35;')"
    mutate errno-einval "$(sub 'const EINVAL: c_int = 22;' 'const EINVAL: c_int = 21;')"
    mutate keep-zero-page-entry "$(sub 'Some(page) if page[cl] != 0 =>' 'Some(page) =>')"
    mutate char2uni-zero-test "$(sub 'if u == 0x0000 {' 'if u == 0x0001 {')"
    mutate char2uni-ret2 "$(sub '    1
}

/// `static struct nls_table' '    2
}

/// `static struct nls_table')"
    mutate char2uni-no-store "$(sub 'unsafe { *uni = u };' 'let _ = uni;')"
    mutate uni2char-no-store "$(sub 'unsafe { *out = page[cl] };' 'let _ = out;')"
    mutate hi-byte-shift "$(sub '((uni & 0xff00) >> 8)' '((uni & 0xff00) >> 9)')"
    mutate lo-byte-mask "$(sub '(uni & 0x00ff) as usize' '(uni & 0x007f) as usize')"
    mutate charset-name "$(sub 'charset: b"' 'charset: b"x')"
    mutate lower-upper-swapped "$(sub 'charset2lower: CHARSET2LOWER.as_ptr(),' 'charset2lower: CHARSET2UPPER.as_ptr(),')
$(sub 'charset2upper: CHARSET2UPPER.as_ptr(),' 'charset2upper: CHARSET2LOWER.as_ptr(),')"
    # one-entry table mutants: flip the last element of each static table
    for t in $(grep -o '^static [A-Z0-9_]*: \[u[0-9]*; 256\]' "$RS" | awk '{print $2}' | tr -d ':'); do
        mutate "table-$t-last" 's = re.sub(r"(static '"$t"': \[u[0-9]+; 256\] = \[.*?0x)([0-9a-f]+)(,\n\];)", lambda m: m.group(1) + format(int(m.group(2),16) ^ 1, "0%dx" % len(m.group(2))) + m.group(3), s, count=1, flags=re.S)'
        mutate "table-$t-first" 's = re.sub(r"(static '"$t"': \[u[0-9]+; 256\] = \[\n    0x)([0-9a-f]+)", lambda m: m.group(1) + format(int(m.group(2),16) ^ 1, "0%dx" % len(m.group(2))), s, count=1)'
    done
    last=$(grep -o 't\[0x[0-9a-f]*\] = Some(&PAGE[0-9A-F]*);' "$RS" | tail -1)
    if [ "$last" != "t[0x00] = Some(&PAGE00);" ]; then   # multi-page charset: index mutants for the LAST page
        idx=${last#t[}; idx=${idx%%]*}
        mutate last-page-index-off-by-one "$(sub "$last" "${last/$idx/0x$(printf %02x $(( idx - 1 )))}")"
        prev=$(grep -o 't\[0x[0-9a-f]*\] = Some(&PAGE[0-9A-F]*);' "$RS" | tail -2 | head -1)
        mutate last-two-pages-swapped "$(sub "$prev" "${prev%Some*}Some(&${last##*&}")
$(sub "$last" "${last%Some*}Some(&${prev##*&}")"
    fi
    mutate page-index-shift "$(sub 't[0x00] = Some(&PAGE00);' 't[0x01] = Some(&PAGE00);')"
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t"
