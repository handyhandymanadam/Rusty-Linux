#!/usr/bin/env bash
# port/test/lzo_scomp/run.sh [lzo|lzorle] [--sabotage] -- differential for the
# two helper bodies of crypto/lzo.c (or crypto/lzo-rle.c).
# The library calls (lzo1x_*_safe) are MOCKED by main.c, identically for the
# pristine C and the Rust: the mock records its arguments and returns any
# programmed result, so every return code and every length is reachable.
# Not covered here: the scomp table, alloc_ctx/free_ctx and registration (C
# glue, exercised in the kernel by libtest.c via the crypto API).
set -euo pipefail
which=${1:-lzo}; mode=${2:-}
case "$which" in
    lzo)    cfile=lzo.c;     rsfile=lzo_rs.rs;    cdef=NAME_LZO;    pfx=lzo;    efn=1 ;;
    lzorle) cfile=lzo-rle.c; rsfile=lzorle_rs.rs; cdef=NAME_LZORLE; pfx=lzorle; efn=2 ;;
    *) echo "usage: run.sh lzo|lzorle [--sabotage]"; exit 2 ;;
esac
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/lzo_scomp"
out="${TMPDIR:-/tmp}/lzo-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/$cfile"
RS="$root/port/tree/crypto/$rsfile"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$out/extract.c"
sed "s|EXTRACT|$out/extract.c|" "$here/ref.c" > "$out/ref.c"
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name lzo_scomp_rs -o "$2/librs.a" "$1"
    cc -O2 -Wall -D$cdef -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -DEXPECT_COMPRESS_FN=$efn -DRS_COMPRESS=crypto_${pfx}_rs_compress -DRS_DECOMPRESS=crypto_${pfx}_rs_decompress -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)   target: $which"
build "$RS" "$out/real"
"$out/real/t" 200000 >/dev/null
if LZO_PROVE_CAN_FAIL=1 "$out/real/t" 1000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned output detected"
if [ "$mode" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)>=1, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 20000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
einval-code~return -EINVAL;~return -EINVAL + 1;
err-compare~if err != LZO_E_OK {~if err < LZO_E_OK {
narrow-to-u16~unsafe { *dlen = tmp_len as u32 };~unsafe { *dlen = tmp_len as u16 as u32 };
widen-to-u16~let mut tmp_len = unsafe { *dlen } as usize;~let mut tmp_len = unsafe { *dlen } as u16 as usize;
slen-narrowed~src, slen as usize, dst, &mut tmp_len, ctx~src, slen as u16 as usize, dst, &mut tmp_len, ctx
write-before-check~let err = unsafe { lzo1x_decompress_safe(src, slen as usize, dst, &mut tmp_len) };~let err = unsafe { lzo1x_decompress_safe(src, slen as usize, dst, &mut tmp_len) }; unsafe { *dlen = tmp_len as u32 };
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" 3000000
