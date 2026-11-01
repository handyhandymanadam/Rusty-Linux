#!/usr/bin/env bash
# port/test/nls_utf8/run.sh -- exhaustive differential for fs/nls/nls_utf8.c.
#   run.sh             full run (4 shards)
#   run.sh --sabotage  prove the harness fails on 7 mutants of the Rust
# C arm = port/pristine/fs/nls/nls_utf8.c (compiled unmodified via a wrapper);
# Rust arm = port/tree/fs/nls/nls_utf8_rs.rs (the file the kernel builds).
# The utf8<->utf32 helpers both call are extracted from pristine nls_base.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/nls_utf8"
out="${TMPDIR:-/tmp}/nls-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/fs/nls/nls_utf8.c"
RS="$root/port/tree/fs/nls/nls_utf8_rs.rs"
BASE="$root/port/pristine/fs/nls/nls_base.c"
for f in "$C" "$RS" "$BASE"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

python3 "$here/extract_base.py" "$BASE" "$out/base_ref.c"
sed "s|NLS_UTF8_C|$C|" "$here/ref_utf8.c" > "$out/ref_utf8.c"

# real include/linux/nls.h (idirafter) with shimmed init/module/etc. in front
INC=(-I "$here/shim" -idirafter "$root/src/linux/include" -idirafter "$root/src/linux/include/uapi")
build() {   # build <rs> <dir>
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name nls_utf8_rs -o "$2/librs.a" "$1"
    for f in "$out/ref_utf8.c" "$out/base_ref.c" "$here/shim_register.c" "$here/main.c"; do
        cc -O2 -Wall -Wno-unused-function "${INC[@]}" -c -o "$2/$(basename "$f" .c).o" "$f"
    done
    cc -o "$2/t" "$2"/*.o "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if NLS_FAILFAST=1 NLS_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then
    echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"

if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert f in s; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if NLS_FAILFAST=1 "$out/m$n/t" 0 1 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
bl-zero-ok~if boundlen <= 0 {~if boundlen < 0 {
wrong-errno-1~const ENAMETOOLONG: c_int = 36;~const ENAMETOOLONG: c_int = 35;
no-question-mark~unsafe { *out = b'?' };~unsafe { *out = b'!' };
wchar-limit~if n < 0 || u > MAX_WCHAR_T~if n < 0 || u >= MAX_WCHAR_T
wrong-fill~unsafe { *uni = 0x003f };~unsafe { *uni = 0x0021 };
errno-einval~const EINVAL: c_int = 22;~const EINVAL: c_int = 21;
identity-off~t[i] = i as u8;~t[i] = (i as u8) ^ (((i == 65) as u8) * 32);
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
pids=(); rc=0
for s in 0 1 2 3; do "$out/real/t" "$s" 4 & pids+=($!); done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
exit $rc
