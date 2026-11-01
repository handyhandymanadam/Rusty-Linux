#!/usr/bin/env bash
# port/test/rsa_helper/run.sh -- differential for the logic of crypto/rsa_helper.c (the eight rsa_get_* ASN.1 action callbacks).
#   run.sh             both builds (FIPS unset and the CONFIG_CRYPTO_FIPS arm), n_sz x vlen sweeps incl. the 256-byte FIPS
#                      boundary and leading zeros, NULL values, both guard-page placements, 400k random contexts
#   run.sh --sabotage  mutants of the Rust must each be caught
# C arm = the eight functions sliced out of port/pristine/crypto/rsa_helper.c (extract.py fails if they change); Rust arm =
# port/tree/crypto/rsa_helper_rs.rs (with --cfg CONFIG_CRYPTO_FIPS in the second build); oracle = spec_ok() in main.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/rsa_helper"
out="${TMPDIR:-/tmp}/rsa_helper-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/rsa_helper.c"
RS="${RSA_HELPER_RS:-$root/port/tree/crypto/rsa_helper_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$out/extract.c"
build() {   # build <rs> <dir> <fips 0|1>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    local cfg=() cdef=()
    if [ "$3" = 1 ]; then cfg=(--cfg 'CONFIG_CRYPTO_FIPS'); cdef=(-DFIPS); fi
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on "${cfg[@]}" \
        --check-cfg 'cfg(CONFIG_CRYPTO_FIPS)' --check-cfg 'cfg(kani)' -D unsafe_op_in_unsafe_fn -D warnings --crate-name rsa_helper_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w "${cdef[@]}" -I "$here" -c -o "$2/c.o" "$out/extract.c"
    cc -O2 -Wall "${cdef[@]}" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
# run.sh --object <rsa_helper_rs.o>: link the REAL object the kernel build produced (CONFIG_CRYPTO_FIPS unset, as in both
# kernel configs; kernel flags, retpoline thunks stubbed) instead of re-compiling the Rust.
if [ "${1:-}" = "--object" ]; then
    obj=${2:?usage: run.sh --object <build-dir>/crypto/rsa_helper_rs.o}
    mkdir -p "$out/obj"
    cc -O1 -w -I "$here" -c -o "$out/obj/c.o" "$out/extract.c"
    cc -O2 -Wall -c -o "$out/obj/main.o" "$here/main.c"
    cc -c -o "$out/obj/thunks.o" "$here/thunks.S"
    cc -o "$out/obj/t" "$out/obj/main.o" "$out/obj/c.o" "$obj" "$out/obj/thunks.o"
    echo "object: $obj ($(sha256sum "$obj" | cut -c1-16))"
    if "$out/obj/t" --poison >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "prove-can-fail: poisoned result detected"
    "$out/obj/t"
    exit 0
fi
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/plain" 0
build "$RS" "$out/fips" 1
if "$out/plain/t" --poison >/dev/null 2>&1 || "$out/fips/t" --poison >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned Rust result detected in both builds"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0; eq=0; eqok=0
    mut() {   # mut <name> <from> <to> [nth] [equiv]
        python3 - "$RS" "$out/mut.rs" "$2" "$3" "${4:-1}" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b, nth = sys.argv[3], sys.argv[4], int(sys.argv[5])
assert s.count(a) >= nth, "pattern missing: " + a
i = -1
for _ in range(nth): i = s.index(a, i + 1)
open(sys.argv[2], "w").write(s[:i] + b + s[i + len(a):])
PY
        n=$((n+1)); build "$out/mut.rs" "$out/m$n" 1 >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" >/dev/null 2>&1; then
            if [ "${5:-}" = equiv ]; then echo "equivalent mutant $1: not seen (as expected)"; eqok=$((eqok+1)); eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: *** NOT CAUGHT"; fi
        else
            if [ "${5:-}" = equiv ]; then echo "equivalent mutant $1: SEEN -- not equivalent"; eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: caught"; caught=$((caught+1)); fi
        fi
    }
    mut n-null-ok          'if value.is_null() || vlen == 0 {' 'if vlen == 0 {'
    mut n-zero-len-ok      'if value.is_null() || vlen == 0 {' 'if value.is_null() {'
    mut n-fips-threshold   'if n_sz < 256 {' 'if n_sz < 255 {'
    mut n-fips-no-strip    'while n_sz != 0 && *ptr == 0 {' 'while false && n_sz != 0 && *ptr == 0 {'
    mut n-fips-msg         'RSA: key size not allowed in FIPS mode' 'RSA: key size not allowed in FIPS Mode' 2
    mut n-fips-level       '\x013RSA' '\x014RSA'
    mut n-fips-no-print    '_printk(c"\x013RSA: key size not allowed in FIPS mode\n".as_ptr());' ''
    mut n-fips-always      'if fips_enabled != 0 {' 'if fips_enabled != 0 || true {'
    mut n-fips-never       'if fips_enabled != 0 {' 'if fips_enabled != 0 && false {'
    mut n-store-len-short  '(*key).n_sz = vlen;' '(*key).n_sz = vlen - 1;'
    mut n-store-nothing    '(*key).n = value as *const u8;' '(*key).n = core::ptr::null();'
    # `n_sz == 0` in e and d is REDUNDANT with `vlen == 0 || vlen > n_sz` (n_sz == 0 and vlen > 0 is vlen > n_sz): equivalent mutants
    mut e-no-n-check       '(*key).n_sz == 0 || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).e =' 'vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).e =' 1 equiv
    mut e-longer-ok        'vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).e =' 'vlen > (*key).n_sz + 1 {
            return -EINVAL;
        }
        (*key).e ='
    mut e-size-field       '(*key).e_sz = vlen;' '(*key).d_sz = vlen;'
    mut d-no-n-check       '(*key).n_sz == 0 || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).d =' 'vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).d =' 1 equiv
    mut d-ptr-field        '(*key).d = value as *const u8;' '(*key).e = value as *const u8;'
    mut p-longer-ok        'vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).p =' 'vlen > (*key).n_sz + 1 {
            return -EINVAL;
        }
        (*key).p ='
    mut p-null-ok          'if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).p =' 'if vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).p ='
    mut q-size-field       '(*key).q_sz = vlen;' '(*key).p_sz = vlen;'
    mut dp-zero-ok         'if value.is_null() || vlen == 0 || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).dp =' 'if value.is_null() || vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).dp ='
    mut dq-ptr-field       '(*key).dq = value as *const u8;' '(*key).dp = value as *const u8;'
    mut qinv-size-off      '(*key).qinv_sz = vlen;' '(*key).qinv_sz = vlen + 1;'
    mut qinv-longer-ok     'vlen > (*key).n_sz {
            return -EINVAL;
        }
        (*key).qinv =' 'vlen > (*key).n_sz + 1 {
            return -EINVAL;
        }
        (*key).qinv ='
    echo "$caught of $n mutants caught; $eqok of $eq equivalent mutants unseen"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ]; exit
fi
"$out/plain/t"
"$out/fips/t"
