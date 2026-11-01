#!/usr/bin/env bash
# port/test/aes_generic/run.sh [--sabotage] -- differential for crypto/aes_generic.c
#   subject: the REAL glue slice (crypto/aes_generic_glue.c: ft/it data, set_key, thunks)
#            + the Rust (crypto/aes_generic_rs.rs: block code, private fl/il tables)
#   ref    : the PRISTINE crypto_aes_encrypt/decrypt and all four tables (sliced from
#            port/pristine/crypto/aes_generic.c every run)
#   oracle : an independent FIPS-197 implementation in main.c, plus the FIPS-197
#            Appendix B / C.1 / C.2 / C.3 vectors.
# The key schedule in every ctx comes from the REAL aes_expandkey: lib/crypto/aes_rs.rs
# (the Rust the kernel runs), compiled into the same probe crate as aes_generic_rs.rs
# (one crate: two Rust staticlibs would clash on core's symbols).
# NOT covered: the crypto_alg table, module glue (kernel: libtest test_aes_generic()).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/aes_generic"
out="${TMPDIR:-/tmp}/aesgen-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/aes_generic.c"
GLUE="$root/port/tree/crypto/aes_generic_glue.c"
RS="$root/port/tree/crypto/aes_generic_rs.rs"
LIB="$root/port/tree/lib/crypto/aes_rs.rs"
for f in "$C" "$GLUE" "$RS" "$LIB"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$C" "$GLUE" "$out"
sed "s|SLICE|$out/ref_slice.c|" "$here/ref.c" > "$out/ref.c"
sed "s|SLICE|$out/subj_slice.c|" "$here/subj.c" > "$out/subj.c"
CF=(-O2 -g -Wall -Wno-unused-function -I "$here/shim")
REN=(-Dcrypto_ft_tab=ref_ft_tab -Dcrypto_it_tab=ref_it_tab -Dcrypto_aes_set_key=ref_set_key)
probe() { # probe RS_FILE OUT.rs : lib aes_rs.rs + the generic rs in one crate, plus table probes
    {
        echo '#![allow(non_snake_case, dead_code, non_upper_case_globals)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        echo 'mod aes_lib { #[allow(unused_imports)] use crate::kernel;'
        sed 's|^//!|//|' "$LIB"
        echo '}'
        echo 'mod aes_gen {'
        sed 's|^//!|//|' "$1"
        echo '#[no_mangle] pub extern "C" fn aesgen_probe_fl(k: usize, x: usize) -> u32 { FL_TAB.0[k][x] }'
        echo '#[no_mangle] pub extern "C" fn aesgen_probe_il(k: usize, x: usize) -> u32 { IL_TAB.0[k][x] }'
        echo '#[no_mangle] pub extern "C" fn aesgen_probe_sbox(x: usize) -> u32 { SBOX[x] as u32 }'
        echo '#[no_mangle] pub extern "C" fn aesgen_probe_isbox(x: usize) -> u32 { INV_SBOX[x] as u32 }'
        echo '}'
    } > "$2"
}
build() { # build RS_FILE DIR
    mkdir -p "$2"; probe "$1" "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name aesgen_rs -o "$2/librs.a" "$2/probe.rs"
    cc "${CF[@]}" "${REN[@]}" -c -o "$2/ref.o" "$out/ref.c"
    cc "${CF[@]}" -c -o "$2/subj.o" "$out/subj.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/subj.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if AESGEN_PROVE_CAN_FAIL=1 "$out/real/t" 2000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: a flipped output bit is detected"
if AESGEN_PROVE_BASIS_CAN_FAIL=1 "$out/real/t" 2000 >/dev/null 2>&1; then echo "*** BASIS CHECK CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: a wrong field polynomial in the FIPS oracle is detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$(printf '%b' "$from") TO=$(printf '%b' "$to") python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)>=1, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if ( "$out/m$n/t" 5000 ) >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
enc-rounds-24~if key_len > 24 {\n        b1 = f_nround~if key_len >= 24 {\n        b1 = f_nround
enc-rounds-16~if key_len > 16 {\n        b1 = f_nround~if key_len > 24 {\n        b1 = f_nround
dec-rounds-24~if key_len > 24 {\n        b1 = i_nround~if key_len >= 24 {\n        b1 = i_nround
dec-rounds-17 (equal on 16/24/32)~if key_len > 16 {\n        b1 = i_nround~if key_len > 17 {\n        b1 = i_nround
key-len-unsigned (equal on 16/24/32)~let key_len = ctx.key_length as i32;~let key_len = ctx.key_length;
enc-shift-index~ft[1][byte(bi[(n + 1) & 3], 1)]~ft[1][byte(bi[(n + 3) & 3], 1)]
dec-shift-index~it[1][byte(bi[(n + 3) & 3], 1)]~it[1][byte(bi[(n + 1) & 3], 1)]
enc-swapped-table~ft[2][byte(bi[(n + 2) & 3], 2)]~ft[3][byte(bi[(n + 2) & 3], 2)]
dec-swapped-table~it[0][byte(bi[n], 0)]~it[1][byte(bi[n], 0)]
last-round-table-enc~let fl = &FL_TAB.0;~let fl = &IL_TAB.0;
last-round-table-dec~let il = &IL_TAB.0;~let il = &FL_TAB.0;
last-round-key-word~f_rl(bi, 3, ks[kp + 3])~f_rl(bi, 3, ks[kp + 2])
enc-initial-addroundkey~ks[0] ^ get_le32(in_),~get_le32(in_),
dec-wrong-schedule~let ks = &ctx.key_dec;~let ks = &ctx.key_enc;
load-byte-order~u32::from_le_bytes(bytes.try_into().unwrap())~u32::from_be_bytes(bytes.try_into().unwrap())
store-byte-order~v.to_le_bytes()~v.to_be_bytes()
round-key-advance-enc~*kp += 4;~*kp += 3;
round-key-advance-dec~i_rn(bi, 3, ks[*kp + 3]),\n    ];\n    *kp += 4;~i_rn(bi, 3, ks[*kp + 3]),\n    ];\n    *kp += 5;
round-key-xor-truncated~ft[3][byte(bi[(n + 3) & 3], 3)]\n        ^ k~ft[3][byte(bi[(n + 3) & 3], 3)]\n        ^ (k & 0xffff)
fl-position~(sbox[x] as u32) << (8 * k)~(sbox[x] as u32) << (8 * (3 - k))
sbox-affine-constant~^ b.rotate_left(4) ^ 0x63~^ b.rotate_left(4) ^ 0x62
inv-affine-constant~s.rotate_left(6) ^ 0x05~s.rotate_left(6) ^ 0x04
field-polynomial~{ 0x1b } else~{ 0x1d } else
inverse-exponent~while i < 6 {~while i < 5 {
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" 1000000
