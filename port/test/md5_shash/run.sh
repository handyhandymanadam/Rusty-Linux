#!/usr/bin/env bash
# port/test/md5_shash/run.sh -- differential for crypto/md5.c (shash layer).
#   run.sh             C (pristine helpers) vs Rust, ~4M comparisons
#   run.sh --sabotage  7 mutants of the Rust must each be caught
# Scope: the four state export/import helpers and md5_zero_message_hash. NOT
# the digest (lib/crypto/md5, port/test/md5/) and NOT the shash_alg glue, which
# stays C and is exercised in the kernel (libtest.c via the crypto API, and
# CONFIG_CRYPTO_SELFTESTS in the scratch config).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/md5_shash"
out="${TMPDIR:-/tmp}/md5shash-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/md5.c"
RS="$root/port/tree/crypto/md5_shash_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the shim's struct md5_ctx must be the kernel's (whitespace-insensitive)
norm() { sed -n '/^struct md5_ctx {/,/^};/p;/^struct md5_block_state {/,/^};/p' "$1" | sed 's/__attribute__((aligned(\(.*\))))/__aligned(\1)/' | tr -d ' \t\n'; }
[ "$(norm "$root/src/linux/include/crypto/md5.h")" = "$(norm "$root/port/test/md5/shim/crypto/md5.h")" ] \
    || { echo "SHIM MISMATCH: struct md5_ctx / md5_block_state"; exit 1; }
echo "shim struct md5_ctx matches include/crypto/md5.h"
python3 "$here/extract.py" "$C" "$out/extract.c"
sed "s|EXTRACT|$out/extract.c|" "$here/ref.c" > "$out/ref.c"
build() {
    mkdir -p "$2"
    { echo '#![allow(non_snake_case)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use {kabi_export, kabi_rule}; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name md5_shash_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -Dmd5_zero_message_hash=c_md5_zero_message_hash -I "$root/port/test/md5/shim" -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -I "$root/port/test/md5/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if MD5S_PROVE_CAN_FAIL=1 "$out/real/t" 1000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned output detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert f in s, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 20000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
partial-mod~ctx.bytecount % BLOCK_SIZE~ctx.bytecount % 32
no-round-down~ctx.bytecount -= partial;~ctx.bytecount -= 0;
export-extra-zero~*p.add(CTX_SIZE) = partial as u8;~*p.add(CTX_SIZE) = 0;
import-ignores-extra~let extra = *p.add(CTX_SIZE) as u64;~let extra = (*p.add(CTX_SIZE) as u64) & 0;
import-overflow-panics~(*ctx).bytecount.wrapping_add(extra)~(*ctx).bytecount + extra
export-core-short~ctx as *const u8, out as *mut u8, BUF_OFFSET~ctx as *const u8, out as *mut u8, BUF_OFFSET - 1
zero-hash-byte~0xd4, 0x1d, 0x8c~0xd4, 0x1e, 0x8c
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" 2000000
