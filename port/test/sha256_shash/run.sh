#!/usr/bin/env bash
# port/test/sha256_shash/run.sh -- differential for crypto/sha256.c (shash layer).
#   run.sh             C (pristine helpers) vs Rust, >= 1M comparisons
#   run.sh --sabotage  mutants of the Rust must each be caught
# Scope: the four state export/import helpers, on sha224_ctx and sha256_ctx.
# NOT the digests (lib/crypto/sha256, port/test/sha256/), NOT the shash_alg
# glue and NOT the sha224/sha256_zero_message_hash tables, which stay C data;
# those are exercised in the kernel (libtest.c via the crypto API, and
# CONFIG_CRYPTO_SELFTESTS in the scratch config).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/sha256_shash"
out="${TMPDIR:-/tmp}/sha256shash-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/sha256.c"
RS="$root/port/tree/crypto/sha256_shash_rs.rs"
SHIM="$root/port/test/sha256/shim"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the shim's context structs must be the kernel's (whitespace-insensitive;
# the kernel's __aligned() on buf is dropped: u64 already forces 8-byte alignment)
norm() { sed -n '/^struct sha256_block_state {/,/^};/p;/^struct __sha256_ctx {/,/^};/p;/^struct sha224_ctx {/,/^};/p;/^struct sha256_ctx {/,/^};/p' "$1" | sed 's/ __aligned(__alignof__(__be64))//;s/SHA256_STATE_WORDS/8/' | tr -d ' \t\n'; }
[ "$(norm "$root/src/linux/include/crypto/sha2.h")" = "$(norm "$SHIM/crypto/sha2.h")" ] \
    || { echo "SHIM MISMATCH: struct __sha256_ctx / sha256_block_state / sha224_ctx / sha256_ctx"; exit 1; }
echo "shim struct __sha256_ctx (+ sha224_ctx, sha256_ctx) matches include/crypto/sha2.h"
python3 "$here/extract.py" "$C" "$out/extract.c"
sed "s|EXTRACT|$out/extract.c|" "$here/ref.c" > "$out/ref.c"
build() {
    mkdir -p "$2"
    { echo '#![allow(non_snake_case)]'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name sha256_shash_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -I "$SHIM" -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -I "$SHIM" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if SHA256S_PROVE_CAN_FAIL=1 "$out/real/t" 1000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned output detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)==1, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 20000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
partial-mod~ctx.bytecount % BLOCK_SIZE~ctx.bytecount % 32
no-round-down~ctx.bytecount -= partial;~ctx.bytecount -= 0;
export-extra-zero~*p.add(CTX_SIZE) = partial as u8;~*p.add(CTX_SIZE) = 0;
export-extra-truncated~*p.add(CTX_SIZE) = partial as u8;~*p.add(CTX_SIZE) = (partial as u8) & 0x1f;
export-extra-offset~*p.add(CTX_SIZE) = partial as u8;~*p.add(CTX_SIZE - 1) = partial as u8;
export-copy-short~as *const u8, p, CTX_SIZE);~as *const u8, p, CTX_SIZE - 1);
import-ignores-extra~let extra = *p.add(CTX_SIZE) as u64;~let extra = (*p.add(CTX_SIZE) as u64) & 0;
import-extra-offset~let extra = *p.add(CTX_SIZE) as u64;~let extra = *p.add(CTX_SIZE - 1) as u64;
import-extra-signed~let extra = *p.add(CTX_SIZE) as u64;~let extra = *p.add(CTX_SIZE) as i8 as u64;
import-overflow-panics~(*ctx).bytecount.wrapping_add(extra)~(*ctx).bytecount + extra
import-clears-top-bit~(*ctx).bytecount.wrapping_add(extra)~(*ctx).bytecount.wrapping_add(extra) & !(1u64 << 63)
import-copy-short~copy_nonoverlapping(p, ctx as *mut u8, CTX_SIZE)~copy_nonoverlapping(p, ctx as *mut u8, CTX_SIZE - 1)
export-core-short~ctx as *const u8, out as *mut u8, BUF_OFFSET~ctx as *const u8, out as *mut u8, BUF_OFFSET - 1
export-core-long~ctx as *const u8, out as *mut u8, BUF_OFFSET~ctx as *const u8, out as *mut u8, BUF_OFFSET + 1
import-core-short~in_ as *const u8, ctx as *mut u8, BUF_OFFSET~in_ as *const u8, ctx as *mut u8, BUF_OFFSET - 1
import-core-long~in_ as *const u8, ctx as *mut u8, BUF_OFFSET~in_ as *const u8, ctx as *mut u8, BUF_OFFSET + 1
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" 1000000
