#!/usr/bin/env bash
# port/test/mpi-mul-pow/run.sh -- the userspace differential for
# lib/crypto/mpi/mpi-mul.c (mpi_mul/mpi_mulm) and lib/crypto/mpi/mpi-pow.c
# (mpi_powm).
#
# Links the full mpi/ crate graph these two files' real dependency chain
# pulls in transitively (mpi_tdiv_r -> mpi_add -> mpi_mod -> mpi_fdiv_r,
# a genuine cross-reference loop resolved at static-link time, not build
# order) -- every one of those crates already has its own independent
# harness; this one is not re-verifying them, just needs them present to
# link.
#
# THE RUST IS GENERATED from the files the kernel builds, not copied. The
# C is port/pristine/, not the tree. mpi-pow.c's retained cond_resched()
# thunk (port/tree/lib/crypto/mpi/mpi-pow.c) is linked for the Rust arm
# only -- the C arm (pristine mpi-pow.c) calls the shim's stub directly.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpi-mul-pow"
out="${TMPDIR:-/tmp}/mpimulpow-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C_MUL="$root/port/pristine/lib/crypto/mpi/mpi-mul.c"
C_POW="$root/port/pristine/lib/crypto/mpi/mpi-pow.c"
RETAINED_POW="$root/port/tree/lib/crypto/mpi/mpi-pow.c"
declare -A RS=(
    [mpiutil_rs]="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
    [generic_mpih_rs]="$root/port/tree/lib/crypto/mpi/generic_mpih_rs.rs"
    [mpih_div_rs]="$root/port/tree/lib/crypto/mpi/mpih_div_rs.rs"
    [mpi_div_rs]="$root/port/tree/lib/crypto/mpi/mpi_div_rs.rs"
    [mpi_mod_rs]="$root/port/tree/lib/crypto/mpi/mpi_mod_rs.rs"
    [mpi_add_rs]="$root/port/tree/lib/crypto/mpi/mpi_add_rs.rs"
    [mpi_sub_ui_rs]="$root/port/tree/lib/crypto/mpi/mpi_sub_ui_rs.rs"
    [mpih_mul_rs]="$root/port/tree/lib/crypto/mpi/mpih_mul_rs.rs"
    [mpi_mul_rs]="$root/port/tree/lib/crypto/mpi/mpi_mul_rs.rs"
    [mpi_pow_rs]="$root/port/tree/lib/crypto/mpi/mpi_pow_rs.rs"
)
for f in "$C_MUL" "$C_POW" "$RETAINED_POW" "${RS[@]}"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

gen_rs() {
    {
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        sed 's|^//!|//|' "$1"
    } > "$2"
}

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
LIBS=()
for name in mpiutil_rs generic_mpih_rs mpih_div_rs mpi_div_rs mpi_mod_rs \
            mpi_add_rs mpi_sub_ui_rs mpih_mul_rs mpi_mul_rs mpi_pow_rs; do
    gen_rs "${RS[$name]}" "$out/probe_$name.rs"
    "$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name "$name" \
        -o "$out/lib$name.a" "$out/probe_$name.rs"
    LIBS+=("$out/lib$name.a")
done

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN_MUL=(-Dmpi_mul=c_mpi_mul -Dmpi_mulm=c_mpi_mulm)
REN_POW=(-Dmpi_powm=c_mpi_powm)
cc "${CF[@]}" "${REN_MUL[@]}" -c -o "$out/c_mul.o" "$C_MUL"
cc "${CF[@]}" "${REN_POW[@]}" -c -o "$out/c_pow.o" "$C_POW"
cc "${CF[@]}" -c -o "$out/retained_pow.o" "$RETAINED_POW"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

cat > "$out/thunks.c" <<'EOF'
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
void *rust_mpi_kmalloc(size_t len) { return malloc(len); }
void *rust_mpi_kcalloc(size_t n, size_t size) { return calloc(n, size); }
void rust_mpi_kfree(void *p) { free(p); }
void rust_mpi_kfree_sensitive(void *p) { free(p); }
int _printk(const char *fmt, ...)
{
	va_list ap;
	int ret;
	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return ret;
}
EOF
cc -O2 -g -c -o "$out/thunks.o" "$out/thunks.c"

# --start-group/--end-group: the mpi/ crates cross-reference each other
# (mpi_add_rs -> mpi_mod_rs -> mpi_div_rs -> mpi_add_rs), a genuine
# circular dependency at the symbol level that a single left-to-right
# archive scan cannot resolve.
cc -o "$out/t" "$out/drv.o" "$out/c_mul.o" "$out/c_pow.o" "$out/retained_pow.o" \
    "$out/thunks.o" -Wl,--start-group "${LIBS[@]}" -Wl,--end-group -lcrypto

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIMULPOW_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
