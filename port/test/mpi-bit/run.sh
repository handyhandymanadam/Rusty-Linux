#!/usr/bin/env bash
# port/test/mpi-bit/run.sh -- the userspace differential for
# lib/crypto/mpi/mpi-bit.c.
#
# SCOPE: mpi_normalize/mpi_get_nbits/mpi_test_bit/mpi_set_bit/mpi_rshift
# (mpi-bit.c -> mpi_bit_rs.rs). mpi_alloc/mpi_resize (mpiutil_rs) and
# mpihelp_rshift (generic_mpih_rs) are shared dependencies, already
# ported and verified; not under test here.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C
# is port/pristine/, not the tree.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpi-bit"
out="${TMPDIR:-/tmp}/mpibit-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpi-bit.c"
RS="$root/port/tree/lib/crypto/mpi/mpi_bit_rs.rs"
RS_UTIL="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
RS_MPIH="$root/port/tree/lib/crypto/mpi/generic_mpih_rs.rs"
for f in "$C" "$RS" "$RS_UTIL" "$RS_MPIH"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

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
gen_rs "$RS_UTIL" "$out/probe_util.rs"
gen_rs "$RS_MPIH" "$out/probe_mpih.rs"
gen_rs "$RS" "$out/probe_bit.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpiutil_rs -o "$out/libutil.a" "$out/probe_util.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name generic_mpih_rs -o "$out/libmpih.a" "$out/probe_mpih.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_bit_rs -o "$out/libbit.a" "$out/probe_bit.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmpi_normalize=c_mpi_normalize -Dmpi_get_nbits=c_mpi_get_nbits
     -Dmpi_test_bit=c_mpi_test_bit -Dmpi_set_bit=c_mpi_set_bit
     -Dmpi_rshift=c_mpi_rshift)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c_bit.o" "$C"
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

cc -o "$out/t" "$out/drv.o" "$out/c_bit.o" "$out/thunks.o" \
    "$out/libbit.a" "$out/libmpih.a" "$out/libutil.a" -lcrypto

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIBIT_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
