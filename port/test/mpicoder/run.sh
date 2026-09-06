#!/usr/bin/env bash
# port/test/mpicoder/run.sh -- the userspace differential for
# lib/crypto/mpi/mpicoder.c.
#
# SCOPE: mpi_read_raw_data/mpi_read_from_buffer/mpi_read_buffer/
# mpi_get_buffer/mpi_write_to_sgl/mpi_read_raw_from_sgl (mpicoder.c ->
# mpicoder_rs.rs). mpi_alloc/mpi_free (mpiutil_rs) are shared
# dependencies, already ported and verified; not under test here.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The
# C is port/pristine/, not the tree. struct scatterlist/sg_miter_* are a
# from-scratch simulation -- see shim/linux/scatterlist.h's own comment.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpicoder"
out="${TMPDIR:-/tmp}/mpicoder-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpicoder.c"
RS="$root/port/tree/lib/crypto/mpi/mpicoder_rs.rs"
RS_UTIL="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
for f in "$C" "$RS" "$RS_UTIL"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

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
gen_rs "$RS" "$out/probe_coder.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpiutil_rs -o "$out/libutil.a" "$out/probe_util.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpicoder_rs -o "$out/libcoder.a" "$out/probe_coder.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmpi_read_raw_data=c_mpi_read_raw_data -Dmpi_read_from_buffer=c_mpi_read_from_buffer
     -Dmpi_read_buffer=c_mpi_read_buffer -Dmpi_get_buffer=c_mpi_get_buffer
     -Dmpi_write_to_sgl=c_mpi_write_to_sgl -Dmpi_read_raw_from_sgl=c_mpi_read_raw_from_sgl)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c_coder.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" -c -o "$out/sgl_shim.o" "$here/shim/sgl_shim.c"

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

cc -o "$out/t" "$out/drv.o" "$out/c_coder.o" "$out/sgl_shim.o" "$out/thunks.o" \
    "$out/libcoder.a" "$out/libutil.a" -lcrypto

# The arrangement proves itself FIRST, before its clean run is believed.
if MPICODER_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
