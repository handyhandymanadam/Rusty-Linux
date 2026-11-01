#!/usr/bin/env bash
# port/test/mpih-mul/run.sh -- the userspace differential for
# lib/crypto/mpi/mpih-mul.c.
#
# SCOPE: mpihelp_mul/mpihelp_mul_karatsuba_case/
# mpihelp_release_karatsuba_ctx/mpih_sqr_n_basecase/mpih_sqr_n
# (mpih-mul.c -> mpih_mul_rs.rs) -- none exported, all real symbols
# mpi-mul.c/mpi-pow.c (both still C) call directly.
#
# Shared dependencies pulled in as real code, not stubs: mpiutil_rs
# (mpi_alloc_limb_space/mpi_free_limb_space) and generic_mpih_rs
# (mpihelp_mul_1/addmul_1/add_n/sub_n/cmp) -- both already independently
# verified by their own harnesses; not under test here.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C
# is port/pristine/, not the tree. longlong.h is a trivial shim (see its
# own comment): mpih-mul.c never invokes anything it defines.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpih-mul"
out="${TMPDIR:-/tmp}/mpihmul-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpih-mul.c"
RS="$root/port/tree/lib/crypto/mpi/mpih_mul_rs.rs"
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
gen_rs "$RS" "$out/probe_mul.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpiutil_rs -o "$out/libutil.a" "$out/probe_util.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name generic_mpih_rs -o "$out/libmpih.a" "$out/probe_mpih.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpih_mul_rs -o "$out/libmul.a" "$out/probe_mul.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmpihelp_mul=c_mpihelp_mul -Dmpihelp_mul_karatsuba_case=c_mpihelp_mul_karatsuba_case
     -Dmpihelp_release_karatsuba_ctx=c_mpihelp_release_karatsuba_ctx
     -Dmpih_sqr_n_basecase=c_mpih_sqr_n_basecase -Dmpih_sqr_n=c_mpih_sqr_n)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c_mul.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

# rust_mpi_k{malloc,calloc,free,free_sensitive}: retained-thunk stand-ins,
# same reasoning as port/test/mpiutil/drv.c -- needed here because
# mpihelp_mul_karatsuba_case's ctx->next allocation goes through
# mpiutil_rs's own dependency on them (indirectly, via the real
# mpi_alloc_limb_space/mpi_free_limb_space) AND directly (kzalloc/kfree,
# reused as rust_mpi_kcalloc/rust_mpi_kfree per mpih_mul_rs.rs's own
# module doc comment).
cat > "$out/thunks.c" <<'EOF'
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
void *rust_mpi_kmalloc(size_t len) { return malloc(len); }
void *rust_mpi_kcalloc(size_t n, size_t size) { return calloc(n, size); }
void rust_mpi_kfree(void *p) { free(p); }
void rust_mpi_kfree_sensitive(void *p) { free(p); }
/* mpi_free()'s invalid-flags path calls this directly; unreachable here
 * (every MPI-shaped buffer this harness touches has flags == 0), but must
 * resolve at link time -- same reasoning as port/test/mpi-add/drv.c. */
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

cc -o "$out/t" "$out/drv.o" "$out/c_mul.o" "$out/thunks.o" \
    "$out/libmul.a" "$out/libmpih.a" "$out/libutil.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIHMUL_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
