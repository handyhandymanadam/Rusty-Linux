#!/usr/bin/env bash
# kbuild-env.sh -- pin the toolchain kbuild actually uses.
#
# WHY THIS EXISTS
#   A previous attempt had a harness silently compiling with a different
#   compiler than the kernel. `rustc` on PATH here is a rustup shim and three
#   toolchains are installed (nightly, stable, 1.98.0); which one it resolves
#   to is a global mutable setting, not a property of this project.
#
# WHY 1.98.0 STABLE AND NOT THE NIGHTLY
#   6.18.49 cannot link nightly 1.100.0's `core`. Nightly added
#   `ClampBounds` impls for f32/f64 (core/src/cmp/clamp.rs, impl_for_float!),
#   which are concrete, always codegen'd, and emit soft-float calls:
#       ld.lld: undefined symbol: fmaximum_numf, fminimum_numf, __gtsf2,
#                                 fmaximum_num,  fminimum_num,  __gtdf2
#   The kernel builds core itself against a `-mmx,+soft-float` target and
#   provides no float builtins, so this is unlinkable rather than merely
#   awkward. 1.98.0's core has no clamp.rs and no such impls.
#   This is the SCOPE.md §2 lag cost, arriving inverted: the toolchain was too
#   NEW for the LTS, not too old.
#
# THE THING THAT IS NOT OBVIOUS, and was measured rather than assumed:
#   kbuild IGNORES RUSTC from the environment. The kernel Makefile says
#   `RUSTC = rustc`, and a makefile assignment beats an environment variable
#   in GNU make. Verified in this tree:
#       RUSTC=/nonexistent/rustc make rustavailable   ->  "Rust is available!"
#       make RUSTC=/nonexistent/rustc rustavailable   ->  fails
#   So the pins MUST be passed as make command-line arguments. Exporting them
#   looks identical and does nothing. Use `kmake`, never bare `make`.
#
# USE
#   source ./kbuild-env.sh    # from the repo root
#   kmake O=../../build-fast olddefconfig
#   kmake O=../../build-fast -j"$(nproc)"
#
#   ./kbuild-env.sh          prints the toolchain it READ from disk, and exits
#                            non-zero if a pinned path is missing.

RUSTY_TOOLCHAIN="$HOME/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu"

# Absolute paths -- deliberately NOT the ~/.cargo/bin shims.
KB_RUSTC="$RUSTY_TOOLCHAIN/bin/rustc"
KB_CARGO="$RUSTY_TOOLCHAIN/bin/cargo"
KB_RUSTDOC="$RUSTY_TOOLCHAIN/bin/rustdoc"
KB_RUSTFMT="$RUSTY_TOOLCHAIN/bin/rustfmt"
KB_RUST_LIB_SRC="$RUSTY_TOOLCHAIN/lib/rustlib/src/rust/library"
KB_BINDGEN=/usr/bin/bindgen

# C side: LLVM=1 selects the clang/lld toolchain. clang on PATH is a ccache
# wrapper (/usr/lib64/ccache/clang -> ccache); that is intentional, it is
# content-hashed and the report below shows what it resolves to.
KB_LLVM=1

# kABI STABILITY RULES MUST BE ENABLED, and this is not a Kconfig symbol --
# scripts/Makefile.build:194 passes --stable to gendwarfksyms only when
# KBUILD_GENDWARFKSYMS_STABLE is set. Without it the KABI_TYPE_STRING() rules
# in our thunk-free files are SILENTLY IGNORED and the MODVERSIONS CRCs move.
#
# Measured on lib/bcd.c, the first thunk-free port: with Rust defining
# _bcd2bin() directly and no rule in force, the fingerprint went
# 0x605be21c -> 0xcf47c3a6.
#
# THE REASON ORIGINALLY WRITTEN HERE WAS WRONG, and is corrected in
# port/tree/include/linux/kabi.h and port/tree/lib/math/int_pow.c. It is not
# that Rust spells `unsigned char` as `u8`. Where the EXPORT_SYMBOL stays in C,
# the hashed DWARF comes from export.h's __gendwarfksyms_ptr_<sym>, a
# pointer-to-function whose DW_TAG_subroutine_type has parameter types but no
# parameter NAMES; losing the names is what moves the CRC, and no Rust type is
# ever consulted. Where the export moves INTO the Rust object
# (kernel::kabi_export!), the Rust DWARF is hashed and the type spelling does
# matter -- which is the case this flag now mostly serves.
#
# It is here rather than in a config fragment because forgetting it does not
# fail the build -- it silently changes the module ABI, which is the worst
# shape a mistake can take. rig/kabi-pin.sh --check catches it after the fact.
KB_GENDWARFKSYMS_STABLE=1

kmake() {
    make -C "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/src/linux" \
        KBUILD_GENDWARFKSYMS_STABLE="$KB_GENDWARFKSYMS_STABLE" \
        LLVM="$KB_LLVM" \
        RUSTC="$KB_RUSTC" \
        CARGO="$KB_CARGO" \
        RUSTDOC="$KB_RUSTDOC" \
        RUSTFMT="$KB_RUSTFMT" \
        BINDGEN="$KB_BINDGEN" \
        HOSTRUSTC="$KB_RUSTC" \
        RUST_LIB_SRC="$KB_RUST_LIB_SRC" \
        "$@"
}

kbuild_env_report() {
    local rc=0 p
    echo "pinned toolchain, as READ from disk:"
    for p in "$KB_RUSTC" "$KB_CARGO" "$KB_RUSTDOC" "$KB_RUSTFMT" \
             "$KB_BINDGEN" "$KB_RUST_LIB_SRC"; do
        if [ -e "$p" ]; then
            printf '  ok      %s\n' "$p"
        else
            printf '  MISSING %s\n' "$p"; rc=1
        fi
    done
    echo
    printf '  rustc    %s\n' "$("$KB_RUSTC" --version 2>&1)"
    printf '  rustc-llvm %s\n' "$("$KB_RUSTC" --version --verbose 2>&1 | sed -n 's/^LLVM version: //p')"
    printf '  bindgen  %s\n' "$("$KB_BINDGEN" --version 2>&1)"
    printf '  clang    %s  [%s -> %s]\n' \
        "$(clang --version 2>&1 | head -1)" \
        "$(command -v clang)" "$(readlink -f "$(command -v clang)")"
    printf '  ld.lld   %s\n' "$(ld.lld --version 2>&1)"
    echo
    echo "  PATH rustc would have been: $(command -v rustc) -> $(rustc --version 2>&1)"
    echo "  (kbuild never sees that one; kmake passes the pin on the command line)"
    return $rc
}

# Executed rather than sourced -> report and exit with what was read.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    kbuild_env_report
    exit $?
fi
