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
#   This is the notes/SCOPE.md §2 lag cost, arriving inverted: the toolchain was too
#   NEW for the LTS, not too old.
#
#   FIXED UPSTREAM, 2026-09-06: reported to the rustc team, who pointed at
#   rust-lang/rust#162191 (merged 2026-09-04) -- marks the float ClampBounds
#   methods #[inline], so they no longer force soft-float symbols into every
#   core.o regardless of use. Verified directly, not just read: pulled
#   nightly 1.100.0 (f248f4038, 2026-09-05) and did a full build-fast build
#   against it in a scratch dir -- `RUSTC L rust/core.o` through a clean
#   `bzImage` link, zero undefined-symbol errors. Still pinned to 1.98.0
#   here regardless; nothing forces a move off a working stable toolchain,
#   this just means nightly is no longer a hazard if we ever want it.
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
#   source /home/adam/Rusty-Linux/kbuild-env.sh
#   kmake O=../../build-fast olddefconfig
#   kmake O=../../build-fast -j"$(nproc)"
#
#   ./kbuild-env.sh          prints the toolchain it READ from disk, verifies
#                            every pinned version, and exits non-zero if any
#                            path is missing or any version is wrong.
#
# ON A MACHINE WHERE THE TOOLS LIVE SOMEWHERE ELSE
#   Create kbuild-env.local.sh next to this file (gitignored) and set the
#   KB_* path variable(s) that differ:
#
#       KB_BINDGEN=/opt/bindgen-0.72.1/bin/bindgen
#
#   PATHS are per-machine. VERSIONS (KB_PIN_*) are the contract and are not
#   overridable from there -- an override that pointed at a different version
#   would be the exact failure this file exists to prevent, so it is checked
#   and refused rather than trusted.

# The repo root this file lives in -- NOT $(pwd) (this is sourced, and the
# caller's cwd is whatever it happens to be) and NOT a hardcoded path (a
# worktree at a different path sources its OWN copy of this file, and a
# hardcoded path would silently point kmake() at the main checkout's tree
# instead -- found by md5-porter, 2026-09-05, running from
# ../Rusty-Linux-wt-md5). ${BASH_SOURCE[0]} is this file's own path
# regardless of who sources it or from where.
KB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# THE PIN IS A VERSION, NOT A PATH. This distinction was implicit before and
# it cost a session: the paths below were one machine's absolute paths, so on
# a second machine `/usr/bin/bindgen` simply did not exist -- and the only
# symptom was CONFIG_RUST silently vanishing from the built .config, because
# `make rustavailable` failed and Kconfig dropped the symbol without a word.
# That is notes/PRIOR-ART.md §2's kernel-that-contains-no-Rust, reached through the
# very file that exists to prevent it. rig/config.sh caught it by reading the
# built .config back; nothing in here did.
#
# So: versions are the contract and are NOT overridable. Paths are only how a
# given machine reaches them, and ARE overridable -- but every override is
# still an absolute path to a specific binary that is then VERSION-CHECKED
# below. There is no PATH fallback anywhere in this file, and adding one would
# reintroduce exactly the defect it was written against.
KB_PIN_RUSTC=1.98.0
KB_PIN_BINDGEN=0.72.1
KB_PIN_LLVM=22.1.8

# Per-machine overrides, in precedence order:
#   1. kbuild-env.local.sh next to this file (gitignored; set KB_* there)
#   2. the environment
#   3. the defaults below
# The local file is sourced FIRST so it can set anything, and the `:=`
# defaults then fill in only what nobody supplied.
if [ -r "$KB_ROOT/kbuild-env.local.sh" ]; then
    . "$KB_ROOT/kbuild-env.local.sh"
fi

: "${RUSTY_TOOLCHAIN:=$HOME/.rustup/toolchains/$KB_PIN_RUSTC-x86_64-unknown-linux-gnu}"

# Absolute paths -- deliberately NOT the ~/.cargo/bin shims.
: "${KB_RUSTC:=$RUSTY_TOOLCHAIN/bin/rustc}"
: "${KB_CARGO:=$RUSTY_TOOLCHAIN/bin/cargo}"
: "${KB_RUSTDOC:=$RUSTY_TOOLCHAIN/bin/rustdoc}"
: "${KB_RUSTFMT:=$RUSTY_TOOLCHAIN/bin/rustfmt}"
: "${KB_RUST_LIB_SRC:=$RUSTY_TOOLCHAIN/lib/rustlib/src/rust/library}"
: "${KB_BINDGEN:=/usr/bin/bindgen}"

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

# kb_verify -- every pinned tool exists AND reports its pinned version.
#
# WHY kmake CALLS THIS. Before, this file only checked anything when EXECUTED;
# when SOURCED -- which is how all ~50 rig scripts and every build use it --
# nothing was verified at all. `kbuild_env_report` printed "MISSING" to a human
# who might not be there, and kmake ran regardless. A missing or wrong-version
# tool then surfaced as a silently different kernel, not as an error.
#
# It reports the version it READ from each binary, never the fact that it
# looked -- same rule as every guard in rig/.
kb_verify() {
    local rc=0 got

    _kb_need() {   # <label> <path> <expected> <version-command...>
        local label=$1 path=$2 want=$3; shift 3
        if [ ! -e "$path" ]; then
            printf '  MISSING  %-9s %s\n' "$label" "$path" >&2
            rc=1; return
        fi
        [ -n "$want" ] || return 0
        got=$("$@" 2>&1 | head -1)
        # Compare the first dotted-numeric TOKEN exactly. A substring test
        # would pass 1.98.01 for 1.98.0, and a check that cannot fail cleanly
        # is the same class of defect as the one this file guards against.
        local ver
        ver=$(printf '%s\n' "$got" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ "$ver" = "$want" ] && return 0
        printf '  VERSION  %-9s pinned %s, but %s reports %s (%s)\n' \
               "$label" "$want" "$path" "${ver:-no version found}" "$got" >&2
        rc=1
    }

    _kb_need rustc   "$KB_RUSTC"        "$KB_PIN_RUSTC"   "$KB_RUSTC" --version
    _kb_need cargo   "$KB_CARGO"        ""
    _kb_need rustdoc "$KB_RUSTDOC"      ""
    _kb_need rustfmt "$KB_RUSTFMT"      ""
    _kb_need rustsrc "$KB_RUST_LIB_SRC" ""
    _kb_need bindgen "$KB_BINDGEN"      "$KB_PIN_BINDGEN" "$KB_BINDGEN" --version

    # clang/ld.lld are the one pair kbuild DOES resolve through PATH (LLVM=1),
    # so they are the remaining route to "built with the wrong compiler" and
    # are version-checked for exactly that reason.
    local cc ld
    cc=$(command -v clang 2>/dev/null) || cc=
    ld=$(command -v ld.lld 2>/dev/null) || ld=
    if [ -z "$cc" ]; then printf '  MISSING  %-9s not on PATH\n' clang >&2; rc=1
    else _kb_need clang "$cc" "$KB_PIN_LLVM" clang --version; fi
    if [ -z "$ld" ]; then printf '  MISSING  %-9s not on PATH\n' ld.lld >&2; rc=1
    else _kb_need ld.lld "$ld" "$KB_PIN_LLVM" ld.lld --version; fi

    unset -f _kb_need
    return $rc
}

# Memoised: kmake is called many times per build and the checks spawn
# processes. KB_VERIFIED is set only on a PASS, so a failure re-reports.
kb_require() {
    [ "${KB_VERIFIED:-0}" = 1 ] && return 0
    if kb_verify; then KB_VERIFIED=1; return 0; fi
    cat >&2 <<'KBERR'

kbuild-env.sh: REFUSING TO BUILD. The pinned toolchain is not what is on disk.

This is not a warning. Building anyway is the failure this file exists to
prevent -- a previous attempt silently compiled with the wrong compiler, and
on this project a missing bindgen silently drops CONFIG_RUST and produces a
kernel with no Rust in it that passes every behavioural check.

Fix the PATH, not the pin: create kbuild-env.local.sh next to this file
(it is gitignored) and set the KB_* variable(s) named above, e.g.

    KB_BINDGEN=/opt/bindgen-0.72.1/bin/bindgen

Versions (KB_PIN_*) are the contract and are deliberately not overridable.
KBERR
    return 1
}

kmake() {
    kb_require || return 1
    # KB_ARCH (unset by default => native x86-64, byte-for-byte the old command):
    # set KB_ARCH=arm64 for the cross build (logs/arm64.md). LLVM=1 needs no
    # CROSS_COMPILE; clang takes --target from ARCH.
    make -C "$KB_ROOT/src/linux" ${KB_ARCH:+ARCH=$KB_ARCH} \
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
    echo
    echo "pins (not overridable): rustc $KB_PIN_RUSTC, bindgen $KB_PIN_BINDGEN, llvm $KB_PIN_LLVM"
    if [ -r "$KB_ROOT/kbuild-env.local.sh" ]; then
        echo "local override in effect: $KB_ROOT/kbuild-env.local.sh"
    else
        echo "no kbuild-env.local.sh; using defaults + environment"
    fi
    echo
    if kb_verify; then
        echo "  VERIFIED -- every pinned tool is present and reports its pinned version"
    else
        echo "  ^^ kmake WILL REFUSE TO RUN until the above is fixed" >&2
        rc=1
    fi
    return $rc
}

# Executed rather than sourced -> report and exit with what was read.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    kbuild_env_report
    exit $?
fi
