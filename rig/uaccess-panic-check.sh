#!/usr/bin/env bash
# uaccess-panic-check.sh <build-dir>
#
# List every ported Rust object with an undefined `core::panicking::*`
# symbol -- any panic path (overflow-checked add/sub/mul, bounds checks,
# plain panic!/unwrap/expect).
#
# CORRECTED 2026-09-06 (decompress-porter, verified independently): this
# comment used to say these checks were "unset in both of this project's
# configs, but real and user-selectable" -- FALSE, and stated without
# checking. CONFIG_RUST_OVERFLOW_CHECKS=y in BOTH build-fast/.config and
# build-full/.config (it is `default y, depends on RUST` in
# lib/Kconfig.debug, and neither fragment turns it off), confirmed a
# third way against the actual per-object .cmd files
# (`-Coverflow-checks=y` really is passed to rustc). Every hit this
# script finds is a LIVE panic path in both of today's real builds, not
# a hypothetical one gated behind a config nobody sets. Only
# CONFIG_FUNCTION_TRACER/DYNAMIC_FTRACE/KASAN/KCOV/KCSAN/UBSAN (the
# separate, unrelated symbols the objtool/notrace finding in
# logs/porting-hazards.md depends on) are actually off in both configs --
# do not conflate the two findings.
#
# WHY THIS EXISTS. Adversarial review found the same defect shape three
# times independently in one night (2026-09-06): usercopy_rs.rs,
# strnlen_user_rs.rs, strncpy_from_user_rs.rs, and a related instance in
# iomap.c's PIO helpers. All three uaccess-bracketed cases share the same
# consequence, which is what makes the hazard worse than an ordinary panic:
# the panicking body runs INSIDE the retained C entry's
# user_read_access_begin()/user_access_end() (STAC/CLAC) bracket. A panic
# there never reaches user_access_end(), so the kernel dies with SMAP
# disabled -- a failure mode the C being replaced cannot produce, because it
# has no checked-arithmetic panic path at all.
#
# AN ORDINARY (non-uaccess) HIT IS STILL A REAL DIVERGENCE, not a pass.
# Where the C silently wraps or indexes out of range, a Rust BUG() on the
# same input is a worse failure mode than the C's, even without SMAP
# involved -- lower severity than the uaccess case, never "fine". Read a
# long list of hits as a list of divergences to triage, not as noise.
#
# WHAT THIS DOES NOT DO. It does not determine which objects are actually
# uaccess-bracketed -- that requires knowing the call graph, which this
# project's crate-per-file, retained-C-entry shape does not expose to a
# simple script. It lists every core::panicking dependency (any of them
# could fire under the right config regardless of bracket), and a human
# decides which entries matter most: check whether the C entry that calls
# into the object toggles STAC/CLAC (grep the C file for
# user_read_access_begin/masked_user_access_begin) before deciding this is
# the elevated-severity shape rather than an ordinary panic path.
#
# THE FIX IS NOT ONE PATTERN -- the C's own semantics choose it, not
# reviewer taste.
#   - C is DEFINED wraparound (unsigned +/-/*)   -> wrapping_* IS the C's
#     semantics, faithfully reproduced. (strnlen_user_rs.rs,
#     strncpy_from_user_rs.rs.)
#   - C is UB or implementation-defined (a shift by an unbounded count,
#     signed overflow) -> there is no C behaviour to reproduce by wrapping;
#     constrain the operand's PROVABLE RANGE instead (e.g. `n & 7` before
#     a shift), so the compiler eliminates the check by proof.
#     (usercopy_rs.rs's aligned_byte_mask.)
#   Reaching for wrapping_* on the second shape would silently codify an
#   architecture's incidental behaviour (e.g. x86's shift-count-mod-64) as
#   a guarantee, and the panic symbol disappearing would read as a fix
#   while papering over a real divergence from a C that has no defined
#   answer at all. Read the C before picking either one.
#
# THIS SCRIPT'S OWN HISTORY, because it is unusually long for a ~130-line
# file and worth having in one place rather than in git log alone. Every
# one of these was found the same day, by adversarial review, one round
# after the last fix landed:
#   v1: matched only the panic_const_* mangled shape -- missed
#       panic_bounds_check and plain panic!/unwrap/expect entirely, and
#       hardcoded a specific mangling scheme's hash-prefix structure.
#   v2: `set -e`+pipefail treated "grep found nothing" (the common,
#       expected case) as pipeline failure and aborted after the FIRST
#       clean object -- the sweep never got past file #1.
#   v2: a self-test EXIT trap's own exit status clobbered a deliberate
#       `exit 0`, so real findings printed correctly and the script still
#       reported failure.
#   v2: `$build` got normalized to an absolute path, then a later `find`
#       call prepended the root AGAIN -- searching a path that never
#       existed, silently returning zero results. Every prior "0 objects"
#       claim from this script, on any build, was false; confirmed against
#       nm -u showing a live panic_const_add_overflow in lib/dim/
#       rdma_dim_rs.o that the script had already called clean.
#   v3 (this version): the CLASS behind that last bug was still live --
#       any nonexistent search root (a typo, a build that was never
#       compiled, `find`'s `2>/dev/null` swallowing a missing directory)
#       still printed "0 object(s)", byte-identical to a genuinely clean
#       sweep. Fixed by asserting the search root exists before scanning
#       and always printing how many objects were actually SCANNED, not
#       just how many matched -- "0 of 412 objects" cannot be misread as
#       "the sweep never ran", the way bare "0 objects" could and did.
#   v3: the self-test only ran when explicitly asked (`--self-test` or no
#       argument), never on the invocation people actually use for the
#       job. Fixed: it now runs before every real sweep too, and a sweep
#       refuses to report results if the self-test could not be trusted.
#   v3: the self-test called bare `rustc`, not this project's pinned
#       toolchain ($KB_RUSTC via kbuild-env.sh, which every other rig/
#       script sources) -- on a machine with no unpinned rustc on PATH,
#       every self-test silently could not run, and "couldn't build the
#       fixture" and "the matcher is broken" printed the same message and
#       exit code, indistinguishable from each other. Fixed: sources
#       kbuild-env.sh like the rest of rig/, and a toolchain-missing
#       result is now worded and coded differently from a matcher failure.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

SELF_TEST_TMP=""
cleanup_self_test() {
    # An EXIT trap's own exit status becomes the script's final exit status.
    [ -n "$SELF_TEST_TMP" ] && rm -rf "$SELF_TEST_TMP"
    true
}
trap cleanup_self_test EXIT

# Exit codes from self_test(), distinguished on purpose: a broken
# environment (no pinned rustc) must never read the same as a broken
# matcher, or a real regression hides behind "oh, self-test doesn't work
# here" the next time someone sees it fail.
ST_OK=0
ST_NO_TOOLCHAIN=2
ST_MATCHER_BROKEN=3

self_test() {
    SELF_TEST_TMP=$(mktemp -d)
    local out="$SELF_TEST_TMP"
    cat > "$out/fixture.rs" <<'EOF'
#[no_mangle]
pub extern "C" fn fixture(a: &[u8], i: usize) -> u8 { a[i] }
EOF
    if [ ! -x "$KB_RUSTC" ]; then
        echo "self-test: pinned rustc not found at $KB_RUSTC -- cannot self-test on this machine" >&2
        return $ST_NO_TOOLCHAIN
    fi
    # -C panic=abort to match how the real objects this script scans are
    # actually built; without it the fixture also pulls in
    # panic_cannot_unwind, which is harmless for matching but makes the
    # fixture a less faithful stand-in for what it's meant to represent.
    if ! "$KB_RUSTC" --edition 2021 --crate-type lib --emit=obj \
            -C debug-assertions=on -C panic=abort \
            -o "$out/fixture.o" "$out/fixture.rs" 2>/dev/null; then
        echo "self-test: pinned rustc could not build the fixture" >&2
        return $ST_NO_TOOLCHAIN
    fi
    if ! nm -u "$out/fixture.o" 2>/dev/null | grep -q '4core9panicking'; then
        echo "*** SELF-TEST FAILED: fixture has no core::panicking dependency to find -- build changed?" >&2
        return $ST_MATCHER_BROKEN
    fi
    local hit; hit=$(matches "$out/fixture.o")
    if [ -z "$hit" ]; then
        echo "*** SELF-TEST FAILED: this script did not detect its own fixture's panic_bounds_check dependency" >&2
        return $ST_MATCHER_BROKEN
    fi
    echo "self-test: fixture's panic dependency detected ($hit) -- the matcher works"
    return $ST_OK
}

# Any undefined symbol naming core::panicking, demangled -- not just the
# panic_const_* family, and not tied to a specific mangling scheme's exact
# hash/prefix shape.
matches() {
    # `grep -oE` exits 1 when an object has NO panicking dependency, the
    # common case -- guarded with `|| true` so that (under this script's
    # own `set -e -o pipefail`) the ordinary "nothing found" result does
    # not abort the whole sweep.
    nm -u "$1" 2>/dev/null | c++filt 2>/dev/null \
        | { grep -oE 'core(\[[0-9a-f]+\])?::panicking::[A-Za-z0-9_:]+' || true; } \
        | sed -E 's/^core(\[[0-9a-f]+\])?::panicking:://' | sort -u | tr '\n' ',' | sed 's/,$//'
}

if [ "${1:-}" = "--self-test" ]; then
    self_test; exit $?
fi

st_rc=0
self_test || st_rc=$?
echo
if [ "$st_rc" -eq "$ST_NO_TOOLCHAIN" ]; then
    echo "*** proceeding WITHOUT having proven the matcher works on this machine -- treat results below as unverified" >&2
elif [ "$st_rc" -ne "$ST_OK" ]; then
    echo "*** REFUSING TO SCAN: self-test failed ($st_rc), the matcher itself cannot be trusted right now" >&2
    exit "$st_rc"
fi

build=${1:?usage: uaccess-panic-check.sh <build-dir> (or --self-test to just self-test)}
case "$build" in
    /*) ;;                              # already absolute
    *) [ -d "$root/$build" ] && build="$root/$build" ;;
esac
[ -d "$build/lib" ] || { echo "*** no such directory: $build/lib -- refusing to report a result for a build that was never scanned" >&2; exit 1; }

n=0
scanned=0
printf '%-50s %s\n' 'OBJECT' 'core::panicking SYMBOLS'
while IFS= read -r -d '' o; do
    scanned=$((scanned + 1))
    syms=$(matches "$o")
    [ -n "$syms" ] || continue
    n=$((n + 1))
    printf '%-50s %s\n' "${o#"$root"/}" "$syms"
done < <(find "$build/lib" -name '*_rs.o' -print0)

echo
echo "$n of $scanned scanned object(s) have a core::panicking dependency"
if [ "$scanned" -eq 0 ]; then
    echo "*** 0 objects were even SCANNED -- this is not a clean result, it is an empty search; check the build dir" >&2
    exit 1
fi
if [ "$n" -ne 0 ]; then
    echo "For each: grep the C entry it's called from for user_read_access_begin/masked_user_access_begin to judge severity -- and remember an ordinary (non-uaccess) hit is still a real C/Rust divergence, just a lower-severity one." >&2
fi
# Exit code reflects whether the matcher was PROVEN, not just whether the
# scan ran -- adversarially found: this used to be an unconditional
# `exit 0` even on the ST_NO_TOOLCHAIN path, so the one case where the
# matcher is admittedly unproven was the one case that reported success.
# rc=0: scanned, matcher self-tested clean. rc=$ST_NO_TOOLCHAIN: scanned,
# but the matcher's own correctness is unverified on this machine --
# results printed, but a caller checking the exit code (not just stderr,
# which scrolls) sees "unproven", not "clean". rc=$ST_MATCHER_BROKEN
# already refuses before reaching here.
exit "$st_rc"
