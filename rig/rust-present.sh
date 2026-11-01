#!/usr/bin/env bash
# rust-present.sh <build-dir>
#
# Assert that every ported .rs is ACTUALLY IN THE BUILT KERNEL.
#
# WHY THIS EXISTS. The prior attempt (github.com/handyhandymanadam/linux-rust-port)
# lost a day to this exact shape, twice. Its `build-kasan` silently dropped
# CONFIG_RUST -- gcc, plus `depends on !KASAN || CC_IS_CLANG` -- and ran for a
# day with NO RUST IN THE KERNEL AT ALL. "Zero sanitizer reports naming our
# code" was perfectly true, and meant nothing, because the code was not in the
# binary. The same shape hit its lib/zlib_inflate when a rebase silently
# reverted the Makefile wiring. Its own doctrine records the rule that follows:
# assert the subject symbol is present before trusting any negative result.
#
# Our rig had the identical hole. `rig/boot.sh` prints `rust-ran YES`, but that
# greps for ONE marker line emitted by ONE probe -- it says nothing about
# whether lib/zstd's Huffman decoder, or any other specific port, is linked.
# Every green boot, every clean CRC check and every "no faults" is a negative
# result of the kind that goes VOID rather than stale when the object is
# missing.
#
# WHAT IT CHECKS, per port/tree/**/*_rs.rs:
#   1. the matching *_rs.o exists in the build directory;
#   2. every global (nm 'T') that object defines is present in vmlinux;
#   3. the object is a member of a built-in.a or a lib.a, so it was actually
#      linked in rather than merely compiled and left on the floor.
#
# THREE OUTCOMES, and the middle one matters as much as the other two:
#   ok                     -- present, and traced into vmlinux
#   not built (config)     -- this config does not select the module at all.
#                             NOT a failure, but NOT coverage either: it is a
#                             gap this config cannot speak to, and it is
#                             printed and counted so it stays visible.
#   *** MISSING            -- the module IS built and the Rust is NOT in it.
#                             That is the VOID case. Exit 1.
#
# Note lib.a as well as built-in.a: kbuild puts `lib-y` objects in lib.a, which
# is linked only if something references it. Four ports live there
# (earlycpio, plist, union_find, win_minmax) and the first version of this
# check called all four missing.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: rust-present.sh <build-dir>}
[ -d "$root/$build" ] && build="$root/$build"
vmlinux="$build/vmlinux"

[ -f "$vmlinux" ] || { echo "no vmlinux at $vmlinux" >&2; exit 2; }

# every symbol vmlinux defines, once
vmsyms=$(mktemp); trap 'rm -f "$vmsyms"' EXIT
nm --defined-only "$vmlinux" | awk '{print $3}' | sort -u > "$vmsyms"

fail=0
n_files=0
n_syms=0
n_unbuilt=0
n_ok=0

printf '%-52s %5s %6s %s\n' "PORTED FILE" "SYMS" "IN-A" "VERDICT"
while IFS= read -r rs; do
    rel=${rs#"$root/port/tree/"}
    obj="$build/${rel%.rs}.o"
    n_files=$((n_files + 1))

    if [ ! -f "$obj" ]; then
        # A .rs with no object of its own is fine IF another ported .rs pulls
        # it in with include!() or #[path] -- lib/zlib_inflate/inffixed_rs.rs
        # is include!()d by inflate_rs.rs. Then its symbols belong to that
        # crate's object and are checked there. Anything else is a real miss.
        base=$(basename "$rs")
        if grep -rqF "$base" --include='*.rs' "$root/port/tree" \
             --exclude="$base" 2>/dev/null; then
            printf '%-52s %5s %6s %s\n' "$rel" "-" "-" \
                "ok (no object: included by another crate)"
            continue
        fi
        # No object AND no sibling C object from the same module means this
        # config simply does not select it -- a gap, not a fault.
        cdir=$(dirname "$obj")
        cbase=$(basename "${obj%_rs.o}")
        if [ ! -d "$cdir" ] || [ ! -f "$cdir/$cbase.o" ]; then
            printf '%-52s %5s %6s %s\n' "$rel" "-" "-" \
                "not built (this config does not select the module)"
            n_unbuilt=$((n_unbuilt + 1))
            continue
        fi
        printf '%-52s %5s %6s %s\n' "$rel" "-" "-" \
            "*** NO OBJECT but the C sibling IS built: $obj"
        fail=1; continue
    fi

    syms=$(nm --defined-only "$obj" 2>/dev/null | awk '$2 == "T" {print $3}' | sort -u)
    [ -n "$syms" ] || { printf '%-52s %5s %6s %s\n' "$rel" 0 "-" \
        "*** OBJECT DEFINES NO GLOBALS"; fail=1; continue; }

    # arch/x86/boot/startup/ objects are `.pi.o` (position independent, every symbol prefixed
    # `__pi_` by llvm-objcopy; logs/phase-e-pi.md): vmlinux has `__pi_<sym>` and the archive
    # member is `<name>.pi.o`.
    pi=""; case "$rel" in arch/x86/boot/startup/*) pi="__pi_";; esac
    missing=""
    count=0
    while IFS= read -r s; do
        count=$((count + 1))
        grep -qxF "$pi$s" "$vmsyms" || missing="$missing $s"
    done <<< "$syms"
    n_syms=$((n_syms + count))

    # Was it LINKED, or merely compiled and left on the floor? kbuild's
    # built-in.a files are THIN archives, so `ar t` lists build-relative
    # paths rather than bare member names -- matching on a basename finds
    # nothing and reports every port missing, which is how this check first
    # behaved. Walk up from the object's directory to the top-level
    # built-in.a, since a nested archive is itself a member of its parent.
    inar="no"
    d=$(dirname "$obj")
    want=${obj#"$build"/}
    [ -n "$pi" ] && want="${want%.o}.pi.o"
    while [ "$d" != "$build" ] && [ "$d" != "/" ]; do
      for a in "$d/built-in.a" "$d/lib.a"; do
        # Capture the listing into a variable before grep -q sees it. Piping
        # straight into `grep -q` lets grep exit (and close its read end) as
        # soon as it finds a match, which can SIGPIPE `ar`/`sed` before they
        # finish writing; under `set -o pipefail` that non-zero SIGPIPE
        # status overrides grep's own success, so a member that IS in the
        # archive intermittently reports as missing. Command substitution
        # runs the pipeline to completion first, so there is nothing left to
        # SIGPIPE.
        if [ -f "$a" ]; then
            members=$(ar t "$a" 2>/dev/null | sed "s|^$build/||")
            if grep -qxF "$want" <<< "$members"; then
                inar=$(basename "$a" .a); break
            fi
        fi
      done
      [ "$inar" = no ] || break
      d=$(dirname "$d")
    done
    if [ "$inar" = no ] && [ -f "$build/built-in.a" ]; then
        members=$(ar t "$build/built-in.a" 2>/dev/null | sed "s|^$build/||")
        grep -qxF "$want" <<< "$members" && inar="built-in"
    fi

    if [ -n "$missing" ]; then
        printf '%-52s %5d %6s %s\n' "$rel" "$count" "$inar" \
            "*** MISSING FROM vmlinux:$missing"
        fail=1
    elif [ "$inar" = no ]; then
        printf '%-52s %5d %6s %s\n' "$rel" "$count" "$inar" \
            "*** COMPILED BUT NOT IN A built-in.a"
        fail=1
    else
        printf '%-52s %5d %6s %s\n' "$rel" "$count" "$inar" ok
        n_ok=$((n_ok + 1))
    fi
done < <(find "$root/port/tree" -name '*_rs.rs' | sort)

echo
echo "$n_files ported files: $n_ok traced into $(basename "$build")/vmlinux" \
     "($n_syms global symbols), $n_unbuilt not selected by this config"
if [ "$n_unbuilt" != 0 ]; then
    echo "the 'not built' rows are a COVERAGE GAP for this config, not a pass;" \
         "check them against the other config before trusting a negative result"
fi
[ "$fail" = 0 ] || echo "*** a port is NOT in the built kernel -- every negative result from this build is VOID, not merely stale" >&2
exit $fail
