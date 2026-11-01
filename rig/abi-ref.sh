#!/usr/bin/env bash
# abi-ref.sh [build-dir]
#
# BUILD THE C REFERENCE that rig/abi-check.sh compares Rust definitions against
# once their C callers are gone.
#
# THE GAP THIS CLOSES. When a subsystem is fully ported, no C translation unit
# calls its symbols any more, so the compiler never emits a declaration DIE for
# them and there is no C-side authority anywhere in the build. abi-check
# reported 30 such symbols -- FSE_isError, HUF_selectDecoder, xz_dec_lzma2_run,
# the mpihelp_* family, zlib_inflate_table -- as `no C reference`: not passing,
# not failing, simply unverified. The port succeeding is what removed the
# reference.
#
# HOW. port/pristine/ already holds the UNMODIFIED upstream .c for every ported
# file, sha256-verified out of the tarball, because the differential oracle
# needs it. Compiling those with the SAME command line kbuild used gives an
# object whose DWARF carries the original C definitions -- correct types and,
# unlike a header declaration, the original PARAMETER NAMES.
#
# WHY THE DONOR COMMAND LINE AND NOT OUR OWN FLAGS. A hand-maintained copy of
# the kernel's CFLAGS goes stale silently and would make this reference lie in
# the same direction as the thing it is checking. So each file is compiled with
# the exact `savedcmd_` line kbuild recorded for that object, with only the
# input and output paths substituted. Same principle as rig/oracle-world.sh:
# replay the real invocation, never re-describe it.
#
# TWO THINGS MEASURED HERE, BOTH OF WHICH COST AN ATTEMPT:
#   - The prefix in a .cmd file is `savedcmd_`, not `cmd_`. Matching `cmd_`
#     yielded an EMPTY command, `eval ""` returned 0, nothing was compiled, and
#     the "experiment" reported success while doing nothing at all.
#   - A DWARF declaration DIE is emitted for a CALL, not for an address-taken
#     reference. `(void *)&FSE_isError` produces no subprogram DIE; `typeof`
#     produces none either. That is why this compiles real C rather than
#     generating a stub that merely mentions each symbol.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
build=${1:-build-fast}
out="$build/abi-ref"
[ -d "$build" ] || { echo "no build dir $build" >&2; exit 2; }

mkdir -p "$out"

# GENERATED INPUTS the pristine C #includes and a fresh tree no longer produces (the ports stopped
# needing them in the Rust arm): lib/oid_registry_data.c and lib/crc/crc32table.h. Without them
# oid_registry.c and crc32-main.c "do not compile against current headers" and their exports
# show up as NO C REFERENCE. Generated the way the kernel does, into abi-ref/_gen, added with -I.
# (An older tree kept stale copies from before the ports, which hid this -- 2026-10-03.)
gen="$root/$out/_gen"; mkdir -p "$gen/lib/crc" "$gen/include/generated"
perl "$root/src/linux/lib/build_OID_registry" "$root/src/linux/include/linux/oid_registry.h" "$gen/oid_registry_data.c" 2>/dev/null
if [ -f "$build/include/generated/autoconf.h" ]; then
    cp "$root/src/linux/lib/crc/gen_crc32table.c" "$gen/lib/crc/"
    cp "$build/include/generated/autoconf.h" "$gen/include/generated/"
    cc -O1 -I "$root/src/linux/include" -I "$root/src/linux/include/uapi" -I "$root/src/linux/tools/include" \
        -o "$gen/gen_crc32table" "$gen/lib/crc/gen_crc32table.c" 2>/dev/null \
        && "$gen/gen_crc32table" > "$gen/crc32table.h"
fi
n_ok=0; n_nocmd=0; n_fail=0; n_borrowed=0
printf '%-52s %s\n' "PRISTINE FILE" "VERDICT"

while IFS= read -r src; do
    rel=${src#port/pristine/}                     # lib/zstd/common/fse_decompress.c
    obj="$build/${rel%.c}.o"
    cmdfile="$build/$(dirname "$rel")/.$(basename "${rel%.c}").o.cmd"
    donor=own

    # A FILE THE PORT DELETED HAS NO .o.cmd OF ITS OWN, EVER AGAIN.
    #
    # This used to skip such files. That was survivable while every ported C
    # file still existed; kernel::kabi_export!() made it a hole, because the
    # files whose contract most needs re-deriving are exactly the ones that
    # have been deleted. lib/bcd.c was the first: its .cmd went with it, this
    # script skipped it, and rig/kabi-contract-check.sh then read the object
    # left behind by an EARLIER run and reported that everything agreed --
    # while the C had been changed under it. A stale oracle is worse than no
    # oracle, because it answers.
    #
    # So: borrow a donor from a sibling in the same directory. The flags kbuild
    # uses are per-directory with rare per-file overrides (CFLAGS_foo.o), so a
    # sibling is the right command line to within those, and which donor was
    # used is printed rather than assumed.
    if [ ! -f "$cmdfile" ]; then
        # First sibling that is a C compile. On a fresh tree (no stale C .cmd
        # files left over from before the ports) the alphabetical first sibling
        # is often a *_rs.o rustc command, whose flags cannot compile C -- every
        # such file then fails "substitution did not take". Found 2026-10-02 on
        # fedora-server's first from-scratch build.
        sib=""
        # Then, for a directory with no C object of its own left (lib/lz4: its one C file is gone), the
        # top-level lib/ donors: their flags are what lib/*.c is built with (2026-10-03).
        for d in "$build/$(dirname "$rel")" "$build/lib"; do
            for c in "$d"/.*.o.cmd; do
                [ -f "$c" ] || continue
                grep -q '^savedcmd_[^:]*:= *[^ ]*rustc' "$c" && continue
                grep -q 'clang' "$c" || continue
                # an assembler donor (arch/x86/lib/bhi.S) is not a C compile: its input is not substituted and the
                # "reference" comes out as the donor's own object (2026-10-04, cpu.c/csum-partial_64.c unresolved)
                sed -n 's/^savedcmd_[^:]*:= *//p' "$c" | head -1 | grep -qE '\.c *$' || continue
                sib=$c; break
            done
            [ -n "$sib" ] && break
        done
        if [ -n "$sib" ]; then
            cmdfile=$sib
            donor=$(basename "$sib" .o.cmd); donor=${donor#.}
        fi
    fi
    if [ ! -f "$cmdfile" ]; then
        # Nothing to compile with. Make sure a previous run's object cannot be
        # read as though it were current.
        stale="$out/${rel%.c}.o"
        if [ -f "$stale" ]; then
            rm -f "$stale"
            printf '%-52s %s\n' "$rel" "no donor .o.cmd -- REMOVED a stale reference object"
        else
            printf '%-52s %s\n' "$rel" "no donor .o.cmd (not built in this config)"
        fi
        n_nocmd=$((n_nocmd + 1)); continue
    fi
    cmd=$(sed -n 's/^savedcmd_[^:]*:= *//p' "$cmdfile" | head -1)
    if [ -z "$cmd" ]; then
        printf '%-52s %s\n' "$rel" "*** could not read savedcmd_ from $cmdfile"
        n_fail=$((n_fail + 1)); continue
    fi
    dst="$out/${rel%.c}.o"
    mkdir -p "$(dirname "$dst")"
    # The patterns must name the DONOR's file, which is what its command line
    # mentions; the replacements name ours. Using our own base name against a
    # borrowed command matched nothing, so the command still compiled the
    # donor to the donor's own object INSIDE THE BUILD TREE, and the missing
    # output was reported as a failure to compile. Two bugs wearing one hat.
    base=$(basename "${rel%.c}")
    [ "$donor" = own ] || base=$donor
    # Substitute ONLY the input and the output. -MMD would write a depfile
    # next to the original object, so it goes.
    # QUOTED INCLUDES RESOLVE RELATIVE TO THE SOURCE FILE'S OWN DIRECTORY, and
    # the pristine copy does not live where the original does. lib/zstd is full
    # of `#include "mem.h"` and `#include "../common/zstd_deps.h"`, which fail
    # from port/pristine/ with the donor flags alone. Adding -I for the
    # directory the file would normally occupy makes them resolve exactly as
    # they do in a real build -- and to the SAME headers, since the port
    # replaces .c bodies, not headers.
    # $root, not a hardcoded path: a worktree at a different path has its
    # own src/linux, and a hardcoded main-checkout path would silently
    # substitute the WRONG tree's headers -- found by md5-porter, 2026-09-05.
    srcdir="$root/src/linux/$(dirname "$rel")"
    newcmd=$(printf '%s' "$cmd" \
      | sed -E "s#-Wp,-MMD,[^ ]+ # -I$srcdir -I$gen #" \
      | sed -E "s#-o [^ ]*/${base}\.o#-o $root/$dst#" \
      | sed -E "s#[^ ]*/${base}\.c#$root/$src#")
    # Never let a botched substitution write into the real build tree.
    case "$newcmd" in
    *"$root/$dst"*) ;;
    *)  printf '%-52s %s\n' "$rel" "*** substitution did not take -- refusing to run"
        n_fail=$((n_fail + 1)); continue;;
    esac
    if ( cd "$build" && eval "$newcmd" ) >/dev/null 2>"$out/.err"; then
        if [ -s "$dst" ]; then
            if [ "$donor" = own ]; then
                printf '%-52s %s\n' "$rel" "ok"
            else
                printf '%-52s %s\n' "$rel" "ok (flags borrowed from $donor.o)"
                n_borrowed=$((n_borrowed + 1))
            fi
            n_ok=$((n_ok + 1))
        else
            # Belt and braces: a substitution that silently produced a no-op
            # command is exactly how the first attempt "passed".
            printf '%-52s %s\n' "$rel" "*** command succeeded but produced no object"
            n_fail=$((n_fail + 1))
        fi
    else
        printf '%-52s %s\n' "$rel" "*** does not compile against current headers"
        sed -n '/error/{p;q}' "$out/.err" | sed 's/^/      /'
        n_fail=$((n_fail + 1))
    fi
done < <(find port/pristine -name '*.c' | sort)

rm -f "$out/.err"
echo
echo "$n_ok compiled into $out ($n_borrowed with borrowed flags)," \
     "$n_nocmd without a donor command, $n_fail FAILED"
[ "$n_fail" = 0 ] || echo "*** a pristine reference file did not compile -- the C authority is incomplete" >&2
exit $([ "$n_fail" = 0 ] && echo 0 || echo 1)
