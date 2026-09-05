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
        sib=$(ls "$build/$(dirname "$rel")"/.*.o.cmd 2>/dev/null | head -1)
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
    srcdir="$root/src/linux/$(dirname "$rel")"
    newcmd=$(printf '%s' "$cmd" \
      | sed -E "s#-Wp,-MMD,[^ ]+ # -I$srcdir #" \
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
