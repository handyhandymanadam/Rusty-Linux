#!/usr/bin/env bash
# pristine-check.sh
#
# The arrangement Adam ruled on 2026-09-04 (logs/floor.md, RAISE 2) rests on a
# claim: THE C FALLBACK CANNOT DRIFT FROM UPSTREAM, BECAUSE IT IS UPSTREAM.
# That is only true while nobody edits those files. This checks it.
#
# For every .c under port/tree/ with a twin under port/pristine/:
#
#   pristine  -- byte-identical to the tarball. The C arm compiles it directly.
#   EXCEPT    -- deliberately modified, and listed in rig/pristine-except.txt
#                with a reason. Exactly one file is: lib/zlib_inflate/inflate.c,
#                which carries the upstream zlib `copy > whave` hunk.
#   pending   -- modified, not listed: a thunk-shaped port that still has the
#                upstream body overwritten, so CONFIG_RUST=n has nothing to
#                fall back to. NOT a failure yet -- it is the RAISE 2 worklist,
#                and it is printed and counted so the number goes down visibly.
#
# Exit 1 only when a file is modified AND unexplained AND does not look like a
# thunk. A file with no pristine twin is a port-added file (a *_thunk.c, an
# _rs.rs) and is not this script's business.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
exceptions="$root/rig/pristine-except.txt"

n_ident=0; n_except=0; n_pending=0; n_free=0; n_buildedit=0; n_added=0; fail=0
pending_list=()
free_list=()
buildedit_list=()

while IFS= read -r f; do
    rel=${f#"$root/port/tree/"}
    pris="$root/port/pristine/$rel"
    if [ ! -f "$pris" ]; then n_added=$((n_added + 1)); continue; fi

    if cmp -s "$f" "$pris"; then
        n_ident=$((n_ident + 1)); continue
    fi

    reason=$(grep -F "	" "$exceptions" 2>/dev/null | awk -F'\t' -v p="$rel" '$1==p{print $2}')
    if [ -n "$reason" ]; then
        printf '  EXCEPT   %-46s %s\n' "$rel" "$reason"
        n_except=$((n_except + 1)); continue
    fi

    # A thunk-shaped port names the Rust it calls. A THUNK-FREE one does not --
    # it has no C body left to call anything from, only the EXPORT_SYMBOL and
    # the pins -- so it is identified by the marker every ported file carries.
    #
    # Both are known-pending, not unexplained edits, but they are different
    # RAISE 2 problems and are counted separately:
    #
    #   thunk       a C entry survives here, so a CONFIG_RUST=n arm can be
    #               built by pointing the Makefile at port/pristine/ instead.
    #   thunk-free  there is no C body in port/tree/ at all, and for the files
    #               deleted outright (lib/bcd.c) not even a stub. The only C
    #               that still exists for those symbols is port/pristine/, and
    #               nothing yet compiles it. See logs/floor.md RAISE 2.
    # A Makefile or Kconfig we edited is a port edit by construction -- it is
    # how the .rs objects get built at all -- and neither heuristic below
    # applies to it. It is still WALKED, so that it cannot be modified
    # unnoticed; it is just classified by what it adds.
    case "$rel" in
    */Makefile|Makefile|*/Kconfig|Kconfig)
        if grep -qE '_rs\.o|_rs\.rs|_thunk\.o|preboot' "$f"; then
            n_buildedit=$((n_buildedit + 1)); buildedit_list+=("$rel"); continue
        fi
        ;;
    esac

    if grep -q "rust_" "$f"; then
        n_pending=$((n_pending + 1)); pending_list+=("$rel")
    elif grep -q "PORTED TO RUST" "$f"; then
        n_free=$((n_free + 1)); free_list+=("$rel")
    else
        printf '  *** MODIFIED AND UNEXPLAINED  %s\n' "$rel"
        printf '      not byte-identical to port/pristine/, not in %s,\n' "${exceptions#"$root"/}"
        printf '      it calls no rust_* symbol, and it does not say PORTED TO RUST.\n'
        fail=1
    fi
done < <(find "$root/port/tree" -type f \
             \( -name '*.c' -o -name '*.h' -o -name '*.rs' \
                -o -name 'Makefile*' -o -name 'Kconfig' \) | sort)

if [ "$n_pending" != 0 ]; then
    echo
    echo "  pending RAISE 2, THUNK-SHAPED -- upstream body overwritten, but a C"
    echo "  entry survives here, in these $n_pending files:"
    printf '    %s\n' "${pending_list[@]}"
fi

if [ "$n_free" != 0 ]; then
    echo
    echo "  pending RAISE 2, THUNK-FREE -- no C body remains in port/tree/ at all."
    echo "  A CONFIG_RUST=n arm for these has to compile port/pristine/ directly:"
    printf '    %s\n' "${free_list[@]}"
fi

# Files DELETED outright are invisible to the walk above -- there is nothing in
# port/tree/ to find -- so they are listed from the pristine side.
deleted_list=()
while IFS= read -r pf; do
    prel=${pf#"$root/port/pristine/"}
    [ -f "$root/port/tree/$prel" ] && continue
    grep -qs "^${prel%.c}\.o\b\|[ 	]${prel##*/}" /dev/null && true
    deleted_list+=("$prel")
done < <(find "$root/port/pristine" -name '*.c' | sort)
if [ "${#deleted_list[@]}" != 0 ]; then
    echo
    echo "  DELETED -- upstream file with no counterpart in port/tree/. Rust"
    echo "  defines and exports these symbols itself (kernel::kabi_export!):"
    printf '    %s\n' "${deleted_list[@]}"
fi

echo
echo "$n_ident byte-identical to the tarball, $n_except documented exception(s)," \
     "$n_pending pending (thunk), $n_free pending (thunk-free)," \
     "$n_buildedit build-file edit(s)," \
     "${#deleted_list[@]} deleted, $n_added port-added files"
[ "$fail" = 0 ] || echo "*** an upstream file was modified without a recorded reason" >&2
exit $fail
