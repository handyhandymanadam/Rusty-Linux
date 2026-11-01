#!/usr/bin/env bash
# guard-check.sh [--list]
#
# CATCH A THUNK CLOSURE THAT THREW AWAY A GUARD.
#
# WHY THIS EXISTS. On 2026-09-04 seven thunk closures deleted a C entry
# function that was not a pass-through. What went with them:
#
#   lib/math/gcd.c        if (!a || !b) return r;  and a static-key dispatch
#                         -> gcd(x, 0) spun forever; the kernel hung at boot
#   lib/ucs2_string.c     if (count == 0 || WARN_ON_ONCE(...)) return -E2BIG;
#                         -> count == 0 panicked on subtract overflow
#   lib/math/int_log.c    if (value == 0) { WARN_ON(1); return 0; }  x2
#   lib/memweight.c       BUG_ON(bytes / sizeof(long) >= INT_MAX / BITS_PER_LONG)
#   lib/plist.c           2 x WARN_ON, 2 x BUG_ON
#   lib/crypto/chacha-block-generic.c  WARN_ON_ONCE(nrounds != 20 && != 12)  x2
#
# Every one left the signature byte-identical, so rig/abi-check.sh could not
# see it, and rig/crc-check.sh read 0 CHANGED throughout. Only rig/boot.sh
# caught the first two, and only because they happened to be on a path the
# boot self-tests exercise. The other five were found by reading history.
#
# notes/GOALS.md's ratchet says a check is earned when a defect gets through. Seven
# did, from one cause, so this is the check for that cause.
#
# WHAT IT DOES. For every exported symbol this port defines in Rust rather
# than C, it finds the ORIGINAL C body in port/pristine/ and looks for the
# constructs a pass-through does not have. If it finds any, the symbol must
# either still have a C entry in port/tree/ that keeps them, or be listed in
# rig/guard-except.txt with a reason.
#
# WHAT IT DOES NOT DO. It cannot tell you the Rust reproduces the guard
# correctly, only that somebody said where it went. That is deliberate: the
# failure mode here was nobody looking, not somebody looking and being wrong.
#
#   --list   print every symbol it classifies and why, not just the failures
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
port="$root/port/tree"
pristine="$root/port/pristine"
except="$root/rig/guard-except.txt"
list=0
[ "${1:-}" = "--list" ] && list=1

[ -d "$pristine" ] || { echo "no pristine tree at $pristine"; exit 2; }

# Constructs that mean "this body did something a pass-through does not".
# Deliberately broad: a false positive costs one line in guard-except.txt,
# a false negative cost a kernel that does not boot.
guard_re='WARN|BUG_ON|BUG\(|panic|static_branch|static_key|unlikely *\(|likely *\('
guard_re+='|spin_lock|spin_unlock|preempt_|local_irq|rcu_read|might_sleep|lockdep'
guard_re+='|^#(if|ifdef|ifndef|else|elif)|__attribute__|__must_check|barrier\(\)'

declare -A EXC
if [ -r "$except" ]; then
    while read -r sym rest; do
        case "$sym" in ''|'#'*) continue;; esac
        EXC["$sym"]="$rest"
    done < "$except"
fi

# rust_defined: symbols a .rs file defines under the exported name, i.e. the
# ones with no C body left. `rust_`-prefixed names are bodies behind a thunk
# and are not the subject here.
mapfile -t rs_syms < <(
    grep -rhoP '(?<=^#\[no_mangle\]\n)' /dev/null 2>/dev/null
    grep -rhA2 --include='*.rs' '^#\[no_mangle\]' "$port" |
        grep -oP 'extern "C" fn \K[A-Za-z_][A-Za-z0-9_]*' |
        grep -v '^rust_' | sort -u
)

fail=0; checked=0; flagged=0; excused=0; noc=0

# body <file> <symbol>  -- print the C definition of <symbol>, brace-matched.
body() {
    awk -v sym="$2" '
        BEGIN { depth = 0; started = 0 }
        !started {
            # A definition line: the name, an open paren, and no trailing ";"
            if ($0 ~ ("(^|[^A-Za-z0-9_])" sym "[ \t]*\\(") && $0 !~ /;[ \t]*$/) {
                cand = NR; started = 1; buf = $0 "\n"
                depth = gsub(/{/, "{") - gsub(/}/, "}")
                if (depth > 0) inbody = 1
                next
            }
            next
        }
        started {
            buf = buf $0 "\n"
            depth += gsub(/{/, "{") - gsub(/}/, "}")
            if (depth > 0) inbody = 1
            if (inbody && depth <= 0) { printf "%s", buf; exit }
        }
    ' "$1"
}

printf '%-34s %-26s %s\n' SYMBOL 'PRISTINE FILE' VERDICT
for sym in "${rs_syms[@]}"; do
    [ -z "$sym" ] && continue

    # Where did the C live? Look for a pristine file that defines it.
    src=$(grep -rlP "(^|[^A-Za-z0-9_])$sym[ \t]*\(" --include='*.c' "$pristine" 2>/dev/null | head -1)
    if [ -z "$src" ]; then
        noc=$((noc+1))
        [ "$list" -eq 1 ] && printf '%-34s %-26s %s\n' "$sym" "-" "no pristine C (new symbol)"
        continue
    fi
    rel=${src#"$pristine"/}
    checked=$((checked+1))

    b=$(body "$src" "$sym")
    if [ -z "$b" ]; then
        [ "$list" -eq 1 ] && printf '%-34s %-26s %s\n' "$sym" "$rel" "no C body found (declaration only)"
        continue
    fi

    hits=$(printf '%s' "$b" | grep -cE "$guard_re")
    if [ "$hits" -eq 0 ]; then
        [ "$list" -eq 1 ] && printf '%-34s %-26s %s\n' "$sym" "$rel" "pass-through, nothing to keep"
        continue
    fi

    # It had something. Does a C entry still exist in the port tree?
    ported="$port/$rel"
    if [ -r "$ported" ] && [ -n "$(body "$ported" "$sym")" ]; then
        [ "$list" -eq 1 ] && printf '%-34s %-26s %s\n' "$sym" "$rel" "C entry retained"
        continue
    fi

    if [ -n "${EXC[$sym]:-}" ]; then
        excused=$((excused+1))
        [ "$list" -eq 1 ] && printf '%-34s %-26s %s\n' "$sym" "$rel" "excused: ${EXC[$sym]}"
        continue
    fi

    flagged=$((flagged+1)); fail=1
    printf '%-34s %-26s %s\n' "$sym" "$rel" "*** UNACCOUNTED"
    printf '%s\n' "$b" | grep -nE "$guard_re" | sed 's/^/        /'
done

echo
printf 'PASS 1: checked %d symbols with pristine C; %d UNACCOUNTED, %d excused, %d Rust-only\n' \
    "$checked" "$flagged" "$excused" "$noc"
if [ "$fail" -ne 0 ]; then
    echo
    echo 'A C entry that did more than call the Rust was deleted, and nothing says'
    echo 'where its guard went. Either put the C entry back, or reproduce the guard'
    echo "in the Rust and record that in $except."
fi
# ---------------------------------------------------------------------------
# PASS 2: the file's own comments, against the file's own code.
# See rig/guard-doc-check.py for what it does and the case that made it
# necessary. Pass 1 alone would have missed one of the seven.
# ---------------------------------------------------------------------------
echo
"$root/rig/guard-doc-check.py" "$port" "$root/rig/guard-doc-except.txt" || fail=1

exit "$fail"
