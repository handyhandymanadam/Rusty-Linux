#!/usr/bin/env bash
# Prove the LZO differential can fail.
#
# Ten plausible porting slips, one at a time -- an off-by-one in a match
# offset, the wrong shift on a distance byte, a dropped state transition, a
# skipped lookbehind check, a mistranscribed constant. Not random mutations.
#
# THE DEFAULT RUN COUNT IS MEASURED, NOT GUESSED. At 3,000 runs nine of the
# ten were caught and "M2 match offset off by one" was not. That is not a
# weak corpus: gcov shows the state==4 M1 branch it corrupts executing 148
# times in 40,000 runs, so a 3,000-run pass reaches it about seven times and
# needs one of those seven to change a byte. Bisected: not caught at 5,000,
# caught at 20,000 (first mismatch at run 5,530). The default is 25,000.
#
# The general lesson, worth more than the number: a sabotage suite has to be
# sized to the RAREST path it claims to cover, and the only way to know that
# size is to measure the path's rate and then bisect. A suite that passes
# because it never reached the code is indistinguishable from one that passes
# because the code is right.
#
# The file is restored on any exit, including a kill.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
target="$root/port/tree/lib/lzo/lzo1x_decompress_safe_rs.rs"
backup="$(mktemp)"
runs="${1:-25000}"

cp "$target" "$backup"
restore() { cp "$backup" "$target"; rm -f "$backup"; }
trap restore EXIT

apply() {
    FIND="$1" REPL="$2" TGT="$target" python3 - <<'PY'
import os, sys, pathlib
p = pathlib.Path(os.environ['TGT'])
t = p.read_text()
f, r = os.environ['FIND'], os.environ['REPL']
if t.count(f) != 1:
    sys.exit("anchor matched %d times, not 1" % t.count(f))
p.write_text(t.replace(f, r))
PY
}

declare -a NAMES=() FINDS=() REPLS=()
add() { NAMES+=("$1"); FINDS+=("$2"); REPLS+=("$3"); }

add "literal run one byte short" \
    't += 3;' 't += 2;'

add "M2 match offset off by one" \
    'm_pos = op.sub(1 + M2_MAX_OFFSET);' 'm_pos = op.sub(M2_MAX_OFFSET);'

add "M3 distance byte shifted by 2 instead of 3" \
    'm_pos = m_pos.sub(next_byte!() << 3);' 'm_pos = m_pos.sub(next_byte!() << 2);'

add "wrong state after a literal run" \
    'state = 4;
                    entry = Entry::Top;' \
    'state = 3;
                    entry = Entry::Top;'

add "skip the lookbehind check before the match copy" \
    'Entry::MatchCopy => {
                    test_lb!(m_pos);' \
    'Entry::MatchCopy => {
                    if false { test_lb!(m_pos); }'

add "zero-run one byte long" \
    't += MIN_ZERO_RUN_LENGTH;' 't += MIN_ZERO_RUN_LENGTH + 1;'

add "M3 length off by one" \
    't = (t >> 5) - 1 + (3 - 1);' 't = (t >> 5) + (3 - 1);'

add "next taken from three bits instead of two" \
    'm_pos = m_pos.sub(next >> 2);
                        next &= 3;
                        if m_pos == (op as *const c_uchar) {' \
    'm_pos = m_pos.sub(next >> 2);
                        next &= 7;
                        if m_pos == (op as *const c_uchar) {'

add "wrong end-of-stream length check" \
    'return if t != 3 {' 'return if t != 2 {'

add "match_next advances the output by four, not next" \
    '(op as *mut u32).write_unaligned((ip as *const u32).read_unaligned());
                        op = op.add(t);
                        ip = ip.add(t);' \
    '(op as *mut u32).write_unaligned((ip as *const u32).read_unaligned());
                        op = op.add(4);
                        ip = ip.add(t);'

printf '%-54s %s\n' "SABOTAGE" "RESULT"
caught=0; missed=0
for i in "${!NAMES[@]}"; do
    cp "$backup" "$target"
    if ! apply "${FINDS[$i]}" "${REPLS[$i]}" >/dev/null 2>&1; then
        printf '%-54s %s\n' "${NAMES[$i]}" "ANCHOR GONE -- not applied"
        missed=$((missed + 1)); continue
    fi
    out=$("$here/run.sh" "$runs" 2>&1); rc=$?
    # A COMPILE ERROR IS NOT A CATCH. Twice now a mutation has been scored
    # as caught on a nonzero exit that was rustc refusing the file under
    # -D warnings -- a self-assignment lint, and an unused constant. Not one
    # line of the code under test ran. Same shape as checkpatch reporting a
    # clean run on a file it had not recognised as a patch.
    if printf '%s\n' "$out" | grep -qE '^error(\[|:)|aborting due to'; then
        printf '%-54s %s\n' "${NAMES[$i]}" "COMPILE ERROR -- not a catch"
        missed=$((missed + 1)); continue
    fi
    if [ "$rc" -ne 0 ]; then
        why=$(printf '%s\n' "$out" | grep -m1 -E 'MISMATCH|ORACLE SPLIT|panicked at|error\[' \
              | sed 's/^ *//' | cut -c1-38)
        printf '%-54s caught (%s)\n' "${NAMES[$i]}" "${why:-nonzero exit}"
        caught=$((caught + 1))
    else
        printf '%-54s NOT CAUGHT\n' "${NAMES[$i]}"
        missed=$((missed + 1))
    fi
done

cp "$backup" "$target"
echo
echo "caught $caught of $((caught + missed))"
[ "$missed" -eq 0 ]
