#!/usr/bin/env bash
# Prove the LZ4 differential can fail.
#
# Fifteen plausible porting slips in lz4_decompress_rs.rs, one at a time: a
# mistranscribed token field, an off-by-one in a match offset, a dropped
# overflow check, a wrong entry in the small-offset step tables, a lost
# streaming state update.
#
# A COMPILE ERROR IS NOT A CATCH. Three times in two days a mutation has been
# scored as caught on a nonzero exit that was rustc refusing the file under
# -D warnings. The guard below reports those separately and counts them as
# missed.
#
# The file is restored on any exit, including a kill.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
target="$root/port/tree/lib/lz4/lz4_decompress_rs.rs"
backup="$(mktemp)"
runs="${1:-1500}"

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

add "literal length taken from the wrong half of the token" \
    'length = token >> ML_BITS;' \
    'length = token & ML_MASK;'

add "match length taken from the wrong half of the token" \
    '            /* get matchlength */
            length = token & ML_MASK;' \
    '            /* get matchlength */
            length = token >> ML_BITS;'

# NOT a sabotage: copying 15 instead of 16 is NOT CAUGHT, and correctly so.
# The shortcut only enters when the literal length is at most 14, so the 15th
# and 16th bytes are slack the C copies because a constant-size copy is cheaper
# than a variable one. Eight is the smallest value that actually loses data.
add "shortcut copies 8 literal bytes instead of 16" \
    'unsafe { core::ptr::copy_nonoverlapping(ip, op, if END_ON_INPUT { 16 } else { 8 }) };' \
    'unsafe { core::ptr::copy_nonoverlapping(ip, op, 8) };'

add "shortcut match copy drops its last two bytes" \
    'core::ptr::copy_nonoverlapping(m.add(16), op.add(16), 2);' \
    'core::ptr::copy_nonoverlapping(m.add(16), op.add(16), 1);'

add "shortcut taken for overlapping matches too" \
    '&& offset >= 8' \
    '&& offset >= 4'

add "MINMATCH not added to the match length" \
    'length += MINMATCH;' \
    'length += MINMATCH - 1;'

add "offset read big endian" \
    'unsafe { u16::from_le_bytes([*p, *p.add(1)]) as usize }' \
    'unsafe { u16::from_be_bytes([*p, *p.add(1)]) as usize }'

add "the 255 continuation byte loop stops one short" \
    'let more = (if END_ON_INPUT {
                        ip < iend.wrapping_offset(-(RUN_MASK as isize))
                    } else {
                        true
                    }) & (s == 255);' \
    'let more = (if END_ON_INPUT {
                        ip < iend.wrapping_offset(-(RUN_MASK as isize))
                    } else {
                        true
                    }) & (s == 254);'

add "the offset-outside-buffers check is 4 KiB too permissive" \
    'if check_offset && m.wrapping_add(dict_size) < low_prefix {' \
    'if check_offset && m.wrapping_add(dict_size).wrapping_add(4096) < low_prefix {'

add "inc32table entry for offset 3 is wrong" \
    'const INC32TABLE: [usize; 8] = [0, 1, 2, 1, 0, 4, 4, 4];' \
    'const INC32TABLE: [usize; 8] = [0, 1, 2, 2, 0, 4, 4, 4];'

add "dec64table entry for offset 4 is wrong" \
    'const DEC64TABLE: [isize; 8] = [0, 0, 0, -1, -4, 1, 2, 3];' \
    'const DEC64TABLE: [isize; 8] = [0, 0, 0, -1, -3, 1, 2, 3];'

add "the small-offset path is taken for offset 8 as well" \
    'if offset < 8 {' \
    'if offset <= 8 {'

add "the LASTLITERALS reserve is not enforced on a match" \
    'if cpy > oend.wrapping_offset(-LASTLITERALS) {
                /* the last LASTLITERALS bytes must be literals */
                return output_error(ip, src);
            }' \
    'if cpy > oend {
                /* the last LASTLITERALS bytes must be literals */
                return output_error(ip, src);
            }'

add "safe_partial takes the larger of target and capacity" \
    'let cap = core::cmp::min(target_output_size, dst_capacity);' \
    'let cap = core::cmp::max(target_output_size, dst_capacity);'

add "streaming prefix size is not accumulated" \
    'lz4sd.prefix_size += result as usize;
        lz4sd.prefix_end = lz4sd.prefix_end.wrapping_add(result as usize);' \
    'lz4sd.prefix_size = result as usize;
        lz4sd.prefix_end = lz4sd.prefix_end.wrapping_add(result as usize);'

printf '%-58s %s\n' "SABOTAGE" "RESULT"
caught=0; missed=0
for i in "${!NAMES[@]}"; do
    cp "$backup" "$target"
    if ! apply "${FINDS[$i]}" "${REPLS[$i]}" >/dev/null 2>&1; then
        printf '%-58s %s\n' "${NAMES[$i]}" "ANCHOR GONE -- not applied"
        missed=$((missed + 1)); continue
    fi
    out=$("$here/run.sh" "$runs" 2>&1); rc=$?
    if printf '%s\n' "$out" | grep -qE '^error(\[|:)|aborting due to'; then
        printf '%-58s %s\n' "${NAMES[$i]}" "COMPILE ERROR -- not a catch"
        missed=$((missed + 1)); continue
    fi
    if [ "$rc" -ne 0 ]; then
        why=$(printf '%s\n' "$out" | grep -m1 -E 'MISMATCH|panicked at' \
              | sed 's/^ *//' | cut -c1-40)
        printf '%-58s caught (%s)\n' "${NAMES[$i]}" "${why:-nonzero exit}"
        caught=$((caught + 1))
    else
        printf '%-58s NOT CAUGHT\n' "${NAMES[$i]}"
        missed=$((missed + 1))
    fi
done

cp "$backup" "$target"
echo
echo "caught $caught of $((caught + missed))"
[ "$missed" -eq 0 ]
