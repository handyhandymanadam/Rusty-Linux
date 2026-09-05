#!/usr/bin/env bash
# Prove the differential can fail.
#
# GOALS.md and PRIOR-ART.md §5 both say the same thing: a test that has never
# failed is not known to work. This breaks the Rust in nine specific ways,
# one at a time, and checks the differential notices each. Every sabotage is
# a plausible porting slip rather than a random mutation -- an off-by-one in
# a window offset, the wrong half of the two-byte pattern, a dropped tail
# byte, a constant transcribed wrong.
#
# Covers BOTH ported files in this directory: inffast_rs.rs (`add`) and, from
# 2026-09-03, inftrees_rs.rs (`addt`). Both are restored on any exit.
#
# ONE SABOTAGE WAS TRIED AND REMOVED, and the reason is a finding rather than a
# gap. Inverting the `drop != 0 && (huff & mask) != low` test in the
# incomplete-code fill loop of inftrees_rs.rs is NOT CAUGHT, because those four
# lines are unreachable in this kernel: an incomplete code survives the
# validity check only when `max == 1` (inftrees.c:123), and `max == 1` forces
# `root == 1` and therefore `drop == 0`, so the branch is dead. Measured with
# gcov on the ORACLE, not argued: 0 executions of inftrees.c:290-293 across
# 530,867 calls and 278 iterations of that loop. Do not add it back.
#
# The file is restored on any exit, including a kill.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
target="$root/port/tree/lib/zlib_inflate/inffast_rs.rs"
target2="$root/port/tree/lib/zlib_inflate/inftrees_rs.rs"
target3="$root/port/tree/lib/zlib_inflate/inflate_rs.rs"
target4="$root/port/tree/lib/zlib_inflate/inflate.c"
backup="$(mktemp)"
backup2="$(mktemp)"
backup3="$(mktemp)"
backup4="$(mktemp)"
runs="${1:-400}"

cp "$target" "$backup"
cp "$target2" "$backup2"
cp "$target3" "$backup3"
cp "$target4" "$backup4"
restore() {
    cp "$backup" "$target"; cp "$backup2" "$target2"; cp "$backup3" "$target3"
    cp "$backup4" "$target4"
    rm -f "$backup" "$backup2" "$backup3" "$backup4"
}
trap restore EXIT

apply() {  # apply <target> <find> <replace>; fails loudly if not there
    TGT="$1" FIND="$2" REPL="$3" python3 - <<'PY'
import os, sys, pathlib
p = pathlib.Path(os.environ['TGT'])
t = p.read_text()
f, r = os.environ['FIND'], os.environ['REPL']
if t.count(f) != 1:
    sys.exit("sabotage anchor matched %d times, not 1" % t.count(f))
p.write_text(t.replace(f, r))
PY
}

declare -a NAMES=() FINDS=() REPLS=() FILES=()
# add  -- a slip in inffast_rs.rs
# addt -- a slip in inftrees_rs.rs
# addi -- a slip in inflate_rs.rs
# addc -- a slip in the retained pre-boot C body of inflate.c
add()  { NAMES+=("$1"); FINDS+=("$2"); REPLS+=("$3"); FILES+=("$target"); }
addt() { NAMES+=("$1"); FINDS+=("$2"); REPLS+=("$3"); FILES+=("$target2"); }
addi() { NAMES+=("$1"); FINDS+=("$2"); REPLS+=("$3"); FILES+=("$target3"); }
# addc -- a slip in the retained PRE-BOOT C body of inflate.c
addc() { NAMES+=("$1"); FINDS+=("$2"); REPLS+=("$3"); FILES+=("$target4"); }

add "drop the odd tail byte of a direct copy" \
    'if len & 1 != 0 {
                                    *out = *from;
                                    out = out.add(1);
                                }' \
    'if false {
                                    *out = *from;
                                    out = out.add(1);
                                }'

add "splat the wrong half of the dist==1 pattern" \
    'pat[0] = pat[1];' \
    'pat[1] = pat[0];'

add "off by one into the unwrapped window" \
    'from = from.add((wsize - op) as usize);' \
    'from = from.add((wsize - op + 1) as usize);'

add "off by one into the wrapped window" \
    'from = from.add((wsize + write - op) as usize);' \
    'from = from.add((wsize + write - op - 1) as usize);'

add "unroll the window copy by four instead of three" \
    'len -= 3;' \
    'len -= 4;'

add "skip the two-byte alignment step" \
    'if (out as usize).wrapping_sub(1) & 1 == 0 {' \
    'if false {'

add "take the pattern path for dist==3 as well" \
    'if dist > 2 {' \
    'if dist > 3 {'

add "wrong end-of-block mode constant" \
    'pub const MODE_TYPE: c_int = 11;' \
    'pub const MODE_TYPE: c_int = 12;'

add "epilogue reports one byte too much output space" \
    '(257i64 + end.offset_from(out) as i64)' \
    '(258i64 + end.offset_from(out) as i64)'

# --- inftrees_rs.rs -----------------------------------------------------
# The table builder. Its output is 2048 four-byte entries the decoder then
# indexes blind, so a wrong entry is not a wrong answer here -- it is a wrong
# answer somewhere else, later, in code that looks correct.

addt "root table index bits not clamped to the longest code" \
    'if root > max {
        root = max;
    }' \
    'if root > max + 1 {
        root = max;
    }'

addt "over-subscribed set accepted" \
    'if left < 0 {
            // Over-subscribed.
            return -1;
        }' \
    'if left < -1 {
            // Over-subscribed.
            return -1;
        }'

addt "incomplete set accepted for DISTS with more than one code" \
    'if left > 0 && (kind == CODES || max != 1) {' \
    'if left > 0 && (kind == CODES || max != 0) {'

addt "symbol sort offsets off by one length" \
    'offs[len + 1] = offs[len] + count[len];' \
    'offs[len + 1] = offs[len] + count[len + 1];'

addt "length base table indexed without the 257 bias" \
    'let i = ws as usize - 257;' \
    'let i = ws as usize - 256;'

addt "entry bit count forgets the dropped root bits" \
    'bits: (len - drop) as u8,
            val,' \
    'bits: len as u8,
            val,'

addt "replication step uses the sub-table width, not the code length" \
    'let mut incr: u32 = 1u32 << (len - drop);' \
    'let mut incr: u32 = 1u32 << curr;'

addt "backwards code increment starts one bit too low" \
    'incr = 1u32 << (len - 1);
        while huff & incr != 0 {' \
    'incr = 1u32 << (len - 2);
        while huff & incr != 0 {'

addt "sub-table size search stops one length early" \
    'while curr + drop < max {' \
    'while curr + drop < max - 1 {'

addt "root entry points at the wrong sub-table offset" \
    'e.val = next.offset_from(table_base) as u16;' \
    'e.val = next.offset_from(table_base) as u16 + 1;'

addt "sub-table trigger compares the wrong low bits" \
    'low = huff & mask;
            // SAFETY:' \
    'low = huff & (mask >> 1);
            // SAFETY:'

addt "table advance reports the root size, not the space used" \
    '*table = table_base.add(used as usize);' \
    '*table = table_base.add((1usize << root) as usize);'

# --- inflate_rs.rs ------------------------------------------------------
# The state machine. A wrong transition here is not a wrong byte, it is a
# stream that decodes to something else entirely -- or, at the MATCH guard, a
# read past the window.

addi "zlib header window size accepted one bit too large" \
    'if len > state.wbits {' \
    'if len >= state.wbits {'

addi "last-block flag read from two bits" \
    'state.last = r.peek(1) as c_int;' \
    'state.last = r.peek(2) as c_int;'

addi "dynamic block decoded as a stored one" \
    '2 => state.mode = TABLE,' \
    '2 => state.mode = STORED,'

addi "stored block length masked to 15 bits" \
    'state.length = (r.hold as u32) & 0xffff;' \
    'state.length = (r.hold as u32) & 0x7fff;'

addi "literal/length count off by one" \
    'state.nlen = r.peek(5) + 257;' \
    'state.nlen = r.peek(5) + 256;'

# NOT A SABOTAGE, and the reason is a finding. `state.lenbits = 7` -> `8` is
# NOT CAUGHT, because zlib_inflate_table() clamps the requested root bits to
# the longest code present (inftrees.c:102) and the code-length alphabet's
# longest code is almost always <= 7. The parameter selects a table SHAPE, not
# an answer: every root size decodes the same stream, because each entry
# carries its own bit count. It is a performance knob. Do not add it back.

addi "code-length alphabet left one length uninitialised" \
    'while state.have < 19 {' \
    'while state.have < 18 {'

addi "repeat-previous run one short" \
    'copy = 3 + r.peek(2);' \
    'copy = 2 + r.peek(2);'

addi "end-of-block bit tested against the wrong flag" \
    'if this.op & 32 != 0 {' \
    'if this.op & 16 != 0 {'

addi "length extra bits add one too many" \
    'state.length += r.peek(state.extra);' \
    'state.length += r.peek(state.extra) + 1;'

addi "distance off by one" \
    'state.offset = this.val as c_uint;' \
    'state.offset = this.val as c_uint + 1;'

addi "window read starts one byte late" \
    'from_idx = (state.wsize - copy) as usize;' \
    'from_idx = (state.wsize - copy + 1) as usize;'

addi "window write index advanced one too far" \
    'state.write += dist as c_uint;' \
    'state.write += dist as c_uint + 1;'

addi "adler32 second accumulator drifts" \
    's1 += b as u32;
            s2 += s1;' \
    's1 += b as u32;
            s2 += s1 + 1;'

addi "Z_FINISH no longer forces Z_BUF_ERROR" \
    'if ((in_used == 0 && out == 0) || flush == Z_FINISH) && ret == Z_OK {' \
    'if ((in_used == 0 && out == 0) && flush == Z_FINISH) && ret == Z_OK {'

# THE DIVERGENCE ITSELF. Removing this guard makes the port byte-for-byte the
# C again -- and the C reads about 4 GiB past its window on the reproducer in
# upstream/zlib-inflate-oob/. It is caught by the directed stage, not by the
# three-arm comparison, which is the whole reason that stage exists.
addi "the MATCH-state whave guard is removed" \
    'if copy > state.whave {
                        bad(s, state, MSG_DIST_TOO_FAR);
                        continue;
                    }' \
    'if false {
                        bad(s, state, MSG_DIST_TOO_FAR);
                        continue;
                    }'

# --- the retained pre-boot C body ------------------------------------------
# Adam's call, 2026-09-03: fix our kernel, do not wait on Linux. The
# #ifdef STATIC half of inflate.c now carries the same five-line whave guard
# the Rust does. This proves the new fourth arm of the differential can fail --
# nothing in this project had ever tested a retained pre-boot body at all.

addc "the whave guard is missing from the PRE-BOOT C body" \
    '                if (copy > state->whave) {
                    strm->msg = (char *)"invalid distance too far back";
                    state->mode = BAD;
                    break;
                }' \
    '                if (copy > state->whave && 0) {
                    strm->msg = (char *)"invalid distance too far back";
                    state->mode = BAD;
                    break;
                }'

printf '%-52s %s\n' "SABOTAGE" "RESULT"
caught=0
missed=0
for i in "${!NAMES[@]}"; do
    cp "$backup" "$target"; cp "$backup2" "$target2"; cp "$backup3" "$target3"
    cp "$backup4" "$target4"
    if ! apply "${FILES[$i]}" "${FINDS[$i]}" "${REPLS[$i]}" >/dev/null 2>&1; then
        printf '%-52s %s\n' "${NAMES[$i]}" "ANCHOR GONE -- sabotage not applied"
        missed=$((missed + 1))
        continue
    fi
    out=$("$here/run.sh" "$runs" 2>&1)
    rc=$?
    # A COMPILE ERROR IS NOT A CATCH. Twice now a mutation has been scored
    # as caught on a nonzero exit that was rustc refusing the file under
    # -D warnings -- a self-assignment lint, and an unused constant. Not one
    # line of the code under test ran. Same shape as checkpatch reporting a
    # clean run on a file it had not recognised as a patch.
    if printf '%s\n' "$out" | grep -qE '^error(\[|:)|aborting due to'; then
        printf '%-52s %s\n' "${NAMES[$i]}" "COMPILE ERROR -- not a catch"
        missed=$((missed + 1)); continue
    fi
    if [ "$rc" -ne 0 ]; then
        why=$(printf '%s\n' "$out" | grep -m1 -E 'MISMATCH|ORACLE SPLIT|panicked at|EXPECTED|NOT FOUND' \
              | sed 's/^ *//' | cut -c1-40)
        printf '%-52s caught (%s)\n' "${NAMES[$i]}" "${why:-nonzero exit}"
        caught=$((caught + 1))
    else
        printf '%-52s NOT CAUGHT\n' "${NAMES[$i]}"
        missed=$((missed + 1))
    fi
done

cp "$backup" "$target"; cp "$backup2" "$target2"; cp "$backup3" "$target3"
cp "$backup4" "$target4"
echo
echo "caught $caught of $((caught + missed))"
[ "$missed" -eq 0 ]
