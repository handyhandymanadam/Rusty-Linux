#!/usr/bin/env bash
# Prove the xz_dec_bcj differential can fail.
#
# Sixteen plausible porting slips, one at a time -- a mistranscribed opcode
# mask, an address delta off by the instruction width, a wrong shift, a lost
# carry, a straddle-buffer bookkeeping error. Not random mutations: two per
# filter and four in the wrapper, because those are the two places this port
# could be wrong.
#
# THE DEFAULT RUN COUNT IS MEASURED, NOT GUESSED. See the bisect recorded in
# logs/hooks.md.
#
# The file is restored on any exit, including a kill.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
target="$root/port/tree/lib/xz/xz_dec_bcj_rs.rs"
backup="$(mktemp)"
runs="${1:-20000}"

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

# --- x86 -------------------------------------------------------------------
add "x86: call/jmp opcode mask off by one bit" \
    'if buf[i] & 0xFE != 0xE8 {' 'if buf[i] & 0xFC != 0xE8 {'

add "x86: instruction length 4 instead of 5 in the delta" \
    'let d = src.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(5));' \
    'let d = src.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(4));'

add "x86: sign-extension mask one bit short" \
    'let mut dest = dest & 0x01FF_FFFF;' 'let mut dest = dest & 0x00FF_FFFF;'

add "x86: carried mask distance limit 2 instead of 3" \
    '*prev_mask_state = if prev_pos > 3 {' '*prev_mask_state = if prev_pos > 2 {'

# --- powerpc ---------------------------------------------------------------
add "powerpc: bl opcode test drops the LK bit" \
    'if instr & 0xFC00_0003 == 0x4800_0001 {' 'if instr & 0xFC00_0002 == 0x4800_0000 {'

add "powerpc: displacement re-masked one bit wide" \
    'instr &= 0x03FF_FFFC;
            instr |= 0x4800_0001;' \
    'instr &= 0x07FF_FFFC;
            instr |= 0x4800_0001;'

# --- arm -------------------------------------------------------------------
add "arm: BL condition byte mistranscribed" \
    'if buf[i + 3] == 0xEB {' 'if buf[i + 3] == 0xEA {'

add "arm: pipeline offset 4 instead of 8" \
    'addr = addr.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(8));' \
    'addr = addr.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(4));'

# --- armthumb --------------------------------------------------------------
add "armthumb: first halfword pattern off by a bit" \
    'if buf[i + 1] & 0xF8 == 0xF0 && buf[i + 3] & 0xF8 == 0xF8 {' \
    'if buf[i + 1] & 0xF0 == 0xF0 && buf[i + 3] & 0xF8 == 0xF8 {'

add "armthumb: high address bits shifted 18 instead of 19" \
    'let mut addr = ((buf[i + 1] as u32 & 0x07) << 19)' \
    'let mut addr = ((buf[i + 1] as u32 & 0x07) << 18)'

# --- sparc -----------------------------------------------------------------
add "sparc: negative-displacement CALL pattern wrong" \
    'if (instr >> 22) == 0x100 || (instr >> 22) == 0x1FF {' \
    'if (instr >> 22) == 0x100 || (instr >> 22) == 0x1FE {'

add "sparc: sign bit taken from the wrong position" \
    'instr = 0x4000_0000u32.wrapping_sub(instr & 0x40_0000)' \
    'instr = 0x4000_0000u32.wrapping_sub(instr & 0x20_0000)'

# --- arm64 -----------------------------------------------------------------
add "arm64: BL opcode field off by one" \
    'if (instr >> 26) == 0x25 {' 'if (instr >> 26) == 0x24 {'

add "arm64: ADRP range check one bit narrow" \
    'if addr.wrapping_add(0x02_0000) & 0x1C_0000 != 0 {' \
    'if addr.wrapping_add(0x02_0000) & 0x0C_0000 != 0 {'

# --- riscv -----------------------------------------------------------------
add "riscv: JAL rd/funct check mask wrong" \
    'if b1 & 0x0D != 0 {' 'if b1 & 0x0C != 0 {'

add "riscv: AUIPC rounding constant dropped" \
    '| (addr.wrapping_add(0x800) & 0xFFFF_F000);' \
    '| (addr.wrapping_add(0x400) & 0xFFFF_F000);'

# --- the wrapper -----------------------------------------------------------
add "wrapper: flush copies unfiltered bytes too" \
    'let copy_size = core::cmp::min(s.temp_filtered, out_size - out_pos);' \
    'let copy_size = core::cmp::min(s.temp_size, out_size - out_pos);'

add "wrapper: stream position not advanced by the filtered run" \
    '*pos = pos.wrapping_add(filtered as u32);' \
    '*pos = pos.wrapping_add(0);'

add "wrapper: end of stream does not mark the tail filtered" \
    'if s.ret == XZ_STREAM_END {
            s.temp_filtered = s.temp_size;
        }' \
    'if s.ret == XZ_STREAM_END {
            s.temp_filtered = s.temp_filtered.min(s.temp_size);
        }'

add "wrapper: temp room test uses <= instead of <" \
    'if s.temp_size < out_size - out_pos || s.temp_size == 0 {' \
    'if s.temp_size <= out_size - out_pos || s.temp_size == 0 {'

printf '%-56s %s\n' "SABOTAGE" "RESULT"
caught=0; missed=0
for i in "${!NAMES[@]}"; do
    cp "$backup" "$target"
    if ! apply "${FINDS[$i]}" "${REPLS[$i]}" >/dev/null 2>&1; then
        printf '%-56s %s\n' "${NAMES[$i]}" "ANCHOR GONE -- not applied"
        missed=$((missed + 1)); continue
    fi
    out=$("$here/run.sh" "$runs" 2>&1); rc=$?
    # A COMPILE ERROR IS NOT A CATCH. Twice now a mutation has been scored
    # as caught on a nonzero exit that was rustc refusing the file under
    # -D warnings -- a self-assignment lint, and an unused constant. Not one
    # line of the code under test ran. Same shape as checkpatch reporting a
    # clean run on a file it had not recognised as a patch.
    if printf '%s\n' "$out" | grep -qE '^error(\[|:)|aborting due to'; then
        printf '%-56s %s\n' "${NAMES[$i]}" "COMPILE ERROR -- not a catch"
        missed=$((missed + 1)); continue
    fi
    if [ "$rc" -ne 0 ]; then
        why=$(printf '%s\n' "$out" | grep -m1 -E 'MISMATCH|IMPLAUSIBLE|panicked at|error\[' \
              | sed 's/^ *//' | cut -c1-40)
        printf '%-56s caught (%s)\n' "${NAMES[$i]}" "${why:-nonzero exit}"
        caught=$((caught + 1))
    else
        printf '%-56s NOT CAUGHT\n' "${NAMES[$i]}"
        missed=$((missed + 1))
    fi
done

cp "$backup" "$target"
echo
echo "caught $caught of $((caught + missed))"
[ "$missed" -eq 0 ]
