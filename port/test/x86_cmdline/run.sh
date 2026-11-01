#!/usr/bin/env bash
# port/test/x86_cmdline/run.sh -- differential for arch/x86/lib/cmdline.c.
#   run.sh [seed] [iters]   full run, both Kconfig arms (CONFIG_CMDLINE_BOOL off and on)
#   run.sh --sabotage       prove the harness fails on mutants of the Rust (each must be caught)
# C arm = port/pristine/arch/x86/lib/cmdline.c (compiled unmodified); Rust arm =
# port/tree/arch/x86/lib/cmdline.c (the C glue the kernel builds) + cmdline_rs.rs.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/x86_cmdline"
out="${TMPDIR:-/tmp}/x86cmdline.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="${CMD_PRISTINE:-$root/port/pristine/arch/x86/lib/cmdline.c}"
G="${CMD_GLUE:-$root/port/tree/arch/x86/lib/cmdline.c}"
RS="${CMD_RS:-$root/port/tree/arch/x86/lib/cmdline_rs.rs}"
for f in "$C" "$G" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
INC=(-I "$here/shim" -I "$here")
build() {   # build <rs> <dir> <extra cflags...>
    local rs=$1 o=$2; shift 2
    mkdir -p "$o"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name x86_cmdline_rs -o "$o/librs.a" "$rs"
    cc -O2 -Wall -Wno-unused-function -Wno-unused-variable "${INC[@]}" "$@" -DCMDLINE_PRISTINE_C="\"$C\"" -c -o "$o/ref.o" "$here/ref.c"
    cc -O2 -Wall -Wno-unused-function "${INC[@]}" "$@" -DCMDLINE_GLUE_C="\"$G\"" -c -o "$o/glue.o" "$here/glue_ref.c"
    cc -O2 -Wall "${INC[@]}" "$@" -c -o "$o/vars.o" "$here/vars.c"
    cc -O2 -Wall "${INC[@]}" "$@" -c -o "$o/drv.o" "$here/drv.c"
    cc -o "$o/t" "$o"/ref.o "$o"/glue.o "$o"/vars.o "$o"/drv.o "$o/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
if [ "${1:-}" = "--sabotage" ]; then
    build "$RS" "$out/real" -DWITH_BOOL
    echo "prove-can-fail:"
    if CMD_PROVE_CAN_FAIL=1 "$out/real/t" 1 20000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    n=0; caught=0
    mutate() {  # mutate <name> <from> <to>
        n=$((n+1))
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
assert a in s, "pattern missing: " + a
open(sys.argv[2], "w").write(s.replace(a, b, 1))
PY
        build "$out/mut.rs" "$out/m$n" -DWITH_BOOL >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 1 400000 >/dev/null 2>&1; then echo "mutant $1: *** NOT CAUGHT"; else echo "mutant $1: caught"; caught=$((caught+1)); fi
    }
    mutate space-bound            'c <= b'"' '"' // "Close' 'c < b'"' '"' // "Close'
    mutate space-bound-hi         'c <= b'"' '"' // "Close' 'c <= b'"'!'"' // "Close'
    mutate bool-null-ret          'return -1; // No command line' 'return 0; // No command line'
    mutate bool-pos-bound         'while pos < max_cmdline_size {' 'while pos <= max_cmdline_size {'
    mutate bool-wstart            'wstart = pos;' 'wstart = pos - 1;'
    mutate bool-end-not-word      'if c == 0 || myisspace(c) {
                    return wstart;' 'if c == 0 {
                    return wstart;'
    mutate bool-nul-in-cmp        '} else if c == 0 {
                return 0; // hit the NUL terminator of cmdline' '} else if c == 1 {
                return 0; // hit the NUL terminator of cmdline'
    mutate bool-skip-nul          'if c == 0 {
                return 0;
            } else if myisspace(c) {
                state = State::WordStart;' 'if myisspace(c) {
                state = State::WordStart;'
    mutate bool-wordstart-nul     'if c == 0 {
                return 0;
            } else if myisspace(c) {
                continue;' 'if myisspace(c) {
                continue;'
    mutate opt-null-ret           'return -1; // No command line
    }

    // The C' 'return 0; // No command line
    }

    // The C'
    mutate opt-bound              'if before >= max_cmdline_size {' 'if before > max_cmdline_size {'
    mutate opt-bound-lt           'if before >= max_cmdline_size {' 'if before + 1 >= max_cmdline_size {'
    mutate opt-eq-needs-end       'if c == b'"'='"' && oc == 0 {' 'if c == b'"'='"' {'
    mutate opt-len-reset          'len = 0;
                bufptr' 'len = 1;
                bufptr'
    mutate opt-bufptr-reset       'bufptr = buffer as *mut u8;
                state = State::BufCpy;' 'state = State::BufCpy;'
    mutate opt-room-for-nul       'if len < bufsize {' 'if len <= bufsize {'
    mutate opt-nul-write          'if bufsize != 0 {
        // SAFETY' 'if bufsize > 0 {
        // SAFETY'
    mutate opt-nul-always         'if bufsize != 0 {
        // SAFETY' 'if true {
        // SAFETY'
    mutate opt-last-not-first     'len = 0;
                bufptr' 'if len >= 0 { continue; }
                len = 0;
                bufptr'
    mutate opt-buf-space          'if myisspace(c) {
            state = State::WordStart;
        } else {' 'if c == b'"' '"' {
            state = State::WordStart;
        } else {'
    mutate opt-skip-space         'if myisspace(c) {
                state = State::WordStart;
            }
            continue;' 'if c == b'"' '"' {
                state = State::WordStart;
            }
            continue;'
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
rc=0
for arm in "" "-DWITH_BOOL"; do
    echo "== arm: ${arm:-CONFIG_CMDLINE_BOOL off}"
    build "$RS" "$out/real${arm:+B}" $arm
    if [ -z "$arm" ]; then
        echo "prove-can-fail:"
        if CMD_PROVE_CAN_FAIL=1 "$out/real/t" 1 20000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
        echo "  ok, poisoned Rust result detected"
    fi
    "$out/real${arm:+B}/t" "${1:-1}" "${2:-20000000}" || rc=1
done
exit $rc
