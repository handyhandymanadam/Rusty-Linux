#!/usr/bin/env bash
# abi-check-selftest.sh [build-dir]
#
# THE ACCEPTANCE TEST FOR rig/abi-check.sh. A guard that has only ever run on a
# healthy tree has not been tested. This breaks things on purpose, one at a
# time, and requires the guard to notice.
#
# ---------------------------------------------------------------------------
# EVERY CASE HERE IS A DEFECT THAT ACTUALLY GOT THROUGH. None is invented.
#
# THE FIRST VERSION OF THIS TEST WAS WRONG IN TWO WAYS, both easy to repeat:
#
# 1. ITS SABOTAGES DID NOT COMPILE. It rewrote the Rust signature and left the
#    thunk's `unsigned rust_bcd2bin(unsigned char);` declaration alone, so the
#    C compiler rejected the build -- and the test counted that as the guard
#    "catching" it. It did not. The COMPILER caught it, using the declaration
#    that deleting the thunk removes. A sabotage that only fails to compile
#    exercises nothing.
#
#    So every case changes the Rust signature AND the thunk's forward
#    declaration together, leaving the exported entry symbol untouched. That
#    compiles cleanly, and the Rust body genuinely no longer matches the symbol
#    C callers see -- the post-thunk defect, staged in a tree that still has
#    thunks.
#
# 2. ITS VERDICT WAS THE GUARD'S EXIT STATUS, already 1 on a clean tree from
#    pre-existing false positives. Every case reported "caught" regardless,
#    including cases that never ran. A test whose pass condition is already
#    true before it runs is not a test.
#
#    The verdict here is a DIFF against a baseline from the clean tree: the
#    target symbol's own line must change from `ok`, and every other line must
#    stay byte-identical, which also catches collateral damage.
#
# CASES 4 AND 5 EXIST BECAUSE ADVERSARIAL REVIEW PLANTED THEM AND THE GUARD
# SAID `0 MISMATCH, exit 0`:
#   4. arc4_crypt was in the 20-of-71 pass-throughs the pairing regex silently
#      dropped -- a void tail call with no `return` keyword. There was no line
#      for it in the output at all, before or after.
#   5. ZSTD_getErrorCode's PARAMETER break hid behind a whole-pair exception
#      that existed only for its unmeasurable RETURN.
# Both classes are now structurally impossible. These cases are what says so.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
build=${1:-build-fast}

# EVERY PATH HERE MUST EXIST. `git checkout -- <missing path>` fails and
# restores NOTHING, and the restore below sent its stderr to /dev/null. When
# lib/bcd.c, lib/crypto/arc4.c and zstd_common_thunk.c were deleted -- their
# exports and contracts having moved into the Rust -- this list still named
# them, so every restore silently failed and the run left three sabotaged
# files in the tree. The existence check under it is not decoration.
FILES=(
    port/tree/lib/bcd_rs.rs
    port/tree/lib/crypto/arc4_rs.rs
    port/tree/lib/zstd/common/zstd_common_rs.rs
)

for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "FILES names $f, which does not exist -- the restore" \
                          "would silently do nothing. Fix the list." >&2; exit 2; }
done

work=$(mktemp -d)
# REFUSE TO RUN ON A DIRTY TREE. This rewrites tracked files and restores them
# from git; starting from unknown content means the restore cannot be trusted,
# and an earlier adversary's sabotage reached a commit exactly that way.
if ! git diff --quiet -- "${FILES[@]}" || ! git diff --cached --quiet -- "${FILES[@]}"; then
    echo "REFUSING: one of the files this test rewrites has uncommitted changes:" >&2
    git status --porcelain -- "${FILES[@]}" >&2
    exit 2
fi
restore() { git checkout -- "${FILES[@]}" || { echo "*** RESTORE FAILED" >&2; exit 2; }; ./rig/apply.sh >/dev/null 2>&1; }
trap 'restore; rm -rf "$work"' EXIT

source ./kbuild-env.sh
build_tree() { kmake O=../../"$build" -j4 >"$work/build.log" 2>&1; }
# COMPARE ONLY THE PER-SYMBOL VERDICT LINES. A first attempt diffed whole
# files and called every case a false alarm: it counted the stderr banner
# (folded in by 2>&1) and the target's OWN indented `C .../Rust ...` detail
# lines as "unrelated changes". Verdict lines start with an identifier in
# column 1; details are indented and banners start with `***`.
verdicts() { grep -E '^[A-Za-z_]' "$1" | grep -vE '^[0-9]+ match,'; }

echo "=== baseline: the clean tree, which must already be healthy"
./rig/apply.sh >/dev/null 2>&1
build_tree || { echo "clean tree does not build -- cannot test" >&2; exit 2; }
./rig/abi-check.sh "$build" >"$work/baseline.txt" 2>&1
tail -1 "$work/baseline.txt" | sed 's/^/    /'

# args: target name why  then triples of  <file> <old> <new>
run_case() {
    local target="$1" name="$2" why="$3"; shift 3
    git checkout -- "${FILES[@]}" || { echo "*** RESTORE FAILED" >&2; exit 2; }
    local base_line; base_line=$(grep -E "^$target " "$work/baseline.txt" || true)
    case "$base_line" in
        *" ok "*) ;;
        *) printf '%-22s %-40s %s\n' "$name" "$why" "*** NOT ok ON CLEAN TREE -- proves nothing"
           return 1;;
    esac
    if ! python3 - "$@" <<'PYEOF'
import sys
a = sys.argv[1:]
for i in range(0, len(a), 3):
    path, old, new = a[i], a[i+1], a[i+2]
    s = open(path).read()
    if old not in s:
        sys.exit("EDIT DID NOT APPLY in %s: %r" % (path, old))
    open(path, "w").write(s.replace(old, new, 1))
PYEOF
    then
        printf '%-22s %-40s %s\n' "$name" "$why" "BROKEN CASE (edit did not apply)"
        return 1
    fi
    ./rig/apply.sh >/dev/null 2>&1
    if ! build_tree; then
        # NOT a pass. See note 1 above: a sabotage that fails to compile tests
        # the C declaration, which is the thing being removed. The case is at
        # fault and must be rewritten so that it compiles.
        printf '%-22s %-40s %s\n' "$name" "$why" "*** CASE FAILED TO COMPILE"
        grep -m2 'error' "$work/build.log" | sed 's/^/      /'
        return 1
    fi
    ./rig/abi-check.sh "$build" >"$work/after.txt" 2>&1
    local after; after=$(grep -E "^$target " "$work/after.txt" || true)
    if [ "$after" = "$base_line" ]; then
        printf '%-22s %-40s %s\n' "$name" "$why" "*** NOT CAUGHT"
        echo "      line unchanged: $after"
        return 1
    fi
    case "$after" in
        *MISMATCH*|*UNRESOLVED*) ;;
        *) printf '%-22s %-40s %s\n' "$name" "$why" "*** NOT CAUGHT (changed, but not to a failure)"
           echo "      before: $base_line"; echo "      after:  $after"; return 1;;
    esac
    printf '%-22s %-40s %s\n' "$name" "$why" "caught"
    local collateral
    collateral=$(diff <(verdicts "$work/baseline.txt" | grep -vE "^$target ") \
                      <(verdicts "$work/after.txt"    | grep -vE "^$target ") | head -4)
    [ -z "$collateral" ] || { echo "      *** but unrelated lines also changed:"
                              echo "$collateral" | sed 's/^/      /'; return 1; }
    return 0
}

echo
printf '%-22s %-40s %s\n' CASE "STANDS FOR" VERDICT
pass=0; miss=0

# CASES 1-3 NOW EDIT ONLY THE RUST, because lib/bcd is thunk-free: Rust
# defines _bcd2bin() and there is no C forward declaration left to keep in
# step. That makes them a STRONGER test than before -- the sabotage compiles
# with nothing complaining, which is precisely the post-thunk world these
# cases were always standing in for.
#
# Note what does NOT catch them any more: the MODVERSIONS fingerprint. The
# KABI_TYPE_STRING pin in bcd.c holds the CRC at its C value BY CONSTRUCTION,
# so a drifting Rust signature no longer moves it. Pinning buys ABI
# compatibility and spends the CRC's value as a drift detector. abi-check.sh
# is what is left.
#
# 1. THE DEMONSTRATED DEFECT. This exact change built clean, kept CRC
#    0xdf37db04, loaded as a module and printed the RIGHT ANSWER, because clang
#    happened to zero-extend the register.
run_case _bcd2bin param-widened "u8 param -> u64: the proven break" \
    port/tree/lib/bcd_rs.rs \
      'fn _bcd2bin(val: u8) -> c_uint {' \
      'fn _bcd2bin(val: u64) -> c_uint {' \
  && pass=$((pass+1)) || miss=$((miss+1))

# 2. The other half of the signature.
run_case _bcd2bin return-widened "return unsigned -> u64" \
    port/tree/lib/bcd_rs.rs \
      'fn _bcd2bin(val: u8) -> c_uint {
    ((val & 0x0f) as c_uint) + (val >> 4) as c_uint * 10' \
      'fn _bcd2bin(val: u8) -> u64 {
    ((val & 0x0f) as u64) + (val >> 4) as u64 * 10' \
  && pass=$((pass+1)) || miss=$((miss+1))

# 3. SAME WIDTH, WRONG SIGN. The register does not change, so no behavioural
#    test and no CRC can see this. Only a signature can.
run_case _bcd2bin signedness "unsigned char param became signed" \
    port/tree/lib/bcd_rs.rs \
      'fn _bcd2bin(val: u8) -> c_uint {' \
      'fn _bcd2bin(val: i8) -> c_uint {' \
  && pass=$((pass+1)) || miss=$((miss+1))

# 4. THE PAIRING HOLE. arc4_crypt returns VOID, and a void tail call --
#    `rust_arc4_crypt(...)` with no `return` -- was one of 20 of 71
#    pass-throughs the old pairing regex dropped entirely. Review planted this
#    and the guard printed `0 MISMATCH, exit 0` with no line for arc4_crypt.
#
#    lib/crypto/arc4.c is now deleted and the Rust exports arc4_crypt itself,
#    so the sabotage edits only the Rust -- there is no C declaration left to
#    keep in step. That makes it a stronger case, not a weaker one: nothing
#    but abi-check.sh can see it, and it is now paired against the pristine C
#    reference rather than a declaration in the tree.
run_case arc4_crypt void-thunk-pairing "a VOID symbol: silently unpaired before" \
    port/tree/lib/crypto/arc4_rs.rs \
      '    len: c_uint,
) {' \
      '    len: u64,
) {' \
  && pass=$((pass+1)) || miss=$((miss+1))

# 5. THE EXCEPTION HOLE. ZSTD_getErrorCode has a declared exception for its
#    unmeasurable anonymous-enum RETURN. Review hid a PARAMETER width change
#    behind it -- the old code excused the whole pair.
# NOTE: this symbol is now THUNK-FREE (commit 2ca83b2), so the sabotage edits
# only the Rust -- there is no forward declaration left to keep in step, which
# makes the case stronger, not weaker.
run_case ZSTD_getErrorCode except-scope "param break behind a ret-slot exception" \
    port/tree/lib/zstd/common/zstd_common_rs.rs \
      'fn ZSTD_getErrorCode(code: usize) -> i32 {' \
      'fn ZSTD_getErrorCode(code: u32) -> i32 {
    let code = code as usize;' \
  && pass=$((pass+1)) || miss=$((miss+1))

# 6. THE NEGATIVE CONTROL, and it is not optional. A guard that flags
#    everything is as useless as one that flags nothing -- and a case in the
#    previous version "passed" only because the guard was already failing.
echo
git checkout -- "${FILES[@]}" || { echo "*** RESTORE FAILED" >&2; exit 2; }
python3 - <<'PYEOF'
p = "port/tree/lib/bcd_rs.rs"; s = open(p).read()
old = "((val & 0x0f) as c_uint) + (val >> 4) as c_uint * 10"
assert old in s, "negative control edit did not apply"
open(p, "w").write(s.replace(old, old + " + 0", 1))
PYEOF
./rig/apply.sh >/dev/null 2>&1
if build_tree; then
    ./rig/abi-check.sh "$build" >"$work/neg.txt" 2>&1
    if diff -q <(verdicts "$work/baseline.txt") <(verdicts "$work/neg.txt") >/dev/null; then
        printf '%-22s %-40s %s\n' negative-control "body changed, signature not" "correctly silent"
        pass=$((pass+1))
    else
        printf '%-22s %-40s %s\n' negative-control "body changed, signature not" "*** FALSE POSITIVE"
        diff <(verdicts "$work/baseline.txt") <(verdicts "$work/neg.txt") | head -6 | sed 's/^/      /'
        miss=$((miss+1))
    fi
else
    printf '%-22s %-40s %s\n' negative-control "body changed, signature not" "*** did not compile"
    miss=$((miss+1))
fi

echo
echo "=== restoring and verifying the tree came back"
restore
build_tree || { echo "*** RESTORED TREE DOES NOT BUILD" >&2; exit 1; }
./rig/abi-check.sh "$build" >"$work/final.txt" 2>&1
if diff -q <(verdicts "$work/baseline.txt") <(verdicts "$work/final.txt") >/dev/null; then
    echo "    restored: guard output identical to baseline"
else
    echo "*** RESTORE INCOMPLETE -- guard output differs from baseline" >&2
    diff <(verdicts "$work/baseline.txt") <(verdicts "$work/final.txt") | head -10 >&2
    miss=$((miss+1))
fi
d=$(git status --porcelain -- "${FILES[@]}")
[ -z "$d" ] && echo "    tree clean" || { echo "*** TREE LEFT DIRTY:"; echo "$d"; miss=$((miss+1)); }

echo
echo "$pass caught, $miss MISSED"
[ "$miss" = 0 ] || echo "*** the guard does not catch a defect the C compiler catches today" >&2
exit $([ "$miss" = 0 ] && echo 0 || echo 1)
