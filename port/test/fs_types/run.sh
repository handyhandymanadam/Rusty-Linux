#!/usr/bin/env bash
# port/test/fs_types/run.sh -- exhaustive differential for fs/fs_types.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/fs_types"
out="${TMPDIR:-/tmp}/fstypes.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${FST_RS:-$root/port/tree/fs/fs_types_rs.rs}"
C="$root/port/pristine/fs/fs_types.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
REN=""; for fn in fs_ftype_to_dtype fs_umode_to_ftype fs_umode_to_dtype; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name fs_types_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -I "$here/shim" -DFS_TYPES_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if FST_PROVE_CAN_FAIL=1 "$out/real/t" >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if timeout 300 "$out/m$n/t" >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
guard~if filetype >= FT_MAX {~if filetype > FT_MAX {
t-reg~t[FT_REG_FILE as usize] = DT_REG;~t[FT_REG_FILE as usize] = DT_DIR;
t-sock~t[FT_SOCK as usize] = DT_SOCK;~t[FT_SOCK as usize] = DT_FIFO;
t-lnk~t[FT_SYMLINK as usize] = DT_LNK;~t[FT_SYMLINK as usize] = DT_REG;
r-fifo~t[DT_FIFO as usize] = FT_FIFO;~t[DT_FIFO as usize] = FT_SOCK;
r-blk~t[DT_BLK as usize] = FT_BLKDEV;~t[DT_BLK as usize] = FT_CHRDEV;
r-lnk~t[DT_LNK as usize] = FT_SYMLINK;~t[DT_LNK as usize] = FT_UNKNOWN;
r-wht~let mut t = [FT_UNKNOWN; DT_MAX];~let mut t = [FT_REG_FILE; DT_MAX];
ifmt~const S_IFMT: u16 = 0o170000;~const S_IFMT: u16 = 0o160000;
shift~const S_DT_SHIFT: u32 = 12;~const S_DT_SHIFT: u32 = 11;
dtype-compose~fs_ftype_to_dtype(fs_umode_to_ftype(mode) as c_uint)~fs_umode_to_ftype(mode)
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
"$out/real/t"
echo "PASS"
