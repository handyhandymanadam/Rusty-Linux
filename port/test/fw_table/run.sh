#!/usr/bin/env bash
# port/test/fw_table/run.sh -- the userspace differential for lib/fw_table.c.
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. The C is
# port/pristine/lib/fw_table.c, compiled with its two global symbols renamed
# c_* so both arms link into one binary.
#
# THE ORACLE'S STRUCT LAYOUTS ARE UPSTREAM'S OWN TEXT. This harness's
# shim/linux/acpi.h includes port/pristine/include/acpi/{actypes,actbl}.h
# verbatim rather than transcribing the seven ACPICA header structs -- and
# actbl.h pulls actbl1/2/3.h itself. Every offset the port reads is checked
# against offsetof() on THOSE definitions in drv.c's geometry stage, and that
# check would be worth nothing if both sides had come from the same pen.
#
# CRITERION 8 (logs/floor.md RAISE 3) BIT ON THE FIRST COMPILE, and the check
# for it is below rather than in a comment. `include/linux/fw_table.h:52`
# forks on `IS_ENABLED(CONFIG_ACPI) && !IS_ENABLED(CONFIG_CXL_BUS)`; with
# CONFIG_ACPI undefined the preprocessor took the #else arm -- the "CXL"
# namespace export, the arm config-full does NOT build -- and the oracle
# would have been a different program from the kernel's. The shim defines
# CONFIG_ACPI=1 and leaves CONFIG_CXL_BUS/CONFIG_ACPI_TABLE_LIB undefined, to
# match build-full/.config, and `check_export_arm` below reads the resulting
# expansion back out of the preprocessor rather than trusting that.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/fw_table"
out="${TMPDIR:-/tmp}/fw_table-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

# sabotage.sh points these at mutated copies.
C="${FW_TABLE_C:-$root/port/pristine/lib/fw_table.c}"
RS="${FW_TABLE_RS:-$root/port/tree/lib/fw_table_rs.rs}"
PINC="${FW_TABLE_INC:-$root/port/pristine/include}"
for f in "$C" "$RS" "$PINC/linux/fw_table.h" "$PINC/acpi/actbl.h" \
         "$PINC/acpi/actypes.h"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

mkprobe() {
    local dst=$1
    {
        echo '//! Harness probe. The real module documentation is in'
        echo '//! port/tree/lib/fw_table_rs.rs; run.sh demotes it because an'
        echo '//! inner doc comment cannot follow the prelude below.'
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        sed 's|^//!|//|' "$RS"
        cat <<'PROBE'

// ---- harness only, appended by port/test/fw_table/run.sh ---------------

/// Writes this crate's view of the mirrored C structs' geometry into `out`,
/// in the order drv.c's `stage_geometry()` reads it. Harness only: appended
/// to a copy, never seen by the kernel build. Lives inside the crate because
/// that is the only place `offset_of!` can reach these private fields.
///
/// # Safety
/// `out` must point to at least `GEOM_N` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn rs_geometry(out: *mut usize) {
    use core::mem::{align_of, offset_of, size_of};
    // SAFETY: caller guarantees `out` has room for every index written.
    unsafe {
        *out.add(0)  = size_of::<AcpiTableHeader>();
        *out.add(1)  = offset_of!(AcpiTableHeader, signature);
        *out.add(2)  = offset_of!(AcpiTableHeader, length);
        *out.add(3)  = offset_of!(AcpiTableHeader, revision);
        *out.add(4)  = offset_of!(AcpiTableHeader, oem_id);
        *out.add(5)  = offset_of!(AcpiTableHeader, asl_compiler_revision);

        *out.add(6)  = size_of::<AcpiTableCdat>();
        *out.add(7)  = offset_of!(AcpiTableCdat, length);
        *out.add(8)  = offset_of!(AcpiTableCdat, sequence);

        *out.add(9)  = size_of::<AcpiSubtableHeader>();
        *out.add(10) = offset_of!(AcpiSubtableHeader, r#type);
        *out.add(11) = offset_of!(AcpiSubtableHeader, length);

        *out.add(12) = size_of::<AcpiHmatStructure>();
        *out.add(13) = offset_of!(AcpiHmatStructure, r#type);
        *out.add(14) = offset_of!(AcpiHmatStructure, length);

        *out.add(15) = size_of::<AcpiPrmtModuleHeader>();
        *out.add(16) = offset_of!(AcpiPrmtModuleHeader, length);

        *out.add(17) = size_of::<AcpiCedtHeader>();
        *out.add(18) = offset_of!(AcpiCedtHeader, r#type);
        *out.add(19) = offset_of!(AcpiCedtHeader, length);

        *out.add(20) = size_of::<AcpiCdatHeader>();
        *out.add(21) = offset_of!(AcpiCdatHeader, r#type);
        *out.add(22) = offset_of!(AcpiCdatHeader, length);

        *out.add(23) = size_of::<FwTableHeader>();
        *out.add(24) = size_of::<AcpiSubtableHeaders>();

        *out.add(25) = size_of::<AcpiSubtableProc>();
        *out.add(26) = offset_of!(AcpiSubtableProc, id);
        *out.add(27) = offset_of!(AcpiSubtableProc, handler);
        *out.add(28) = offset_of!(AcpiSubtableProc, handler_arg);
        *out.add(29) = offset_of!(AcpiSubtableProc, arg);
        *out.add(30) = offset_of!(AcpiSubtableProc, count);
        *out.add(31) = align_of::<AcpiSubtableProc>();
    }
}
PROBE
    } > "$dst"
}

# The kernel's own rustc lint set.
RSFLAGS=(--edition 2021 -O -C panic=abort -C overflow-checks=on
         -D unsafe_op_in_unsafe_fn -D warnings -A unreachable_pub
         -Dnon_ascii_idents -Wmissing_docs -Wrust_2018_idioms)

CF=(-O2 -g -Wall -Wextra -Wno-unused-parameter
    # The three -Wsign-compare hits are upstream's own, at fw_table.c:177,
    # :180 and :203 -- and they are exactly the two integer promotions
    # fw_table_rs.rs documents (unsigned long vs int, and int vs unsigned
    # int). Suppressed because the kernel does not build with the warning,
    # and named here so the suppression is not mistaken for tidiness.
    -Wno-sign-compare
    -I "$here/shim" -I "$root/port/test/common/shim" -I "$PINC")

REN=(
    -Dacpi_parse_entries_array=c_acpi_parse_entries_array
    -Dcdat_table_parse=c_cdat_table_parse
)

# ---------------------------------------------------------------------------
# RAISE 1 -- every combination of the Kconfig symbols the ported file reads.
# ---------------------------------------------------------------------------
mapfile -t CFGS < <(grep -o 'cfg(CONFIG_[A-Z0-9_]*)' "$RS" \
                    | sed 's/cfg(\(.*\))/\1/' | sort -u)
n=${#CFGS[@]}
echo "RAISE 1 sweep: $n cfg symbol(s) -> $((1 << n)) subset(s), --emit=metadata"
mkprobe "$out/sweep.rs"
for ((mask = 0; mask < (1 << n); mask++)); do
    args=()
    for ((b = 0; b < n; b++)); do
        (( mask & (1 << b) )) && args+=(--cfg "${CFGS[b]}")
    done
    "$KB_RUSTC" "${RSFLAGS[@]}" --crate-type lib --emit=metadata \
        --crate-name fw_table_rs -o "$out/sweep.rmeta" \
        "${args[@]}" "$out/sweep.rs"
done
echo "  all $((1 << n)) subset(s) type-check"

# ---------------------------------------------------------------------------
# Criterion 8, read back rather than asserted: the export macro must expand
# to NOTHING. If the oracle ever takes the CXL arm again, this says so.
# ---------------------------------------------------------------------------
check_export_arm() {
    local expanded
    expanded=$(cc "${CF[@]}" -E "$C" | tail -1 | tr -d ' \t')
    if [ "$expanded" != ";" ]; then
        echo "*** THE ORACLE TOOK THE WRONG EXPORT ARM."
        echo "    EXPORT_SYMBOL_FWTBL_LIB expanded to: $expanded"
        echo "    config-full has CONFIG_ACPI=y, CONFIG_CXL_BUS unset and"
        echo "    CONFIG_ACPI_TABLE_LIB unset, in which it expands to nothing."
        exit 1
    fi
    echo "criterion 8: EXPORT_SYMBOL_FWTBL_LIB expands to nothing, as on config-full"
}
check_export_arm

# ---------------------------------------------------------------------------
# Section placement. The differential cannot see this and the shim
# deliberately drops __init, so it is measured on the objects instead: the
# port must land in .init.text and leave .text empty, exactly as the C does.
# The Rust is built with the kernel's own flags; the C with __init expanded
# to the section attribute the kernel's <linux/init.h> gives it.
# ---------------------------------------------------------------------------
mkprobe "$out/probe.rs"
"$KB_RUSTC" "${RSFLAGS[@]}" --crate-type staticlib \
    --crate-name fw_table_rs -o "$out/librs.a" "$out/probe.rs"

section_sizes() {   # <object> -> "<.text size> <.init.text size>"
    objdump -h "$1" | awk '
        $2 == ".text"      { t = strtonum("0x" $3) }
        $2 == ".init.text" { i = strtonum("0x" $3) }
        END { printf "%d %d\n", t + 0, i + 0 }'
}

rsobj=$(ar t "$out/librs.a" | grep -m1 'fw_table_rs')
( cd "$out" && ar x librs.a "$rsobj" )
# It is __init_or_acpilib that lib/fw_table.c's functions carry, via
# fw_table.h:55 -- not __init. Overriding __init compiles a file that never
# mentions it.
cc "${CF[@]}" -D__init_or_acpilib='__attribute__((section(".init.text")))' \
   "${REN[@]}" -c -o "$out/cref-init.o" "$C"

read -r rs_text rs_init < <(section_sizes "$out/$rsobj")
read -r c_text c_init < <(section_sizes "$out/cref-init.o")
printf 'section placement   .text  .init.text\n'
printf '  C (with __init)   %-6s %s\n' "$c_text" "$c_init"
printf '  Rust              %-6s %s\n' "$rs_text" "$rs_init"
if [ "$rs_text" -ne 0 ] || [ "$rs_init" -eq 0 ]; then
    echo "*** THE PORT IS NOT IN .init.text. The C's whole body is discarded"
    echo "    after boot and this one would not be."
    exit 1
fi
if [ "$c_text" -ne 0 ] || [ "$c_init" -eq 0 ]; then
    echo "*** THE C ARM IS NOT IN .init.text EITHER -- the check above proves"
    echo "    nothing, because the thing it compares against did not happen."
    exit 1
fi

# ---------------------------------------------------------------------------
# The differential.
# ---------------------------------------------------------------------------
cc "${CF[@]}" "${REN[@]}" -c -o "$out/cref.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/cref.o" "$out/librs.a"

# THE ARRANGEMENT PROVES ITSELF FIRST. One byte of the Rust arm's table
# differs, so the arms must disagree. The evidence required is the driver's
# PRINTED verdict, not its exit code -- a sabotaged port can crash, and a
# crash is also a nonzero exit.
set +e
FW_TABLE_PROVE_CAN_FAIL=1 "$out/t" > "$out/poisoned.log" 2>&1
prc=$?
set -e
if ! grep -q '^MISMATCH:\|^GEOMETRY:' "$out/poisoned.log"; then
    echo "*** THE HARNESS CANNOT DISAGREE: the poisoned run (exit $prc)"
    echo "    reported no mismatch. Last lines:"
    tail -5 "$out/poisoned.log" | sed 's/^/    /'
    exit 1
fi
echo "prove-can-fail: a poisoned Rust arm is reported (exit $prc)"

"$out/t"
