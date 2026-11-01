#!/usr/bin/env bash
# layout-acpi.sh [builddir]  (default build-kas: needs hotremove_srat + NODES_SHIFT) -- compiler-checked layouts/constants of acpi_rs.rs
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
b=${1:-build-kas}
export CMD_DONOR="$root/build-efi"   # build-kas never compiles acpi.c (Rust replaces it): borrow the saved kbuild command from build-efi, run in build-kas
export LAYOUT_CFGS="efi hotremove_srat kexec_core stubf_test_nothing"
export STUBF_NODES_SHIFT=$(sed -n 's/^CONFIG_NODES_SHIFT=//p' "$root/$b/.config")
KB_RUSTC=$KB_RUSTC exec python3 "$root/rig/stubf/layout-check.py" "$root/$b" "$root/rig/stubf/layouts-acpi.txt" \
  "$root/port/tree/arch/x86/boot/compressed/acpi_rs.rs" arch/x86/boot/compressed/.acpi.o.cmd '#define BOOT_CTYPE_H' '#include "misc.h"' '#include "error.h"' '#include "../string.h"' '#include "efi.h"' '#include <asm/bootparam.h>' '#include <linux/numa.h>'
