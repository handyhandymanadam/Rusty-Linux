#!/usr/bin/env bash
# layout-misc.sh [builddir]  -- compiler-checked layouts of the ELF structs misc_rs.rs mirrors (rig/stubf/layout-check.py)
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
LAYOUT_CFGS="${LAYOUT_CFGS:-amd_mem_encrypt}" KB_RUSTC=$KB_RUSTC exec python3 "$root/rig/stubf/layout-check.py" "$root/${1:-build-efi}" "$root/rig/stubg/layouts-misc.txt" \
  "$root/port/tree/arch/x86/boot/compressed/misc_rs.rs" arch/x86/boot/compressed/.misc.o.cmd '#include "misc.h"'
