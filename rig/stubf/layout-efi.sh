#!/usr/bin/env bash
# layout-efi.sh [builddir]  -- compiler-checked layouts of every struct efi_rs.rs mirrors (see layout-check.py)
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
KB_RUSTC=$KB_RUSTC exec python3 "$root/rig/stubf/layout-check.py" "$root/${1:-build-efi}" "$root/rig/stubf/layouts-efi.txt" \
  "$root/port/tree/arch/x86/boot/compressed/efi_rs.rs" arch/x86/boot/compressed/.efi.o.cmd '#include "misc.h"' '#include <asm/bootparam.h>' '#include <asm/setup_data.h>'
