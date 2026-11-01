#!/usr/bin/env bash
# layout-kaslr.sh [builddir]  (default build-kas: has KHO-less EFI+ACPI+HOTREMOVE) -- compiler-checked layouts/constants of kaslr_rs.rs
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
b=${1:-build-kas}
export CMD_DONOR="$root/build-efi"
export LAYOUT_CFGS="efi unaccepted_memory kexec_handover hotremove_acpi"
KB_RUSTC=$KB_RUSTC exec python3 "$root/rig/stubf/layout-check.py" "$root/$b" "$root/rig/stubf/layouts-kaslr.txt" \
  "$root/port/tree/arch/x86/boot/compressed/kaslr_rs.rs" arch/x86/boot/compressed/.kaslr.o.cmd '#define BOOT_CTYPE_H' '#include "misc.h"' '#include "error.h"' '#include "../string.h"' '#include "efi.h"' '#include <asm/bootparam.h>' '#define _SETUP' '#include <asm/setup.h>' '#undef _SETUP' '#include <asm/archrandom.h>' '#include <asm/cpufeatures.h>' '#include <asm/e820/types.h>' '#include <linux/kexec_handover.h>'
