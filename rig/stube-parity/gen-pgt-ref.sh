#!/usr/bin/env bash
# gen-pgt-ref.sh <out.inc>: extract the REAL C of find_trampoline_placement() (pgtable_64.c) and
# sanitize_boot_params() (asm/bootparam_utils.h) from the pristine 6.18.49 tree. The only edits
# are the two absolute BIOS-data-area reads (0x40e, 0x413), which a userspace test cannot do,
# replaced by g_ebda_word / g_bios_word.
K=$(cd "$(dirname "$0")/../.." && pwd)/src/linux
{
  sed -n "/^#define sizeof_mbr/,/^}$/p" "$K/arch/x86/include/asm/bootparam_utils.h"
  sed -n '/^static unsigned long find_trampoline_placement/,/^}/p' "$K/arch/x86/boot/compressed/pgtable_64.c" \
    | sed -e 's/\*(unsigned short \*)0x40e/g_ebda_word/' -e 's/\*(unsigned short \*)0x413/g_bios_word/'
} > "$1"
