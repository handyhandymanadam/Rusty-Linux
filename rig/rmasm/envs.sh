#!/usr/bin/env bash
# envs.sh BUILD_DIR [--cfgs] -- the RMASM build inputs, extracted from BUILD_DIR the SAME way arch/x86/boot/Makefile does.
#   (default)  print `export RMASM_PHYSICAL_START=.. RMASM_PHYSICAL_ALIGN=.. RMASM_SVGA_MODE=NORMAL_VGA`
#   --cfgs     print the --cfg flags header_rs.rs derives from the .config (x86_64 x86_32 efi_stub efi_mixed efi_sbat
#              efi_handover_protocol relocatable efi kexec_core)
b=$1
if [ "${2:-}" = --cfgs ]; then
  for p in 'X86_64 x86_64' 'X86_32 x86_32' 'EFI_STUB efi_stub' 'EFI_MIXED efi_mixed' 'EFI_SBAT efi_sbat' 'EFI_HANDOVER_PROTOCOL efi_handover_protocol' \
           'RELOCATABLE relocatable' 'EFI efi' 'KEXEC_CORE kexec_core'; do set -- $b $p
    grep -q "^CONFIG_$2=y" "$b/.config" && printf -- '--cfg=%s ' $3; done; echo; exit 0; fi
cfg() { sed -n "s/^CONFIG_$1=\(.*\)/\1/p" "$b/.config"; }
echo "export RMASM_PHYSICAL_START=$(cfg PHYSICAL_START) RMASM_PHYSICAL_ALIGN=$(cfg PHYSICAL_ALIGN) RMASM_SVGA_MODE=NORMAL_VGA"
