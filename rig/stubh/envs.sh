#!/usr/bin/env bash
# envs.sh BUILD_DIR -- print the STUBH_* environment the head_64_rs.rs build needs, extracted from BUILD_DIR the SAME way
# the Makefile does (config values from .config, feature masks from the generated cpufeaturemasks.h). check.sh evals it.
b=$1
if [ "${2:-}" = --cfgs ]; then   # the --cfg flags compressed/Makefile's stubh_cfgs-y derives from the same .config
  for p in 'AMD_MEM_ENCRYPT amd_mem_encrypt' 'RELOCATABLE relocatable' 'FRAME_POINTER frame_pointer' 'MITIGATION_SLS mitigation_sls'; do set -- $b $p
    grep -q "^CONFIG_$2=y" "$b/.config" && printf -- '--cfg=%s ' $3; done; echo; exit 0; fi
cfg() { sed -n "s/^CONFIG_$1=\(.*\)/\1/p" "$b/.config"; }
mask() { sed -n "s/^#define REQUIRED_MASK$1[[:space:]]*\(0x[0-9a-fA-F]*\)U.*/\1/p" "$b/arch/x86/include/generated/asm/cpufeaturemasks.h"; }
echo "export STUBH_PHYSICAL_START=$(cfg PHYSICAL_START) STUBH_PHYSICAL_ALIGN=$(cfg PHYSICAL_ALIGN)"
echo "export STUBH_REQUIRED_MASK0=$(mask 0) STUBH_REQUIRED_MASK1=$(mask 1)"
echo "export STUBH_FUNCTION_ALIGNMENT=$(cfg FUNCTION_ALIGNMENT)"
