#!/usr/bin/env bash
# run-pm-kani.sh -- Kani on port/tree/arch/x86/boot/pm_rs.rs (#[cfg(kani)] mod kmodel/proofs): go_to_protected_mode() for ALL ds, boot_gdt/boot_params
# 32-bit addresses, realmode_swtch, code32_start and enable_a20() results: exact effect sequence, GDT bytes (architectural values written out in the
# harness), gdt_ptr and jump arguments; plus the (u32)&x + (ds() << 4) arithmetic. Needs cargo-kani. RM_GEN_DIR = the kbuild dir holding pm_gen.rs.
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root/rig/realmode/kani-pm" && RM_GEN_DIR="$root/build-fast/arch/x86/boot" cargo kani 2>&1 | grep -E "^Checking harness|^VERIFICATION|^Complete|^error|Failed Checks|SUCCESSFUL|FAILED|cover|SATISFIED|UNSATISFIABLE|unwinding"
