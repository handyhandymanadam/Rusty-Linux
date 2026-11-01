// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/kernel_info.S (STUBH, Phase C).
//!
//! The `kernel_info` structure bootloaders read through the setup header's `kernel_info`
//! field: magic "LToP", header size, total size, maximal setup_data type. It is DATA, emitted
//! with `global_asm!` so that section name, flags and the global symbol are exactly the
//! assembler's (vmlinux.lds.S places `.rodata.kernel_info`; zoffset.h reads `kernel_info`).
//! Object-level equivalence with the .S object: rig/stubh/objcmp.py.
//! TEST-GAP: nothing in this rig reads `kernel_info` (QEMU `-kernel` does not). It is data: the proof is byte equality of the
//! section and of the whole bzImage with the .S build (rig/stubh/imgcmp.sh).
// C-HEADERS: asm/bootparam.h

use core::arch::global_asm;

const SETUP_ENUM_MAX: u32 = 0xa; // C: SETUP_ENUM_MAX
const SETUP_INDIRECT: u32 = 1 << 31; // C: SETUP_INDIRECT
const SETUP_TYPE_MAX: u32 = SETUP_ENUM_MAX | SETUP_INDIRECT; // C: SETUP_TYPE_MAX

global_asm!(
    r#"
	.section ".rodata.kernel_info", "a"

	.global kernel_info

kernel_info:
	/* Header, Linux top (structure). */
	.ascii	"LToP"
	/* Size. */
	.long	kernel_info_var_len_data - kernel_info
	/* Size total. */
	.long	kernel_info_end - kernel_info

	/* Maximal allowed type for setup_data and setup_indirect structs. */
	.long	{SETUP_TYPE_MAX}

kernel_info_var_len_data:
	/* Empty for time being... */
kernel_info_end:
"#,
    SETUP_TYPE_MAX = const SETUP_TYPE_MAX,
    options(att_syntax)
);
