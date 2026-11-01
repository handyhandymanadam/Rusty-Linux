// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/pmjump.S (RMASM, Phase C2): `protected_mode_jump(u32 entrypoint, u32 bootparams)`,
//! the actual switch from real to 32-bit protected mode, and its 32-bit landing pad `.Lin_pm32` in `.text32`.
//! 16-bit (`.code16`) then `.code32` text in one `global_asm!`. The text is the .S verbatim (AT&T). Mechanical expansion:
//! `SYM_FUNC_START_NOALIGN(x)` (linkage.h) = `.globl x ; x:`, `SYM_FUNC_START_LOCAL_NOALIGN(x)` = `x:`,
//! `SYM_FUNC_END(x)` = `.type x, STT_FUNC ; .size x, .-x`. Header constants (`__BOOT_CS/DS/TSS` of asm/segment.h,
//! `X86_CR0_PE` of asm/processor-flags.h) are `const` operands checked against the headers by rig/rmasm/consts.sh.
//! The object is the contract (rig/rmasm/check.sh); setup.elf and bzImage byte-identical with `boot_rmasm_rust=`.
//! TEST-GAP: a wrong byte here is a silent reset or a hang before any output; the only check is object identity plus the
//! boot (every legacy-BIOS boot runs it once; EFI/OVMF never does). The far-jump operand fix-up `addl %ebx, 2f` (the
//! setup's linear base) is exercised only with setup at 0x90000 (QEMU `-kernel`); other load addresses by argument only.
// C-HEADERS: asm/boot.h asm/processor-flags.h asm/segment.h linux/linkage.h

use core::arch::global_asm;

const __BOOT_CS: usize = 0x10; // C: __BOOT_CS
const __BOOT_DS: usize = 0x18; // C: __BOOT_DS
const __BOOT_TSS: usize = 0x20; // C: __BOOT_TSS
const X86_CR0_PE: usize = 1 << 0; // C: X86_CR0_PE

global_asm!(
    r#"
/*
 * The actual transition into protected mode
 */

	.text
	.code16

/*
 * void protected_mode_jump(u32 entrypoint, u32 bootparams);
 */
	.globl protected_mode_jump
protected_mode_jump:
	movl	%edx, %esi		# Pointer to boot_params table

	xorl	%ebx, %ebx
	movw	%cs, %bx
	shll	$4, %ebx
	addl	%ebx, 2f
	jmp	1f			# Short jump to serialize on 386/486
1:

	movw	${__BOOT_DS}, %cx
	movw	${__BOOT_TSS}, %di

	movl	%cr0, %edx
	orb	${X86_CR0_PE}, %dl	# Protected mode
	movl	%edx, %cr0

	# Transition to 32-bit mode
	.byte	0x66, 0xea		# ljmpl opcode
2:	.long	.Lin_pm32		# offset
	.word	{__BOOT_CS}		# segment
	.type protected_mode_jump, STT_FUNC
	.size protected_mode_jump, .-protected_mode_jump

	.code32
	.section ".text32","ax"
.Lin_pm32:
	# Set up data segments for flat 32-bit mode
	movl	%ecx, %ds
	movl	%ecx, %es
	movl	%ecx, %fs
	movl	%ecx, %gs
	movl	%ecx, %ss
	# The 32-bit code sets up its own stack, but this way we do have
	# a valid stack if some debugging hack wants to use it.
	addl	%ebx, %esp

	# Set up TR to make Intel VT happy
	ltr	%di

	# Clear registers to allow for future extensions to the
	# 32-bit boot protocol
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi

	# Set up LDTR to make Intel VT happy
	lldt	%cx

	jmpl	*%eax			# Jump to the 32-bit entrypoint
	.type .Lin_pm32, STT_FUNC
	.size .Lin_pm32, .-.Lin_pm32
"#,
    __BOOT_CS = const __BOOT_CS,
    __BOOT_DS = const __BOOT_DS,
    __BOOT_TSS = const __BOOT_TSS,
    X86_CR0_PE = const X86_CR0_PE,
    options(att_syntax)
);
